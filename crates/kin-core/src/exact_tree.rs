// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Shared exact repository-tree transition planning.
//!
//! These functions consume graph truth plus an explicit, complete ingress
//! observation. They do not inspect the filesystem and must never be used as a
//! runtime query fallback.

use std::collections::BTreeMap;

use kin_model::{ArtifactId, LocatedEntry, RepoPath, ResolvedTree, TreeDelta, TreeEntry};

use crate::{KinError, Result};

/// One explicit, identity-bearing operation over graph-owned repository truth.
///
/// Paths remain locations. A move keeps the source artifact identity, while a
/// copy must carry a caller-stable fresh identity so transaction retries do not
/// silently mint a different artifact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArtifactTreeOperation {
    Move {
        artifact_id: ArtifactId,
        destination: RepoPath,
    },
    Copy {
        source_artifact_id: ArtifactId,
        new_artifact_id: ArtifactId,
        destination: RepoPath,
    },
}

/// Plan explicit moves and copies as one exact tree transaction.
///
/// The planner never reads projected files and never classifies by language or
/// content. Blob, executable, symlink, Gitlink, binary, configuration, and
/// unsupported-language entries all follow the same identity rules. Every move
/// is removed before any destination is inserted by [`ResolvedTree::apply`],
/// so swaps and rename cycles are supported without order-dependent behavior.
pub fn plan_artifact_operations(
    current: &ResolvedTree,
    operations: &[ArtifactTreeOperation],
) -> Result<Vec<TreeDelta>> {
    let mut deltas = Vec::with_capacity(operations.len());
    for operation in operations {
        let delta = match operation {
            ArtifactTreeOperation::Move {
                artifact_id,
                destination,
            } => {
                let source = current.get(artifact_id).ok_or_else(|| {
                    KinError::Other(format!(
                        "cannot move unknown repository artifact {artifact_id:?}"
                    ))
                })?;
                TreeDelta::Updated {
                    artifact_id: *artifact_id,
                    old: source.located_entry(),
                    new: LocatedEntry::new(destination.clone(), source.entry),
                }
            }
            ArtifactTreeOperation::Copy {
                source_artifact_id,
                new_artifact_id,
                destination,
            } => {
                let source = current.get(source_artifact_id).ok_or_else(|| {
                    KinError::Other(format!(
                        "cannot copy unknown repository artifact {source_artifact_id:?}"
                    ))
                })?;
                TreeDelta::Added {
                    artifact_id: *new_artifact_id,
                    new: LocatedEntry::new(destination.clone(), source.entry),
                }
            }
        };
        deltas.push(delta);
    }

    sort_deltas(&mut deltas);
    current.apply(&deltas).map_err(|error| {
        KinError::Other(format!("invalid explicit artifact operation: {error}"))
    })?;
    Ok(deltas)
}

/// Resolve one source path through graph truth and plan an identity-preserving
/// move. This is a path-addressed convenience for CLI/API boundaries; the
/// resulting delta is identity-addressed.
pub fn plan_artifact_move(
    current: &ResolvedTree,
    source: &RepoPath,
    destination: RepoPath,
) -> Result<Vec<TreeDelta>> {
    let artifact_id = current.artifact_id_at_path(source).ok_or_else(|| {
        KinError::Other(format!(
            "cannot move untracked repository path {source}; admit it before moving it"
        ))
    })?;
    plan_artifact_operations(
        current,
        &[ArtifactTreeOperation::Move {
            artifact_id,
            destination,
        }],
    )
}

/// Resolve one source path through graph truth and plan a copy with an explicit
/// fresh identity. The caller owns `new_artifact_id` so an operation can be
/// retried idempotently through the repository transaction boundary.
pub fn plan_artifact_copy(
    current: &ResolvedTree,
    source: &RepoPath,
    destination: RepoPath,
    new_artifact_id: ArtifactId,
) -> Result<Vec<TreeDelta>> {
    let source_artifact_id = current.artifact_id_at_path(source).ok_or_else(|| {
        KinError::Other(format!(
            "cannot copy untracked repository path {source}; admit it before copying it"
        ))
    })?;
    plan_artifact_operations(
        current,
        &[ArtifactTreeOperation::Copy {
            source_artifact_id,
            new_artifact_id,
            destination,
        }],
    )
}

/// Compute the exact identity-bearing correction between two graph trees.
pub fn exact_tree_correction(
    current: &ResolvedTree,
    desired: &ResolvedTree,
) -> Result<Vec<TreeDelta>> {
    let mut deltas = Vec::new();
    for old in current.artifacts() {
        match desired.get(&old.artifact_id) {
            Some(new) if new == old => {}
            Some(new) => deltas.push(TreeDelta::Updated {
                artifact_id: old.artifact_id,
                old: old.located_entry(),
                new: new.located_entry(),
            }),
            None => deltas.push(TreeDelta::Removed {
                artifact_id: old.artifact_id,
                old: old.located_entry(),
            }),
        }
    }
    for new in desired.artifacts() {
        if current.get(&new.artifact_id).is_none() {
            deltas.push(TreeDelta::Added {
                artifact_id: new.artifact_id,
                new: new.located_entry(),
            });
        }
    }
    sort_deltas(&mut deltas);
    let staged = current
        .apply(&deltas)
        .map_err(|error| KinError::Other(format!("invalid exact tree correction: {error}")))?;
    if staged != *desired {
        return Err(KinError::Other(
            "exact tree correction did not resolve to the requested target".to_string(),
        ));
    }
    Ok(deltas)
}

/// Plan a complete host/session observation against graph-owned identity.
///
/// Unique exact-entry moves retain `ArtifactId`; same-path changes retain
/// identity after move matching; additions receive new identities. Duplicate
/// exact entries that make a move ambiguous fail closed.
pub fn plan_observed_tree_deltas(
    previous: &ResolvedTree,
    observed: BTreeMap<RepoPath, TreeEntry>,
) -> Result<Vec<TreeDelta>> {
    let mut old_by_id = previous
        .artifacts()
        .map(|artifact| (artifact.artifact_id, artifact.located_entry()))
        .collect::<BTreeMap<_, _>>();
    let mut new_by_path = observed;
    let mut deltas = Vec::new();

    let unchanged = old_by_id
        .iter()
        .filter_map(|(artifact_id, old)| {
            (new_by_path.get(&old.path) == Some(&old.entry)).then_some(*artifact_id)
        })
        .collect::<Vec<_>>();
    let mut retained = Vec::with_capacity(unchanged.len());
    for artifact_id in unchanged {
        let old = old_by_id
            .remove(&artifact_id)
            .expect("unchanged artifact came from old tree");
        new_by_path.remove(&old.path);
        retained.push((artifact_id, old));
    }

    // A path-stable exact entry plus another observed copy of the same entry is
    // not enough evidence to decide whether the original artifact stayed put
    // and was copied, or moved while an identical replacement took its old
    // path. Stable identity must not depend on that unobservable intent.
    if let Some((artifact_id, old, duplicate)) = retained.iter().find_map(|(artifact_id, old)| {
        new_by_path
            .iter()
            .find_map(|(path, entry)| (entry == &old.entry).then_some((*artifact_id, old, path)))
    }) {
        return Err(KinError::Other(format!(
            "identity-underdetermined repository transition for artifact {artifact_id:?} at {}: \
             the same exact entry also appears at {}; use an explicit identity-bearing copy/move",
            old.path, duplicate
        )));
    }

    let unique_moves = old_by_id
        .iter()
        .filter_map(|(artifact_id, old)| {
            let candidates = new_by_path
                .iter()
                .filter_map(|(path, entry)| (entry == &old.entry).then_some(path))
                .collect::<Vec<_>>();
            let [new_path] = candidates.as_slice() else {
                return None;
            };
            let old_candidate_count = old_by_id
                .values()
                .filter(|candidate| candidate.entry == old.entry)
                .count();
            (old_candidate_count == 1).then_some((*artifact_id, (*new_path).clone()))
        })
        .collect::<Vec<_>>();
    for (artifact_id, new_path) in unique_moves {
        let old = old_by_id
            .remove(&artifact_id)
            .expect("move artifact came from old tree");
        let new_entry = new_by_path
            .remove(&new_path)
            .expect("move destination came from observed tree");
        deltas.push(TreeDelta::Updated {
            artifact_id,
            old,
            new: LocatedEntry::new(new_path, new_entry),
        });
    }

    if let Some((artifact_id, old, candidates)) = old_by_id.iter().find_map(|(artifact_id, old)| {
        let candidates = new_by_path
            .iter()
            .filter_map(|(path, entry)| (entry == &old.entry).then_some(path.clone()))
            .collect::<Vec<_>>();
        (!candidates.is_empty()).then_some((*artifact_id, old, candidates))
    }) {
        return Err(KinError::Other(format!(
            "ambiguous repository identity transition for artifact {artifact_id:?} at {}: \
             exact entry also appears at {}; use an explicit identity-bearing move",
            old.path,
            candidates
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        )));
    }

    let same_path_updates = old_by_id
        .iter()
        .filter_map(|(artifact_id, old)| {
            new_by_path
                .contains_key(&old.path)
                .then_some((*artifact_id, old.path.clone()))
        })
        .collect::<Vec<_>>();
    for (artifact_id, path) in same_path_updates {
        let old = old_by_id
            .remove(&artifact_id)
            .expect("same-path artifact came from old tree");
        let new_entry = new_by_path
            .remove(&path)
            .expect("same-path entry came from observed tree");
        deltas.push(TreeDelta::Updated {
            artifact_id,
            old,
            new: LocatedEntry::new(path, new_entry),
        });
    }

    if !old_by_id.is_empty() && !new_by_path.is_empty() {
        let removed = old_by_id
            .values()
            .map(|old| old.path.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        let added = new_by_path
            .keys()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ");
        return Err(KinError::Other(format!(
            "identity-underdetermined repository transition: unmatched removals [{removed}] and \
             additions [{added}] may be move-plus-edit operations; use explicit identity-bearing \
             add/remove/move commands"
        )));
    }

    deltas.extend(
        old_by_id
            .into_iter()
            .map(|(artifact_id, old)| TreeDelta::Removed { artifact_id, old }),
    );
    deltas.extend(
        new_by_path
            .into_iter()
            .map(|(path, entry)| TreeDelta::Added {
                artifact_id: ArtifactId::new(),
                new: LocatedEntry::new(path, entry),
            }),
    );
    sort_deltas(&mut deltas);
    Ok(deltas)
}

fn sort_deltas(deltas: &mut [TreeDelta]) {
    deltas.sort_by(|left, right| {
        let left_path = left
            .new_state()
            .or_else(|| left.old_state())
            .expect("tree delta has one side");
        let right_path = right
            .new_state()
            .or_else(|| right.old_state())
            .expect("tree delta has one side");
        left_path
            .path
            .cmp(&right_path.path)
            .then_with(|| left.artifact_id().cmp(&right.artifact_id()))
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{GitObjectId, Hash256, ResolvedArtifact};

    fn resolved(artifacts: Vec<(ArtifactId, RepoPath, TreeEntry)>) -> ResolvedTree {
        ResolvedTree::from_artifacts(
            artifacts
                .into_iter()
                .map(|(id, path, entry)| ResolvedArtifact::new(id, path, entry)),
        )
        .unwrap()
    }

    #[test]
    fn observation_preserves_unique_move_identity_and_path_reuse() {
        let moved_id = ArtifactId::new();
        let moved = TreeEntry::blob(Hash256::from_bytes([0x11; 32]), false);
        let replacement = TreeEntry::blob(Hash256::from_bytes([0x22; 32]), true);
        let old = RepoPath::from_utf8("compose.yaml").unwrap();
        let new = RepoPath::from_utf8("deploy/compose.yaml").unwrap();
        let previous = resolved(vec![(moved_id, old.clone(), moved)]);

        let deltas = plan_observed_tree_deltas(
            &previous,
            BTreeMap::from([(old.clone(), replacement), (new.clone(), moved)]),
        )
        .unwrap();
        let next = previous.apply(&deltas).unwrap();

        assert_eq!(next.get(&moved_id).unwrap().path, new);
        assert_ne!(next.artifact_at_path(&old).unwrap().artifact_id, moved_id);
    }

    #[test]
    fn observation_supports_atomic_swaps_with_non_utf8_paths() {
        let left_id = ArtifactId::new();
        let right_id = ArtifactId::new();
        let left_entry = TreeEntry::blob(Hash256::from_bytes([0x33; 32]), false);
        let right_entry = TreeEntry::symlink(Hash256::from_bytes([0x44; 32]));
        let left = RepoPath::from_bytes(b"left-\xff".to_vec()).unwrap();
        let right = RepoPath::from_utf8("right").unwrap();
        let previous = resolved(vec![
            (left_id, left.clone(), left_entry),
            (right_id, right.clone(), right_entry),
        ]);

        let deltas = plan_observed_tree_deltas(
            &previous,
            BTreeMap::from([(left.clone(), right_entry), (right.clone(), left_entry)]),
        )
        .unwrap();
        let next = previous.apply(&deltas).unwrap();

        assert_eq!(next.get(&left_id).unwrap().path, right);
        assert_eq!(next.get(&right_id).unwrap().path, left);
    }

    #[test]
    fn observation_fails_closed_on_ambiguous_identity() {
        let id = ArtifactId::new();
        let entry = TreeEntry::blob(Hash256::from_bytes([0x55; 32]), false);
        let previous = resolved(vec![(id, RepoPath::from_utf8("old").unwrap(), entry)]);
        let error = plan_observed_tree_deltas(
            &previous,
            BTreeMap::from([
                (RepoPath::from_utf8("copy-a").unwrap(), entry),
                (RepoPath::from_utf8("copy-b").unwrap(), entry),
            ]),
        )
        .unwrap_err();
        assert!(error.to_string().contains("ambiguous repository identity"));
    }

    #[test]
    fn observation_fails_closed_on_move_plus_edit() {
        let id = ArtifactId::new();
        let previous = resolved(vec![(
            id,
            RepoPath::from_utf8("old").unwrap(),
            TreeEntry::blob(Hash256::from_bytes([0x61; 32]), false),
        )]);

        let error = plan_observed_tree_deltas(
            &previous,
            BTreeMap::from([(
                RepoPath::from_utf8("new").unwrap(),
                TreeEntry::blob(Hash256::from_bytes([0x62; 32]), false),
            )]),
        )
        .unwrap_err();

        assert!(error.to_string().contains("identity-underdetermined"));
        assert_eq!(previous.get(&id).unwrap().path.as_utf8(), Some("old"));
    }

    #[test]
    fn observation_fails_closed_on_identical_move_and_path_replacement() {
        let id = ArtifactId::new();
        let entry = TreeEntry::blob(Hash256::from_bytes([0x71; 32]), false);
        let old = RepoPath::from_utf8("old").unwrap();
        let previous = resolved(vec![(id, old.clone(), entry)]);

        let error = plan_observed_tree_deltas(
            &previous,
            BTreeMap::from([(old, entry), (RepoPath::from_utf8("new").unwrap(), entry)]),
        )
        .unwrap_err();

        assert!(error.to_string().contains("identity-underdetermined"));
    }

    #[test]
    fn explicit_move_preserves_identity_for_arbitrary_artifact_bytes() {
        let artifact_id = ArtifactId::new();
        let source = RepoPath::from_utf8("compose.yaml").unwrap();
        let destination = RepoPath::from_bytes(b"deploy/compose-\xff.yaml".to_vec()).unwrap();
        let entry = TreeEntry::blob(Hash256::from_bytes([0x81; 32]), true);
        let current = resolved(vec![(artifact_id, source.clone(), entry)]);

        let deltas = plan_artifact_move(&current, &source, destination.clone()).unwrap();
        let next = current.apply(&deltas).unwrap();

        assert!(next.artifact_at_path(&source).is_none());
        assert_eq!(next.artifact_id_at_path(&destination), Some(artifact_id));
        assert_eq!(next.get(&artifact_id).unwrap().entry, entry);
    }

    #[test]
    fn explicit_copy_mints_identity_without_reinterpreting_entry_kind() {
        let source_id = ArtifactId::new();
        let copied_id = ArtifactId::new();
        let source = RepoPath::from_utf8("vendor/module").unwrap();
        let destination = RepoPath::from_utf8("vendor/module-copy").unwrap();
        let entry = TreeEntry::gitlink(GitObjectId::sha1([0x91; 20]));
        let current = resolved(vec![(source_id, source.clone(), entry)]);

        let deltas = plan_artifact_copy(&current, &source, destination.clone(), copied_id).unwrap();
        let next = current.apply(&deltas).unwrap();

        assert_eq!(next.artifact_id_at_path(&source), Some(source_id));
        assert_eq!(next.artifact_id_at_path(&destination), Some(copied_id));
        assert_eq!(next.get(&copied_id).unwrap().entry, entry);
    }

    #[test]
    fn explicit_operations_support_atomic_swaps_and_copy_from_a_moved_source() {
        let left_id = ArtifactId::new();
        let right_id = ArtifactId::new();
        let copy_id = ArtifactId::new();
        let left = RepoPath::from_utf8("left").unwrap();
        let right = RepoPath::from_utf8("right").unwrap();
        let copy = RepoPath::from_utf8("copies/left-link").unwrap();
        let left_entry = TreeEntry::symlink(Hash256::from_bytes([0xa1; 32]));
        let right_entry = TreeEntry::blob(Hash256::from_bytes([0xa2; 32]), false);
        let current = resolved(vec![
            (left_id, left.clone(), left_entry),
            (right_id, right.clone(), right_entry),
        ]);

        let deltas = plan_artifact_operations(
            &current,
            &[
                ArtifactTreeOperation::Move {
                    artifact_id: left_id,
                    destination: right.clone(),
                },
                ArtifactTreeOperation::Move {
                    artifact_id: right_id,
                    destination: left.clone(),
                },
                ArtifactTreeOperation::Copy {
                    source_artifact_id: left_id,
                    new_artifact_id: copy_id,
                    destination: copy.clone(),
                },
            ],
        )
        .unwrap();
        let next = current.apply(&deltas).unwrap();

        assert_eq!(next.artifact_id_at_path(&right), Some(left_id));
        assert_eq!(next.artifact_id_at_path(&left), Some(right_id));
        assert_eq!(next.artifact_id_at_path(&copy), Some(copy_id));
        assert_eq!(next.get(&copy_id).unwrap().entry, left_entry);
    }

    #[test]
    fn explicit_operations_reject_colliding_paths_and_id_reuse_atomically() {
        let source_id = ArtifactId::new();
        let occupied_id = ArtifactId::new();
        let source = RepoPath::from_utf8("source.bin").unwrap();
        let occupied = RepoPath::from_utf8("occupied.bin").unwrap();
        let current = resolved(vec![
            (
                source_id,
                source,
                TreeEntry::blob(Hash256::from_bytes([0xb1; 32]), false),
            ),
            (
                occupied_id,
                occupied.clone(),
                TreeEntry::blob(Hash256::from_bytes([0xb2; 32]), false),
            ),
        ]);

        let path_error = plan_artifact_operations(
            &current,
            &[ArtifactTreeOperation::Move {
                artifact_id: source_id,
                destination: occupied,
            }],
        )
        .unwrap_err();
        assert!(path_error.to_string().contains("remains occupied"));

        let id_error = plan_artifact_operations(
            &current,
            &[ArtifactTreeOperation::Copy {
                source_artifact_id: source_id,
                new_artifact_id: occupied_id,
                destination: RepoPath::from_utf8("copy.bin").unwrap(),
            }],
        )
        .unwrap_err();
        assert!(id_error.to_string().contains("already exists"));
        assert_eq!(current.len(), 2);
    }

    #[test]
    fn explicit_operations_reject_untracked_sources_and_noop_moves() {
        let artifact_id = ArtifactId::new();
        let tracked = RepoPath::from_utf8("tracked").unwrap();
        let current = resolved(vec![(
            artifact_id,
            tracked.clone(),
            TreeEntry::blob(Hash256::from_bytes([0xc1; 32]), false),
        )]);

        let untracked = RepoPath::from_utf8("untracked").unwrap();
        let error = plan_artifact_move(
            &current,
            &untracked,
            RepoPath::from_utf8("destination").unwrap(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("cannot move untracked"));

        let error = plan_artifact_move(&current, &tracked, tracked.clone()).unwrap_err();
        assert!(error.to_string().contains("no-op"));
    }
}
