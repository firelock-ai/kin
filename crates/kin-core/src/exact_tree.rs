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
    for artifact_id in unchanged {
        let old = old_by_id
            .remove(&artifact_id)
            .expect("unchanged artifact came from old tree");
        new_by_path.remove(&old.path);
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
    use kin_model::{Hash256, ResolvedArtifact};

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
}
