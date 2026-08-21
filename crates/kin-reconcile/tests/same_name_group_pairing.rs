// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Carrying a re-parsed declaration forward onto the right existing entity when
//! several declarations in one file share a name.
//!
//! Entity identity is `(file, kind, name, start_line)`, so any edit that adds or
//! removes a line retires the id of every declaration below it and drops them to
//! the name-based carry-forward passes. Name and kind alone cannot tell one
//! member of a Python `@overload` group from another, and the graph returns a
//! file's entities in query order rather than declaration order, so the group's
//! members were paired arbitrarily: three untouched declarations came back as
//! three modifications reporting signature transitions in mutually
//! contradictory directions. A reviewer reading two findings that say
//! `A -> B` and `B -> A` about the same function stops believing the tool.

use std::path::PathBuf;

use kin_blobs::BlobStore;
use kin_db::InMemoryGraph;
use kin_index::FileEvent;
use kin_model::{
    ArtifactId, Entity, EntityDelta, EntityStore, Hash256, LocatedEntry, RepoPath,
    TransactionDelta, TreeDelta, TreeEntry,
};
use kin_reconcile::Reconciler;
use tempfile::TempDir;

/// A repository built the way a user builds one: write the file, admit its
/// artifact, reconcile, apply.
struct LiveRepo {
    dir: TempDir,
    graph: InMemoryGraph,
    blobs: BlobStore,
    reconciler: Reconciler,
}

impl LiveRepo {
    fn new() -> Self {
        let dir = TempDir::new().expect("temp repo");
        let blobs = BlobStore::new(dir.path().join("blobs")).expect("blob store");
        let graph = InMemoryGraph::new();
        let mut reconciler = Reconciler::new(dir.path().to_path_buf());
        reconciler.seed_cross_file_linker_from_graph(&graph);
        Self {
            dir,
            graph,
            blobs,
            reconciler,
        }
    }

    fn abs(&self, rel: &str) -> PathBuf {
        self.dir.path().join(rel)
    }

    fn commit(&mut self, rel: &str, source: &str) -> TransactionDelta {
        let path = self.abs(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create parent");
        }
        std::fs::write(&path, source).expect("write source");

        let blob_hash = self.blobs.write(source.as_bytes()).expect("store blob");
        let repo_path = RepoPath::from_utf8(rel.to_string()).expect("repo path");
        let entry = TreeEntry::blob(Hash256::from_bytes(blob_hash.0), false);
        let tree_delta = match self.graph.artifact_id_at_path(&repo_path) {
            Some(artifact_id) => {
                let old_entry = self
                    .graph
                    .get_tree_entry(&kin_model::FilePathId::new(rel))
                    .ok()
                    .flatten();
                match old_entry {
                    Some(old) if old == entry => None,
                    Some(old) => Some(TreeDelta::Updated {
                        artifact_id,
                        old: LocatedEntry::new(repo_path.clone(), old),
                        new: LocatedEntry::new(repo_path, entry),
                    }),
                    None => Some(TreeDelta::Added {
                        artifact_id,
                        new: LocatedEntry::new(repo_path, entry),
                    }),
                }
            }
            None => Some(TreeDelta::Added {
                artifact_id: ArtifactId::new(),
                new: LocatedEntry::new(repo_path, entry),
            }),
        };
        if let Some(tree_delta) = tree_delta {
            self.graph
                .apply_transaction_delta(&TransactionDelta {
                    tree_deltas: vec![tree_delta],
                    ..TransactionDelta::default()
                })
                .expect("admit artifact");
        }

        let result = self
            .reconciler
            .reconcile_file_change(&FileEvent::Changed(path), &self.blobs, &self.graph)
            .expect("reconcile succeeds");
        let (_, delta) = result.into_parts();
        self.graph
            .apply_transaction_delta(&delta)
            .expect("apply reconciled delta");
        delta
    }
}

/// Three declarations of `render`: two `@overload` stubs and the implementation.
/// `leading` sits above all of them so an edit there shifts every line below.
const BASE: &str = r#"from typing import Literal, overload

LIMIT: int = 30


def leading(value):
    return value


@overload
def render(value: str, raw: Literal[True]) -> bytes: ...


@overload
def render(value: str, raw: Literal[False] = False) -> str: ...


def render(value, raw=False):
    return value.encode() if raw else value


def trailing(value):
    return render(value)
"#;

/// Every `(old signature, new signature)` a modification on `name` reported.
fn signature_transitions<'a>(
    delta: &'a TransactionDelta,
    name: &str,
) -> Vec<(&'a str, &'a str)> {
    delta
        .entity_deltas
        .iter()
        .filter_map(|entity_delta| match entity_delta {
            EntityDelta::Modified { old, new } if new.name == name => {
                Some((old.signature.as_str(), new.signature.as_str()))
            }
            _ => None,
        })
        .collect()
}

fn modified_pairs(delta: &TransactionDelta) -> Vec<(&Entity, &Entity)> {
    delta
        .entity_deltas
        .iter()
        .filter_map(|entity_delta| match entity_delta {
            EntityDelta::Modified { old, new } => Some((old, new)),
            _ => None,
        })
        .collect()
}

/// The defect exactly as FIR-2479 reports it: an edit that touches no member of
/// a same-name group still rotates the group's members onto each other, and the
/// rotation surfaces as breaking-change findings that contradict one another.
#[test]
fn a_line_shift_above_a_same_name_group_does_not_rotate_its_members() {
    let mut repo = LiveRepo::new();
    repo.commit("mod.py", BASE);

    // One line added inside `leading`. Nothing in the `render` group is touched,
    // and every declaration below `leading` shifts down by exactly one line.
    let edited = BASE.replace(
        "def leading(value):\n    return value",
        "def leading(value):\n    value = value\n    return value",
    );
    assert_ne!(edited, BASE, "the fixture edit must apply");
    assert_eq!(
        edited.lines().count(),
        BASE.lines().count() + 1,
        "the fixture edit must shift the lines below it"
    );

    let delta = repo.commit("mod.py", &edited);

    let transitions = signature_transitions(&delta, "render");
    assert_eq!(
        transitions.len(),
        3,
        "all three declarations of `render` should still be carried forward, got {transitions:#?}"
    );
    for (old_signature, new_signature) in &transitions {
        assert_eq!(
            old_signature, new_signature,
            "a declaration nobody edited was paired with a different declaration of the same \
             name: `{old_signature}` was reported as becoming `{new_signature}`"
        );
    }

    // The cheap invariant the ticket names: no two findings about one name may
    // describe inverse transitions. It is what makes the fabrication obvious to
    // a reader, so it is asserted directly rather than inferred from the above.
    for (left_old, left_new) in &transitions {
        for (right_old, right_new) in &transitions {
            assert!(
                !(left_old == right_new && left_new == right_old && left_old != left_new),
                "contradictory pair reported on `render`: `{left_old}` -> `{left_new}` \
                 alongside `{right_old}` -> `{right_new}`"
            );
        }
    }
}

/// The positive control. Editing one member of the group must still be reported,
/// on that member, with its real transition, and must not disturb the others.
#[test]
fn editing_one_member_of_a_same_name_group_reports_exactly_that_member() {
    let mut repo = LiveRepo::new();
    repo.commit("mod.py", BASE);

    let edited = BASE.replace(
        "def render(value, raw=False):",
        "def render(value, raw=False, encoding=\"utf-8\"):",
    );
    assert_ne!(edited, BASE, "the fixture edit must apply");
    assert_eq!(
        edited.lines().count(),
        BASE.lines().count(),
        "this fixture must not move any line, so only the edited declaration can differ"
    );

    let delta = repo.commit("mod.py", &edited);

    let changed: Vec<(&str, &str)> = signature_transitions(&delta, "render")
        .into_iter()
        .filter(|(old_signature, new_signature)| old_signature != new_signature)
        .collect();
    assert_eq!(
        changed,
        vec![(
            "def render(value, raw=False)",
            "def render(value, raw=False, encoding=\"utf-8\")",
        )],
        "the implementation's own signature change is the only one that may be reported"
    );
}

/// Position alone is not enough, so the signature tier is load-bearing rather
/// than belt-and-braces. Inserting a block BETWEEN two members of the group
/// moves the later members further than the spacing between them, so pairing on
/// nearest declaration position cross-pairs the stub with the implementation.
/// Only the declaration's own signature gets this right.
#[test]
fn a_wide_insertion_inside_a_same_name_group_pairs_by_signature_not_position() {
    let mut repo = LiveRepo::new();
    repo.commit("mod.py", BASE);

    // Twelve lines land between the first stub and the second. The group's
    // members sit four lines apart, so every later member is now nearer to the
    // slot its neighbour used to occupy than to its own.
    let filler: String = (0..4)
        .map(|index| format!("\n\ndef filler_{index}(value):\n    return value\n"))
        .collect();
    let edited = BASE.replace(
        "def render(value: str, raw: Literal[True]) -> bytes: ...\n",
        &format!("def render(value: str, raw: Literal[True]) -> bytes: ...\n{filler}"),
    );
    assert_ne!(edited, BASE, "the fixture edit must apply");
    assert!(
        edited.lines().count() >= BASE.lines().count() + 12,
        "the insertion must be wider than the spacing between group members, got {} vs {}",
        edited.lines().count(),
        BASE.lines().count()
    );

    let delta = repo.commit("mod.py", &edited);

    let transitions = signature_transitions(&delta, "render");
    assert_eq!(
        transitions.len(),
        3,
        "all three declarations of `render` should still be carried forward, got {transitions:#?}"
    );
    for (old_signature, new_signature) in &transitions {
        assert_eq!(
            old_signature, new_signature,
            "a declaration nobody edited was paired with a different declaration of the same \
             name: `{old_signature}` was reported as becoming `{new_signature}`"
        );
    }
}

/// The other direction: when a member's own signature changed, the signature
/// tier cannot match it, and the fallback decides. Two members change here, so
/// the fallback has two candidates for two declarations and its ordering rule is
/// what picks. Nearest declaration position pairs each with the one it actually
/// descends from; the graph's query order is not declaration order and has no
/// reason to.
#[test]
fn when_signatures_moved_the_fallback_pairs_by_nearest_declaration() {
    let mut repo = LiveRepo::new();
    repo.commit("mod.py", BASE);

    let edited = BASE
        .replace("LIMIT: int = 30", "LIMIT: int = 30\nEXTRA: int = 1")
        .replace(
            "def render(value: str, raw: Literal[True]) -> bytes: ...",
            "def render(value: str, raw: Literal[True], *, strict: bool) -> bytes: ...",
        )
        .replace(
            "def render(value: str, raw: Literal[False] = False) -> str: ...",
            "def render(value: str, raw: Literal[False] = False, *, strict: bool) -> str: ...",
        );
    assert_ne!(edited, BASE, "the fixture edit must apply");

    let delta = repo.commit("mod.py", &edited);

    let mut transitions = signature_transitions(&delta, "render")
        .into_iter()
        .filter(|(old_signature, new_signature)| old_signature != new_signature)
        .collect::<Vec<_>>();
    transitions.sort_unstable();
    assert_eq!(
        transitions,
        vec![
            (
                "@overload def render(value: str, raw: Literal[False] = False) -> str",
                "@overload def render(value: str, raw: Literal[False] = False, *, strict: bool) \
                 -> str",
            ),
            (
                "@overload def render(value: str, raw: Literal[True]) -> bytes",
                "@overload def render(value: str, raw: Literal[True], *, strict: bool) -> bytes",
            ),
        ],
        "each stub must be reported against the stub it descends from, not against the other"
    );
}

/// Identity is never invented: whatever an entity is paired with, the id the
/// graph already holds is the id the modification carries. This is the rule
/// FIR-1656 protects, asserted here so a future pairing change cannot quietly
/// mint a new persisted identity for an existing declaration.
#[test]
fn carry_forward_never_mints_a_new_identity_for_an_existing_declaration() {
    let mut repo = LiveRepo::new();
    repo.commit("mod.py", BASE);

    let edited = BASE.replace(
        "def leading(value):\n    return value",
        "def leading(value):\n    value = value\n    return value",
    );
    assert_ne!(edited, BASE, "the fixture edit must apply");
    let delta = repo.commit("mod.py", &edited);

    let pairs = modified_pairs(&delta);
    assert!(
        !pairs.is_empty(),
        "the fixture must produce modifications for this assertion to mean anything"
    );
    for (old, new) in pairs {
        assert_eq!(
            old.id, new.id,
            "a carried-forward declaration must keep the id the graph already holds"
        );
    }
}
