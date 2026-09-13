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

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;

use kin_blobs::BlobStore;
use kin_db::{InMemoryGraph, SnapshotManager};
use kin_index::FileEvent;
use kin_model::{
    ArtifactId, Entity, EntityDelta, EntityStore, GraphNodeId, Hash256, LocatedEntry, RelationKind,
    RepoPath, TransactionDelta, TreeDelta, TreeEntry,
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

    fn reopen(&mut self) {
        let path = self.dir.path().join("graph.kndb");
        SnapshotManager::save_graph(&path, &self.graph).expect("persist graph");
        let manager = SnapshotManager::open_without_text_index(&path).expect("reopen graph");
        let graph = manager.graph();
        drop(manager);
        self.graph = Arc::try_unwrap(graph).unwrap_or_else(|_| panic!("sole graph owner"));
        self.reconciler = Reconciler::new(self.dir.path().to_path_buf());
        self.reconciler
            .seed_cross_file_linker_from_graph(&self.graph);
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
fn signature_transitions<'a>(delta: &'a TransactionDelta, name: &str) -> Vec<(&'a str, &'a str)> {
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

const OVERLOAD_INT: &str =
    "@overload\ndef render(value: int) -> int:\n    return render_int(value)\n";
const OVERLOAD_STR: &str =
    "@overload\ndef render(value: str) -> str:\n    return render_str(value)\n";
const HELPERS: &str = "from typing import overload\n\ndef render_int(value):\n    return value + 1\n\ndef render_str(value):\n    return value.upper()\n\n";

fn render_group(repo: &LiveRepo) -> HashMap<String, Entity> {
    repo.graph
        .list_all_entities()
        .expect("entities")
        .into_iter()
        .filter(|entity| entity.name == "render")
        .map(|entity| (entity.signature.clone(), entity))
        .collect()
}

fn relation_endpoints(
    repo: &LiveRepo,
    group: &HashMap<String, Entity>,
) -> HashSet<(GraphNodeId, GraphNodeId, RelationKind)> {
    group
        .values()
        .flat_map(|entity| {
            repo.graph
                .get_all_relations_for_entity(&entity.id)
                .expect("declaration relations")
        })
        .map(|relation| (relation.src, relation.dst, relation.kind))
        .collect()
}

fn assert_occupied_line_pairing(base: &str, edited: &str) {
    for reopen_before_edit in [false, true] {
        let mut repo = LiveRepo::new();
        repo.commit("mod.py", base);
        let before = render_group(&repo);
        assert_eq!(before.len(), 2, "fixture must expose distinct overloads");
        let endpoints = relation_endpoints(&repo, &before);
        for entity in before.values() {
            assert!(
                endpoints.iter().any(|(src, _, kind)| {
                    *src == GraphNodeId::Entity(entity.id) && *kind == RelationKind::Calls
                }),
                "each overload must have a real parsed call relation"
            );
        }
        if reopen_before_edit {
            repo.reopen();
        }

        let delta = repo.commit("mod.py", edited);
        for (old, new) in signature_transitions(&delta, "render") {
            assert_eq!(
                old, new,
                "moving an overload fabricated a signature transition"
            );
        }
        // Check both the applied graph and the persisted/reopened graph. A
        // further parse after reopen must honor the carried identity too.
        for reopen_after_edit in [false, true] {
            if reopen_after_edit {
                repo.reopen();
                repo.commit("mod.py", edited);
            }
            let after = render_group(&repo);
            assert_eq!(after.len(), before.len());
            for (signature, old) in &before {
                let new = after.get(signature).expect("same signature remains");
                assert_eq!(old.id, new.id, "identity changed for {signature}");
                assert_eq!(old.fingerprint, new.fingerprint);
                let old_span = old.span.as_ref().expect("old span");
                let new_span = new.span.as_ref().expect("new span");
                assert_eq!(
                    &base[old_span.start_byte..old_span.end_byte],
                    &edited[new_span.start_byte..new_span.end_byte],
                    "stable identity must still read the same declaration body"
                );
            }
            assert_eq!(
                relation_endpoints(&repo, &after),
                endpoints,
                "relations must remain attached to the same declarations"
            );
        }
    }
}

#[test]
fn swapping_overloads_on_occupied_lines_preserves_declaration_identity() {
    assert_eq!(OVERLOAD_INT.lines().count(), OVERLOAD_STR.lines().count());
    let base = format!("{HELPERS}{OVERLOAD_INT}\n{OVERLOAD_STR}");
    let edited = format!("{HELPERS}{OVERLOAD_STR}\n{OVERLOAD_INT}");
    assert_occupied_line_pairing(&base, &edited);
}

#[test]
fn insertion_equal_to_overload_spacing_preserves_declaration_identity() {
    let base = format!("{HELPERS}{OVERLOAD_INT}\n{OVERLOAD_STR}");
    let spacing = OVERLOAD_INT.lines().count() + 1;
    let edited = format!("{}{base}", "\n".repeat(spacing));
    assert_occupied_line_pairing(&base, &edited);
}

/// Read each declaration from its persisted blob provenance, so two declarations
/// with the same signature are distinguished by the helper their body calls.
fn render_bodies(repo: &LiveRepo) -> HashMap<String, Entity> {
    repo.graph
        .list_all_entities()
        .expect("entities")
        .into_iter()
        .filter(|entity| entity.name == "render")
        .map(|entity| {
            let hash = kin_blobs::Hash256::from_hex(
                entity.metadata.extra["blob_hash"]
                    .as_str()
                    .expect("blob hash"),
            )
            .expect("valid blob hash");
            let content = repo.blobs.read(&hash).expect("persisted source");
            let span = entity.span.as_ref().expect("declaration span");
            let body = std::str::from_utf8(&content[span.start_byte..span.end_byte])
                .expect("UTF-8 declaration");
            let helper = ["render_int(value)", "render_str(value)"]
                .into_iter()
                .find(|helper| body.contains(helper))
                .expect("distinct body helper")
                .to_string();
            (helper, entity)
        })
        .collect()
}

#[test]
fn converging_on_a_siblings_signature_keeps_both_persistent_body_identities() {
    // Exercise both parse orders. An edited declaration must not claim its
    // unchanged sibling's identity just because it is visited first.
    for int_first in [true, false] {
        for reopen_before_edit in [false, true] {
            let base = if int_first {
                format!("{HELPERS}{OVERLOAD_INT}\n{OVERLOAD_STR}")
            } else {
                format!("{HELPERS}{OVERLOAD_STR}\n{OVERLOAD_INT}")
            };
            let edited = base.replace("value: int) -> int", "value: str) -> str");
            let mut repo = LiveRepo::new();
            repo.commit("mod.py", &base);
            let before = render_bodies(&repo);
            assert_eq!(before.len(), 2);
            let endpoints = relation_endpoints(&repo, &before);
            for helper in ["render_int", "render_str"] {
                let target = repo
                    .graph
                    .list_all_entities()
                    .expect("entities")
                    .into_iter()
                    .find(|entity| entity.name == helper)
                    .expect("helper");
                assert!(
                    endpoints.contains(&(
                        GraphNodeId::Entity(before[&format!("{helper}(value)")].id),
                        GraphNodeId::Entity(target.id),
                        RelationKind::Calls,
                    )),
                    "fixture must have a resolved call to {helper}"
                );
            }
            if reopen_before_edit {
                repo.reopen();
            }

            let delta = repo.commit("mod.py", &edited);
            assert!(!delta.entity_deltas.iter().any(|change| matches!(
                change,
                EntityDelta::Added { .. } | EntityDelta::Removed { .. }
            )));
            let transitions = signature_transitions(&delta, "render")
                .into_iter()
                .filter(|(old, new)| old != new)
                .collect::<Vec<_>>();
            assert_eq!(
                transitions,
                vec![(
                    before["render_int(value)"].signature.as_str(),
                    before["render_str(value)"].signature.as_str(),
                )]
            );

            for reopen_after_edit in [false, true] {
                if reopen_after_edit {
                    repo.reopen();
                    repo.commit("mod.py", &edited);
                }
                let after = render_bodies(&repo);
                assert_eq!(after.len(), 2, "neither declaration may disappear");
                for (body, old) in &before {
                    let new = &after[body];
                    assert_eq!(old.id, new.id, "identity swapped for body {body}");
                    assert_eq!(old.span, new.span, "neither declaration moved");
                    if body == "render_str(value)" {
                        assert_eq!(old.fingerprint, new.fingerprint);
                    } else {
                        assert_ne!(old.fingerprint.behavior_hash, new.fingerprint.behavior_hash);
                    }
                }
                assert_eq!(relation_endpoints(&repo, &after), endpoints);
            }
        }
    }
}

#[test]
fn swapping_same_signature_declarations_preserves_distinct_body_identity() {
    let int_body = OVERLOAD_INT.replace("value: int) -> int", "value: str) -> str");
    let base = format!("{HELPERS}{int_body}\n{OVERLOAD_STR}");
    let edited = format!("{HELPERS}{OVERLOAD_STR}\n{int_body}");
    for reopen_before_edit in [false, true] {
        let mut repo = LiveRepo::new();
        repo.commit("mod.py", &base);
        let before = render_bodies(&repo);
        assert_eq!(before.len(), 2);
        let endpoints = relation_endpoints(&repo, &before);
        if reopen_before_edit {
            repo.reopen();
        }
        repo.commit("mod.py", &edited);
        for reopen_after_edit in [false, true] {
            if reopen_after_edit {
                repo.reopen();
                repo.commit("mod.py", &edited);
            }
            let after = render_bodies(&repo);
            assert_eq!(after.len(), 2);
            for (body, old) in &before {
                assert_eq!(old.id, after[body].id, "identity swapped for {body}");
                assert_eq!(old.fingerprint, after[body].fingerprint);
            }
            assert_eq!(relation_endpoints(&repo, &after), endpoints);
        }
    }
}

#[test]
fn inserting_a_declaration_at_a_carried_members_old_position_adds_a_fresh_identity() {
    let base = format!("{HELPERS}{OVERLOAD_STR}");
    let edited = format!("{HELPERS}{OVERLOAD_INT}\n{OVERLOAD_STR}");
    let mut repo = LiveRepo::new();
    repo.commit("mod.py", &base);
    let before = render_bodies(&repo);
    repo.reopen();
    let delta = repo.commit("mod.py", &edited);
    let additions = delta
        .entity_deltas
        .iter()
        .filter_map(|change| match change {
            EntityDelta::Added { new } if new.name == "render" => Some(new.id),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(
        additions.len(),
        1,
        "the new declaration must be admitted once"
    );
    assert!(!delta
        .entity_deltas
        .iter()
        .any(|change| matches!(change, EntityDelta::Removed { .. })));
    for reopened in [false, true] {
        if reopened {
            repo.reopen();
            repo.commit("mod.py", &edited);
        }
        let after = render_bodies(&repo);
        assert_eq!(after.len(), 2);
        assert_eq!(
            before["render_str(value)"].id,
            after["render_str(value)"].id
        );
        assert_eq!(additions[0], after["render_int(value)"].id);
        assert_ne!(after["render_int(value)"].id, after["render_str(value)"].id);
        let endpoints = relation_endpoints(&repo, &after);
        for helper in ["render_int", "render_str"] {
            let target = repo
                .graph
                .list_all_entities()
                .expect("entities")
                .into_iter()
                .find(|entity| entity.name == helper)
                .expect("helper");
            assert!(
                endpoints.contains(&(
                    GraphNodeId::Entity(after[&format!("{helper}(value)")].id),
                    GraphNodeId::Entity(target.id),
                    RelationKind::Calls,
                )),
                "the call to {helper} must use its declaration's carried or fresh id"
            );
        }
    }
}

#[test]
fn a_planner_retained_rename_keeps_identity_with_a_same_signature_sibling() {
    let named_before = OVERLOAD_INT.replace("def render(", "def render_before(");
    let base = format!("{HELPERS}{named_before}\n{OVERLOAD_STR}");
    let edited = base.replace(
        "def render_before(value: int) -> int",
        "def render(value: str) -> str",
    );
    let mut repo = LiveRepo::new();
    repo.commit("mod.py", &base);
    let old = repo
        .graph
        .list_all_entities()
        .expect("entities")
        .into_iter()
        .find(|entity| entity.name == "render_before")
        .expect("renamed member");
    let sibling = render_bodies(&repo)["render_str(value)"].clone();
    repo.reopen();

    // Parse real CAS bytes, then retain the chosen entity id as a semantic
    // rename planner does. Remap its relation and layout references as well.
    let hash = repo.blobs.write(edited.as_bytes()).expect("rename source");
    let mut indexed = kin_index::IndexPipeline::new()
        .index_file_content_with_tests(
            &kin_model::FilePathId::new("mod.py"),
            edited.as_bytes(),
            hash,
        )
        .expect("real parser")
        .indexed_file;
    let renamed = indexed
        .entities
        .iter_mut()
        .find(|entity| {
            entity.name == "render"
                && entity.span.as_ref().is_some_and(|span| {
                    edited[span.start_byte..span.end_byte].contains("render_int(value)")
                })
        })
        .expect("parsed renamed declaration");
    let parser_id = renamed.id;
    assert_ne!(
        parser_id, old.id,
        "a rename must retain an explicit, non-parser id"
    );
    renamed.id = old.id;
    for relation in &mut indexed.relations {
        if relation.src == GraphNodeId::Entity(parser_id) {
            relation.src = GraphNodeId::Entity(old.id);
        }
        if relation.dst == GraphNodeId::Entity(parser_id) {
            relation.dst = GraphNodeId::Entity(old.id);
        }
    }
    for region in &mut indexed.file_layout.regions {
        if let kin_model::SourceRegion::EntityRef { entity_id, .. } = region {
            if *entity_id == parser_id {
                *entity_id = old.id;
            }
        }
    }
    let result = repo
        .reconciler
        .reconcile_indexed_content(&indexed, &repo.blobs, &repo.graph)
        .expect("graph-authoritative rename");
    assert!(!result.delta.entity_deltas.iter().any(|change| matches!(
        change,
        EntityDelta::Added { .. } | EntityDelta::Removed { .. }
    )));
    repo.graph
        .apply_transaction_delta(&result.delta)
        .expect("apply rename");
    for reopened in [false, true] {
        if reopened {
            repo.reopen();
            repo.commit("mod.py", &edited);
        }
        let after = render_bodies(&repo);
        assert_eq!(after.len(), 2);
        assert_eq!(after["render_int(value)"].id, old.id);
        assert_eq!(after["render_str(value)"].id, sibling.id);
        assert_eq!(after["render_int(value)"].signature, sibling.signature);
        let endpoints = relation_endpoints(&repo, &after);
        for helper in ["render_int", "render_str"] {
            let target = repo
                .graph
                .list_all_entities()
                .expect("entities")
                .into_iter()
                .find(|entity| entity.name == helper)
                .expect("helper");
            assert!(endpoints.contains(&(
                GraphNodeId::Entity(after[&format!("{helper}(value)")].id),
                GraphNodeId::Entity(target.id),
                RelationKind::Calls,
            )));
        }
    }
}
