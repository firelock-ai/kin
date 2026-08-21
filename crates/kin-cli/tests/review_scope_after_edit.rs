// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! What a review says about a one-line edit, end to end from the parser.
//!
//! The storage delta for an edit covers every declaration in the touched file:
//! the reconciler stamps that file's blob hash onto all of them, and any added
//! or removed byte shifts the span of every declaration below the edit. Both are
//! real provenance and the published change has to carry them, or the workspace
//! overlay keeps the difference and reports dirty forever.
//!
//! A review is a different question. It asks what a reviewer must look at, and
//! the answer for a one-line edit is the entity that was edited, plus the file's
//! own module entity, whose body is the file and whose fingerprint therefore did
//! move. The module is kept deliberately: suppressing it would hide a content
//! change that really happened. Every other declaration in the file must be
//! absent. These tests drive the real Python parser and the real reconciler,
//! then read the review surfaces, so they fail if either half of that separation
//! breaks.

use std::path::PathBuf;

use kin_blobs::BlobStore;
use kin_db::InMemoryGraph;
use kin_index::FileEvent;
use kin_model::{
    ArtifactId, AuthorId, EntityStore, Hash256, LocatedEntry, RepoPath, SemanticChange,
    SemanticChangeId, Timestamp, TransactionDelta, TreeDelta, TreeEntry,
};
use kin_reconcile::Reconciler;
use tempfile::TempDir;

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

/// The change a commit of this delta would publish.
fn change_from(delta: &TransactionDelta) -> SemanticChange {
    SemanticChange {
        id: SemanticChangeId::from_hash(Hash256::from_bytes([2; 32])),
        origin: kin_model::ChangeOrigin::Native,
        parents: vec![SemanticChangeId::from_hash(Hash256::from_bytes([1; 32]))],
        timestamp: Timestamp::now(),
        author: AuthorId::new("test"),
        message: "edit one line".to_string(),
        entity_deltas: delta.entity_deltas.clone(),
        relation_deltas: delta.relation_deltas.clone(),
        tree_deltas: vec![],
        admission_policy_delta: None,
        projected_files: vec![],
        spec_link: None,
        evidence: vec![],
        risk_summary: None,
        external_reference_deltas: Vec::new(),
    }
}

/// A file with one constant, an `@overload` group, a caller, and a class, so a
/// one-line edit has plenty of untouched company. `ABOVE_THE_EDIT` is declared
/// before `LIMIT`, so its text and its position are both provably untouched by
/// an edit to `LIMIT`: it is this fixture's `REDIRECT_STATI`.
const BASE: &str = r#"from typing import Literal, overload

ABOVE_THE_EDIT: int = 1
REDIRECT_LIMIT: int = 30
BELOW_THE_EDIT: int = 2


@overload
def render(value: str, raw: Literal[True]) -> bytes: ...


@overload
def render(value: str, raw: Literal[False] = False) -> str: ...


def render(value, raw=False):
    return value.encode() if raw else value


def dispatch(value, raw=False):
    return render(value, raw)


class Client:
    def __init__(self):
        self.limit = REDIRECT_LIMIT

    def send(self, value):
        return dispatch(value)
"#;

fn modified_names(diff: &kin_review::SemanticDiff) -> Vec<String> {
    let mut names: Vec<String> = diff
        .modified_entities()
        .into_iter()
        .map(|(_, new)| new.name.clone())
        .collect();
    names.sort();
    names
}

/// FIR-2479's headline falsification. One byte changes, the review names the
/// entity that changed and the file it lives in, and the count of records the
/// storage layer re-emitted is published rather than hidden.
#[test]
fn a_one_line_value_edit_reviews_as_the_edited_entity_and_its_module() {
    let mut repo = LiveRepo::new();
    let first = repo.commit("mod.py", BASE);
    assert!(
        first.entity_deltas.len() >= 8,
        "the fixture must produce a file with several entities, got {}",
        first.entity_deltas.len()
    );

    // The whole edit. One byte shorter, so no line moves and every declaration
    // above it is untouched in text and in position.
    let edited = BASE.replace("REDIRECT_LIMIT: int = 30", "REDIRECT_LIMIT: int = 5");
    assert_ne!(edited, BASE, "the fixture edit must apply");
    assert_eq!(
        edited.lines().count(),
        BASE.lines().count(),
        "this edit must not move a line"
    );

    let delta = repo.commit("mod.py", &edited);
    let stored = delta.entity_deltas.len();
    assert!(
        stored >= 8,
        "the storage delta is expected to carry the whole file; got {stored}"
    );

    let change = change_from(&delta);
    let diff = kin_review::diff_from_change(&change);

    // The edited constant, and the module entity whose body is the file. Nothing
    // else: not the declaration above the edit, not the ones below it, and not
    // one member of the `render` group.
    assert_eq!(
        modified_names(&diff),
        vec!["REDIRECT_LIMIT".to_string(), "mod".to_string()],
        "a one-line value edit must review as the edited entity and its file's module"
    );
    for untouched in [
        "ABOVE_THE_EDIT",
        "BELOW_THE_EDIT",
        "render",
        "dispatch",
        "Client",
        "Client.send",
    ] {
        assert!(
            !modified_names(&diff).contains(&untouched.to_string()),
            "`{untouched}` was not edited and must not be reported as modified"
        );
    }
    assert_eq!(
        diff.provenance_only_entity_changes,
        stored - 2,
        "every record the review set aside must be counted"
    );
}

/// The other half: the review must not report a declaration against a different
/// declaration of the same name, and it must never publish two findings about
/// one name that contradict each other.
///
/// The edit here inserts a block BETWEEN two members of the `render` group, so
/// every later member moves further than the spacing between them. That shape is
/// deliberate: a one-line shift is small enough that pairing by nearest position
/// alone still lands correctly, so a test built on one could not fail when the
/// pairing rule is wrong.
#[test]
fn a_wide_insertion_produces_no_contradictory_breaking_changes() {
    let mut repo = LiveRepo::new();
    repo.commit("mod.py", BASE);

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
        "the insertion must be wider than the spacing between group members"
    );

    let delta = repo.commit("mod.py", &edited);
    let change = change_from(&delta);
    let diff = kin_review::diff_from_change(&change);
    let impact = kin_review::analyze_impact(&repo.graph, &diff).expect("impact");
    let risk = kin_review::assess_risk(&diff, &impact);

    let render_findings: Vec<&String> = risk
        .breaking_changes
        .iter()
        .filter(|finding| finding.contains("render"))
        .collect();
    assert!(
        render_findings.is_empty(),
        "nothing about `render` was edited, so no breaking change may name it: {render_findings:#?}"
    );
    assert!(
        !modified_names(&diff).contains(&"render".to_string()),
        "no member of the `render` group was edited, so none may be reported as modified: {:#?}",
        modified_names(&diff)
    );

    // The cheap invariant a reader can apply by eye: for a signature finding
    // `X: A -> B` there must be no sibling `X: B -> A`.
    let transitions: Vec<(String, String)> = diff
        .modified_entities()
        .into_iter()
        .map(|(old, new)| (old.signature.clone(), new.signature.clone()))
        .collect();
    for (left_old, left_new) in &transitions {
        for (right_old, right_new) in &transitions {
            assert!(
                !(left_old == right_new && left_new == right_old && left_old != left_new),
                "contradictory transitions reported: `{left_old}` -> `{left_new}` alongside \
                 `{right_old}` -> `{right_new}`"
            );
        }
    }
}

/// The positive control. A real signature change on a function with a graph-known
/// caller must survive every rule above, be reported on that function, and reach
/// the breaking-changes list. `dispatch` is used rather than `render` because
/// `render` has three declarations sharing one name, and which of them a call
/// binds to is a separate question that must not decide this test.
#[test]
fn a_real_signature_change_with_a_caller_still_reports_as_breaking() {
    let mut repo = LiveRepo::new();
    repo.commit("mod.py", BASE);

    let edited = BASE.replace(
        "def dispatch(value, raw=False):",
        "def dispatch(value, raw=False, *, trace_id):",
    );
    assert_ne!(edited, BASE, "the fixture edit must apply");
    let delta = repo.commit("mod.py", &edited);

    let change = change_from(&delta);
    let diff = kin_review::diff_from_change(&change);

    assert_eq!(
        modified_names(&diff),
        vec!["dispatch".to_string(), "mod".to_string()],
        "the edited implementation and its file's module are the only entities reported"
    );

    let impact = kin_review::analyze_impact(&repo.graph, &diff).expect("impact");
    let risk = kin_review::assess_risk(&diff, &impact);
    let signature_findings: Vec<&String> = risk
        .breaking_changes
        .iter()
        .filter(|finding| finding.starts_with("Signature change on `dispatch`"))
        .collect();
    assert_eq!(
        signature_findings.len(),
        1,
        "the real signature change must reach the breaking-changes list exactly once, got {:#?}",
        risk.breaking_changes
    );
    assert!(
        signature_findings[0].contains("def dispatch(value, raw=False)")
            && signature_findings[0].contains("trace_id"),
        "the finding must carry the real transition, got {}",
        signature_findings[0]
    );
}
