// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! FIR-2828. The scripted check for the class where a completeness denominator
//! never reaches the store it is supposed to qualify.
//!
//! `kin_mcp::caller_arrival` decides whether an absence may be certified by
//! subtracting a file's resolved `Calls` edges from the call sites the parser
//! read there. The parse side of that subtraction is
//! [`kin_parser::FILE_PARSED_CALL_SITES_KEY`], and on a converted Python
//! repository it was absent from every file: the extractor withheld it from any
//! file whose call extraction it could not fully represent, which on real Python
//! is nearly all of them. So the gate had no numerator to subtract from, every
//! file landed in its absent-count branch, and a file whose every call became an
//! edge was indistinguishable from one holding calls the graph never saw.
//!
//! Two claims are asserted here and they are different. The first is that the
//! count is the file's WHOLE call side rather than the relations extraction
//! managed to emit, because a short count subtracts to zero and reads as a fully
//! accounted file. The second is that the count survives the conversion path, so
//! the gate is not keyed on a signal only a hand-built fixture emits.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::path::Path;
use std::process::{Command, Output};

use kin_blobs::BlobStore;
use kin_git::{
    admit_semantic_git_import, capture_lossless_git_repository, plan_semantic_git_import,
};
use kin_index::{derive_historical_semantic_deltas, IndexPipeline};
use kin_model::{
    ChangeStore, Entity, EntityDelta, FilePathId, Relation, RelationDelta, RelationKind,
    RepositoryId, SemanticChange,
};

/// The focal's file. Nothing here reaches outward, so it never joins its own
/// family.
const STORE_PY: &str = r#"def open_db():
    return {}


def note_body(db, note_id):
    return ""
"#;

/// A family file with no shortfall: two call sites, and the linker records an
/// edge for both. The receiver call is what made the extractor withhold this
/// file's count, and it is also an edge the graph holds.
const CLEAN_PY: &str = r#"from notepkg import store
from notepkg.store import note_body


def summarize(note_id):
    db = store.open_db()
    return note_body(db, note_id)
"#;

/// A family file with a real shortfall: three call sites, two relations. The
/// subscript callee has no name the extractor can bind, so it produces no
/// relation at all and a count taken off the relations cannot see it.
const MESSY_PY: &str = r#"from notepkg import store
from notepkg.store import note_body


def summarize_messy(note_id, handlers):
    db = store.open_db()
    body = note_body(db, note_id)
    return handlers["render"](body)
"#;

fn blob_hash() -> kin_blobs::Hash256 {
    kin_blobs::Hash256::from_bytes([9; 32])
}

fn index(path: &str, source: &str) -> kin_index::IndexedFile {
    IndexPipeline::new()
        .index_file_content_with_tests(&FilePathId::new(path), source.as_bytes(), blob_hash())
        .unwrap_or_else(|error| panic!("indexing {path} failed: {error}"))
        .indexed_file
}

/// The one count every entity of a file carries, read the way every consumer
/// reads it.
fn stamped_call_sites(entities: &[Entity], path: &str) -> Option<u64> {
    let of_file: Vec<&Entity> = entities
        .iter()
        .filter(|entity| entity.file_origin.as_ref().is_some_and(|f| f.0 == path))
        .collect();
    assert!(
        !of_file.is_empty(),
        "no entity of {path} reached the store, so its count would be absent for the wrong reason"
    );
    let counts: BTreeSet<Option<u64>> = of_file
        .iter()
        .map(|entity| {
            entity
                .metadata
                .extra
                .get(kin_parser::FILE_PARSED_CALL_SITES_KEY)
                .and_then(serde_json::Value::as_u64)
        })
        .collect();
    assert_eq!(
        counts.len(),
        1,
        "every entity of {path} must carry the same count, since a consumer settles the file on \
         whichever entity it reads first: {counts:?}"
    );
    counts.into_iter().next().expect("one count")
}

fn emitted_call_relations(indexed: &kin_index::IndexedFile) -> usize {
    indexed
        .extracted_relations
        .iter()
        .filter(|relation| relation.kind == RelationKind::Calls)
        .count()
}

/// The claim the gate's arithmetic rests on: the stamped number is the file's
/// whole call side, not the relations extraction managed to emit.
///
/// `messy.py` writes three calls. Two carry a name the extractor can bind and
/// become relations; `handlers["render"](body)` does not and becomes nothing.
/// A count taken off the relations reports two, the graph resolves two, and the
/// subtraction finds no shortfall on a file holding a call the graph never saw.
#[test]
fn a_file_whose_callee_cannot_be_named_still_reports_every_call_site() {
    let indexed = index("notepkg/messy.py", MESSY_PY);

    assert_eq!(
        emitted_call_relations(&indexed),
        2,
        "the fixture must hold exactly one call the extractor cannot represent, or it is not \
         testing the gap between the two numbers"
    );
    assert_eq!(
        stamped_call_sites(&indexed.entities, "notepkg/messy.py"),
        Some(3),
        "the stamped count must be every call site the file holds, including the one that \
         produced no relation"
    );
}

/// The control, and it is what keeps the change from being a blanket inflation.
/// A file whose every call site became a relation reports exactly the number it
/// always reported, so no reading that was already right moves.
#[test]
fn a_file_whose_calls_all_became_relations_reports_the_number_it_always_did() {
    let indexed = index("notepkg/clean.py", CLEAN_PY);

    let emitted = emitted_call_relations(&indexed);
    assert_eq!(
        emitted, 2,
        "the control fixture must emit both of its calls"
    );
    assert_eq!(
        stamped_call_sites(&indexed.entities, "notepkg/clean.py"),
        Some(emitted as u64),
        "a file with nothing unrepresentable must report the relation count, or the census and \
         the relations disagree where they must not"
    );
}

/// A call written where no callable entity owns the edge is still a call site
/// the graph holds no edge for, so it counts. Module scope is the cheapest
/// instance and the one a converted repository is full of.
#[test]
fn a_call_outside_every_function_body_is_still_a_call_site() {
    let indexed = index(
        "notepkg/toplevel.py",
        "from notepkg import store\n\nDB = store.open_db()\n\n\ndef reader(note_id):\n    return DB\n",
    );

    assert_eq!(
        emitted_call_relations(&indexed),
        0,
        "a module-scope call owns no calling entity, so the extractor emits no relation for it"
    );
    assert_eq!(
        stamped_call_sites(&indexed.entities, "notepkg/toplevel.py"),
        Some(1),
        "and it is still a call site, so the file's count is one rather than absent or zero"
    );
}

/// The join, over the path a brownfield repository actually takes. Every claim
/// above is about one parse; this is about what a converted store holds, which
/// is the surface `kin graph status` and `caller_arrival` read.
#[test]
fn every_file_of_a_converted_history_carries_its_call_count() {
    let dir = tempfile::tempdir().unwrap();
    let repo = admit_repository(
        dir.path(),
        "fir2828-parse-side-counts",
        &[
            ("notepkg/__init__.py", ""),
            ("notepkg/store.py", STORE_PY),
            ("notepkg/clean.py", CLEAN_PY),
            ("notepkg/messy.py", MESSY_PY),
        ],
    );

    let mut files: BTreeSet<String> = BTreeSet::new();
    for entity in &repo.entities {
        // An external reference target stands for a symbol another repository
        // owns. It has no file, so it has no call side and is not what this is
        // about.
        if kin_index::is_external_reference_target(entity) {
            continue;
        }
        if let Some(file) = entity.file_origin.as_ref() {
            files.insert(file.0.clone());
        }
    }
    assert_eq!(
        files.iter().cloned().collect::<Vec<_>>(),
        vec![
            "notepkg/__init__.py".to_string(),
            "notepkg/clean.py".to_string(),
            "notepkg/messy.py".to_string(),
            "notepkg/store.py".to_string(),
        ],
        "the conversion must hold entities for every file, or a missing count below would be \
         missing for the wrong reason"
    );

    let mut unmeasured = Vec::new();
    for file in &files {
        if stamped_call_sites(&repo.entities, file).is_none() {
            unmeasured.push(file.clone());
        }
    }
    assert!(
        unmeasured.is_empty(),
        "a converted store must carry a parse-side call count for every file whose entities it \
         holds; these carry none: {unmeasured:?}"
    );

    assert_eq!(
        stamped_call_sites(&repo.entities, "notepkg/messy.py"),
        Some(3),
        "and the count that survives conversion is the whole call side, not the relations"
    );
    assert_eq!(
        stamped_call_sites(&repo.entities, "notepkg/clean.py"),
        Some(2),
        "while the file with nothing unrepresentable is unchanged"
    );
}

/// One admitted repository, reduced to the entity and relation state its
/// first-parent history replays to.
struct AdmittedRepository {
    entities: Vec<Entity>,
    #[allow(dead_code)]
    relations: Vec<Relation>,
}

/// Build a Git repository from `files`, admit it exactly as `kin init` does,
/// and replay its first-parent history into entity and relation state.
fn admit_repository(dir: &Path, repository_id: &str, files: &[(&str, &str)]) -> AdmittedRepository {
    std::fs::create_dir_all(dir).unwrap();
    git_ok(dir, ["init", "--quiet", "--initial-branch", "main"]);
    git_ok(dir, ["config", "user.name", "Fixture"]);
    git_ok(dir, ["config", "user.email", "fixture@example.invalid"]);
    for (path, body) in files {
        let file = dir.join(path);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, body).unwrap();
    }
    git_ok(dir, ["add", "--all"]);
    git_ok(dir, ["commit", "--quiet", "--message", "seed"]);

    let blob_store = BlobStore::new(dir.join(".fixture-cas")).unwrap();
    let snapshot = capture_lossless_git_repository(
        dir,
        RepositoryId::new(repository_id).unwrap(),
        &blob_store,
    )
    .unwrap();
    let plan = plan_semantic_git_import(&snapshot, &blob_store).unwrap();
    let trees = plan
        .aliases
        .iter()
        .map(|alias| {
            (
                alias.change_id,
                plan.commit_trees
                    .get(&alias.oid)
                    .expect("every imported commit has an exact resolved tree")
                    .clone(),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let bindings = derive_historical_semantic_deltas(&plan.changes, &trees, &blob_store)
        .unwrap()
        .into_iter()
        .map(|delta| {
            kin_git::HistoricalSemanticBinding::owned(
                delta.change_id,
                delta.entity_deltas,
                delta.relation_deltas,
            )
        })
        .collect::<Vec<_>>();
    let admitted = admit_semantic_git_import(
        &plan
            .with_historical_semantics(&blob_store, bindings)
            .unwrap(),
        &blob_store,
    )
    .unwrap();
    admitted.validate(&blob_store).unwrap();

    let graph = kin_db::InMemoryGraph::new();
    for change in &admitted.changes {
        graph.create_change(change).unwrap();
    }
    let head = admitted
        .changes
        .iter()
        .map(|change| change.id)
        .find(|candidate| {
            !admitted
                .changes
                .iter()
                .any(|change| change.parents.contains(candidate))
        })
        .expect("history must have a head");
    graph
        .resolve_graph_at(&head)
        .expect("admitted history must replay");

    replay_first_parent(&admitted.changes)
}

/// Apply every change's deltas in parent-first order, the way durable authority
/// replay derives the state a workspace reports.
fn replay_first_parent(changes: &[SemanticChange]) -> AdmittedRepository {
    let known: BTreeSet<_> = changes.iter().map(|change| change.id).collect();
    let mut applied = BTreeSet::new();
    let mut ordered = Vec::with_capacity(changes.len());
    while ordered.len() < changes.len() {
        let next = changes
            .iter()
            .find(|change| {
                !applied.contains(&change.id)
                    && change
                        .parents
                        .iter()
                        .all(|parent| !known.contains(parent) || applied.contains(parent))
            })
            .expect("the admitted change set must be a DAG rooted in this history");
        applied.insert(next.id);
        ordered.push(next);
    }

    let mut entities = BTreeMap::new();
    let mut relations = BTreeMap::new();
    for change in ordered {
        for delta in &change.entity_deltas {
            match delta {
                EntityDelta::Added { new } | EntityDelta::Modified { new, .. } => {
                    entities.insert(new.id, new.clone());
                }
                EntityDelta::Removed { old } => {
                    entities.remove(&old.id);
                }
            }
        }
        for delta in &change.relation_deltas {
            match delta {
                RelationDelta::Added { new } | RelationDelta::Modified { new, .. } => {
                    relations.insert(new.id, new.clone());
                }
                RelationDelta::Removed { old } => {
                    relations.remove(&old.id);
                }
            }
        }
    }

    AdmittedRepository {
        entities: entities.into_values().collect(),
        relations: relations.into_values().collect(),
    }
}

fn git_ok<I, S>(repo: &Path, args: I)
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let output = git_output(repo, args);
    assert!(
        output.status.success(),
        "git failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn git_output<I, S>(repo: &Path, args: I) -> Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    Command::new("git")
        .current_dir(repo)
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .output()
        .expect("git runs")
}
