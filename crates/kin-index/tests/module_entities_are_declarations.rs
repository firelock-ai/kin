// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! A method call contributes no entity, and every `Module` entity is a
//! declaration with a file origin.
//!
//! FIR-2819. Measured on production, `Module` was the most common entity kind
//! in the graph and most of it was not modules: 30,240 of 63,356 entities
//! across five repositories, of which 29,422 carried no file path and 29,201
//! had a `.` or a `(` in the name. The verbatim samples were `sig_str.join`,
//! `std::io::stdin().read_to_string`, `Math.random` and `"structured".into`,
//! which are the receiver expressions of method calls. The discriminator was
//! exact: of `kin`'s 21,526 `Module` entities, the 664 carrying a file path all
//! had clean names and read as real `mod` declarations.
//!
//! The producer was one tier. A member call whose receiver no tier could settle
//! was recorded as a placeholder edge whose destination id was derived from the
//! receiver STRING, and the entity synthesized to back that destination was
//! named `{receiver_leaf}.{symbol}` with `EntityKind::Module` and no file
//! origin. `"a.rs".into()` reached it as receiver `"a.rs"`, whose leaf after
//! the final dot is `rs"`, which is where the 101 first segments spelled `rs"`
//! came from.
//!
//! `kin-model`'s external-reference module already states the rule that tier
//! broke: parser spelling stays relation evidence until a resolver can bind it,
//! and only a resolver-issued coordinate earns a persisted identity. The tier
//! took unresolved parser spelling and gave it one, through the entity door.
//!
//! Every fixture here goes through the real git admission path, because that is
//! the path that synthesizes these entities. The live reconcile path drops the
//! edge instead, so a fixture built that way could not see the class at all.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::path::Path;
use std::process::{Command, Output};

use kin_blobs::BlobStore;
use kin_git::{
    admit_semantic_git_import, capture_lossless_git_repository, plan_semantic_git_import,
};
use kin_index::derive_historical_semantic_deltas;
use kin_model::{
    ChangeStore, Entity, EntityDelta, EntityKind, Relation, RelationDelta, RelationKind,
    RepositoryId, SemanticChange,
};

/// One admitted repository, reduced to the entity and relation state its
/// first-parent history replays to.
struct AdmittedRepository {
    entities: Vec<Entity>,
    relations: Vec<Relation>,
}

impl AdmittedRepository {
    fn modules(&self) -> Vec<&Entity> {
        self.entities
            .iter()
            .filter(|entity| entity.kind == EntityKind::Module)
            .collect()
    }

    fn describe(&self) -> String {
        let mut rows: Vec<String> = self
            .entities
            .iter()
            .map(|entity| {
                format!(
                    "  {:?} {:?} file={:?}",
                    entity.kind,
                    entity.name,
                    entity.file_origin.as_ref().map(|file| file.0.clone())
                )
            })
            .collect();
        rows.sort();
        rows.join("\n")
    }
}

/// Two module declarations, and eleven method calls whose receivers are locals
/// this repository does not define a method for.
///
/// Every call here took the removed tier on the tree this fixture is written
/// against: `parts.join`, `raw.trim`, `text.split`, `seen.insert`, and the
/// three string-literal receivers that produced the name fragments the ticket
/// samples. `"a.rs".into()` is the one that made `rs"`.
const RUST_LIB: &str = r#"mod alpha;
mod beta;

use std::collections::BTreeSet;

pub fn run(raw: &str) -> String {
    let text = raw.trim();
    let parts: Vec<&str> = text.split(',').collect();
    let mut seen = BTreeSet::new();
    for part in &parts {
        seen.insert(part.to_string());
    }
    let joined = parts.join("-");
    let owned: String = "structured".into();
    let suffixed: String = "a.rs".into();
    let padded = joined.to_uppercase();
    format!("{padded}{owned}{suffixed}{}", seen.len())
}
"#;

/// The first control: module declarations and no method calls at all. Its
/// `Module` count must not move, because nothing here ever reached the tier.
const RUST_DECLARATIONS_ONLY: &str = r#"mod gamma;
mod delta;

pub const LIMIT: usize = 7;
"#;

const RUST_ALPHA: &str = "pub fn alpha_helper() -> usize {\n    1\n}\n";
const RUST_BETA: &str = "pub fn beta_helper() -> usize {\n    2\n}\n";
const RUST_GAMMA: &str = "pub fn gamma_helper() -> usize {\n    3\n}\n";
const RUST_DELTA: &str = "pub fn delta_helper() -> usize {\n    4\n}\n";

/// The second control, and the one that fails if the removal went too far: a
/// call whose destination this repository really does define must keep its
/// edge. `caller` calls `alpha_helper`, which `src/alpha.rs` declares.
const RUST_CALLER: &str = r#"use crate::alpha::alpha_helper;

pub fn caller() -> usize {
    alpha_helper()
}
"#;

#[test]
fn a_method_call_contributes_no_module_entity() {
    let root = tempfile::tempdir().unwrap();
    let repo = admit_repository(
        &root.path().join("rust"),
        "frag-rust",
        &[
            ("src/lib.rs", RUST_LIB),
            ("src/alpha.rs", RUST_ALPHA),
            ("src/beta.rs", RUST_BETA),
            ("src/caller.rs", RUST_CALLER),
        ],
    );

    let modules = repo.modules();

    // The fragment tell, asserted first and on its own, because it is the claim
    // that is exactly about this defect: the removed tier named its targets
    // `{receiver_leaf}.{symbol}`, so a `.` or a `(` in a Module name is the
    // signature of a call expression whatever else is true of the row.
    let fragments: Vec<String> = modules
        .iter()
        .filter(|entity| entity.name.contains('.') || entity.name.contains('('))
        .map(|entity| entity.name.clone())
        .collect();
    assert!(
        fragments.is_empty(),
        "no Module name may carry a `.` or a `(`, which is what a method-call \
         receiver looks like: {fragments:?}\nall entities:\n{}",
        repo.describe()
    );

    // The second claim, and it is NOT the first one restated. Production showed
    // 20,862 pathless Module entities against 20,761 carrying a `.`, so the two
    // populations differ by about a hundred rows: the cross-repo import class,
    // which is pathless too and is named by a real imported symbol rather than
    // by an expression. That class stays, so the claim here is not that every
    // Module has a file, it is that a pathless one is backed by an import this
    // repository actually wrote. A Module with neither is a fabrication.
    let unbacked: Vec<String> = modules
        .iter()
        .filter(|entity| entity.file_origin.is_none())
        .filter(|entity| !is_import_backed(&repo, entity))
        .map(|entity| entity.name.clone())
        .collect();
    assert!(
        unbacked.is_empty(),
        "a Module entity carries a file it is declared in, or an import naming \
         the module it came from; these carry neither: {unbacked:?}\nall \
         entities:\n{}",
        repo.describe()
    );

    // The call the repository really does define keeps its edge, so the fix is
    // a removal of fabrication and not a removal of resolution.
    let caller = repo
        .entities
        .iter()
        .find(|entity| entity.name == "caller")
        .unwrap_or_else(|| panic!("the fixture declares `caller`:\n{}", repo.describe()));
    let target = repo
        .entities
        .iter()
        .find(|entity| entity.name == "alpha_helper")
        .unwrap_or_else(|| panic!("the fixture declares `alpha_helper`:\n{}", repo.describe()));
    assert!(
        repo.relations.iter().any(|relation| {
            relation.kind == RelationKind::Calls
                && relation.src.as_entity() == Some(caller.id)
                && relation.dst.as_entity() == Some(target.id)
        }),
        "the call to a function this repository declares must survive; \
         relations from `caller`: {:?}",
        repo.relations
            .iter()
            .filter(|relation| relation.src.as_entity() == Some(caller.id))
            .map(|relation| (relation.kind, relation.dst))
            .collect::<Vec<_>>()
    );
}

#[test]
fn a_repository_of_declarations_and_no_method_calls_is_unaffected() {
    let root = tempfile::tempdir().unwrap();
    let repo = admit_repository(
        &root.path().join("control"),
        "frag-control",
        &[
            ("src/lib.rs", RUST_DECLARATIONS_ONLY),
            ("src/gamma.rs", RUST_GAMMA),
            ("src/delta.rs", RUST_DELTA),
        ],
    );

    let names: BTreeSet<String> = repo
        .modules()
        .iter()
        .map(|entity| entity.name.clone())
        .collect();

    assert_eq!(
        names,
        ["delta", "gamma"]
            .into_iter()
            .map(str::to_string)
            .collect::<BTreeSet<_>>(),
        "a file that declares two modules and calls no method contributes \
         exactly those two module entities and nothing else:\n{}",
        repo.describe()
    );
}

/// The class that stays, asserted present rather than assumed absent.
///
/// Without this the pathless claim above is vacuous: a fixture that mints no
/// placeholder of either class satisfies it by producing nothing. This one
/// imports a symbol no file here defines, which is the shape the cross-repo
/// tier answers, and pins that what comes back is named by the symbol the
/// source wrote and carries the module it came from.
#[test]
fn a_cross_repo_import_still_earns_its_pathless_module_and_names_a_symbol() {
    let root = tempfile::tempdir().unwrap();
    let repo = admit_repository(
        &root.path().join("consumer"),
        "frag-consumer",
        &[(
            "src/app.rs",
            "use provider::do_work;\n\npub fn run_task() -> u32 {\n    do_work()\n}\n",
        )],
    );

    let modules = repo.modules();
    let pathless: Vec<&&Entity> = modules
        .iter()
        .filter(|entity| entity.file_origin.is_none())
        .collect();

    assert_eq!(
        pathless.len(),
        1,
        "an import of a symbol nothing here defines must produce exactly one \
         cross-repo target:\n{}",
        repo.describe()
    );
    let target = pathless[0];
    assert_eq!(
        target.name,
        "do_work",
        "and it is named by the symbol the source imported, not by an \
         expression:\n{}",
        repo.describe()
    );
    assert!(
        is_import_backed(&repo, target),
        "and it carries the module it came from, which is the coordinate the \
         spine resolves it by: {:?}",
        repo.relations
            .iter()
            .filter(|relation| relation.dst.as_entity() == Some(target.id))
            .map(|relation| relation.import_source.clone())
            .collect::<Vec<_>>()
    );
}

/// Whether a pathless entity is the destination of a relation naming the module
/// it came from.
///
/// This is what separates the class that stays from the class that went. A
/// cross-repo import placeholder carries a non-empty `import_source`, which is
/// the resolver coordinate the spine binds it by. The receiver placeholder
/// carried none, because there was no module to name, which is exactly why its
/// identity had to be invented out of the receiver's spelling.
fn is_import_backed(repo: &AdmittedRepository, entity: &Entity) -> bool {
    repo.relations.iter().any(|relation| {
        relation.dst.as_entity() == Some(entity.id)
            && relation
                .import_source
                .as_deref()
                .is_some_and(|source| !source.trim().is_empty())
    })
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

    // Admission fails closed on a relation naming a destination entity the tree
    // does not define, so this replay is also the assertion that removing the
    // synthesized targets removed the edges that named them. A surviving
    // placeholder edge makes `derive_historical_semantic_deltas` return an
    // error above rather than reaching here.
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
