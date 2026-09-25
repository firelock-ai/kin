// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Language-server obligations settle through the parser occurrence they cite.
//!
//! When a target leaves, every relation into it retires, and a surviving
//! caller's bindings are kept as debt until a later parse proves each one
//! retained or removed. A language-server relation cites a name token rather
//! than a site the parser records, so under load, when pyright answered before
//! the target left, its obligations could never be matched and the caller kept
//! them after it had dropped every use of the name. These tests pin the rule
//! that replaces that: the cited token belongs to a parser occurrence, and the
//! obligation lives exactly as long as that occurrence does, unless a relation
//! of its own kind at the kept occurrence resolves to the same target again.
//!
//! Every parser relation here comes from real source. The language-server
//! relations are installed by hand, shaped like the ones pyright produced in
//! the failing runs, because what they cite is the point of the tests.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use kin_blobs::BlobStore;
use kin_db::storage::binding_history::BindingHistoryVerifier as _;
use kin_db::{GraphSnapshot, InMemoryGraph, KinDbError};
use kin_index::binding_debt::{
    inspect_local_binding_debt, obligation_is_satisfied, parser_owns_binding, LocalBindingDebt,
    LocalBindingObligation,
};
use kin_index::binding_history::LocalBindingHistoryVerifier;
use kin_index::{IndexPipeline, IndexedFile};
use kin_model::{
    ArtifactId, Entity, EntityKind, EntityStore, FilePathId, GraphNodeId, Hash256, LocatedEntry,
    Relation, RelationDelta, RelationEvidence, RelationId, RelationKind, RelationOrigin, RepoPath,
    SourceSpan, TransactionDelta, TreeDelta, TreeEntry,
};
use kin_reconcile::Reconciler;

const TARGET: &str = "def beta(value):\n    return value\n";
const CALLER: &str = "from right import beta\n\ndef run(value):\n    return beta(value) + 2\n";
const STILL_CALLING: &str =
    "from right import beta\n\n# unchanged use\ndef run(value):\n    return beta(value) + 2\n";
const MOVED: &str = "from right import beta\n\ndef run(value):\n    return value + 2\n\n\
                     def other(value):\n    return beta(value)\n";
const DROPPED: &str = "def run(value):\n    return value + 9\n";

struct Repo {
    _root: tempfile::TempDir,
    blobs: BlobStore,
    graph: Arc<InMemoryGraph>,
    reconciler: Reconciler,
}

impl Repo {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let blobs = BlobStore::new(root.path().join("blobs")).unwrap();
        let graph = Arc::new(InMemoryGraph::new());
        let mut reconciler = Reconciler::new(root.path().to_owned());
        reconciler.seed_cross_file_linker_from_graph(graph.as_ref());
        Self {
            _root: root,
            blobs,
            graph,
            reconciler,
        }
    }

    /// Admit `source` at `file` and reconcile it through the live path.
    fn edit(&mut self, file: &str, source: &str) {
        let blob = self.blobs.write(source.as_bytes()).unwrap();
        let path = RepoPath::from_utf8(file).unwrap();
        let new = LocatedEntry::new(
            path.clone(),
            TreeEntry::blob(Hash256::from_bytes(blob.0), false),
        );
        let tree_delta = match self.graph.get_tree_entry(&FilePathId::new(file)).unwrap() {
            Some(old) => TreeDelta::Updated {
                artifact_id: self.graph.artifact_id_at_path(&path).unwrap(),
                old: LocatedEntry::new(path, old),
                new,
            },
            None => TreeDelta::Added {
                artifact_id: ArtifactId::new(),
                new,
            },
        };
        self.graph
            .apply_transaction_delta(&TransactionDelta {
                tree_deltas: vec![tree_delta],
                ..Default::default()
            })
            .unwrap();
        let indexed = parse(file, source);
        let result = self
            .reconciler
            .reconcile_indexed_observation(&indexed, &self.blobs, self.graph.as_ref())
            .expect("real admitted source reconciliation");
        self.graph.apply_transaction_delta(&result.delta).unwrap();
    }

    /// Remove `file` the way canonical admission does: the debt its surviving
    /// callers owe is planned from the relations about to retire, and published
    /// in the same transaction that removes the file.
    fn remove(&mut self, file: &str) {
        let file_id = FilePathId::new(file);
        let path = RepoPath::from_utf8(file).unwrap();
        let artifact = self.graph.artifact_id_at_path(&path).unwrap();
        let entry = self.graph.get_tree_entry(&file_id).unwrap().unwrap();
        let entities: Vec<_> = self
            .graph
            .list_all_entities()
            .unwrap()
            .into_iter()
            .filter(|entity| entity.file_origin.as_ref() == Some(&file_id))
            .collect();
        let departing = entities.iter().map(|entity| entity.id).collect();
        let mut incident = BTreeMap::new();
        for entity in &entities {
            for relation in self.graph.get_all_relations_for_entity(&entity.id).unwrap() {
                incident.insert(relation.id, relation);
            }
        }
        for relation in self
            .graph
            .get_all_relations_for_node(&GraphNodeId::Artifact(artifact))
            .unwrap()
        {
            incident.insert(relation.id, relation);
        }
        let incident: Vec<_> = incident.into_values().collect();
        let mut relations = kin_reconcile::plan_local_binding_obligations(
            &departing,
            &incident,
            |id| Ok(self.graph.get_entity(&id).unwrap()),
            |file| {
                let path = RepoPath::from_utf8(file.0.clone()).unwrap();
                let Some(artifact) = self.graph.artifact_id_at_path(&path) else {
                    return Ok(None);
                };
                Ok(match self.graph.get_tree_entry(file).unwrap() {
                    Some(TreeEntry::Blob { hash, .. }) => Some((artifact, hash)),
                    _ => None,
                })
            },
            |id| {
                Ok(self
                    .graph
                    .get_all_relations_for_node(&GraphNodeId::Artifact(id))
                    .unwrap())
            },
            |id| Ok(self.graph.get_relation_by_id(&id)),
        )
        .expect("plan debt from the relations about to retire");
        relations.extend(
            incident
                .into_iter()
                .map(|old| RelationDelta::Removed { old }),
        );
        self.graph
            .apply_transaction_delta(&TransactionDelta {
                tree_deltas: vec![TreeDelta::Removed {
                    artifact_id: artifact,
                    old: LocatedEntry::new(path, entry),
                }],
                entity_deltas: entities
                    .into_iter()
                    .map(|old| kin_model::EntityDelta::Removed { old })
                    .collect(),
                relation_deltas: relations,
                ..Default::default()
            })
            .expect("publish the removal and its debt in one transaction");
    }

    fn install(&self, relations: &[Relation]) {
        self.graph
            .apply_transaction_delta(&TransactionDelta {
                relation_deltas: relations
                    .iter()
                    .cloned()
                    .map(|new| RelationDelta::Added { new })
                    .collect(),
                ..Default::default()
            })
            .unwrap();
    }

    fn entity(&self, file: &str, kind: EntityKind, name: &str) -> Entity {
        self.graph
            .list_all_entities()
            .unwrap()
            .into_iter()
            .find(|entity| {
                entity.kind == kind
                    && entity.name == name
                    && entity.file_origin.as_ref().is_some_and(|f| f.0 == file)
            })
            .unwrap_or_else(|| panic!("missing {kind:?} {file}:{name}"))
    }

    fn entities_of(&self, file: &str) -> Vec<Entity> {
        self.graph
            .list_all_entities()
            .unwrap()
            .into_iter()
            .filter(|entity| entity.file_origin.as_ref().is_some_and(|f| f.0 == file))
            .collect()
    }

    fn artifact(&self, file: &str) -> ArtifactId {
        self.graph
            .artifact_id_at_path(&RepoPath::from_utf8(file).unwrap())
            .unwrap()
    }

    fn blob(&self, file: &str) -> Hash256 {
        match self.graph.get_tree_entry(&FilePathId::new(file)).unwrap() {
            Some(TreeEntry::Blob { hash, .. }) => hash,
            other => panic!("{file} has no admitted blob: {other:?}"),
        }
    }

    fn debt(&self, source: &str) -> Option<LocalBindingDebt> {
        let artifact = self.artifact(source);
        let relations = self
            .graph
            .get_all_relations_for_node(&GraphNodeId::Artifact(artifact))
            .unwrap();
        inspect_local_binding_debt(
            &FilePathId::new(source),
            artifact,
            self.blob(source),
            &relations.iter().collect::<Vec<_>>(),
        )
        .expect("recorded debt decodes against the current admitted source")
    }

    /// The retired relations `source` still owes, by identity.
    fn owed(&self, source: &str) -> BTreeSet<RelationId> {
        self.debt(source)
            .map(|debt| {
                debt.obligations
                    .iter()
                    .map(|o| o.retired_relation.id)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// What the binding-history verifier makes of one graph transition.
    fn verifies(&self, before: &GraphSnapshot, after: &GraphSnapshot) -> bool {
        let load = |digest: Hash256| -> Result<Option<Vec<u8>>, KinDbError> {
            self.blobs
                .read(&kin_blobs::Hash256::from_bytes(*digest.as_bytes()))
                .map(Some)
                .map_err(|error| KinDbError::StorageError(error.to_string()))
        };
        LocalBindingHistoryVerifier
            .verify_graph_transition(before, after, &load)
            .expect("the verifier reaches a verdict")
    }

    /// Apply one edit and require the verifier to accept the transition.
    fn checked_edit(&mut self, file: &str, source: &str) {
        let before = self.graph.to_snapshot();
        self.edit(file, source);
        let after = self.graph.to_snapshot();
        assert!(
            self.verifies(&before, &after),
            "editing {file} must stay a checked transition"
        );
    }

    fn checked_remove(&mut self, file: &str) {
        let before = self.graph.to_snapshot();
        self.remove(file);
        let after = self.graph.to_snapshot();
        assert!(
            self.verifies(&before, &after),
            "removing {file} must stay a checked transition"
        );
    }
}

fn parse(file: &str, source: &str) -> IndexedFile {
    IndexPipeline::new()
        .index_file_content_with_tests(
            &FilePathId::new(file),
            source.as_bytes(),
            kin_blobs::digest(source.as_bytes()),
        )
        .expect("real source indexing")
        .indexed_file
}

/// `len` bytes of `source` starting at `start`, as a one-line span in `file`.
fn span_at(file: &str, source: &str, start: usize, len: usize) -> SourceSpan {
    let line = source[..start].matches('\n').count() as u32;
    let col = (start - source[..start].rfind('\n').map_or(0, |at| at + 1)) as u32;
    SourceSpan {
        file: FilePathId::new(file),
        start_byte: start,
        end_byte: start + len,
        start_line: line,
        start_col: col,
        end_line: line,
        end_col: col + len as u32,
    }
}

/// A relation shaped like pyright's: language-server origin, one evidence
/// record per token it was reported at.
fn language_server(
    kind: RelationKind,
    rule: &str,
    src: &Entity,
    dst: &Entity,
    at: &[SourceSpan],
) -> Relation {
    Relation {
        id: RelationId::new(),
        kind,
        src: GraphNodeId::Entity(src.id),
        dst: GraphNodeId::Entity(dst.id),
        confidence: 0.95,
        origin: RelationOrigin::Lsp,
        created_in: None,
        import_source: None,
        evidence: at
            .iter()
            .cloned()
            .map(|span| RelationEvidence {
                source_span: Some(span),
                parser_rule: Some(rule.to_string()),
                occurrence_count: 1,
                ..RelationEvidence::default()
            })
            .collect(),
    }
}

/// The caller and target of `CALLER`, with the relations pyright added before
/// the target left: the call, the name at the call and at the import, the
/// module token, and the module `right` itself as a referenced entity.
fn pyright_enriched_caller() -> (Repo, Vec<Relation>) {
    let mut repo = Repo::new();
    repo.edit("right.py", TARGET);
    repo.edit("caller.py", CALLER);
    let run = repo.entity("caller.py", EntityKind::Function, "run");
    let module = repo.entity("caller.py", EntityKind::Module, "caller");
    let beta = repo.entity("right.py", EntityKind::Function, "beta");
    let right = repo.entity("right.py", EntityKind::Module, "right");
    let at_module = span_at("caller.py", CALLER, CALLER.find("right").unwrap(), 5);
    let at_import = span_at("caller.py", CALLER, CALLER.find("beta").unwrap(), 4);
    let at_call = span_at("caller.py", CALLER, CALLER.rfind("beta").unwrap(), 4);
    let enrichment = vec![
        language_server(
            RelationKind::Calls,
            "lsp_call_hierarchy",
            &run,
            &beta,
            std::slice::from_ref(&at_call),
        ),
        language_server(
            RelationKind::References,
            "lsp_definition",
            &run,
            &beta,
            std::slice::from_ref(&at_call),
        ),
        language_server(
            RelationKind::References,
            "lsp_references",
            &module,
            &beta,
            &[at_module, at_import.clone()],
        ),
        language_server(
            RelationKind::UsesType,
            "lsp_references",
            &module,
            &beta,
            &[at_import],
        ),
        language_server(
            RelationKind::References,
            "lsp_references",
            &run,
            &right,
            &[at_call],
        ),
    ];
    repo.install(&enrichment);
    (repo, enrichment)
}

#[test]
fn pyright_obligations_live_exactly_as_long_as_the_occurrences_they_cite() {
    let (mut repo, enrichment) = pyright_enriched_caller();
    repo.checked_remove("right.py");

    let recorded = repo
        .debt("caller.py")
        .expect("the removal records the caller's bindings to beta");
    let owed = repo.owed("caller.py");
    for relation in &enrichment {
        assert!(
            owed.contains(&relation.id),
            "each language-server binding into the departed file is recorded: {:?} {}",
            relation.kind,
            relation.evidence[0]
                .parser_rule
                .as_deref()
                .unwrap_or_default()
        );
    }
    assert!(recorded
        .obligations
        .iter()
        .any(|o| parser_owns_binding(&o.retired_relation)));

    // Kept, moved to another function, and kept again: each body still names
    // beta at the import and at a call, so nothing settles.
    for (stage, body) in [
        ("an unrelated comment", STILL_CALLING),
        ("the call moved into another function", MOVED),
    ] {
        repo.checked_edit("caller.py", body);
        assert_eq!(
            repo.owed("caller.py"),
            owed,
            "{stage}: a kept occurrence keeps every obligation it carries"
        );
    }

    // The caller drops beta. Every obligation, the parser's and pyright's,
    // settles with the occurrences it cited.
    repo.checked_edit("caller.py", DROPPED);
    assert!(
        repo.debt("caller.py").is_none(),
        "a caller that no longer names beta owes nothing: {:?}",
        repo.debt("caller.py")
    );
}

#[test]
fn a_binding_only_a_language_server_saw_stays_owed_while_its_call_remains() {
    const WORK: &str = "def work():\n    return 7\n";
    const DYNAMIC: &str = "def run(callback):\n    return callback()\n";
    const KEPT: &str = "# kept\ndef run(callback):\n    return callback()\n";
    const GONE: &str = "def run(callback):\n    return 7\n";
    let mut repo = Repo::new();
    repo.edit("target.py", WORK);
    repo.edit("caller.py", DYNAMIC);
    let run = repo.entity("caller.py", EntityKind::Function, "run");
    let work = repo.entity("target.py", EntityKind::Function, "work");
    let call = language_server(
        RelationKind::Calls,
        "lsp_call_hierarchy",
        &run,
        &work,
        &[span_at(
            "caller.py",
            DYNAMIC,
            DYNAMIC.rfind("callback").unwrap(),
            8,
        )],
    );
    repo.install(std::slice::from_ref(&call));
    repo.checked_remove("target.py");
    assert_eq!(
        repo.owed("caller.py"),
        BTreeSet::from([call.id]),
        "the parser never bound this call, so the language server's binding is the whole debt"
    );

    repo.checked_edit("caller.py", KEPT);
    assert_eq!(
        repo.owed("caller.py"),
        BTreeSet::from([call.id]),
        "the call it resolved is still there, so the binding is still owed"
    );

    repo.checked_edit("caller.py", GONE);
    assert!(
        repo.debt("caller.py").is_none(),
        "the call is gone, so the binding it carried is settled"
    );
}

/// The Python adapter records a plain read of `beta` as its own reference, so
/// the case that needs the callee rule is a read it records under a wider site:
/// `right.beta`, whose reference site is the whole attribute. Pyright cites the
/// `beta` token inside it, which also sits inside `wrap(...)`.
#[test]
fn a_name_read_inside_a_calls_arguments_is_not_that_call() {
    const PASSING: &str = "import right\n\ndef run(value):\n    return wrap(right.beta)\n\n\
                           def wrap(f):\n    return f\n";
    const REWRAPPED: &str = "import right\n\ndef run(value):\n    return keep(right.beta)\n\n\
                             def keep(f):\n    return f\n";
    let mut repo = Repo::new();
    repo.edit("right.py", TARGET);
    repo.edit("caller.py", PASSING);
    let run = repo.entity("caller.py", EntityKind::Function, "run");
    let beta = repo.entity("right.py", EntityKind::Function, "beta");
    let read = language_server(
        RelationKind::References,
        "lsp_references",
        &run,
        &beta,
        &[span_at(
            "caller.py",
            PASSING,
            PASSING.find("right.beta").unwrap() + "right.".len(),
            4,
        )],
    );
    repo.install(std::slice::from_ref(&read));
    repo.checked_remove("right.py");
    assert!(repo.owed("caller.py").contains(&read.id));

    // `wrap(...)` is gone but beta is still read. The token sat inside that
    // call's site without being its callee, so the call's removal proves
    // nothing about it.
    repo.checked_edit("caller.py", REWRAPPED);
    assert!(
        repo.owed("caller.py").contains(&read.id),
        "beta is still read, so its binding is still owed"
    );
}

/// The settle rule itself, against a kept occurrence: only a relation of the
/// obligation's own kind, cited inside the kept occurrence, into an entity of
/// the same name in the same file, settles it.
#[test]
fn a_kept_occurrence_settles_only_against_the_same_target_again() {
    let (mut repo, enrichment) = pyright_enriched_caller();
    repo.remove("right.py");
    let owed = repo.debt("caller.py").unwrap();
    let reference = &enrichment[1];
    assert_eq!(reference.kind, RelationKind::References);
    let obligation: &LocalBindingObligation = owed
        .obligations
        .iter()
        .find(|o| o.retired_relation.id == reference.id)
        .expect("pyright's reference at the call is owed");

    repo.edit("caller.py", STILL_CALLING);
    repo.edit("other.py", "def beta(value):\n    return value * 3\n");
    repo.edit("right.py", TARGET);
    let run = repo.entity("caller.py", EntityKind::Function, "run");
    let elsewhere = repo.entity("other.py", EntityKind::Function, "beta");
    let restored = repo.entity("right.py", EntityKind::Function, "beta");
    let at_call = span_at(
        "caller.py",
        STILL_CALLING,
        STILL_CALLING.rfind("beta").unwrap(),
        4,
    );
    let at_import = span_at(
        "caller.py",
        STILL_CALLING,
        STILL_CALLING.find("beta").unwrap(),
        4,
    );
    let old = parse("caller.py", CALLER);
    let current = parse("caller.py", STILL_CALLING);
    let entities = repo.entities_of("caller.py");
    let known: BTreeMap<_, _> = [elsewhere.clone(), restored.clone()]
        .into_iter()
        .map(|entity| (entity.id, entity))
        .collect();
    let settles = |produced: Relation| -> bool {
        obligation_is_satisfied(
            repo.graph.as_ref(),
            repo.artifact("caller.py"),
            obligation,
            &old,
            CALLER.as_bytes(),
            &current,
            &entities,
            &[produced],
            &mut |id| Ok(known.get(&id).cloned()),
        )
        .expect("the proof reaches a verdict")
    };

    assert!(
        !settles(language_server(
            RelationKind::References,
            "lsp_references",
            &run,
            &elsewhere,
            std::slice::from_ref(&at_call),
        )),
        "a beta in another file shares the name token and is still a different target"
    );
    assert!(
        !settles(language_server(
            RelationKind::Calls,
            "lsp_call_hierarchy",
            &run,
            &restored,
            std::slice::from_ref(&at_call),
        )),
        "a relation of another kind does not settle a reference"
    );
    assert!(
        !settles(language_server(
            RelationKind::References,
            "lsp_references",
            &run,
            &restored,
            &[at_import],
        )),
        "a relation cited outside the kept call does not settle the call's reference"
    );
    assert!(
        settles(language_server(
            RelationKind::References,
            "lsp_references",
            &run,
            &restored,
            &[at_call],
        )),
        "a reference at the kept call into beta in right.py again settles it"
    );
}

/// The verifier treats a modified relation as retired, so a language-server
/// refinement of one it already published goes through the same proof. Kept at
/// the same occurrence and into the same target, it is a checked transition.
/// Pointed at a different target, it withdraws the binding without recording
/// it, and the transition is refused.
#[test]
fn a_refined_language_server_relation_is_checked_only_while_it_keeps_its_target() {
    let (repo, enrichment) = pyright_enriched_caller();
    // A reference, because the parser's own call from run to beta would
    // re-resolve a language-server call at the same occurrence on its own.
    let call = &enrichment[1];
    assert_eq!(call.kind, RelationKind::References);
    let right = repo.entity("right.py", EntityKind::Module, "right");
    let refine = |new: Relation| {
        let before = repo.graph.to_snapshot();
        repo.graph
            .apply_transaction_delta(&TransactionDelta {
                relation_deltas: vec![RelationDelta::Modified {
                    old: repo.graph.get_relation_by_id(&call.id).unwrap(),
                    new,
                }],
                ..Default::default()
            })
            .unwrap();
        let after = repo.graph.to_snapshot();
        repo.verifies(&before, &after)
    };

    let mut sharper = call.clone();
    sharper.confidence = 1.0;
    sharper.evidence[0].parser_rule = Some("lsp_references".into());
    assert!(
        refine(sharper.clone()),
        "the same reference at the call into the same beta is a kept binding"
    );

    let mut redirected = sharper;
    redirected.dst = GraphNodeId::Entity(right.id);
    assert!(
        !refine(redirected),
        "the reference no longer binds beta and nothing records that it did"
    );
}
