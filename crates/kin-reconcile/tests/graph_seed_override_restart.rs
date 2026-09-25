// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Persisted override facts survive startup and the live reconcile fold.

use kin_blobs::BlobStore;
use kin_db::{InMemoryGraph, SnapshotManager};
use kin_index::{FileEvent, FileParseData, IncrementalLinker, RelationResolution};
use kin_model::{
    ArtifactId, Entity, EntityId, EntityStore, FilePathId, Hash256, LocatedEntry,
    ParseCompleteness, Relation, RelationEvidence, RelationKind, RepoPath, TransactionDelta,
    TreeDelta, TreeEntry,
};
use kin_reconcile::Reconciler;
use std::collections::HashMap;
use std::sync::Arc;

const BASE: &str = "class Base:\n    def send(self, request):\n        raise NotImplementedError\n    def resolve(self, request):\n        return self.send(request)\n";
const CHILD: &str = "from base import Base as Alias\n\nclass Child(Alias):\n    def send(self, request):\n        return request\n";

fn parse(file: &str, source: &str) -> FileParseData {
    let indexed = kin_index::IndexPipeline::new()
        .index_file_content_with_tests(
            &FilePathId::new(file),
            source.as_bytes(),
            kin_blobs::digest(source.as_bytes()),
        )
        .unwrap()
        .indexed_file;
    FileParseData {
        file_path: file.to_string(),
        entities: indexed.entities,
        relations: indexed.extracted_relations,
        imports: indexed.imports,
    }
}

struct Repo {
    root: tempfile::TempDir,
    blobs: BlobStore,
    graph: Arc<InMemoryGraph>,
    reconciler: Reconciler,
    generation: usize,
}

impl Repo {
    fn new(child: &str) -> Self {
        let root = tempfile::tempdir().unwrap();
        let blobs = BlobStore::new(root.path().join("blobs")).unwrap();
        let graph = Arc::new(InMemoryGraph::new());
        let other = BASE.replace("Base", "OtherBase");
        let sources = [
            ("base.py", BASE),
            ("child.py", child),
            ("other.py", other.as_str()),
        ];
        let files: Vec<_> = sources
            .iter()
            .map(|(file, source)| parse(file, source))
            .collect();
        let artifacts: HashMap<_, _> = files
            .iter()
            .map(|file| (file.file_path.clone(), ArtifactId::new()))
            .collect();
        for (file, source) in sources {
            let blob = blobs.write(source.as_bytes()).unwrap();
            graph
                .apply_transaction_delta(&TransactionDelta {
                    tree_deltas: vec![TreeDelta::Added {
                        artifact_id: artifacts[file],
                        new: LocatedEntry::new(
                            RepoPath::from_utf8(file.to_string()).unwrap(),
                            TreeEntry::blob(Hash256::from_bytes(blob.0), false),
                        ),
                    }],
                    ..TransactionDelta::default()
                })
                .unwrap();
        }
        for file in &files {
            for entity in &file.entities {
                graph.upsert_entity(entity).unwrap();
            }
        }
        for relation in kin_index::link_cross_file(&files, &artifacts).unwrap() {
            graph.upsert_relation(&relation).unwrap();
        }
        let reconciler = Reconciler::new(root.path().to_path_buf());
        let mut repo = Self {
            root,
            blobs,
            graph,
            reconciler,
            generation: 0,
        };
        repo.reopen();
        repo
    }

    fn reopen(&mut self) {
        self.generation += 1;
        let path = self
            .root
            .path()
            .join(format!("snapshot-{}.kindb", self.generation));
        SnapshotManager::save_graph(&path, self.graph.as_ref()).unwrap();
        let manager = SnapshotManager::open_without_text_index(&path).unwrap();
        self.graph = manager.graph();
        self.reconciler = Reconciler::new(self.root.path().to_path_buf());
        self.reconciler
            .seed_lkg_entities_from_graph(self.graph.as_ref());
        self.reconciler
            .seed_cross_file_linker_from_graph(self.graph.as_ref());
    }

    fn edit(&mut self, file: &str, source: &str) -> TransactionDelta {
        let source_path = self.root.path().join(file);
        std::fs::write(&source_path, source).unwrap();
        let old_entry = self
            .graph
            .get_tree_entry(&FilePathId::new(file))
            .unwrap()
            .unwrap();
        let blob = self.blobs.write(source.as_bytes()).unwrap();
        let path = RepoPath::from_utf8(file.to_string()).unwrap();
        self.graph
            .apply_transaction_delta(&TransactionDelta {
                tree_deltas: vec![TreeDelta::Updated {
                    artifact_id: self.graph.artifact_id_at_path(&path).unwrap(),
                    old: LocatedEntry::new(path.clone(), old_entry),
                    new: LocatedEntry::new(
                        path,
                        TreeEntry::blob(Hash256::from_bytes(blob.0), false),
                    ),
                }],
                ..TransactionDelta::default()
            })
            .unwrap();
        let result = self
            .reconciler
            .reconcile_file_change(
                &FileEvent::Changed(source_path),
                &self.blobs,
                self.graph.as_ref(),
            )
            .unwrap();
        let (_, delta) = result.into_parts();
        self.graph.apply_transaction_delta(&delta).unwrap();
        delta
    }

    fn entity(&self, name: &str) -> Entity {
        self.graph
            .list_all_entities()
            .unwrap()
            .into_iter()
            .find(|entity| entity.name == name)
            .unwrap()
    }

    fn call(&self, owner: &str) -> Relation {
        let src = self.entity(&format!("{owner}.resolve")).id;
        let dst = self.entity(&format!("{owner}.send")).id;
        self.graph
            .get_all_relations_for_entity(&src)
            .unwrap()
            .into_iter()
            .find(|relation| {
                relation.kind == RelationKind::Calls
                    && relation.src.as_entity() == Some(src)
                    && relation.dst.as_entity() == Some(dst)
            })
            .unwrap()
    }

    fn overrides(&self, owner: &str) -> Vec<Relation> {
        let dst = self.entity(&format!("{owner}.send")).id;
        self.graph
            .get_all_relations_for_entity(&dst)
            .unwrap()
            .into_iter()
            .filter(|relation| {
                relation.kind == RelationKind::Overrides && relation.dst.as_entity() == Some(dst)
            })
            .collect()
    }

    fn seeded_index(&self) -> IncrementalLinker {
        let mut files: HashMap<String, Vec<Entity>> = HashMap::new();
        for entity in self.graph.list_all_entities().unwrap() {
            files
                .entry(entity.file_origin.as_ref().unwrap().0.clone())
                .or_default()
                .push(entity);
        }
        let mut linker = IncrementalLinker::new();
        for (file, entities) in files {
            let artifact = self
                .graph
                .artifact_id_at_path(&RepoPath::from_utf8(file.clone()).unwrap())
                .unwrap();
            linker.add_file(&file, artifact, &entities);
        }
        linker
    }
}

fn edited_base() -> String {
    BASE.replace(
        "return self.send(request)",
        "normalized = request\n        return self.send(normalized)",
    )
}

/// The call sites `call` carries, after checking its occurrence certificates.
///
/// A parser `Calls` edge carries, beside each site record, one span-free
/// certificate of the tier that site resolved at (`kin_index::occurrence`). A
/// certificate qualifies a site and is never one, so sites are read through
/// the product's own split rather than by counting raw evidence, and the
/// certificates are pinned here instead: one per site, of the current rule,
/// carrying none of a site's fields, valid for this edge, and certifying every
/// site at the edge's own tier. A stale certificate, or one bound to a site the
/// edge no longer carries, fails that validation.
fn certified_sites(call: &Relation) -> Vec<&RelationEvidence> {
    let sites = kin_index::occurrence::original_evidence(call)
        .unwrap_or_else(|| panic!("every occurrence certificate must validate: {call:?}"));
    let certificates: Vec<_> = call
        .evidence
        .iter()
        .filter(|record| kin_index::occurrence::is_certificate(record))
        .collect();
    assert_eq!(
        certificates.len(),
        sites.len(),
        "exactly one occurrence certificate per site: {call:?}"
    );
    for certificate in certificates {
        assert_eq!(
            certificate.parser_rule.as_deref(),
            Some(kin_index::occurrence::OCCURRENCE_RULE)
        );
        assert!(certificate.source_span.is_none());
        assert!(certificate.source_path.is_none());
        assert!(certificate.resolved_path.is_none());
        assert!(certificate.call_shape.is_none());
        assert_eq!(certificate.occurrence_count, 0);
        assert!(certificate.token.is_some());
    }
    let (proven, withheld) = kin_index::occurrence::proven_sites(call);
    assert!(!withheld, "no site may lose its certified tier: {call:?}");
    assert_eq!(proven.len(), sites.len());
    assert!(
        kin_index::occurrence::groups(call).iter().all(|group| {
            group.resolution == RelationResolution::of(call)
                && !group.receiver_name_guess
                && !group.qualification_missing
        }),
        "every site is certified at the edge's own tier: {call:?}"
    );
    sites
}

fn assert_fresh_occurrences(call: &Relation, source: &str, count: usize, dynamic: usize) {
    let sites = certified_sites(call);
    assert_eq!(
        sites.len(),
        count,
        "no extra marker occurrences or stale sites"
    );
    let mut qualified = 0;
    for record in sites {
        let span = record.source_span.as_ref().unwrap();
        let occurrence = &source[span.start_byte..span.end_byte];
        assert!(
            occurrence.starts_with("self.send(") || occurrence.starts_with("Base.send("),
            "{occurrence}"
        );
        assert!(record.call_shape.is_some());
        assert_eq!(record.occurrence_count, 1);
        assert_eq!(
            record.parser_rule.as_deref(),
            Some(kin_index::CALL_SHAPE_EVIDENCE_AGGREGATION_V1)
        );
        if record.token.as_deref() == Some(kin_index::SELF_DISPATCH_OVERRIDE_EVIDENCE_V1) {
            assert!(occurrence.starts_with("self.send("));
            qualified += 1;
        }
    }
    assert_eq!(qualified, dynamic);
}

fn assert_restart(warm: bool) {
    let mut repo = Repo::new(CHILD);
    let initial = repo.call("Base");
    assert_eq!(initial.confidence, 0.86);
    assert!(!repo.root.path().join("child.py").exists());
    if warm {
        repo.edit(
            "child.py",
            &CHILD.replace("return request", "copy = request\n        return copy"),
        );
        std::fs::remove_file(repo.root.path().join("child.py")).unwrap();
    }
    let source = edited_base();
    repo.edit("base.py", &source);
    assert_eq!(repo.reconciler.cross_file_linker().last_files_resolved(), 2);
    let call = repo.call("Base");
    assert_eq!(call.confidence, 0.86);
    assert_eq!(call.id, initial.id);
    assert_fresh_occurrences(&call, &source, 1, 1);
    assert_eq!(repo.overrides("Base").len(), 1);
    repo.reopen();
    assert_eq!(repo.call("Base"), call);
}

#[test]
fn reopened_graph_seed_retains_unchanged_child_override_on_base_only_edit() {
    assert_restart(false);
}

#[test]
fn warm_hierarchy_classification_survives_reconcile_merge() {
    assert_restart(true);
}

#[test]
fn removing_the_override_clears_dispatch_qualification_after_reopen() {
    let mut repo = Repo::new(CHILD);
    repo.edit(
        "child.py",
        "from base import Base as Alias\n\nclass Child(Alias):\n    pass\n",
    );
    assert!(repo.overrides("Base").is_empty());
    repo.reopen();
    repo.edit("base.py", &edited_base());
    assert_eq!(repo.call("Base").confidence, 1.0);
    assert!(!kin_index::is_self_dispatch_candidate(&repo.call("Base")));
}

#[test]
fn retargeted_import_with_same_override_identity_does_not_keep_old_base_qualification() {
    let mut repo = Repo::new(CHILD);
    repo.edit(
        "child.py",
        &CHILD.replace("from base import Base", "from other import OtherBase"),
    );
    assert!(repo.overrides("Base").is_empty());
    assert_eq!(repo.overrides("OtherBase").len(), 1);
    repo.reopen();
    repo.edit("base.py", &edited_base());
    repo.edit("other.py", &edited_base().replace("Base", "OtherBase"));
    assert_eq!(repo.call("Base").confidence, 1.0);
    assert_eq!(repo.call("OtherBase").confidence, 0.86);
}

#[test]
fn ordinary_self_call_without_an_override_keeps_its_tier() {
    let mut repo = Repo::new("class Child:\n    pass\n");
    repo.edit("base.py", &edited_base());
    assert_eq!(repo.call("Base").confidence, 1.0);
    assert_fresh_occurrences(&repo.call("Base"), &edited_base(), 1, 0);
}

#[test]
fn unresolved_explicit_base_site_keeps_mixed_call_coverage_incomplete() {
    let mut repo = Repo::new(CHILD);
    let source = BASE.replace("return self.send(request)", "self.send(request)\n        Base.send(self, request=request)\n        return self.send(request=request)");
    let extracted = parse("base.py", &source);
    assert!(extracted
        .relations
        .iter()
        .any(kin_parser::is_call_extraction_incomplete_marker));
    repo.edit("base.py", &source);
    let call = repo.call("Base");
    assert_eq!(call.confidence, 0.86);
    let sites = certified_sites(&call);
    assert_eq!(
        sites.len(),
        2,
        "only the two self sites have resolved targets"
    );
    for record in sites {
        let span = record.source_span.as_ref().unwrap();
        assert!(source[span.start_byte..span.end_byte].starts_with("self.send("));
        assert_eq!(record.occurrence_count, 1);
        assert!(
            record.call_shape.is_none(),
            "unresolved explicit site must not turn into complete shapes"
        );
        assert_eq!(
            record.parser_rule.as_deref(),
            Some(kin_index::CALL_SHAPE_EVIDENCE_INCOMPLETE_EXTRACTION_V1)
        );
        assert_eq!(
            record.token.as_deref(),
            Some(kin_index::SELF_DISPATCH_OVERRIDE_EVIDENCE_V1)
        );
    }
    repo.reopen();
    assert_eq!(repo.call("Base"), call);
}

#[test]
fn persisted_overrides_exclude_fresh_source_slices_before_graph_publication() {
    let repo = Repo::new(CHILD);
    let base = parse("base.py", &edited_base());
    let child = parse(
        "child.py",
        &CHILD.replace("from base import Base", "from other import OtherBase"),
    );
    let mut linker = repo.seeded_index();
    for file in [&base, &child] {
        let artifact = repo
            .graph
            .artifact_id_at_path(&RepoPath::from_utf8(file.file_path.clone()).unwrap())
            .unwrap();
        linker.add_file(&file.file_path, artifact, &file.entities);
    }
    let files = [base, child];
    let completeness = files
        .iter()
        .map(|file| (file.file_path.clone(), ParseCompleteness::Full))
        .collect();
    let relations = kin_index::link_cross_file_incremental_with_graph(
        &files,
        &linker,
        &completeness,
        repo.graph.as_ref(),
    )
    .unwrap();
    let src = repo.entity("Base.resolve").id;
    let dst = repo.entity("Base.send").id;
    let call = relations
        .iter()
        .find(|relation| {
            relation.kind == RelationKind::Calls
                && relation.src.as_entity() == Some(src)
                && relation.dst.as_entity() == Some(dst)
        })
        .unwrap();
    assert_eq!(
        call.confidence, 1.0,
        "old graph source must not override its fresh import retarget"
    );
    assert_eq!(
        repo.overrides("Base").len(),
        1,
        "the exclusion was exercised before publication"
    );
}

#[test]
fn removed_or_replaced_identities_cannot_borrow_old_override_facts() {
    for mode in ["removed-source", "replaced-source", "replaced-target"] {
        let repo = Repo::new(CHILD);
        let mut linker = repo.seeded_index();
        let mut base = parse("base.py", &edited_base());
        if mode == "removed-source" {
            linker.remove_file("child.py");
        } else if mode == "replaced-source" {
            let mut child = parse("child.py", CHILD);
            child
                .entities
                .iter_mut()
                .find(|entity| entity.name == "Child.send")
                .unwrap()
                .id = EntityId::new();
            let artifact = repo
                .graph
                .artifact_id_at_path(&RepoPath::from_utf8("child.py".to_string()).unwrap())
                .unwrap();
            linker.add_file("child.py", artifact, &child.entities);
        } else {
            base.entities
                .iter_mut()
                .find(|entity| entity.name == "Base.send")
                .unwrap()
                .id = EntityId::new();
        }
        let artifact = repo
            .graph
            .artifact_id_at_path(&RepoPath::from_utf8("base.py".to_string()).unwrap())
            .unwrap();
        linker.add_file("base.py", artifact, &base.entities);
        let completeness = HashMap::from([("base.py".to_string(), ParseCompleteness::Full)]);
        let src = base
            .entities
            .iter()
            .find(|entity| entity.name == "Base.resolve")
            .unwrap()
            .id;
        let dst = base
            .entities
            .iter()
            .find(|entity| entity.name == "Base.send")
            .unwrap()
            .id;
        let relations = kin_index::link_cross_file_incremental_with_graph(
            &[base],
            &linker,
            &completeness,
            repo.graph.as_ref(),
        )
        .unwrap();
        let call = relations
            .iter()
            .find(|relation| {
                relation.kind == RelationKind::Calls
                    && relation.src.as_entity() == Some(src)
                    && relation.dst.as_entity() == Some(dst)
            })
            .unwrap();
        assert_eq!(call.confidence, 1.0, "{mode}");
        assert!(!kin_index::is_self_dispatch_candidate(call), "{mode}");
    }
}
