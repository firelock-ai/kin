// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! A `self`/`cls` receiver-method call must not be labelled `type_resolved`
//! onto a destination an `Overrides` edge names as a replaced base.
//!
//! The requests-library shape: `SessionRedirectMixin` declares an abstract
//! `send` and calls it through `self` from a sibling method
//! (`resolve_redirects`); `Session(SessionRedirectMixin)` overrides `send`
//! with the concrete 78-line method that actually runs. Before this fix, the
//! same-file exact-name tier and the Extends-chain walk both stamped that call
//! at full, parser-certain confidence onto the never-executed stub — kin's
//! highest confidence tag on a destination that Python's method resolution
//! order never dispatches to. This file drives the real parser and the real
//! linker (both batch and incremental) over that exact shape.

use kin_index::resolution::{RelationResolution, DISPATCH_CANDIDATE_CONFIDENCE};
use kin_index::{overriding_methods, FileParseData, OverrideCandidate};
use kin_model::{ArtifactId, Entity, EntityId, EntityStore, FilePathId, RelationKind};
use kin_parser::{LanguageAdapter, PythonAdapter};

fn parse_py(file_path: &str, source: &str) -> FileParseData {
    let adapter = PythonAdapter;
    let file_id = FilePathId::new(file_path);
    let bytes = source.as_bytes();
    let tree = adapter.parse(bytes).expect("parse");
    let output = adapter.extract(&tree, bytes, &file_id).expect("extract");

    let entities: Vec<Entity> = output
        .entities
        .into_iter()
        .map(|e| e.into_entity_with_source(adapter.language_id(), &file_id, Some(bytes)))
        .collect();

    FileParseData {
        file_path: file_path.to_string(),
        entities,
        relations: output.relations,
        imports: output.imports,
    }
}

fn entity_id(files: &[FileParseData], file: &str, name: &str) -> EntityId {
    files
        .iter()
        .flat_map(|f| f.entities.iter())
        .find(|e| e.name == name && e.file_origin.as_ref().map(|p| p.0.as_str()) == Some(file))
        .unwrap_or_else(|| panic!("entity `{name}` in `{file}` not found"))
        .id
}

fn entity(files: &[FileParseData], file: &str, name: &str) -> Entity {
    files
        .iter()
        .flat_map(|f| f.entities.iter())
        .find(|e| e.name == name && e.file_origin.as_ref().map(|p| p.0.as_str()) == Some(file))
        .unwrap_or_else(|| panic!("entity `{name}` in `{file}` not found"))
        .clone()
}

fn call_relation(
    relations: &[kin_model::Relation],
    src: EntityId,
    dst: EntityId,
) -> Option<&kin_model::Relation> {
    relations.iter().find(|r| {
        r.kind == RelationKind::Calls
            && r.src.as_entity() == Some(src)
            && r.dst.as_entity() == Some(dst)
    })
}

fn has_relation(
    relations: &[kin_model::Relation],
    kind: RelationKind,
    src: EntityId,
    dst: EntityId,
) -> bool {
    relations
        .iter()
        .any(|r| r.kind == kind && r.src.as_entity() == Some(src) && r.dst.as_entity() == Some(dst))
}

fn link_cross_file(files: &[FileParseData]) -> Vec<kin_model::Relation> {
    let artifact_ids = files
        .iter()
        .map(|file| (file.file_path.clone(), ArtifactId::new()))
        .collect();
    kin_index::link_cross_file(files, &artifact_ids)
        .expect("every fixture file has an explicitly assigned artifact identity")
}

/// The `sessions.py` shape, same file, mirroring the reported defect exactly:
/// a mixin declares an abstract `send`, calls it through `self` from a
/// sibling method, and a concrete subclass overrides it.
const SESSIONS: &str = "\
class SessionRedirectMixin:
    def send(self, request):
        raise NotImplementedError

    def resolve_redirects(self, request):
        return self.send(request)


class Session(SessionRedirectMixin):
    def send(self, request):
        return request
";

#[test]
fn same_file_self_call_to_an_overridden_stub_is_not_type_resolved() {
    let files = vec![parse_py("sessions.py", SESSIONS)];

    let resolve_redirects = entity_id(
        &files,
        "sessions.py",
        "SessionRedirectMixin.resolve_redirects",
    );
    let stub = entity_id(&files, "sessions.py", "SessionRedirectMixin.send");
    let concrete = entity_id(&files, "sessions.py", "Session.send");

    let relations = link_cross_file(&files);

    assert!(
        has_relation(&relations, RelationKind::Overrides, concrete, stub),
        "Session.send must override SessionRedirectMixin.send: {relations:#?}"
    );

    let call = call_relation(&relations, resolve_redirects, stub).unwrap_or_else(|| {
        panic!("self.send(...) in resolve_redirects must resolve to the stub: {relations:#?}")
    });
    assert_eq!(
        call.confidence, DISPATCH_CANDIDATE_CONFIDENCE,
        "a self-call reaching an overridden stub must not carry the same-file \
         parser-certain confidence: {call:#?}"
    );
    assert_eq!(
        RelationResolution::of(call),
        RelationResolution::ImportScoped,
        "kin's highest confidence tag (type_resolved) must not land on a \
         destination the receiver's runtime class can replace: {call:#?}"
    );
    assert!(
        !has_relation(&relations, RelationKind::Calls, resolve_redirects, concrete),
        "the linker must not fabricate a direct edge to the override either — \
         the row on the stub is what carries the dispatch note: {relations:#?}"
    );

    // The candidate list a caller like `trace_data_flow` would attach beside
    // that row is already answerable from the graph the linker produced: put
    // the parsed entities and the `Overrides` edge into a store and ask.
    let store = kin_db::InMemoryGraph::new();
    for file in &files {
        for e in &file.entities {
            store.upsert_entity(e).expect("seed entity");
        }
    }
    for relation in &relations {
        if relation.kind == RelationKind::Overrides {
            store
                .upsert_relation(relation)
                .expect("seed Overrides edge");
        }
    }
    let stub_entity = entity(&files, "sessions.py", "SessionRedirectMixin.send");
    let candidates = overriding_methods(&store, &stub_entity).expect("read overrides");
    assert_eq!(
        candidates,
        vec![OverrideCandidate {
            entity_id: concrete,
            qualified_name: "Session.send".to_string(),
        }],
        "the stub's override candidates must name Session.send"
    );
}

/// Cross-file arm of the same shape, through the Extends-chain walk
/// ([`kin_index::linker::resolve_inherited_method`], `INHERITED_METHOD_CONFIDENCE`)
/// rather than the same-file exact-name hit: `Middle` inherits `send` from
/// `Base` without overriding it, and `Session` overrides `Base.send`
/// elsewhere. A call through `self` inside `Middle` must not be stamped
/// `type_resolved` onto `Base.send` either, because `Middle`'s own receiver
/// could just as well be a `Session` at runtime.
#[test]
fn cross_file_inherited_self_call_to_an_overridden_ancestor_is_not_type_resolved() {
    let files = vec![
        parse_py(
            "base.py",
            "class Base:\n    def send(self, request):\n        raise NotImplementedError\n",
        ),
        parse_py(
            "middle.py",
            "from base import Base\n\nclass Middle(Base):\n    def resolve(self, request):\n        return self.send(request)\n",
        ),
        parse_py(
            "session.py",
            "from base import Base\n\nclass Session(Base):\n    def send(self, request):\n        return request\n",
        ),
    ];

    let caller = entity_id(&files, "middle.py", "Middle.resolve");
    let base_send = entity_id(&files, "base.py", "Base.send");
    let session_send = entity_id(&files, "session.py", "Session.send");

    let relations = link_cross_file(&files);

    assert!(
        has_relation(&relations, RelationKind::Overrides, session_send, base_send),
        "Session.send must override Base.send: {relations:#?}"
    );
    let call = call_relation(&relations, caller, base_send).unwrap_or_else(|| {
        panic!("self.send(...) in Middle.resolve must resolve to the inherited Base.send: {relations:#?}")
    });
    assert_eq!(
        call.confidence, DISPATCH_CANDIDATE_CONFIDENCE,
        "an inherited self-call whose ancestor is itself overridden elsewhere \
         must not carry the inherited-dispatch tier's proven confidence: {call:#?}"
    );
    assert_eq!(
        RelationResolution::of(call),
        RelationResolution::ImportScoped
    );
}

/// The existing, still-correct shape must be untouched: when the CALLING
/// class itself is the one that overrides the method (nothing further
/// subclasses it), `self.m()` must keep resolving to that override at full
/// confidence. `kin-index/tests/python_call_resolution.rs` already covers
/// this; this is the same guarantee restated against THIS fix's exact gate
/// (`overridden_bases`, keyed on the RESOLVED destination, not the caller).
#[test]
fn a_call_resolving_straight_to_the_final_override_stays_type_resolved() {
    let files = vec![parse_py(
        "app.py",
        "class Base:\n    def validate(self):\n        return 1\n\nclass Command(Base):\n    def validate(self):\n        return 2\n    def handle(self):\n        self.validate()\n",
    )];

    let caller = entity_id(&files, "app.py", "Command.handle");
    let override_target = entity_id(&files, "app.py", "Command.validate");

    let relations = link_cross_file(&files);
    let call = call_relation(&relations, caller, override_target).unwrap_or_else(|| {
        panic!("self.validate() must resolve to Command's own override: {relations:#?}")
    });
    assert_eq!(call.confidence, 1.0, "{call:#?}");
    assert_eq!(
        RelationResolution::of(call),
        RelationResolution::TypeResolved
    );
}

#[test]
fn incremental_linking_matches_batch_on_the_same_dispatch_shape() {
    use kin_index::{link_cross_file_incremental, IncrementalLinker};

    let files = vec![parse_py("sessions.py", SESSIONS)];

    let mut linker = IncrementalLinker::new();
    for file in &files {
        linker.add_file(&file.file_path, ArtifactId::new(), &file.entities);
    }
    linker.record_class_bases(&files);

    let resolve_redirects = entity_id(
        &files,
        "sessions.py",
        "SessionRedirectMixin.resolve_redirects",
    );
    let stub = entity_id(&files, "sessions.py", "SessionRedirectMixin.send");

    let relations = link_cross_file_incremental(&files, &linker)
        .expect("every fixture file has an explicitly assigned artifact identity");
    let call = call_relation(&relations, resolve_redirects, stub).unwrap_or_else(|| {
        panic!("incremental linking must still resolve self.send(...) to the stub: {relations:#?}")
    });
    assert_eq!(
        call.confidence, DISPATCH_CANDIDATE_CONFIDENCE,
        "incremental linking must downgrade this edge exactly like the batch linker: {call:#?}"
    );
    assert_eq!(
        RelationResolution::of(call),
        RelationResolution::ImportScoped
    );
}

const ALIAS_BASE: &str = "class Base:\n    def send(self, request):\n        raise NotImplementedError\n    def resolve(self, request):\n        return self.send(request)\n";
const ALIAS_CHILD: &str = "from base import Base as Alias\n\nclass Child(Alias):\n    def send(self, request):\n        return request\n";

fn alias_fixture() -> (Vec<FileParseData>, kin_index::IncrementalLinker, ArtifactId) {
    let files = vec![
        parse_py("base.py", ALIAS_BASE),
        parse_py("child.py", ALIAS_CHILD),
    ];
    let mut linker = kin_index::IncrementalLinker::new();
    let base_artifact = ArtifactId::new();
    linker.add_file("base.py", base_artifact, &files[0].entities);
    linker.add_file("child.py", ArtifactId::new(), &files[1].entities);
    linker.record_class_bases(&files);
    let full = link_cross_file(&files);
    let initial = kin_index::link_cross_file_incremental(&files, &linker).unwrap();
    let caller = entity_id(&files, "base.py", "Base.resolve");
    let target = entity_id(&files, "base.py", "Base.send");
    for relations in [&full, &initial] {
        assert_eq!(
            call_relation(relations, caller, target).unwrap().confidence,
            DISPATCH_CANDIDATE_CONFIDENCE,
            "fixture initially detects the aliased override"
        );
    }
    (files, linker, base_artifact)
}

fn assert_base_only_edit_keeps_alias_override(
    mut linker: kin_index::IncrementalLinker,
    base_artifact: ArtifactId,
) {
    let edited = parse_py("base.py", &format!("{ALIAS_BASE}\n# comment-only change\n"));
    linker.remove_file("base.py");
    linker.add_file("base.py", base_artifact, &edited.entities);
    linker.record_class_bases(std::slice::from_ref(&edited));
    let caller = entity_id(std::slice::from_ref(&edited), "base.py", "Base.resolve");
    let target = entity_id(std::slice::from_ref(&edited), "base.py", "Base.send");
    let relations =
        kin_index::link_cross_file_incremental(std::slice::from_ref(&edited), &linker).unwrap();
    let call = call_relation(&relations, caller, target).expect("self call remains represented");
    assert_eq!(
        call.confidence, DISPATCH_CANDIDATE_CONFIDENCE,
        "an unchanged child's imported Base alias still permits overriding this target"
    );
    assert_eq!(
        RelationResolution::of(call),
        RelationResolution::ImportScoped
    );
}

#[test]
fn base_only_edit_retains_an_unchanged_childs_imported_base_alias() {
    let (_, linker, base_artifact) = alias_fixture();
    assert_base_only_edit_keeps_alias_override(linker, base_artifact);
}

#[test]
fn checkpoint_restore_retains_an_unchanged_childs_imported_base_alias() {
    let (_, linker, base_artifact) = alias_fixture();
    let bytes = serde_json::to_vec(&linker.to_checkpoint_v1()).unwrap();
    let checkpoint = serde_json::from_slice(&bytes).unwrap();
    let restored = kin_index::IncrementalLinker::from_checkpoint_v1(checkpoint).unwrap();
    assert_base_only_edit_keeps_alias_override(restored, base_artifact);
}

fn assert_dispatch_confidence(
    file: &FileParseData,
    class: &str,
    linker: &kin_index::IncrementalLinker,
    expected: f32,
) {
    let files = std::slice::from_ref(file);
    let caller = entity_id(files, &file.file_path, &format!("{class}.resolve"));
    let target = entity_id(files, &file.file_path, &format!("{class}.send"));
    let relations = kin_index::link_cross_file_incremental(files, linker).unwrap();
    assert_eq!(
        call_relation(&relations, caller, target)
            .unwrap()
            .confidence,
        expected
    );
}

#[test]
fn retargeted_child_import_replaces_its_previous_base_binding() {
    let (files, mut linker, _) = alias_fixture();
    let other = parse_py(
        "other.py",
        &ALIAS_BASE.replace("class Base:", "class OtherBase:"),
    );
    linker.add_file("other.py", ArtifactId::new(), &other.entities);
    let child = parse_py(
        "child.py",
        &ALIAS_CHILD.replace("from base import Base", "from other import OtherBase"),
    );
    linker.remove_file("child.py");
    linker.add_file("child.py", ArtifactId::new(), &child.entities);
    linker.record_class_bases(std::slice::from_ref(&child));
    assert_dispatch_confidence(&files[0], "Base", &linker, 1.0);
    assert_dispatch_confidence(&other, "OtherBase", &linker, DISPATCH_CANDIDATE_CONFIDENCE);
}

#[test]
fn removed_child_import_does_not_survive_in_the_recorded_hierarchy() {
    let (files, mut linker, _) = alias_fixture();
    // An intermediate edit leaves Alias unresolved. Retaining the deleted
    // import would assert a base relationship the current source no longer has.
    let edited = parse_py(
        "child.py",
        &ALIAS_CHILD.replace("from base import Base as Alias\n", ""),
    );
    linker.record_class_bases(std::slice::from_ref(&edited));
    assert_dispatch_confidence(&files[0], "Base", &linker, 1.0);
}

#[test]
fn current_step_import_removal_overlays_the_previous_binding() {
    let (files, linker, _) = alias_fixture();
    let edited = parse_py(
        "child.py",
        &ALIAS_CHILD.replace("from base import Base as Alias\n", ""),
    );
    // The caller may link fresh parse data before recording it persistently.
    // Empty fresh imports must still replace the old context in that pass.
    let relations =
        kin_index::link_cross_file_incremental(&[files[0].clone(), edited], &linker).unwrap();
    let caller = entity_id(&files, "base.py", "Base.resolve");
    let target = entity_id(&files, "base.py", "Base.send");
    assert_eq!(
        call_relation(&relations, caller, target)
            .unwrap()
            .confidence,
        1.0
    );
}

#[test]
fn removed_child_clears_its_hierarchy_and_import_binding() {
    let (files, mut linker, _) = alias_fixture();
    linker.remove_file("child.py");
    assert_dispatch_confidence(&files[0], "Base", &linker, 1.0);
}
