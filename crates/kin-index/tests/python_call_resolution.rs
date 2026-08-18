// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Cross-file arm of the Python call-resolution regression net.
//!
//! The extractor narrows Python attribute callees to their leaf name
//! (`module.func()` -> `func`, `obj.method()` -> `method`); this test drives the
//! real parser -> real linker pipeline to prove that the narrowed simple name
//! resolves to the *actual* target entity defined in another file. The
//! same-file extraction arm (leaf-name narrowing, import_source, and the
//! nesting-recursion pin) lives in `kin-parser/tests/python_call_resolution.rs`;
//! together they cover {bare call, module-attribute call, method call} x
//! {same-file, cross-file}.

use kin_index::{link_cross_file as link_cross_file_with_identities, FileParseData};
use kin_model::{ArtifactId, Entity, EntityId, FilePathId, RelationKind};
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

/// EntityId of the entity named `name` originating in `file`, across all files.
fn entity_id(files: &[FileParseData], file: &str, name: &str) -> EntityId {
    files
        .iter()
        .flat_map(|f| f.entities.iter())
        .find(|e| e.name == name && e.file_origin.as_ref().map(|p| p.0.as_str()) == Some(file))
        .unwrap_or_else(|| panic!("entity `{name}` in `{file}` not found"))
        .id
}

fn has_call(relations: &[kin_model::Relation], src: EntityId, dst: EntityId) -> bool {
    relations.iter().any(|r| {
        r.kind == RelationKind::Calls
            && r.src.as_entity() == Some(src)
            && r.dst.as_entity() == Some(dst)
    })
}

fn link_cross_file(files: &[FileParseData]) -> Vec<kin_model::Relation> {
    let artifact_ids = files
        .iter()
        .map(|file| (file.file_path.clone(), ArtifactId::new()))
        .collect();
    link_cross_file_with_identities(files, &artifact_ids)
        .expect("every fixture file has an explicitly assigned artifact identity")
}

#[test]
fn cross_file_bare_call_with_import_resolves() {
    // caller.py imports and calls a free function defined in helpers.py.
    let files = vec![
        parse_py(
            "caller.py",
            "from helpers import compute\n\ndef run():\n    compute()\n",
        ),
        parse_py("helpers.py", "def compute():\n    return 1\n"),
    ];

    let run = entity_id(&files, "caller.py", "run");
    let compute = entity_id(&files, "helpers.py", "compute");

    let relations = link_cross_file(&files);
    assert!(
        has_call(&relations, run, compute),
        "bare imported call `compute()` should resolve run -> helpers.py::compute"
    );
}

#[test]
fn cross_file_module_attribute_call_resolves() {
    // caller.py calls `mathlib.compute()`; the leaf `compute` must resolve to
    // the function defined in mathlib.py.
    let files = vec![
        parse_py(
            "caller.py",
            "import mathlib\n\ndef run():\n    mathlib.compute()\n",
        ),
        parse_py("mathlib.py", "def compute():\n    return 2\n"),
    ];

    let run = entity_id(&files, "caller.py", "run");
    let compute = entity_id(&files, "mathlib.py", "compute");

    let relations = link_cross_file(&files);
    assert!(
        has_call(&relations, run, compute),
        "module-attribute call `mathlib.compute()` should resolve run -> mathlib.py::compute"
    );
}

#[test]
fn cross_file_method_call_on_instance_resolves() {
    // caller.py builds a Service and calls `svc.process()`; the leaf `process`
    // must resolve to the method Service.process defined in service.py.
    let files = vec![
        parse_py(
            "caller.py",
            "from service import Service\n\ndef run():\n    svc = Service()\n    svc.process()\n",
        ),
        parse_py(
            "service.py",
            "class Service:\n    def process(self):\n        return 3\n",
        ),
    ];

    let run = entity_id(&files, "caller.py", "run");
    let process = entity_id(&files, "service.py", "Service.process");

    let relations = link_cross_file(&files);
    assert!(
        has_call(&relations, run, process),
        "method call `svc.process()` should resolve run -> service.py::Service.process"
    );
}

// ---- inheritance-aware receiver-method resolution (self./cls. dispatch) ----

fn call_confidence(relations: &[kin_model::Relation], src: EntityId, dst: EntityId) -> Option<f32> {
    relations
        .iter()
        .find(|r| {
            r.kind == RelationKind::Calls
                && r.src.as_entity() == Some(src)
                && r.dst.as_entity() == Some(dst)
        })
        .map(|r| r.confidence)
}

#[test]
fn inherited_self_call_resolves_to_base_method_cross_file() {
    // The Django inherited-self-call shape: Command(BaseCommand) calls
    // self.validate(), and validate is defined only on the base class in
    // another file. The edge must exist AND carry verdict-driving confidence
    // (>= 0.6, the review-side strong-consumer floor) — a weak fan-out edge
    // would not count the caller as a consumer of a removed API.
    let files = vec![
        parse_py(
            "base.py",
            "class BaseCommand:\n    def validate(self, display_num_errors=False):\n        return 1\n",
        ),
        parse_py(
            "runserver.py",
            "from base import BaseCommand\n\nclass Command(BaseCommand):\n    def inner_run(self):\n        self.validate(display_num_errors=True)\n",
        ),
    ];

    let caller = entity_id(&files, "runserver.py", "Command.inner_run");
    let target = entity_id(&files, "base.py", "BaseCommand.validate");

    let relations = link_cross_file(&files);
    assert!(
        has_call(&relations, caller, target),
        "self.validate() in Command(BaseCommand) must resolve to the inherited BaseCommand.validate"
    );
    let confidence = call_confidence(&relations, caller, target).unwrap();
    assert!(
        confidence >= 0.6,
        "inherited-method edge must drive review verdicts (confidence {confidence} < 0.6)"
    );
}

#[test]
fn inherited_self_call_resolves_same_file() {
    // Same-file base class: the pre-qualification linker could never link ANY
    // same-file self-call (the bare-name tier is cross-file-only); the
    // qualified form + hierarchy walk closes that gap too.
    let files = vec![parse_py(
        "base.py",
        "class BaseCommand:\n    def validate(self):\n        return 1\n\nclass AppCommand(BaseCommand):\n    def handle(self):\n        self.validate()\n",
    )];

    let caller = entity_id(&files, "base.py", "AppCommand.handle");
    let target = entity_id(&files, "base.py", "BaseCommand.validate");

    let relations = link_cross_file(&files);
    assert!(
        has_call(&relations, caller, target),
        "self.validate() in a same-file subclass must resolve to BaseCommand.validate"
    );
}

#[test]
fn self_call_resolves_to_own_override_not_base() {
    // When the subclass overrides the method, self.m() dispatches to the
    // override: the same-file exact tier wins at full confidence and the walk
    // never fires. The base's copy must NOT be linked.
    let files = vec![
        parse_py(
            "base.py",
            "class BaseCommand:\n    def validate(self):\n        return 1\n",
        ),
        parse_py(
            "sub.py",
            "from base import BaseCommand\n\nclass Command(BaseCommand):\n    def validate(self):\n        return 2\n    def handle(self):\n        self.validate()\n",
        ),
    ];

    let caller = entity_id(&files, "sub.py", "Command.handle");
    let override_target = entity_id(&files, "sub.py", "Command.validate");
    let base_target = entity_id(&files, "base.py", "BaseCommand.validate");

    let relations = link_cross_file(&files);
    assert!(
        has_call(&relations, caller, override_target),
        "self.validate() must resolve to the local override Command.validate"
    );
    assert!(
        !has_call(&relations, caller, base_target),
        "the shadowed base method must not receive the dispatch edge"
    );
}

#[test]
fn transitive_inheritance_resolves_through_chain() {
    // A -> B -> C across three files: the walk crosses multiple hops and links
    // to the ancestor that actually defines the method.
    let files = vec![
        parse_py(
            "a.py",
            "from b import Middle\n\nclass Leaf(Middle):\n    def run(self):\n        self.shared_helper()\n",
        ),
        parse_py("b.py", "from c import Root\n\nclass Middle(Root):\n    pass\n"),
        parse_py(
            "c.py",
            "class Root:\n    def shared_helper(self):\n        return 3\n",
        ),
    ];

    let caller = entity_id(&files, "a.py", "Leaf.run");
    let target = entity_id(&files, "c.py", "Root.shared_helper");

    let relations = link_cross_file(&files);
    assert!(
        has_call(&relations, caller, target),
        "self.shared_helper() must resolve transitively Leaf -> Middle -> Root.shared_helper"
    );
}

#[test]
fn unresolvable_base_falls_back_to_bare_fanout() {
    // The class extends something outside the graph (external package /
    // builtin), so the walk finds nothing — the call must then keep the
    // pre-qualification recall by fanning out on the bare leaf like any
    // receiver-method call.
    let files = vec![
        parse_py(
            "caller.py",
            "from ext.pkg import ExternalBase\n\nclass Sub(ExternalBase):\n    def run(self):\n        self.helper()\n",
        ),
        parse_py(
            "impl_one.py",
            "class One:\n    def helper(self):\n        return 1\n",
        ),
        parse_py(
            "impl_two.py",
            "class Two:\n    def helper(self):\n        return 2\n",
        ),
    ];

    let caller = entity_id(&files, "caller.py", "Sub.run");
    let one = entity_id(&files, "impl_one.py", "One.helper");
    let two = entity_id(&files, "impl_two.py", "Two.helper");

    let relations = link_cross_file(&files);
    assert!(
        has_call(&relations, caller, one) && has_call(&relations, caller, two),
        "an unresolvable hierarchy must fall back to the bare-leaf fan-out, keeping both candidates"
    );
}

#[test]
fn inheritance_cycle_terminates_without_edge() {
    // A malformed cyclic hierarchy must terminate (cycle guard) and honestly
    // resolve nothing rather than hang or fabricate an edge.
    let files = vec![parse_py(
        "cyc.py",
        "class Alpha(Beta):\n    def run(self):\n        self.nowhere()\n\nclass Beta(Alpha):\n    pass\n",
    )];

    let caller = entity_id(&files, "cyc.py", "Alpha.run");
    let relations = link_cross_file(&files);
    assert!(
        !relations
            .iter()
            .any(|r| r.kind == RelationKind::Calls && r.src.as_entity() == Some(caller)),
        "a cyclic hierarchy with an undefined method must produce no Calls edge"
    );
}

// ---- incremental-linker parity (the historical-replay path) ----

#[test]
fn incremental_inherited_self_call_resolves_with_batch_parity() {
    use kin_index::{link_cross_file_incremental, IncrementalLinker};

    let files = vec![
        parse_py(
            "base.py",
            "class BaseCommand:\n    def validate(self, display_num_errors=False):\n        return 1\n",
        ),
        parse_py(
            "runserver.py",
            "from base import BaseCommand\n\nclass Command(BaseCommand):\n    def inner_run(self):\n        self.validate(display_num_errors=True)\n",
        ),
    ];

    let mut linker = IncrementalLinker::new();
    for file in &files {
        linker.add_file(&file.file_path, ArtifactId::new(), &file.entities);
    }
    linker.record_class_bases(&files);

    let caller = entity_id(&files, "runserver.py", "Command.inner_run");
    let target = entity_id(&files, "base.py", "BaseCommand.validate");

    let relations = link_cross_file_incremental(&files, &linker)
        .expect("every fixture file has an explicitly assigned artifact identity");
    assert!(
        has_call(&relations, caller, target),
        "incremental linking must resolve the inherited method exactly like the batch linker"
    );
    let confidence = call_confidence(&relations, caller, target).unwrap();
    assert!(
        confidence >= 0.6,
        "incremental inherited-method edge must drive review verdicts (confidence {confidence} < 0.6)"
    );
}

#[test]
fn incremental_hierarchy_persists_across_steps() {
    use kin_index::{link_cross_file_incremental, IncrementalLinker};

    // Step 1 records the base file; step 2 relinks ONLY the caller file. The
    // walk must cross the step boundary through the linker's persistent
    // hierarchy state — this is the historical-replay shape, where a later
    // commit touches the subclass while the base class last changed many
    // commits earlier.
    let base = parse_py(
        "base.py",
        "class BaseCommand:\n    def validate(self):\n        return 1\n",
    );
    let caller = parse_py(
        "runserver.py",
        "from base import BaseCommand\n\nclass Command(BaseCommand):\n    def inner_run(self):\n        self.validate()\n",
    );

    let mut linker = IncrementalLinker::new();
    linker.add_file(&base.file_path, ArtifactId::new(), &base.entities);
    linker.record_class_bases(std::slice::from_ref(&base));

    linker.add_file(&caller.file_path, ArtifactId::new(), &caller.entities);

    let caller_id = entity_id(
        std::slice::from_ref(&caller),
        "runserver.py",
        "Command.inner_run",
    );
    let target_id = entity_id(
        std::slice::from_ref(&base),
        "base.py",
        "BaseCommand.validate",
    );

    // Only the caller file is in this step's parse data; base.py's hierarchy
    // lives in the persistent linker state (and the caller's own hierarchy in
    // the step-local overlay).
    let relations = link_cross_file_incremental(std::slice::from_ref(&caller), &linker)
        .expect("every fixture file has an explicitly assigned artifact identity");
    assert!(
        has_call(&relations, caller_id, target_id),
        "an inheritance walk must cross incremental step boundaries via recorded hierarchy state"
    );
}

/// The receiver-reach narrowing is a property of BOTH fan-out tiers, so the
/// incremental linker must drop the same unreachable candidate the batch linker
/// does. Without this the live-edit path re-mints the false inbound caller the
/// moment the calling file is relinked.
#[test]
fn incremental_receiver_call_does_not_reach_an_unimportable_owner() {
    use kin_index::{link_cross_file_incremental, IncrementalLinker};

    let files = vec![
        parse_py(
            "app/adapter.py",
            "class Adapter:\n    def send(self, request):\n        return request\n",
        ),
        parse_py(
            "app/session.py",
            "from .adapter import Adapter\n\n\nclass Session:\n    def __init__(self):\n        self.adapter = Adapter()\n\n    def send(self, request):\n        return self.adapter.send(request)\n",
        ),
        parse_py(
            "app/pipeline.py",
            "from .session import Session\n\n\ndef run_all(session):\n    return session.send({})\n",
        ),
    ];

    let mut linker = IncrementalLinker::new();
    for file in &files {
        linker.add_file(&file.file_path, ArtifactId::new(), &file.entities);
    }
    linker.record_class_bases(&files);

    let run_all = entity_id(&files, "app/pipeline.py", "run_all");
    let session_send = entity_id(&files, "app/session.py", "Session.send");
    let adapter_send = entity_id(&files, "app/adapter.py", "Adapter.send");

    let relations = link_cross_file_incremental(&files, &linker)
        .expect("every fixture file has an explicitly assigned artifact identity");
    assert!(
        has_call(&relations, run_all, session_send),
        "`session.send(...)` must still reach `Session.send`, whose type this file imports"
    );
    assert!(
        !has_call(&relations, run_all, adapter_send),
        "`app/pipeline.py` never names `Adapter`, so `Adapter.send` cannot be this receiver"
    );
}
