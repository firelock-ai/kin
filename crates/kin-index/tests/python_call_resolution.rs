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

use kin_index::{link_cross_file, FileParseData};
use kin_model::{Entity, EntityId, FilePathId, RelationKind};
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
