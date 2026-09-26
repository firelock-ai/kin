// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use kin_model::{EntityKind, FilePathId};
use kin_parser::{LanguageAdapter, PythonAdapter};

#[test]
fn decorated_class_and_method_keep_their_own_syntax_and_declaration_identity() {
    let source = "from foreign import outer, inner\n\n@outer\nclass Service:\n    @inner\n    def run(self):\n        return 1\n";
    let adapter = PythonAdapter;
    let file = FilePathId::new("service.py");
    let tree = adapter.parse(source.as_bytes()).unwrap();
    let output = adapter.extract(&tree, source.as_bytes(), &file).unwrap();
    for (name, kind, decorator, line) in [
        ("Service", EntityKind::Class, "outer", 3),
        ("Service.run", EntityKind::Method, "inner", 5),
    ] {
        let entity = output
            .entities
            .iter()
            .find(|entity| entity.name == name)
            .unwrap();
        assert_eq!(entity.kind, kind);
        assert_eq!(entity.declaration_line, Some(line));
        assert!(entity.signature.starts_with(&format!("@{decorator} ")));
        assert!(!entity.signature.contains(if decorator == "outer" {
            "@inner"
        } else {
            "@outer"
        }));
        let call = output
            .relations
            .iter()
            .find(|relation| relation.dst_name == decorator)
            .unwrap();
        assert_eq!(call.src_name, name);
        let site = call.site.as_ref().unwrap();
        assert!(entity.span.start_byte <= site.start_byte && site.end_byte <= entity.span.end_byte);
        let converted = entity.clone().into_entity(adapter.language_id(), &file);
        assert_eq!(
            converted.id,
            kin_model::EntityId::from_content("service.py", name, &format!("{kind:?}"), line)
        );
    }
}

#[test]
fn a_decorator_written_through_an_object_carries_its_receiver() {
    // `@app.post("/items/")` is a call to the member `post` of `app`, so it
    // arrives exactly as the same call written in a body would: the leaf name
    // plus the receiver as written. A bare decorator names the function itself
    // and carries none.
    let source = "\
import pytest
from registry import register

app = FastAPI()


@app.post(\"/items/\")
@register
async def create_item(item):
    return item


@pytest.mark.parametrize(\"value\", [1])
def test_value(value):
    assert value


class Box:
    @property
    def size(self):
        return self._size

    @size.setter
    def size(self, value):
        self._size = value
";
    let adapter = PythonAdapter;
    let file = FilePathId::new("routes.py");
    let tree = adapter.parse(source.as_bytes()).unwrap();
    let output = adapter.extract(&tree, source.as_bytes(), &file).unwrap();
    let decorator_call = |src: &str, dst: &str| {
        output
            .relations
            .iter()
            .find(|relation| {
                relation.kind == kin_model::RelationKind::Calls
                    && relation.src_name == src
                    && relation.dst_name == dst
            })
            .unwrap_or_else(|| panic!("no decorator call {src} -> {dst}"))
    };
    for (src, dst, receiver) in [
        ("create_item", "post", Some("app")),
        ("create_item", "register", None),
        ("test_value", "parametrize", Some("pytest.mark")),
        ("Box.size", "property", None),
        ("Box.size", "setter", Some("size")),
    ] {
        let call = decorator_call(src, dst);
        assert_eq!(call.receiver.as_deref(), receiver, "{src} -> {dst}");
        if receiver.is_some() {
            assert_eq!(
                call.import_source, None,
                "a member call is not the local binding an import introduced"
            );
        }
    }
    assert_eq!(
        decorator_call("create_item", "register")
            .import_source
            .as_deref(),
        Some("registry"),
        "a bare decorator keeps the import it names"
    );
}
