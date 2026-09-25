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
