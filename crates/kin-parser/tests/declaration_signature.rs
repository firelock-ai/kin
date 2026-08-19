use kin_model::FilePathId;
use kin_parser::{LanguageAdapter, PythonAdapter};

#[test]
fn a_comment_under_the_def_is_not_part_of_the_signature() {
    let src = br#"
def _cmd_backlinks(db, args) -> int:
    # Database.resolve accepts a title, a full path or a path suffix, which is more
    # than LinkGraph.lookup does; the graph only ever resolves link targets.
    return 0
"#;
    let a = PythonAdapter;
    let file = FilePathId("cli.py".to_string());
    let tree = a.parse(src).expect("parse");
    let out = a.extract(&tree, src, &file).expect("extract");
    let e = out
        .entities
        .iter()
        .find(|e| e.name == "_cmd_backlinks")
        .expect("entity");
    eprintln!("SIG=<{}>", e.signature);
    assert!(
        !e.signature.contains("Database.resolve accepts"),
        "signature swallowed the comment: {}",
        e.signature
    );
    assert!(
        e.signature.contains("_cmd_backlinks"),
        "signature lost the declaration: {}",
        e.signature
    );
}
