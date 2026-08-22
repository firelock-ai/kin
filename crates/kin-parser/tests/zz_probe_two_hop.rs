use kin_model::FilePathId;
use kin_parser::{LanguageAdapter, PythonAdapter};

#[test]
fn probe() {
    for (path, src) in [
        ("models.py", "\nfrom adapters import HTTPAdapter\n\n\nclass Response:\n    status_code: int\n    connection: HTTPAdapter\n"),
        ("auth.py", "\nfrom models import Response\n\n\nclass HTTPDigestAuth:\n    def handle_401(self, r: Response, **kwargs):\n        return r.connection.send(prep, **kwargs)\n"),
    ] {
        let adapter = PythonAdapter;
        let file_id = FilePathId::new(path);
        let bytes = src.as_bytes();
        let tree = adapter.parse(bytes).expect("parse");
        let out = adapter.extract(&tree, bytes, &file_id).expect("extract");
        println!("=== {path} ENTITIES ===");
        for e in &out.entities {
            println!("  {:?} {} ", e.kind, e.name);
        }
        println!("=== {path} RELATIONS ===");
        for r in &out.relations {
            println!("  {:?} {} -> {} import_source={:?} receiver={:?}", r.kind, r.src_name, r.dst_name, r.import_source, r.receiver);
        }
        println!("=== {path} IMPORTS ===");
        for i in &out.imports {
            println!("  {i:?}");
        }
    }
}
