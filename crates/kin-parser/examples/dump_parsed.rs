// kin/crates/kin-parser/examples/dump_parsed.rs
use std::env;
use std::fs;
use std::path::Path;

use kin_parser::AdapterRegistry;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: dump_parsed <file>");
        std::process::exit(1);
    }
    let path = &args[1];
    let content = fs::read(path).expect("failed to read file");

    let extension = Path::new(path)
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("");
    let registry = AdapterRegistry::new();
    let adapter = registry
        .get_by_extension(extension)
        .unwrap_or_else(|| panic!("no parser adapter for extension `{extension}`"));
    let tree = adapter.parse(&content).expect("failed to parse");
    let path_id = kin_model::FilePathId::new(path);
    let output = adapter
        .extract(&tree, &content, &path_id)
        .expect("failed to extract");

    println!("--- ENTITIES ---");
    for e in &output.entities {
        println!("{:?} {}", e.kind, e.name);
    }
    println!("\n--- RELATIONS ---");
    for r in &output.relations {
        println!("{:?} {} -> {}", r.kind, r.src_name, r.dst_name);
    }
    println!("\n--- IMPORTS ---");
    for import in &output.imports {
        println!("{import:?}");
    }
}
