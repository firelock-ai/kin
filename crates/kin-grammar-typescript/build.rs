// SPDX-License-Identifier: MIT
// Derived from tree-sitter-typescript's bindings/rust/build.rs, with the
// grammar moved under `grammar/` so the vendored upstream tree sits apart from
// this crate's own source. See README.md.

fn main() {
    let grammar_dir = std::path::Path::new("grammar");
    let typescript_dir = grammar_dir.join("typescript").join("src");
    let tsx_dir = grammar_dir.join("tsx").join("src");
    let common_dir = grammar_dir.join("common");

    let mut config = cc::Build::new();
    config.include(&typescript_dir);
    config
        .flag_if_supported("-std=c11")
        .flag_if_supported("-Wno-unused-parameter");

    for path in &[
        typescript_dir.join("parser.c"),
        typescript_dir.join("scanner.c"),
        tsx_dir.join("parser.c"),
        tsx_dir.join("scanner.c"),
    ] {
        config.file(path);
        println!("cargo:rerun-if-changed={}", path.to_str().unwrap());
    }

    println!(
        "cargo:rerun-if-changed={}",
        common_dir.join("scanner.h").to_str().unwrap()
    );

    config.compile("kin-grammar-typescript");
}
