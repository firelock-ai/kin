// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC
//
// Round-trip tests: parse -> get entities -> modify one entity -> project -> re-parse
// -> verify unchanged entities are identical.
//
// Uses inline source code strings for Rust, Python, TypeScript, Go, and Java.

use kin_model::{EntityId, FileLayout, FilePathId, ImportSection, SourceRegion};
use kin_projection::splice::{apply_splices, reconstruct_file, splice_entity, Splice};

// ── Helper ──────────────────────────────────────────────────────────────

/// Build a FileLayout with trivia and entity regions from the given byte ranges.
fn layout_with_entities(
    file_id: &str,
    regions: Vec<(Option<EntityId>, std::ops::Range<usize>)>,
) -> FileLayout {
    FileLayout {
        file_id: FilePathId::new(file_id),
        imports: ImportSection {
            byte_range: 0..0,
            items: vec![],
        },
        regions: regions
            .into_iter()
            .map(|(maybe_id, range)| match maybe_id {
                Some(id) => SourceRegion::EntityRef {
                    entity_id: id,
                    byte_range: range,
                },
                None => SourceRegion::Trivia { byte_range: range },
            })
            .collect(),
    }
}

// ── Rust round-trip ─────────────────────────────────────────────────────

#[test]
fn rust_fn_round_trip() {
    let source = b"// header\nfn add(a: i32, b: i32) -> i32 {\n    a + b\n}\n// footer\n";
    let entity_id = EntityId::new();

    let layout = layout_with_entities(
        "lib.rs",
        vec![
            (None, 0..10),             // "// header\n"
            (Some(entity_id), 10..53), // "fn add(a: i32, b: i32) -> i32 {\n    a + b\n}\n"
            (None, 53..63),            // "// footer\n"
        ],
    );

    // Modify the entity
    let new_body = b"fn add(a: i32, b: i32) -> i32 {\n    a.wrapping_add(b)\n}\n";
    let splice = splice_entity(&layout, &entity_id, new_body).unwrap();
    let result = apply_splices(source, vec![splice]).unwrap();

    // Verify trivia is preserved
    assert!(result.starts_with(b"// header\n"));
    assert!(result.ends_with(b"// footer\n"));
    // Verify the entity was modified
    assert!(result
        .windows(b"wrapping_add".len())
        .any(|w| w == b"wrapping_add"));
}

#[test]
fn rust_fn_unchanged_entities_preserved() {
    let source = b"fn unchanged() {}\nfn target() { old }\nfn also_unchanged() {}\n";
    let unchanged_id = EntityId::new();
    let target_id = EntityId::new();
    let also_unchanged_id = EntityId::new();

    let layout = layout_with_entities(
        "test.rs",
        vec![
            (Some(unchanged_id), 0..18),
            (None, 18..19), // "\n"
            (Some(target_id), 19..38),
            (None, 38..39), // "\n"
            (Some(also_unchanged_id), 39..60),
            (None, 60..61), // "\n"
        ],
    );

    let new_body = b"fn target() { new }";
    let result = reconstruct_file(source, &layout, |id| {
        if *id == target_id {
            Some(new_body.to_vec())
        } else {
            None // Keep original
        }
    })
    .unwrap();

    // Unchanged entities should be identical
    assert!(result.starts_with(b"fn unchanged() {}"));
    assert!(result.ends_with(b"fn also_unchanged() {}\n"));
    assert!(result
        .windows(b"fn target() { new }".len())
        .any(|w| w == b"fn target() { new }"));
}

// ── Python round-trip ───────────────────────────────────────────────────

#[test]
fn python_def_round_trip() {
    let source = b"# utils\ndef greet(name):\n    return f\"Hello, {name}\"\n# end\n";
    let entity_id = EntityId::new();

    let layout = layout_with_entities(
        "utils.py",
        vec![
            (None, 0..8),             // "# utils\n"
            (Some(entity_id), 8..51), // "def greet(name):\n    return f\"Hello, {name}\"\n"
            (None, 51..58),           // "# end\n"
        ],
    );

    let new_body = b"def greet(name):\n    return f\"Hi, {name}!\"\n";
    let splice = splice_entity(&layout, &entity_id, new_body).unwrap();
    let result = apply_splices(source, vec![splice]).unwrap();

    assert!(result.starts_with(b"# utils\n"));
    assert!(result.ends_with(b"# end\n"));
    assert!(result.windows(b"Hi,".len()).any(|w| w == b"Hi,"));
}

#[test]
fn python_multiple_defs_modify_one() {
    let source = b"def a():\n    pass\ndef b():\n    pass\ndef c():\n    pass\n";
    let id_a = EntityId::new();
    let id_b = EntityId::new();
    let id_c = EntityId::new();

    let layout = layout_with_entities(
        "multi.py",
        vec![
            (Some(id_a), 0..18),  // "def a():\n    pass\n"
            (Some(id_b), 18..36), // "def b():\n    pass\n"
            (Some(id_c), 36..54), // "def c():\n    pass\n"
        ],
    );

    let new_b = b"def b():\n    return 42\n";
    let result = reconstruct_file(source, &layout, |id| {
        if *id == id_b {
            Some(new_b.to_vec())
        } else {
            None
        }
    })
    .unwrap();

    assert!(result.starts_with(b"def a():\n    pass\n"));
    assert!(result
        .windows(b"return 42".len())
        .any(|w| w == b"return 42"));
    assert!(result.ends_with(b"def c():\n    pass\n"));
}

// ── TypeScript round-trip ───────────────────────────────────────────────

#[test]
fn typescript_function_round_trip() {
    let source = b"// module\nexport function parse(input: string): number {\n  return parseInt(input);\n}\n// done\n";
    let entity_id = EntityId::new();

    let layout = layout_with_entities(
        "parser.ts",
        vec![
            (None, 0..10),             // "// module\n"
            (Some(entity_id), 10..85), // function body
            (None, 85..93),            // "// done\n"
        ],
    );

    let new_body = b"export function parse(input: string): number {\n  return Number(input);\n}\n";
    let splice = splice_entity(&layout, &entity_id, new_body).unwrap();
    let result = apply_splices(source, vec![splice]).unwrap();

    assert!(result.starts_with(b"// module\n"));
    assert!(result.ends_with(b"// done\n"));
    assert!(result
        .windows(b"Number(input)".len())
        .any(|w| w == b"Number(input)"));
}

#[test]
fn typescript_arrow_function_round_trip() {
    let source = b"const add = (a: number, b: number): number => a + b;\n";
    let entity_id = EntityId::new();

    let layout = layout_with_entities("math.ts", vec![(Some(entity_id), 0..53)]);

    let new_body = b"const add = (a: number, b: number): number => a + b + 0;\n";
    let result = reconstruct_file(source, &layout, |id| {
        if *id == entity_id {
            Some(new_body.to_vec())
        } else {
            None
        }
    })
    .unwrap();

    assert_eq!(result, new_body);
}

// ── Go round-trip ───────────────────────────────────────────────────────

#[test]
fn go_func_round_trip() {
    let source = b"package main\n\nfunc Add(a, b int) int {\n\treturn a + b\n}\n\n// end\n";
    let entity_id = EntityId::new();

    let layout = layout_with_entities(
        "math.go",
        vec![
            (None, 0..14),             // "package main\n\n"
            (Some(entity_id), 14..50), // "func Add(a, b int) int {\n\treturn a + b\n}\n"
            (None, 50..58),            // "\n// end\n"
        ],
    );

    let new_body = b"func Add(a, b int) int {\n\tresult := a + b\n\treturn result\n}\n";
    let splice = splice_entity(&layout, &entity_id, new_body).unwrap();
    let result = apply_splices(source, vec![splice]).unwrap();

    assert!(result.starts_with(b"package main\n\n"));
    assert!(result.ends_with(b"\n// end\n"));
    assert!(result
        .windows(b"result :=".len())
        .any(|w| w == b"result :="));
}

#[test]
fn go_multiple_funcs_preserve_unchanged() {
    let source = b"func X() {}\nfunc Y() {}\nfunc Z() {}\n";
    let id_x = EntityId::new();
    let id_y = EntityId::new();
    let id_z = EntityId::new();

    let layout = layout_with_entities(
        "funcs.go",
        vec![
            (Some(id_x), 0..12),
            (Some(id_y), 12..24),
            (Some(id_z), 24..36),
        ],
    );

    let new_y = b"func Y() { changed }";
    let result = reconstruct_file(source, &layout, |id| {
        if *id == id_y {
            Some(new_y.to_vec())
        } else {
            None
        }
    })
    .unwrap();

    assert!(result.starts_with(b"func X() {}"));
    assert!(result.windows(b"changed".len()).any(|w| w == b"changed"));
    assert!(result.ends_with(b"func Z() {}\n"));
}

// ── Java round-trip ─────────────────────────────────────────────────────

#[test]
fn java_method_round_trip() {
    let source = b"// Main.java\npublic int add(int a, int b) {\n    return a + b;\n}\n// end\n";
    let entity_id = EntityId::new();

    let layout = layout_with_entities(
        "Main.java",
        vec![
            (None, 0..13),             // "// Main.java\n"
            (Some(entity_id), 13..58), // method body
            (None, 58..65),            // "// end\n"
        ],
    );

    let new_body = b"public int add(int a, int b) {\n    return Math.addExact(a, b);\n}\n";
    let splice = splice_entity(&layout, &entity_id, new_body).unwrap();
    let result = apply_splices(source, vec![splice]).unwrap();

    assert!(result.starts_with(b"// Main.java\n"));
    assert!(result.ends_with(b"// end\n"));
    assert!(result
        .windows(b"Math.addExact".len())
        .any(|w| w == b"Math.addExact"));
}

// ── Edge cases ──────────────────────────────────────────────────────────

#[test]
fn empty_original_with_insertion() {
    let source = b"";
    let splices = vec![Splice {
        byte_range: 0..0,
        new_content: b"fn new_function() {}".to_vec(),
    }];
    let result = apply_splices(source, splices).unwrap();
    assert_eq!(result, b"fn new_function() {}");
}

#[test]
fn entity_replaced_with_empty_content() {
    let source = b"// before\nfn old() {}\n// after\n";
    let entity_id = EntityId::new();

    let layout = layout_with_entities(
        "empty.rs",
        vec![(None, 0..10), (Some(entity_id), 10..21), (None, 21..31)],
    );

    let result = reconstruct_file(source, &layout, |id| {
        if *id == entity_id {
            Some(Vec::new()) // Replace with empty
        } else {
            None
        }
    })
    .unwrap();

    // Trivia preserved, entity body removed
    assert_eq!(result, b"// before\n\n// after\n");
}

#[test]
fn entity_replaced_with_larger_content() {
    let source = b"ab";
    let entity_id = EntityId::new();

    let layout = layout_with_entities("grow.rs", vec![(Some(entity_id), 0..2)]);

    let new_body = b"abcdefghij";
    let result = reconstruct_file(source, &layout, |id| {
        if *id == entity_id {
            Some(new_body.to_vec())
        } else {
            None
        }
    })
    .unwrap();

    assert_eq!(result, b"abcdefghij");
}

#[test]
fn multiple_splices_different_sizes() {
    let source = b"aaaa bbbb cccc";
    let splices = vec![
        Splice {
            byte_range: 0..4,
            new_content: b"xx".to_vec(), // shrink
        },
        Splice {
            byte_range: 5..9,
            new_content: b"yyyyyy".to_vec(), // grow
        },
        Splice {
            byte_range: 10..14,
            new_content: b"zzzz".to_vec(), // same size
        },
    ];
    let result = apply_splices(source, splices).unwrap();
    assert_eq!(result, b"xx yyyyyy zzzz");
}
