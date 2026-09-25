// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! A call that resolves in its own file links that file's definition and no
//! same-named definition anywhere else, unless the name can mean something
//! else there.
//!
//! The linker's same-file tier binds a call to the entity of that name in the
//! calling file at full confidence. It also fanned out to every entity of the
//! same name in every other file, at the name-match confidence, on the theory
//! that the local entity might be a prototype whose body lives elsewhere. That
//! theory holds for a few shapes only, and the fan-out ran on every call. So a
//! helper defined in several files answered every one of those files' calls:
//! kin's own source defines `human_bytes` five times, and impact analysis
//! answered twenty callers for each of them, including callers in crates that
//! do not depend on the definition's crate.
//!
//! Each case here parses real source through the language's adapter and links
//! it through both linkers, batch and incremental, which must agree. The
//! positive half of every case is the control: the adapter did emit the bare
//! call and it bound the local definition, so a language that simply records no
//! call cannot pass as one the linker kept clean.
//!
//! The cases after the first are the shapes in which the call is still handed
//! on, because the destination can be elsewhere: a C prototype or a TypeScript
//! ambient declaration, whose body lives in another file; a Kotlin or Swift
//! top-level function, which another file can overload; a C++ overload the call
//! can see through a header it includes and that the argument count cannot
//! separate from the local definition; and a Python name an import can rebind,
//! which goes on to the import it names. The C++ default-argument case and the
//! unseen C++ overload are the counterweights: a header prototype of the very
//! function the file defines is not an overload, and neither is a same-named
//! function nothing the caller includes declares.

use std::collections::HashSet;

use kin_index::{link_cross_file, link_cross_file_incremental, FileParseData, IncrementalLinker};
use kin_model::{ArtifactId, Entity, EntityId, EntityKind, FilePathId, Relation, RelationKind};
use kin_parser::{
    CAdapter, CppAdapter, GoAdapter, JavaScriptAdapter, KotlinAdapter, LanguageAdapter,
    PythonAdapter, RustAdapter, SwiftAdapter, TypeScriptAdapter,
};

fn adapter_for(language: &str) -> Box<dyn LanguageAdapter> {
    match language {
        "c" => Box::new(CAdapter),
        "cpp" => Box::new(CppAdapter),
        "go" => Box::new(GoAdapter),
        "javascript" => Box::new(JavaScriptAdapter),
        "kotlin" => Box::new(KotlinAdapter),
        "python" => Box::new(PythonAdapter),
        "rust" => Box::new(RustAdapter),
        "swift" => Box::new(SwiftAdapter),
        "typescript" => Box::new(TypeScriptAdapter),
        other => panic!("no adapter wired for `{other}` in this suite"),
    }
}

fn parse(language: &str, file_path: &str, source: &str) -> FileParseData {
    let adapter = adapter_for(language);
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
        .filter(|f| f.file_path == file)
        .flat_map(|f| f.entities.iter())
        .filter(|e| e.name == name)
        // A C file holding a prototype and a definition of one name carries two
        // entities under it. The fixtures below never do, and a lookup that
        // silently picked one would hide that they had started to.
        .fold(None, |found: Option<EntityId>, e| {
            assert!(found.is_none(), "`{name}` names two entities in `{file}`");
            Some(e.id)
        })
        .unwrap_or_else(|| {
            let known: Vec<&str> = files
                .iter()
                .filter(|f| f.file_path == file)
                .flat_map(|f| f.entities.iter())
                .map(|e| e.name.as_str())
                .collect();
            panic!("entity `{name}` in `{file}` not found; the file holds {known:?}")
        })
}

/// Link through both linkers, assert they agree on every `Calls` edge and its
/// confidence, and return the batch edges.
fn link_both(files: &[FileParseData]) -> Vec<Relation> {
    let artifact_ids = files
        .iter()
        .map(|file| (file.file_path.clone(), ArtifactId::new()))
        .collect();
    let batch = link_cross_file(files, &artifact_ids)
        .expect("every fixture file has an explicitly assigned artifact identity");

    let mut linker = IncrementalLinker::new();
    for file in files {
        linker.add_file(
            &file.file_path,
            artifact_ids[&file.file_path],
            &file.entities,
        );
    }
    let incremental = link_cross_file_incremental(files, &linker)
        .expect("every fixture file has an explicitly assigned artifact identity");

    let calls = |relations: &[Relation]| -> HashSet<(EntityId, EntityId, u32)> {
        relations
            .iter()
            .filter(|r| r.kind == RelationKind::Calls)
            .filter_map(|r| {
                Some((
                    r.src.as_entity()?,
                    r.dst.as_entity()?,
                    r.confidence.to_bits(),
                ))
            })
            .collect()
    };
    assert_eq!(
        calls(&batch),
        calls(&incremental),
        "the batch and incremental linkers disagree on these files' Calls edges"
    );
    batch
}

/// Every `Calls` edge out of `src`, as (destination, confidence).
fn calls_from(relations: &[Relation], src: EntityId) -> Vec<(EntityId, f32)> {
    let mut out: Vec<(EntityId, f32)> = relations
        .iter()
        .filter(|r| r.kind == RelationKind::Calls && r.src.as_entity() == Some(src))
        .filter_map(|r| Some((r.dst.as_entity()?, r.confidence)))
        .collect();
    out.sort_by_key(|(id, _)| *id);
    out
}

/// One language's three files: two that define `helper` and call it from a
/// function of their own, and one that only defines it.
struct Case {
    language: &'static str,
    /// (path, caller name, source) for the two calling files.
    calling: [(&'static str, &'static str, &'static str); 2],
    /// (path, source) for the file that defines `helper` and calls nothing.
    bystander: (&'static str, &'static str),
}

const CASES: &[Case] = &[
    Case {
        language: "rust",
        calling: [
            (
                "crates/cli/src/byte_fmt.rs",
                "format_bytes",
                "pub fn helper(n: u64) -> u64 { n }\npub fn format_bytes(n: u64) -> u64 { helper(n) }\n",
            ),
            (
                "crates/core/src/init.rs",
                "report_size",
                "fn helper(n: u64) -> u64 { n + 1 }\npub fn report_size(n: u64) -> u64 { helper(n) }\n",
            ),
        ],
        bystander: (
            "crates/spawn/src/lib.rs",
            "pub fn helper(n: u64) -> u64 { n * 2 }\n",
        ),
    },
    Case {
        language: "python",
        calling: [
            (
                "pkg/cli/byte_fmt.py",
                "format_bytes",
                "def helper(n):\n    return n\n\n\ndef format_bytes(n):\n    return helper(n)\n",
            ),
            (
                "pkg/core/init.py",
                "report_size",
                "def helper(n):\n    return n + 1\n\n\ndef report_size(n):\n    return helper(n)\n",
            ),
        ],
        bystander: ("pkg/spawn/lib.py", "def helper(n):\n    return n * 2\n"),
    },
    Case {
        language: "go",
        calling: [
            (
                "cli/bytefmt/bytefmt.go",
                "FormatBytes",
                "package bytefmt\n\nfunc helper(n int) int { return n }\n\nfunc FormatBytes(n int) int { return helper(n) }\n",
            ),
            (
                "core/initattempt/init.go",
                "ReportSize",
                "package initattempt\n\nfunc helper(n int) int { return n + 1 }\n\nfunc ReportSize(n int) int { return helper(n) }\n",
            ),
        ],
        bystander: (
            "spawn/lib/lib.go",
            "package lib\n\nfunc helper(n int) int { return n * 2 }\n",
        ),
    },
    Case {
        language: "typescript",
        calling: [
            (
                "src/cli/byteFmt.ts",
                "formatBytes",
                "function helper(n: number): number { return n; }\nexport function formatBytes(n: number): number { return helper(n); }\n",
            ),
            (
                "src/core/init.ts",
                "reportSize",
                "function helper(n: number): number { return n + 1; }\nexport function reportSize(n: number): number { return helper(n); }\n",
            ),
        ],
        bystander: (
            "src/spawn/lib.ts",
            "export function helper(n: number): number { return n * 2; }\n",
        ),
    },
    Case {
        language: "javascript",
        calling: [
            (
                "lib/cli/byteFmt.js",
                "formatBytes",
                "function helper(n) { return n; }\nfunction formatBytes(n) { return helper(n); }\nmodule.exports = { formatBytes };\n",
            ),
            (
                "lib/core/init.js",
                "reportSize",
                "function helper(n) { return n + 1; }\nfunction reportSize(n) { return helper(n); }\nmodule.exports = { reportSize };\n",
            ),
        ],
        bystander: (
            "lib/spawn/lib.js",
            "function helper(n) { return n * 2; }\nmodule.exports = { helper };\n",
        ),
    },
    Case {
        language: "c",
        calling: [
            (
                "src/byte_fmt.c",
                "format_bytes",
                "static int helper(int n) { return n; }\nint format_bytes(int n) { return helper(n); }\n",
            ),
            (
                "src/init.c",
                "report_size",
                "static int helper(int n) { return n + 1; }\nint report_size(int n) { return helper(n); }\n",
            ),
        ],
        bystander: ("src/lib.c", "static int helper(int n) { return n * 2; }\n"),
    },
    // C++ overloads by parameter types, which the linker does not read, but a
    // call reaches only a function its translation unit declares. None of these
    // files includes anything, so no other `helper` is an overload of the local
    // one, and each file's `static` helper settles its own call.
    Case {
        language: "cpp",
        calling: [
            (
                "src/byte_fmt.cpp",
                "format_bytes",
                "static int helper(int n) { return n; }\nint format_bytes(int n) { return helper(n); }\n",
            ),
            (
                "src/init.cpp",
                "report_size",
                "static int helper(int n) { return n + 1; }\nint report_size(int n) { return helper(n); }\n",
            ),
        ],
        bystander: (
            "src/lib.cpp",
            "static int helper(int n) { return n * 2; }\n",
        ),
    },
];

#[test]
fn a_call_to_a_same_file_definition_links_no_same_named_definition_elsewhere() {
    for case in CASES {
        let language = case.language;
        let mut files: Vec<FileParseData> = case
            .calling
            .iter()
            .map(|(path, _, source)| parse(language, path, source))
            .collect();
        files.push(parse(language, case.bystander.0, case.bystander.1));
        let relations = link_both(&files);

        let helpers: Vec<EntityId> = case
            .calling
            .iter()
            .map(|(path, _, _)| *path)
            .chain(std::iter::once(case.bystander.0))
            .map(|path| entity_id(&files, path, "helper"))
            .collect();

        for (index, (path, caller, _)) in case.calling.iter().enumerate() {
            let caller_id = entity_id(&files, path, caller);
            let own = helpers[index];
            let edges = calls_from(&relations, caller_id);
            // The control: the adapter emitted the bare call and it reached the
            // definition in the caller's own file, parser-certain.
            assert!(
                edges.contains(&(own, 1.0)),
                "{language}: `{caller}` in {path} must bind its own `helper` at full \
                 confidence; its edges are {edges:?}"
            );
            // The subject: nothing else. Every other `helper` shares the name and
            // nothing more, so an edge to one is a caller that definition never
            // had.
            assert_eq!(
                edges,
                vec![(own, 1.0)],
                "{language}: `{caller}` in {path} resolved its call in its own file, so no \
                 same-named `helper` in another file may be linked as its callee"
            );
        }

        // Read from the destination's side, which is what `kin refs` and impact
        // analysis read: each definition answers its own file's caller, and the
        // definition nobody in its file calls answers nobody.
        for (index, helper) in helpers.iter().enumerate() {
            let callers: Vec<EntityId> = relations
                .iter()
                .filter(|r| r.kind == RelationKind::Calls && r.dst.as_entity() == Some(*helper))
                .filter_map(|r| r.src.as_entity())
                .collect();
            let expected: Vec<EntityId> = case
                .calling
                .get(index)
                .map(|(path, caller, _)| vec![entity_id(&files, path, caller)])
                .unwrap_or_default();
            assert_eq!(
                callers, expected,
                "{language}: the `helper` in file {index} answers exactly the callers in its \
                 own file"
            );
        }
    }
}

#[test]
fn a_c_prototype_still_reaches_the_definition_in_another_file() {
    // `app.c` declares `work` and calls it; `work.c` defines it. The local entity
    // is a prototype, which is the one shape in which the same-file match is not
    // the destination, so the definition is linked beside it as a candidate.
    let files = vec![
        parse(
            "c",
            "app.c",
            "int work(int a);\nint run(void) { return work(1); }\n",
        ),
        parse("c", "work.c", "int work(int a) { return a; }\n"),
        // A third `work`, defined in a file of its own with nothing tying it to
        // `app.c`, which a prototype's candidates legitimately include: a name
        // is all a prototype offers.
        parse("c", "other/work.c", "int work(int a) { return a + 1; }\n"),
    ];
    let relations = link_both(&files);

    let run = entity_id(&files, "app.c", "run");
    let prototype = entity_id(&files, "app.c", "work");
    let definition = entity_id(&files, "work.c", "work");
    let other = entity_id(&files, "other/work.c", "work");
    let edges = calls_from(&relations, run);
    assert!(
        edges.contains(&(prototype, 1.0)),
        "the local prototype takes the call: {edges:?}"
    );
    for candidate in [definition, other] {
        assert!(
            edges.contains(&(candidate, 0.7)),
            "a prototype's body lives elsewhere, so each same-named definition is a \
             name-only candidate: {edges:?}"
        );
    }
}

/// Parse `(language, path, source)` triples into one fixture set.
fn parse_all(files: &[(&str, &str, &str)]) -> Vec<FileParseData> {
    files
        .iter()
        .map(|(language, path, source)| parse(language, path, source))
        .collect()
}

#[test]
fn a_typescript_ambient_declaration_still_reaches_the_definition_in_another_file() {
    // `declare const helper` says the binding exists and gives it no value, the
    // TypeScript counterpart of a C prototype, so its callers are handed on to
    // the definition that shares its name.
    let files = parse_all(&[
        (
            "typescript",
            "src/app.ts",
            "declare const helper: (n: number) => number;\nexport function run(n: number): number { return helper(n); }\n",
        ),
        (
            "typescript",
            "lib/helper.ts",
            "export function helper(n: number): number { return n * 2; }\n",
        ),
    ]);
    let relations = link_both(&files);

    let run = entity_id(&files, "src/app.ts", "run");
    let declared = entity_id(&files, "src/app.ts", "helper");
    // `lib/helper.ts` also holds its own module surface, which TypeScript names
    // after the file's stem, so the name `helper` is carried twice there.
    let of_kind = |kind: EntityKind| {
        files
            .iter()
            .filter(|file| file.file_path == "lib/helper.ts")
            .flat_map(|file| file.entities.iter())
            .find(|entity| entity.name == "helper" && entity.kind == kind)
            .map(|entity| entity.id)
            .unwrap_or_else(|| panic!("no {kind:?} named `helper` in lib/helper.ts"))
    };
    let definition = of_kind(EntityKind::Function);
    let module = of_kind(EntityKind::Module);
    let edges = calls_from(&relations, run);
    assert!(
        edges.contains(&(declared, 1.0)),
        "the local declaration takes the call: {edges:?}"
    );
    assert!(
        edges.contains(&(definition, 0.7)),
        "an ambient declaration's value lives elsewhere, so the definition is a name-only \
         candidate: {edges:?}"
    );
    assert!(
        !edges.iter().any(|(id, _)| *id == module),
        "a module is never what a call reaches, whatever it is named: {edges:?}"
    );
    assert_eq!(edges.len(), 2, "nothing else: {edges:?}");
}

#[test]
fn a_kotlin_or_swift_call_is_handed_on_to_an_overload_in_another_file() {
    // Kotlin and Swift name a top-level function bare, and another file of the
    // same package or module can overload it by parameter types, which the
    // linker does not read. The local definition takes the call and the
    // same-named function in the other file stays linked as a candidate.
    let cases: [(&str, (&str, &str), (&str, &str)); 2] = [
        (
            "kotlin",
            (
                "app/Format.kt",
                "package app\n\nfun helper(n: Int): Int {\n    return n\n}\n\nfun formatBytes(n: Int): Int {\n    return helper(n)\n}\n",
            ),
            (
                "app/Text.kt",
                "package app\n\nfun helper(s: String): String {\n    return s\n}\n",
            ),
        ),
        (
            "swift",
            (
                "Sources/App/Format.swift",
                "func helper(_ n: Int) -> Int {\n    return n\n}\n\nfunc formatBytes(_ n: Int) -> Int {\n    return helper(n)\n}\n",
            ),
            (
                "Sources/App/Text.swift",
                "func helper(_ s: String) -> String {\n    return s\n}\n",
            ),
        ),
    ];
    for (language, (calling_path, calling_source), (other_path, other_source)) in cases {
        let files = parse_all(&[
            (language, calling_path, calling_source),
            (language, other_path, other_source),
        ]);
        let relations = link_both(&files);

        let caller = entity_id(&files, calling_path, "formatBytes");
        let own = entity_id(&files, calling_path, "helper");
        let overload = entity_id(&files, other_path, "helper");
        let edges = calls_from(&relations, caller);
        assert!(
            edges.contains(&(own, 1.0)),
            "{language}: the local definition takes the call: {edges:?}"
        );
        assert!(
            edges.contains(&(overload, 0.7)),
            "{language}: an overload in another file is a name-only candidate: {edges:?}"
        );
        assert_eq!(edges.len(), 2, "{language}: nothing else: {edges:?}");
    }
}

#[test]
fn a_cpp_call_the_argument_count_cannot_separate_is_handed_on() {
    // The header the caller includes declares three overloads of `helper`, and
    // `helper(double)` takes one argument too, so the count cannot say which of
    // the two one-argument overloads the call reaches: the other one's
    // definition is a candidate. `helper(int, int)` cannot take one argument and
    // is not.
    let files = parse_all(&[
        (
            "cpp",
            "src/helper.h",
            "int helper(int n);\nint helper(double d);\nint helper(int a, int b);\n",
        ),
        (
            "cpp",
            "src/scale.cpp",
            "#include \"helper.h\"\n\nint helper(int n) { return n; }\nint run(int n) { return helper(n); }\n",
        ),
        (
            "cpp",
            "src/ratio.cpp",
            "#include \"helper.h\"\n\nint helper(double d) { return 0; }\n",
        ),
        (
            "cpp",
            "src/pair.cpp",
            "#include \"helper.h\"\n\nint helper(int a, int b) { return a + b; }\n",
        ),
    ]);
    let relations = link_both(&files);

    let run = entity_id(&files, "src/scale.cpp", "run");
    let own = entity_id(&files, "src/scale.cpp", "helper");
    let same_count = entity_id(&files, "src/ratio.cpp", "helper");
    let other_count = entity_id(&files, "src/pair.cpp", "helper");
    let edges = calls_from(&relations, run);
    assert!(
        edges.contains(&(own, 1.0)),
        "the local definition takes the call: {edges:?}"
    );
    assert!(
        edges.contains(&(same_count, 0.7)),
        "an overload the header declares and the argument count admits is a candidate: \
         {edges:?}"
    );
    assert!(
        !edges.iter().any(|(id, _)| *id == other_count),
        "an overload the argument count rejects is not: {edges:?}"
    );
    assert_eq!(
        edges.len(),
        2,
        "the header's declarations give way to the definitions: {edges:?}"
    );
}

#[test]
fn a_cpp_overload_the_caller_cannot_see_is_no_candidate() {
    // The same two one-argument functions, but `scale.cpp` includes nothing that
    // declares `helper(double)`, so the call cannot reach it and settles on the
    // local definition.
    let files = parse_all(&[
        ("cpp", "src/ratio.h", "int helper(double d);\n"),
        (
            "cpp",
            "src/scale.cpp",
            "int helper(int n) { return n; }\nint run(int n) { return helper(n); }\n",
        ),
        (
            "cpp",
            "src/ratio.cpp",
            "#include \"ratio.h\"\n\nint helper(double d) { return 0; }\n",
        ),
    ]);
    let relations = link_both(&files);

    let run = entity_id(&files, "src/scale.cpp", "run");
    let own = entity_id(&files, "src/scale.cpp", "helper");
    assert_eq!(calls_from(&relations, run), vec![(own, 1.0)]);
}

#[test]
fn a_cpp_definition_takes_its_default_arguments_from_its_header_declaration() {
    // C++ writes a default argument on the declaration. Read alone, the
    // definition `scale(int n, int factor)` rejects the one-argument call its
    // own file makes, which handed that call to the header prototype of the
    // very same function as if it were another overload.
    let files = parse_all(&[
        ("cpp", "src/util.h", "int scale(int n, int factor = 2);\n"),
        (
            "cpp",
            "src/util.cpp",
            "#include \"util.h\"\n\nint scale(int n, int factor) { return n * factor; }\n\nint twice(int n) { return scale(n); }\n",
        ),
        (
            "cpp",
            "src/other.cpp",
            "int scale(int a, int b, int c) { return a * b * c; }\n",
        ),
    ]);
    let relations = link_both(&files);

    let twice = entity_id(&files, "src/util.cpp", "twice");
    let definition = entity_id(&files, "src/util.cpp", "scale");
    let edges = calls_from(&relations, twice);
    assert_eq!(
        edges,
        vec![(definition, 1.0)],
        "the definition admits the call through its declared default and settles it"
    );
}

#[test]
fn a_python_name_an_import_can_rebind_goes_on_to_the_import() {
    // `from ... import helper` after `def helper` rebinds the name, so the call
    // below reaches the imported function. Which binding a call reaches depends
    // on an order the linker does not model, so the local definition is only a
    // candidate, and the call goes on to the import, which resolves it to the
    // module it names and to no other `helper`.
    let files = parse_all(&[
        (
            "python",
            "pkg/cli/byte_fmt.py",
            "def helper(n):\n    return n\n\n\nfrom pkg.spawn.lib import helper\n\n\ndef format_bytes(n):\n    return helper(n)\n",
        ),
        ("python", "pkg/spawn/lib.py", "def helper(n):\n    return n * 2\n"),
        ("python", "pkg/other/lib.py", "def helper(n):\n    return n * 3\n"),
    ]);
    let relations = link_both(&files);

    let caller = entity_id(&files, "pkg/cli/byte_fmt.py", "format_bytes");
    let own = entity_id(&files, "pkg/cli/byte_fmt.py", "helper");
    let imported = entity_id(&files, "pkg/spawn/lib.py", "helper");
    let unrelated = entity_id(&files, "pkg/other/lib.py", "helper");
    let edges = calls_from(&relations, caller);
    assert!(
        edges.contains(&(own, 0.7)),
        "the local definition is a candidate, not a fact: {edges:?}"
    );
    let to_import = edges
        .iter()
        .find(|(id, _)| *id == imported)
        .unwrap_or_else(|| panic!("the import resolves the call: {edges:?}"));
    assert!(
        to_import.1 > 0.7,
        "the import names its module, so its edge is import-resolved: {edges:?}"
    );
    assert!(
        !edges.iter().any(|(id, _)| *id == unrelated),
        "a `helper` the file neither defines nor imports is no candidate: {edges:?}"
    );
}
