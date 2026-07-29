// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The capability fixture's `evidence_tests` entries are free text. Nothing in
//! the capability suite ties an entry to a test that exists, so a rename or a
//! deletion leaves a command citing a test that no longer runs, and a later
//! status flip inherits that citation as if it still proved something.
//!
//! Every entry is resolved here against an inventory of the workspace's test
//! functions. The inventory is built by scanning the sources rather than by
//! asking cargo: a recursive cargo invocation inside a test is neither hermetic
//! nor cheap, and the only questions an entry asks are whether a name is
//! defined and where.

use serde_json::Value;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

/// A test function defined somewhere in the workspace.
struct TestFunction {
    /// The segments that address it: crate (or integration-test target),
    /// module chain, function name.
    path: Vec<String>,
    /// The defining file, relative to the workspace root, so it compares
    /// directly against the paths the fixture writes.
    file: PathBuf,
}

impl TestFunction {
    fn name(&self) -> &str {
        self.path
            .last()
            .expect("a test path ends in its function name")
    }
}

/// The three shapes an `evidence_tests` entry takes.
enum Evidence {
    /// A source file whose tests are collectively the evidence:
    /// `crates/kin-cli/tests/init_json.rs`.
    File(String),
    /// One named test inside one file:
    /// `crates/kin-cli/tests/command_capabilities.rs::push_reaches_the_transfer_surface_instead_of_the_capability_gate`.
    FileScoped { file: String, function: String },
    /// A Rust path, qualified to whatever depth its author wrote. Both
    /// `kin_daemon::api::tests::foo` and `api::tests::foo` address one test, so
    /// an entry resolves when it is a suffix of a real test's path.
    Qualified(Vec<String>),
}

fn classify(entry: &str) -> Evidence {
    if let Some((file, function)) = entry.split_once(".rs::") {
        return Evidence::FileScoped {
            file: format!("{file}.rs"),
            function: function.to_string(),
        };
    }
    if entry.ends_with(".rs") {
        return Evidence::File(entry.to_string());
    }
    Evidence::Qualified(entry.split("::").map(str::to_string).collect())
}

/// The lowest test count that can still mean the scanner worked.
///
/// An inventory that came back empty would report every entry as dangling,
/// which reads as a fixture problem when it is a scanner problem. The floor is
/// far under the real count so it only ever fires on the latter.
const MINIMUM_PLAUSIBLE_TEST_COUNT: usize = 500;

#[test]
fn every_capability_evidence_entry_names_a_test_that_exists() {
    let root = workspace_root();
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/git-replacement-capabilities-v1.json");
    let report: Value = serde_json::from_str(
        &std::fs::read_to_string(&fixture)
            .unwrap_or_else(|error| panic!("read {}: {error}", fixture.display())),
    )
    .expect("capability fixture should be JSON");

    let inventory = collect_test_functions(&root);
    assert!(
        inventory.len() >= MINIMUM_PLAUSIBLE_TEST_COUNT,
        "the workspace test scan found only {} test functions under {}, so it is the scan \
         that is broken rather than the fixture",
        inventory.len(),
        root.display()
    );
    let files_defining_tests = inventory
        .iter()
        .map(|test| test.file.as_path())
        .collect::<BTreeSet<_>>();

    let mut dangling = Vec::new();
    for command in commands_of(&report) {
        let name = command["command"]
            .as_str()
            .expect("command should be a string");
        for entry in evidence_entries(command) {
            let unresolved = match classify(entry) {
                Evidence::File(file) => {
                    if !root.join(&file).is_file() {
                        Some("no such file in the workspace".to_string())
                    } else if !files_defining_tests.contains(Path::new(&file)) {
                        Some("file defines no test function".to_string())
                    } else {
                        None
                    }
                }
                Evidence::FileScoped { file, function } => {
                    if inventory
                        .iter()
                        .any(|test| test.file == Path::new(&file) && test.name() == function)
                    {
                        None
                    } else {
                        Some(format!("no test `{function}` in {file}"))
                    }
                }
                Evidence::Qualified(segments) => {
                    if inventory.iter().any(|test| test.path.ends_with(&segments)) {
                        None
                    } else {
                        Some(unresolved_path_reason(&inventory, &segments))
                    }
                }
            };
            if let Some(reason) = unresolved {
                dangling.push(format!("  [{name}] {entry}\n      {reason}"));
            }
        }
    }

    assert!(
        dangling.is_empty(),
        "{} capability evidence entries name tests that do not exist. Point each at the test \
         that carries the evidence now, or drop the claim:\n{}",
        dangling.len(),
        dangling.join("\n")
    );
}

/// A command that claims to be ready must cite something.
///
/// Resolving the named tests is worth nothing against a flip that names none,
/// which is the cheaper way to move a command to `ready` without evidence.
#[test]
fn every_ready_capability_cites_at_least_one_evidence_test() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/git-replacement-capabilities-v1.json");
    let report: Value = serde_json::from_str(
        &std::fs::read_to_string(&fixture)
            .unwrap_or_else(|error| panic!("read {}: {error}", fixture.display())),
    )
    .expect("capability fixture should be JSON");

    let uncited = commands_of(&report)
        .filter(|command| command["status"] == "ready")
        .filter(|command| evidence_entries(command).next().is_none())
        .map(|command| {
            command["command"]
                .as_str()
                .expect("command should be a string")
        })
        .collect::<Vec<_>>();

    assert!(
        uncited.is_empty(),
        "ready commands with no evidence_tests: {}",
        uncited.join(", ")
    );
}

fn commands_of(report: &Value) -> impl Iterator<Item = &Value> {
    report["commands"]
        .as_array()
        .expect("commands should be an array")
        .iter()
}

fn evidence_entries(command: &Value) -> impl Iterator<Item = &str> {
    command["evidence_tests"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|entry| {
            entry
                .as_str()
                .expect("evidence_tests entries should be strings")
        })
}

/// Says whether a qualified entry missed on the name or only on the prefix, so
/// a rename and a moved module do not produce the same message.
fn unresolved_path_reason(inventory: &[TestFunction], segments: &[String]) -> String {
    let name = segments.last().expect("an entry has at least one segment");
    let defined_at = inventory
        .iter()
        .filter(|test| test.name() == name)
        .map(|test| test.path.join("::"))
        .collect::<BTreeSet<_>>();
    if defined_at.is_empty() {
        format!("no test function named `{name}` in the workspace")
    } else {
        format!(
            "`{name}` exists but not under this path; it is defined as {}",
            defined_at.into_iter().collect::<Vec<_>>().join(", ")
        )
    }
}

fn workspace_root() -> PathBuf {
    let mut directory = Path::new(env!("CARGO_MANIFEST_DIR"));
    loop {
        let manifest = directory.join("Cargo.toml");
        if std::fs::read_to_string(&manifest)
            .is_ok_and(|text| text.lines().any(|line| line.trim() == "[workspace]"))
        {
            return directory.to_path_buf();
        }
        directory = directory
            .parent()
            .expect("a workspace manifest above crates/kin-cli");
    }
}

/// Every test function in every crate of the workspace.
fn collect_test_functions(root: &Path) -> Vec<TestFunction> {
    let mut tests = Vec::new();
    for manifest in crate_manifests(root) {
        let Some(crate_ident) = package_ident(&manifest) else {
            continue;
        };
        let directory = manifest
            .parent()
            .expect("a manifest path has a parent directory");

        // `src` files are addressed through the crate, `tests` files through
        // the integration-test target that the file itself names.
        for (subdirectory, prefix) in [("src", vec![crate_ident.clone()]), ("tests", Vec::new())] {
            let base = directory.join(subdirectory);
            for file in rust_sources(&base) {
                let mut chain = prefix.clone();
                chain.extend(module_chain(
                    file.strip_prefix(&base).expect("file is under its base"),
                ));
                let relative = file
                    .strip_prefix(root)
                    .expect("workspace files are under the workspace root")
                    .to_path_buf();
                scan_file(&file, &chain, &relative, &mut tests);
            }
        }
    }
    tests
}

fn crate_manifests(root: &Path) -> Vec<PathBuf> {
    let mut manifests = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let manifest = directory.join("Cargo.toml");
        if manifest.is_file() {
            manifests.push(manifest);
        }
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            // Build output and dot directories hold neither workspace sources
            // nor anything a fixture entry may cite.
            if path.is_dir() && name != "target" && !name.starts_with('.') {
                pending.push(path);
            }
        }
    }
    manifests
}

/// The `[package] name` of a manifest, as the identifier Rust paths use.
/// Virtual manifests have none and own no sources.
fn package_ident(manifest: &Path) -> Option<String> {
    let text = std::fs::read_to_string(manifest).ok()?;
    let mut in_package = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_package = line == "[package]";
            continue;
        }
        if !in_package {
            continue;
        }
        // Matching the bare `name` key, not every key that starts with it: a
        // `namespace` line must fall through rather than end the search and
        // drop the whole crate out of the inventory.
        if let Some(value) = line.strip_prefix("name") {
            if let Some(value) = value.trim_start().strip_prefix('=') {
                return Some(value.trim().trim_matches('"').replace('-', "_"));
            }
        }
    }
    None
}

fn rust_sources(base: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut pending = vec![base.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                files.push(path);
            }
        }
    }
    files
}

/// The module segments a file contributes, by Rust's file-to-module rules.
fn module_chain(relative: &Path) -> Vec<String> {
    let mut segments = relative
        .components()
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    let file = segments.pop().expect("a file path has a final component");
    let stem = file.strip_suffix(".rs").unwrap_or(&file);
    if !matches!(stem, "lib" | "main" | "mod") {
        segments.push(stem.to_string());
    }
    segments
}

fn scan_file(file: &Path, chain: &[String], relative: &Path, tests: &mut Vec<TestFunction>) {
    let Ok(source) = std::fs::read_to_string(file) else {
        return;
    };
    let source = blank_comments_and_literals(&source);
    let bytes = source.as_bytes();

    let mut modules: Vec<(String, usize)> = Vec::new();
    let mut depth = 0usize;
    let mut pending_module: Option<String> = None;
    let mut pending_test = false;
    let mut cursor = 0;

    while cursor < bytes.len() {
        match bytes[cursor] {
            b'{' => {
                depth += 1;
                if let Some(name) = pending_module.take() {
                    modules.push((name, depth));
                }
                cursor += 1;
            }
            b'}' => {
                depth = depth.saturating_sub(1);
                while modules.last().is_some_and(|(_, opened)| *opened > depth) {
                    modules.pop();
                }
                pending_test = false;
                cursor += 1;
            }
            b';' => {
                // `mod name;` declares a file module that is scanned on its own.
                pending_module = None;
                cursor += 1;
            }
            b'#' => {
                let (attribute, next) = read_attribute(bytes, cursor);
                if let Some(attribute) = attribute {
                    pending_test |= is_test_attribute(attribute);
                }
                cursor = next;
            }
            byte if is_ident_start(byte) => {
                let (word, next) = read_ident(bytes, cursor);
                cursor = next;
                match word {
                    "fn" => {
                        let (name, after) = read_ident(bytes, skip_space(bytes, cursor));
                        if !name.is_empty() {
                            cursor = after;
                            if pending_test {
                                let mut path = chain.to_vec();
                                path.extend(modules.iter().map(|(name, _)| name.clone()));
                                path.push(name.to_string());
                                tests.push(TestFunction {
                                    path,
                                    file: relative.to_path_buf(),
                                });
                            }
                        }
                        pending_test = false;
                    }
                    "mod" => {
                        let (name, after) = read_ident(bytes, skip_space(bytes, cursor));
                        if !name.is_empty() {
                            pending_module = Some(name.to_string());
                            cursor = after;
                        }
                        pending_test = false;
                    }
                    // Any other item keyword means the attribute run that is
                    // open did not belong to a test function after all.
                    "struct" | "enum" | "union" | "impl" | "trait" | "use" | "type" | "static"
                    | "let" | "macro_rules" => pending_test = false,
                    _ => {}
                }
            }
            _ => cursor += 1,
        }
    }
}

/// Reads the attribute starting at `cursor`, returning its inner text and the
/// index just past it. Anything that is not an attribute yields `None` and the
/// next index, so the caller always advances.
fn read_attribute(bytes: &[u8], cursor: usize) -> (Option<&str>, usize) {
    let open = match bytes.get(cursor + 1) {
        Some(b'[') => cursor + 2,
        Some(b'!') if bytes.get(cursor + 2) == Some(&b'[') => cursor + 3,
        _ => return (None, cursor + 1),
    };
    let mut depth = 1usize;
    let mut index = open;
    while index < bytes.len() {
        match bytes[index] {
            b'[' => depth += 1,
            b']' => {
                depth -= 1;
                if depth == 0 {
                    let inner = std::str::from_utf8(&bytes[open..index]).unwrap_or("");
                    return (Some(inner), index + 1);
                }
            }
            _ => {}
        }
        index += 1;
    }
    (None, bytes.len())
}

/// True for `#[test]` and for any `path::to::test`, including `#[tokio::test]`
/// and its parameterised form. Segment equality is what keeps `#[rstest]` and
/// `#[test_case(..)]` out.
fn is_test_attribute(attribute: &str) -> bool {
    let path = attribute
        .trim()
        .split(['(', ' ', '\n', '\t'])
        .next()
        .unwrap_or("");
    path.rsplit("::").next() == Some("test")
}

fn is_ident_start(byte: u8) -> bool {
    byte.is_ascii_alphabetic() || byte == b'_'
}

fn is_ident_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn read_ident(bytes: &[u8], cursor: usize) -> (&str, usize) {
    if cursor >= bytes.len() || !is_ident_start(bytes[cursor]) {
        return ("", cursor);
    }
    let mut end = cursor;
    while end < bytes.len() && is_ident_byte(bytes[end]) {
        end += 1;
    }
    (std::str::from_utf8(&bytes[cursor..end]).unwrap_or(""), end)
}

fn skip_space(bytes: &[u8], cursor: usize) -> usize {
    let mut index = cursor;
    while index < bytes.len() && bytes[index].is_ascii_whitespace() {
        index += 1;
    }
    index
}

/// Overwrites every comment and literal with spaces, leaving byte length and
/// line structure intact.
///
/// The module chain is recovered by counting braces, and these sources are full
/// of braces inside raw-string fixtures, inside `'{'` literals, and inside
/// commented-out code. Blanking them first is what keeps the chain from
/// drifting and reporting a live test as dangling.
fn blank_comments_and_literals(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut out = bytes.to_vec();
    let mut cursor = 0;

    while cursor < bytes.len() {
        // A quote or a raw-string prefix only opens a literal when it is not
        // itself the tail of an identifier.
        let after_ident = cursor > 0 && is_ident_byte(bytes[cursor - 1]);
        match bytes[cursor] {
            b'/' if bytes.get(cursor + 1) == Some(&b'/') => {
                while cursor < bytes.len() && bytes[cursor] != b'\n' {
                    out[cursor] = b' ';
                    cursor += 1;
                }
            }
            b'/' if bytes.get(cursor + 1) == Some(&b'*') => {
                cursor = blank_block_comment(bytes, &mut out, cursor);
            }
            b'"' => cursor = blank_quoted(bytes, &mut out, cursor),
            b'\'' => cursor = blank_char_literal(bytes, &mut out, cursor),
            b'r' | b'b' if !after_ident => match raw_string_open(bytes, cursor) {
                Some((hashes, quote)) => {
                    cursor = blank_raw_string(bytes, &mut out, cursor, hashes, quote);
                }
                None => cursor += 1,
            },
            _ => cursor += 1,
        }
    }

    String::from_utf8(out).expect("blanking replaces whole literals with ASCII spaces")
}

fn blank(out: &mut [u8], range: std::ops::Range<usize>) {
    for index in range {
        if out[index] != b'\n' {
            out[index] = b' ';
        }
    }
}

fn blank_block_comment(bytes: &[u8], out: &mut [u8], start: usize) -> usize {
    let mut depth = 0usize;
    let mut cursor = start;
    while cursor < bytes.len() {
        if bytes[cursor] == b'/' && bytes.get(cursor + 1) == Some(&b'*') {
            depth += 1;
            cursor += 2;
        } else if bytes[cursor] == b'*' && bytes.get(cursor + 1) == Some(&b'/') {
            depth -= 1;
            cursor += 2;
            if depth == 0 {
                break;
            }
        } else {
            cursor += 1;
        }
    }
    blank(out, start..cursor);
    cursor
}

fn blank_quoted(bytes: &[u8], out: &mut [u8], start: usize) -> usize {
    let mut cursor = start + 1;
    while cursor < bytes.len() {
        match bytes[cursor] {
            b'\\' => cursor += 2,
            b'"' => {
                cursor += 1;
                break;
            }
            _ => cursor += 1,
        }
    }
    let end = cursor.min(bytes.len());
    blank(out, start..end);
    end
}

/// Blanks a character literal, leaving a lifetime alone. `'a` in `Cow<'a, str>`
/// and `'outer:` on a loop are not literals, and treating one as an unterminated
/// literal would blank the rest of the file.
fn blank_char_literal(bytes: &[u8], out: &mut [u8], start: usize) -> usize {
    let body = start + 1;
    let end = match bytes.get(body) {
        Some(b'\\') => {
            let mut cursor = body + 2;
            while cursor < bytes.len() && bytes[cursor] != b'\'' {
                cursor += 1;
            }
            cursor + 1
        }
        Some(_) => {
            // One character, however many bytes it takes, then the closer.
            let mut cursor = body + 1;
            while cursor < bytes.len() && (bytes[cursor] & 0b1100_0000) == 0b1000_0000 {
                cursor += 1;
            }
            if bytes.get(cursor) != Some(&b'\'') {
                return start + 1;
            }
            cursor + 1
        }
        None => return start + 1,
    };
    let end = end.min(bytes.len());
    blank(out, start..end);
    end
}

/// Recognises `r"`, `r#"`, `br##"` and friends, returning the hash count and
/// the index of the opening quote.
fn raw_string_open(bytes: &[u8], start: usize) -> Option<(usize, usize)> {
    let mut cursor = start;
    if bytes[cursor] == b'b' {
        cursor += 1;
    }
    if bytes.get(cursor) != Some(&b'r') {
        return None;
    }
    cursor += 1;
    let hashes_start = cursor;
    while bytes.get(cursor) == Some(&b'#') {
        cursor += 1;
    }
    if bytes.get(cursor) != Some(&b'"') {
        return None;
    }
    Some((cursor - hashes_start, cursor))
}

fn blank_raw_string(
    bytes: &[u8],
    out: &mut [u8],
    start: usize,
    hashes: usize,
    quote: usize,
) -> usize {
    let mut cursor = quote + 1;
    let end = loop {
        if cursor >= bytes.len() {
            break bytes.len();
        }
        if bytes[cursor] == b'"' {
            let closing = cursor + 1;
            if bytes[closing..]
                .iter()
                .take(hashes)
                .filter(|b| **b == b'#')
                .count()
                == hashes
            {
                break closing + hashes;
            }
        }
        cursor += 1;
    };
    let end = end.min(bytes.len());
    blank(out, start..end);
    end
}
