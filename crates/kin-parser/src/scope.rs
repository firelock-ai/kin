// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! What namespace an entity lives in, one rule per language.
//!
//! Three classes, and which class a language is in decides where its answer
//! comes from rather than how confident it is.
//!
//! **Declared.** Java, Kotlin, Go, PHP, C++, C# and Ruby write the namespace in
//! the source. The extractor reads it and passes it in; nothing here guesses it.
//! When the extractor did not read one, the answer is [`EntityScope::NotComputed`],
//! never "no namespace", because those are different facts and a query that
//! confuses them narrows silently.
//!
//! **Derived.** Python, Rust, TypeScript and JavaScript put the namespace in the
//! layout: a directory tree plus a marker decides what an importer types. These
//! rules read the layout, and they read it through [`ScopeLayout`] rather than
//! off the disk, so the same rule answers from the graph at query time and from
//! a fixture in a test.
//!
//! **None.** C, HCL and Swift have no namespace at this level. C has none at
//! all, HCL has blocks rather than namespaces, and a Swift module is a
//! build-target property no source file declares, so deriving one from layout
//! would be an invention.
//!
//! Nothing here reads a file. Every input arrives as an argument.

use kin_model::{EntityScope, FilePathId, LanguageId, ScopeAbsence, ScopePath};

use crate::languages::{js_module_identity, TS_SUFFIXES};

/// The JavaScript suffixes, beside TypeScript's, so a `.mjs` module names itself
/// the way a `.ts` one does.
pub const JS_SUFFIXES: &[&str] = &[".mjs", ".cjs", ".jsx", ".js"];

/// Which manifest declares a package for a language.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ManifestKind {
    /// `Cargo.toml`, whose `[package] name` is a Rust crate's root segment.
    Cargo,
    /// `package.json`, whose directory roots every module specifier under it.
    Node,
}

/// A package manifest the layout found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Manifest {
    /// The manifest's directory, repository-relative, empty for the root.
    pub dir: String,
    /// The package name it declares, when it declares one.
    pub name: Option<String>,
}

/// What the layout rules need to know, asked rather than read.
///
/// Every method answers about repository-relative directories. The
/// implementation in the product answers from the graph, so a scope is derived
/// from graph truth and the Zero File-Search Authority Rule holds; the
/// implementation in these tests answers from a list.
pub trait ScopeLayout {
    /// Whether `dir` holds an `__init__.py`, which is what makes it importable
    /// as a Python package and what ends the walk up.
    fn is_python_package(&self, dir: &str) -> bool;

    /// The nearest manifest of `kind` at or above `dir`.
    fn manifest_at_or_above(&self, dir: &str, kind: ManifestKind) -> Option<Manifest>;
}

/// What the caller knows about one entity, beside the layout.
#[derive(Debug, Clone, Copy)]
pub struct ScopeInputs<'a> {
    pub language: LanguageId,
    /// Where the entity's bytes sit. `None` for a graph-created entity that
    /// projection has not placed.
    pub file: Option<&'a FilePathId>,
    /// The namespace the source declares for this entity, when the language
    /// declares one and the extractor read it. A Java `package a.b;`, a Go
    /// `package queue`, the container chain of a C++ `namespace`.
    pub declared: Option<&'a str>,
}

/// The namespace an entity lives in.
pub fn derive<L: ScopeLayout>(inputs: ScopeInputs<'_>, layout: &L) -> EntityScope {
    use LanguageId::*;

    match inputs.language {
        C | Hcl | Swift => EntityScope::None(ScopeAbsence::LanguageHasNone),
        Java | Kotlin | Go | Php | Cpp | CSharp | Ruby => declared_scope(inputs.declared),
        Python => match inputs.file {
            Some(file) => python_scope(&file.0, layout),
            None => EntityScope::None(ScopeAbsence::NoFileOrigin),
        },
        Rust => match inputs.file {
            Some(file) => rust_scope(&file.0, inputs.declared, layout),
            None => EntityScope::None(ScopeAbsence::NoFileOrigin),
        },
        TypeScript | JavaScript => match inputs.file {
            Some(file) => ecmascript_scope(&file.0, inputs.language, layout),
            None => EntityScope::None(ScopeAbsence::NoFileOrigin),
        },
    }
}

/// A declared namespace is read, never inferred, so an unread one is uncomputed.
fn declared_scope(declared: Option<&str>) -> EntityScope {
    match declared.map(ScopePath::parse) {
        Some(Ok(path)) => EntityScope::Known(path),
        // A declaration that parses to nothing is a declaration of the root
        // namespace, which Java writes by omitting the clause and Go cannot
        // write at all. The file is in the default namespace, which is a fact,
        // not an absence of one.
        Some(Err(_)) => EntityScope::None(ScopeAbsence::PathNamesNoModule),
        None => EntityScope::NotComputed,
    }
}

/// Python: the ancestor directories that are packages, then the module.
///
/// `queue/models.py` under a `queue/__init__.py` is `queue.models`, which is
/// what an importer types, and what the extractor records today is `models`,
/// which three other files in the tree also record.
fn python_scope<L: ScopeLayout>(path: &str, layout: &L) -> EntityScope {
    let (module, is_package) = python_module_identity(path);
    let dir = parent_dir(path);
    // A package's `__init__.py` is named after its own directory, so the walk
    // for it starts one level higher or it would name itself twice.
    let walk_from = if is_package { parent_dir(dir) } else { dir };
    let mut segments = package_chain(walk_from, layout);
    if !module.is_empty() {
        segments.push(module);
    }
    known_or_absent(segments)
}

/// Rust: the crate, then the module path the layout spells, then inline modules.
///
/// `crates/kin-mcp/src/handlers/review.rs` in the crate `kin-mcp` is
/// `kin_mcp::handlers::review`, and a `mod tests` inside it is
/// `kin_mcp::handlers::review::tests`.
fn rust_scope<L: ScopeLayout>(path: &str, declared: Option<&str>, layout: &L) -> EntityScope {
    let Some(manifest) = layout.manifest_at_or_above(parent_dir(path), ManifestKind::Cargo) else {
        // Without a crate there is no root segment to hang the module path on,
        // and two crates' `queue::models` would collide in one repository.
        return EntityScope::NotComputed;
    };
    let Some(crate_name) = manifest.name else {
        return EntityScope::NotComputed;
    };
    let mut segments = vec![crate_name.replace('-', "_")];
    segments.extend(rust_module_path(path, &manifest.dir));
    if let Some(declared) = declared {
        if let Ok(inline) = ScopePath::parse(declared) {
            segments.extend(inline.segments().iter().cloned());
        }
    }
    known_or_absent(segments)
}

/// The module path a Rust file's location spells, relative to its crate.
///
/// Both layouts of one module answer the same: `src/queue/models.rs` and
/// `src/queue/models/mod.rs` are `queue::models`. A crate root, `src/lib.rs` or
/// `src/main.rs`, adds nothing, because the crate segment already names it.
fn rust_module_path(path: &str, crate_dir: &str) -> Vec<String> {
    let relative = strip_dir_prefix(path, crate_dir);
    let Some(under_src) = relative.strip_prefix("src/") else {
        return Vec::new();
    };
    let Some(stem) = under_src.strip_suffix(".rs") else {
        return Vec::new();
    };
    let mut segments: Vec<String> = stem.split('/').map(str::to_string).collect();
    match segments.last().map(String::as_str) {
        Some("lib") | Some("main") | Some("mod") => {
            segments.pop();
        }
        _ => {}
    }
    segments
}

/// TypeScript and JavaScript: the path from the package root, then the module.
///
/// A module specifier is what code names in an import, and it is read relative
/// to the package that owns the file, so `packages/repo-eval/src/score.ts` in
/// the package rooted at `packages/repo-eval` is `src.score`. With no manifest
/// above it the repository is the package, which is the single-package case
/// rather than a fallback.
fn ecmascript_scope<L: ScopeLayout>(path: &str, language: LanguageId, layout: &L) -> EntityScope {
    let suffixes = if language == LanguageId::TypeScript {
        TS_SUFFIXES
    } else {
        JS_SUFFIXES
    };
    let (module, is_index) = js_module_identity(path, suffixes);
    let dir = parent_dir(path);
    let root = layout
        .manifest_at_or_above(dir, ManifestKind::Node)
        .map(|manifest| manifest.dir)
        .unwrap_or_default();
    // An index file is named after its own directory, so the path to it stops
    // one level higher, exactly as a Python package's `__init__.py` does.
    let walk_from = if is_index { parent_dir(dir) } else { dir };
    let mut segments: Vec<String> = strip_dir_prefix(walk_from, &root)
        .split('/')
        .filter(|segment| !segment.is_empty())
        .map(str::to_string)
        .collect();
    if !module.is_empty() {
        segments.push(module);
    }
    known_or_absent(segments)
}

/// The Python module identity of a path: its name, and whether it is a package
/// marker. The same rule `languages::python` names its Module entities by.
fn python_module_identity(path: &str) -> (String, bool) {
    let basename = path.rsplit('/').next().unwrap_or(path);
    if basename == "__init__.py" {
        let package = parent_dir(path)
            .rsplit('/')
            .next()
            .unwrap_or("")
            .to_string();
        return (package, true);
    }
    (
        basename.strip_suffix(".py").unwrap_or("").to_string(),
        false,
    )
}

/// The importable package directories at and above `dir`, outermost first.
///
/// The walk stops at the first directory that is not a package, which is what
/// makes `a/b/c` with `__init__.py` in `b` and `c` but not `a` answer `b.c`.
fn package_chain<L: ScopeLayout>(dir: &str, layout: &L) -> Vec<String> {
    let mut chain: Vec<String> = Vec::new();
    let mut current = dir;
    while !current.is_empty() && layout.is_python_package(current) {
        chain.push(current.rsplit('/').next().unwrap_or(current).to_string());
        current = parent_dir(current);
    }
    chain.reverse();
    chain
}

/// The directory holding `path`, empty at the repository root.
fn parent_dir(path: &str) -> &str {
    match path.rsplit_once('/') {
        Some((head, _)) => head,
        None => "",
    }
}

/// `path` with `prefix` and its separator removed, when `prefix` is a directory
/// above it. Segment-wise, so `src` does not strip from `srcgen/x`.
fn strip_dir_prefix<'a>(path: &'a str, prefix: &str) -> &'a str {
    if prefix.is_empty() {
        return path;
    }
    path.strip_prefix(prefix)
        .and_then(|rest| {
            rest.strip_prefix('/')
                .or(Some(""))
                .filter(|_| rest.is_empty() || rest.starts_with('/'))
        })
        .unwrap_or(path)
}

/// Segments into a scope, or the reason they name no module.
fn known_or_absent(segments: Vec<String>) -> EntityScope {
    match ScopePath::new(segments) {
        Ok(path) => EntityScope::Known(path),
        Err(_) => EntityScope::None(ScopeAbsence::PathNamesNoModule),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A layout answered from two lists, so a rule is tested against a stated
    /// tree rather than against whatever the disk happens to hold.
    struct StaticLayout {
        python_packages: Vec<&'static str>,
        manifests: Vec<(&'static str, ManifestKind, Option<&'static str>)>,
    }

    impl ScopeLayout for StaticLayout {
        fn is_python_package(&self, dir: &str) -> bool {
            self.python_packages.contains(&dir)
        }

        fn manifest_at_or_above(&self, dir: &str, kind: ManifestKind) -> Option<Manifest> {
            let mut current = dir;
            loop {
                if let Some((found, _, name)) = self
                    .manifests
                    .iter()
                    .find(|(at, at_kind, _)| *at == current && *at_kind == kind)
                {
                    return Some(Manifest {
                        dir: (*found).to_string(),
                        name: name.map(str::to_string),
                    });
                }
                if current.is_empty() {
                    return None;
                }
                current = parent_dir(current);
            }
        }
    }

    fn empty_layout() -> StaticLayout {
        StaticLayout {
            python_packages: Vec::new(),
            manifests: Vec::new(),
        }
    }

    fn scope_of(language: LanguageId, path: &str, layout: &StaticLayout) -> EntityScope {
        derive(
            ScopeInputs {
                language,
                file: Some(&FilePathId(path.to_string())),
                declared: None,
            },
            layout,
        )
    }

    fn declared_of(language: LanguageId, declared: &str) -> EntityScope {
        derive(
            ScopeInputs {
                language,
                file: Some(&FilePathId("src/Thing.java".to_string())),
                declared: Some(declared),
            },
            &empty_layout(),
        )
    }

    fn known(scope: &EntityScope) -> String {
        match scope {
            EntityScope::Known(path) => path.to_string(),
            other => panic!("expected a known scope, got {other}"),
        }
    }

    #[test]
    fn a_language_with_no_namespace_says_so_rather_than_going_uncomputed() {
        for language in [LanguageId::C, LanguageId::Hcl, LanguageId::Swift] {
            assert_eq!(
                scope_of(language, "src/thing.c", &empty_layout()),
                EntityScope::None(ScopeAbsence::LanguageHasNone),
                "{language} has no namespace at this level, which is an answer"
            );
        }
    }

    #[test]
    fn a_declared_namespace_is_read_and_an_unread_one_is_uncomputed() {
        for language in [
            LanguageId::Java,
            LanguageId::Kotlin,
            LanguageId::Go,
            LanguageId::Php,
            LanguageId::Cpp,
            LanguageId::CSharp,
            LanguageId::Ruby,
        ] {
            assert_eq!(
                known(&declared_of(language, "com.example.queue")),
                "com.example.queue",
                "{language} declares its namespace and the rule reads it"
            );
            assert_eq!(
                scope_of(language, "src/Thing.java", &empty_layout()),
                EntityScope::NotComputed,
                "{language} with no declaration read is uncomputed, not scopeless"
            );
        }
    }

    #[test]
    fn a_declared_namespace_parses_from_every_spelling_its_language_writes() {
        assert_eq!(
            known(&declared_of(LanguageId::Php, "App\\Http")),
            "App.Http"
        );
        assert_eq!(
            known(&declared_of(LanguageId::Cpp, "outer::inner")),
            "outer.inner"
        );
        assert_eq!(known(&declared_of(LanguageId::Go, "queue")), "queue");
    }

    #[test]
    fn python_walks_the_package_chain_and_stops_where_it_ends() {
        let layout = StaticLayout {
            python_packages: vec!["a/queue", "a/queue/models"],
            manifests: Vec::new(),
        };
        assert_eq!(
            known(&scope_of(
                LanguageId::Python,
                "a/queue/models/user.py",
                &layout
            )),
            "queue.models.user",
            "the chain is the packages, and `a` is not one"
        );
        assert_eq!(
            known(&scope_of(LanguageId::Python, "a/loose.py", &layout)),
            "loose",
            "a module outside every package is named by itself"
        );
    }

    #[test]
    fn a_python_package_marker_is_named_after_its_directory_once() {
        let layout = StaticLayout {
            python_packages: vec!["queue", "queue/models"],
            manifests: Vec::new(),
        };
        assert_eq!(
            known(&scope_of(
                LanguageId::Python,
                "queue/models/__init__.py",
                &layout
            )),
            "queue.models",
            "the marker names its own directory, and must not name it twice"
        );
    }

    #[test]
    fn rust_names_the_crate_then_the_module_path_in_both_layouts() {
        let layout = StaticLayout {
            python_packages: Vec::new(),
            manifests: vec![("crates/kin-mcp", ManifestKind::Cargo, Some("kin-mcp"))],
        };
        assert_eq!(
            known(&scope_of(
                LanguageId::Rust,
                "crates/kin-mcp/src/handlers/review.rs",
                &layout
            )),
            "kin_mcp.handlers.review"
        );
        assert_eq!(
            known(&scope_of(
                LanguageId::Rust,
                "crates/kin-mcp/src/handlers/mod.rs",
                &layout
            )),
            "kin_mcp.handlers",
            "the two spellings of one module answer alike"
        );
        assert_eq!(
            known(&scope_of(
                LanguageId::Rust,
                "crates/kin-mcp/src/lib.rs",
                &layout
            )),
            "kin_mcp",
            "the crate root adds no segment because the crate segment names it"
        );
    }

    #[test]
    fn rust_without_a_crate_is_uncomputed_rather_than_rooted_at_the_repository() {
        assert_eq!(
            scope_of(LanguageId::Rust, "scripts/tool.rs", &empty_layout()),
            EntityScope::NotComputed,
            "two crates' queue::models would collide with no crate segment"
        );
    }

    #[test]
    fn rust_appends_the_inline_modules_the_extractor_read() {
        let layout = StaticLayout {
            python_packages: Vec::new(),
            manifests: vec![("", ManifestKind::Cargo, Some("kin-model"))],
        };
        let scope = derive(
            ScopeInputs {
                language: LanguageId::Rust,
                file: Some(&FilePathId("src/entity.rs".to_string())),
                declared: Some("tests"),
            },
            &layout,
        );
        assert_eq!(known(&scope), "kin_model.entity.tests");
    }

    #[test]
    fn a_module_specifier_is_read_from_the_package_that_owns_the_file() {
        let layout = StaticLayout {
            python_packages: Vec::new(),
            manifests: vec![
                ("", ManifestKind::Node, Some("kinlab")),
                (
                    "packages/repo-eval",
                    ManifestKind::Node,
                    Some("@kinlab/repo-eval"),
                ),
            ],
        };
        assert_eq!(
            known(&scope_of(
                LanguageId::TypeScript,
                "packages/repo-eval/src/score.ts",
                &layout
            )),
            "src.score",
            "the nearest package roots the specifier, not the repository"
        );
        assert_eq!(
            known(&scope_of(
                LanguageId::TypeScript,
                "services/gateway/main.ts",
                &layout
            )),
            "services.gateway.main",
            "a file under no nested package is rooted at the repository package"
        );
    }

    #[test]
    fn an_index_file_takes_the_directory_it_marks() {
        let layout = StaticLayout {
            python_packages: Vec::new(),
            manifests: vec![("", ManifestKind::Node, Some("kinlab"))],
        };
        assert_eq!(
            known(&scope_of(
                LanguageId::TypeScript,
                "packages/ui/index.ts",
                &layout
            )),
            "packages.ui",
            "require('./packages/ui') names the directory, not an `index` module"
        );
        assert_eq!(
            known(&scope_of(LanguageId::JavaScript, "lib/index.js", &layout)),
            "lib"
        );
    }

    #[test]
    fn a_declaration_file_scopes_like_the_module_it_declares() {
        let layout = StaticLayout {
            python_packages: Vec::new(),
            manifests: vec![("", ManifestKind::Node, Some("kinlab"))],
        };
        assert_eq!(
            known(&scope_of(
                LanguageId::TypeScript,
                "types/marked.d.ts",
                &layout
            )),
            "types.marked",
            "the `.d.ts` suffix is stripped whole, not down to `marked.d`"
        );
    }

    #[test]
    fn an_entity_with_no_file_cannot_be_placed_by_layout() {
        for language in [
            LanguageId::Python,
            LanguageId::Rust,
            LanguageId::TypeScript,
            LanguageId::JavaScript,
        ] {
            assert_eq!(
                derive(
                    ScopeInputs {
                        language,
                        file: None,
                        declared: None
                    },
                    &empty_layout()
                ),
                EntityScope::None(ScopeAbsence::NoFileOrigin),
                "{language} derives from layout and there is no layout without a file"
            );
        }
    }

    #[test]
    fn a_root_level_index_names_the_repository_and_so_names_no_module() {
        let layout = StaticLayout {
            python_packages: Vec::new(),
            manifests: vec![("", ManifestKind::Node, Some("kinlab"))],
        };
        assert_eq!(
            scope_of(LanguageId::JavaScript, "index.js", &layout),
            EntityScope::None(ScopeAbsence::PathNamesNoModule),
            "there is no module above the package root to name"
        );
    }

    #[test]
    fn a_prefix_that_is_not_a_directory_boundary_does_not_strip() {
        assert_eq!(strip_dir_prefix("srcgen/x.ts", "src"), "srcgen/x.ts");
        assert_eq!(strip_dir_prefix("src/x.ts", "src"), "x.ts");
        assert_eq!(strip_dir_prefix("src", "src"), "");
        assert_eq!(strip_dir_prefix("src/x.ts", ""), "src/x.ts");
    }

    /// The positive control. Every assertion above this one is satisfied by a
    /// rule set that answers `NotComputed` for everything, so one arm has to
    /// require real scopes for real paths across all three classes.
    #[test]
    fn the_rules_produce_real_scopes_across_all_three_classes() {
        let layout = StaticLayout {
            python_packages: vec!["queue"],
            manifests: vec![
                ("", ManifestKind::Cargo, Some("kin-model")),
                ("", ManifestKind::Node, Some("kinlab")),
            ],
        };
        let cases: Vec<(LanguageId, &str, Option<&str>, &str)> = vec![
            (LanguageId::Python, "queue/models.py", None, "queue.models"),
            (LanguageId::Rust, "src/entity.rs", None, "kin_model.entity"),
            (LanguageId::TypeScript, "web/app.ts", None, "web.app"),
            (LanguageId::JavaScript, "web/app.js", None, "web.app"),
            (
                LanguageId::Java,
                "A.java",
                Some("com.example"),
                "com.example",
            ),
            (LanguageId::Go, "a.go", Some("queue"), "queue"),
        ];
        for (language, path, declared, expected) in cases {
            let scope = derive(
                ScopeInputs {
                    language,
                    file: Some(&FilePathId(path.to_string())),
                    declared,
                },
                &layout,
            );
            assert_eq!(known(&scope), expected, "{language} at {path}");
        }
    }
}
