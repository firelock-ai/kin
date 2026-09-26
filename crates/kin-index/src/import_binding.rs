// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Where an import coordinate lands in this repository, for the languages whose
//! import syntax the generic module-path resolver cannot read.
//!
//! `linker::resolve_module_path` understands a relative specifier, a repo-local
//! header, a monorepo package and a Python dotted module. A Go package path
//! reaches it through a dedicated branch. Nothing there reads a Rust `use`
//! path, a PHP namespace, a Swift module or a Java or Kotlin package that has
//! had its type name split off into the specifier, so those coordinates
//! resolved to nothing and no import edge of any kind was minted for them.
//!
//! What this module answers is narrower than that resolver, and deliberately:
//! given the coordinate an import statement wrote and the name it bound, which
//! file in this repository holds it, and is the binding the module itself or a
//! member inside it. The caller turns that into an edge; nothing here knows
//! about relations.
//!
//! Two rules run through every resolver below.
//!
//! A coordinate is matched as a PATH SUFFIX, longest first, because a build
//! layout puts a package under a source root the coordinate does not name:
//! `com.example.store` is `src/main/java/com/example/store`, and `App\Models`
//! is `src/Models` under a PSR-4 map this repository cannot read. Dropping
//! leading segments one at a time finds the root without guessing at its name.
//!
//! A member file refuses on ambiguity and a module directory does not. Two
//! files answering one member coordinate means the repository holds two
//! symbols of that name and nothing here can say which was imported, so no
//! edge is minted; a fabricated edge is worse than a missing one. A module
//! directory holds many files by construction, so it takes its lexicographically
//! smallest source file as the package's stable representative, which is the
//! rule `resolve_go_module_import` already resolves Go packages by.

use std::collections::HashSet;

/// The import syntax a file writes, read from the file's own extension.
///
/// This is the same shape `resolve_module_path` already uses to send a `.py`
/// importer to the Python resolver: the language a coordinate is written in is
/// a fact about the importing file, and the path is the only carrier of it that
/// every linking path holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ImportDialect {
    /// `import "github.com/org/repo/pkg/store"`, a slash path naming a package
    /// directory. The specifier binds the package, never a member.
    Go,
    /// `import com.example.store.Store;` and `import com.example.store.*`, a
    /// dotted package with the type name already split into the specifier.
    JavaLike,
    /// `use App\Models\User;`, a backslash coordinate that carries the member.
    Php,
    /// `use crate::store::Store;`, a `::` path whose last segment is either a
    /// member of the module before it or a module of its own.
    Rust,
    /// `import Store` and `import struct Store.Record`, a module name that is a
    /// directory here and an optional dotted member inside it.
    Swift,
}

impl ImportDialect {
    /// The dialect `path` writes its imports in, or `None` for a language the
    /// generic resolver already answers for.
    pub(crate) fn of_path(path: &str) -> Option<Self> {
        match path.rsplit('.').next()? {
            "go" => Some(Self::Go),
            "java" | "kt" | "kts" => Some(Self::JavaLike),
            "php" => Some(Self::Php),
            "rs" => Some(Self::Rust),
            "swift" => Some(Self::Swift),
            _ => None,
        }
    }

    /// Source extensions a file of this dialect's own language can carry.
    fn extensions(self) -> &'static [&'static str] {
        match self {
            Self::Go => &["go"],
            Self::JavaLike => &["java", "kt", "kts"],
            Self::Php => &["php"],
            Self::Rust => &["rs"],
            Self::Swift => &["swift"],
        }
    }

    /// The separator this dialect writes between coordinate segments.
    fn separators(self) -> &'static [char] {
        match self {
            Self::Go => &['/'],
            Self::JavaLike | Self::Swift => &['.'],
            Self::Php => &['\\'],
            Self::Rust => &[':'],
        }
    }
}

/// What an import specifier bound, once the repository was searched for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SpecifierBinding {
    /// The repository file the coordinate landed in.
    pub(crate) file: String,
    /// The name to bind inside that file, or `None` when the specifier named
    /// the module itself rather than a member of it.
    pub(crate) member: Option<String>,
}

/// Bind one import specifier to a file in this repository.
///
/// `module_path` is the coordinate the import statement wrote and `member` is
/// the name the specifier bound, as the adapter split them. The split differs
/// per language and this function is where that difference is spent: Java and
/// Kotlin hand over a package and a type, PHP hands over one coordinate that
/// already ends in the type, Go hands over a package and the package's own
/// name, and Rust hands over a module path whose last segment may be either.
pub(crate) fn bind_import_specifier<S>(
    importer_file: &str,
    module_path: &str,
    member: Option<&str>,
    known_files: &HashSet<S>,
) -> Option<SpecifierBinding>
where
    S: std::borrow::Borrow<str> + std::hash::Hash + Eq,
{
    let dialect = ImportDialect::of_path(importer_file)?;
    let segments = coordinate_segments(dialect, module_path);
    let member = member
        .map(str::trim)
        .filter(|name| !name.is_empty() && *name != "*" && *name != "self");

    match dialect {
        // A Go import names a package directory and binds the package. The
        // specifier's name is the package's own local name, never a symbol the
        // target declares, so scoring it against the target's symbols would
        // report a miss for a claim the import never made.
        ImportDialect::Go => module_binding(dialect, &segments, 1, known_files),

        // A Java or Kotlin import writes the type into the specifier, so the
        // member's own file is `<package>/<Type>.java`. A wildcard import
        // carries no member and lands on the package instead.
        ImportDialect::JavaLike => match member {
            Some(member) => member_binding(dialect, &segments, member, known_files)
                .or_else(|| module_binding(dialect, &segments, 1, known_files))
                // `import static com.example.Util.helper;` writes the TYPE into
                // the module path and the member into the specifier, so the
                // file is the type's and the member lives inside it.
                .or_else(|| {
                    let (type_name, namespace) = segments.split_last()?;
                    let binding = member_binding(dialect, namespace, type_name, known_files)?;
                    Some(SpecifierBinding {
                        file: binding.file,
                        member: Some(member.to_string()),
                    })
                }),
            None => module_binding(dialect, &segments, 1, known_files),
        },

        // A PHP `use` writes the whole coordinate, so the last segment is the
        // member and everything before it is the namespace.
        ImportDialect::Php => {
            let (last, namespace) = segments.split_last()?;
            member_binding(dialect, namespace, last, known_files)
                .or_else(|| module_binding(dialect, &segments, 1, known_files))
        }

        // A Rust `use` path's last segment is a module of its own as often as
        // it is a member of the module before it, and the repository settles
        // which: a file answering `<path>/<name>.rs` makes it a module.
        ImportDialect::Rust => {
            let segments = strip_rust_anchor(&segments);
            match member {
                Some(member) => {
                    let mut with_member = segments.clone();
                    with_member.push(member.to_string());
                    // The floor keeps the innermost module segment beside the
                    // name. Letting `crate::a::b::C` degrade to a bare `C.rs`
                    // would bind a declaration to an unrelated file that
                    // happens to be named after it, ahead of the module the
                    // coordinate really wrote.
                    let floor = with_member.len().min(2);
                    module_binding(dialect, &with_member, floor, known_files).or_else(|| {
                        // Not a module of its own, so it is a declaration inside
                        // the module before it, whose own file is what the
                        // coordinate names.
                        module_binding(dialect, &segments, 1, known_files).map(|binding| {
                            SpecifierBinding {
                                file: binding.file,
                                member: Some(member.to_string()),
                            }
                        })
                    })
                }
                None => module_binding(dialect, &segments, 1, known_files),
            }
        }

        // A Swift module is a directory and `import struct Store.Record` writes
        // the member into the coordinate's tail.
        ImportDialect::Swift => match segments.split_first() {
            Some((module, [])) => {
                module_binding(dialect, std::slice::from_ref(module), 1, known_files)
            }
            Some((module, rest)) => {
                let last = rest.last()?;
                member_binding(dialect, std::slice::from_ref(module), last, known_files).or_else(
                    || module_binding(dialect, std::slice::from_ref(module), 1, known_files),
                )
            }
            None => None,
        },
    }
}

/// Split a coordinate into its segments, dropping the empties a `::` or a
/// leading separator leaves behind.
fn coordinate_segments(dialect: ImportDialect, module_path: &str) -> Vec<String> {
    module_path
        .split(dialect.separators())
        .map(str::trim)
        .filter(|segment| !segment.is_empty())
        .map(str::to_string)
        .collect()
}

/// Drop the anchor a Rust `use` path opens with.
///
/// `crate`, `self` and `super` name a position in the module tree rather than a
/// directory on disk. `super` in particular climbs, and this module cannot
/// climb without knowing which module the importing file is, so the anchor is
/// dropped and the suffix search below is left to find the rest. That makes
/// `super::store::Store` and `crate::store::Store` reach the same file, which
/// is right whenever the repository holds one `store` and is why the suffix
/// search refuses when it holds two.
fn strip_rust_anchor(segments: &[String]) -> Vec<String> {
    segments
        .iter()
        .skip_while(|segment| matches!(segment.as_str(), "crate" | "self" | "super"))
        .cloned()
        .collect()
}

/// The file a member coordinate names, or `None` when the repository holds no
/// such file or holds more than one at the same specificity.
fn member_binding<S>(
    dialect: ImportDialect,
    namespace: &[String],
    member: &str,
    known_files: &HashSet<S>,
) -> Option<SpecifierBinding>
where
    S: std::borrow::Borrow<str> + std::hash::Hash + Eq,
{
    let mut segments = namespace.to_vec();
    segments.push(member.to_string());
    // How far the suffix search may degrade. `com.example.store.Store` must not
    // fall all the way to `Store.java`, because `com/example/mystore/Store.java`
    // answers that and is a different package; keeping the innermost namespace
    // segment is what stops it. A coordinate whose namespace is one segment is
    // the case where that segment IS the root the layout maps away, as PSR-4
    // maps `App\` onto `src/`, so there the bare member is the only thing left
    // to match on.
    let floor = if namespace.len() <= 1 { 1 } else { 2 };
    let file = unique_file_for_suffix(dialect, &segments, floor, known_files)?;
    Some(SpecifierBinding {
        file,
        member: Some(member.to_string()),
    })
}

/// The file that represents a module coordinate.
///
/// A module that is a file of its own answers first; a module that is a
/// directory answers with the lexicographically smallest source file directly
/// inside it, which is how a Go package has had a stable representative since
/// `resolve_go_module_import` was written.
fn module_binding<S>(
    dialect: ImportDialect,
    segments: &[String],
    floor: usize,
    known_files: &HashSet<S>,
) -> Option<SpecifierBinding>
where
    S: std::borrow::Borrow<str> + std::hash::Hash + Eq,
{
    if segments.is_empty() {
        return None;
    }
    // Rust is the only dialect here whose module can be a file: `crate::store`
    // is `store.rs` as readily as `store/mod.rs`. A Go package, a Java or Kotlin
    // package, a PHP namespace and a Swift module are directories, and letting
    // `internal/store/store.go` answer for the package `internal/store` would
    // pick a member file and call it the package.
    if dialect == ImportDialect::Rust {
        if let Some(file) = unique_file_for_suffix(dialect, segments, floor, known_files) {
            return Some(SpecifierBinding { file, member: None });
        }
    }
    let file = directory_representative(dialect, segments, known_files)?;
    Some(SpecifierBinding { file, member: None })
}

/// The one file whose path ends in `<segments>.<ext>`, matched longest-suffix
/// first and refusing where a suffix length answers more than once.
fn unique_file_for_suffix<S>(
    dialect: ImportDialect,
    segments: &[String],
    floor: usize,
    known_files: &HashSet<S>,
) -> Option<String>
where
    S: std::borrow::Borrow<str> + std::hash::Hash + Eq,
{
    let deepest = segments.len().saturating_sub(floor.max(1));
    for drop in 0..=deepest {
        let stem = segments[drop..].join("/");
        if stem.is_empty() {
            continue;
        }
        let mut matched: Vec<&str> = Vec::new();
        for extension in dialect.extensions() {
            // `<stem>.<ext>` is the module's own file and `<stem>/mod.rs` is the
            // directory form Rust writes the same module as. Both are the module
            // itself, so both are candidates at this suffix length.
            for tail in [
                format!("{stem}.{extension}"),
                format!("{stem}/mod.{extension}"),
            ] {
                for file in known_files.iter() {
                    let file = file.borrow();
                    if path_ends_with_segments(file, &tail) && !matched.contains(&file) {
                        matched.push(file);
                    }
                }
            }
        }
        match matched.len() {
            0 => continue,
            1 => return Some(matched[0].to_string()),
            // Ambiguous at this specificity. A shorter suffix is strictly less
            // specific and cannot settle what this one could not, so the search
            // stops here rather than walking down into a worse answer.
            _ => return None,
        }
    }
    None
}

/// The lexicographically smallest source file directly inside the directory
/// `segments` names, matched longest-suffix first.
fn directory_representative<S>(
    dialect: ImportDialect,
    segments: &[String],
    known_files: &HashSet<S>,
) -> Option<String>
where
    S: std::borrow::Borrow<str> + std::hash::Hash + Eq,
{
    for drop in 0..segments.len() {
        let directory = segments[drop..].join("/");
        if directory.is_empty() {
            continue;
        }
        let mut best: Option<&str> = None;
        let mut directories: Vec<&str> = Vec::new();
        for file in known_files.iter() {
            let file = file.borrow();
            let Some(name) = file_in_directory(file, &directory) else {
                continue;
            };
            let has_extension = dialect
                .extensions()
                .iter()
                .any(|extension| name.ends_with(&format!(".{extension}")));
            if !has_extension {
                continue;
            }
            let owner = &file[..file.len() - name.len() - 1];
            if !directories.contains(&owner) {
                directories.push(owner);
            }
            if best.is_none_or(|current| file < current) {
                best = Some(file);
            }
        }
        // Two directories answering one coordinate is the same ambiguity a
        // member file refuses on: the repository holds the package twice and
        // nothing here can say which was imported.
        if directories.len() > 1 {
            return None;
        }
        if let Some(best) = best {
            return Some(best.to_string());
        }
    }
    None
}

/// Whether `path` ends in `tail` on a path-segment boundary, so `store/User.php`
/// matches `src/Models/store/User.php` and never `src/mystore/User.php`.
fn path_ends_with_segments(path: &str, tail: &str) -> bool {
    if path == tail {
        return true;
    }
    path.len() > tail.len()
        && path.ends_with(tail)
        && path.as_bytes()[path.len() - tail.len() - 1] == b'/'
}

/// The file name of `path` when `path` sits DIRECTLY in the directory `tail`
/// names, on a path-segment boundary.
fn file_in_directory<'a>(path: &'a str, tail: &str) -> Option<&'a str> {
    let (directory, name) = path.rsplit_once('/')?;
    path_ends_with_segments(directory, tail).then_some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn files(paths: &[&str]) -> HashSet<String> {
        paths.iter().map(|path| (*path).to_string()).collect()
    }

    #[test]
    fn a_dialect_is_read_from_the_importing_file() {
        assert_eq!(
            ImportDialect::of_path("cmd/main.go"),
            Some(ImportDialect::Go)
        );
        assert_eq!(
            ImportDialect::of_path("src/main/java/A.java"),
            Some(ImportDialect::JavaLike)
        );
        assert_eq!(
            ImportDialect::of_path("src/A.kt"),
            Some(ImportDialect::JavaLike)
        );
        assert_eq!(
            ImportDialect::of_path("src/A.php"),
            Some(ImportDialect::Php)
        );
        assert_eq!(
            ImportDialect::of_path("src/a.rs"),
            Some(ImportDialect::Rust)
        );
        assert_eq!(
            ImportDialect::of_path("Sources/A.swift"),
            Some(ImportDialect::Swift)
        );
        // A language the generic resolver already answers for is not this
        // module's business, and saying otherwise would route it here.
        assert_eq!(ImportDialect::of_path("src/a.ts"), None);
        assert_eq!(ImportDialect::of_path("nk/a.py"), None);
    }

    #[test]
    fn a_go_package_path_binds_its_directory_representative() {
        let known = files(&[
            "internal/store/store.go",
            "internal/store/aaa.go",
            "cmd/main.go",
        ]);
        let bound = bind_import_specifier(
            "cmd/main.go",
            "github.com/org/repo/internal/store",
            Some("store"),
            &known,
        )
        .expect("a Go package directory binds");
        assert_eq!(bound.file, "internal/store/aaa.go");
        assert_eq!(bound.member, None);
    }

    #[test]
    fn a_java_import_binds_the_type_the_specifier_named() {
        let known = files(&[
            "src/main/java/com/example/store/Store.java",
            "src/main/java/com/example/app/App.java",
        ]);
        let bound = bind_import_specifier(
            "src/main/java/com/example/app/App.java",
            "com.example.store",
            Some("Store"),
            &known,
        )
        .expect("a Java type binds");
        assert_eq!(bound.file, "src/main/java/com/example/store/Store.java");
        assert_eq!(bound.member.as_deref(), Some("Store"));
    }

    #[test]
    fn a_java_wildcard_import_binds_the_package() {
        let known = files(&[
            "src/main/java/com/example/store/Store.java",
            "src/main/java/com/example/store/Record.java",
            "src/main/java/com/example/app/App.java",
        ]);
        let bound = bind_import_specifier(
            "src/main/java/com/example/app/App.java",
            "com.example.store",
            Some("*"),
            &known,
        )
        .expect("a Java package binds");
        assert_eq!(bound.file, "src/main/java/com/example/store/Record.java");
        assert_eq!(bound.member, None);
    }

    #[test]
    fn a_php_use_binds_the_class_its_coordinate_ends_in() {
        let known = files(&["src/Models/User.php", "src/App.php"]);
        let bound = bind_import_specifier("src/App.php", "App\\Models\\User", Some("User"), &known)
            .expect("a PHP class binds");
        assert_eq!(bound.file, "src/Models/User.php");
        assert_eq!(bound.member.as_deref(), Some("User"));
    }

    #[test]
    fn a_rust_use_binds_a_member_of_the_module_before_it() {
        let known = files(&["src/store.rs", "src/app.rs"]);
        let bound = bind_import_specifier("src/app.rs", "crate::store", Some("Store"), &known)
            .expect("a Rust member binds");
        assert_eq!(bound.file, "src/store.rs");
        assert_eq!(bound.member.as_deref(), Some("Store"));
    }

    #[test]
    fn a_rust_use_whose_last_segment_is_itself_a_module_binds_that_module() {
        let known = files(&["src/store/records.rs", "src/app.rs"]);
        let bound = bind_import_specifier("src/app.rs", "crate::store", Some("records"), &known)
            .expect("a Rust submodule binds");
        assert_eq!(bound.file, "src/store/records.rs");
        assert_eq!(bound.member, None);
    }

    #[test]
    fn a_rust_module_written_as_a_directory_binds_its_mod_file() {
        let known = files(&["src/store/mod.rs", "src/app.rs"]);
        let bound = bind_import_specifier("src/app.rs", "crate::store", Some("Store"), &known)
            .expect("a Rust mod.rs binds");
        assert_eq!(bound.file, "src/store/mod.rs");
        assert_eq!(bound.member.as_deref(), Some("Store"));
    }

    #[test]
    fn a_swift_module_binds_its_directory_and_a_kinded_import_binds_the_member() {
        let known = files(&["Sources/Store/Record.swift", "Sources/App/App.swift"]);
        let module = bind_import_specifier("Sources/App/App.swift", "Store", Some("Store"), &known)
            .expect("a Swift module binds");
        assert_eq!(module.file, "Sources/Store/Record.swift");
        assert_eq!(module.member, None);

        let member = bind_import_specifier(
            "Sources/App/App.swift",
            "Store.Record",
            Some("Record"),
            &known,
        )
        .expect("a Swift member binds");
        assert_eq!(member.file, "Sources/Store/Record.swift");
        assert_eq!(member.member.as_deref(), Some("Record"));
    }

    #[test]
    fn a_java_static_import_binds_the_member_inside_the_type_it_names() {
        // `import static com.example.util.Text.trim;` writes the TYPE into the
        // module path and the member into the specifier, so the file is the
        // type's and the member is selected inside it.
        let known = files(&[
            "src/main/java/com/example/util/Text.java",
            "src/main/java/com/example/app/App.java",
        ]);
        let bound = bind_import_specifier(
            "src/main/java/com/example/app/App.java",
            "com.example.util.Text",
            Some("trim"),
            &known,
        )
        .expect("a Java static import binds");
        assert_eq!(bound.file, "src/main/java/com/example/util/Text.java");
        assert_eq!(bound.member.as_deref(), Some("trim"));
    }

    #[test]
    fn a_rust_coordinate_does_not_degrade_to_a_bare_file_of_the_same_name() {
        // `crate::a::b::C` must not bind `src/C.rs`, which is a different
        // module that happens to share the declaration's name. The module the
        // coordinate really wrote is `a/b`, and `C` is selected inside it.
        let known = files(&["src/a/b.rs", "src/C.rs", "src/app.rs"]);
        let bound = bind_import_specifier("src/app.rs", "crate::a::b", Some("C"), &known)
            .expect("the coordinate binds its own module");
        assert_eq!(bound.file, "src/a/b.rs");
        assert_eq!(bound.member.as_deref(), Some("C"));
    }

    #[test]
    fn a_coordinate_this_repository_does_not_hold_binds_nothing() {
        let known = files(&["src/app.rs", "src/main/java/com/example/app/App.java"]);
        assert_eq!(
            bind_import_specifier("src/app.rs", "serde::de", Some("Deserialize"), &known),
            None
        );
        assert_eq!(
            bind_import_specifier(
                "src/main/java/com/example/app/App.java",
                "java.util",
                Some("List"),
                &known
            ),
            None
        );
    }

    #[test]
    fn two_files_answering_one_member_coordinate_bind_nothing() {
        // `Store` under two source roots. Nothing here can say which the import
        // named, so the honest answer is no edge rather than the smaller path.
        let known = files(&[
            "src/main/java/com/example/store/Store.java",
            "extras/com/example/store/Store.java",
            "src/main/java/com/example/app/App.java",
        ]);
        assert_eq!(
            bind_import_specifier(
                "src/main/java/com/example/app/App.java",
                "com.example.store",
                Some("Store"),
                &known
            ),
            None
        );
    }

    #[test]
    fn a_suffix_matches_only_on_a_path_segment_boundary() {
        // `mystore/Store.java` ends in the same bytes as `store/Store.java` and
        // is a different package; matching it would bind the wrong file.
        let known = files(&[
            "src/main/java/com/example/mystore/Store.java",
            "src/main/java/com/example/app/App.java",
        ]);
        assert_eq!(
            bind_import_specifier(
                "src/main/java/com/example/app/App.java",
                "com.example.store",
                Some("Store"),
                &known
            ),
            None
        );
    }

    #[test]
    fn a_directory_representative_is_a_direct_child_and_not_a_descendant() {
        // A file in a SUBdirectory of the package is not in the package, and
        // binding it would make a nested package answer for its parent.
        let known = files(&["internal/store/nested/deep.go", "cmd/main.go"]);
        assert_eq!(
            bind_import_specifier(
                "cmd/main.go",
                "org/repo/internal/store",
                Some("store"),
                &known
            ),
            None
        );
    }
}
