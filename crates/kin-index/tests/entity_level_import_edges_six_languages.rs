// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Entity-level `Imports` edges for Go, Java, Kotlin, PHP, Rust and Swift.
//!
//! Measured before the change, on a Go store built from cli/cli: `Imports`
//! appears zero times in the relation census, in both the language-server tier
//! (0 of 66,545 relations) and the tier without one (0 of 35,814), against
//! 1,537 for a TypeScript store and 179 for a Python store. The product
//! disclosed it rather than hiding it, and the disclosure was exact: these six
//! languages minted no entity-rooted import edge at all, so "who imports this"
//! had no answer in any of them however the question was asked.
//!
//! Two halves were missing. Five of the six adapters emitted no `Module`
//! entity, and an entity-level import edge is sourced at the importing file's
//! module entity, so there was nothing for the edge to start from. And the
//! generic module-path resolver reads a relative specifier, a repo-local
//! header, a monorepo package, a Python dotted module and a Go module path; a
//! Rust `use` path, a PHP namespace, a Swift module and a Java or Kotlin
//! package whose type name was split into the specifier take none of those
//! branches, so there was nothing for the edge to end at either.
//!
//! Every case here drives the real adapter and the real linker. Four import
//! shapes are graded per language where the language writes them: a plain
//! import of a module, a selective import of a named member, an aliased
//! import, and an import of something this repository does not hold. The last
//! one must leave a disclosure rather than vanish.

use std::collections::{HashMap, HashSet};

use kin_index::{
    link_cross_file, link_cross_file_incremental, link_cross_file_with_completeness,
    FileParseCompletenessMap, FileParseData, IncrementalLinker, RelationResolution,
    IMPORT_RESOLUTION_COVERAGE_V1,
};
use kin_model::{
    ArtifactId, Entity, EntityKind, FilePathId, GraphNodeId, ParseCompleteness, Relation,
    RelationKind,
};
use kin_parser::{
    GoAdapter, JavaAdapter, KotlinAdapter, LanguageAdapter, PhpAdapter, RustAdapter, SwiftAdapter,
};

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

fn parse_with(adapter: &dyn LanguageAdapter, path: &str, src: &str) -> FileParseData {
    let file_id = FilePathId::new(path);
    let bytes = src.as_bytes();
    let tree = adapter.parse(bytes).expect("fixture parses");
    let output = adapter
        .extract(&tree, bytes, &file_id)
        .expect("fixture extracts");
    let entities: Vec<Entity> = output
        .entities
        .into_iter()
        .map(|entity| entity.into_entity_with_source(adapter.language_id(), &file_id, Some(bytes)))
        .collect();
    FileParseData {
        file_path: path.to_string(),
        entities,
        relations: output.relations,
        imports: output.imports,
    }
}

fn go(path: &str, src: &str) -> FileParseData {
    parse_with(&GoAdapter, path, src)
}
fn java(path: &str, src: &str) -> FileParseData {
    parse_with(&JavaAdapter, path, src)
}
fn kotlin(path: &str, src: &str) -> FileParseData {
    parse_with(&KotlinAdapter, path, src)
}
fn php(path: &str, src: &str) -> FileParseData {
    parse_with(&PhpAdapter, path, src)
}
fn rust(path: &str, src: &str) -> FileParseData {
    parse_with(&RustAdapter, path, src)
}
fn swift(path: &str, src: &str) -> FileParseData {
    parse_with(&SwiftAdapter, path, src)
}

fn artifact_ids(files: &[FileParseData]) -> HashMap<String, ArtifactId> {
    files
        .iter()
        .map(|file| (file.file_path.clone(), ArtifactId::new()))
        .collect()
}

/// Link through the batch linker and the incremental one, assert they agree on
/// every entity-rooted `Imports` edge, and return the batch relations.
///
/// The tier under test has a batch site and an incremental twin, and only the
/// batch one is reached by a cold `kin init`. Grading one leaves a warm relink
/// free to drop what a cold link found, which is the failure a daemon shows and
/// a fresh build does not.
fn link_both(files: &[FileParseData]) -> Vec<Relation> {
    let ids = artifact_ids(files);
    let batch = link_cross_file(files, &ids).expect("fixture links");

    let mut linker = IncrementalLinker::new();
    for file in files {
        linker.add_file(
            &file.file_path,
            *ids.get(&file.file_path)
                .expect("every fixture file has an id"),
            &file.entities,
        );
    }
    let incremental = link_cross_file_incremental(files, &linker).expect("fixture relinks");

    assert_eq!(
        import_pairs(files, &batch),
        import_pairs(files, &incremental),
        "the batch and incremental linkers disagree on this fixture's entity-level Imports edges"
    );
    assert_eq!(
        import_resolutions(&batch),
        import_resolutions(&incremental),
        "the batch and incremental linkers disagree on this fixture's import resolution tiers"
    );
    batch
}

/// Entity-rooted `Imports` edges as `(source entity name, destination entity
/// name)`, sorted.
///
/// Names rather than ids, because an assertion that reports `[]` against an
/// expected pair says which pair is missing and an assertion over ids does not.
fn import_pairs(files: &[FileParseData], relations: &[Relation]) -> Vec<(String, String)> {
    let name_of: HashMap<_, _> = files
        .iter()
        .flat_map(|file| file.entities.iter())
        .map(|entity| (entity.id, entity.name.clone()))
        .collect();
    let mut out: Vec<(String, String)> = relations
        .iter()
        .filter(|relation| relation.kind == RelationKind::Imports)
        .filter_map(|relation| match (relation.src, relation.dst) {
            (GraphNodeId::Entity(src), GraphNodeId::Entity(dst)) => {
                Some((name_of.get(&src)?.clone(), name_of.get(&dst)?.clone()))
            }
            _ => None,
        })
        .collect();
    out.sort();
    out.dedup();
    out
}

/// The resolution tier every entity-rooted `Imports` edge carries, sorted.
fn import_resolutions(relations: &[Relation]) -> Vec<&'static str> {
    let mut out: Vec<&'static str> = relations
        .iter()
        .filter(|relation| relation.kind == RelationKind::Imports)
        .filter(|relation| relation.src.as_entity().is_some() && relation.dst.as_entity().is_some())
        .map(|relation| RelationResolution::of(relation).as_str())
        .collect();
    out.sort_unstable();
    out
}

fn assert_imports(files: &[FileParseData], expected: &[(&str, &str)]) -> Vec<Relation> {
    let relations = link_both(files);
    let pairs = import_pairs(files, &relations);
    for (src, dst) in expected {
        assert!(
            pairs.contains(&((*src).to_string(), (*dst).to_string())),
            "no entity-level Imports edge from `{src}` to `{dst}`; the fixture produced {pairs:?}"
        );
    }
    relations
}

/// Every entity-rooted `Imports` edge in the fixture resolves to `import_scoped`.
///
/// This is the claim, not a detail. The destination is a module a coordinate
/// settled and a name selected inside it, never an export a specifier proved,
/// so an edge here must not carry the `type_resolved` tag an ECMAScript named
/// import earns. Weakening that would let `min_resolution: type_resolved` count
/// a package representative as a proven destination.
fn assert_every_import_is_import_scoped(relations: &[Relation]) {
    let tiers = import_resolutions(relations);
    assert!(
        !tiers.is_empty(),
        "the fixture produced no import edge at all"
    );
    assert!(
        tiers.iter().all(|tier| *tier == "import_scoped"),
        "every entity-level import edge in these languages is import_scoped; got {tiers:?}"
    );
}

/// What the per-file coverage certificate says about one file's imports:
/// `(statements the parser read, statements that reached this repository)`.
///
/// This is where an import of something this repository does not hold is
/// disclosed. The edge is not minted, because there is no destination to mint
/// it against, and the difference between these two numbers is the product
/// saying so rather than the file looking import-complete.
fn import_disclosure(files: &[FileParseData], file_path: &str) -> (u32, u32) {
    let ids = artifact_ids(files);
    let completeness: FileParseCompletenessMap = files
        .iter()
        .map(|file| (file.file_path.clone(), ParseCompleteness::Full))
        .collect();
    let relations = link_cross_file_with_completeness(files, &ids, &completeness)
        .expect("fixture links with completeness");
    let artifact = *ids.get(file_path).expect("the file has an artifact id");
    let evidence = relations
        .iter()
        .filter(|relation| relation.src == GraphNodeId::Artifact(artifact))
        .flat_map(|relation| relation.evidence.iter())
        .find(|evidence| {
            evidence.parser_rule.as_deref() == Some(IMPORT_RESOLUTION_COVERAGE_V1)
                && evidence.source_path.as_deref() == Some(file_path)
        })
        .unwrap_or_else(|| panic!("no import-resolution certificate for `{file_path}`"));
    let resolved: u32 = evidence
        .token
        .as_deref()
        .expect("the certificate carries a resolved count")
        .parse()
        .expect("the resolved count is a number");
    (evidence.occurrence_count, resolved)
}

/// The module surface entity names a file carries.
fn module_names(file: &FileParseData) -> Vec<&str> {
    file.entities
        .iter()
        .filter(|entity| entity.kind == EntityKind::Module)
        .map(|entity| entity.name.as_str())
        .collect()
}

/// The control every one of these cases needs.
///
/// An entity-level import edge is sourced at the importing file's module
/// entity. A fixture whose adapter emitted none produces zero edges for a
/// reason that has nothing to do with the linker, and reads identically to a
/// linker refusal, so the fixture would grade nothing.
fn assert_has_module_surface(file: &FileParseData) {
    assert!(
        !module_names(file).is_empty(),
        "`{}` carries no module entity, so no import edge could be sourced at it \
         whatever the linker does. Fix the adapter, not the assertion",
        file.file_path
    );
}

// ---------------------------------------------------------------------------
// Go
// ---------------------------------------------------------------------------

const GO_MAIN: &str = r#"package main

import (
	"fmt"
	"github.com/example/app/internal/store"
	alias "github.com/example/app/internal/audit"
)

func Run() {
	fmt.Println(store.Open())
	alias.Record()
}
"#;

const GO_STORE: &str = "package store\n\nfunc Open() int {\n\treturn 1\n}\n";
const GO_AUDIT: &str = "package audit\n\nfunc Record() {}\n";

#[test]
fn a_go_package_import_reaches_the_package_entity() {
    let files = [
        go("cmd/app/main.go", GO_MAIN),
        go("internal/store/store.go", GO_STORE),
        go("internal/audit/audit.go", GO_AUDIT),
    ];
    assert_has_module_surface(&files[0]);
    assert_eq!(module_names(&files[1]), vec!["store"]);

    let relations = assert_imports(&files, &[("main", "store"), ("main", "audit")]);
    assert_every_import_is_import_scoped(&relations);
}

#[test]
fn a_go_import_of_a_package_outside_the_repository_is_disclosed_not_dropped() {
    let files = [
        go("cmd/app/main.go", GO_MAIN),
        go("internal/store/store.go", GO_STORE),
        go("internal/audit/audit.go", GO_AUDIT),
    ];
    // Three import statements, two of which this repository answers. `fmt` is
    // the standard library and has no in-repo destination, so it mints no edge;
    // the certificate is where a reader learns that rather than reading two
    // edges and assuming the file imported twice.
    assert_eq!(import_disclosure(&files, "cmd/app/main.go"), (3, 2));
}

// ---------------------------------------------------------------------------
// Java
// ---------------------------------------------------------------------------

const JAVA_APP: &str = r#"package com.example.app;

import com.example.store.Store;
import com.example.audit.*;
import java.util.List;

public class App {
    public void run() {
        Store.open();
    }
}
"#;

const JAVA_STORE: &str = r#"package com.example.store;

public class Store {
    public static int open() { return 1; }
}
"#;

const JAVA_AUDIT: &str = r#"package com.example.audit;

public class Audit {
    public void record() {}
}
"#;

#[test]
fn a_java_selective_import_reaches_the_type_and_a_wildcard_reaches_the_package() {
    let files = [
        java("src/main/java/com/example/app/App.java", JAVA_APP),
        java("src/main/java/com/example/store/Store.java", JAVA_STORE),
        java("src/main/java/com/example/audit/Audit.java", JAVA_AUDIT),
    ];
    assert_has_module_surface(&files[0]);
    assert_eq!(module_names(&files[0]), vec!["app"]);

    let relations = assert_imports(
        &files,
        &[
            // The selective import names the type, so the edge lands on the
            // type and not on the package that holds it.
            ("app", "Store"),
            // The wildcard names no type at all, so the edge lands on the
            // package's own module surface.
            ("app", "audit"),
        ],
    );
    assert_every_import_is_import_scoped(&relations);
}

#[test]
fn a_java_import_of_a_type_outside_the_repository_is_disclosed_not_dropped() {
    let files = [
        java("src/main/java/com/example/app/App.java", JAVA_APP),
        java("src/main/java/com/example/store/Store.java", JAVA_STORE),
        java("src/main/java/com/example/audit/Audit.java", JAVA_AUDIT),
    ];
    // `java.util.List` is the JDK. Three statements, two answered.
    assert_eq!(
        import_disclosure(&files, "src/main/java/com/example/app/App.java"),
        (3, 2)
    );
}

// ---------------------------------------------------------------------------
// Kotlin
// ---------------------------------------------------------------------------

const KOTLIN_APP: &str = r#"package com.example.app

import com.example.store.Store
import com.example.audit.Audit as Trail
import kotlin.collections.List

class App {
    fun run(): Int {
        return Store.open()
    }
}
"#;

const KOTLIN_STORE: &str = r#"package com.example.store

class Store {
    fun open(): Int = 1
}
"#;

const KOTLIN_AUDIT: &str = r#"package com.example.audit

class Audit {
    fun record() {}
}
"#;

#[test]
fn a_kotlin_import_reaches_the_type_it_names_and_an_alias_binds_the_original() {
    let files = [
        kotlin("src/main/kotlin/com/example/app/App.kt", KOTLIN_APP),
        kotlin("src/main/kotlin/com/example/store/Store.kt", KOTLIN_STORE),
        kotlin("src/main/kotlin/com/example/audit/Audit.kt", KOTLIN_AUDIT),
    ];
    assert_has_module_surface(&files[0]);

    let relations = assert_imports(
        &files,
        &[
            ("app", "Store"),
            // Bound by the name the TARGET declares, not by the local alias.
            // An edge to `Trail` would point at a name no file writes.
            ("app", "Audit"),
        ],
    );
    assert_every_import_is_import_scoped(&relations);
}

#[test]
fn a_kotlin_import_of_a_type_outside_the_repository_is_disclosed_not_dropped() {
    let files = [
        kotlin("src/main/kotlin/com/example/app/App.kt", KOTLIN_APP),
        kotlin("src/main/kotlin/com/example/store/Store.kt", KOTLIN_STORE),
        kotlin("src/main/kotlin/com/example/audit/Audit.kt", KOTLIN_AUDIT),
    ];
    assert_eq!(
        import_disclosure(&files, "src/main/kotlin/com/example/app/App.kt"),
        (3, 2)
    );
}

// ---------------------------------------------------------------------------
// PHP
// ---------------------------------------------------------------------------

const PHP_APP: &str = r#"<?php
namespace App;

use App\Models\User;
use App\Models\Record as Row;
use Vendor\Http\Client;

class App {
    public function run() {
        return new User();
    }
}
"#;

const PHP_USER: &str =
    "<?php\nnamespace App\\Models;\n\nclass User {\n    public function name() {}\n}\n";
const PHP_RECORD: &str =
    "<?php\nnamespace App\\Models;\n\nclass Record {\n    public function id() {}\n}\n";

#[test]
fn a_php_use_reaches_the_class_it_names_and_an_alias_binds_the_original() {
    let files = [
        php("src/App.php", PHP_APP),
        php("src/Models/User.php", PHP_USER),
        php("src/Models/Record.php", PHP_RECORD),
    ];
    assert_has_module_surface(&files[0]);

    let relations = assert_imports(&files, &[("App", "User"), ("App", "Record")]);
    assert_every_import_is_import_scoped(&relations);
}

#[test]
fn a_php_use_of_a_class_outside_the_repository_is_disclosed_not_dropped() {
    let files = [
        php("src/App.php", PHP_APP),
        php("src/Models/User.php", PHP_USER),
        php("src/Models/Record.php", PHP_RECORD),
    ];
    assert_eq!(import_disclosure(&files, "src/App.php"), (3, 2));
}

// ---------------------------------------------------------------------------
// Rust
// ---------------------------------------------------------------------------

const RUST_APP: &str = r#"use crate::store;
use crate::store::Store;
use crate::audit::Audit as Trail;
use serde::Deserialize;

pub fn run() -> usize {
    store::open()
}
"#;

const RUST_STORE: &str = r#"pub struct Store;

pub fn open() -> usize {
    1
}
"#;

const RUST_AUDIT: &str = "pub struct Audit;\n";

#[test]
fn a_rust_use_reaches_a_module_and_a_member_and_binds_an_alias_to_its_original() {
    let files = [
        rust("src/app.rs", RUST_APP),
        rust("src/store.rs", RUST_STORE),
        rust("src/audit.rs", RUST_AUDIT),
    ];
    assert_has_module_surface(&files[0]);
    assert_eq!(module_names(&files[0]), vec!["app"]);

    let relations = assert_imports(
        &files,
        &[
            // `use crate::store;` names the module itself.
            ("app", "store"),
            // `use crate::store::Store;` names a declaration inside it.
            ("app", "Store"),
            // The alias binds the name the target declares.
            ("app", "Audit"),
        ],
    );
    assert_every_import_is_import_scoped(&relations);
}

#[test]
fn a_rust_use_of_a_crate_outside_the_repository_is_disclosed_not_dropped() {
    let files = [
        rust("src/app.rs", RUST_APP),
        rust("src/store.rs", RUST_STORE),
        rust("src/audit.rs", RUST_AUDIT),
    ];
    // Four `use` statements; `serde::Deserialize` is a dependency this
    // repository does not hold and reaches no file here.
    assert_eq!(import_disclosure(&files, "src/app.rs"), (4, 3));
}

// ---------------------------------------------------------------------------
// Swift
// ---------------------------------------------------------------------------

const SWIFT_APP: &str = r#"import Store
import struct Audit.Record
import Foundation

class App {
    func run() {}
}
"#;

const SWIFT_STORE: &str = "class Store {\n    func open() {}\n}\n";
const SWIFT_RECORD: &str = "struct Record {\n    var id: Int\n}\n";

#[test]
fn a_swift_module_import_reaches_the_module_and_a_kinded_import_reaches_the_member() {
    let files = [
        swift("Sources/App/App.swift", SWIFT_APP),
        swift("Sources/Store/Store.swift", SWIFT_STORE),
        swift("Sources/Audit/Record.swift", SWIFT_RECORD),
    ];
    assert_has_module_surface(&files[0]);

    let relations = assert_imports(
        &files,
        &[
            // The module import lands on the representative file's own surface.
            ("App", "Store"),
            // `import struct Audit.Record` names the member.
            ("App", "Record"),
        ],
    );
    assert_every_import_is_import_scoped(&relations);
}

#[test]
fn a_swift_import_of_a_module_outside_the_repository_is_disclosed_not_dropped() {
    let files = [
        swift("Sources/App/App.swift", SWIFT_APP),
        swift("Sources/Store/Store.swift", SWIFT_STORE),
        swift("Sources/Audit/Record.swift", SWIFT_RECORD),
    ];
    assert_eq!(import_disclosure(&files, "Sources/App/App.swift"), (3, 2));
}

// ---------------------------------------------------------------------------
// The claims that hold across every language here
// ---------------------------------------------------------------------------

/// An import that binds nothing mints nothing, in every one of these languages.
///
/// The control for every case above. Without it a fixture could pass by minting
/// an edge for every import statement against whatever file sorted first, and
/// every positive assertion would still be green.
#[test]
fn an_import_naming_a_module_this_repository_does_not_hold_mints_no_edge() {
    let cases: Vec<(&str, Vec<FileParseData>, &str)> = vec![
        (
            "go",
            vec![go(
                "cmd/app/main.go",
                "package main\n\nimport \"golang.org/x/sync/errgroup\"\n\nfunc Run() {}\n",
            )],
            "errgroup",
        ),
        (
            "java",
            vec![java(
                "src/main/java/com/example/app/App.java",
                "package com.example.app;\n\nimport java.util.List;\n\npublic class App {}\n",
            )],
            "List",
        ),
        (
            "kotlin",
            vec![kotlin(
                "src/main/kotlin/com/example/app/App.kt",
                "package com.example.app\n\nimport kotlin.collections.List\n\nclass App\n",
            )],
            "List",
        ),
        (
            "php",
            vec![php(
                "src/App.php",
                "<?php\nnamespace App;\n\nuse Vendor\\Http\\Client;\n\nclass App {}\n",
            )],
            "Client",
        ),
        (
            "rust",
            vec![rust(
                "src/app.rs",
                "use serde::Deserialize;\n\npub fn run() {}\n",
            )],
            "Deserialize",
        ),
        (
            "swift",
            vec![swift(
                "Sources/App/App.swift",
                "import Foundation\n\nclass App {}\n",
            )],
            "Foundation",
        ),
    ];

    for (language, files, absent) in cases {
        let relations = link_both(&files);
        let pairs = import_pairs(&files, &relations);
        assert!(
            pairs.is_empty(),
            "{language}: an import of `{absent}`, which this repository does not hold, minted \
             {pairs:?}"
        );
        // And the file still reports that it HAS an import statement, so the
        // absence above is a disclosed gap and not an empty import list.
        assert!(
            !files[0].imports.is_empty(),
            "{language}: the adapter recorded no import at all, so this case grades nothing"
        );
    }
}

/// Every entity-level import edge names a destination the fixture really holds.
///
/// A dangling endpoint is worse than a missing edge: admission fails closed on
/// a relation naming an entity the tree does not define, so an edge minted
/// against an invented destination takes the whole import down with it.
#[test]
fn every_minted_import_edge_names_an_entity_the_fixture_declares() {
    let files = [
        go("cmd/app/main.go", GO_MAIN),
        go("internal/store/store.go", GO_STORE),
        go("internal/audit/audit.go", GO_AUDIT),
        java("src/main/java/com/example/app/App.java", JAVA_APP),
        java("src/main/java/com/example/store/Store.java", JAVA_STORE),
        java("src/main/java/com/example/audit/Audit.java", JAVA_AUDIT),
        php("src/App.php", PHP_APP),
        php("src/Models/User.php", PHP_USER),
        php("src/Models/Record.php", PHP_RECORD),
        rust("src/app.rs", RUST_APP),
        rust("src/store.rs", RUST_STORE),
        rust("src/audit.rs", RUST_AUDIT),
    ];
    let known: HashSet<_> = files
        .iter()
        .flat_map(|file| file.entities.iter())
        .map(|entity| entity.id)
        .collect();

    let relations = link_both(&files);
    for relation in relations
        .iter()
        .filter(|relation| relation.kind == RelationKind::Imports)
    {
        if let GraphNodeId::Entity(src) = relation.src {
            assert!(
                known.contains(&src),
                "import edge sourced at an unknown entity"
            );
        }
        if let GraphNodeId::Entity(dst) = relation.dst {
            assert!(
                known.contains(&dst),
                "import edge naming a destination this fixture does not declare: {:?}",
                relation.evidence
            );
        }
    }
}

/// The importing file's own module surface is the edge's source, and never some
/// declaration that happens to sit first in the file.
///
/// Anchoring to "the first entity in the file" would claim one particular
/// symbol owns a file-level dependency. The Rust fixture is the one that can
/// catch it, because a Rust file carries module entities of its own for every
/// `mod` it declares and those are NOT the file's surface.
#[test]
fn an_import_edge_is_sourced_at_the_file_surface_and_not_at_a_declared_module() {
    let files = [
        rust(
            "src/lib.rs",
            "mod audit;\nmod store;\n\nuse crate::store::Store;\n\npub fn run(_: Store) {}\n",
        ),
        rust("src/store.rs", RUST_STORE),
        rust("src/audit.rs", RUST_AUDIT),
    ];
    // `src/lib.rs` declares `audit` and `store` as modules, and carries its own
    // surface named `crate`. All three are `Module` entities in one file.
    let names = module_names(&files[0]);
    assert_eq!(
        names.first(),
        Some(&"crate"),
        "the surface leads: {names:?}"
    );

    let relations = link_both(&files);
    let pairs = import_pairs(&files, &relations);
    assert!(
        pairs.contains(&("crate".to_string(), "Store".to_string())),
        "the crate root's own surface owns its import; got {pairs:?}"
    );
    assert!(
        !pairs
            .iter()
            .any(|(src, _)| src == "audit" || src == "store"),
        "a declared module must not be made to own the file's imports; got {pairs:?}"
    );
}

/// A reopened graph lists entities by identity, not parser insertion order.
/// Both possible identity orders must still source a file's import at its own
/// module, even when a declared child module sorts before it.
fn permuted_rust_import_fixture(surface_first: bool) -> Vec<FileParseData> {
    let mut files = vec![
        rust("src/lib.rs", "mod util;\npub use util::helper;\n"),
        rust("src/util.rs", "pub fn helper() {}\n"),
    ];
    for (file_index, file) in files.iter_mut().enumerate() {
        for (index, entity) in file.entities.iter_mut().enumerate() {
            let ordinal = if file_index == 0 && entity.kind == EntityKind::Module {
                if (entity.name == "crate") == surface_first {
                    1
                } else {
                    2
                }
            } else {
                10 + file_index * 10 + index
            };
            entity.id = kin_model::EntityId(uuid::Uuid::from_u128(ordinal as u128));
        }
        file.entities.sort_by_key(|entity| entity.id);
    }
    files
}

fn assert_rust_file_owns_import(files: &[FileParseData], relations: &[Relation]) {
    assert_eq!(
        import_pairs(files, relations),
        vec![("crate".to_string(), "helper".to_string())],
        "the Rust file surface owns pub use regardless of stored entity order"
    );
}

#[test]
fn rust_import_owner_batch_ignores_entity_identity_order() {
    for surface_first in [false, true] {
        let files = permuted_rust_import_fixture(surface_first);
        let relations = link_cross_file(&files, &artifact_ids(&files)).unwrap();
        assert_rust_file_owns_import(&files, &relations);
    }
}

#[test]
fn rust_import_owner_incremental_and_checkpoint_ignore_entity_identity_order() {
    for surface_first in [false, true] {
        let files = permuted_rust_import_fixture(surface_first);
        let ids = artifact_ids(&files);
        let mut linker = IncrementalLinker::new();
        for file in &files {
            linker.add_file(&file.file_path, ids[&file.file_path], &file.entities);
        }
        // Only the importer is relinked; the target's identity is read from
        // the persisted repository index, not the changed-file slice.
        let changed = &files[..1];
        let relations = link_cross_file_incremental(changed, &linker).unwrap();
        assert_rust_file_owns_import(&files, &relations);
        let restored = IncrementalLinker::from_checkpoint_v1(linker.to_checkpoint_v1()).unwrap();
        let relations = link_cross_file_incremental(changed, &restored).unwrap();
        assert_rust_file_owns_import(&files, &relations);
    }
}

#[test]
fn rust_import_owner_missing_surface_never_uses_a_child_module() {
    let mut files = permuted_rust_import_fixture(false);
    files[0].entities.retain(|entity| entity.name != "crate");
    let ids = artifact_ids(&files);
    let batch = link_cross_file(&files, &ids).unwrap();
    assert!(import_pairs(&files, &batch).is_empty());
    let mut linker = IncrementalLinker::new();
    for file in &files {
        linker.add_file(&file.file_path, ids[&file.file_path], &file.entities);
    }
    let restored = IncrementalLinker::from_checkpoint_v1(linker.to_checkpoint_v1()).unwrap();
    let incremental = link_cross_file_incremental(&files[..1], &restored).unwrap();
    assert!(import_pairs(&files, &incremental).is_empty());
    // A missing entity surface does not erase the independently admitted
    // file dependency. Its artifact edge remains available in both paths.
    for relations in [&batch, &incremental] {
        assert!(relations
            .iter()
            .any(|relation| relation.kind == RelationKind::Imports
                && relation.src == GraphNodeId::Artifact(ids["src/lib.rs"])
                && relation.dst == GraphNodeId::Artifact(ids["src/util.rs"])));
    }
}

#[test]
fn rust_import_owner_same_named_function_cannot_hide_the_file_module() {
    for reverse in [false, true] {
        let mut files = vec![
            rust("src/app.rs", "use crate::util::helper;\npub fn app() {}\n"),
            rust("src/util.rs", "pub fn helper() {}\n"),
        ];
        if reverse {
            files[0].entities.reverse();
        }
        let module = files[0]
            .entities
            .iter()
            .find(|entity| entity.kind == EntityKind::Module && entity.name == "app")
            .unwrap()
            .id;
        assert!(files[0]
            .entities
            .iter()
            .any(|entity| { entity.kind == EntityKind::Function && entity.name == "app" }));
        let helper = files[1]
            .entities
            .iter()
            .find(|entity| entity.name == "helper")
            .unwrap()
            .id;
        let ids = artifact_ids(&files);
        let mut linker = IncrementalLinker::new();
        for file in &files {
            linker.add_file(&file.file_path, ids[&file.file_path], &file.entities);
        }
        let restored = IncrementalLinker::from_checkpoint_v1(linker.to_checkpoint_v1()).unwrap();
        for relations in [
            link_cross_file(&files, &ids).unwrap(),
            link_cross_file_incremental(&files[..1], &linker).unwrap(),
            link_cross_file_incremental(&files[..1], &restored).unwrap(),
        ] {
            let imports: Vec<_> = relations
                .iter()
                .filter(|relation| {
                    relation.kind == RelationKind::Imports && relation.src.as_entity().is_some()
                })
                .map(|relation| (relation.src, relation.dst))
                .collect();
            assert_eq!(
                imports,
                vec![(GraphNodeId::Entity(module), GraphNodeId::Entity(helper))]
            );
        }
    }
}
