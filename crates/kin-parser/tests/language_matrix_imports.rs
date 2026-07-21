// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Per-language import/module-edge matrix.
//!
//! Every language with a full adapter must turn an import/use/require/include
//! statement into a `FileImport` the cross-file linker can key on. All 13
//! adapters do (GREEN). The `#[ignore]`d cells pin two YELLOW warts: PHP
//! `require`/`include` (as opposed to `use`) produces no FileImport, and a C#
//! `using Alias = Ns.Target;` records the alias as the module path and loses the
//! target namespace.

use kin_model::FilePathId;
use kin_parser::{
    CAdapter, CSharpAdapter, CppAdapter, GoAdapter, JavaAdapter, JavaScriptAdapter, KotlinAdapter,
    LanguageAdapter, ParseOutput, PhpAdapter, PythonAdapter, RubyAdapter, RustAdapter,
    SwiftAdapter, TypeScriptAdapter,
};

fn extract(adapter: &dyn LanguageAdapter, path: &str, src: &str) -> ParseOutput {
    let bytes = src.as_bytes();
    let tree = adapter.parse(bytes).expect("parse should succeed");
    adapter
        .extract(&tree, bytes, &FilePathId::new(path))
        .expect("extract should succeed")
}

fn has_import(out: &ParseOutput, module_path: &str) -> bool {
    out.imports.iter().any(|i| i.module_path == module_path)
}

fn has_specifier(out: &ParseOutput, module_path: &str, local_name: &str) -> bool {
    out.imports.iter().any(|i| {
        i.module_path == module_path && i.specifiers.iter().any(|s| s.local_name == local_name)
    })
}

#[test]
fn typescript_named_and_aliased_imports() {
    let out = extract(
        &TypeScriptAdapter,
        "s.ts",
        "import { helper, other as aliased } from \"./util\";\n",
    );
    assert!(has_specifier(&out, "./util", "helper"));
    let aliased = out
        .imports
        .iter()
        .flat_map(|i| &i.specifiers)
        .find(|s| s.local_name == "aliased")
        .expect("aliased specifier");
    assert_eq!(aliased.original_name.as_deref(), Some("other"));
}

#[test]
fn javascript_import_and_require() {
    let out = extract(
        &JavaScriptAdapter,
        "s.js",
        "import { helper } from \"./util\";\nconst mod = require(\"./mod\");\n",
    );
    assert!(has_specifier(&out, "./util", "helper"));
    assert!(
        has_import(&out, "./mod"),
        "require() should yield a FileImport"
    );
}

#[test]
fn python_import_and_from_import() {
    let out = extract(
        &PythonAdapter,
        "s.py",
        "import os\nfrom helpers import compute\n",
    );
    assert!(has_specifier(&out, "os", "os"));
    assert!(has_specifier(&out, "helpers", "compute"));
}

#[test]
fn go_import() {
    let out = extract(&GoAdapter, "s.go", "package main\nimport \"fmt\"\n");
    assert!(has_import(&out, "fmt"));
}

#[test]
fn java_import_and_static_import() {
    let out = extract(
        &JavaAdapter,
        "S.java",
        "import java.util.List;\nimport static java.lang.Math.max;\nclass C {}\n",
    );
    assert!(has_specifier(&out, "java.util", "List"));
    assert!(has_specifier(&out, "java.lang.Math", "max"));
}

#[test]
fn rust_use() {
    let out = extract(
        &RustAdapter,
        "s.rs",
        "use std::collections::HashMap;\nfn f() {}\n",
    );
    assert!(has_specifier(&out, "std::collections", "HashMap"));
}

#[test]
fn c_include() {
    let out = extract(
        &CAdapter,
        "s.c",
        "#include <stdio.h>\n#include \"local.h\"\n",
    );
    assert!(has_import(&out, "stdio.h"));
    assert!(has_import(&out, "local.h"));
}

#[test]
fn cpp_include() {
    let out = extract(
        &CppAdapter,
        "s.cpp",
        "#include <string>\n#include \"local.h\"\n",
    );
    assert!(has_import(&out, "string"));
    assert!(has_import(&out, "local.h"));
}

#[test]
fn csharp_using() {
    let out = extract(&CSharpAdapter, "S.cs", "using System;\nclass C {}\n");
    assert!(has_import(&out, "System"));
}

#[test]
fn ruby_require_and_require_relative() {
    let out = extract(
        &RubyAdapter,
        "s.rb",
        "require 'json'\nrequire_relative 'helper'\n",
    );
    assert!(has_import(&out, "json"));
    assert!(has_import(&out, "helper"));
}

#[test]
fn php_use() {
    let out = extract(&PhpAdapter, "s.php", "<?php\nuse App\\Helper;\n");
    assert!(has_specifier(&out, "App\\Helper", "Helper"));
}

#[test]
fn kotlin_import() {
    let out = extract(
        &KotlinAdapter,
        "s.kt",
        "import kotlin.collections.List\nfun f() {}\n",
    );
    assert!(has_specifier(&out, "kotlin.collections", "List"));
}

#[test]
fn swift_import() {
    let out = extract(&SwiftAdapter, "s.swift", "import Foundation\n");
    assert!(has_import(&out, "Foundation"));
}

// ---------------------------------------------------------------------------
// Pinned gaps (YELLOW) — executable, #[ignore]d with observed behavior.
// ---------------------------------------------------------------------------

#[test]
#[ignore = "YELLOW: PHP `require`/`include` produces no FileImport — only `use` statements are captured, so file-inclusion dependencies are invisible to the linker"]
fn php_require_should_produce_import() {
    let out = extract(&PhpAdapter, "s.php", "<?php\nrequire 'bootstrap.php';\n");
    assert!(has_import(&out, "bootstrap.php"));
}

#[test]
#[ignore = "YELLOW: a C# `using Alias = Ns.Target;` records the alias (`Data`) as the module path and drops the target namespace `System.Collections.Generic`"]
fn csharp_using_alias_should_record_target_namespace() {
    let out = extract(
        &CSharpAdapter,
        "S.cs",
        "using Data = System.Collections.Generic;\nclass C {}\n",
    );
    assert!(
        has_import(&out, "System.Collections.Generic"),
        "alias import should record the target namespace, got {:?}",
        out.imports
            .iter()
            .map(|i| &i.module_path)
            .collect::<Vec<_>>()
    );
}
