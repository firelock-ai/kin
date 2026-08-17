// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Declared entry points, read from the package manifests the graph tracks.
//!
//! An entry point is referenced from outside the graph by construction: a
//! console script is invoked by the launcher the manifest declares, a `main` is
//! invoked by the runtime. Neither produces an edge for the graph to hold, so a
//! reachability scan that keys on inbound edges alone reports the program's own
//! entry as deletable. `kin dead-code` did exactly that on a fresh install: it
//! listed `main`, the console script declared in `pyproject.toml`.
//!
//! Parsing only lives here. The bytes are supplied by the caller from
//! graph-owned blob storage, never from a working-tree read.

use kin_model::Entity;
use serde::{Deserialize, Serialize};

/// One entry point a manifest declares.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeclaredEntryPoint {
    /// Path of the manifest that declares it, as the graph tracks it.
    pub manifest: String,
    /// The declaration as written, for the output to quote.
    pub declaration: String,
    /// Dotted module path (`nk.cli`), when the declaration names one.
    pub module: Option<String>,
    /// File path as written (`./bin/cli.js`), when the declaration names one.
    pub file: Option<String>,
    /// Symbol the launcher calls (`main`), when the declaration names one.
    pub symbol: Option<String>,
}

/// Every entry point declared by the manifests that could be read, plus the
/// manifests that could NOT be, because an unread manifest is a hole in this
/// evidence and a caller must be able to say so rather than assume none.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeclaredEntryPoints {
    pub entries: Vec<DeclaredEntryPoint>,
    pub manifests_read: Vec<String>,
    pub manifests_unreadable: Vec<String>,
}

impl DeclaredEntryPoints {
    /// The declaration this entity satisfies, if any.
    pub fn declaration_for(&self, entity: &Entity) -> Option<&DeclaredEntryPoint> {
        let file = entity.file_origin.as_ref().map(|file| file.0.as_str());
        self.entries
            .iter()
            .find(|entry| entry_matches(entry, &entity.name, file))
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

fn entry_matches(entry: &DeclaredEntryPoint, name: &str, file: Option<&str>) -> bool {
    let symbol_matches = match entry.symbol.as_deref() {
        Some(symbol) => symbol_names_entity(symbol, name),
        // A declaration that names only a file (a `bin` script, a Cargo binary)
        // says the file is launched, not which symbol runs. Only the runtime
        // entry inside it is claimed; claiming every declaration in the file
        // would hide real dead code behind one manifest line.
        None => is_conventional_entry_point_name(name),
    };
    if !symbol_matches {
        return false;
    }
    match (entry.module.as_deref(), entry.file.as_deref(), file) {
        (Some(module), _, Some(file)) => module_names_file(module, file),
        (None, Some(declared), Some(file)) => file_names_file(declared, file),
        // A declaration with neither module nor file is not enough to bind, and
        // an entity with no file cannot be bound to one.
        _ => false,
    }
}

/// Whether a declared symbol names this entity.
///
/// Handles the qualified forms manifests use: `main`, `Cls.method`, and an
/// entity whose graph name carries its owner (`Database.ingest_note`).
fn symbol_names_entity(symbol: &str, name: &str) -> bool {
    if symbol == name {
        return true;
    }
    let symbol_leaf = bare_name(symbol);
    let name_leaf = bare_name(name);
    symbol_leaf == name_leaf && (symbol.contains('.') || name.contains('.') || name.contains("::"))
}

/// Whether a dotted module path names this file.
///
/// `nk.cli` names `nk/cli.py`, `src/nk/cli.py`, and `nk/cli/__init__.py`. The
/// comparison is on the file's own dotted form so a package prefix the manifest
/// omits (`src/`) does not break the match.
fn module_names_file(module: &str, file: &str) -> bool {
    let module = module.trim().trim_matches('.');
    if module.is_empty() {
        return false;
    }
    let dotted = dotted_form(file);
    dotted == module || dotted.ends_with(&format!(".{module}"))
}

fn file_names_file(declared: &str, file: &str) -> bool {
    let declared = declared.trim().trim_start_matches("./").replace('\\', "/");
    if declared.is_empty() {
        return false;
    }
    let file = file.replace('\\', "/");
    file == declared || file.ends_with(&format!("/{declared}"))
}

/// A file path as a dotted module path: extension dropped, separators to dots,
/// a package `__init__` collapsed onto its package.
fn dotted_form(file: &str) -> String {
    let normalized = file.replace('\\', "/");
    let without_extension = match normalized.rsplit_once('.') {
        Some((stem, extension)) if !extension.contains('/') => stem,
        _ => normalized.as_str(),
    };
    let trimmed = without_extension
        .trim_end_matches("/__init__")
        .trim_end_matches("/index")
        .trim_end_matches("/mod");
    trimmed.trim_matches('/').replace('/', ".")
}

fn bare_name(name: &str) -> &str {
    match name.rfind("::") {
        Some(index) => &name[index + 2..],
        None => match name.rfind('.') {
            Some(index) => &name[index + 1..],
            None => name,
        },
    }
}

/// Whether the entity is the runtime's own entry point by naming convention.
///
/// `main` is called by the runtime or by a `__main__` guard in every language
/// Kin extracts, and neither leaves an edge. Language-independent on purpose: a
/// `main` reported as deletable is wrong in Rust, Go, C, Java and Python alike,
/// and the cost of the rule is only that a genuinely unused helper named `main`
/// goes unreported.
pub fn is_conventional_entry_point(entity: &Entity) -> bool {
    is_conventional_entry_point_name(&entity.name)
}

fn is_conventional_entry_point_name(name: &str) -> bool {
    matches!(bare_name(name.trim()), "main" | "__main__")
}

/// Manifest kinds this parser understands, for a caller that has to disclose
/// which surfaces it consulted.
pub const SUPPORTED_ENTRY_POINT_MANIFESTS: [&str; 4] = [
    "pyproject.toml",
    "package.json",
    "Cargo.toml",
    "composer.json",
];

/// Whether a manifest path is one this parser can read entry points from.
pub fn declares_entry_points(manifest_path: &str) -> bool {
    let name = manifest_path.rsplit('/').next().unwrap_or(manifest_path);
    SUPPORTED_ENTRY_POINT_MANIFESTS.contains(&name)
}

/// Parse the entry points a manifest declares.
///
/// Returns an empty list for a manifest kind this parser does not read or for
/// bytes it cannot parse; the caller records the manifest as unreadable so the
/// gap is disclosed rather than read as "no entry points declared".
pub fn parse_manifest_entry_points(manifest_path: &str, bytes: &[u8]) -> Vec<DeclaredEntryPoint> {
    let Ok(text) = std::str::from_utf8(bytes) else {
        return Vec::new();
    };
    let name = manifest_path.rsplit('/').next().unwrap_or(manifest_path);
    match name {
        "pyproject.toml" => parse_pyproject(manifest_path, text),
        "Cargo.toml" => parse_cargo(manifest_path, text),
        "package.json" | "composer.json" => parse_node_manifest(manifest_path, text),
        _ => Vec::new(),
    }
}

fn parse_pyproject(manifest_path: &str, text: &str) -> Vec<DeclaredEntryPoint> {
    let Ok(value) = toml::from_str::<toml::Value>(text) else {
        return Vec::new();
    };
    let mut entries = Vec::new();

    let mut script_tables: Vec<&toml::value::Table> = Vec::new();
    if let Some(project) = value.get("project").and_then(toml::Value::as_table) {
        for key in ["scripts", "gui-scripts"] {
            if let Some(table) = project.get(key).and_then(toml::Value::as_table) {
                script_tables.push(table);
            }
        }
        if let Some(groups) = project.get("entry-points").and_then(toml::Value::as_table) {
            for group in groups.values() {
                if let Some(table) = group.as_table() {
                    script_tables.push(table);
                }
            }
        }
    }
    if let Some(table) = value
        .get("tool")
        .and_then(|tool| tool.get("poetry"))
        .and_then(|poetry| poetry.get("scripts"))
        .and_then(toml::Value::as_table)
    {
        script_tables.push(table);
    }

    for table in script_tables {
        for (script, target) in table {
            let Some(target) = target.as_str() else {
                continue;
            };
            entries.push(python_entry(manifest_path, script, target));
        }
    }
    entries
}

fn python_entry(manifest_path: &str, script: &str, target: &str) -> DeclaredEntryPoint {
    let (module, symbol) = match target.split_once(':') {
        Some((module, symbol)) => (module.trim(), Some(symbol.trim().to_string())),
        None => (target.trim(), None),
    };
    DeclaredEntryPoint {
        manifest: manifest_path.to_string(),
        declaration: format!("{script} = \"{target}\""),
        module: (!module.is_empty()).then(|| module.to_string()),
        file: None,
        symbol,
    }
}

fn parse_cargo(manifest_path: &str, text: &str) -> Vec<DeclaredEntryPoint> {
    let Ok(value) = toml::from_str::<toml::Value>(text) else {
        return Vec::new();
    };
    let mut entries = Vec::new();
    let bins = value
        .get("bin")
        .and_then(toml::Value::as_array)
        .map(|bins| bins.as_slice())
        .unwrap_or_default();
    for bin in bins {
        let name = bin.get("name").and_then(toml::Value::as_str);
        let path = bin
            .get("path")
            .and_then(toml::Value::as_str)
            .map(|path| path.to_string())
            .or_else(|| name.map(|name| format!("src/bin/{name}.rs")));
        let Some(path) = path else {
            continue;
        };
        entries.push(DeclaredEntryPoint {
            manifest: manifest_path.to_string(),
            declaration: format!("[[bin]] {path}"),
            module: None,
            file: Some(path),
            symbol: None,
        });
    }
    if value.get("package").is_some() {
        entries.push(DeclaredEntryPoint {
            manifest: manifest_path.to_string(),
            declaration: "[package] default binary src/main.rs".to_string(),
            module: None,
            file: Some("src/main.rs".to_string()),
            symbol: None,
        });
    }
    entries
}

fn parse_node_manifest(manifest_path: &str, text: &str) -> Vec<DeclaredEntryPoint> {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(text) else {
        return Vec::new();
    };
    let mut entries = Vec::new();
    let mut push_file = |declaration: String, file: &str| {
        entries.push(DeclaredEntryPoint {
            manifest: manifest_path.to_string(),
            declaration,
            module: None,
            file: Some(file.to_string()),
            symbol: None,
        });
    };

    match value.get("bin") {
        Some(serde_json::Value::String(file)) => push_file(format!("bin = \"{file}\""), file),
        Some(serde_json::Value::Object(map)) => {
            for (name, target) in map {
                if let Some(file) = target.as_str() {
                    push_file(format!("bin.{name} = \"{file}\""), file);
                }
            }
        }
        Some(serde_json::Value::Array(items)) => {
            for target in items {
                if let Some(file) = target.as_str() {
                    push_file(format!("bin = \"{file}\""), file);
                }
            }
        }
        _ => {}
    }
    for key in ["main", "module"] {
        if let Some(file) = value.get(key).and_then(serde_json::Value::as_str) {
            push_file(format!("{key} = \"{file}\""), file);
        }
    }
    entries
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::entity::{
        EntityKind, EntityMetadata, EntityRole, FingerprintAlgorithm, SemanticFingerprint,
        Visibility,
    };
    use kin_model::ids::{FilePathId, Hash256};
    use kin_model::{EntityId, LanguageId};

    fn entity(name: &str, file: &str) -> Entity {
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Python,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0; 32]),
                signature_hash: Hash256::from_bytes([0; 32]),
                behavior_hash: Hash256::from_bytes([0; 32]),
                equivalence_hash: Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new(file)),
            span: None,
            signature: format!("def {name}()"),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    /// The exact declaration whose entity `kin dead-code` listed for deletion.
    #[test]
    fn a_pyproject_console_script_binds_to_its_function() {
        let manifest = r#"
[project]
name = "notekeeper"

[project.scripts]
nk = "nk.cli:main"
"#;
        let entries = parse_manifest_entry_points("pyproject.toml", manifest.as_bytes());
        assert_eq!(entries.len(), 1, "{entries:?}");
        let declared = DeclaredEntryPoints {
            entries,
            manifests_read: vec!["pyproject.toml".to_string()],
            manifests_unreadable: Vec::new(),
        };

        assert!(declared
            .declaration_for(&entity("main", "nk/cli.py"))
            .is_some());
        assert!(declared
            .declaration_for(&entity("main", "src/nk/cli.py"))
            .is_some());
        assert!(
            declared
                .declaration_for(&entity("build_parser", "nk/cli.py"))
                .is_none(),
            "the declaration names main, not every function in the file"
        );
        assert!(
            declared
                .declaration_for(&entity("main", "nk/other.py"))
                .is_none(),
            "the declaration names nk.cli, not every module"
        );
    }

    #[test]
    fn poetry_and_gui_scripts_are_read_too() {
        let manifest = r#"
[project]
gui-scripts = { nkw = "nk.gui:launch" }

[tool.poetry.scripts]
nkp = "nk.legacy:run"
"#;
        let entries = parse_manifest_entry_points("pyproject.toml", manifest.as_bytes());
        let declared = DeclaredEntryPoints {
            entries,
            manifests_read: vec!["pyproject.toml".to_string()],
            manifests_unreadable: Vec::new(),
        };
        assert!(declared
            .declaration_for(&entity("launch", "nk/gui.py"))
            .is_some());
        assert!(declared
            .declaration_for(&entity("run", "nk/legacy.py"))
            .is_some());
    }

    #[test]
    fn a_node_bin_declaration_claims_only_the_runtime_entry_in_its_file() {
        let manifest = r#"{ "bin": { "nk": "./bin/cli.js" }, "main": "index.js" }"#;
        let entries = parse_manifest_entry_points("package.json", manifest.as_bytes());
        let declared = DeclaredEntryPoints {
            entries,
            manifests_read: vec!["package.json".to_string()],
            manifests_unreadable: Vec::new(),
        };
        assert!(declared
            .declaration_for(&entity("main", "bin/cli.js"))
            .is_some());
        assert!(
            declared
                .declaration_for(&entity("helper", "bin/cli.js"))
                .is_none(),
            "a bin path names the file, so only its runtime entry is claimed"
        );
    }

    #[test]
    fn a_cargo_manifest_claims_its_binary_paths() {
        let manifest = r#"
[package]
name = "kin"

[[bin]]
name = "kin"
path = "src/cli.rs"
"#;
        let entries = parse_manifest_entry_points("Cargo.toml", manifest.as_bytes());
        let declared = DeclaredEntryPoints {
            entries,
            manifests_read: vec!["Cargo.toml".to_string()],
            manifests_unreadable: Vec::new(),
        };
        assert!(declared
            .declaration_for(&entity("main", "src/cli.rs"))
            .is_some());
        assert!(declared
            .declaration_for(&entity("main", "src/main.rs"))
            .is_some());
    }

    #[test]
    fn main_is_an_entry_point_by_convention_in_every_language() {
        assert!(is_conventional_entry_point(&entity("main", "nk/cli.py")));
        assert!(is_conventional_entry_point(&entity("__main__", "nk/x.py")));
        assert!(is_conventional_entry_point(&entity("App.main", "App.java")));
        assert!(!is_conventional_entry_point(&entity(
            "maintain",
            "nk/cli.py"
        )));
        assert!(!is_conventional_entry_point(&entity("domain", "nk/cli.py")));
    }

    #[test]
    fn an_unparseable_manifest_declares_nothing_and_says_nothing() {
        assert!(parse_manifest_entry_points("pyproject.toml", b"[project").is_empty());
        assert!(parse_manifest_entry_points("Gemfile", b"gem 'rails'").is_empty());
        assert!(!declares_entry_points("Gemfile"));
        assert!(declares_entry_points("packages/web/package.json"));
    }
}
