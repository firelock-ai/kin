// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Naming a declaration outside the repository as an external symbol.
//!
//! A definition answer that lands outside the repository proves the call names
//! something the repository does not own. To record it as a target, Kin names
//! it the way SCIP does: the package that holds the file, at the version the
//! server loaded, and the chain of declarations from the file down to the
//! answered one.
//!
//! Both halves come from what answered. The descriptor chain is the server's
//! own `textDocument/documentSymbol` answer about the target file, walked down
//! to the symbol whose name the definition landed on. The package is the root
//! that holds the file, read from its own manifest: `package.json` for npm,
//! a wheel's `.dist-info` for Python, `Cargo.toml` for a crate, the module
//! cache's `module@version` directory for Go. A standard library is named by
//! the version the server loaded: the TypeScript package whose lib files it
//! read, the Python version its stubs were evaluated for, the Rust sysroot's
//! rustc, the Go toolchain's `VERSION`.
//!
//! The target's location is used only to name it. It is never stored or
//! served, so no local path reaches the graph. When the package or the symbol
//! cannot be named, nothing is: the answer still proves the call leaves the
//! repository, and the site is recorded as outside rather than as a node Kin
//! made up.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use kin_model::{DescriptorSuffix, ExternalSymbol, ScipDescriptor, ScipPackage};
use serde_json::Value;
use tracing::debug;

use crate::adapters::Resolution;
use crate::call_sites::{LocationRange, OutsideLocation};
use crate::lifecycle::LspServer;
use crate::protocol;

/// How long one `documentSymbol` answer about a dependency file may take.
/// TypeScript's DOM declarations are large, and the answer is asked once per
/// server and kept.
const DOCUMENT_SYMBOL_BUDGET: std::time::Duration = std::time::Duration::from_secs(30);

/// The toolchain versions standard libraries are named by, from the
/// environment the server was started against.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StdlibVersions {
    /// The `major.minor` Python version pyright evaluates its stubs for.
    pub python: Option<String>,
    /// The rustc release whose sysroot rust-analyzer reads.
    pub rust: Option<String>,
    /// The Go toolchain release.
    pub go: Option<String>,
}

impl StdlibVersions {
    /// The versions a launch's environment names.
    pub fn from_resolution(resolution: Option<&Resolution>) -> Self {
        let mut versions = Self::default();
        let Some(toolchain) =
            resolution.and_then(|resolution| resolution.environment.toolchain.as_ref())
        else {
            return versions;
        };
        let numeric = release_version(&toolchain.version);
        match toolchain.name.as_str() {
            "python" => {
                versions.python =
                    numeric.map(|version| version.split('.').take(2).collect::<Vec<_>>().join("."))
            }
            "rust" => versions.rust = numeric,
            "go" => versions.go = numeric,
            _ => {}
        }
        versions
    }
}

/// `text` when it reads as a release version (`1.90.0`, `3.12`, `go1.23.4`
/// as `1.23.4`), and `None` for a channel name or `unknown`.
fn release_version(text: &str) -> Option<String> {
    let text = text.trim();
    let text = text.strip_prefix("go").unwrap_or(text);
    let version: String = text
        .chars()
        .take_while(|ch| ch.is_ascii_digit() || *ch == '.')
        .collect();
    let version = version.trim_end_matches('.').to_string();
    (version.contains('.') && version.starts_with(|ch: char| ch.is_ascii_digit()))
        .then_some(version)
}

/// One declaration a document's symbols name, with the chain that reaches it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct NamedSymbol {
    chain: Vec<ScipDescriptor>,
    selection: LocationRange,
}

/// Names outside declarations for one server, keeping what it learned about
/// each dependency file for the server's lifetime.
#[derive(Debug, Default)]
pub struct ExternalSymbolNamer {
    stdlib: StdlibVersions,
    /// A file's symbols, by URI. Empty when the server named none.
    documents: Mutex<HashMap<String, Arc<Vec<NamedSymbol>>>>,
    /// The package holding a file, and the file's own namespace descriptors,
    /// by path. `None` when no package could be named.
    packages: Mutex<HashMap<PathBuf, Option<(ScipPackage, Vec<ScipDescriptor>)>>>,
}

impl ExternalSymbolNamer {
    pub fn new(stdlib: StdlibVersions) -> Self {
        Self {
            stdlib,
            ..Self::default()
        }
    }

    /// Name every distinct location in `locations`. A location this namer
    /// cannot name is absent from the answer.
    pub async fn name_all(
        &self,
        server: &LspServer,
        locations: &[OutsideLocation],
    ) -> HashMap<OutsideLocation, ExternalSymbol> {
        let mut named = HashMap::new();
        for location in locations {
            if named.contains_key(location) {
                continue;
            }
            if let Some(symbol) = self.name(server, location).await {
                named.insert(location.clone(), symbol);
            }
        }
        named
    }

    /// Name the declaration at `location`, or `None` when its package or its
    /// symbol cannot be named.
    pub async fn name(
        &self,
        server: &LspServer,
        location: &OutsideLocation,
    ) -> Option<ExternalSymbol> {
        let path = protocol::uri_to_path(&location.uri)?;
        let (package, namespace) = self.package(&path)?;
        let symbols = self.symbols(server, &location.uri, &path).await;
        let chain = chain_at(&symbols, &location.range)?;
        let mut descriptors = namespace;
        descriptors.extend(chain);
        ExternalSymbol::new(package, descriptors).ok()
    }

    fn package(&self, path: &Path) -> Option<(ScipPackage, Vec<ScipDescriptor>)> {
        if let Ok(held) = self.packages.lock() {
            if let Some(known) = held.get(path) {
                return known.clone();
            }
        }
        let found = package_of(path, &self.stdlib);
        if let Ok(mut held) = self.packages.lock() {
            held.insert(path.to_path_buf(), found.clone());
        }
        found
    }

    async fn symbols(&self, server: &LspServer, uri: &str, path: &Path) -> Arc<Vec<NamedSymbol>> {
        if let Ok(held) = self.documents.lock() {
            if let Some(known) = held.get(uri) {
                return Arc::clone(known);
            }
        }
        let symbols = Arc::new(document_symbols(server, uri, path).await);
        if let Ok(mut held) = self.documents.lock() {
            held.insert(uri.to_string(), Arc::clone(&symbols));
        }
        symbols
    }
}

/// Ask the server for the symbols of a dependency file, opening it for the
/// question and closing it after. Any failure names nothing.
async fn document_symbols(server: &LspServer, uri: &str, path: &Path) -> Vec<NamedSymbol> {
    let Some(language) = document_language(path) else {
        return Vec::new();
    };
    // The file lies outside the repository, in an environment the server
    // already loaded; its text is read only so the server can answer about
    // it, and nothing of it is kept.
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let opened = server
        .client
        .notify(
            "textDocument/didOpen",
            serde_json::json!({
                "textDocument": {
                    "uri": uri,
                    "languageId": language.lsp_id(),
                    "version": 1,
                    "text": text,
                }
            }),
        )
        .await;
    if opened.is_err() {
        return Vec::new();
    }
    let answer = server
        .client
        .request_within(
            "textDocument/documentSymbol",
            serde_json::json!({ "textDocument": { "uri": uri } }),
            DOCUMENT_SYMBOL_BUDGET,
        )
        .await;
    let _ = server
        .client
        .notify(
            "textDocument/didClose",
            serde_json::json!({ "textDocument": { "uri": uri } }),
        )
        .await;
    match answer {
        Ok(value) => symbols_from_answer(&value, language),
        Err(error) => {
            debug!(%error, "a dependency file's symbols could not be read; its declarations stay unnamed");
            Vec::new()
        }
    }
}

/// The languages whose dependency files Kin can name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DocumentLanguage {
    TypeScript,
    JavaScript,
    Python,
    Rust,
    Go,
}

impl DocumentLanguage {
    fn lsp_id(self) -> &'static str {
        match self {
            Self::TypeScript => "typescript",
            Self::JavaScript => "javascript",
            Self::Python => "python",
            Self::Rust => "rust",
            Self::Go => "go",
        }
    }
}

fn document_language(path: &Path) -> Option<DocumentLanguage> {
    let extension = path.extension()?.to_str()?;
    Some(match extension {
        "ts" | "tsx" | "mts" | "cts" => DocumentLanguage::TypeScript,
        "js" | "jsx" | "mjs" | "cjs" => DocumentLanguage::JavaScript,
        "py" | "pyi" => DocumentLanguage::Python,
        "rs" => DocumentLanguage::Rust,
        "go" => DocumentLanguage::Go,
        _ => return None,
    })
}

/// Every declaration a `documentSymbol` answer names, with its chain.
///
/// Hierarchical `DocumentSymbol` answers give the chain directly. A flat
/// `SymbolInformation` answer gives each symbol's container by name, which is
/// kept as a one-step chain above it.
fn symbols_from_answer(value: &Value, language: DocumentLanguage) -> Vec<NamedSymbol> {
    let Some(items) = value.as_array() else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for item in items {
        if item.get("selectionRange").is_some() || item.get("children").is_some() {
            walk_document_symbol(item, &[], language, &mut out);
        } else if let Some(range) = item
            .get("location")
            .and_then(|location| location.get("range"))
            .and_then(range_of)
        {
            let Some(kind) = item.get("kind").and_then(Value::as_u64) else {
                continue;
            };
            let Some(name) = item.get("name").and_then(Value::as_str) else {
                continue;
            };
            let mut chain = Vec::new();
            if let Some(container) = item.get("containerName").and_then(Value::as_str) {
                if !container.is_empty() {
                    chain.extend(descriptors_for(container, 5, language));
                }
            }
            chain.extend(descriptors_for(name, kind, language));
            if !chain.is_empty() {
                out.push(NamedSymbol {
                    chain,
                    selection: range,
                });
            }
        }
    }
    out
}

fn walk_document_symbol(
    item: &Value,
    parents: &[ScipDescriptor],
    language: DocumentLanguage,
    out: &mut Vec<NamedSymbol>,
) {
    let (Some(name), Some(kind)) = (
        item.get("name").and_then(Value::as_str),
        item.get("kind").and_then(Value::as_u64),
    ) else {
        return;
    };
    let mut chain = parents.to_vec();
    chain.extend(descriptors_for(name, kind, language));
    if let Some(selection) = item.get("selectionRange").and_then(range_of) {
        if chain.len() > parents.len() {
            out.push(NamedSymbol {
                chain: chain.clone(),
                selection,
            });
        }
    }
    if let Some(children) = item.get("children").and_then(Value::as_array) {
        for child in children {
            walk_document_symbol(child, &chain, language, out);
        }
    }
}

fn range_of(value: &Value) -> Option<LocationRange> {
    let range: protocol::Range = serde_json::from_value(value.clone()).ok()?;
    Some(LocationRange::from(&range))
}

/// The descriptors one symbol adds to its parent's chain, from its name as the
/// server spelled it and its LSP `SymbolKind`.
fn descriptors_for(name: &str, kind: u64, language: DocumentLanguage) -> Vec<ScipDescriptor> {
    let name = name.trim();
    if name.is_empty() {
        return Vec::new();
    }
    match language {
        // rust-analyzer lists an `impl` block as a symbol of its own, named by
        // its header. Its members belong to the type it implements.
        DocumentLanguage::Rust if name.starts_with("impl") => rust_impl_self_type(name)
            .map(|self_type| vec![ScipDescriptor::type_(self_type)])
            .unwrap_or_default(),
        // gopls names a method `(*Buffer).Write` at the top level.
        DocumentLanguage::Go if name.starts_with('(') => {
            let Some((receiver, method)) = name.split_once(").") else {
                return vec![ScipDescriptor::new(name, suffix_for(kind))];
            };
            let receiver = receiver.trim_start_matches('(').trim_start_matches('*');
            vec![
                ScipDescriptor::type_(receiver),
                ScipDescriptor::method(method),
            ]
        }
        _ => {
            // A signature a server spells into the name (`map(callbackfn)`)
            // is not part of the name.
            let bare = name.split('(').next().unwrap_or(name).trim();
            if bare.is_empty() {
                return Vec::new();
            }
            vec![ScipDescriptor::new(bare, suffix_for(kind))]
        }
    }
}

/// SCIP's suffix for an LSP `SymbolKind`.
fn suffix_for(kind: u64) -> DescriptorSuffix {
    match kind {
        // Module, Namespace, Package.
        2..=4 => DescriptorSuffix::Namespace,
        // Class, Enum, Interface, Struct, and Object, which rust-analyzer
        // gives an `impl` block.
        5 | 10 | 11 | 19 | 23 => DescriptorSuffix::Type,
        // Method, Constructor, Function.
        6 | 9 | 12 => DescriptorSuffix::Method,
        26 => DescriptorSuffix::TypeParameter,
        _ => DescriptorSuffix::Term,
    }
}

/// The type an `impl` header implements: `Vec` for `impl<T, A> Vec<T, A>` and
/// for `impl<T> Clone for Vec<T>`.
fn rust_impl_self_type(header: &str) -> Option<String> {
    let rest = header.strip_prefix("impl")?;
    // Skip the impl's own generics, which may nest.
    let rest = rest.trim_start();
    let rest = if rest.starts_with('<') {
        let mut depth = 0usize;
        let mut end = None;
        for (index, ch) in rest.char_indices() {
            match ch {
                '<' => depth += 1,
                '>' => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        end = Some(index + 1);
                        break;
                    }
                }
                _ => {}
            }
        }
        &rest[end?..]
    } else {
        rest
    };
    let self_type = match rest.rsplit_once(" for ") {
        Some((_, self_type)) => self_type,
        None => rest,
    };
    let self_type = self_type
        .trim()
        .trim_start_matches('&')
        .trim_start_matches("mut ");
    let self_type = self_type.split('<').next()?.trim();
    let self_type = self_type.rsplit("::").next()?.trim();
    (!self_type.is_empty()
        && self_type
            .chars()
            .all(|ch| ch.is_alphanumeric() || ch == '_'))
    .then(|| self_type.to_string())
}

/// The chain of the innermost symbol whose name holds the start of `range`.
fn chain_at(symbols: &[NamedSymbol], range: &LocationRange) -> Option<Vec<ScipDescriptor>> {
    symbols
        .iter()
        .filter(|symbol| symbol.selection.holds_start_of(range))
        .max_by_key(|symbol| symbol.chain.len())
        .map(|symbol| symbol.chain.clone())
}

/// The package holding `path` and the namespace descriptors of the file
/// inside it.
fn package_of(path: &Path, stdlib: &StdlibVersions) -> Option<(ScipPackage, Vec<ScipDescriptor>)> {
    match document_language(path)? {
        DocumentLanguage::TypeScript | DocumentLanguage::JavaScript => npm_package_of(path),
        DocumentLanguage::Python => python_package_of(path, stdlib),
        DocumentLanguage::Rust => cargo_package_of(path, stdlib),
        DocumentLanguage::Go => go_package_of(path, stdlib),
    }
}

/// The components of `path` below `root`, joined by `/`.
fn relative(path: &Path, root: &Path) -> Option<String> {
    let rest = path.strip_prefix(root).ok()?;
    let parts: Vec<String> = rest
        .components()
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .collect();
    (!parts.is_empty()).then(|| parts.join("/"))
}

/// An npm package: the nearest `package.json` above the file that has a name
/// and a version. TypeScript's own lib files are named by the file alone
/// (`` `lib.es5.d.ts`/ ``); any other file by its path in the package.
fn npm_package_of(path: &Path) -> Option<(ScipPackage, Vec<ScipDescriptor>)> {
    for dir in path.ancestors().skip(1) {
        let manifest = dir.join("package.json");
        let Ok(text) = std::fs::read_to_string(&manifest) else {
            continue;
        };
        let Ok(value) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        let (Some(name), Some(version)) = (
            value.get("name").and_then(Value::as_str),
            value.get("version").and_then(Value::as_str),
        ) else {
            continue;
        };
        let package = ScipPackage::new("npm", name, version).ok()?;
        let inside = relative(path, dir)?;
        let file = if name == "typescript" {
            inside
                .strip_prefix("lib/")
                .filter(|lib| !lib.contains('/'))
                .unwrap_or(&inside)
                .to_string()
        } else {
            inside
        };
        return Some((package, vec![ScipDescriptor::namespace(file)]));
    }
    None
}

/// A Python module's dotted name from its path below a root: `os/path.pyi`
/// is `os.path` and `json/__init__.pyi` is `json`.
fn python_module(inside: &str) -> Option<String> {
    let stem = inside
        .strip_suffix(".pyi")
        .or_else(|| inside.strip_suffix(".py"))?;
    let mut parts: Vec<&str> = stem.split('/').collect();
    if parts.last() == Some(&"__init__") {
        parts.pop();
    }
    (!parts.is_empty() && parts.iter().all(|part| !part.is_empty())).then(|| parts.join("."))
}

/// A Python package: typeshed's standard library stubs, a stub distribution
/// typeshed bundles, or an installed distribution in `site-packages`.
fn python_package_of(
    path: &Path,
    stdlib: &StdlibVersions,
) -> Option<(ScipPackage, Vec<ScipDescriptor>)> {
    let components: Vec<String> = path
        .components()
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .collect();
    if let Some(at) = components
        .iter()
        .position(|component| component == "typeshed-fallback")
    {
        let kind = components.get(at + 1)?;
        if kind == "stdlib" {
            let module = python_module(&components[at + 2..].join("/"))?;
            let version = stdlib.python.clone()?;
            let package = ScipPackage::new("python", "python-stdlib", version).ok()?;
            return Some((package, vec![ScipDescriptor::namespace(module)]));
        }
        if kind == "stubs" {
            let distribution = components.get(at + 2)?;
            let root: PathBuf = components[..at + 3].iter().collect();
            let metadata = std::fs::read_to_string(root.join("METADATA.toml")).ok()?;
            let version = metadata
                .parse::<toml::Table>()
                .ok()?
                .get("version")?
                .as_str()?
                .to_string();
            let module = python_module(&components[at + 3..].join("/"))?;
            let package = ScipPackage::new("python", distribution.as_str(), version).ok()?;
            return Some((package, vec![ScipDescriptor::namespace(module)]));
        }
        return None;
    }
    if let Some(at) = components
        .iter()
        .rposition(|component| component == "site-packages")
    {
        let site: PathBuf = components[..=at].iter().collect();
        let top = components.get(at + 1)?;
        let (name, version) = distribution_owning(&site, top)?;
        let module = python_module(&components[at + 1..].join("/"))?;
        let package = ScipPackage::new("python", name, version).ok()?;
        return Some((package, vec![ScipDescriptor::namespace(module)]));
    }
    // An interpreter's own library, `lib/python3.12/json/__init__.py`.
    let at = components.iter().rposition(|component| {
        component.starts_with("python3") && component[7..].starts_with('.')
    })?;
    let module = python_module(&components[at + 1..].join("/"))?;
    let version = stdlib
        .python
        .clone()
        .or_else(|| Some(components[at].trim_start_matches("python").to_string()))?;
    let package = ScipPackage::new("python", "python-stdlib", version).ok()?;
    Some((package, vec![ScipDescriptor::namespace(module)]))
}

/// The installed distribution whose files include the top-level entry `top`
/// of `site`, by its `.dist-info` record: its name and version.
fn distribution_owning(site: &Path, top: &str) -> Option<(String, String)> {
    let entries = std::fs::read_dir(site).ok()?;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(stem) = name.strip_suffix(".dist-info") else {
            continue;
        };
        let Ok(record) = std::fs::read_to_string(entry.path().join("RECORD")) else {
            continue;
        };
        let owns = record.lines().any(|line| {
            let file = line.split(',').next().unwrap_or_default();
            file.split('/').next() == Some(top)
        });
        if !owns {
            continue;
        }
        let metadata = std::fs::read_to_string(entry.path().join("METADATA")).unwrap_or_default();
        let field = |key: &str| {
            metadata
                .lines()
                .find_map(|line| line.strip_prefix(key).map(|value| value.trim().to_string()))
        };
        let (fallback_name, fallback_version) = stem.rsplit_once('-')?;
        return Some((
            field("Name:").unwrap_or_else(|| fallback_name.to_string()),
            field("Version:").unwrap_or_else(|| fallback_version.to_string()),
        ));
    }
    None
}

/// A Rust crate: the sysroot's `std`, `core` or `alloc` at the rustc release
/// that ships them, or the nearest crate manifest above the file.
fn cargo_package_of(
    path: &Path,
    stdlib: &StdlibVersions,
) -> Option<(ScipPackage, Vec<ScipDescriptor>)> {
    let components: Vec<String> = path
        .components()
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .collect();
    let library = components
        .windows(3)
        .position(|window| window[0] == "src" && window[1] == "rust" && window[2] == "library");
    if let Some(at) = library {
        let crate_name = components.get(at + 3)?;
        let inside = components.get(at + 4..)?;
        let version = stdlib
            .rust
            .clone()
            .or_else(|| sysroot_release(path))
            .or_else(|| {
                components
                    .iter()
                    .find_map(|component| release_version(component))
            })?;
        let package = ScipPackage::new("cargo", crate_name.as_str(), version).ok()?;
        return Some((package, rust_module_descriptors(inside)?));
    }
    for dir in path.ancestors().skip(1) {
        let Ok(text) = std::fs::read_to_string(dir.join("Cargo.toml")) else {
            continue;
        };
        let manifest = text.parse::<toml::Table>().ok()?;
        let package = manifest.get("package")?.as_table()?;
        let name = package.get("name")?.as_str()?;
        let version = package.get("version")?.as_str()?;
        let package = ScipPackage::new("cargo", name, version).ok()?;
        let inside: Vec<String> = path
            .strip_prefix(dir)
            .ok()?
            .components()
            .map(|component| component.as_os_str().to_string_lossy().into_owned())
            .collect();
        return Some((package, rust_module_descriptors(&inside)?));
    }
    None
}

/// The module path of a crate file below the crate root: `src/vec/mod.rs` is
/// `vec/`, `src/lib.rs` is the crate root itself. A file outside `src` is
/// named by its whole path.
fn rust_module_descriptors(inside: &[String]) -> Option<Vec<ScipDescriptor>> {
    let (first, rest) = inside.split_first()?;
    if first != "src" {
        return Some(vec![ScipDescriptor::namespace(inside.join("/"))]);
    }
    let mut modules: Vec<String> = rest.to_vec();
    let file = modules.pop()?;
    let stem = file.strip_suffix(".rs")?;
    if !matches!(stem, "lib" | "mod" | "main") {
        modules.push(stem.to_string());
    }
    Some(modules.into_iter().map(ScipDescriptor::namespace).collect())
}

/// The rustc release of a rustup sysroot, from the channel manifest it ships.
fn sysroot_release(path: &Path) -> Option<String> {
    for dir in path.ancestors() {
        if dir.file_name().and_then(|name| name.to_str()) != Some("rustlib") {
            continue;
        }
        let manifest = std::fs::read_to_string(dir.join("multirust-channel-manifest.toml")).ok()?;
        let table = manifest.parse::<toml::Table>().ok()?;
        let version = table.get("pkg")?.get("rustc")?.get("version")?.as_str()?;
        return release_version(version);
    }
    None
}

/// A Go package: the standard library under the toolchain's `src`, or a
/// module in the module cache, named by its import path.
fn go_package_of(
    path: &Path,
    stdlib: &StdlibVersions,
) -> Option<(ScipPackage, Vec<ScipDescriptor>)> {
    let directory = path.parent()?;
    let components: Vec<String> = directory
        .components()
        .map(|component| component.as_os_str().to_string_lossy().into_owned())
        .collect();
    if let Some(at) = components
        .iter()
        .position(|component| component.contains('@'))
    {
        let (last, version) = components[at].rsplit_once('@')?;
        let start = components[..at]
            .windows(2)
            .rposition(|window| window[0] == "pkg" && window[1] == "mod")
            .map(|index| index + 2)?;
        let mut module_parts: Vec<String> = components[start..at].to_vec();
        module_parts.push(last.to_string());
        let module = unescape_module_path(&module_parts.join("/"));
        let mut import = module.clone();
        for part in &components[at + 1..] {
            import.push('/');
            import.push_str(part);
        }
        let package = ScipPackage::new("go", module, version).ok()?;
        return Some((package, vec![ScipDescriptor::namespace(import)]));
    }
    for (index, dir) in directory.ancestors().enumerate() {
        if dir.file_name().and_then(|name| name.to_str()) != Some("src") {
            continue;
        }
        let root = dir.parent()?;
        let version = std::fs::read_to_string(root.join("VERSION"))
            .ok()
            .and_then(|text| text.lines().next().and_then(release_version))
            .or_else(|| stdlib.go.clone())?;
        if index == 0 {
            return None;
        }
        let import = relative(directory, dir)?;
        let package = ScipPackage::new("go", "std", version).ok()?;
        return Some((package, vec![ScipDescriptor::namespace(import)]));
    }
    None
}

/// The module cache writes an upper-case letter as `!` and its lower case.
fn unescape_module_path(escaped: &str) -> String {
    let mut out = String::with_capacity(escaped.len());
    let mut upper = false;
    for ch in escaped.chars() {
        if ch == '!' {
            upper = true;
        } else if upper {
            out.extend(ch.to_uppercase());
            upper = false;
        } else {
            out.push(ch);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(path: &Path, text: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    /// A fresh directory under the system temporary directory.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!(
                "kin-lsp-external-symbols-{}",
                kin_model::EntityId::new()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            Self(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn typescript_lib_files_are_named_by_the_loaded_typescript() {
        let dir = Scratch::new();
        let typescript = dir.path().join("node_modules/typescript");
        write(
            &typescript.join("package.json"),
            r#"{"name":"typescript","version":"5.6.3"}"#,
        );
        let lib = typescript.join("lib/lib.es5.d.ts");
        write(&lib, "interface Array<T> { map(): void }");
        let (package, namespace) = npm_package_of(&lib).unwrap();
        assert_eq!(package.encode(), "npm typescript 5.6.3");
        assert_eq!(namespace, vec![ScipDescriptor::namespace("lib.es5.d.ts")]);

        // A package's nested manifest without a name does not end the walk.
        let lodash = dir.path().join("node_modules/lodash");
        write(
            &lodash.join("package.json"),
            r#"{"name":"lodash","version":"4.17.21"}"#,
        );
        write(&lodash.join("fp/package.json"), r#"{"type":"module"}"#);
        let file = lodash.join("fp/map.d.ts");
        write(&file, "");
        let (package, namespace) = npm_package_of(&file).unwrap();
        assert_eq!(package.encode(), "npm lodash 4.17.21");
        assert_eq!(namespace, vec![ScipDescriptor::namespace("fp/map.d.ts")]);
    }

    #[test]
    fn python_stdlib_stubs_are_named_by_the_evaluated_version() {
        let stdlib = StdlibVersions {
            python: Some("3.12".to_string()),
            ..StdlibVersions::default()
        };
        let path = Path::new("/opt/pyright/dist/typeshed-fallback/stdlib/os/path.pyi");
        let (package, namespace) = python_package_of(path, &stdlib).unwrap();
        assert_eq!(package.encode(), "python python-stdlib 3.12");
        assert_eq!(namespace, vec![ScipDescriptor::namespace("os.path")]);
        let builtins = Path::new("/x/typeshed-fallback/stdlib/builtins.pyi");
        assert_eq!(
            python_package_of(builtins, &stdlib).unwrap().1,
            vec![ScipDescriptor::namespace("builtins")]
        );
        assert!(
            python_package_of(builtins, &StdlibVersions::default()).is_none(),
            "no evaluated version, no name"
        );
    }

    #[test]
    fn python_distributions_are_named_by_their_record() {
        let dir = Scratch::new();
        let site = dir.path().join("lib/python3.12/site-packages");
        write(
            &site.join("starlette-0.41.3.dist-info/RECORD"),
            "starlette/__init__.py,sha256=x,10\nstarlette/routing.py,sha256=y,20\n",
        );
        write(
            &site.join("starlette-0.41.3.dist-info/METADATA"),
            "Metadata-Version: 2.3\nName: starlette\nVersion: 0.41.3\n",
        );
        let file = site.join("starlette/routing.py");
        write(&file, "");
        let (package, namespace) = python_package_of(&file, &StdlibVersions::default()).unwrap();
        assert_eq!(package.encode(), "python starlette 0.41.3");
        assert_eq!(
            namespace,
            vec![ScipDescriptor::namespace("starlette.routing")]
        );
    }

    #[test]
    fn rust_sysroot_crates_and_registry_crates_are_named() {
        let stdlib = StdlibVersions {
            rust: Some("1.90.0".to_string()),
            ..StdlibVersions::default()
        };
        let vec = Path::new(
            "/h/.rustup/toolchains/stable-x/lib/rustlib/src/rust/library/alloc/src/vec/mod.rs",
        );
        let (package, namespace) = cargo_package_of(vec, &stdlib).unwrap();
        assert_eq!(package.encode(), "cargo alloc 1.90.0");
        assert_eq!(namespace, vec![ScipDescriptor::namespace("vec")]);

        let dir = Scratch::new();
        let krate = dir.path().join("registry/src/index/serde-1.0.210");
        write(
            &krate.join("Cargo.toml"),
            "[package]\nname = \"serde\"\nversion = \"1.0.210\"\n",
        );
        let file = krate.join("src/de/mod.rs");
        write(&file, "");
        let (package, namespace) = cargo_package_of(&file, &stdlib).unwrap();
        assert_eq!(package.encode(), "cargo serde 1.0.210");
        assert_eq!(namespace, vec![ScipDescriptor::namespace("de")]);
    }

    #[test]
    fn go_std_and_module_cache_packages_are_named_by_import_path() {
        let dir = Scratch::new();
        let goroot = dir.path().join("go");
        write(&goroot.join("VERSION"), "go1.23.4\ntime 2024-12-03\n");
        let file = goroot.join("src/net/http/client.go");
        write(&file, "");
        let (package, namespace) = go_package_of(&file, &StdlibVersions::default()).unwrap();
        assert_eq!(package.encode(), "go std 1.23.4");
        assert_eq!(namespace, vec![ScipDescriptor::namespace("net/http")]);

        let cached = Path::new("/h/go/pkg/mod/github.com/!burnt!sushi/toml@v1.4.0/internal/tz.go");
        let (package, namespace) = go_package_of(cached, &StdlibVersions::default()).unwrap();
        assert_eq!(package.encode(), "go github.com/BurntSushi/toml v1.4.0");
        assert_eq!(
            namespace,
            vec![ScipDescriptor::namespace(
                "github.com/BurntSushi/toml/internal"
            )]
        );
    }

    #[test]
    fn document_symbols_name_the_innermost_declaration_at_the_answer() {
        let answer = serde_json::json!([{
            "name": "Array",
            "kind": 11,
            "range": {"start": {"line": 1, "character": 0}, "end": {"line": 50, "character": 1}},
            "selectionRange": {"start": {"line": 1, "character": 10}, "end": {"line": 1, "character": 15}},
            "children": [{
                "name": "map",
                "kind": 6,
                "range": {"start": {"line": 9, "character": 4}, "end": {"line": 9, "character": 60}},
                "selectionRange": {"start": {"line": 9, "character": 4}, "end": {"line": 9, "character": 7}}
            }]
        }]);
        let symbols = symbols_from_answer(&answer, DocumentLanguage::TypeScript);
        let at_map = LocationRange {
            start_line: 9,
            start_character: 4,
            end_line: 9,
            end_character: 7,
        };
        assert_eq!(
            chain_at(&symbols, &at_map).unwrap(),
            vec![
                ScipDescriptor::type_("Array"),
                ScipDescriptor::method("map")
            ]
        );
        let nowhere = LocationRange {
            start_line: 30,
            start_character: 0,
            end_line: 30,
            end_character: 3,
        };
        assert_eq!(
            chain_at(&symbols, &nowhere),
            None,
            "no symbol's name holds it"
        );
    }

    #[test]
    fn rust_impl_headers_and_go_receivers_name_their_type() {
        assert_eq!(
            rust_impl_self_type("impl<T, A: Allocator> Vec<T, A>").as_deref(),
            Some("Vec")
        );
        assert_eq!(
            rust_impl_self_type("impl<T: Clone> Clone for Vec<T>").as_deref(),
            Some("Vec")
        );
        assert_eq!(
            rust_impl_self_type("impl fmt::Debug for std::path::Path").as_deref(),
            Some("Path")
        );
        assert_eq!(
            descriptors_for("(*Buffer).Write", 6, DocumentLanguage::Go),
            vec![
                ScipDescriptor::type_("Buffer"),
                ScipDescriptor::method("Write")
            ]
        );
    }

    #[test]
    fn release_versions_read_only_releases() {
        assert_eq!(release_version("1.90.0").as_deref(), Some("1.90.0"));
        assert_eq!(release_version("go1.23.4").as_deref(), Some("1.23.4"));
        assert_eq!(release_version("3.12.4").as_deref(), Some("3.12.4"));
        assert_eq!(release_version("stable"), None);
        assert_eq!(release_version("unknown"), None);
        assert_eq!(
            release_version("1.90.0 (1159e78c4 2025-09-14)").as_deref(),
            Some("1.90.0")
        );
    }
}
