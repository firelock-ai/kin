// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Convert LSP responses into graph relations.
//!
//! The enrichment pipeline:
//! 1. For each entity in the graph, prepare a call hierarchy request
//! 2. Send to LSP server, get outgoing/incoming calls
//! 3. Match call targets against existing graph entities by file + position
//! 4. Produce Relations with RelationOrigin::Lsp

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use tracing::debug;

use crate::error::{LspError, Result};
use crate::file_enrichment::identifier_positions_in_line;
use crate::lifecycle::LspServer;
use crate::protocol::{
    self, CallHierarchyItem, Position, TextDocumentIdentifier, TypeHierarchyItem,
    TypeHierarchyPrepareParams, TypeHierarchySupertypesParams,
};
use kin_model::{
    EntityId, GraphNodeId, Relation, RelationEvidence, RelationId, RelationKind, RelationOrigin,
    SourceSpan,
};

/// Result of enriching a single file via LSP.
#[derive(Debug, Default)]
pub struct EnrichmentResult {
    /// New relations discovered by LSP (type-resolved calls, references, etc.)
    pub relations: Vec<Relation>,
    /// Entities that LSP couldn't resolve (for diagnostics).
    pub unresolved: Vec<String>,
    /// Number of call hierarchy items processed.
    pub items_processed: usize,
}

/// Lightweight entity reference for matching LSP locations to graph entities.
#[derive(Debug, Clone)]
pub struct EntityRef {
    pub id: EntityId,
    pub name: String,
    pub file_path: String,
    pub start_line: u32,
    pub start_col: u32,
    pub end_line: u32,
    /// Position of the entity NAME (not declaration start).
    /// LSP prepareCallHierarchy needs cursor on the name, not the fn keyword.
    ///
    /// A hint derived from the signature. A per-entity query is asked where the
    /// captured source spells the name, which is here when it does and
    /// elsewhere on the declaration line when it does not (see
    /// `SourcePositions::name_position`).
    pub name_line: u32,
    pub name_col: u32,
    /// Whether the entity's own name is written in its declaration.
    ///
    /// False for a module or file surface, whose name is its file's. No token
    /// in the file names it, so a query asked for it lands on whatever the file
    /// opens with, and every answer about that token would be attributed to the
    /// module. The per-entity name queries skip such an entity.
    pub declares_name: bool,
    /// The graph entity's kind.
    ///
    /// A server's reference answer can depend on it: gopls answers a method's
    /// references with those of every method related to it through interface
    /// satisfaction as well, so a Go method's reference sites are proven one
    /// by one before any is recorded (see [`enrich_entity_references`]).
    pub kind: kin_model::EntityKind,
}

impl EntityRef {
    /// Whether an entity of `kind` writes its own name in its declaration.
    pub fn kind_declares_name(kind: kin_model::EntityKind) -> bool {
        !matches!(
            kind,
            kin_model::EntityKind::Module
                | kin_model::EntityKind::Package
                | kin_model::EntityKind::File
        )
    }
}

/// Spatial index: given a file URI and line number, find the matching entity.
///
/// Files are held by repository-relative path, the graph's own spelling, and a
/// server names a file by an absolute URI. The two are joined by stripping the
/// workspace root from the URI's path and looking up what is left exactly (see
/// [`Self::repository_file`]).
pub struct EntityIndex {
    /// Repository-relative file path → that file's entities, by start line.
    by_file: HashMap<String, Vec<EntityRef>>,
    /// Every indexed file's package directory and file stem, as
    /// [`module_tail`] spells them, for recognizing an installed copy.
    module_tails: std::collections::HashSet<String>,
    /// The workspace root, spelled as a `file:` URI decodes on this host.
    root: PathBuf,
    /// The workspace root's real path, spelled the same way, when the root is
    /// on this host's disk.
    real_root: Option<PathBuf>,
    /// The real path of each path an answer named outside the files this
    /// index holds, resolved once (see [`Self::held_file`]).
    real_paths: std::sync::Mutex<HashMap<PathBuf, Option<PathBuf>>>,
}

/// A path's last directory and its file name without extensions, with a
/// stub package's `-stubs` suffix dropped: `requests/models` for
/// `src/requests/models.py`, for `site-packages/requests/models.py`, and for
/// `requests-stubs/models.pyi`. `None` for a path with no directory.
fn module_tail(path: &str) -> Option<String> {
    let mut parts = path.rsplit(['/', '\\']);
    let name = parts.next()?;
    let parent = parts.next().filter(|parent| !parent.is_empty())?;
    let stem = name.split('.').next().filter(|stem| !stem.is_empty())?;
    let parent = parent.strip_suffix("-stubs").unwrap_or(parent);
    Some(format!("{parent}/{stem}").to_lowercase())
}

/// A path respelled the way a server's answer decodes, so the two compare in
/// the one spelling `require_source_uri` compares them in. On Windows
/// `std::fs::canonicalize` returns `\\?\C:\repo`, and a server answers
/// `file:///c%3A/repo/...`, which decodes to `C:/repo/...`. On Unix an
/// absolute path comes back byte for byte.
fn host_spelling(path: &Path) -> PathBuf {
    protocol::uri_to_path(&protocol::path_to_uri(path)).unwrap_or_else(|| path.to_path_buf())
}

impl EntityIndex {
    /// Build an index from entity refs whose `file_path` is relative to
    /// `workspace_root`, the root the language server was started at.
    pub fn new(entities: Vec<EntityRef>, workspace_root: &Path) -> Self {
        let mut by_file: HashMap<String, Vec<EntityRef>> = HashMap::new();
        for entity in entities {
            by_file
                .entry(entity.file_path.clone())
                .or_default()
                .push(entity);
        }
        // Sort each file's entities by start line for binary search.
        for entries in by_file.values_mut() {
            entries.sort_by_key(|e| e.start_line);
        }
        let module_tails = by_file
            .keys()
            .filter_map(|file| module_tail(file))
            .collect();
        let root = host_spelling(workspace_root);
        let real_root = crate::call_sites::real_path(workspace_root)
            .map(|real| host_spelling(&real))
            .filter(|real| *real != root);
        Self {
            by_file,
            module_tails,
            root,
            real_root,
            real_paths: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// The repository-relative path of an absolute `path` below the workspace
    /// root or the root's real path, `/`-separated as the graph spells paths.
    fn relative_file(&self, path: &Path) -> Option<String> {
        let relative = path.strip_prefix(&self.root).ok().or_else(|| {
            self.real_root
                .as_deref()
                .and_then(|real| path.strip_prefix(real).ok())
        })?;
        let mut file = String::new();
        for component in relative.components() {
            let std::path::Component::Normal(part) = component else {
                return None;
            };
            if !file.is_empty() {
                file.push('/');
            }
            file.push_str(part.to_str()?);
        }
        (!file.is_empty()).then_some(file)
    }

    /// The real path of `path`, spelled as the root is, looked up once.
    fn real_path_of(&self, path: &Path) -> Option<PathBuf> {
        let resolve = || crate::call_sites::real_path(path).map(|real| host_spelling(&real));
        let Ok(mut held) = self.real_paths.lock() else {
            return resolve();
        };
        held.entry(path.to_path_buf())
            .or_insert_with(resolve)
            .clone()
    }

    /// The file this index holds that a `file:` URI names: the one at its
    /// path below the workspace root, or, when the index holds no file there,
    /// the one at its real path.
    ///
    /// A package manager links a workspace package into a dependency
    /// directory by a symbolic link to the package's own directory, as pnpm
    /// does with `node_modules/<package>`, and Kin's analysis environment
    /// does from its layout outside the repository. A file reached through
    /// such a link is the repository's source it links to.
    pub fn held_file(&self, uri: &str) -> Option<String> {
        if let Some(file) = self
            .repository_file(uri)
            .filter(|file| self.by_file.contains_key(file))
        {
            return Some(file);
        }
        let path = protocol::uri_to_path(uri)?;
        if !path.is_absolute() {
            return None;
        }
        let file = self.relative_file(&self.real_path_of(&path)?)?;
        self.by_file.contains_key(&file).then_some(file)
    }

    /// The repository-relative path a `file:` URI names: its path below the
    /// workspace root, `/`-separated as the graph spells paths.
    ///
    /// `None` for a URI outside the root, including a dependency's source in
    /// a module cache or a sibling checkout whose path merely ends the same
    /// way, for a remainder that is empty, climbs out of the root or is not
    /// UTF-8, and for anything that is not a local `file:` URI. The result is
    /// the file's path whether or not this index holds it.
    pub fn repository_file(&self, uri: &str) -> Option<String> {
        let path = protocol::uri_to_path(uri)?;
        let relative = path.strip_prefix(&self.root).ok()?;
        let mut file = String::new();
        for component in relative.components() {
            let std::path::Component::Normal(part) = component else {
                return None;
            };
            if !file.is_empty() {
                file.push('/');
            }
            file.push_str(part.to_str()?);
        }
        (!file.is_empty()).then_some(file)
    }

    /// Whether a URI outside the workspace lands, at `line`, in a declaration
    /// of an admitted file whose repository path is a whole-component tail of
    /// the URI's path, like `/foreign/types.py` for an admitted `types.py`.
    ///
    /// Such a location names no admitted file and is placed nowhere. The
    /// suffix placement used to put it in the admitted file, and the
    /// references arm refused an answer holding one rather than reading it as
    /// a site outside the admitted inventory. This keeps that refusal
    /// without placing anything, and it looks each tail up exactly, so no
    /// hash seed takes part in the verdict.
    pub fn admitted_source_outside(&self, uri: &str, line: u32) -> bool {
        if self.repository_file(uri).is_some() {
            return false;
        }
        let Some(path) = protocol::uri_to_path(uri) else {
            return false;
        };
        let mut parts = Vec::new();
        for component in path.components() {
            match component {
                std::path::Component::Prefix(_) | std::path::Component::RootDir => {}
                std::path::Component::Normal(part) => match part.to_str() {
                    Some(part) => parts.push(part),
                    None => return false,
                },
                _ => return false,
            }
        }
        (0..parts.len()).any(|start| {
            self.by_file
                .get(&parts[start..].join("/"))
                .is_some_and(|entries| {
                    entries
                        .iter()
                        .any(|e| line >= e.start_line && line <= e.end_line)
                })
        })
    }

    /// Find the entity at the given file URI and position.
    ///
    /// Returns the INNERMOST entity whose span contains the line: the method
    /// rather than the class that holds it, and the class rather than the module
    /// that holds them both.
    ///
    /// This returned the FIRST containing span, and a module entity carries a
    /// whole-file span and sorts first, so every position in a file resolved to
    /// its module. The consequences were total rather than partial. Same-file
    /// targets resolved to the same module as their source, making `source ==
    /// dst`, and 954 edges were silently dropped that way in one file of the
    /// requests corpus. Cross-file targets resolved to the target file's module,
    /// so the whole file-level definitions pass emitted only module-to-module
    /// edges and produced no entity-level edge at all. The pass answered
    /// correctly and the mapping threw the answer away.
    ///
    /// Line bases: LSP positions are 0-based, and kin graph spans are 0-based
    /// too (`kin_mcp`'s `presentation_line` adds one for display, which is what
    /// makes the graph's own base visible). They agree, so no conversion happens
    /// here. That agreement is asserted in the tests rather than assumed,
    /// because it currently holds by convention on both sides and a one-line
    /// change to either would silently shift every lookup by a line, which on
    /// `def` lines means resolving the enclosing scope instead of the method.
    ///
    /// The file is the one whose repository path is exactly the URI's path
    /// below the workspace root. The lookup used to take the absolute path
    /// itself as the key, which no repository-relative key ever equals, and
    /// then fall back to the first key the path ended with. Where one
    /// repository path ends another, both keys matched: cli/cli's
    /// `api/client_test.go` ends `pkg/cmd/attestation/api/client_test.go`, and
    /// whichever of the two a `HashMap` iterated to first won, so each index's
    /// random seed picked the file. A wrong pick put a site in a file that does
    /// not hold it, which wrote false edges and, once sources were checked,
    /// refused the whole answer. A dependency's source in a module cache ended
    /// in a repository path just as well, and matched a file that is not it.
    /// A path through a workspace package's symbolic link names the file at
    /// its real path (see [`Self::held_file`]), which is exact too.
    pub fn find_at(&self, uri: &str, line: u32) -> Option<&EntityRef> {
        let entries = self.by_file.get(&self.held_file(uri)?)?;

        entries
            .iter()
            .filter(|e| line >= e.start_line && line <= e.end_line)
            // Smallest span wins. Ties break on the later start, which is the
            // more deeply nested of two spans that begin together, so a method
            // whose body is its whole parent still beats the parent.
            .min_by_key(|e| {
                (
                    e.end_line.saturating_sub(e.start_line),
                    u32::MAX - e.start_line,
                )
            })
    }

    /// Whether a file this URI names may be a copy of one the index holds.
    ///
    /// A definition answer outside the workspace can land in an installed
    /// copy of this very repository: a `src/` layout package whose tests
    /// import it by name resolve to the copy in `site-packages`, and a stub
    /// package ships `.pyi` twins of its modules. Such an answer names the
    /// repository's own declaration under another path, so it proves nothing
    /// about where the call goes. Matched the way [`Self::find_at`] matches a
    /// path, and then by package directory and file stem, which can only
    /// call more answers copies than there are.
    pub fn may_hold_file(&self, uri: &str) -> bool {
        if self
            .repository_file(uri)
            .is_some_and(|file| self.by_file.contains_key(&file))
        {
            return true;
        }
        protocol::uri_to_path(uri).is_some_and(|path| {
            let parts: Vec<&str> = path
                .components()
                .filter_map(|component| match component {
                    std::path::Component::Normal(part) => part.to_str(),
                    _ => None,
                })
                .collect();
            (0..parts.len()).any(|start| self.by_file.contains_key(&parts[start..].join("/")))
                || module_tail(path.to_string_lossy().as_ref())
                    .is_some_and(|tail| self.module_tails.contains(&tail))
        })
    }

    /// Whether a declaration the server placed at `uri` lies outside the
    /// repository, decided by what the graph holds rather than by where the
    /// file sits relative to the workspace root.
    ///
    /// - A file this index holds is the repository's, including one reached
    ///   through a symbolic link (see [`Self::held_file`]).
    /// - A file that may be an installed copy of one it holds is the
    ///   repository's own code under another path, and refutes nothing (see
    ///   [`Self::may_hold_file`]).
    /// - Otherwise the file's real path decides. Outside the workspace root it
    ///   is a toolchain's, a dependency's or another checkout's. Inside the
    ///   root it is outside only in a dependency directory, such as the
    ///   repository's own `node_modules` holding the TypeScript it runs, or a
    ///   virtual environment in the checkout. Any other file inside the root
    ///   may be the repository's own, such as its build output or a
    ///   generated file, and is undecided.
    ///
    /// Only a `file:` URI with an absolute path can be outside; any other
    /// scheme is undecided.
    pub fn outside_repository(&self, uri: &str) -> bool {
        let Some(path) = protocol::uri_to_path(uri) else {
            return false;
        };
        if !path.is_absolute() || !self.root.is_absolute() {
            return false;
        }
        if self.held_file(uri).is_some() || self.may_hold_file(uri) {
            return false;
        }
        let judged = self.real_path_of(&path).unwrap_or(path);
        let below = crate::call_sites::directories_below(&judged, &self.root).or_else(|| {
            self.real_root
                .as_deref()
                .and_then(|real| crate::call_sites::directories_below(&judged, real))
        });
        match below {
            None => true,
            Some(directories) => crate::call_sites::in_dependency_directory(&directories),
        }
    }

    /// Return every entity in the file at repository-relative `file_path`.
    ///
    /// Only that exact path names the file. A path another one merely ends
    /// with names no file here, for the reason [`Self::find_at`] gives.
    pub fn entities_in_file(&self, file_path: &str) -> Vec<&EntityRef> {
        self.by_file
            .get(file_path)
            .map(|entries| entries.iter().collect())
            .unwrap_or_default()
    }

    /// The one entity named `name`, or whose name ends in `.name`.
    ///
    /// `None` when no entity matches and when several do. This returned
    /// whichever match a `HashMap` iterated to first, so a name two entities
    /// answer to, like cli/cli's `GetByRepoAndDigest` on both `LiveClient` and
    /// `MockClient`, named one of them at random.
    pub fn find_by_name(&self, name: &str) -> Option<&EntityRef> {
        let member = format!(".{name}");
        let mut matches = self
            .by_file
            .values()
            .flatten()
            .filter(|e| e.name == name || e.name.ends_with(&member));
        let found = matches.next()?;
        matches.next().is_none().then_some(found)
    }
}

/// Evidence naming the position the server was asked about.
///
/// The call site, not the definition. Enrichment relations carried
/// `evidence: Vec::new()`, so an edge a language server proved arrived with no
/// reference site and every consuming surface reported `no_evidence_span` for
/// it. The position is already in hand at every call below, so this costs no
/// extra round trip: it is the range the server itself reported the reference
/// at.
///
/// Lines are 0-based on both sides, matching LSP and kin graph spans, and the
/// display surfaces add one.
pub(crate) fn query_position_evidence(
    rule: &'static str,
    span: SourceSpan,
) -> Vec<RelationEvidence> {
    vec![position_evidence(rule, span)]
}

fn admitted_text(documents: Option<DocumentProvider<'_>>, file: &str) -> Result<String> {
    documents
        .and_then(|provider| provider(file))
        .ok_or_else(|| LspError::Protocol(format!("repository source unavailable for LSP: {file}")))
}

#[cfg(test)]
mod installed_copy_tests {
    use super::*;

    fn index_of(files: &[&str]) -> EntityIndex {
        EntityIndex::new(
            files
                .iter()
                .map(|file| EntityRef {
                    id: kin_model::EntityId::new(),
                    name: "f".into(),
                    file_path: (*file).into(),
                    start_line: 0,
                    start_col: 0,
                    end_line: 0,
                    name_line: 0,
                    name_col: 0,
                    declares_name: true,
                    kind: kin_model::EntityKind::Function,
                })
                .collect(),
            Path::new("/repo"),
        )
    }

    /// A `src/` layout package installed into an environment is the
    /// repository's own code under another path, and so is its stub package.
    #[test]
    fn an_installed_copy_of_a_repository_module_is_recognized() {
        let index = index_of(&["src/requests/models.py", "tests/test_requests.py"]);
        for copy in [
            "file:///venv/lib/python3.12/site-packages/requests/models.py",
            "file:///venv/lib/python3.12/site-packages/requests-stubs/models.pyi",
            "file:///venv/lib/python3.12/site-packages/Requests/Models.py",
        ] {
            assert!(index.may_hold_file(copy), "{copy}");
        }
        for foreign in [
            "file:///usr/lib/python3.12/json/__init__.py",
            "file:///venv/lib/python3.12/site-packages/httpx/models.py",
            "file:///opt/typeshed/stdlib/builtins.pyi",
        ] {
            assert!(!index.may_hold_file(foreign), "{foreign}");
        }
    }
}

#[cfg(test)]
mod outside_repository_tests {
    use super::*;

    fn index_at(root: &Path, files: &[&str]) -> EntityIndex {
        EntityIndex::new(
            files
                .iter()
                .map(|file| EntityRef {
                    id: kin_model::EntityId::new(),
                    name: "helper".into(),
                    file_path: (*file).into(),
                    start_line: 0,
                    start_col: 0,
                    end_line: 2,
                    name_line: 1,
                    name_col: 16,
                    declares_name: true,
                    kind: kin_model::EntityKind::Function,
                })
                .collect(),
            root,
        )
    }

    /// A dependency directory inside the workspace root holds no repository
    /// source, so an answer there leaves the repository: a repository's own
    /// TypeScript under `node_modules`, a package in pnpm's store, and a
    /// virtual environment inside the checkout.
    #[test]
    fn a_dependency_directory_inside_the_root_is_outside() {
        let index = index_at(Path::new("/repo"), &["src/index.ts", "app/main.py"]);
        for outside in [
            "file:///repo/node_modules/typescript/lib/lib.es5.d.ts",
            "file:///repo/node_modules/.pnpm/vitest@1.6.0/node_modules/vitest/dist/index.d.ts",
            "file:///repo/packages/web/node_modules/@types/node/globals.d.ts",
            "file:///repo/.venv/lib/python3.12/site-packages/httpx/_client.py",
            "file:///usr/lib/python3.12/json/__init__.py",
        ] {
            assert!(index.outside_repository(outside), "{outside}");
        }
    }

    /// A root whose tree holds a toolchain's or a package manager's caches
    /// still reads their files as outside: a Cargo registry, the Go module
    /// cache, rustup's toolchains, and Kin's own analysis environments.
    #[test]
    fn dependency_caches_under_the_root_are_outside() {
        let index = index_at(Path::new("/home/dev"), &["project/engine/plan.rs"]);
        for outside in [
            "file:///home/dev/.cargo/registry/src/index.crates.io-6f17d22bba15001f/serde-1.0.219/src/lib.rs",
            "file:///home/dev/go/pkg/mod/github.com/gin-gonic/gin@v1.10.0/gin.go",
            "file:///home/dev/.rustup/toolchains/stable-aarch64-apple-darwin/lib/rustlib/src/rust/library/core/src/option.rs",
            "file:///home/dev/.kin/cache/analysis-environments/python/cp311/site/httpx/_client.py",
        ] {
            assert!(index.outside_repository(outside), "{outside}");
        }
    }

    /// Inside the root, only a dependency directory is outside. A file the
    /// graph holds is the repository's, and so may be a file it does not
    /// hold, such as its own build output or a generated file, so neither
    /// refutes anything.
    #[test]
    fn repository_files_the_graph_does_not_hold_are_not_outside() {
        let index = index_at(Path::new("/repo"), &["src/index.ts"]);
        for inside in [
            "file:///repo/src/index.ts",
            "file:///repo/dist/index.d.ts",
            "file:///repo/src/generated/schema.ts",
            "file:///repo/pkg/mod/local.go",
            "jdt://contents/rt.jar/java.util/List.class",
        ] {
            assert!(!index.outside_repository(inside), "{inside}");
        }
    }

    /// An installed copy of a package the workspace itself provides is the
    /// repository's own code under another path, wherever it is installed.
    #[test]
    fn an_installed_copy_in_a_dependency_directory_is_not_outside() {
        let index = index_at(
            Path::new("/repo"),
            &["src/requests/models.py", "src/driver/Driver.ts"],
        );
        for copy in [
            "file:///repo/.venv/lib/python3.12/site-packages/requests/models.py",
            "file:///repo/node_modules/typeorm/driver/Driver.d.ts",
            "file:///repo/node_modules/.pnpm/typeorm@0.3.20/node_modules/typeorm/driver/Driver.d.ts",
        ] {
            assert!(!index.outside_repository(copy), "{copy}");
        }
    }

    /// A temporary directory, removed when it is dropped.
    struct Scratch(PathBuf);

    impl Scratch {
        fn new(label: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "kin-lsp-outside-{label}-{}",
                kin_model::EntityId::new()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            // The root as a server answers it: its real path.
            Self(std::fs::canonicalize(&dir).unwrap())
        }

        fn file(&self, relative: &str) {
            let path = self.0.join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::fs::write(path, "export function helper() {}\n").unwrap();
        }

        fn link(&self, relative: &str, target: &Path) {
            let path = self.0.join(relative);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            std::os::unix::fs::symlink(target, path).unwrap();
        }

        fn uri(&self, relative: &str) -> String {
            protocol::path_to_uri(&self.0.join(relative))
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// pnpm links a workspace package into `node_modules` by a symbolic link
    /// to its directory. A file reached through that link is the repository's
    /// source it links to: placed in that source when the graph holds it, and
    /// never outside even when the graph does not, as with the package's own
    /// build output. A dependency pnpm links from its store stays outside.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_workspace_package_is_the_source_it_links_to() {
        let root = Scratch::new("pnpm");
        root.file("packages/pkg/src/lib.ts");
        root.file("packages/pkg/dist/lib.d.ts");
        root.link("node_modules/pkg", Path::new("../packages/pkg"));
        root.file("node_modules/.pnpm/dep@1.0.0/node_modules/dep/index.d.ts");
        root.link(
            "node_modules/dep",
            Path::new(".pnpm/dep@1.0.0/node_modules/dep"),
        );
        let index = index_at(&root.0, &["packages/pkg/src/lib.ts"]);

        let linked = root.uri("node_modules/pkg/src/lib.ts");
        assert_eq!(
            index
                .find_at(&linked, 1)
                .map(|entity| entity.file_path.as_str()),
            Some("packages/pkg/src/lib.ts")
        );
        assert!(!index.outside_repository(&linked));
        assert!(!index.outside_repository(&root.uri("node_modules/pkg/dist/lib.d.ts")));
        assert!(index.outside_repository(&root.uri("node_modules/dep/index.d.ts")));
        assert!(index.outside_repository(
            &root.uri("node_modules/.pnpm/dep@1.0.0/node_modules/dep/index.d.ts")
        ));
    }

    /// A workspace package linked from a layout outside the repository, as
    /// Kin's analysis environment lays one out, is the repository's source
    /// all the same.
    #[cfg(unix)]
    #[test]
    fn a_workspace_package_linked_from_outside_the_root_is_its_source() {
        let root = Scratch::new("root");
        let layout = Scratch::new("layout");
        root.file("packages/pkg/src/lib.ts");
        layout.link("node_modules/pkg", &root.0.join("packages/pkg"));
        let index = index_at(&root.0, &["packages/pkg/src/lib.ts"]);

        let linked = layout.uri("node_modules/pkg/src/lib.ts");
        assert_eq!(
            index
                .find_at(&linked, 1)
                .map(|entity| entity.file_path.as_str()),
            Some("packages/pkg/src/lib.ts")
        );
        assert!(!index.outside_repository(&linked));
    }
}

/// Refuse an answer whose URI names a file other than the admitted one.
///
/// Compared as files rather than as strings: a server may spell the same path
/// with other escapes, or a Windows drive as `c%3A`, and that is still the file
/// Kin opened.
fn require_source_uri(uri: &str, file: &str, root: &Path) -> Result<()> {
    if !protocol::same_file_uri(uri, &protocol::path_to_uri(&root.join(file))) {
        return Err(LspError::Protocol(format!(
            "LSP source URI does not identify admitted file {file}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod source_uri_tests {
    use super::*;

    /// A server that escapes `@` or a space names the admitted file all the
    /// same, and one that names a sibling is still refused.
    #[test]
    fn a_differently_escaped_uri_still_identifies_the_admitted_file() {
        let root = Path::new("/repo");
        require_source_uri(
            "file:///repo/packages/%40scope/my%20dir/a.ts",
            "packages/@scope/my dir/a.ts",
            root,
        )
        .expect("the same file, escaped differently");
        require_source_uri(
            &protocol::path_to_uri(&root.join("src/a.py")),
            "src/a.py",
            root,
        )
        .expect("Kin's own spelling");
        assert!(require_source_uri("file:///repo/src/b.py", "src/a.py", root).is_err());
        assert!(require_source_uri("file:///elsewhere/src/a.py", "src/a.py", root).is_err());
    }
}

/// The most positions one enrichment edge records.
///
/// A language server can answer with more sites than any reader will act on,
/// and each one is persisted evidence. The consuming surfaces already declare an
/// enrichment edge's site list a floor rather than a total, so stopping here
/// reports fewer sites than exist and never reports a total it cannot support.
pub const MAX_SITES_PER_EDGE: usize = 64;

/// Every position the server reported for one edge, in source order, capped at
/// [`MAX_SITES_PER_EDGE`].
///
/// A server answers `find_references` and `outgoingCalls` with a list, and
/// keeping only its head threw away every site after the first. The edge is
/// keyed on (kind, source, destination), so the sites of one edge have to travel
/// as several evidence records on that one edge rather than as several edges.
///
/// Ordered by position rather than by arrival, so the stored record is a
/// function of the positions alone. That is also what makes the cap
/// deterministic: it keeps the earliest sites in the file rather than whichever
/// ones the server happened to name first.
pub(crate) fn query_positions_evidence(
    rule: &'static str,
    source: &crate::source_positions::SourcePositions<'_>,
    ranges: impl IntoIterator<Item = protocol::Range>,
) -> Result<Vec<RelationEvidence>> {
    fn key(range: &protocol::Range) -> (u32, u32, u32, u32) {
        (
            range.start.line,
            range.start.character,
            range.end.line,
            range.end.character,
        )
    }
    let mut ordered: Vec<protocol::Range> = ranges.into_iter().collect();
    ordered.sort_by_key(key);
    ordered.dedup_by_key(|range| key(range));
    // The retained list is a floor, but truncation must not hide malformed
    // observations and turn a failed query into a successful completion.
    let mut evidence = ordered
        .iter()
        .map(|range| {
            source
                .range(range)
                .map(|span| position_evidence(rule, span))
        })
        .collect::<Result<Vec<_>>>()?;
    evidence.truncate(MAX_SITES_PER_EDGE);
    Ok(evidence)
}

fn position_evidence(rule: &'static str, span: SourceSpan) -> RelationEvidence {
    RelationEvidence {
        source_span: Some(span),
        parser_rule: Some(rule.to_string()),
        occurrence_count: 1,
        ..Default::default()
    }
}

/// The id of an edge a language server proved between two repository
/// entities (see [`crate::relation_identity`]).
pub(crate) fn deterministic_relation_id(
    kind: RelationKind,
    src: EntityId,
    dst: EntityId,
) -> RelationId {
    crate::relation_identity::language_server_relation_id(kind, src, dst)
}

/// What one caller's call hierarchy proved, and how much of the server's
/// answer it could not.
#[derive(Debug, Default)]
pub struct EntityCalls {
    /// One `Calls` edge per target the server placed at least one call site of
    /// inside the caller, carrying those sites and no others.
    pub relations: Vec<Relation>,
    /// Outgoing calls the server reported without a single site inside the
    /// caller's lines. None of them became an edge. The answer that reported
    /// them was not proven whole, so a pass that reports completeness counts
    /// the query as one that did not finish.
    pub unproven_calls: usize,
    /// Call ranges inside the caller whose call the server resolved to a
    /// declaration outside the repository, in a file the graph holds no twin
    /// of. Each refutes an in-repository guess at that range.
    pub outside_sites: Vec<crate::call_sites::SiteAnswer>,
}

/// Query outgoing calls from a specific entity and produce Relations.
///
/// The caller is proven call by call. A call counts only at the sites the
/// server placed inside the caller's own lines: its other sites are dropped,
/// and a call left with none is dropped whole and counted in
/// [`EntityCalls::unproven_calls`]. The caller's other calls stand.
///
/// Each site belongs to the entity that makes the call, the innermost one
/// whose lines hold it. A class's call hierarchy lists the calls its
/// property decorators and initializers make, and on typeorm 6,612 such
/// sites were recorded as the class calling when the parser, and the
/// definition at the same token, name the property. A call the server
/// resolved outside the repository mints no edge and is kept in
/// [`EntityCalls::outside_sites`] as the refutation it is.
///
/// One call without a site in the caller used to refuse the whole caller, and
/// the file pass then counted that caller as a failed query, so every edge it
/// had proven went with the one it had not. A malformed position anywhere in
/// the answer still refuses all of it: it means the server holds text other
/// than the admitted document, and then none of its positions is proven.
pub async fn enrich_entity_calls(
    server: &LspServer,
    caller: &EntityRef,
    index: &EntityIndex,
    workspace_root: &Path,
    documents: Option<DocumentProvider<'_>>,
) -> Result<EntityCalls> {
    if !server.has_call_hierarchy() {
        return Ok(EntityCalls::default());
    }

    let file_path = workspace_root.join(&caller.file_path);
    let uri = protocol::path_to_uri(&file_path);

    let text = admitted_text(documents, &caller.file_path)?;
    let positions = crate::source_positions::SourcePositions::new(&caller.file_path, &text);
    let Some(request_position) = positions.name_position(caller)? else {
        return Ok(EntityCalls::default());
    };

    // Step 1: Prepare call hierarchy at the entity's position.
    let prepare_result = server
        .client
        .request(
            "textDocument/prepareCallHierarchy",
            protocol::CallHierarchyPrepareParams {
                text_document: TextDocumentIdentifier { uri: uri.clone() },
                position: request_position.clone(),
            },
        )
        .await;

    let items: Vec<CallHierarchyItem> = decode_optional_array(prepare_result?)?;

    if items.is_empty() {
        return Ok(EntityCalls::default());
    }

    // Step 2: The prepared source that is the queried entity.
    let item = prepared_source(
        &items,
        server.typescript_grammars(),
        caller,
        index,
        &positions,
        &text,
        workspace_root,
        &request_position,
    )?;
    // A TypeScript binding's initializer is prepared with its selection, the
    // binding's name, outside its enclosing range, the initializer.
    // `prepared_source` admits one only once it is proven.
    let enclosing = positions.range(&item.range)?;
    let selection = positions.range(&item.selection_range)?;
    let binding_initializer =
        selection.start_byte < enclosing.start_byte || selection.end_byte > enclosing.end_byte;
    let outgoing_result = server
        .client
        .request(
            "callHierarchy/outgoingCalls",
            protocol::CallHierarchyOutgoingCallsParams { item: item.clone() },
        )
        .await;

    let outgoing: Vec<protocol::CallHierarchyOutgoingCall> =
        decode_optional_array(outgoing_result?)?;

    // Step 3: Match each outgoing call target to a graph entity.
    let mut calls = EntityCalls::default();
    for call in &outgoing {
        let mut inside = Vec::with_capacity(call.from_ranges.len());
        for range in &call.from_ranges {
            // Checked whether or not the site is kept, so a malformed site
            // cannot hide behind the caller-lines test below.
            positions.range(range)?;
            if range.start.line >= caller.start_line && range.end.line <= caller.end_line {
                inside.push(range.clone());
            }
        }
        // A binding's initializer is narrower than its declaration line. A
        // second declarator may share that line, so its call sites must not be
        // attributed to this binding. Validate every site before the evidence
        // cap can omit any of them.
        if binding_initializer {
            for range in &call.from_ranges {
                let span = positions.range(range)?;
                if span.start_byte < enclosing.start_byte || span.end_byte > enclosing.end_byte {
                    return Err(LspError::Protocol(
                        "outgoing call is outside the proven binding initializer".into(),
                    ));
                }
            }
        }
        if inside.is_empty() {
            // No site the server named lies in the caller, so nothing proves
            // this caller makes the call. It is counted, not minted.
            calls.unproven_calls += 1;
            debug!(
                caller = %caller.name,
                target = %call.to.name,
                sites = call.from_ranges.len(),
                "LSP outgoing call has no site inside the queried caller; dropped"
            );
            continue;
        }
        if inside.len() < call.from_ranges.len() {
            debug!(
                caller = %caller.name,
                target = %call.to.name,
                dropped = call.from_ranges.len() - inside.len(),
                "LSP outgoing call sites outside the queried caller were dropped"
            );
        }
        let target_line = call.to.selection_range.start.line;
        let target_uri = &call.to.uri;

        // The entity that makes each call: the innermost one holding its site.
        let mut by_owner: Vec<(&EntityRef, Vec<protocol::Range>)> = Vec::new();
        for range in inside {
            let owner = site_owner(index, &uri, caller, range.start.line);
            match by_owner.iter_mut().find(|(held, _)| held.id == owner.id) {
                Some((_, ranges)) => ranges.push(range),
                None => by_owner.push((owner, vec![range])),
            }
        }

        // Position only. The name fallback matched the FIRST entity whose name
        // ended with the target's, which for `send` was the caller itself, so
        // the edge became a self-loop and was dropped: a proven answer thrown
        // away and reported as nothing found. Worse, when it did not self-loop
        // it stamped an arbitrary same-named entity with `RelationOrigin::Lsp`,
        // which reads `type_resolved`, a fabricated edge wearing the strongest
        // resolution there is. A position that maps to nothing now produces no
        // edge, which is the honest answer and a reportable gap.
        let target = index
            .find_at(target_uri, target_line)
            .and_then(|found| call_target(index, found, &call.to, documents));

        match target {
            Some(target_ref) => {
                for (owner, ranges) in by_owner {
                    calls.relations.push(Relation {
                        id: deterministic_relation_id(RelationKind::Calls, owner.id, target_ref.id),
                        kind: RelationKind::Calls,
                        src: GraphNodeId::Entity(owner.id),
                        dst: GraphNodeId::Entity(target_ref.id),
                        confidence: 0.95,
                        origin: RelationOrigin::Lsp,
                        created_in: None,
                        import_source: None,
                        // Every call SITE the owner makes, which is what a
                        // reader needs and what `reference_lines` publishes.
                        // The server answers with one range per call it saw,
                        // and taking only the head reported a caller that
                        // calls the target five times as calling it once.
                        evidence: query_positions_evidence(
                            crate::call_sites::CALL_HIERARCHY_RULE,
                            &positions,
                            ranges,
                        )?,
                    });
                }
            }
            // A declaration outside the workspace, in no file the graph could
            // hold a twin of: the call leaves the repository, which refutes
            // any in-repository guess at its site. An installed copy of a
            // module the workspace provides is the repository's own code
            // under another path and refutes nothing.
            None if index.outside_repository(target_uri) => {
                let outside = crate::call_sites::OutsideLocation {
                    uri: target_uri.clone(),
                    range: crate::call_sites::LocationRange::from(&call.to.selection_range),
                };
                for (owner, ranges) in by_owner {
                    for range in ranges {
                        calls.outside_sites.push(crate::call_sites::SiteAnswer {
                            source: owner.id,
                            site: positions.range(&range)?,
                            target: crate::call_sites::SiteTarget::Outside(outside.clone()),
                            rule: crate::call_sites::CALL_HIERARCHY_RULE,
                        });
                    }
                }
            }
            None => {
                debug!(
                    caller = %caller.name,
                    target = %call.to.name,
                    "LSP call target not found in graph"
                );
            }
        }
    }

    Ok(calls)
}

/// The entity a call hierarchy item names, given the entity `find_at`
/// placed its name in.
///
/// An item named on its entity's own declaration line is that entity. One
/// named elsewhere inside it names something that entity holds: a TypeScript
/// overload signature, which belongs to the implementation Kin keeps for the
/// function, or a declaration the graph has no entity for. Inside a module
/// surface, which declares no name, the latter is no call target at all:
/// axum's `get` is generated by `top_level_handler_fn!(get, GET)` at the top
/// of `method_routing.rs`, and its calls were recorded as calls of that
/// module, as typeorm's calls of the overloaded `@Column()` were recorded as
/// calls of `Column.ts`. Inside a named entity the item stays with that
/// entity, as it always has, since a decorated declaration's recorded line
/// can lie above its name.
fn call_target<'i>(
    index: &'i EntityIndex,
    found: &'i EntityRef,
    item: &CallHierarchyItem,
    documents: Option<DocumentProvider<'_>>,
) -> Option<&'i EntityRef> {
    if found.declares_name && item.selection_range.start.line == found.name_line {
        return Some(found);
    }
    if crate::file_enrichment::is_script_source(&found.file_path) {
        let signature = protocol::Location {
            uri: item.uri.clone(),
            range: item.selection_range.clone(),
        };
        let implementation = documents
            .and_then(|provider| provider(&found.file_path))
            .and_then(|text| {
                crate::file_enrichment::overload_implementation(index, found, &text, &signature)
            });
        if implementation.is_some() {
            return implementation;
        }
    }
    found.declares_name.then_some(found)
}

/// The entity that makes a call the server reported on `line` of `caller`.
///
/// The innermost entity holding that line, when its lines lie inside the
/// caller's and are fewer; otherwise the caller itself. Entities are placed by
/// line, so two declarations sharing the caller's lines cannot be told apart
/// and the site stays with the caller the server was asked about.
fn site_owner<'a>(
    index: &'a EntityIndex,
    uri: &str,
    caller: &'a EntityRef,
    line: u32,
) -> &'a EntityRef {
    match index.find_at(uri, line) {
        Some(owner)
            if owner.id != caller.id
                && owner.file_path == caller.file_path
                && owner.start_line >= caller.start_line
                && owner.end_line <= caller.end_line
                && owner.end_line - owner.start_line < caller.end_line - caller.start_line =>
        {
            owner
        }
        _ => caller,
    }
}

/// The prepared call hierarchy item that is the queried caller.
///
/// An item is the caller when it names the admitted file, its ranges are real
/// positions there with the selection inside the enclosing range (or outside
/// it only as a TypeScript binding initializer proven with `grammars`), and
/// its selection starts on a line where the caller is the innermost entity. A
/// lone item that is not the caller refuses the query.
///
/// A server can prepare several items at one position. Refusing every such
/// answer threw away the caller's calls even when one item was plainly the
/// caller, so the item that is the caller AND whose selection holds the
/// position that was asked is chosen, when exactly one is. An item in another
/// file is not the caller and is passed over. None, or more than one, is still
/// ambiguous and refused: choosing between them would be a guess.
#[allow(clippy::too_many_arguments)]
fn prepared_source<'a>(
    items: &'a [CallHierarchyItem],
    grammars: Option<&crate::typescript_call_hierarchy::TypeScriptGrammars>,
    caller: &EntityRef,
    index: &EntityIndex,
    positions: &crate::source_positions::SourcePositions<'_>,
    text: &str,
    workspace_root: &Path,
    asked: &Position,
) -> Result<&'a CallHierarchyItem> {
    let well_formed = |item: &CallHierarchyItem| -> Result<()> {
        let enclosing = positions.range(&item.range)?;
        let selection = positions.range(&item.selection_range)?;
        if (selection.start_byte < enclosing.start_byte || selection.end_byte > enclosing.end_byte)
            && !crate::typescript_call_hierarchy::proves_binding_initializer(
                grammars, caller, text, asked, &selection, &enclosing,
            )
        {
            return Err(LspError::Protocol(
                "prepared call hierarchy selection is outside its source range".into(),
            ));
        }
        Ok(())
    };
    let is_caller = |item: &CallHierarchyItem| {
        index
            .find_at(&item.uri, item.selection_range.start.line)
            .map(|e| e.id)
            == Some(caller.id)
    };
    if let [item] = items {
        require_source_uri(&item.uri, &caller.file_path, workspace_root)?;
        well_formed(item)?;
        if !is_caller(item) {
            return Err(LspError::Protocol(
                "prepared call hierarchy source is not the queried entity".into(),
            ));
        }
        return Ok(item);
    }
    let mut chosen = Vec::new();
    for item in items {
        if require_source_uri(&item.uri, &caller.file_path, workspace_root).is_err() {
            continue;
        }
        well_formed(item)?;
        if is_caller(item) && holds(&item.selection_range, asked) {
            chosen.push(item);
        }
    }
    match chosen.as_slice() {
        [item] => Ok(item),
        _ => Err(LspError::Protocol(
            "ambiguous prepared call hierarchy source".into(),
        )),
    }
}

/// Whether `position` lies in the half-open `range`.
fn holds(range: &protocol::Range, position: &Position) -> bool {
    let at = |p: &Position| (p.line, p.character);
    at(&range.start) <= at(position) && at(position) < at(&range.end)
}

/// Query type hierarchy supertypes for a method entity to detect Overrides relations.
/// If the method exists on a parent trait/type, emit an Overrides relation.
pub async fn enrich_entity_overrides(
    server: &LspServer,
    method: &EntityRef,
    index: &EntityIndex,
    workspace_root: &Path,
    documents: Option<DocumentProvider<'_>>,
) -> Result<Vec<Relation>> {
    if !server.has_type_hierarchy() {
        return Ok(Vec::new());
    }

    // Only query methods (names containing '.'), not standalone functions.
    if !method.name.contains('.') {
        return Ok(Vec::new());
    }

    let method_short_name = method.name.rsplit('.').next().unwrap_or(&method.name);

    let file_path = workspace_root.join(&method.file_path);
    let uri = protocol::path_to_uri(&file_path);

    let text = admitted_text(documents, &method.file_path)?;
    let positions = crate::source_positions::SourcePositions::new(&method.file_path, &text);
    let Some(request_position) = positions.name_position(method)? else {
        return Ok(Vec::new());
    };

    // Step 1: Prepare type hierarchy at the method's position.
    let prepare_result = server
        .client
        .request(
            "textDocument/prepareTypeHierarchy",
            TypeHierarchyPrepareParams {
                text_document: TextDocumentIdentifier { uri: uri.clone() },
                position: request_position,
            },
        )
        .await;

    let items: Vec<TypeHierarchyItem> = decode_optional_array(prepare_result?)?;

    if items.is_empty() {
        return Ok(Vec::new());
    }

    // Step 2: Query supertypes for the first item.
    let item = &items[0];
    let supertypes_result = server
        .client
        .request(
            "typeHierarchy/supertypes",
            TypeHierarchySupertypesParams { item: item.clone() },
        )
        .await;

    let supertypes: Vec<TypeHierarchyItem> = decode_optional_array(supertypes_result?)?;

    // Step 3: For each supertype, check if a method with the same name exists in the graph.
    let mut relations = Vec::new();
    for supertype in &supertypes {
        // Look for "SupertypeName.method_name" in the graph index.
        let candidate_name = format!("{}.{}", supertype.name, method_short_name);
        // Position only, for the same reason as the call mapping: a name match
        // here would pick some other class's method of the same name and stamp
        // it as a proven override.
        let _ = &candidate_name;
        let target = index.find_at(&supertype.uri, supertype.selection_range.start.line);

        if let Some(target_ref) = target {
            relations.push(Relation {
                id: deterministic_relation_id(RelationKind::Overrides, method.id, target_ref.id),
                kind: RelationKind::Overrides,
                src: GraphNodeId::Entity(method.id),
                dst: GraphNodeId::Entity(target_ref.id),
                confidence: 0.90,
                origin: RelationOrigin::Lsp,
                created_in: None,
                import_source: None,
                evidence: Vec::new(),
            });
            debug!(
                method = %method.name,
                overrides = %target_ref.name,
                "discovered Overrides relation"
            );
        }
    }

    Ok(relations)
}

/// The member expression an identifier position opens, when it opens one.
///
/// Returns the receiver text, the member's column, and the member's text for
/// `express.Router` asked at `express`. Returns `None` for a bare identifier,
/// for the member half of an expression (which is not itself a receiver), and
/// for a dot followed by anything that is not an identifier.
pub(crate) fn member_expression_at(line_text: &str, col: u32) -> Option<(String, u32, String)> {
    let chars: Vec<char> = line_text.chars().collect();
    let start = col as usize;
    if start >= chars.len() {
        return None;
    }
    // Both halves must START like an identifier rather than merely contain
    // identifier characters, so `1.5` is a number and not a member expression.
    // The caller only offers identifier starts today, but a predicate that
    // depends on its caller's filtering is one refactor from being wrong.
    if !(chars[start].is_alphabetic() || chars[start] == '_') {
        return None;
    }
    let mut end = start;
    while end < chars.len() && (chars[end].is_alphanumeric() || chars[end] == '_') {
        end += 1;
    }
    if chars.get(end) != Some(&'.') {
        return None;
    }
    let member_start = end + 1;
    if !chars
        .get(member_start)
        .is_some_and(|ch| ch.is_alphabetic() || *ch == '_')
    {
        return None;
    }
    let mut member_end = member_start;
    while member_end < chars.len()
        && (chars[member_end].is_alphanumeric() || chars[member_end] == '_')
    {
        member_end += 1;
    }
    Some((
        chars[start..end].iter().collect(),
        member_start as u32,
        chars[member_start..member_end].iter().collect(),
    ))
}

fn decode_optional_array<T: serde::de::DeserializeOwned>(
    value: serde_json::Value,
) -> Result<Vec<T>> {
    if value.is_null() {
        return Ok(Vec::new());
    }
    Ok(serde_json::from_value(value)?)
}

/// Decode the location and location-link shapes, preserving malformed replies
/// as errors instead of certifying them as empty answers.
pub(crate) fn decode_locations(value: serde_json::Value) -> Result<Vec<protocol::Location>> {
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct LocationLink {
        target_uri: String,
        target_selection_range: protocol::Range,
        #[serde(rename = "targetRange")]
        _target_range: protocol::Range,
    }
    #[derive(serde::Deserialize)]
    #[serde(untagged)]
    enum Answer {
        Locations(Vec<protocol::Location>),
        Location(protocol::Location),
        Links(Vec<LocationLink>),
    }
    if value.is_null() {
        return Ok(Vec::new());
    }
    Ok(match serde_json::from_value(value)? {
        Answer::Locations(locations) => locations,
        Answer::Location(location) => vec![location],
        Answer::Links(links) => links
            .into_iter()
            .map(|link| protocol::Location {
                uri: link.target_uri,
                range: link.target_selection_range,
            })
            .collect(),
    })
}

/// One location answer for a request at a position.
pub(crate) async fn locations_at(
    server: &LspServer,
    method: &'static str,
    uri: &str,
    line: u32,
    character: u32,
) -> Result<Vec<protocol::Location>> {
    if (method == "textDocument/definition" && !server.has_definition())
        || (method == "textDocument/typeDefinition" && !server.has_type_definition())
    {
        return Ok(Vec::new());
    }
    let value = server
        .client
        .request(
            method,
            protocol::TextDocumentPositionParams {
                text_document: TextDocumentIdentifier {
                    uri: uri.to_string(),
                },
                position: Position { line, character },
            },
        )
        .await?;
    decode_locations(value)
}

/// Whether this receiver names a module rather than a value in this file.
///
/// Measured on express with typescript-language-server: `express` in
/// `express.Router()` answers `definition` with `./index.js:10`, another file
/// entirely, because the server follows the require through to the module it
/// resolves. The value receivers on the same page stay home: `res` answers with
/// its own parameter at `api_v1.js:6` and `apiv1` with its declaration at
/// `api_v1.js:4`.
///
/// So the question "is this a module" is answered by where its definition
/// lives, and it is the server answering rather than this code guessing. A
/// receiver whose definition is a declaration in the file being enriched is a
/// value in that file; one whose definition is another file's module entry is a
/// reference to that module.
///
/// The file being enriched is the one whose repository path is exactly
/// `enriched_path`, read the way [`EntityIndex::repository_file`] reads a URI,
/// and a file outside the workspace is always another file. Compared by
/// suffix, any file whose path ended in `enriched_path` read as this one: in
/// cli/cli's root `api/client.go`, a receiver resolved into
/// `pkg/cmd/attestation/api/client.go`, or into a module cache path ending in
/// `api/client.go`, was taken for a value here and its member was never
/// joined. An answer that names no local file makes no module, as before.
pub(crate) fn receiver_names_a_module(
    definitions: &[protocol::Location],
    index: &EntityIndex,
    enriched_path: &str,
) -> bool {
    definitions.iter().any(|location| {
        protocol::uri_to_path(&location.uri).is_some()
            && index.repository_file(&location.uri).as_deref() != Some(enriched_path)
    })
}

/// A declined location request located nothing. Every other failure stays one.
fn declined_as_empty(answer: Result<Vec<protocol::Location>>) -> Result<Vec<protocol::Location>> {
    match answer {
        Err(error) if error.is_declined() => Ok(Vec::new()),
        other => other,
    }
}

/// The declarations a receiver names when the server resolved it to values of
/// that same name in other files, which makes it an imported value rather than
/// a module.
///
/// [`receiver_names_a_module`] reads every definition in another file as a
/// module. That holds for `express` in `express.Router()`, whose definition is
/// the module entry `./index.js:10` and maps to `createApplication`. It does not
/// hold for an imported value: Flask's `current_app.config[...]` resolves
/// `current_app` to its own declaration in `flask/globals.py`, and read as a
/// module it minted no edge, so no file that uses an imported constant as a
/// receiver was recorded as referencing it.
///
/// `Some` only when every answer is a non-empty range on an entity's
/// declaration line and that entity declares the receiver's own name. A module
/// answers with an empty range at the top of its file and a module surface
/// declares no name, so `flask` in `flask.Blueprint(...)`, and `settings` in
/// `settings.DEBUG` even where `settings.py` opens by declaring `settings`, stay
/// modules. An alias, an answer on an import line, an answer inside a body and
/// a differently named declaration on the same line all refuse.
pub(crate) fn receiver_declared_values<'a>(
    definitions: &[protocol::Location],
    index: &'a EntityIndex,
    receiver: &str,
) -> Option<Vec<&'a EntityRef>> {
    if definitions.is_empty() {
        return None;
    }
    definitions
        .iter()
        .map(|location| {
            let range = &location.range;
            let empty =
                (range.start.line, range.start.character) == (range.end.line, range.end.character);
            index
                .find_at(&location.uri, range.start.line)
                .filter(|entity| {
                    !empty
                        && entity.declares_name
                        && entity.name_line == range.start.line
                        && entity.name.rsplit('.').next() == Some(receiver)
                })
        })
        .collect()
}

/// Whether `path` is Python source, whose entities carry their exact
/// declaration line: a decorated definition records it below its decorators.
pub(crate) fn is_python_source(path: &str) -> bool {
    path.ends_with(".py") || path.ends_with(".pyi")
}

/// Whether an answer at `range`, which `find_at` placed in `dst`, names `dst`
/// itself.
///
/// Only Python destinations are read this way, because pyright's answers have
/// two shapes that make it decidable. A named declaration answers with its name
/// token, on the line the entity records as declaring that name. A module
/// answers with an empty range at the top of its file.
///
/// So an answer on another line of `dst`'s span names something declared
/// inside it: pyright answers `_static_folder` with the class attribute and
/// with `self._static_folder = value` inside a property setter, and the second
/// answer made the attribute's own line read as a reference to the setter. And
/// an empty answer names a module, which `find_at` turns into whatever the
/// file's first line declares, so `from .globals import current_app` read as a
/// reference to the class `globals.py` opens with. A module surface declares
/// no name, and it is the only entity such an answer can name.
pub(crate) fn answer_names_entity(dst: &EntityRef, range: &protocol::Range) -> bool {
    if !is_python_source(&dst.file_path) {
        return true;
    }
    let empty = (range.start.line, range.start.character) == (range.end.line, range.end.character);
    if empty {
        return !dst.declares_name;
    }
    range.start.line == dst.name_line
}

/// Whether two answers name the same place.
fn same_location(left: &protocol::Location, right: &protocol::Location) -> bool {
    left.uri == right.uri && left.range.start.line == right.range.start.line
}

/// Graph-owned text for a repository-relative path, supplied by the caller.
///
/// The join below has to ask the server about a token in a file OTHER than the
/// one being enriched, and a language server answers only about documents it
/// has been handed. The daemon opens exactly the file it is enriching, so that
/// second document does not exist as far as the server is concerned and every
/// query against it comes back empty.
///
/// Reading the second file off disk here would answer the question and break
/// the rule that matters more: after graph truth exists, a runtime query path
/// does not get its answer from raw filesystem contents. So the content arrives
/// from the caller, which holds repository authority: the daemon passes its
/// graph/CAS source view, exactly the bytes it already opens the enriched file
/// with. A caller that supplies no provider, or a provider that has nothing for
/// a path, leaves the join declining precisely as it does today.
pub type DocumentProvider<'a> = &'a (dyn Fn(&str) -> Option<String> + Send + Sync);

/// The LSP language id for a path, by extension.
///
/// `None` means this code cannot name the language, and the caller declines
/// rather than opening the document under a guess: a document opened as the
/// wrong language answers nothing, which is indistinguishable at the call site
/// from a document that was never opened, and only one of those is honest.
fn lsp_language_id(path: &str) -> Option<&'static str> {
    let extension = path.rsplit_once('.').map(|(_, ext)| ext)?;
    Some(match extension {
        "js" | "mjs" | "cjs" => "javascript",
        "jsx" => "javascriptreact",
        "ts" | "mts" | "cts" => "typescript",
        "tsx" => "typescriptreact",
        "py" | "pyi" => "python",
        "rs" => "rust",
        "go" => "go",
        "java" => "java",
        "c" | "h" => "c",
        "cc" | "cpp" | "cxx" | "hpp" | "hh" => "cpp",
        "rb" => "ruby",
        "php" => "php",
        "swift" => "swift",
        "kt" | "kts" => "kotlin",
        "cs" => "csharp",
        _ => return None,
    })
}

/// Documents this pass handed to the server itself, closed when it is done.
///
/// Scoped to one entity's enrichment. Opening is lazy and each path is opened
/// at most once, because the join reaches the same module file for every
/// candidate export it considers and a per-candidate open would be both slower
/// and a lifecycle the server has no reason to expect.
///
/// The file being enriched is never opened here. Its caller already holds that
/// document open, and re-opening a live document is a change notification this
/// pass has no business sending.
pub(crate) struct ScopedDocuments<'a> {
    server: &'a LspServer,
    provider: Option<DocumentProvider<'a>>,
    open: std::collections::HashSet<String>,
    texts: std::collections::HashMap<String, String>,
}

impl<'a> ScopedDocuments<'a> {
    pub(crate) fn new(server: &'a LspServer, provider: Option<DocumentProvider<'a>>) -> Self {
        Self {
            server,
            provider,
            open: std::collections::HashSet::new(),
            texts: std::collections::HashMap::new(),
        }
    }

    pub(crate) fn remember(&mut self, file: &str, text: &str) {
        self.texts.insert(file.to_owned(), text.to_owned());
    }

    fn text(&self, file: &str) -> Result<&str> {
        self.texts
            .get(file)
            .map(String::as_str)
            .ok_or_else(|| LspError::Protocol(format!("captured LSP document unavailable: {file}")))
    }

    /// Hand `rel_path` to the server if it is not already open, and report
    /// whether the server now holds it.
    pub(crate) async fn ensure_open(&mut self, rel_path: &str, uri: &str) -> Result<bool> {
        if self.open.contains(uri) {
            return Ok(true);
        }
        let Some(provider) = self.provider else {
            debug!(
                path = %rel_path,
                "declined a cross-file query: no document provider was supplied"
            );
            return Ok(false);
        };
        let Some(language_id) = lsp_language_id(rel_path) else {
            debug!(path = %rel_path, "declined a cross-file query: unknown language for this path");
            return Ok(false);
        };
        let Some(text) = provider(rel_path) else {
            debug!(
                path = %rel_path,
                "declined a cross-file query: repository authority has no text for this path"
            );
            return Ok(false);
        };
        self.texts.insert(rel_path.to_owned(), text.clone());
        // Ownership precedes the notification await: the frame can reach the
        // server even when its caller is cancelled before the write ack.
        self.open.insert(uri.to_string());
        let notified = self
            .server
            .client
            .notify(
                "textDocument/didOpen",
                serde_json::json!({
                    "textDocument": {
                        "uri": uri,
                        "languageId": language_id,
                        "version": 1,
                        "text": text,
                    }
                }),
            )
            .await;
        if let Err(error) = notified {
            debug!(path = %rel_path, error = %error, "failed to open a document for a cross-file query");
            return Err(error);
        }
        debug!(path = %rel_path, "opened a graph-owned document for a cross-file query");
        Ok(true)
    }

    /// Queue all closes before the first suspension, preserving cleanup if the
    /// caller is cancelled while waiting for their write acknowledgment.
    pub(crate) async fn close_all(&mut self) -> Result<()> {
        if self.open.is_empty() {
            return Ok(());
        }
        let done = self
            .server
            .client
            .close_documents(self.open.drain().collect())?;
        done.await.map_err(|_| LspError::ServerDied)?
    }
}

impl Drop for ScopedDocuments<'_> {
    fn drop(&mut self) {
        if !self.open.is_empty() {
            let _ = self
                .server
                .client
                .close_documents(self.open.drain().collect());
        }
    }
}

/// Whether the server proved the candidate export resolves where the member
/// resolves.
///
/// `any` over `any`, and the emptiness behavior is the point rather than an
/// accident: an un-opened document answers with NO locations, and an unproven
/// candidate must not bind, so empty on either side has to be false. Written
/// with `all` instead, empty would be vacuously true and every same-named
/// export in the module file would bind on its name alone, which is the
/// fallback this crate deleted.
fn candidate_is_proven(
    candidate_definitions: &[protocol::Location],
    member_definitions: &[protocol::Location],
) -> bool {
    candidate_definitions.iter().any(|proven| {
        member_definitions
            .iter()
            .any(|member| same_location(proven, member))
    })
}

/// The in-tree exports a member expression on a module receiver binds to.
///
/// This is the equivalence join, and the reason it is not the bare-name
/// fallback this crate deleted. The server proves where the MEMBER resolves;
/// it proves separately where a candidate export's OWN token resolves. Binding
/// requires those two answers to name the same place, so a same-named export of
/// something else does not qualify: on express, `Router` and `exports.Router`
/// both resolve to `node_modules/router/index.js:51` and join, while
/// `exports.Route` resolves to `router/lib/route.js`, a different file, and is
/// refused. Nothing is ever matched on the name alone.
///
/// The export's own token lives in the module file, which is not the file being
/// enriched, and a server answers only about documents it holds. The caller
/// opens the enriched file and nothing else, so `documents` is what makes the
/// second leg answerable at all; without it every candidate declines rather
/// than binding.
///
/// Both enrichment arms call this. They differ only in the relation kind they
/// mint from the result, never in what they are willing to believe.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn member_export_bindings<'a>(
    server: &LspServer,
    index: &'a EntityIndex,
    workspace_root: &Path,
    documents: &mut ScopedDocuments<'_>,
    enriched_file: &str,
    uri: &str,
    line: u32,
    receiver_col: u32,
    member_col: u32,
    member_name: &str,
) -> Result<MemberBindings<'a>> {
    // A declined answer on any leg proves no binding, so it binds nothing
    // rather than failing the caller's whole pass. gopls declines
    // typeDefinition at a package-level value of an unnamed struct type, and
    // failing there cost every definition edge of the file asking.
    let module_locations = declined_as_empty(
        locations_at(
            server,
            "textDocument/typeDefinition",
            uri,
            line,
            receiver_col,
        )
        .await,
    )?;
    let member_definitions = declined_as_empty(
        locations_at(server, "textDocument/definition", uri, line, member_col).await,
    )?;
    let mut bound: Vec<&EntityRef> = Vec::new();
    let mut unasked = 0usize;

    for module_location in &module_locations {
        // A module outside the workspace holds no candidate, however its
        // path ends.
        let Some(module_file) = index.repository_file(&module_location.uri) else {
            continue;
        };
        for candidate in index.entities_in_file(&module_file) {
            if candidate.name != member_name {
                continue;
            }
            let candidate_uri = protocol::path_to_uri(&workspace_root.join(&candidate.file_path));
            if candidate.file_path != enriched_file
                && !documents
                    .ensure_open(&candidate.file_path, &candidate_uri)
                    .await?
            {
                continue;
            }
            let candidate_text = documents.text(&candidate.file_path)?;
            let candidate_positions =
                crate::source_positions::SourcePositions::new(&candidate.file_path, candidate_text);
            let candidate_position = match candidate_positions.name_position(candidate) {
                Ok(Some(position)) => position,
                Ok(None) => continue,
                // The candidate's declaration line does not spell its name, so
                // its token cannot be asked about. That leaves this one join
                // unfinished, not the file that asked for it.
                Err(error) => {
                    unasked += 1;
                    debug!(
                        candidate = %candidate.name,
                        %error,
                        "a member join could not ask about a candidate export"
                    );
                    continue;
                }
            };
            let candidate_definitions = declined_as_empty(
                locations_at(
                    server,
                    "textDocument/definition",
                    &candidate_uri,
                    candidate_position.line,
                    candidate_position.character,
                )
                .await,
            )?;
            if !candidate_is_proven(&candidate_definitions, &member_definitions) {
                continue;
            }
            if bound.iter().any(|already| already.id == candidate.id) {
                continue;
            }
            bound.push(candidate);
        }
    }
    Ok(MemberBindings { bound, unasked })
}

/// What a member join proved, and what it could not ask.
pub(crate) struct MemberBindings<'a> {
    /// The in-tree exports the member binds to.
    pub(crate) bound: Vec<&'a EntityRef>,
    /// Same-named candidate exports whose own name could not be located, so
    /// the join could not ask about them. Nonzero means the join did not
    /// finish, and a caller that reports completeness has to count it.
    pub(crate) unasked: usize,
}

/// Query type definitions for entities referenced in a function's signature/body.
/// For each resolved type, find it in the graph index and emit UsesType relations.
///
/// `documents` supplies graph-owned text for the primary file and any
/// cross-file join. Missing primary text is an explicit source gap; projected
/// filesystem content never supplies the identifier positions for this pass.
pub async fn enrich_entity_uses_type(
    server: &LspServer,
    entity: &EntityRef,
    index: &EntityIndex,
    workspace_root: &Path,
    documents: Option<DocumentProvider<'_>>,
) -> Result<Vec<Relation>> {
    if !server.has_type_definition() {
        return Ok(Vec::new());
    }

    let file_path = workspace_root.join(&entity.file_path);
    let uri = protocol::path_to_uri(&file_path);
    let file_content = documents
        .and_then(|provider| provider(&entity.file_path))
        .ok_or_else(|| {
            LspError::Protocol(format!(
                "repository source unavailable for UsesType: {}",
                entity.file_path
            ))
        })?;
    let positions = crate::source_positions::SourcePositions::new(&entity.file_path, &file_content);
    let lines: Vec<&str> = file_content.lines().collect();

    // Sample positions within the entity's span to discover type usages.
    // We query real identifier starts within the entity span to catch parameter
    // types, return types, and type references in the body.
    let mut relations = Vec::new();
    let mut seen_targets = std::collections::HashSet::new();
    let mut scoped_documents = ScopedDocuments::new(server, documents);
    scoped_documents.remember(&entity.file_path, &file_content);

    let result = async {
        for line in entity.start_line..=entity.end_line {
            let Some(line_text) = lines.get(line as usize) else {
                continue;
            };
            // A module surface declares no name and spans its whole file, so
            // every line a declaration inside it owns would be asked about twice
            // and the module credited with its members' types. It asks about its
            // own top-level lines only.
            if !entity.declares_name
                && index.find_at(&uri, line).map(|owner| owner.id) != Some(entity.id)
            {
                continue;
            }

            for col in identifier_positions_in_line(line_text) {
                // A member expression on a MODULE receiver is answered by its
                // member, never by the receiver. `express.Router()` asked at
                // `express` returns the module's own type, `lib/express.js:35`,
                // which `find_at` reads as `createApplication`, so every file that
                // so much as names `express` was recorded as using that one
                // function: 50 inbound edges on express's default export and zero
                // on `Router`, which has 32 real reference sites.
                //
                // Value receivers are untouched. `res` in `res.send(...)` genuinely
                // tells the enclosing function it uses the Response type, and that
                // edge is not this pass's mistake.
                if let Some((_receiver, member_col, member_name)) =
                    member_expression_at(line_text, col)
                {
                    let receiver_definitions = match locations_at(
                        server,
                        "textDocument/definition",
                        &uri,
                        line,
                        positions.scalar_position(line, col)?.character,
                    )
                    .await
                    {
                        Ok(locations) => locations,
                        // Declined at this position: nothing here, next one.
                        Err(error) if error.is_declined() => continue,
                        Err(error) => return Err(error),
                    };
                    if receiver_names_a_module(&receiver_definitions, index, &entity.file_path) {
                        let bindings = member_export_bindings(
                            server,
                            index,
                            workspace_root,
                            &mut scoped_documents,
                            &entity.file_path,
                            &uri,
                            line,
                            positions.scalar_position(line, col)?.character,
                            positions.scalar_position(line, member_col)?.character,
                            &member_name,
                        )
                        .await?;
                        // This arm reports no partial answer, so a join it
                        // could not finish is the entity's failure, as it
                        // was when the unlocated name ended the join.
                        if bindings.unasked > 0 {
                            return Err(LspError::Protocol(format!(
                                "`{member_name}` has {} candidate export(s) whose name could not \
                                 be located to ask about",
                                bindings.unasked
                            )));
                        }
                        for candidate in bindings.bound {
                            if candidate.id == entity.id || !seen_targets.insert(candidate.id) {
                                continue;
                            }
                            relations.push(Relation {
                                id: deterministic_relation_id(
                                    RelationKind::UsesType,
                                    entity.id,
                                    candidate.id,
                                ),
                                kind: RelationKind::UsesType,
                                src: GraphNodeId::Entity(entity.id),
                                dst: GraphNodeId::Entity(candidate.id),
                                confidence: 0.85,
                                origin: RelationOrigin::Lsp,
                                created_in: None,
                                import_source: None,
                                evidence: query_position_evidence(
                                    "lsp_member_on_module",
                                    positions.token(line, member_col)?,
                                ),
                            });
                            debug!(
                                entity = %entity.name,
                                member = %member_name,
                                uses_type = %candidate.name,
                                "bound a member on a module receiver to its export"
                            );
                        }
                        // The receiver's own type is not this entity's fact, whether
                        // or not the member bound to anything. Declining here is
                        // what makes the inflated attribution stop.
                        continue;
                    }
                }

                let type_def_result = server
                    .client
                    .request(
                        "textDocument/typeDefinition",
                        protocol::TextDocumentPositionParams {
                            text_document: TextDocumentIdentifier { uri: uri.clone() },
                            position: positions.scalar_position(line, col)?,
                        },
                    )
                    .await;

                // A declined position has no type to find, and says nothing about
                // the next one. Stopping here, as this arm used to, ended every Go
                // entity's pass at its `func` keyword.
                let locations = match type_def_result {
                    Ok(value) => decode_locations(value)?,
                    Err(error) if error.is_declined() => continue,
                    Err(error) => return Err(error),
                };

                for loc in &locations {
                    let target_line = loc.range.start.line;
                    // Position only. The old fallback took the FILE STEM and looked
                    // that up by name, so a reference in `sessions.py` could be
                    // attributed to whatever entity happened to be called
                    // `sessions`, which is a guess wearing a proven label.
                    let target = index.find_at(&loc.uri, target_line);

                    if let Some(target_ref) = target {
                        // The definitions pass reads a Python answer the same
                        // way: one inside a body, or an empty one naming a
                        // module, is not about the entity it landed in.
                        if !answer_names_entity(target_ref, &loc.range) {
                            continue;
                        }
                        // Skip self-references and duplicates.
                        if target_ref.id == entity.id || !seen_targets.insert(target_ref.id) {
                            continue;
                        }

                        relations.push(Relation {
                            id: deterministic_relation_id(
                                RelationKind::UsesType,
                                entity.id,
                                target_ref.id,
                            ),
                            kind: RelationKind::UsesType,
                            src: GraphNodeId::Entity(entity.id),
                            dst: GraphNodeId::Entity(target_ref.id),
                            confidence: 0.85,
                            origin: RelationOrigin::Lsp,
                            created_in: None,
                            import_source: None,
                            // The queried caller token, not the returned definition
                            // range in the target's document.
                            evidence: query_position_evidence(
                                "lsp_references",
                                positions.token(line, col)?,
                            ),
                        });
                        debug!(
                            entity = %entity.name,
                            uses_type = %target_ref.name,
                            "discovered UsesType relation"
                        );
                    }
                }
            }
        }

        Ok(relations)
    }
    .await;
    let closed = scoped_documents.close_all().await;
    match result {
        Ok(relations) => {
            closed?;
            Ok(relations)
        }
        Err(error) => Err(error),
    }
}

/// Whether `path` is Go source, whose language server widens a method's
/// references to the methods related to it through interface satisfaction.
pub fn is_go_source(path: &str) -> bool {
    path.ends_with(".go")
}

/// Whether a Go declaration line declares a method with a receiver,
/// `func (r T) Name(`, rather than an interface's method spec, `Name(`.
fn declares_a_receiver(line: &str) -> bool {
    line.trim_start()
        .strip_prefix("func")
        .is_some_and(|rest| rest.trim_start().starts_with('('))
}

/// Whether the server's `references` answer for `entity` can hold sites that
/// resolve to some other declaration, so that each site has to be proven
/// before it is recorded as a reference to `entity`.
///
/// gopls widens a method's references by design. Its documentation says "the
/// references to a method of a concrete type include references to
/// corresponding interface methods", and an interface method's include those
/// of the concrete methods that implement it. Those sites are real uses of a
/// related method, and not one of them is resolved to `entity` by the Go type
/// checker: `repo.RepoOwner()` on a `ghrepo.Interface` value is a call of the
/// interface method, whatever the value holds at run time.
///
/// An interface method spec is always proven, because its answer is also
/// widened by the methods of related interfaces, which `implementation` does
/// not name. A concrete method's answer is widened only by the interface
/// methods it corresponds to, and those are exactly what gopls answers
/// `textDocument/implementation` with there. When that answer is empty the
/// references answer is the method's own and stands as given, which keeps a
/// method nothing dispatches to, like a test registry's `Register` with 1,484
/// call sites on the gh CLI, from paying one definition query per site.
async fn references_may_name_related_methods(
    server: &LspServer,
    entity: &EntityRef,
    positions: &crate::source_positions::SourcePositions<'_>,
    uri: &str,
    request_position: &Position,
) -> Result<bool> {
    if entity.kind != kin_model::EntityKind::Method || !is_go_source(&entity.file_path) {
        return Ok(false);
    }
    if !declares_a_receiver(positions.line_text(entity.name_line)?) {
        return Ok(true);
    }
    if !server.has_implementation() {
        return Ok(true);
    }
    let answer = server
        .client
        .request(
            "textDocument/implementation",
            protocol::TextDocumentPositionParams {
                text_document: TextDocumentIdentifier {
                    uri: uri.to_string(),
                },
                position: request_position.clone(),
            },
        )
        .await;
    match answer {
        Ok(value) => Ok(!decode_locations(value)?.is_empty()),
        // A server that can answer nothing more ends the arm. Any other
        // failure leaves the widening unknown, so every site is proven.
        Err(error) if error.ends_the_session() => Err(error),
        Err(_) => Ok(true),
    }
}

/// Whether the server resolves the reference at `site` to `entity` itself:
/// its definition there lands in `entity`'s own declaration.
///
/// The site is asked at the position the server reported it at, so the
/// question and the answer being proven share one view of the document. A
/// definition of a site in a method's references answer is a method's name,
/// and no other method is declared inside one, so the innermost entity it
/// lands in is the method it resolves to. A declined or empty definition
/// proves nothing, and the site is not recorded.
async fn site_resolves_to(
    server: &LspServer,
    site: &protocol::Location,
    entity: &EntityRef,
    index: &EntityIndex,
) -> Result<bool> {
    let definitions = declined_as_empty(
        locations_at(
            server,
            "textDocument/definition",
            &site.uri,
            site.range.start.line,
            site.range.start.character,
        )
        .await,
    )?;
    Ok(definitions.iter().any(|definition| {
        index
            .find_at(&definition.uri, definition.range.start.line)
            .map(|found| found.id)
            == Some(entity.id)
    }))
}

/// Query textDocument/references for an entity to find all references to it.
/// Returns References relations from the referencing entity to this entity.
///
/// A site is recorded only when it resolves to `entity`. A server that widens
/// its answer past that, as gopls does for a method (see
/// [`references_may_name_related_methods`]), has each site proven by its
/// definition first. Recording the widened answer as it came made every call
/// through an interface a confirmed caller of each concrete method behind it:
/// on the gh CLI, `Repository.RepoOwner` went from 4 confirmed call sites to
/// 137, and the 133 added were `RepoOwner()` calls on a `ghrepo.Interface`
/// value. Those callers belong to the interface method, where the dispatch
/// candidates of a concrete method are read from.
pub async fn enrich_entity_references(
    server: &LspServer,
    entity: &EntityRef,
    index: &EntityIndex,
    workspace_root: &Path,
    documents: Option<DocumentProvider<'_>>,
) -> Result<Vec<Relation>> {
    if !server.has_references() {
        return Ok(Vec::new());
    }

    let file_path = workspace_root.join(&entity.file_path);
    let uri = protocol::path_to_uri(&file_path);

    let text = admitted_text(documents, &entity.file_path)?;
    let positions = crate::source_positions::SourcePositions::new(&entity.file_path, &text);
    let Some(request_position) = positions.name_position(entity)? else {
        return Ok(Vec::new());
    };

    // Query references at the entity's name position.
    let result = server
        .client
        .request(
            "textDocument/references",
            serde_json::json!({
                "textDocument": { "uri": uri },
                "position": request_position,
                "context": { "includeDeclaration": false }
            }),
        )
        .await;

    let locations: Vec<protocol::Location> = decode_optional_array(result?)?;

    // Validate every returned in-root occurrence before entity/self filtering:
    // an invalid start line must not disappear as a successful empty answer.
    // Group by exact path so each captured source and line index is loaded once.
    let mut by_file: std::collections::BTreeMap<String, Vec<&protocol::Location>> =
        Default::default();
    for location in &locations {
        let mapped = index.find_at(&location.uri, location.range.start.line);
        let Some(path) = protocol::uri_to_path(&location.uri) else {
            if mapped.is_some() {
                return Err(LspError::Protocol("invalid local reference URI".into()));
            }
            continue;
        };
        let Ok(relative) = path.strip_prefix(workspace_root) else {
            if mapped.is_some()
                || index.admitted_source_outside(&location.uri, location.range.start.line)
            {
                return Err(LspError::Protocol(
                    "foreign reference URI matched a local source".into(),
                ));
            }
            continue; // External source is outside the admitted inventory.
        };
        if relative
            .components()
            .any(|part| !matches!(part, std::path::Component::Normal(_)))
        {
            return Err(LspError::Protocol(
                "noncanonical local reference path".into(),
            ));
        }
        let file = relative
            .to_str()
            .ok_or_else(|| LspError::Protocol("non-UTF8 local reference path".into()))?;
        require_source_uri(&location.uri, file, workspace_root)?;
        by_file.entry(file.to_owned()).or_default().push(location);
    }
    // Decided once, and only for an answer holding a site that would become
    // evidence, so an entity nothing references asks nothing more.
    let mut proven_sites_only: Option<bool> = None;
    let rule = references_evidence_rule(entity);
    let mut relations = Vec::new();
    for (file, locations) in by_file {
        let text = if file == entity.file_path {
            text.clone()
        } else {
            admitted_text(documents, &file)?
        };
        let site_positions = crate::source_positions::SourcePositions::new(&file, &text);
        let mut by_entity: std::collections::BTreeMap<EntityId, Vec<protocol::Range>> =
            Default::default();
        for location in locations {
            site_positions.range(&location.range)?;
            let Some(referencing) = index.find_at(&location.uri, location.range.start.line) else {
                continue;
            };
            require_source_uri(&location.uri, &referencing.file_path, workspace_root)?;
            if referencing.id == entity.id {
                continue;
            }
            let prove = match proven_sites_only {
                Some(prove) => prove,
                None => {
                    let prove = references_may_name_related_methods(
                        server,
                        entity,
                        &positions,
                        &uri,
                        &request_position,
                    )
                    .await?;
                    *proven_sites_only.insert(prove)
                }
            };
            if prove && !site_resolves_to(server, location, entity, index).await? {
                continue;
            }
            by_entity
                .entry(referencing.id)
                .or_default()
                .push(location.range.clone());
        }
        for (source, ranges) in by_entity {
            relations.push(Relation {
                id: deterministic_relation_id(RelationKind::References, source, entity.id),
                kind: RelationKind::References,
                src: GraphNodeId::Entity(source),
                dst: GraphNodeId::Entity(entity.id),
                confidence: 0.95,
                origin: RelationOrigin::Lsp,
                created_in: None,
                import_source: None,
                evidence: query_positions_evidence(rule, &site_positions, ranges)?,
            });
        }
    }

    Ok(relations)
}

/// The evidence rule `entity`'s reference sites are recorded under.
///
/// A Go method's sites are proven one by one before any is recorded, and builds
/// that recorded gopls's widened answer as it came wrote the same edges under
/// [`kin_model::LSP_REFERENCES_RULE`]. Those records are still in the stores
/// such builds enriched, so the proven sites carry a rule of their own, which is
/// what lets a reader tell the two apart and a re-derivation replace the old.
fn references_evidence_rule(entity: &EntityRef) -> &'static str {
    if entity.kind == kin_model::EntityKind::Method && is_go_source(&entity.file_path) {
        kin_model::LSP_PROVEN_METHOD_REFERENCES_RULE
    } else {
        kin_model::LSP_REFERENCES_RULE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn range(start_line: u32, start_col: u32) -> protocol::Range {
        protocol::Range {
            start: protocol::Position {
                line: start_line,
                character: start_col,
            },
            end: protocol::Position {
                line: start_line,
                character: start_col + 1,
            },
        }
    }

    /// Every distinct position a server answered with becomes one evidence
    /// record under the caller's own file.
    ///
    /// The reference arm built its edges with no evidence at all while holding
    /// these ranges, so an edge a language server proved arrived with no
    /// reference site and every consuming surface reported it as having no
    /// evidence span.
    #[test]
    fn every_reported_position_becomes_one_site() {
        let text = "                    \n".repeat(100);
        let source = crate::source_positions::SourcePositions::new("pkg/caller.go", &text);
        let evidence =
            query_positions_evidence("lsp_references", &source, [range(4, 8), range(9, 2)])
                .unwrap();
        let spans: Vec<(String, u32, u32)> = evidence
            .iter()
            .map(|record| {
                let span = record.source_span.as_ref().expect("a site carries a span");
                (span.file.0.clone(), span.start_line, span.start_col)
            })
            .collect();
        assert_eq!(
            spans,
            vec![
                ("pkg/caller.go".to_string(), 4, 8),
                ("pkg/caller.go".to_string(), 9, 2),
            ]
        );
    }

    /// One position answered twice is one site, so a server that repeats itself
    /// cannot inflate an edge's site count.
    #[test]
    fn a_repeated_position_is_one_site() {
        let text = "                    \n".repeat(100);
        let source = crate::source_positions::SourcePositions::new("pkg/caller.go", &text);
        let evidence =
            query_positions_evidence("lsp_references", &source, [range(4, 8), range(4, 8)])
                .unwrap();
        assert_eq!(evidence.len(), 1);
    }

    /// The per-edge ceiling holds, which is what lets the surfaces keep calling
    /// an enrichment edge's site list a floor rather than a total, and it keeps
    /// the earliest sites in the file whatever order the server named them in.
    #[test]
    fn the_site_list_stops_at_the_per_edge_ceiling() {
        let ranges: Vec<protocol::Range> = (0..(MAX_SITES_PER_EDGE as u32 + 10))
            .rev()
            .map(|line| range(line, 0))
            .collect();
        let text = "                    \n".repeat(100);
        let source = crate::source_positions::SourcePositions::new("pkg/caller.go", &text);
        let evidence = query_positions_evidence("lsp_references", &source, ranges).unwrap();
        assert_eq!(evidence.len(), MAX_SITES_PER_EDGE);
        let lines: Vec<u32> = evidence
            .iter()
            .map(|record| record.source_span.as_ref().expect("a site").start_line)
            .collect();
        assert_eq!(lines, (0..MAX_SITES_PER_EDGE as u32).collect::<Vec<_>>());
    }

    /// The record is a function of the positions, not of the order they arrived
    /// in, so two servers that answer the same sites in different orders store
    /// the same edge.
    #[test]
    fn the_site_list_does_not_depend_on_arrival_order() {
        let text = "                    \n".repeat(100);
        let source = crate::source_positions::SourcePositions::new("pkg/caller.go", &text);
        let forward =
            query_positions_evidence("lsp_references", &source, [range(4, 8), range(9, 2)]);
        let backward =
            query_positions_evidence("lsp_references", &source, [range(9, 2), range(4, 8)]);
        assert_eq!(forward.unwrap(), backward.unwrap());
    }

    #[test]
    fn entity_index_finds_by_position() {
        let entities = vec![
            EntityRef {
                id: EntityId::new(),
                name: "foo".to_string(),
                file_path: "src/lib.rs".to_string(),
                start_line: 10,
                start_col: 0,
                end_line: 20,
                name_line: 10,
                name_col: 3,
                declares_name: true,
                kind: kin_model::EntityKind::Function,
            },
            EntityRef {
                id: EntityId::new(),
                name: "bar".to_string(),
                file_path: "src/lib.rs".to_string(),
                start_line: 25,
                start_col: 0,
                end_line: 35,
                name_line: 25,
                name_col: 3,
                declares_name: true,
                kind: kin_model::EntityKind::Function,
            },
        ];
        let index = EntityIndex::new(entities, Path::new("/project"));

        let found = index.find_at("file:///project/src/lib.rs", 15);
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "foo");

        let found = index.find_at("file:///project/src/lib.rs", 30);
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "bar");

        // Outside any entity
        let found = index.find_at("file:///project/src/lib.rs", 22);
        assert!(found.is_none());
    }

    #[test]
    fn entity_index_finds_by_name() {
        let entities = vec![EntityRef {
            id: EntityId::new(),
            name: "Config.new".to_string(),
            file_path: "src/config.rs".to_string(),
            start_line: 5,
            start_col: 0,
            end_line: 10,
            name_line: 5,
            name_col: 7,
            declares_name: true,
            kind: kin_model::EntityKind::Function,
        }];
        let index = EntityIndex::new(entities, Path::new("/project"));

        assert!(index.find_by_name("Config.new").is_some());
        assert!(index.find_by_name("new").is_some()); // suffix match
        assert!(index.find_by_name("nonexistent").is_none());
    }

    #[test]
    fn deterministic_relation_ids_are_stable_for_same_edge() {
        let src = EntityId::new();
        let dst = EntityId::new();
        let first = deterministic_relation_id(RelationKind::Calls, src, dst);
        let second = deterministic_relation_id(RelationKind::Calls, src, dst);
        let different = deterministic_relation_id(RelationKind::References, src, dst);

        assert_eq!(first, second);
        assert_ne!(first, different);
    }
}

#[cfg(test)]
mod innermost_span_tests {
    use super::*;

    fn at(name: &str, start: u32, end: u32) -> EntityRef {
        EntityRef {
            id: EntityId::new(),
            name: name.to_string(),
            file_path: "src/requests/adapters.py".to_string(),
            start_line: start,
            start_col: 0,
            end_line: end,
            name_line: start,
            name_col: 4,
            declares_name: true,
            kind: kin_model::EntityKind::Function,
        }
    }

    /// The requests shape, in the order the index actually holds it: the module
    /// spans the whole file and sorts first, the class sits inside it, and the
    /// method inside that.
    fn adapters_file() -> EntityIndex {
        EntityIndex::new(
            vec![
                at("adapters", 0, 400),
                at("BaseAdapter", 121, 155),
                at("BaseAdapter.send", 127, 140),
                at("HTTPAdapter", 157, 399),
                at("HTTPAdapter.send", 633, 700),
            ],
            Path::new("/repo"),
        )
    }

    /// The defect, as a test. A position inside a method must resolve to the
    /// METHOD, not to the class or the module that contain it.
    ///
    /// Returning the first containing span returned the module for every
    /// position in the file, which made same-file targets equal their own source
    /// and be dropped as self-loops (954 of them in one file of the requests
    /// corpus) and made cross-file targets resolve to the target file's module,
    /// so the whole definitions pass emitted only module-to-module edges.
    #[test]
    fn a_position_inside_a_method_resolves_to_the_method() {
        let index = adapters_file();
        let found = index
            .find_at("file:///repo/src/requests/adapters.py", 127)
            .expect("line 127 is inside BaseAdapter.send");
        assert_eq!(
            found.name, "BaseAdapter.send",
            "the innermost containing span wins; got the enclosing scope instead"
        );
    }

    /// The other rungs, so this is a rule about nesting rather than one lucky
    /// case: inside the class but outside any method resolves to the class, and
    /// outside every class resolves to the module.
    #[test]
    fn nesting_resolves_rung_by_rung() {
        let index = adapters_file();
        let uri = "file:///repo/src/requests/adapters.py";
        assert_eq!(
            index.find_at(uri, 150).map(|e| e.name.as_str()),
            Some("BaseAdapter"),
            "inside the class, outside its methods"
        );
        assert_eq!(
            index.find_at(uri, 10).map(|e| e.name.as_str()),
            Some("adapters"),
            "outside every class, the module is the innermost thing there is"
        );
        assert_eq!(
            index.find_at(uri, 500).map(|e| e.name.as_str()),
            None,
            "past the end of the file nothing contains the line"
        );
    }

    /// Line bases: LSP positions are 0-based and kin graph spans are 0-based, so
    /// `find_at` converts nothing. Asserted rather than assumed, because it
    /// holds by convention on both sides and a one-line change to either would
    /// shift every lookup silently.
    ///
    /// Stated in both directions: the first line of a method's span is INSIDE
    /// it, and the line before is not. Under a base mismatch a `def` line lands
    /// one short and resolves to the enclosing scope, which is exactly the
    /// failure this file is fixing, so an off-by-one here is indistinguishable
    /// from the bug.
    #[test]
    fn the_zero_based_line_convention_holds_in_both_directions() {
        let index = adapters_file();
        let uri = "file:///repo/src/requests/adapters.py";
        assert_eq!(
            index.find_at(uri, 127).map(|e| e.name.as_str()),
            Some("BaseAdapter.send"),
            "a span's own first line is inside it"
        );
        assert_eq!(
            index.find_at(uri, 126).map(|e| e.name.as_str()),
            Some("BaseAdapter"),
            "the line before it is not, and falls to the enclosing scope"
        );
        assert_eq!(
            index.find_at(uri, 140).map(|e| e.name.as_str()),
            Some("BaseAdapter.send"),
            "a span's own last line is inside it"
        );
    }

    /// Two spans that begin on the same line: the smaller one wins, so a class
    /// whose only member starts with it does not swallow that member.
    #[test]
    fn a_tie_on_the_start_line_prefers_the_smaller_span() {
        let index = EntityIndex::new(
            vec![at("Outer", 5, 40), at("Outer.only", 5, 12)],
            Path::new("/repo"),
        );
        assert_eq!(
            index
                .find_at("file:///repo/src/requests/adapters.py", 6)
                .map(|e| e.name.as_str()),
            Some("Outer.only")
        );
    }
}

/// Files whose repository paths end the same way.
///
/// A server names a file by an absolute URI, and the index holds files by
/// repository-relative path. cli/cli has two pairs whose relative paths end
/// each other: `api/client.go` ends `pkg/cmd/attestation/api/client.go`, and
/// `api/client_test.go` ends `pkg/cmd/attestation/api/client_test.go`. A
/// suffix join finds both files of a pair for the longer path, and taking
/// whichever match a `HashMap` iterates to first let each index's random seed
/// pick the file.
#[cfg(test)]
mod colliding_path_tests {
    use super::*;

    /// Where the checkout sits in these tests. Nothing reads it.
    const ROOT: &str = "/work/cli";

    /// Fresh indexes per property. Each hashes its keys under its own random
    /// seed, and a lookup that depends on the seed answers a colliding pair
    /// right in about half of them, so passing all 64 by luck has a chance of
    /// about 2^-64.
    const BUILDS: usize = 64;

    fn uri(file: &str) -> String {
        protocol::path_to_uri(&Path::new(ROOT).join(file))
    }

    fn declared(name: &str, file: &str, start: u32, end: u32) -> EntityRef {
        EntityRef {
            id: EntityId::new(),
            name: name.to_string(),
            file_path: file.to_string(),
            start_line: start,
            start_col: 0,
            end_line: end,
            name_line: start,
            name_col: 5,
            declares_name: true,
            kind: kin_model::EntityKind::Function,
        }
    }

    fn build(entities: &[EntityRef]) -> EntityIndex {
        EntityIndex::new(entities.to_vec(), Path::new(ROOT))
    }

    /// The declaration holding 0-based line 59 in each colliding file, with
    /// its span, as cli/cli c033f2961 has them.
    fn cli_client_files() -> Vec<EntityRef> {
        vec![
            declared("Client.GraphQL", "api/client.go", 55, 63),
            declared("TestGraphQLError", "api/client_test.go", 46, 75),
            declared(
                "LiveClient.BuildOwnerAndDigestURL",
                "pkg/cmd/attestation/api/client.go",
                57,
                60,
            ),
            declared(
                "TestGetByDigest",
                "pkg/cmd/attestation/api/client_test.go",
                57,
                72,
            ),
        ]
    }

    /// Each lookup, over [`BUILDS`] fresh indexes, of every `expected`
    /// entity's own file at `line` that did not name that entity.
    fn misread(entities: &[EntityRef], expected: &[&EntityRef], line: u32) -> Vec<String> {
        let mut wrong = Vec::new();
        for build_number in 0..BUILDS {
            let index = build(entities);
            for entity in expected {
                let found = index.find_at(&uri(&entity.file_path), line);
                if found.map(|found| found.id) != Some(entity.id) {
                    wrong.push(format!(
                        "build {build_number}: {}:{line} named {:?}",
                        entity.file_path,
                        found.map(|found| format!("{} in {}", found.name, found.file_path)),
                    ));
                }
            }
        }
        wrong
    }

    fn report(wrong: &[String], lookups: usize) -> String {
        format!(
            "{} of {lookups} lookups named another file's entity or none:\n{}",
            wrong.len(),
            wrong.join("\n")
        )
    }

    /// The defect. Every file, the longer path of each pair included,
    /// resolves to its own declaration, whatever seed the index drew.
    #[test]
    fn a_file_whose_path_ends_another_resolves_to_itself_under_every_seed() {
        let entities = cli_client_files();
        let expected: Vec<&EntityRef> = entities.iter().collect();
        let wrong = misread(&entities, &expected, 59);
        assert!(
            wrong.is_empty(),
            "{}",
            report(&wrong, BUILDS * expected.len())
        );
    }

    /// A shared tail that starts inside a path component names no other
    /// file: `xapi/client.go` is not `api/client.go`, whether or not the index
    /// also holds `xapi/client.go`.
    #[test]
    fn a_suffix_that_starts_inside_a_component_is_not_the_file() {
        let api = declared("Client.GraphQL", "api/client.go", 55, 63);
        let xapi = declared("Client.Do", "xapi/client.go", 50, 70);
        let both = [api.clone(), xapi.clone()];
        let wrong = misread(&both, &[&api, &xapi], 59);
        assert!(wrong.is_empty(), "{}", report(&wrong, BUILDS * 2));

        let index = build(std::slice::from_ref(&api));
        assert_eq!(
            index
                .find_at(&uri("xapi/client.go"), 59)
                .map(|found| found.file_path.as_str()),
            None,
            "a file the index does not hold resolves to nothing"
        );
        assert!(
            index.entities_in_file("client.go").is_empty(),
            "a partial path names no file"
        );
    }

    /// A location outside the checkout is no repository file, however its
    /// path ends. gopls answers a dependency's declaration with a module
    /// cache path, and go-gh's `pkg/api/client.go` ends in `api/client.go`.
    ///
    /// Such a location is still recognised as landing where an admitted file
    /// declares something, which is what lets the references arm refuse it
    /// rather than read it as a site outside the admitted inventory.
    #[test]
    fn a_location_outside_the_workspace_names_no_repository_file() {
        let index = build(&[declared("Client.GraphQL", "api/client.go", 55, 63)]);
        for outside in [
            "file:///home/dev/go/pkg/mod/github.com/cli/go-gh/v2@v2.11.2/pkg/api/client.go",
            "file:///work/other/cli/api/client.go",
            "file:///work/cli2/api/client.go",
        ] {
            assert_eq!(
                index
                    .find_at(outside, 59)
                    .map(|found| found.file_path.as_str()),
                None,
                "{outside}"
            );
            assert_eq!(index.repository_file(outside), None, "{outside}");
            assert!(index.admitted_source_outside(outside, 59), "{outside}");
            assert!(
                !index.admitted_source_outside(outside, 10),
                "{outside}: no admitted declaration holds line 10"
            );
        }
        assert!(
            !index.admitted_source_outside("file:///elsewhere/xapi/client.go", 59),
            "a tail that starts inside a component is not an admitted path"
        );
        assert!(
            !index.admitted_source_outside(&uri("api/client.go"), 59),
            "a location inside the workspace is not outside it"
        );
        assert_eq!(
            index.repository_file(&uri("api/client.go")).as_deref(),
            Some("api/client.go")
        );
    }

    /// The positive control: a file no other path ends with still resolves,
    /// including from a URI that escapes characters Kin's own spelling keeps.
    #[test]
    fn a_file_with_no_colliding_path_still_resolves() {
        let config = declared("Config.Get", "internal/config/config.go", 10, 20);
        let scoped = declared("render", "packages/@scope/my dir/a.ts", 0, 4);
        let index = build(&[config.clone(), scoped.clone()]);
        assert_eq!(
            index
                .find_at(&uri("internal/config/config.go"), 12)
                .map(|found| found.id),
            Some(config.id)
        );
        assert_eq!(
            index
                .find_at("file:///work/cli/packages/%40scope/my%20dir/a.ts", 2)
                .map(|found| found.id),
            Some(scoped.id),
            "the decoded path is what names the file"
        );
        assert_eq!(
            index
                .entities_in_file("internal/config/config.go")
                .iter()
                .map(|found| found.id)
                .collect::<Vec<_>>(),
            [config.id]
        );
    }

    /// A name several entities answer to names none of them. The lookup
    /// returned whichever match iteration reached first, and cli/cli declares
    /// `GetByRepoAndDigest` on both `LiveClient` and `MockClient`.
    #[test]
    fn a_name_two_entities_answer_to_names_neither() {
        let live = declared(
            "LiveClient.GetByRepoAndDigest",
            "pkg/cmd/attestation/api/client.go",
            52,
            55,
        );
        let mock = declared(
            "MockClient.GetByRepoAndDigest",
            "pkg/cmd/attestation/api/mock_client.go",
            14,
            16,
        );
        let graphql = declared("Client.GraphQL", "api/client.go", 55, 63);
        let index = build(&[live.clone(), mock, graphql.clone()]);
        assert!(
            index.find_by_name("GetByRepoAndDigest").is_none(),
            "two methods answer to the bare name"
        );
        assert_eq!(
            index
                .find_by_name("LiveClient.GetByRepoAndDigest")
                .map(|found| found.id),
            Some(live.id)
        );
        assert_eq!(
            index.find_by_name("GraphQL").map(|found| found.id),
            Some(graphql.id),
            "a bare name one entity answers to still resolves"
        );
        assert!(index.find_by_name("Missing").is_none());
    }
}

#[cfg(test)]
mod member_on_module_tests {
    use super::{member_expression_at, receiver_names_a_module, same_location};
    use crate::protocol::{Location, Position, Range};

    fn location(uri: &str, line: u32) -> Location {
        Location {
            uri: uri.to_string(),
            range: Range {
                start: Position { line, character: 0 },
                end: Position { line, character: 0 },
            },
        }
    }

    /// An index that holds nothing, rooted where a test's URIs put the
    /// checkout. Which file a URI names needs only the root.
    fn rooted_at(root: &str) -> super::EntityIndex {
        super::EntityIndex::new(Vec::new(), std::path::Path::new(root))
    }

    /// The express case: asked at the receiver, the member is what matters.
    #[test]
    fn a_receiver_reports_the_member_it_opens() {
        let (receiver, col, member) =
            member_expression_at("var apiv1 = express.Router();", 12).expect("a member expression");
        assert_eq!(receiver, "express");
        assert_eq!(member, "Router");
        assert_eq!(col, 20);
    }

    /// Asked at the member half, there is no further member to bind, so the
    /// position falls through to the ordinary type query rather than recursing.
    #[test]
    fn the_member_half_is_not_itself_a_receiver() {
        assert!(member_expression_at("var apiv1 = express.Router();", 20).is_none());
    }

    /// A bare call has no receiver at all.
    #[test]
    fn a_bare_identifier_opens_nothing() {
        assert!(member_expression_at("finalhandler(req, res);", 0).is_none());
    }

    /// A dot that opens no identifier is not a member expression, so a numeric
    /// literal or a trailing dot cannot be read as one.
    #[test]
    fn a_dot_without_a_member_opens_nothing() {
        assert!(member_expression_at("value.", 0).is_none());
        assert!(member_expression_at("wait 1.5 seconds", 5).is_none());
    }

    /// The module-versus-value rule, as measured. `express` answers with
    /// another file; `res` and `apiv1` answer with their own declarations in
    /// the file being enriched.
    #[test]
    fn a_definition_in_another_file_names_a_module() {
        assert!(receiver_names_a_module(
            &[location("file:///w/index.js", 10)],
            &rooted_at("/w"),
            "examples/multi-router/controllers/api_v1.js"
        ));
    }

    fn declared(name: &str, file: &str, line: u32, declares_name: bool) -> super::EntityRef {
        super::EntityRef {
            id: kin_model::EntityId::new(),
            name: name.into(),
            file_path: file.into(),
            start_line: line,
            start_col: 0,
            end_line: line + 2,
            name_line: line,
            name_col: 0,
            declares_name,
            kind: kin_model::EntityKind::Function,
        }
    }

    fn spanning(uri: &str, line: u32, start: u32, end: u32) -> Location {
        Location {
            uri: uri.to_string(),
            range: Range {
                start: Position {
                    line,
                    character: start,
                },
                end: Position {
                    line,
                    character: end,
                },
            },
        }
    }

    /// Flask's `current_app.config[...]`: the receiver answers from another
    /// file with its own declaration's name, which makes it a value. Every
    /// other shape keeps the module reading.
    #[test]
    fn only_an_imported_value_declaration_is_a_receiver_value() {
        use super::receiver_declared_values;
        let current_app = declared("current_app", "src/flask/globals.py", 43, true);
        let current_app_id = current_app.id;
        let index = super::EntityIndex::new(
            vec![
                declared("flask", "src/flask/__init__.py", 0, false),
                current_app,
                declared("createApplication", "lib/express.js", 9, true),
                declared("settings", "conf/settings.py", 0, true),
            ],
            std::path::Path::new("/w"),
        );
        let globals = "file:///w/src/flask/globals.py";
        let value = [spanning(globals, 43, 0, 11)];
        assert!(receiver_names_a_module(
            &value,
            &index,
            "examples/tutorial/flaskr/db.py"
        ));
        let found = receiver_declared_values(&value, &index, "current_app").expect("a value");
        assert_eq!(
            found.iter().map(|entity| entity.id).collect::<Vec<_>>(),
            [current_app_id]
        );
        for (answers, receiver, why) in [
            (vec![spanning(globals, 43, 0, 11)], "g", "an alias"),
            (
                vec![spanning(globals, 44, 4, 8)],
                "current_app",
                "an answer inside the declaration's body",
            ),
            (
                vec![location("file:///w/src/flask/__init__.py", 0)],
                "flask",
                "a module surface",
            ),
            (
                vec![spanning("file:///w/lib/express.js", 9, 0, 17)],
                "express",
                "a differently named export",
            ),
            (
                vec![location("file:///w/conf/settings.py", 0)],
                "settings",
                "a module's empty answer on a line that declares its name",
            ),
            (
                vec![
                    spanning(globals, 43, 0, 11),
                    spanning("file:///w/lib/express.js", 9, 0, 17),
                ],
                "current_app",
                "one answer that is not the value's declaration",
            ),
            (vec![], "current_app", "no answer at all"),
        ] {
            assert!(
                receiver_declared_values(&answers, &index, receiver).is_none(),
                "{why}"
            );
        }
    }

    #[test]
    fn a_definition_in_this_file_names_a_value() {
        let here = "examples/multi-router/controllers/api_v1.js";
        let index = rooted_at("/w");
        assert!(!receiver_names_a_module(
            &[location(&format!("file:///w/{here}"), 6)],
            &index,
            here
        ));
        assert!(
            !receiver_names_a_module(&[], &index, here),
            "a receiver the server said nothing about is not promoted to a module"
        );
    }

    /// Another file is another file however its path ends. Enriching cli/cli's
    /// root `api/client.go`, a definition in `pkg/cmd/attestation/api/client.go`,
    /// or in a module cache path that also ends in `api/client.go`, named a
    /// module all the same, and matched by suffix it read as this file's own
    /// value, which skipped the member join.
    #[test]
    fn a_definition_in_a_file_whose_path_ends_like_this_one_names_a_module() {
        let here = "api/client.go";
        let index = rooted_at("/work/cli");
        for elsewhere in [
            "file:///work/cli/pkg/cmd/attestation/api/client.go",
            "file:///home/dev/go/pkg/mod/github.com/cli/go-gh/v2@v2.11.2/pkg/api/client.go",
        ] {
            assert!(
                receiver_names_a_module(&[location(elsewhere, 0)], &index, here),
                "{elsewhere} is not {here}"
            );
        }
        assert!(
            !receiver_names_a_module(
                &[location("file:///work/cli/api/client.go", 12)],
                &index,
                here
            ),
            "a definition in the enriched file itself names a value"
        );
        assert!(
            !receiver_names_a_module(&[location("jdt://contents/api/client.go", 0)], &index, here),
            "an answer that names no local file promotes nothing to a module"
        );
    }

    /// The document this pass opens is named by its own extension. A path it
    /// cannot classify is declined rather than opened under a guess.
    #[test]
    fn a_document_is_opened_under_the_language_its_extension_names() {
        use super::lsp_language_id;
        assert_eq!(lsp_language_id("lib/express.js"), Some("javascript"));
        assert_eq!(lsp_language_id("src/app.mjs"), Some("javascript"));
        assert_eq!(lsp_language_id("src/app.tsx"), Some("typescriptreact"));
        assert_eq!(lsp_language_id("requests/sessions.py"), Some("python"));
        assert_eq!(lsp_language_id("src/enrichment.rs"), Some("rust"));
        assert_eq!(
            lsp_language_id("LICENSE"),
            None,
            "a path with no extension names no language"
        );
        assert_eq!(
            lsp_language_id("docs/readme.md"),
            None,
            "an extension this map does not carry is declined, never guessed"
        );
    }

    /// A provider is what makes the second leg answerable, and its absence is
    /// what makes the join decline. Both are the same code path, so both are
    /// asserted against the same helper the join calls.
    #[tokio::test]
    async fn a_missing_provider_declines_and_a_present_one_opens() {
        use super::{DocumentProvider, ScopedDocuments};

        let server = crate::lifecycle::LspServer::offline_for_tests();

        let mut without = ScopedDocuments::new(&server, None);
        assert!(
            !without
                .ensure_open("lib/express.js", "file:///w/lib/express.js")
                .await
                .unwrap(),
            "no provider means the join keeps declining, never a disk read"
        );
        assert!(without.open.is_empty());

        // The provider counts its calls, so "opened at most once" is observable
        // rather than merely consistent with a set that cannot hold duplicates.
        let asked = std::sync::atomic::AtomicUsize::new(0);
        let provider: &(dyn Fn(&str) -> Option<String> + Send + Sync) = &|path: &str| {
            asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            (path == "lib/express.js").then(|| "exports.Router = Router;".to_string())
        };
        let mut with = ScopedDocuments::new(&server, Some(provider as DocumentProvider<'_>));
        assert!(
            with.ensure_open("lib/express.js", "file:///w/lib/express.js")
                .await
                .unwrap(),
            "a provider that answers hands the document to the server"
        );
        assert_eq!(with.open.len(), 1);
        assert!(
            with.ensure_open("lib/express.js", "file:///w/lib/express.js")
                .await
                .unwrap(),
            "a document already open stays open"
        );
        assert_eq!(
            asked.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the same document is opened at most once per entity"
        );

        assert!(
            !with
                .ensure_open("lib/other.js", "file:///w/lib/other.js")
                .await
                .unwrap(),
            "a path repository authority has nothing for declines"
        );
        assert!(
            !with
                .ensure_open("NOTICE", "file:///w/NOTICE")
                .await
                .unwrap(),
            "a path whose language cannot be named declines"
        );
        assert_eq!(with.open.len(), 1);

        with.close_all().await.unwrap();
        assert!(
            with.open.is_empty(),
            "every document this pass opened is closed with it"
        );
    }

    /// The invariant both arms depend on, exercised on the decision rule with
    /// real inputs rather than on an offline server that answers nothing.
    ///
    /// The empty cases are the ones that matter. A document the server was never
    /// handed answers with NO locations, which is exactly what this join saw
    /// before a provider existed, and an unproven candidate must not bind.
    /// Written with `all` instead of `any`, empty would be vacuously true and
    /// every same-named export in the module file would bind on its name alone.
    #[test]
    fn an_unproven_candidate_never_binds() {
        use super::candidate_is_proven;
        let member = [location("file:///w/node_modules/router/index.js", 51)];
        let router_export = [location("file:///w/node_modules/router/index.js", 51)];
        let route_export = [location("file:///w/node_modules/router/lib/route.js", 40)];

        assert!(candidate_is_proven(&router_export, &member));
        assert!(
            !candidate_is_proven(&route_export, &member),
            "a same-named export of something else must not bind"
        );
        assert!(
            !candidate_is_proven(&[], &member),
            "an un-opened document answers nothing, and nothing is not a proof"
        );
        assert!(
            !candidate_is_proven(&router_export, &[]),
            "a member the server could not resolve proves nothing either"
        );
        assert!(
            !candidate_is_proven(&[], &[]),
            "two silences are not an agreement"
        );
    }

    /// The join compares a place, not a name, which is what keeps this apart
    /// from the bare-name fallback this pass deleted.
    #[test]
    fn the_join_compares_the_place_two_answers_name() {
        let member = location("file:///w/node_modules/router/index.js", 51);
        let router_export = location("file:///w/node_modules/router/index.js", 51);
        let route_export = location("file:///w/node_modules/router/lib/route.js", 40);
        assert!(same_location(&router_export, &member));
        assert!(
            !same_location(&route_export, &member),
            "a same-shaped export of something else must not join"
        );
    }
}
