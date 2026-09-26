// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Source units addressed by language-native identity, and the repository base
//! that guards work on them.
//!
//! A unit is named the way its language names it (for Go, a package relative
//! to its module root plus the package name and a role), never by a file path.
//! Kin derives the unit's projection path by convention and owns its package
//! clause and import block. A repository base is the workspace instant the
//! caller last observed; work addressed to a unit is refused when repository
//! authority has moved since, exactly as a source base refuses a stale entity
//! edit.

use serde::{Deserialize, Serialize};

use crate::source_base::SourceBaseContext;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RepositoryBaseSchema {
    #[serde(rename = "kin.repository.base.v1")]
    V1,
}

/// One observed workspace instant, carried unchanged into unit-addressed work.
/// An optimistic concurrency expectation, not an authorization token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RepositoryBase {
    pub schema: RepositoryBaseSchema,
    pub context: SourceBaseContext,
}

impl RepositoryBase {
    pub fn from_workspace(workspace: &kin_model::WorkspaceState) -> Result<Self, String> {
        Ok(Self {
            schema: RepositoryBaseSchema::V1,
            context: SourceBaseContext::from_workspace(workspace)?,
        })
    }

    pub fn validate(&self) -> Result<(), String> {
        self.context.validate()
    }
}

/// Machine-readable refusal for a stale repository base, emitted only after the
/// unchanged staged work is durable.
///
/// `current` is the base repository authority holds now. It rides on the
/// refusal so a caller retries in one step: the unit-addressed work names its
/// unit and declarations by identity, an occupied name or foreign package is
/// refused again at the retry, and the footprint check keeps every existing
/// declaration's bytes, so resending against the current base cannot
/// overwrite what moved.
///
/// `source_reads` names each operation (by index and entity id) that carries
/// an entity `source_base`. The current repository base does not refresh an
/// entity's source base, so those operations need a fresh source read before
/// the resend, and `next_step` says so; unit-addressed operations need only
/// the current repository base.
pub fn repository_base_conflict(
    transaction_id: &str,
    reason: &str,
    current: Option<&RepositoryBase>,
    source_reads: &[(usize, kin_model::EntityId)],
) -> String {
    let mut refusal = serde_json::json!({
        "schema": "kin.repository.base_conflict.v1",
        "code": "repository_base_conflict",
        "transaction_id": transaction_id,
        "applied": false,
        "staged_operations_retained": true,
        "reason": reason,
        "next_step": repository_conflict_next_step(!source_reads.is_empty(), current.is_some()),
        "remedy": "Repository authority moved after you read the repository_base you sent. Follow next_step in a new mutate (and a new request_id for a keyed mutation); a name taken since is refused again, and every declaration already in the unit keeps its exact bytes. The stale transaction stays open until you abort it (kin call kin_transaction_abort with its transaction_id)."
    });
    if let Some(current) = current {
        refusal["current_repository_base"] =
            serde_json::to_value(current).unwrap_or(serde_json::Value::Null);
    }
    if !source_reads.is_empty() {
        refusal["source_reads_required"] = source_reads
            .iter()
            .map(|(operation, entity_id)| {
                serde_json::json!({"operation": operation, "entity_id": entity_id})
            })
            .collect();
    }
    refusal.to_string()
}

/// What a caller does after a repository-base conflict, given whether any of
/// its operations carried an entity source base and whether the refusal could
/// carry the current repository base.
pub fn repository_conflict_next_step(
    needs_source_reads: bool,
    current_available: bool,
) -> &'static str {
    if !current_available {
        return if needs_source_reads {
            "The current repository_base could not be read, so this refusal carries none. Call \
             status (kin graph status) or session for a fresh repository_base, re-read each \
             entity in source_reads_required with source (get_entity_source) for a fresh \
             source_base, and resend every operation with those bases."
        } else {
            "The current repository_base could not be read, so this refusal carries none. Call \
             status (kin graph status) or session for a fresh repository_base, and resend the \
             same operations with it in place of the stale repository_base."
        };
    }
    if needs_source_reads {
        "Re-read each entity in source_reads_required with source (get_entity_source), rebuild \
         that operation from the read, with the fresh source_base it returns, and resend every \
         operation with current_repository_base in place of the stale repository_base. The \
         unit-addressed operations need only current_repository_base."
    } else {
        "Resend the same operations with current_repository_base in place of the stale \
         repository_base."
    }
}

pub fn is_repository_base_conflict(text: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(text).is_ok_and(|value| {
        value["schema"] == "kin.repository.base_conflict.v1"
            && value["code"] == "repository_base_conflict"
            && value["applied"] == false
            && value["staged_operations_retained"] == true
    })
}

/// What a unit holds, in its language's own terms.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnitRole {
    /// Ordinary package source.
    #[default]
    Source,
    /// Test code compiled only by the language's test runner (Go `_test.go`).
    Test,
}

/// A source unit named by language-native identity.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "language", rename_all = "snake_case", deny_unknown_fields)]
pub enum SourceUnit {
    /// A Go package unit. `package` is the import path relative to the module
    /// root (`.` for the root package, `internal/store`), `name` its package
    /// clause, and `role` whether this is the package's source or test unit.
    Go {
        package: String,
        name: String,
        #[serde(default)]
        role: UnitRole,
    },
}

/// The file-name stem Kin projects a Go unit to, derived from its package name.
///
/// The Go toolchain reads meaning into file names: everything after the first
/// underscore can make a file platform-specific (`_linux`, `_amd64`) or a test
/// (`_test`), and a leading `_` or `.` hides it. A package name is kept exactly
/// as given, so the stem, never the identity, absorbs that: a name with an
/// underscore gains a neutral `_unit` element, which is neither a platform, an
/// architecture nor `test`, and a leading underscore gains a `unit` prefix.
/// The mapping is deterministic and internal; callers never name files.
pub fn go_unit_file_stem(package_name: &str) -> String {
    let mut stem = if package_name.starts_with('_') {
        format!("unit{package_name}")
    } else {
        package_name.to_string()
    };
    if stem.contains('_') {
        stem.push_str("_unit");
    }
    stem
}

impl SourceUnit {
    pub fn language(&self) -> kin_model::LanguageId {
        match self {
            Self::Go { .. } => kin_model::LanguageId::Go,
        }
    }

    pub fn role(&self) -> UnitRole {
        match self {
            Self::Go { role, .. } => *role,
        }
    }

    /// The unit's package clause name.
    pub fn package_name(&self) -> &str {
        match self {
            Self::Go { name, .. } => name,
        }
    }

    /// Human-readable identity for refusals: never a path.
    pub fn describe(&self) -> String {
        match self {
            Self::Go {
                package,
                name,
                role,
            } => format!(
                "Go package {package} (package {name}, {} unit)",
                match role {
                    UnitRole::Source => "source",
                    UnitRole::Test => "test",
                }
            ),
        }
    }

    /// Refuse anything that is not a language-native identity. A file path, a
    /// file name, an escape or a directory the toolchain ignores is refused.
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::Go { package, name, .. } => {
                if package != "." {
                    if package.is_empty()
                        || package.len() > 512
                        || package.starts_with('/')
                        || package.ends_with('/')
                    {
                        return Err(format!(
                            "Go unit package {package:?} must be \".\" or an import path relative \
                             to the module root, such as \"internal/store\""
                        ));
                    }
                    for element in package.split('/') {
                        if element.is_empty()
                            || element == "."
                            || element == ".."
                            || element.starts_with('.')
                            || element.starts_with('_')
                            || element == "testdata"
                            || element == "vendor"
                            || !element
                                .bytes()
                                .all(|byte| byte.is_ascii_alphanumeric() || b"_.-~".contains(&byte))
                        {
                            return Err(format!(
                                "Go unit package {package:?} is not a package import path relative \
                                 to the module root: element {element:?} is empty, relative, \
                                 ignored by the Go toolchain, or not a plain name. Address the \
                                 unit by package, never by file path"
                            ));
                        }
                    }
                    if package.ends_with(".go") {
                        return Err(format!(
                            "Go unit package {package:?} looks like a file; address the unit by \
                             its package, such as \"internal/store\", never by file path"
                        ));
                    }
                }
                if !kin_parser::go_unit::is_go_identifier(name) || name == "_" {
                    return Err(format!(
                        "Go unit name {name:?} must be the package clause name, one Go identifier"
                    ));
                }
                Ok(())
            }
        }
    }

    /// The projection path Kin derives for this unit: the package directory
    /// under the module root, then `<name>.go` or `<name>_test.go`.
    pub fn projection_path(&self, module_root: &str) -> Result<kin_model::RepoPath, String> {
        self.validate()?;
        let Self::Go {
            package,
            name,
            role,
        } = self;
        let mut directory = module_root.trim_end_matches('/').to_string();
        if package != "." {
            if !directory.is_empty() {
                directory.push('/');
            }
            directory.push_str(package);
        }
        let stem = go_unit_file_stem(name);
        let file = match role {
            UnitRole::Source => format!("{stem}.go"),
            UnitRole::Test => format!("{stem}_test.go"),
        };
        let path = if directory.is_empty() {
            file
        } else {
            format!("{directory}/{file}")
        };
        let path = kin_model::RepoPath::from_utf8(path).map_err(|error| error.to_string())?;
        kin_core::validate_source_paths([&path]).map_err(|error| error.to_string())?;
        Ok(path)
    }
}

/// The Go module root: the directory of the repository's one `go.mod`, or the
/// repository root when there is none. Several modules are refused, because a
/// module-relative package would not say which one it means.
pub fn go_module_root<'a>(
    paths: impl IntoIterator<Item = &'a kin_model::RepoPath>,
) -> Result<String, String> {
    let mut roots = paths
        .into_iter()
        .map(ToString::to_string)
        .filter_map(|path| match path.rsplit_once('/') {
            Some((directory, "go.mod")) => Some(directory.to_string()),
            None if path == "go.mod" => Some(String::new()),
            _ => None,
        })
        .collect::<Vec<_>>();
    roots.sort();
    roots.dedup();
    match roots.len() {
        0 => Ok(String::new()),
        1 => Ok(roots.remove(0)),
        count => Err(format!(
            "this repository holds {count} Go modules; addressing a unit by a module-relative \
             package needs exactly one go.mod, and multi-module repositories are not supported yet"
        )),
    }
}

/// The unit's projection path resolved against a tree's own `go.mod`.
pub fn unit_projection_path(
    unit: &SourceUnit,
    tree: &kin_model::ResolvedTree,
) -> Result<kin_model::RepoPath, String> {
    match unit {
        SourceUnit::Go { .. } => {
            let root = go_module_root(tree.artifacts().map(|artifact| &artifact.path))?;
            unit.projection_path(&root)
        }
    }
}

/// A declaration kind, language-neutral in name. Each language admits the
/// subset it declares; the graph's own kind names are accepted as synonyms so
/// a kind read from search can be written back unchanged.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeclarationKind {
    Function,
    Method,
    Struct,
    Class,
    Interface,
    #[serde(alias = "type_alias")]
    Type,
    #[serde(alias = "constant")]
    Const,
    #[serde(alias = "static_var")]
    Var,
}

impl DeclarationKind {
    pub const WIRE_NAMES: [&'static str; 8] = [
        "function",
        "method",
        "struct",
        "class",
        "interface",
        "type",
        "const",
        "var",
    ];

    /// The Go declaration this kind names, or a refusal naming the Go kinds.
    pub fn go(self) -> Result<kin_parser::go_unit::GoDeclarationKind, String> {
        use kin_parser::go_unit::GoDeclarationKind as Go;
        Ok(match self {
            Self::Function => Go::Function,
            Self::Method => Go::Method,
            Self::Struct | Self::Class => Go::Struct,
            Self::Interface => Go::Interface,
            Self::Type => Go::Type,
            Self::Const => Go::Const,
            Self::Var => Go::Var,
        })
    }
}

/// One import: a bare path, or a path with an explicit package name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ImportSpec {
    Path(String),
    Named(NamedImport),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NamedImport {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
}

impl ImportSpec {
    pub fn go(&self) -> kin_parser::go_unit::GoImport {
        match self {
            Self::Path(path) => kin_parser::go_unit::GoImport {
                path: path.clone(),
                alias: None,
            },
            Self::Named(named) => kin_parser::go_unit::GoImport {
                path: named.path.clone(),
                alias: named.alias.clone(),
            },
        }
    }

    pub fn path(&self) -> &str {
        match self {
            Self::Path(path) => path,
            Self::Named(named) => &named.path,
        }
    }
}

fn validate_imports(unit: &SourceUnit, imports: &[ImportSpec]) -> Result<(), String> {
    match unit {
        SourceUnit::Go { .. } => {
            for import in imports {
                import.go().validate()?;
            }
        }
    }
    let mut paths = imports.iter().map(ImportSpec::path).collect::<Vec<_>>();
    paths.sort_unstable();
    if paths.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err("each import path may appear once per operation".into());
    }
    Ok(())
}

/// Add and remove imports on one unit. Adding a held import and removing an
/// absent one are no-ops, so the operation is idempotent against its unit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnitImports {
    pub repository_base: RepositoryBase,
    pub unit: SourceUnit,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub add: Vec<ImportSpec>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub remove: Vec<ImportSpec>,
}

impl UnitImports {
    pub fn validate(&self) -> Result<(), String> {
        self.repository_base.validate()?;
        self.unit.validate()?;
        if self.add.is_empty() && self.remove.is_empty() {
            return Err("UnitImports needs at least one import to add or remove".into());
        }
        validate_imports(&self.unit, &self.add)?;
        validate_imports(&self.unit, &self.remove)?;
        if self
            .add
            .iter()
            .any(|add| self.remove.iter().any(|remove| remove.path() == add.path()))
        {
            return Err("an import path cannot be both added and removed in one operation".into());
        }
        Ok(())
    }
}

pub(crate) fn validate_create_imports(
    unit: &SourceUnit,
    imports: &[ImportSpec],
) -> Result<(), String> {
    validate_imports(unit, imports)
}

pub fn repository_base_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "description": "The repository_base Kin returned from session, status or the last mutate, unchanged. Work addressed to a unit is refused as repository_base_conflict when repository authority has moved since.",
        "properties": {
            "schema": {"const": "kin.repository.base.v1"},
            "context": {
                "type": "object",
                "properties": {
                    "repository_id": {"type": "string"},
                    "workspace_id": {"type": "string"},
                    "workspace_generation": {"type": "integer", "minimum": 0},
                    "workspace_head_hash": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                    "workspace_tree_hash": {"type": "string", "pattern": "^[0-9a-f]{64}$"}
                },
                "required": ["repository_id", "workspace_id", "workspace_generation", "workspace_head_hash", "workspace_tree_hash"],
                "additionalProperties": false
            }
        },
        "required": ["schema", "context"],
        "additionalProperties": false
    })
}

pub fn source_unit_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "description": "A source unit named by language identity, never by path. Go: package is the import path relative to the module root (\".\" or \"internal/store\"), name is the package clause, role is source or test (the package's _test unit). Kin derives the file and owns the package clause.",
        "properties": {
            "language": {"const": "go"},
            "package": {"type": "string", "minLength": 1},
            "name": {"type": "string", "pattern": "^[A-Za-z_][A-Za-z0-9_]*$"},
            "role": {"type": "string", "enum": ["source", "test"], "default": "source"}
        },
        "required": ["language", "package", "name"],
        "additionalProperties": false
    })
}

pub fn import_spec_schema() -> serde_json::Value {
    serde_json::json!({
        "oneOf": [
            {"type": "string", "minLength": 1, "description": "An import path, such as \"fmt\" or \"example.com/app/internal/store\"."},
            {
                "type": "object",
                "properties": {
                    "path": {"type": "string", "minLength": 1},
                    "alias": {"type": "string", "description": "Explicit package name, \"_\" or \".\"."}
                },
                "required": ["path"],
                "additionalProperties": false
            }
        ]
    })
}

pub fn unit_imports_schema() -> serde_json::Value {
    serde_json::json!({
        "type": "object",
        "description": "Add or remove imports on one source unit. Kin writes the unit's single import block deterministically (standard library first, each group sorted). Adding a held import or removing an absent one is a no-op.",
        "properties": {
            "repository_base": repository_base_schema(),
            "unit": source_unit_schema(),
            "add": {"type": "array", "items": import_spec_schema()},
            "remove": {"type": "array", "items": import_spec_schema()}
        },
        "required": ["repository_base", "unit"],
        "additionalProperties": false
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn go(package: &str, name: &str, role: UnitRole) -> SourceUnit {
        SourceUnit::Go {
            package: package.into(),
            name: name.into(),
            role,
        }
    }

    #[test]
    fn source_units_project_by_convention_and_refuse_paths() {
        for (unit, root, expected) in [
            (go(".", "main", UnitRole::Source), "", "main.go"),
            (go(".", "main", UnitRole::Test), "", "main_test.go"),
            (
                go("internal/store", "store", UnitRole::Source),
                "",
                "internal/store/store.go",
            ),
            (
                go("internal/store", "store", UnitRole::Test),
                "backend",
                "backend/internal/store/store_test.go",
            ),
        ] {
            assert_eq!(unit.projection_path(root).unwrap().to_string(), expected);
        }
        for (package, name) in [
            ("internal/store/store.go", "store"),
            ("/abs", "store"),
            ("../escape", "store"),
            ("a//b", "store"),
            ("internal\\store", "store"),
            ("testdata/x", "x"),
            ("_hidden", "x"),
            ("", "x"),
            (".", "store.go"),
            (".", "internal/store"),
            (".", "func"),
            (".", "_"),
        ] {
            assert!(
                go(package, name, UnitRole::Source).validate().is_err(),
                "{package} {name}"
            );
        }
    }

    /// Go's own file-name rule (go/build `goodOSArchFile` plus the `_test`
    /// and hidden-file rules), used to prove no projected unit is constrained.
    fn go_reads_file_as(file: &str) -> (&'static str, bool) {
        const OS: [&str; 18] = [
            "aix",
            "android",
            "darwin",
            "dragonfly",
            "freebsd",
            "hurd",
            "illumos",
            "ios",
            "js",
            "linux",
            "nacl",
            "netbsd",
            "openbsd",
            "plan9",
            "solaris",
            "wasip1",
            "windows",
            "zos",
        ];
        const ARCH: [&str; 24] = [
            "386",
            "amd64",
            "amd64p32",
            "arm",
            "armbe",
            "arm64",
            "arm64be",
            "loong64",
            "mips",
            "mipsle",
            "mips64",
            "mips64le",
            "mips64p32",
            "mips64p32le",
            "ppc",
            "ppc64",
            "ppc64le",
            "riscv",
            "riscv64",
            "s390",
            "s390x",
            "sparc",
            "sparc64",
            "wasm",
        ];
        let hidden = file.starts_with('_') || file.starts_with('.');
        let role = if file.ends_with("_test.go") {
            "test"
        } else {
            "source"
        };
        let name = file.trim_end_matches(".go");
        let Some(first) = name.find('_') else {
            return (role, !hidden);
        };
        let mut elements = name[first..].split('_').collect::<Vec<_>>();
        if elements.last() == Some(&"test") {
            elements.pop();
        }
        let n = elements.len();
        let constrained =
            (n >= 2 && OS.contains(&elements[n - 2]) && ARCH.contains(&elements[n - 1]))
                || (n >= 1 && (OS.contains(&elements[n - 1]) || ARCH.contains(&elements[n - 1])));
        (role, !hidden && !constrained)
    }

    /// A legal Go package name is kept exactly; its projected file is always an
    /// unconstrained file of the unit's own role.
    #[test]
    fn go_package_names_are_kept_and_projected_files_are_never_constrained() {
        for (name, source, test) in [
            ("store", "store.go", "store_test.go"),
            (
                "store_test",
                "store_test_unit.go",
                "store_test_unit_test.go",
            ),
            ("foo_linux", "foo_linux_unit.go", "foo_linux_unit_test.go"),
            (
                "foo_linux_amd64",
                "foo_linux_amd64_unit.go",
                "foo_linux_amd64_unit_test.go",
            ),
            ("linux", "linux.go", "linux_test.go"),
            ("_hidden", "unit_hidden_unit.go", "unit_hidden_unit_test.go"),
        ] {
            for (role, expected) in [(UnitRole::Source, source), (UnitRole::Test, test)] {
                let unit = go(".", name, role);
                unit.validate()
                    .unwrap_or_else(|error| panic!("{name}: {error}"));
                let file = unit.projection_path("").unwrap().to_string();
                assert_eq!(file, expected, "{name} {role:?}");
                let wanted = if role == UnitRole::Test {
                    "test"
                } else {
                    "source"
                };
                assert_eq!(go_reads_file_as(&file), (wanted, true), "{file}");
            }
        }
    }

    #[test]
    fn source_unit_wire_is_closed_and_language_tagged() {
        let unit: SourceUnit = serde_json::from_value(serde_json::json!({
            "language": "go", "package": "internal/store", "name": "store"
        }))
        .unwrap();
        assert_eq!(unit.role(), UnitRole::Source);
        for bad in [
            serde_json::json!({"language": "go", "package": ".", "name": "main", "path": "main.go"}),
            serde_json::json!({"language": "cobol", "package": ".", "name": "main"}),
            serde_json::json!({"package": ".", "name": "main"}),
            serde_json::json!({"language": "go", "package": ".", "name": "main", "role": "vendor"}),
        ] {
            assert!(
                serde_json::from_value::<SourceUnit>(bad.clone()).is_err(),
                "{bad}"
            );
        }
    }

    /// A refusal that cannot carry the current base never tells the caller to
    /// resend with it; it names the read that supplies one.
    #[test]
    fn a_conflict_without_the_current_base_names_where_to_read_one() {
        let base = RepositoryBase {
            schema: RepositoryBaseSchema::V1,
            context: SourceBaseContext {
                repository_id: "conflict".into(),
                workspace_id: uuid::Uuid::new_v4().to_string(),
                workspace_generation: 3,
                workspace_head_hash: "a".repeat(64),
                workspace_tree_hash: "b".repeat(64),
            },
        };
        let entity = kin_model::EntityId::new();
        for (current, reads) in [
            (None, vec![]),
            (None, vec![(0, entity)]),
            (Some(&base), vec![]),
            (Some(&base), vec![(0, entity)]),
        ] {
            let refusal: serde_json::Value =
                serde_json::from_str(&repository_base_conflict("tx", "moved", current, &reads))
                    .unwrap();
            assert!(is_repository_base_conflict(&refusal.to_string()));
            let next = refusal["next_step"].as_str().unwrap();
            assert_eq!(
                refusal.get("current_repository_base").is_some(),
                current.is_some()
            );
            if current.is_some() {
                assert!(next.contains("with current_repository_base"), "{next}");
            } else {
                assert!(!next.contains("current_repository_base"), "{next}");
                assert!(
                    next.contains("status (kin graph status) or session"),
                    "{next}"
                );
            }
            assert_eq!(
                next.contains("source (get_entity_source)"),
                !reads.is_empty(),
                "{next}"
            );
        }
    }

    #[test]
    fn go_module_root_is_the_one_go_mod() {
        let path = |p: &str| kin_model::RepoPath::from_utf8(p.to_string()).unwrap();
        assert_eq!(go_module_root([&path("README.md")]).unwrap(), "");
        assert_eq!(
            go_module_root([&path("go.mod"), &path("main.go")]).unwrap(),
            ""
        );
        assert_eq!(go_module_root([&path("svc/go.mod")]).unwrap(), "svc");
        assert!(go_module_root([&path("go.mod"), &path("tools/go.mod")]).is_err());
    }

    #[test]
    fn declaration_kinds_accept_graph_synonyms_and_imports_are_closed() {
        for (wire, kind) in [
            ("\"type_alias\"", DeclarationKind::Type),
            ("\"constant\"", DeclarationKind::Const),
            ("\"static_var\"", DeclarationKind::Var),
            ("\"struct\"", DeclarationKind::Struct),
        ] {
            assert_eq!(serde_json::from_str::<DeclarationKind>(wire).unwrap(), kind);
        }
        assert!(serde_json::from_str::<DeclarationKind>("\"module\"").is_err());
        let spec: ImportSpec =
            serde_json::from_value(serde_json::json!({"path": "fmt", "alias": "f"})).unwrap();
        assert_eq!(spec.path(), "fmt");
        assert!(serde_json::from_value::<ImportSpec>(
            serde_json::json!({"path": "fmt", "file": "x"})
        )
        .is_err());
    }
}
