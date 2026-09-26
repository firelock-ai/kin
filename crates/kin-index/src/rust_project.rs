// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Cargo target and Rust module authority from one exact admitted tree.
//!
//! This is static source binding, not compiler/configuration or macro execution
//! proof. No path is read from a host checkout. Unsupported or incomplete input
//! cannot yield a root-dependent binding. Caches must be rebuilt for another
//! selected tree; the value intentionally has no deserializer/checkpoint form.
//! Reachable roots/modules must have a `.rs` suffix in this version, matching
//! the semantic source inventory and invalidation contract. Rust itself allows
//! other explicit filenames; those require a broader support-closure contract.

use std::collections::{BTreeMap, BTreeSet};

use kin_model::{ArtifactId, Entity, EntityId, EntityKind, Hash256, ResolvedTree, TreeEntry};

mod syntax;
mod targets;

pub const RUST_PROJECT_AUTHORITY_VERSION: u32 = 1;

/// A complete inventory can establish static membership or explicitly leave it
/// unproven. This never converts a CAS/read/processing-bound failure into a
/// successful negative observation.
#[derive(Debug, Clone)]
pub enum RustProjectObservation {
    Current(RustProjectAuthority),
    Unproven {
        tree_digest: Hash256,
        reason: String,
    },
}

impl RustProjectObservation {
    pub fn tree_digest(&self) -> Hash256 {
        match self {
            Self::Current(authority) => authority.tree_digest(),
            Self::Unproven { tree_digest, .. } => *tree_digest,
        }
    }
    pub fn authority(&self) -> Option<&RustProjectAuthority> {
        match self {
            Self::Current(authority) => Some(authority),
            Self::Unproven { .. } => None,
        }
    }
}

enum BuildError {
    Unproven(String),
    Refused(String),
}
impl From<String> for BuildError {
    fn from(value: String) -> Self {
        Self::Unproven(value)
    }
}
impl From<&str> for BuildError {
    fn from(value: &str) -> Self {
        Self::Unproven(value.into())
    }
}
impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unproven(reason) | Self::Refused(reason) => f.write_str(reason),
        }
    }
}

/// Stable observation identity for the complete selected artifact tree.
pub fn selected_tree_digest(tree: &ResolvedTree) -> Result<Hash256, String> {
    Ok(kin_blobs::digest(
        &serde_json::to_vec(tree).map_err(|e| e.to_string())?,
    ))
}

#[derive(Debug, Clone, Copy)]
pub struct RustProjectLimits {
    pub artifacts: usize,
    pub path_bytes: usize,
    /// Maximum bytes in each admitted Rust source, including syntax analysis.
    pub body_bytes: usize,
    /// Cargo manifests have a smaller independent bound than source bodies.
    pub manifest_bytes: usize,
    pub total_body_bytes: usize,
    /// Count all named and unnamed AST nodes; independent of retained bindings.
    pub syntax_nodes: usize,
    /// AST nesting only; module and use-path depth limits remain independent.
    pub syntax_depth: usize,
    pub targets: usize,
    pub module_contexts: usize,
}

impl Default for RustProjectLimits {
    fn default() -> Self {
        Self {
            artifacts: 65_536,
            path_bytes: 8 * 1024 * 1024,
            // Measured large Kin sources reach 2.7 MB, 545,217 AST nodes and
            // depth 227. These are processing caps with growth headroom, not
            // a guarantee about peak CAS/parser allocation or elapsed time.
            body_bytes: 8 * 1024 * 1024,
            manifest_bytes: 256 * 1024,
            total_body_bytes: 128 * 1024 * 1024,
            syntax_nodes: 1024 * 1024,
            syntax_depth: 512,
            targets: 2048,
            module_contexts: 16_384,
        }
    }
}

/// A bounded invalidation instruction, not a Cargo-authority or freshness proof.
/// Adapters must run the coherent source batch even for zero/one source; the
/// finalizer independently establishes support or withdraws unsupported facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustProjectBatchInvalidation {
    pub previous_tree_digest: Hash256,
    pub current_tree_digest: Hash256,
    pub affected_sources: Vec<kin_model::FilePathId>,
}

#[derive(Debug, thiserror::Error)]
pub enum RustProjectInvalidationError {
    #[error("Rust project invalidation limit: {0}")]
    Limit(String),
    #[error("Rust project invalidation source path: {0}")]
    InvalidSourcePath(String),
    #[error("Rust project invalidation tree identity: {0}")]
    TreeIdentity(String),
}

fn check_inventory(tree: &ResolvedTree, limits: RustProjectLimits) -> Result<(), String> {
    if tree.len() > limits.artifacts {
        return Err("Rust project artifact inventory budget exceeded".into());
    }
    let mut path_bytes = 0;
    for artifact in tree.artifacts() {
        add(
            &mut path_bytes,
            artifact.path.as_bytes().len(),
            limits.path_bytes,
            "path inventory",
        )?;
    }
    Ok(())
}

fn is_project_input(path: &[u8]) -> bool {
    path.ends_with(b".rs") || path.rsplit(|byte| *byte == b'/').next() == Some(b"Cargo.toml")
}

/// Nominate all current regular Rust sources when an exact admitted Cargo or
/// Rust source artifact changes. This deliberately includes empty/use-only
/// sources, custom roots and disconnected callers, without entity-name tests.
/// `None` means no supported input changed; it never certifies derived freshness.
/// No CAS or filesystem read occurs here. Limits precede inventory cloning and
/// digest serialization. All-Rust invalidation cost remains a measured-product
/// acceptance concern; this first implementation chooses conservative scope.
pub fn affected_source_batch(
    previous: &ResolvedTree,
    current: &ResolvedTree,
    limits: RustProjectLimits,
) -> Result<Option<RustProjectBatchInvalidation>, RustProjectInvalidationError> {
    for tree in [previous, current] {
        check_inventory(tree, limits).map_err(RustProjectInvalidationError::Limit)?;
    }
    let relevant = |tree: &ResolvedTree| {
        tree.artifacts_by_path()
            .filter(|artifact| is_project_input(artifact.path.as_bytes()))
            .map(|artifact| {
                (
                    artifact.path.clone(),
                    (artifact.artifact_id, artifact.entry),
                )
            })
            .collect::<BTreeMap<_, _>>()
    };
    if relevant(previous) == relevant(current) {
        return Ok(None);
    }
    let mut affected_sources = Vec::new();
    for artifact in current.artifacts_by_path().filter(|artifact| {
        artifact.path.as_bytes().ends_with(b".rs")
            && matches!(artifact.entry, TreeEntry::Blob { .. })
    }) {
        let file = std::str::from_utf8(artifact.path.as_bytes()).map_err(|_| {
            RustProjectInvalidationError::InvalidSourcePath(
                "current Rust source is not UTF8".into(),
            )
        })?;
        affected_sources.push(kin_model::FilePathId::new(file));
    }
    Ok(Some(RustProjectBatchInvalidation {
        previous_tree_digest: selected_tree_digest(previous)
            .map_err(RustProjectInvalidationError::TreeIdentity)?,
        current_tree_digest: selected_tree_digest(current)
            .map_err(RustProjectInvalidationError::TreeIdentity)?,
        affected_sources,
    }))
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct CargoTarget {
    pub manifest: String,
    pub manifest_artifact: ArtifactId,
    pub kind: String,
    pub name: String,
    pub root: String,
    pub edition: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustSourceBinding {
    pub artifact: ArtifactId,
    pub digest: Hash256,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct RustResolvedName {
    pub file: String,
    pub name: String,
    pub start: usize,
    pub end: usize,
}

struct ResolvedBinding {
    declaration: RustResolvedName,
    exposure: Exposure,
}

enum Exposure {
    Public,
    Within(Vec<String>),
}

impl Exposure {
    fn includes(&self, caller: &[String]) -> bool {
        match self {
            Self::Public => true,
            Self::Within(path) => caller.starts_with(path),
        }
    }
    fn no_wider_than(&self, target: &Self) -> bool {
        match (self, target) {
            (_, Self::Public) => true,
            (Self::Within(alias), Self::Within(target)) => alias.starts_with(target),
            _ => false,
        }
    }
}

#[derive(Debug, Clone)]
struct ModuleContext {
    file: String,
    syntax_path: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct RustProjectAuthority {
    tree_digest: Hash256,
    targets: Vec<CargoTarget>,
    inputs: BTreeMap<String, RustSourceBinding>,
    sources: BTreeMap<String, syntax::SourceSyntax>,
    modules: BTreeMap<(usize, Vec<String>), ModuleContext>,
    entities: BTreeMap<RustResolvedName, EntityId>,
}

fn add(total: &mut usize, n: usize, cap: usize, what: &str) -> Result<(), String> {
    *total = total
        .checked_add(n)
        .filter(|n| *n <= cap)
        .ok_or_else(|| format!("Rust project {what} budget exceeded"))?;
    Ok(())
}

pub(super) fn parent(path: &str) -> &str {
    path.rsplit_once('/').map_or("", |(parent, _)| parent)
}

/// Portable repository-relative normalization. A platform-dependent absolute
/// spelling or escape outside the admitted repository is not a source path.
pub(super) fn join(base: &str, path: &str) -> Result<String, String> {
    if path.is_empty() || path.starts_with('/') || path.contains(['\\', ':', '\0']) {
        return Err("unsupported Rust project path".into());
    }
    let mut parts: Vec<_> = base.split('/').filter(|p| !p.is_empty()).collect();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop().ok_or("Rust project path escapes repository")?;
            }
            p => parts.push(p),
        }
    }
    if parts.is_empty() {
        return Err("Rust project path is empty".into());
    }
    Ok(parts.join("/"))
}

fn child_directory(file: &str, root: bool) -> Result<String, String> {
    if root || file.rsplit('/').next() == Some("mod.rs") {
        Ok(parent(file).to_owned())
    } else {
        Ok(file
            .strip_suffix(".rs")
            .ok_or("non-Rust module filename")?
            .to_owned())
    }
}

struct Builder<'a, F> {
    entries: BTreeMap<String, (ArtifactId, TreeEntry)>,
    limits: RustProjectLimits,
    bytes: usize,
    read: &'a mut F,
    authority: RustProjectAuthority,
}

impl<F: FnMut(Hash256) -> Result<Vec<u8>, String>> Builder<'_, F> {
    fn body(&mut self, path: &str, byte_limit: usize) -> Result<Vec<u8>, BuildError> {
        let (artifact, entry) = self
            .entries
            .get(path)
            .ok_or_else(|| format!("Rust project source is not admitted: {path}"))?;
        let TreeEntry::Blob { hash, .. } = entry else {
            return Err(
                format!("Rust project input is not a regular admitted blob: {path}").into(),
            );
        };
        let bytes =
            (self.read)(*hash).map_err(|error| BuildError::Refused(format!("{path}: {error}")))?;
        if bytes.len() > byte_limit || kin_blobs::digest(&bytes) != *hash {
            return Err(BuildError::Refused(format!(
                "Rust project body bound failed: {path}"
            )));
        }
        add(
            &mut self.bytes,
            bytes.len(),
            self.limits.total_body_bytes,
            "source bytes",
        )
        .map_err(BuildError::Refused)?;
        self.authority.inputs.insert(
            path.into(),
            RustSourceBinding {
                artifact: *artifact,
                digest: *hash,
            },
        );
        Ok(bytes)
    }

    fn visit(
        &mut self,
        target: usize,
        module: Vec<String>,
        file: String,
        lexical: Vec<String>,
        directory: String,
        stack: &mut BTreeSet<String>,
    ) -> Result<(), BuildError> {
        if !file.ends_with(".rs") {
            return Err("non-.rs Rust root/module support is unproven".into());
        }
        if module.len() > 64 || self.authority.modules.len() >= self.limits.module_contexts {
            return Err(BuildError::Refused(
                "Rust project module traversal budget exceeded".into(),
            ));
        }
        if !self.authority.sources.contains_key(&file) {
            let bytes = self.body(&file, self.limits.body_bytes)?;
            self.authority.sources.insert(
                file.clone(),
                syntax::analyze_with_limits(&bytes, self.limits).map_err(|error| match error {
                    syntax::SyntaxError::Unproven(reason) => {
                        BuildError::Unproven(format!("Rust project syntax {file}: {reason}"))
                    }
                    syntax::SyntaxError::Limit(reason) => {
                        BuildError::Refused(format!("Rust project syntax {file}: {reason}"))
                    }
                })?,
            );
        }
        let syntax = self.authority.sources[&file]
            .modules
            .get(&lexical)
            .ok_or("Rust project inline module observation missing")?
            .clone();
        if self
            .authority
            .modules
            .insert(
                (target, module.clone()),
                ModuleContext {
                    file: file.clone(),
                    syntax_path: lexical.clone(),
                },
            )
            .is_some()
        {
            return Err("duplicate Rust project module context".into());
        }
        for child in syntax.children {
            let mut next_module = module.clone();
            next_module.push(child.name.clone());
            if child.inline {
                let mut next_lexical = lexical.clone();
                next_lexical.push(child.name.clone());
                let next_dir = match child.path_override {
                    Some(path) => join(
                        if lexical.is_empty() {
                            parent(&file)
                        } else {
                            &directory
                        },
                        &path,
                    )?,
                    None => join(&directory, &child.name)?,
                };
                self.visit(
                    target,
                    next_module,
                    file.clone(),
                    next_lexical,
                    next_dir,
                    stack,
                )?;
            } else {
                let explicit_path = child.path_override.is_some();
                let next_file = if let Some(path) = child.path_override {
                    join(
                        if lexical.is_empty() {
                            parent(&file)
                        } else {
                            &directory
                        },
                        &path,
                    )?
                } else {
                    let first = join(&directory, &format!("{}.rs", child.name))?;
                    let second = join(&directory, &format!("{}/mod.rs", child.name))?;
                    match (
                        self.entries.contains_key(&first),
                        self.entries.contains_key(&second),
                    ) {
                        (true, false) => first,
                        (false, true) => second,
                        _ => {
                            return Err(format!(
                                "Rust module {} has missing/competing admitted sources",
                                child.name
                            )
                            .into())
                        }
                    }
                };
                if !stack.insert(next_file.clone()) {
                    return Err("Rust module source cycle".into());
                }
                self.visit(
                    target,
                    next_module,
                    next_file.clone(),
                    Vec::new(),
                    // rustc gives #[path]-included files mod.rs-style ownership:
                    // child modules are siblings, even when named alt.rs.
                    child_directory(&next_file, explicit_path)?,
                    stack,
                )?;
                stack.remove(&next_file);
            }
        }
        Ok(())
    }
}

impl RustProjectAuthority {
    /// The tree must be the exact selected authority (or unpublished candidate).
    /// CAS returns a complete blob before byte caps can be checked, so limits
    /// bound processing/retention, not a strict peak-allocation or time envelope.
    pub fn from_admitted_tree(
        tree: &ResolvedTree,
        limits: RustProjectLimits,
        read: impl FnMut(Hash256) -> Result<Vec<u8>, String>,
    ) -> Result<Self, String> {
        Self::build(tree, limits, read).map_err(|error| error.to_string())
    }

    /// Observe valid-but-unsupported source/configuration as explicitly unknown;
    /// failed custody/reads and exhausted processing budgets refuse the plan.
    pub fn observe_admitted_tree(
        tree: &ResolvedTree,
        limits: RustProjectLimits,
        read: impl FnMut(Hash256) -> Result<Vec<u8>, String>,
    ) -> Result<RustProjectObservation, String> {
        match Self::build(tree, limits, read) {
            Ok(authority) => Ok(RustProjectObservation::Current(authority)),
            Err(BuildError::Unproven(reason)) => Ok(RustProjectObservation::Unproven {
                tree_digest: selected_tree_digest(tree)?,
                reason,
            }),
            Err(BuildError::Refused(reason)) => Err(reason),
        }
    }

    fn build(
        tree: &ResolvedTree,
        limits: RustProjectLimits,
        mut read: impl FnMut(Hash256) -> Result<Vec<u8>, String>,
    ) -> Result<Self, BuildError> {
        check_inventory(tree, limits).map_err(BuildError::Refused)?;
        let mut entries = BTreeMap::new();
        for artifact in tree.artifacts_by_path() {
            let path = std::str::from_utf8(artifact.path.as_bytes())
                .map_err(|_| "Rust project inventory has non-UTF8 path")?;
            entries.insert(path.to_owned(), (artifact.artifact_id, artifact.entry));
        }
        let tree_digest = selected_tree_digest(tree).map_err(BuildError::Refused)?;
        let mut builder = Builder {
            entries,
            limits,
            bytes: 0,
            read: &mut read,
            authority: Self {
                tree_digest,
                targets: Vec::new(),
                inputs: BTreeMap::new(),
                sources: BTreeMap::new(),
                modules: BTreeMap::new(),
                entities: BTreeMap::new(),
            },
        };
        let manifests: Vec<_> = builder
            .entries
            .keys()
            .filter(|p| p.rsplit('/').next() == Some("Cargo.toml"))
            .cloned()
            .collect();
        let mut values = BTreeMap::new();
        for path in manifests {
            let bytes = builder.body(&path, limits.manifest_bytes)?;
            let source = std::str::from_utf8(&bytes).map_err(|_| "Cargo manifest is not UTF8")?;
            let value =
                toml::from_str::<toml::Value>(source).map_err(|e| format!("{path}: {e}"))?;
            values.insert(path, value);
        }
        builder.authority.targets = targets::discover(&values, &builder.entries, limits.targets)?;
        for (index, target) in builder.authority.targets.clone().into_iter().enumerate() {
            let mut stack = BTreeSet::from([target.root.clone()]);
            builder.visit(
                index,
                Vec::new(),
                target.root.clone(),
                Vec::new(),
                child_directory(&target.root, true)?,
                &mut stack,
            )?;
        }
        Ok(builder.authority)
    }

    pub fn tree_digest(&self) -> Hash256 {
        self.tree_digest
    }
    pub fn targets(&self) -> &[CargoTarget] {
        &self.targets
    }
    pub fn source_bindings(&self) -> &BTreeMap<String, RustSourceBinding> {
        &self.inputs
    }
    pub fn contains_source(&self, file: &str) -> bool {
        self.sources.contains_key(file)
    }

    /// Bind only declarations whose identity comes from the supplied semantic
    /// universe and whose exact name/span/body matches these admitted facts.
    /// Empty and use-only modules need no fabricated carrier entity.
    pub fn bind_entities<'a>(
        &mut self,
        entities: impl IntoIterator<Item = &'a Entity>,
    ) -> Result<(), String> {
        // Failed rebinding cannot leave a previously accepted semantic universe
        // callable. Install the new universe only after every input validates.
        self.entities.clear();
        let mut found = BTreeMap::new();
        for entity in entities {
            let (Some(file), Some(span)) = (&entity.file_origin, &entity.span) else {
                continue;
            };
            let Some(input) = self.inputs.get(&file.0) else {
                continue;
            };
            let Some(source) = self.sources.get(&file.0) else {
                continue;
            };
            if entity.kind == EntityKind::Module {
                continue;
            }
            if span.file != *file
                || entity
                    .metadata
                    .extra
                    .get("blob_hash")
                    .and_then(|v| v.as_str())
                    != Some(input.digest.to_string().as_str())
            {
                return Err(format!(
                    "Rust project entity source binding differs: {}",
                    entity.id
                ));
            }
            for declaration in source
                .modules
                .values()
                .flat_map(|module| &module.declarations)
            {
                if declaration.name != entity.name
                    || declaration.start != span.start_byte
                    || declaration.end != span.end_byte
                {
                    continue;
                }
                let key = RustResolvedName {
                    file: file.0.clone(),
                    name: entity.name.clone(),
                    start: declaration.start,
                    end: declaration.end,
                };
                if found
                    .insert(key, entity.id)
                    .is_some_and(|old| old != entity.id)
                {
                    return Err("ambiguous Rust project entity identity".into());
                }
            }
        }
        self.entities = found;
        Ok(())
    }

    pub fn resolve_entity(
        &self,
        caller: &str,
        site: usize,
        module: &str,
        name: &str,
    ) -> Option<(EntityId, String)> {
        let resolved = self.resolve(caller, site, module, name)?;
        Some((*self.entities.get(&resolved)?, resolved.file))
    }

    /// Every applicable supported target/module context must select the same
    /// declaration. The caller still matches that declaration to an admitted
    /// entity and verifies the exact source call/import witness independently.
    pub fn resolve(
        &self,
        caller: &str,
        site: usize,
        module: &str,
        name: &str,
    ) -> Option<RustResolvedName> {
        let mut result = None;
        let mut found = false;
        for ((target, path), context) in &self.modules {
            if context.file != caller {
                continue;
            }
            let scope = self.sources[caller].modules.get(&context.syntax_path)?;
            if site < scope.body_start || site >= scope.body_end {
                continue;
            }
            // An inline lexical body belongs to its deepest module only.
            if self.sources[caller].modules.iter().any(|(child, body)| {
                child.len() > context.syntax_path.len()
                    && child.starts_with(&context.syntax_path)
                    && site >= body.body_start
                    && site < body.body_end
            }) {
                continue;
            }
            found = true;
            let mut parts: Vec<String> = module.split("::").map(str::to_owned).collect();
            parts.push(name.to_owned());
            let resolved = self
                .resolve_path(*target, path, path, &parts, &mut BTreeSet::new(), 0)?
                .declaration;
            if result.as_ref().is_some_and(|old| old != &resolved) {
                return None;
            }
            result = Some(resolved);
        }
        found.then_some(result).flatten()
    }

    fn resolve_path(
        &self,
        target: usize,
        from: &[String],
        caller: &[String],
        parts: &[String],
        seen: &mut BTreeSet<(Vec<String>, Vec<String>)>,
        depth: usize,
    ) -> Option<ResolvedBinding> {
        if depth > 64 || parts.is_empty() || !seen.insert((from.to_vec(), parts.to_vec())) {
            return None;
        }
        let mut module = from.to_vec();
        let mut offset = 0;
        match parts.first()?.as_str() {
            "crate" => {
                module.clear();
                offset = 1;
            }
            "self" => offset = 1,
            "super" => {
                while parts.get(offset).is_some_and(|s| s == "super") {
                    module.pop()?;
                    offset += 1;
                }
            }
            // External prelude/dependency aliases need independent package and
            // dependency resolution. An unprefixed name is not crate authority.
            _ => return None,
        }
        self.resolve_in_module(target, &module, caller, &parts[offset..], seen, depth + 1)
    }

    fn resolve_in_module(
        &self,
        target: usize,
        module: &[String],
        caller: &[String],
        parts: &[String],
        seen: &mut BTreeSet<(Vec<String>, Vec<String>)>,
        depth: usize,
    ) -> Option<ResolvedBinding> {
        if depth > 64 || parts.is_empty() {
            return None;
        }
        let context = self.modules.get(&(target, module.to_vec()))?;
        let syntax = self.sources[&context.file]
            .modules
            .get(&context.syntax_path)?;
        if let Some(child) = syntax.children.iter().find(|child| child.name == parts[0]) {
            if !visible(&child.visibility, module, caller) {
                return None;
            }
            let mut next = module.to_vec();
            next.push(child.name.clone());
            return self.resolve_in_module(target, &next, caller, &parts[1..], seen, depth + 1);
        }
        if let Some(import) = syntax.imports.get(&parts[0]) {
            if !visible(&import.visibility, module, caller) {
                return None;
            }
            // A module-valued alias needs separate binding and traversal
            // scopes. Until that representation is supported, do not lend
            // the importing module's private visibility to a caller's tail.
            if parts.len() != 1 {
                return None;
            }
            let path = import.path.clone();
            // A use path must be accessible where the use is declared, even
            // when the eventual caller could reach its private destination.
            let mut resolved = self.resolve_path(target, module, module, &path, seen, depth + 1)?;
            let exposed = exposure(&import.visibility, module)?;
            if !exposed.no_wider_than(&resolved.exposure) {
                return None;
            }
            resolved.exposure = exposed;
            return Some(resolved);
        }
        let name = parts.join("::");
        let candidates: Vec<_> = syntax
            .declarations
            .iter()
            .filter(|declaration| declaration.name == name)
            .collect();
        let [declaration] = candidates.as_slice() else {
            return None;
        };
        if !visible(&declaration.visibility, module, caller) {
            return None;
        }
        Some(ResolvedBinding {
            declaration: RustResolvedName {
                file: context.file.clone(),
                name,
                start: declaration.start,
                end: declaration.end,
            },
            exposure: exposure(&declaration.visibility, module)?,
        })
    }
}

fn visible(visibility: &syntax::Visibility, owner: &[String], caller: &[String]) -> bool {
    exposure(visibility, owner).is_some_and(|exposure| exposure.includes(caller))
}

fn exposure(visibility: &syntax::Visibility, owner: &[String]) -> Option<Exposure> {
    use syntax::Visibility;
    match visibility {
        Visibility::Public => Some(Exposure::Public),
        Visibility::Crate => Some(Exposure::Within(Vec::new())),
        Visibility::Private => Some(Exposure::Within(owner.to_vec())),
        Visibility::Super => owner
            .split_last()
            .map(|(_, parent)| Exposure::Within(parent.to_vec())),
        Visibility::InPath(path) => {
            let mut allowed = owner.to_vec();
            let mut rest = path.as_slice();
            if rest.first().is_some_and(|s| s == "crate") {
                allowed.clear();
                rest = &rest[1..];
            } else if rest.first().is_some_and(|s| s == "self") {
                rest = &rest[1..];
            } else {
                while rest.first().is_some_and(|s| s == "super") {
                    allowed.pop()?;
                    rest = &rest[1..];
                }
            }
            allowed.extend_from_slice(rest);
            owner
                .starts_with(&allowed)
                .then_some(Exposure::Within(allowed))
        }
    }
}
