// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Conditional exhaustive string-key evidence for a deliberately small CommonJS
//! subset. This is an opt-in analysis API, not a relation producer. In particular,
//! it cannot turn candidate keys into `Calls` or certify an arbitrary receiver.
//!
//! Inputs are an immutable admitted tree and verified CAS bodies. Every admitted
//! supported CommonJS module is inspected; missing, ambiguous, dynamic, or extra consumers
//! refuse the analysis. Other runtimes and non-source assets are explicitly out
//! of scope. No projected source is read. Runtime loader/intrinsic behavior is an
//! explicit *condition*, not something witnessed by these bytes.

use std::collections::{BTreeMap, BTreeSet};

use kin_blobs::BlobStore;
use kin_model::{
    ArtifactId, FilePathId, Hash256, RepoPath, ResolvedArtifact, ResolvedTree, SourceSpan,
    TreeEntry,
};
use kin_parser::key_domain::{
    analyze_import_iteration, analyze_named_export, static_requires, KeyIntrinsic,
};
use serde::Serialize;

pub const KEY_DOMAIN_ANALYZER_VERSION: u32 = 1;

/// These assumptions are supplied by the caller and echoed in the result. They
/// are never inferred from the presence of an identifier named `map`/`forEach`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyDomainCondition {
    StandardArrayMap,
    StandardAsciiStringLowercase,
    StandardArrayForEach,
    /// Standard CommonJS module isolation/cache and relative path resolution,
    /// without injected loaders, require hooks, or virtual module replacement.
    StandardCommonJsLoader,
    /// Only the inspected CommonJS modules execute: no excluded artifact,
    /// unadmitted module, or injected code can mutate these modules/intrinsics.
    /// Extension classification does not prove this runtime boundary.
    ClosedInspectedCommonJsExecution,
}

#[derive(Debug, Clone, Default)]
pub struct KeyDomainAssumptions(BTreeSet<KeyDomainCondition>);

impl KeyDomainAssumptions {
    pub fn new(conditions: impl IntoIterator<Item = KeyDomainCondition>) -> Self {
        Self(conditions.into_iter().collect())
    }
}

/// Processing/retention limits. CAS currently reads and verifies one complete
/// blob before its byte limits can be checked: these are not allocation or wall
/// clock guarantees. No limit ever returns a partial exhaustive result.
#[derive(Debug, Clone, Copy)]
pub struct KeyDomainLimits {
    pub tree_artifacts: usize,
    pub tree_path_bytes: usize,
    pub javascript_modules: usize,
    pub body_bytes: usize,
    pub total_body_bytes: usize,
    pub require_sites: usize,
    pub keys: usize,
}

impl Default for KeyDomainLimits {
    fn default() -> Self {
        Self {
            tree_artifacts: 4096,
            tree_path_bytes: 1024 * 1024,
            javascript_modules: 256,
            body_bytes: 1024 * 1024,
            total_body_bytes: 8 * 1024 * 1024,
            require_sites: 4096,
            keys: 4096,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RefusalKind {
    Limit,
    MissingArtifact,
    UnsupportedInventory,
    UnavailableBody,
    UnsupportedSource,
    ModuleResolution,
    AdditionalConsumer,
    MissingAssumption,
}

#[derive(Debug, thiserror::Error)]
#[error("key domain unproven ({kind:?}): {reason}")]
pub struct KeyDomainRefusal {
    pub kind: RefusalKind,
    pub reason: String,
}

fn refuse(kind: RefusalKind, reason: impl Into<String>) -> KeyDomainRefusal {
    KeyDomainRefusal {
        kind,
        reason: reason.into(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WitnessRole {
    Export,
    ImportIteration,
    ModuleInventory,
    PackageConfiguration,
}

#[derive(Debug, Clone, Serialize)]
pub struct KeySourceWitness {
    pub artifact: ArtifactId,
    pub path: RepoPath,
    pub body_digest: Hash256,
    pub role: WitnessRole,
    pub spans: Vec<SourceSpan>,
}

/// A complete key set within the supported source model under `conditions`.
/// Fields have no public constructors/Deserialize implementation: successful
/// bounded analysis is the only way this crate constructs an instance.
///
/// It is neither runtime attestation nor proof that every key is reached, that a
/// write succeeds, or that an owner remains unchanged. There is intentionally no
/// conversion to an existing graph relation/candidate. Tree/body changes require
/// new analysis; this API provides no automatic persistence/invalidation hook.
#[derive(Debug, Clone, Serialize)]
pub struct ExhaustiveKeyDomain {
    analyzer_version: u32,
    inventory_scope: &'static str,
    tree_digest: Hash256,
    keys: Vec<String>,
    conditions: Vec<KeyDomainCondition>,
    witnesses: Vec<KeySourceWitness>,
    javascript_modules: usize,
    excluded_artifacts: usize,
    source_bytes: usize,
}

impl ExhaustiveKeyDomain {
    pub fn keys(&self) -> &[String] {
        &self.keys
    }
    pub fn conditions(&self) -> &[KeyDomainCondition] {
        &self.conditions
    }
    pub fn witnesses(&self) -> &[KeySourceWitness] {
        &self.witnesses
    }
    pub fn tree_digest(&self) -> Hash256 {
        self.tree_digest
    }
    pub fn javascript_modules(&self) -> usize {
        self.javascript_modules
    }
    pub fn excluded_artifacts(&self) -> usize {
        self.excluded_artifacts
    }
}

struct ModuleBody<'a> {
    artifact: &'a ResolvedArtifact,
    body: Vec<u8>,
    requires: Vec<String>,
}

fn checked_add(
    total: &mut usize,
    amount: usize,
    cap: usize,
    what: &str,
) -> Result<(), KeyDomainRefusal> {
    *total = total
        .checked_add(amount)
        .filter(|next| *next <= cap)
        .ok_or_else(|| refuse(RefusalKind::Limit, format!("{what} exceeds {cap}")))?;
    Ok(())
}

fn body(
    blobs: &BlobStore,
    artifact: &ResolvedArtifact,
    limits: KeyDomainLimits,
    total: &mut usize,
) -> Result<Vec<u8>, KeyDomainRefusal> {
    let TreeEntry::Blob { hash, .. } = artifact.entry else {
        return Err(refuse(
            RefusalKind::UnsupportedInventory,
            format!("{} is not an admitted regular body", artifact.path),
        ));
    };
    let bytes = blobs.read(&hash).map_err(|error| {
        refuse(
            RefusalKind::UnavailableBody,
            format!("{}: {error}", artifact.path),
        )
    })?;
    if bytes.len() > limits.body_bytes {
        return Err(refuse(
            RefusalKind::Limit,
            format!("{} exceeds per-body byte limit", artifact.path),
        ));
    }
    checked_add(
        total,
        bytes.len(),
        limits.total_body_bytes,
        "total source/configuration bytes",
    )?;
    Ok(bytes)
}

fn witness(
    artifact: &ResolvedArtifact,
    role: WitnessRole,
    spans: Vec<SourceSpan>,
) -> KeySourceWitness {
    KeySourceWitness {
        artifact: artifact.artifact_id,
        path: artifact.path.clone(),
        // Inventory admission above establishes a regular blob.
        body_digest: artifact
            .entry
            .blob_identity()
            .expect("admitted regular blob"),
        role,
        spans,
    }
}

/// Resolve a supported relative CommonJS request from exact admitted paths. We
/// deliberately refuse competing candidates rather than guessing Node's ordered
/// preference. Package manifests/native/JSON targets remain unsupported.
fn resolve<'a>(
    tree: &'a ResolvedTree,
    source: &RepoPath,
    request: &str,
) -> Result<&'a ResolvedArtifact, KeyDomainRefusal> {
    if !(request.starts_with("./") || request.starts_with("../"))
        || request.contains(['\\', '?', '#', '\0'])
    {
        return Err(refuse(
            RefusalKind::ModuleResolution,
            format!("{source}: unsupported module request {request:?}"),
        ));
    }
    let path = source.as_utf8().ok_or_else(|| {
        refuse(
            RefusalKind::UnsupportedInventory,
            "non-UTF8 JavaScript path",
        )
    })?;
    let mut segments: Vec<&str> = path.split('/').collect();
    segments.pop();
    for segment in request.split('/') {
        match segment {
            "." => {}
            ".." => {
                if segments.pop().is_none() {
                    return Err(refuse(
                        RefusalKind::ModuleResolution,
                        "relative request escapes admitted repository",
                    ));
                }
            }
            "" => {
                return Err(refuse(
                    RefusalKind::ModuleResolution,
                    "empty module path component",
                ))
            }
            value => segments.push(value),
        }
    }
    let base = segments.join("/");
    if base.is_empty() {
        return Err(refuse(
            RefusalKind::ModuleResolution,
            "repository-root module request unsupported",
        ));
    }
    let candidates = [
        base.clone(),
        format!("{base}.js"),
        format!("{base}.json"),
        format!("{base}.node"),
        format!("{base}/index.js"),
        format!("{base}/index.json"),
        format!("{base}/index.node"),
        format!("{base}/package.json"),
    ];
    let mut found = None;
    for candidate in candidates {
        let candidate = RepoPath::from_utf8(candidate)
            .map_err(|e| refuse(RefusalKind::ModuleResolution, e.to_string()))?;
        if let Some(artifact) = tree.artifact_at_path(&candidate) {
            if found.is_some() {
                return Err(refuse(
                    RefusalKind::ModuleResolution,
                    format!("{source}: ambiguous module request {request:?}"),
                ));
            }
            found = Some(artifact);
        }
    }
    let target = found.ok_or_else(|| {
        refuse(
            RefusalKind::ModuleResolution,
            format!("{source}: missing module {request:?}"),
        )
    })?;
    let target_path = target.path.as_utf8().unwrap_or("");
    if !(target_path.ends_with(".js") || target_path.ends_with(".cjs"))
        || !matches!(target.entry, TreeEntry::Blob { .. })
    {
        return Err(refuse(
            RefusalKind::ModuleResolution,
            format!("{} is not supported CommonJS source", target.path),
        ));
    }
    Ok(target)
}

/// Analyze a named imported binding's complete iteration key set. The immutable
/// tree chooses source identity and bytes; paths resolve imports but never confer
/// artifact identity. No raw-filesystem source reads or public API calls occur.
pub fn analyze_imported_keys(
    tree: &ResolvedTree,
    blobs: &BlobStore,
    importer: ArtifactId,
    binding: &str,
    limits: KeyDomainLimits,
    assumptions: &KeyDomainAssumptions,
) -> Result<ExhaustiveKeyDomain, KeyDomainRefusal> {
    if tree.len() > limits.tree_artifacts {
        return Err(refuse(
            RefusalKind::Limit,
            "tree artifact count exceeds limit",
        ));
    }
    let mut path_bytes = 0;
    for artifact in tree.artifacts() {
        checked_add(
            &mut path_bytes,
            artifact.path.as_bytes().len(),
            limits.tree_path_bytes,
            "tree path bytes",
        )?;
    }
    if tree.get(&importer).is_none() {
        return Err(refuse(
            RefusalKind::MissingArtifact,
            "importer identity is absent from admitted tree",
        ));
    }

    let mut modules = BTreeMap::new();
    let mut witnesses = Vec::new();
    let mut total_bytes = 0;
    let mut require_sites = 0;
    let mut excluded = 0;
    for artifact in tree.artifacts() {
        // A symlink/gitlink can hide an entire alternate code inventory.
        if !matches!(artifact.entry, TreeEntry::Blob { .. }) {
            return Err(refuse(
                RefusalKind::UnsupportedInventory,
                format!("uninspectable tree entry {}", artifact.path),
            ));
        }
        let path = artifact.path.as_utf8().ok_or_else(|| {
            refuse(
                RefusalKind::UnsupportedInventory,
                "non-UTF8 inventory path is outside the supported module model",
            )
        })?;
        let filename = path.rsplit('/').next().unwrap_or(path);
        let extension = filename.rsplit_once('.').map(|(_, extension)| extension);
        if filename == "package.json" {
            let bytes = body(blobs, artifact, limits, &mut total_bytes)?;
            let config: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| {
                refuse(
                    RefusalKind::UnsupportedInventory,
                    format!("{path}: invalid package configuration: {e}"),
                )
            })?;
            let object = config.as_object().ok_or_else(|| {
                refuse(
                    RefusalKind::UnsupportedInventory,
                    "package configuration is not an object",
                )
            })?;
            if object
                .get("type")
                .is_some_and(|kind| kind.as_str() != Some("commonjs"))
            {
                return Err(refuse(
                    RefusalKind::UnsupportedInventory,
                    format!("{path}: non-CommonJS package scope"),
                ));
            }
            witnesses.push(witness(artifact, WitnessRole::PackageConfiguration, vec![]));
            continue;
        }
        match extension {
            Some("js" | "cjs") => {}
            Some("jsx" | "mjs" | "ts" | "tsx" | "mts" | "cts") | None => {
                return Err(refuse(
                    RefusalKind::UnsupportedInventory,
                    format!(
                    "{path}: potentially executable source outside supported CommonJS inventory"
                ),
                ))
            }
            _ => {
                excluded += 1;
                continue;
            }
        }
        if modules.len() >= limits.javascript_modules {
            return Err(refuse(
                RefusalKind::Limit,
                "JavaScript module count exceeds limit",
            ));
        }
        let bytes = body(blobs, artifact, limits, &mut total_bytes)?;
        let requires = static_requires(&bytes)
            .map_err(|e| refuse(RefusalKind::UnsupportedSource, format!("{path}: {e}")))?;
        checked_add(
            &mut require_sites,
            requires.len(),
            limits.require_sites,
            "require sites",
        )?;
        modules.insert(
            artifact.artifact_id,
            ModuleBody {
                artifact,
                body: bytes,
                requires,
            },
        );
    }
    let importing = modules.get(&importer).ok_or_else(|| {
        refuse(
            RefusalKind::UnsupportedInventory,
            "importer is not supported JavaScript source",
        )
    })?;
    let importing_file = FilePathId::new(importing.artifact.path.as_utf8().expect("checked UTF8"));
    let import =
        analyze_import_iteration(&importing.body, &importing_file, binding).map_err(|e| {
            refuse(
                RefusalKind::UnsupportedSource,
                format!("{importing_file}: {e}"),
            )
        })?;
    let producer = resolve(tree, &importing.artifact.path, &import.module)?;
    if producer.artifact_id == importer {
        return Err(refuse(
            RefusalKind::ModuleResolution,
            "self/cyclic key export cannot establish initialization",
        ));
    }
    let exporting = modules.get(&producer.artifact_id).ok_or_else(|| {
        refuse(
            RefusalKind::UnsupportedInventory,
            "export module was not fully inspected",
        )
    })?;
    let export_file = FilePathId::new(producer.path.as_utf8().expect("checked UTF8"));
    let export =
        analyze_named_export(&exporting.body, &export_file, &import.export_name).map_err(|e| {
            refuse(
                RefusalKind::UnsupportedSource,
                format!("{export_file}: {e}"),
            )
        })?;
    if export.keys.len() > limits.keys {
        return Err(refuse(
            RefusalKind::Limit,
            "exported key count exceeds limit",
        ));
    }

    // Complete inventory, including unreachable modules: no unseen/dynamic code
    // is silently treated as an inert consumer. The unique consumer is checked
    // independently from its source-level occurrence/escape analysis.
    let mut producer_consumers = 0;
    for (identity, module) in &modules {
        for request in &module.requires {
            let target = resolve(tree, &module.artifact.path, request)?;
            if target.artifact_id == producer.artifact_id {
                producer_consumers += 1;
                if *identity != importer || producer_consumers > 1 {
                    return Err(refuse(
                        RefusalKind::AdditionalConsumer,
                        format!(
                            "{} adds another consumer of {}",
                            module.artifact.path, producer.path
                        ),
                    ));
                }
            }
        }
    }
    if producer_consumers != 1 {
        return Err(refuse(
            RefusalKind::AdditionalConsumer,
            "no unique exact import occurrence was inventoried",
        ));
    }

    let mut required = BTreeSet::from([
        KeyDomainCondition::StandardCommonJsLoader,
        KeyDomainCondition::ClosedInspectedCommonJsExecution,
    ]);
    for intrinsic in import
        .required_intrinsics
        .iter()
        .chain(&export.required_intrinsics)
    {
        required.insert(match intrinsic {
            KeyIntrinsic::ArrayMap => KeyDomainCondition::StandardArrayMap,
            KeyIntrinsic::StringAsciiLowercase => KeyDomainCondition::StandardAsciiStringLowercase,
            KeyIntrinsic::ArrayForEach => KeyDomainCondition::StandardArrayForEach,
        });
    }
    for condition in &required {
        if !assumptions.0.contains(condition) {
            return Err(refuse(
                RefusalKind::MissingAssumption,
                format!("required conditional premise {condition:?} was not supplied"),
            ));
        }
    }
    let keys = export
        .keys
        .into_iter()
        .map(|key| {
            if import.ascii_lowercase {
                key.to_ascii_lowercase()
            } else {
                key
            }
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    for (identity, module) in &modules {
        let (role, spans) = if *identity == importer {
            (WitnessRole::ImportIteration, import.spans.clone())
        } else if *identity == producer.artifact_id {
            (WitnessRole::Export, export.spans.clone())
        } else {
            (WitnessRole::ModuleInventory, vec![])
        };
        witnesses.push(witness(module.artifact, role, spans));
    }
    let tree_bytes = serde_json::to_vec(tree)
        .map_err(|e| refuse(RefusalKind::UnsupportedInventory, e.to_string()))?;
    Ok(ExhaustiveKeyDomain {
        analyzer_version: KEY_DOMAIN_ANALYZER_VERSION,
        inventory_scope: "all admitted .js/.cjs modules and package.json; other runtimes/assets excluded; unsupported JavaScript, indirection and unknown consumers refuse",
        tree_digest: kin_blobs::digest(&tree_bytes), keys, conditions: required.into_iter().collect(), witnesses,
        javascript_modules: modules.len(), excluded_artifacts: excluded, source_bytes: total_bytes,
    })
}
