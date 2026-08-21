// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Persisted, graph-native repository admission policy.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::collections::BTreeSet;

use crate::{
    AuthorId, Hash256, ModelError, RepoPath, ResolvedTree, Result, TreeEntry, WorkspaceId,
};

pub const ADMISSION_POLICY_SEMANTICS_VERSION: u32 = 2;

/// Content identity of a resolved shared admission policy.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
pub struct AdmissionPolicyHash(pub Hash256);

impl std::fmt::Display for AdmissionPolicyHash {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
pub struct LocalOverlayHash(pub Hash256);

impl std::fmt::Display for LocalOverlayHash {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(formatter)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionRuleSourceKind {
    GitIgnore,
    KinIgnore,
}

/// One branch-versioned gitwildmatch source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdmissionRuleSource {
    pub kind: AdmissionRuleSourceKind,
    pub path: RepoPath,
    /// Directory against which patterns in this source are rooted. `None`
    /// denotes the repository root.
    pub base_directory: Option<RepoPath>,
    pub body_hash: Hash256,
    pub body_len: u64,
    /// Low-to-high precedence. Values must be contiguous from zero.
    pub precedence: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum SensitiveArtifactKind {
    Blob { executable: bool },
    Symlink,
}

/// Explicit approval for exactly one sensitive path, digest, and entry kind.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SensitiveArtifactAllowance {
    pub path: RepoPath,
    pub content_hash: Hash256,
    pub kind: SensitiveArtifactKind,
    pub approved_by: AuthorId,
    pub reason: String,
}

impl SensitiveArtifactAllowance {
    pub fn validate(&self) -> Result<()> {
        if self.reason.trim().is_empty() {
            return Err(ModelError::InvalidOperation(format!(
                "sensitive allowance for {} requires a reason",
                self.path
            )));
        }
        Ok(())
    }

    pub fn matches(
        &self,
        path: &RepoPath,
        content_hash: Hash256,
        kind: SensitiveArtifactKind,
    ) -> bool {
        self.path == *path && self.content_hash == content_hash && self.kind == kind
    }
}

/// Replicated admission policy resolved at a semantic change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SharedAdmissionPolicy {
    pub semantics_version: u32,
    pub generation: u64,
    pub sources: Vec<AdmissionRuleSource>,
    pub sensitive_allowances: Vec<SensitiveArtifactAllowance>,
    pub hash: AdmissionPolicyHash,
}

#[derive(Serialize)]
struct SharedAdmissionPolicyIdentity<'a> {
    semantics_version: u32,
    sources: &'a [AdmissionRuleSource],
    sensitive_allowances: &'a [SensitiveArtifactAllowance],
}

impl SharedAdmissionPolicy {
    pub fn new(
        generation: u64,
        mut sources: Vec<AdmissionRuleSource>,
        mut sensitive_allowances: Vec<SensitiveArtifactAllowance>,
    ) -> Result<Self> {
        sources.sort_by_key(|source| source.precedence);
        sort_canonical(&mut sensitive_allowances)?;
        let mut policy = Self {
            semantics_version: ADMISSION_POLICY_SEMANTICS_VERSION,
            generation,
            sources,
            sensitive_allowances,
            hash: AdmissionPolicyHash(Hash256::from_bytes([0; 32])),
        };
        policy.validate_structure()?;
        policy.hash = policy.compute_hash()?;
        Ok(policy)
    }

    pub fn empty(generation: u64) -> Self {
        Self::new(generation, Vec::new(), Vec::new())
            .expect("empty admission policy is structurally valid")
    }

    pub const fn stamp(&self) -> AdmissionPolicyStamp {
        AdmissionPolicyStamp {
            hash: self.hash,
            generation: self.generation,
        }
    }

    /// Derive the complete shared policy from one exact graph-owned tree.
    ///
    /// The caller resolves source-body lengths through immutable CAS
    /// authority. This method never reads a checkout and never accepts a
    /// caller-provided matcher verdict. Symlinks and Gitlinks named like rule
    /// files remain ordinary tree artifacts; only blob entries contribute
    /// policy sources.
    pub fn derive_from_tree(
        first_parent: Option<&Self>,
        tree: &ResolvedTree,
        source_body_len: impl FnMut(Hash256) -> Result<u64>,
    ) -> Result<(Self, Option<AdmissionPolicyDelta>)> {
        Self::derive_from_tree_with_allowances(first_parent, tree, source_body_len, |_| {
            Err(ModelError::InvalidOperation(format!(
                "this build cannot read {SENSITIVE_ALLOWANCE_SOURCE_PATH}: upgrade to a consumer \
                 that derives sensitive-artifact allowances, or remove the file"
            )))
        })
    }

    /// Derive the complete shared policy, including approvals carried by the tree.
    ///
    /// Separate from [`Self::derive_from_tree`] so consumers adopt allowance
    /// derivation on their own schedule rather than in one synchronized bump.
    /// The older entry point stays callable and refuses by name when a tree
    /// carries approvals it cannot read, which is the loud half of that trade:
    /// a consumer that silently ignored the file would drop approvals a
    /// reviewer believes are in force.
    pub fn derive_from_tree_with_allowances(
        first_parent: Option<&Self>,
        tree: &ResolvedTree,
        mut source_body_len: impl FnMut(Hash256) -> Result<u64>,
        mut allowance_body: impl FnMut(Hash256) -> Result<Vec<u8>>,
    ) -> Result<(Self, Option<AdmissionPolicyDelta>)> {
        let mut sources = Vec::new();
        let mut allowance_blob = None;
        for artifact in tree.artifacts() {
            if let Some(hash) = sensitive_allowance_source_blob(artifact)? {
                allowance_blob = Some(hash);
                continue;
            }
            let Some((base_directory, kind)) = shared_rule_source_path(&artifact.path)? else {
                continue;
            };
            let TreeEntry::Blob { hash, .. } = artifact.entry else {
                continue;
            };
            sources.push(AdmissionRuleSource {
                kind,
                path: artifact.path.clone(),
                base_directory,
                body_hash: hash,
                body_len: source_body_len(hash)?,
                precedence: 0,
            });
        }
        let sensitive_allowances = match allowance_blob {
            Some(hash) => parse_sensitive_allowances(&allowance_body(hash)?)?,
            None => Vec::new(),
        };

        sources.sort_by(compare_rule_sources);
        for (index, source) in sources.iter_mut().enumerate() {
            source.precedence = u32::try_from(index).map_err(|_| {
                ModelError::InvalidOperation(
                    "shared admission source count exceeds u32".to_string(),
                )
            })?;
        }

        let Some(old) = first_parent else {
            let policy = Self::new(0, sources, sensitive_allowances)?;
            let delta = AdmissionPolicyDelta::initialize(policy.clone());
            delta.validate()?;
            return Ok((policy, Some(delta)));
        };

        if old.sources == sources && old.sensitive_allowances == sensitive_allowances {
            return Ok((old.clone(), None));
        }

        let generation = old.generation.checked_add(1).ok_or_else(|| {
            ModelError::InvalidOperation("shared admission-policy generation exhausted".to_string())
        })?;
        let policy = Self::new(generation, sources, sensitive_allowances)?;
        let delta = AdmissionPolicyDelta::update(old.clone(), policy.clone());
        delta.validate()?;
        Ok((policy, Some(delta)))
    }

    pub fn validate(&self) -> Result<()> {
        self.validate_structure()?;
        let computed = self.compute_hash()?;
        if computed != self.hash {
            return Err(ModelError::InvalidOperation(format!(
                "admission policy hash {} recomputes to {}",
                self.hash, computed
            )));
        }
        Ok(())
    }

    fn validate_structure(&self) -> Result<()> {
        if self.semantics_version != ADMISSION_POLICY_SEMANTICS_VERSION {
            return Err(ModelError::InvalidOperation(format!(
                "unsupported admission semantics version {}",
                self.semantics_version
            )));
        }
        let mut source_paths = BTreeSet::new();
        for (index, source) in self.sources.iter().enumerate() {
            if source.precedence
                != u32::try_from(index).map_err(|_| {
                    ModelError::InvalidOperation("admission source count exceeds u32".to_string())
                })?
            {
                return Err(ModelError::InvalidOperation(
                    "admission source precedence must be contiguous from zero".to_string(),
                ));
            }
            if !source_paths.insert(source.path.clone()) {
                return Err(ModelError::InvalidOperation(format!(
                    "admission policy contains duplicate source {}",
                    source.path
                )));
            }
        }
        let mut allowance_paths = BTreeSet::new();
        for allowance in &self.sensitive_allowances {
            allowance.validate()?;
            if !allowance_paths.insert(allowance.path.clone()) {
                return Err(ModelError::InvalidOperation(format!(
                    "admission policy contains more than one sensitive allowance for {}",
                    allowance.path
                )));
            }
        }
        let mut canonical_allowances = self.sensitive_allowances.clone();
        sort_canonical(&mut canonical_allowances)?;
        if canonical_allowances != self.sensitive_allowances {
            return Err(ModelError::InvalidOperation(
                "sensitive allowances are not in canonical order".to_string(),
            ));
        }
        Ok(())
    }

    fn compute_hash(&self) -> Result<AdmissionPolicyHash> {
        let identity = SharedAdmissionPolicyIdentity {
            semantics_version: self.semantics_version,
            sources: &self.sources,
            sensitive_allowances: &self.sensitive_allowances,
        };
        hash_json(b"kin-shared-admission-policy-v1\0", &identity).map(AdmissionPolicyHash)
    }
}

/// Root-level tracked file carrying explicit sensitive-artifact approvals.
///
/// The approval rides the tree rather than policy state on purpose. Policy
/// state dies at the repository boundary, so a teammate who clones and runs
/// `kin init` would hit the same wall a colleague already cleared. A tracked
/// file survives clone and convert, derives on init, and shows up in review as
/// an ordinary diff.
///
/// # Format
///
/// UTF-8 text. Blank lines and lines beginning with `#` are ignored anywhere.
/// The first line that is neither must be the version header
/// `kin-allowances 1`. Every line after it is one approval, five tab-separated
/// fields: the repository path, the artifact's sha256 as 64 hex digits, the
/// entry kind as `blob`, `blob+x` or `symlink`, the approver, and a reason that
/// runs to the end of the line and must not be blank.
///
/// The first three fields are the path, digest and entry kind the admission
/// refusal names, and all three must match for the approval to apply, so
/// re-editing a secret re-blocks it.
///
/// The file is the approval set rather than an addition to it: deleting a line
/// revokes that approval on the next derivation. At most one line per path; a
/// changed digest edits the existing line rather than adding a second.
///
/// A path holding a tab byte, or one that is not valid UTF-8, cannot be written
/// here and is refused by name rather than mis-parsed.
pub const SENSITIVE_ALLOWANCE_SOURCE_PATH: &str = ".kin-allowances";

const SENSITIVE_ALLOWANCE_FORMAT_HEADER: &str = "kin-allowances 1";

/// Parse the tracked allowance file into canonical, validated approvals.
///
/// Every refusal is loud. A malformed file fails the derivation rather than
/// resolving to an empty approval set, because a silently ignored file leaves
/// an author blocked by a rule they believe they cleared, and leaves a reader
/// unable to tell an empty file from an unreadable one.
pub fn parse_sensitive_allowances(body: &[u8]) -> Result<Vec<SensitiveArtifactAllowance>> {
    let text = std::str::from_utf8(body).map_err(|error| {
        ModelError::InvalidOperation(format!(
            "{SENSITIVE_ALLOWANCE_SOURCE_PATH} is not valid UTF-8: {error}"
        ))
    })?;
    let mut allowances = Vec::new();
    let mut header_seen = false;
    for (index, raw) in text.lines().enumerate() {
        let number = index + 1;
        let line = raw.trim_end_matches(['\r']);
        if line.trim().is_empty() || line.starts_with('#') {
            continue;
        }
        if !header_seen {
            if line.trim() != SENSITIVE_ALLOWANCE_FORMAT_HEADER {
                return Err(ModelError::InvalidOperation(format!(
                    "{SENSITIVE_ALLOWANCE_SOURCE_PATH} line {number} must be the format header \
                     \"{SENSITIVE_ALLOWANCE_FORMAT_HEADER}\", found \"{line}\""
                )));
            }
            header_seen = true;
            continue;
        }
        let allowance = parse_sensitive_allowance_line(line, number)?;
        if let Some(earlier) = allowances
            .iter()
            .position(|seen: &SensitiveArtifactAllowance| seen.path == allowance.path)
        {
            return Err(ModelError::InvalidOperation(format!(
                "{SENSITIVE_ALLOWANCE_SOURCE_PATH} line {number}: {} is already approved on an \
                 earlier line; one approval per path, and a changed digest needs the existing \
                 line edited rather than a second one",
                allowances[earlier].path
            )));
        }
        allowances.push(allowance);
    }
    if !header_seen {
        return Err(ModelError::InvalidOperation(format!(
            "{SENSITIVE_ALLOWANCE_SOURCE_PATH} is missing its format header \
             \"{SENSITIVE_ALLOWANCE_FORMAT_HEADER}\""
        )));
    }
    sort_canonical(&mut allowances)?;
    Ok(allowances)
}

fn parse_sensitive_allowance_line(line: &str, number: usize) -> Result<SensitiveArtifactAllowance> {
    let invalid = |detail: String| {
        ModelError::InvalidOperation(format!(
            "{SENSITIVE_ALLOWANCE_SOURCE_PATH} line {number}: {detail}"
        ))
    };
    let mut fields = line.splitn(5, '\t');
    let path = fields
        .next()
        .ok_or_else(|| invalid("missing path".to_string()))?;
    let digest = fields
        .next()
        .ok_or_else(|| invalid("missing digest".to_string()))?;
    let kind = fields
        .next()
        .ok_or_else(|| invalid("missing entry kind".to_string()))?;
    let approved_by = fields
        .next()
        .ok_or_else(|| invalid("missing approver".to_string()))?;
    let reason = fields.next().ok_or_else(|| {
        invalid(
            "expected five tab-separated fields: path, digest, kind, approver, reason".to_string(),
        )
    })?;

    let path = RepoPath::from_utf8(path)
        .map_err(|error| invalid(format!("invalid path \"{path}\": {error}")))?;
    let decoded = hex::decode(digest)
        .map_err(|error| invalid(format!("digest \"{digest}\" is not hex: {error}")))?;
    let bytes: [u8; 32] = decoded.as_slice().try_into().map_err(|_| {
        invalid(format!(
            "digest \"{digest}\" must be 32 bytes of hex, found {}",
            decoded.len()
        ))
    })?;
    let kind = match kind {
        "blob" => SensitiveArtifactKind::Blob { executable: false },
        "blob+x" => SensitiveArtifactKind::Blob { executable: true },
        "symlink" => SensitiveArtifactKind::Symlink,
        other => {
            return Err(invalid(format!(
                "entry kind \"{other}\" must be one of blob, blob+x, symlink"
            )))
        }
    };
    if approved_by.trim().is_empty() {
        return Err(invalid("approver must not be empty".to_string()));
    }
    let allowance = SensitiveArtifactAllowance {
        path,
        content_hash: Hash256::from_bytes(bytes),
        kind,
        approved_by: AuthorId::new(approved_by),
        reason: reason.to_string(),
    };
    allowance
        .validate()
        .map_err(|error| invalid(error.to_string()))?;
    Ok(allowance)
}

/// The blob carrying root-level approvals, if this artifact is that file.
///
/// A nested copy is refused rather than ignored. Silently skipping one would
/// leave an author staring at a file they wrote, in a directory that looks
/// reasonable, with no approval and no explanation.
fn sensitive_allowance_source_blob(artifact: &crate::ResolvedArtifact) -> Result<Option<Hash256>> {
    let bytes = artifact.path.as_bytes();
    let name = match bytes.iter().rposition(|byte| *byte == b'/') {
        Some(separator) => &bytes[separator + 1..],
        None => bytes,
    };
    if name != SENSITIVE_ALLOWANCE_SOURCE_PATH.as_bytes() {
        return Ok(None);
    }
    if bytes != SENSITIVE_ALLOWANCE_SOURCE_PATH.as_bytes() {
        return Err(ModelError::InvalidOperation(format!(
            "sensitive allowances are read only from the repository root: move {} to {}",
            artifact.path, SENSITIVE_ALLOWANCE_SOURCE_PATH
        )));
    }
    match artifact.entry {
        TreeEntry::Blob { hash, .. } => Ok(Some(hash)),
        _ => Err(ModelError::InvalidOperation(format!(
            "{SENSITIVE_ALLOWANCE_SOURCE_PATH} must be a regular file"
        ))),
    }
}

fn shared_rule_source_path(
    path: &RepoPath,
) -> Result<Option<(Option<RepoPath>, AdmissionRuleSourceKind)>> {
    let bytes = path.as_bytes();
    let (base, name) = match bytes.iter().rposition(|byte| *byte == b'/') {
        Some(separator) => (Some(&bytes[..separator]), &bytes[separator + 1..]),
        None => (None, bytes),
    };
    let kind = match name {
        b".gitignore" => AdmissionRuleSourceKind::GitIgnore,
        b".kinignore" => AdmissionRuleSourceKind::KinIgnore,
        _ => return Ok(None),
    };
    let base_directory = base
        .map(RepoPath::from_bytes)
        .transpose()
        .map_err(|error| {
            ModelError::InvalidOperation(format!(
                "invalid shared admission source base for {path}: {error}"
            ))
        })?;
    Ok(Some((base_directory, kind)))
}

fn compare_rule_sources(left: &AdmissionRuleSource, right: &AdmissionRuleSource) -> Ordering {
    rule_source_depth(left)
        .cmp(&rule_source_depth(right))
        .then_with(|| rule_source_base(left).cmp(rule_source_base(right)))
        .then_with(|| rule_source_kind_rank(left.kind).cmp(&rule_source_kind_rank(right.kind)))
        .then_with(|| left.path.as_bytes().cmp(right.path.as_bytes()))
}

fn rule_source_depth(source: &AdmissionRuleSource) -> usize {
    source.base_directory.as_ref().map_or(0, |base| {
        1 + base.as_bytes().iter().filter(|byte| **byte == b'/').count()
    })
}

fn rule_source_base(source: &AdmissionRuleSource) -> &[u8] {
    source
        .base_directory
        .as_ref()
        .map_or(&[], RepoPath::as_bytes)
}

const fn rule_source_kind_rank(kind: AdmissionRuleSourceKind) -> u8 {
    match kind {
        AdmissionRuleSourceKind::GitIgnore => 0,
        AdmissionRuleSourceKind::KinIgnore => 1,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdmissionPolicyStamp {
    pub hash: AdmissionPolicyHash,
    pub generation: u64,
}

/// Exact, self-inverting shared-policy transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdmissionPolicyDelta {
    pub old: Option<SharedAdmissionPolicy>,
    pub new: Option<SharedAdmissionPolicy>,
}

impl AdmissionPolicyDelta {
    pub fn initialize(new: SharedAdmissionPolicy) -> Self {
        Self {
            old: None,
            new: Some(new),
        }
    }

    pub fn update(old: SharedAdmissionPolicy, new: SharedAdmissionPolicy) -> Self {
        Self {
            old: Some(old),
            new: Some(new),
        }
    }

    pub fn inverse(&self) -> Self {
        Self {
            old: self.new.clone(),
            new: self.old.clone(),
        }
    }

    pub fn validate(&self) -> Result<()> {
        if self.old.is_none() && self.new.is_none() {
            return Err(ModelError::InvalidOperation(
                "admission policy delta has no old or new state".to_string(),
            ));
        }
        if self.old == self.new {
            return Err(ModelError::InvalidOperation(
                "admission policy delta is a no-op".to_string(),
            ));
        }
        if let Some(old) = &self.old {
            old.validate()?;
        }
        if let Some(new) = &self.new {
            new.validate()?;
        }
        match (&self.old, &self.new) {
            (None, Some(new)) if new.generation != 0 => {
                return Err(ModelError::InvalidOperation(
                    "initial admission policy generation must be zero".to_string(),
                ));
            }
            (Some(old), Some(new))
                if new.generation != old.generation.saturating_add(1)
                    && old.generation != new.generation.saturating_add(1) =>
            {
                return Err(ModelError::InvalidOperation(format!(
                    "admission policy generations {} and {} are not adjacent",
                    old.generation, new.generation
                )));
            }
            _ => {}
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum LocalAdmissionRuleSourceKind {
    GitInfoExclude,
    GitGlobalExclude,
    KinLocal,
}

/// Filesystem case behavior frozen into one local admission overlay.
///
/// This is authority, not a host hint: the exact same policy bytes produce
/// different answers under case-sensitive and ASCII-folded matching. Persisting
/// the behavior in the overlay identity keeps reopen, replication-local
/// workspace state, and later scans on the same matcher semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AdmissionCase {
    Sensitive,
    FoldAscii,
}

/// One captured local-only gitwildmatch source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LocalAdmissionRuleSource {
    pub kind: LocalAdmissionRuleSourceKind,
    pub body_hash: Hash256,
    pub body_len: u64,
    pub precedence: u32,
}

/// Frozen local overlay. It changes only through an explicit refresh.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FrozenLocalOverlay {
    pub workspace_id: WorkspaceId,
    pub generation: u64,
    pub case: AdmissionCase,
    pub sources: Vec<LocalAdmissionRuleSource>,
    pub hash: LocalOverlayHash,
}

#[derive(Serialize)]
struct LocalOverlayIdentity<'a> {
    case: AdmissionCase,
    sources: &'a [LocalAdmissionRuleSource],
}

impl FrozenLocalOverlay {
    pub fn new(
        workspace_id: WorkspaceId,
        generation: u64,
        case: AdmissionCase,
        mut sources: Vec<LocalAdmissionRuleSource>,
    ) -> Result<Self> {
        sources.sort_by_key(|source| source.precedence);
        let hash = LocalOverlayHash(hash_json(
            b"kin-local-admission-overlay-v2\0",
            &LocalOverlayIdentity {
                case,
                sources: &sources,
            },
        )?);
        let overlay = Self {
            workspace_id,
            generation,
            case,
            sources,
            hash,
        };
        overlay.validate()?;
        Ok(overlay)
    }

    pub fn validate(&self) -> Result<()> {
        for (index, source) in self.sources.iter().enumerate() {
            if source.precedence
                != u32::try_from(index).map_err(|_| {
                    ModelError::InvalidOperation(
                        "local admission source count exceeds u32".to_string(),
                    )
                })?
            {
                return Err(ModelError::InvalidOperation(
                    "local admission source precedence must be contiguous from zero".to_string(),
                ));
            }
        }
        let computed = LocalOverlayHash(hash_json(
            b"kin-local-admission-overlay-v2\0",
            &LocalOverlayIdentity {
                case: self.case,
                sources: &self.sources,
            },
        )?);
        if computed != self.hash {
            return Err(ModelError::InvalidOperation(format!(
                "local admission overlay hash {} recomputes to {}",
                self.hash, computed
            )));
        }
        Ok(())
    }

    pub const fn stamp(&self) -> LocalOverlayStamp {
        LocalOverlayStamp {
            hash: self.hash,
            generation: self.generation,
        }
    }
}

/// Exact, self-inverting refresh of a workspace's frozen local overlay.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FrozenLocalOverlayDelta {
    pub old: Option<FrozenLocalOverlay>,
    pub new: Option<FrozenLocalOverlay>,
}

impl FrozenLocalOverlayDelta {
    pub fn initialize(new: FrozenLocalOverlay) -> Self {
        Self {
            old: None,
            new: Some(new),
        }
    }

    pub fn update(old: FrozenLocalOverlay, new: FrozenLocalOverlay) -> Self {
        Self {
            old: Some(old),
            new: Some(new),
        }
    }

    pub fn inverse(&self) -> Self {
        Self {
            old: self.new.clone(),
            new: self.old.clone(),
        }
    }

    pub fn workspace_id(&self) -> Option<WorkspaceId> {
        self.new
            .as_ref()
            .or(self.old.as_ref())
            .map(|overlay| overlay.workspace_id)
    }

    pub fn validate(&self) -> Result<()> {
        if self.old.is_none() && self.new.is_none() {
            return Err(ModelError::InvalidOperation(
                "local overlay delta has no old or new state".to_string(),
            ));
        }
        if self.old == self.new {
            return Err(ModelError::InvalidOperation(
                "local overlay delta is a no-op".to_string(),
            ));
        }
        if let Some(old) = &self.old {
            old.validate()?;
        }
        if let Some(new) = &self.new {
            new.validate()?;
        }
        match (&self.old, &self.new) {
            (None, Some(new)) if new.generation != 0 => {
                return Err(ModelError::InvalidOperation(
                    "initial local overlay generation must be zero".to_string(),
                ));
            }
            (Some(old), Some(new)) => {
                if old.workspace_id != new.workspace_id {
                    return Err(ModelError::InvalidOperation(
                        "local overlay refresh cannot change workspace identity".to_string(),
                    ));
                }
                if new.generation != old.generation.saturating_add(1)
                    && old.generation != new.generation.saturating_add(1)
                {
                    return Err(ModelError::InvalidOperation(format!(
                        "local overlay generations {} and {} are not adjacent",
                        old.generation, new.generation
                    )));
                }
            }
            _ => {}
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct LocalOverlayStamp {
    pub hash: LocalOverlayHash,
    pub generation: u64,
}

/// Complete policy identity consumed by one local workspace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EffectiveAdmissionPolicyStamp {
    pub shared: AdmissionPolicyStamp,
    pub local: LocalOverlayStamp,
}

/// Hash a payload for an admission identity.
///
/// This deliberately does NOT share `crate::identity::canonical_json_bytes`,
/// and the difference is a contract rather than an accident. That encoder
/// routes through a `serde_json::Value`, whose map normalizes object key order
/// away, so identities built on it are blind to the order a serialization
/// wrote its fields in. `serde_json::to_vec` streams the value instead, so a
/// struct's fields reach the digest in declaration order and a reorder moves
/// the hash.
///
/// The consequence is the useful half. The mirrors hashed here,
/// [`SharedAdmissionPolicyIdentity`] and [`LocalOverlayIdentity`], are field
/// lists kept by hand, and unlike the mirrors in `repository.rs` and `merge.rs`
/// their order is already visible to any hash comparison over them. They owe no
/// separate positional differential for that reason, which is what
/// `tests/persisted_schema.rs` records against them. What a hash comparison
/// still cannot see for either kind is a field the mirrored type grew and the
/// mirror never gained; the subsequence check in that same file is what covers
/// it.
///
/// `the_admission_identity_encoder_preserves_field_order` is what keeps this
/// paragraph true rather than merely written down.
fn hash_json(domain: &[u8], value: &impl Serialize) -> Result<Hash256> {
    let payload =
        serde_json::to_vec(value).map_err(|error| ModelError::Serialization(error.to_string()))?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(
        u64::try_from(payload.len())
            .map_err(|_| {
                ModelError::InvalidOperation("admission identity exceeds u64".to_string())
            })?
            .to_le_bytes(),
    );
    hasher.update(payload);
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(&digest);
    Ok(Hash256::from_bytes(bytes))
}

fn sort_canonical<T: Serialize + Clone>(values: &mut [T]) -> Result<()> {
    let mut keyed = values
        .iter()
        .map(|value| {
            serde_json::to_vec(value)
                .map(|encoded| (encoded, value.clone()))
                .map_err(|error| ModelError::Serialization(error.to_string()))
        })
        .collect::<Result<Vec<_>>>()?;
    keyed.sort_by(|left, right| left.0.cmp(&right.0));
    for (target, (_, value)) in keyed.into_iter().enumerate() {
        values[target] = value;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ArtifactId, ResolvedArtifact};

    fn no_allowance_file(_: Hash256) -> Result<Vec<u8>> {
        panic!("this tree carries no allowance file, so its body must never be read")
    }

    fn allowance(hash: u8, kind: SensitiveArtifactKind) -> SensitiveArtifactAllowance {
        SensitiveArtifactAllowance {
            path: RepoPath::from_utf8(".env").unwrap(),
            content_hash: Hash256::from_bytes([hash; 32]),
            kind,
            approved_by: AuthorId::new("security"),
            reason: "intentional fixture".to_string(),
        }
    }

    /// The admission encoder sees field order, which is the opposite of what
    /// the repository encoder does.
    ///
    /// Both contracts are deliberate and they live one module apart, so the
    /// difference is worth a test rather than a comment. `hash_json` streams
    /// through `serde_json::to_vec`, where a struct's fields reach the digest
    /// in declaration order. `canonical_json_bytes` materializes a
    /// `serde_json::Value` first, where they do not.
    ///
    /// This is what lets `tests/persisted_schema.rs` register the two mirrors
    /// hashed here as needing no positional differential of their own: any hash
    /// comparison over them already fails on a reorder. Route `hash_json`
    /// through `canonical_json_bytes` and this test fails, which is the point.
    ///
    /// The two `assert_eq!` arms are the controls. Without them a hash that
    /// simply differed every call would satisfy the inequality and read as a
    /// pass.
    #[test]
    fn the_admission_identity_encoder_preserves_field_order() {
        #[derive(Serialize)]
        struct Declared {
            alpha: u8,
            beta: &'static str,
        }
        #[derive(Serialize)]
        struct Reordered {
            beta: &'static str,
            alpha: u8,
        }

        let declared = hash_json(
            b"kin-order-probe\0",
            &Declared {
                alpha: 7,
                beta: "value",
            },
        )
        .unwrap();
        let reordered = hash_json(
            b"kin-order-probe\0",
            &Reordered {
                beta: "value",
                alpha: 7,
            },
        )
        .unwrap();
        assert_ne!(
            declared, reordered,
            "the admission identity encoder stopped seeing field order. Every mirror it hashes is \
             registered in tests/persisted_schema.rs as needing no positional differential BECAUSE \
             it sees order, so that registration is now wrong."
        );

        assert_eq!(
            declared,
            hash_json(
                b"kin-order-probe\0",
                &Declared {
                    alpha: 7,
                    beta: "value",
                },
            )
            .unwrap(),
            "the same payload hashed twice must give the same digest, or the inequality above is \
             noise rather than order"
        );
        assert_ne!(
            declared,
            hash_json(
                b"kin-other-probe\0",
                &Declared {
                    alpha: 7,
                    beta: "value",
                },
            )
            .unwrap(),
            "the domain separator must participate in the digest"
        );
    }

    #[test]
    fn sensitive_allowance_matches_exact_path_digest_and_kind_only() {
        let expected = allowance(0x11, SensitiveArtifactKind::Blob { executable: false });
        assert!(expected.matches(
            &RepoPath::from_utf8(".env").unwrap(),
            Hash256::from_bytes([0x11; 32]),
            SensitiveArtifactKind::Blob { executable: false }
        ));
        assert!(!expected.matches(
            &RepoPath::from_utf8(".env.local").unwrap(),
            Hash256::from_bytes([0x11; 32]),
            SensitiveArtifactKind::Blob { executable: false }
        ));
        assert!(!expected.matches(
            &RepoPath::from_utf8(".env").unwrap(),
            Hash256::from_bytes([0x12; 32]),
            SensitiveArtifactKind::Blob { executable: false }
        ));
        assert!(!expected.matches(
            &RepoPath::from_utf8(".env").unwrap(),
            Hash256::from_bytes([0x11; 32]),
            SensitiveArtifactKind::Symlink
        ));
    }

    #[test]
    fn policy_delta_is_exactly_self_inverting() {
        let old = SharedAdmissionPolicy::empty(0);
        let new = SharedAdmissionPolicy::new(
            1,
            Vec::new(),
            vec![allowance(0x22, SensitiveArtifactKind::Symlink)],
        )
        .unwrap();
        let delta = AdmissionPolicyDelta::update(old.clone(), new.clone());
        delta.validate().unwrap();
        let inverse = delta.inverse();
        inverse.validate().unwrap();
        assert_eq!(inverse.old, Some(new));
        assert_eq!(inverse.new, Some(old));
    }

    #[test]
    fn policy_hash_does_not_hide_allowance_changes() {
        let left = SharedAdmissionPolicy::new(
            0,
            Vec::new(),
            vec![allowance(0x31, SensitiveArtifactKind::Symlink)],
        )
        .unwrap();
        let right = SharedAdmissionPolicy::new(
            0,
            Vec::new(),
            vec![allowance(0x32, SensitiveArtifactKind::Symlink)],
        )
        .unwrap();
        assert_ne!(left.hash, right.hash);
    }

    #[test]
    fn shared_policy_is_derived_from_exact_tree_sources_in_canonical_order() {
        let root_hash = Hash256::from_bytes([0x33; 32]);
        let nested_git_hash = Hash256::from_bytes([0x34; 32]);
        let nested_kin_hash = Hash256::from_bytes([0x35; 32]);
        let ignored_symlink_hash = Hash256::from_bytes([0x36; 32]);
        let tree = ResolvedTree::from_artifacts([
            ResolvedArtifact::new(
                ArtifactId::new(),
                RepoPath::from_utf8("src/.kinignore").unwrap(),
                TreeEntry::blob(nested_kin_hash, false),
            ),
            ResolvedArtifact::new(
                ArtifactId::new(),
                RepoPath::from_utf8(".gitignore").unwrap(),
                TreeEntry::blob(root_hash, false),
            ),
            ResolvedArtifact::new(
                ArtifactId::new(),
                RepoPath::from_utf8("src/.gitignore").unwrap(),
                TreeEntry::blob(nested_git_hash, false),
            ),
            ResolvedArtifact::new(
                ArtifactId::new(),
                RepoPath::from_utf8("vendor/.gitignore").unwrap(),
                TreeEntry::symlink(ignored_symlink_hash),
            ),
        ])
        .unwrap();

        let (policy, delta) = SharedAdmissionPolicy::derive_from_tree_with_allowances(
            None,
            &tree,
            |hash| match hash {
                value if value == root_hash => Ok(11),
                value if value == nested_git_hash => Ok(12),
                value if value == nested_kin_hash => Ok(13),
                other => panic!("unexpected source hash {other}"),
            },
            no_allowance_file,
        )
        .unwrap();

        assert_eq!(policy.generation, 0);
        assert_eq!(
            policy
                .sources
                .iter()
                .map(|source| source.path.as_bytes())
                .collect::<Vec<_>>(),
            vec![
                b".gitignore".as_slice(),
                b"src/.gitignore".as_slice(),
                b"src/.kinignore".as_slice(),
            ]
        );
        assert_eq!(
            policy
                .sources
                .iter()
                .map(|source| source.precedence)
                .collect::<Vec<_>>(),
            vec![0, 1, 2]
        );
        assert_eq!(
            delta,
            Some(AdmissionPolicyDelta::initialize(policy.clone()))
        );
    }

    fn allowance_file(entries: &[(&str, [u8; 32], &str, &str, &str)]) -> Vec<u8> {
        let mut body = String::from("# approvals reviewed in the pull request that adds them\n");
        body.push_str(SENSITIVE_ALLOWANCE_FORMAT_HEADER);
        body.push('\n');
        for (path, digest, kind, approver, reason) in entries {
            body.push_str(&format!(
                "{path}\t{}\t{kind}\t{approver}\t{reason}\n",
                hex::encode(digest)
            ));
        }
        body.into_bytes()
    }

    fn tree_with(entries: &[(&str, Hash256)]) -> ResolvedTree {
        ResolvedTree::from_artifacts(entries.iter().map(|(path, hash)| {
            ResolvedArtifact::new(
                ArtifactId::new(),
                RepoPath::from_utf8(*path).unwrap(),
                TreeEntry::blob(*hash, false),
            )
        }))
        .unwrap()
    }

    #[test]
    fn allowances_derive_from_the_tracked_root_file() {
        let ignore = Hash256::from_bytes([0x41; 32]);
        let allowances = Hash256::from_bytes([0x42; 32]);
        let tree = tree_with(&[
            (".gitignore", ignore),
            (SENSITIVE_ALLOWANCE_SOURCE_PATH, allowances),
        ]);
        let body = allowance_file(&[
            (
                "notekeeper/search.py",
                [0x51; 32],
                "blob",
                "troy",
                "tokenizer local, reviewed",
            ),
            (
                "scripts/deploy.sh",
                [0x52; 32],
                "blob+x",
                "troy",
                "vendored fixture key, rotated",
            ),
            (
                "config/link",
                [0x53; 32],
                "symlink",
                "security",
                "points at a mounted secret",
            ),
        ]);

        let (policy, delta) = SharedAdmissionPolicy::derive_from_tree_with_allowances(
            None,
            &tree,
            |_| Ok(9),
            |hash| {
                assert_eq!(hash, allowances, "only the allowance blob may be read");
                Ok(body.clone())
            },
        )
        .unwrap();

        assert_eq!(policy.sensitive_allowances.len(), 3);
        assert!(policy.sensitive_allowances.iter().any(|entry| {
            entry.path == RepoPath::from_utf8("notekeeper/search.py").unwrap()
                && entry.content_hash == Hash256::from_bytes([0x51; 32])
                && entry.kind == SensitiveArtifactKind::Blob { executable: false }
                && entry.approved_by == AuthorId::new("troy")
                && entry.reason == "tokenizer local, reviewed"
        }));
        assert!(policy
            .sensitive_allowances
            .iter()
            .any(|entry| { entry.kind == SensitiveArtifactKind::Blob { executable: true } }));
        assert!(policy
            .sensitive_allowances
            .iter()
            .any(|entry| entry.kind == SensitiveArtifactKind::Symlink));
        assert_eq!(
            policy.sources.len(),
            1,
            "the allowance file is not an ignore source"
        );
        policy.validate().unwrap();
        assert_eq!(delta, Some(AdmissionPolicyDelta::initialize(policy)));
    }

    #[test]
    fn an_edited_allowance_file_advances_the_policy_with_ignore_sources_unchanged() {
        let ignore = Hash256::from_bytes([0x43; 32]);
        let first_blob = Hash256::from_bytes([0x44; 32]);
        let second_blob = Hash256::from_bytes([0x45; 32]);
        let approved = allowance_file(&[(".env", [0x61; 32], "blob", "security", "staging only")]);
        let rotated = allowance_file(&[(".env", [0x62; 32], "blob", "security", "staging only")]);

        let tree = tree_with(&[
            (".gitignore", ignore),
            (SENSITIVE_ALLOWANCE_SOURCE_PATH, first_blob),
        ]);
        let (old, _) = SharedAdmissionPolicy::derive_from_tree_with_allowances(
            None,
            &tree,
            |_| Ok(9),
            |_| Ok(approved.clone()),
        )
        .unwrap();

        let (same, no_delta) = SharedAdmissionPolicy::derive_from_tree_with_allowances(
            Some(&old),
            &tree,
            |_| Ok(9),
            |_| Ok(approved.clone()),
        )
        .unwrap();
        assert_eq!(same, old, "an unchanged tree is a no-op");
        assert_eq!(no_delta, None);

        let edited = tree_with(&[
            (".gitignore", ignore),
            (SENSITIVE_ALLOWANCE_SOURCE_PATH, second_blob),
        ]);
        let (changed, delta) = SharedAdmissionPolicy::derive_from_tree_with_allowances(
            Some(&old),
            &edited,
            |_| Ok(9),
            |_| Ok(rotated.clone()),
        )
        .unwrap();
        assert_eq!(changed.sources, old.sources, "no ignore source moved");
        assert_eq!(
            changed.generation,
            old.generation + 1,
            "an approval change must advance the policy even with sources unchanged"
        );
        assert_eq!(
            changed.sensitive_allowances[0].content_hash,
            Hash256::from_bytes([0x62; 32])
        );
        assert_eq!(delta, Some(AdmissionPolicyDelta::update(old, changed)));
    }

    #[test]
    fn deleting_the_allowance_file_revokes_every_approval() {
        let ignore = Hash256::from_bytes([0x46; 32]);
        let blob = Hash256::from_bytes([0x47; 32]);
        let body = allowance_file(&[(".env", [0x63; 32], "blob", "security", "staging only")]);
        let with_file = tree_with(&[
            (".gitignore", ignore),
            (SENSITIVE_ALLOWANCE_SOURCE_PATH, blob),
        ]);
        let (old, _) = SharedAdmissionPolicy::derive_from_tree_with_allowances(
            None,
            &with_file,
            |_| Ok(9),
            |_| Ok(body.clone()),
        )
        .unwrap();
        assert_eq!(old.sensitive_allowances.len(), 1);

        let without_file = tree_with(&[(".gitignore", ignore)]);
        let (revoked, delta) = SharedAdmissionPolicy::derive_from_tree_with_allowances(
            Some(&old),
            &without_file,
            |_| Ok(9),
            no_allowance_file,
        )
        .unwrap();
        assert!(
            revoked.sensitive_allowances.is_empty(),
            "the tracked file is the approval set, so deleting it revokes"
        );
        assert_eq!(revoked.generation, old.generation + 1);
        assert!(delta.is_some());
    }

    #[test]
    fn the_compatibility_entry_point_refuses_a_tree_carrying_approvals() {
        let ignore = Hash256::from_bytes([0x49; 32]);
        let blob = Hash256::from_bytes([0x4a; 32]);

        let plain = tree_with(&[(".gitignore", ignore)]);
        SharedAdmissionPolicy::derive_from_tree(None, &plain, |_| Ok(9))
            .expect("a tree with no approvals still derives through the older entry point");

        let with_approvals = tree_with(&[
            (".gitignore", ignore),
            (SENSITIVE_ALLOWANCE_SOURCE_PATH, blob),
        ]);
        let error = SharedAdmissionPolicy::derive_from_tree(None, &with_approvals, |_| Ok(9))
            .expect_err("a consumer that cannot read approvals must refuse rather than drop them");
        assert!(
            error.to_string().contains("this build cannot read"),
            "unexpected compatibility refusal: {error}"
        );
    }

    #[test]
    fn a_nested_allowance_file_is_refused_rather_than_ignored() {
        let nested = Hash256::from_bytes([0x48; 32]);
        let tree = tree_with(&[(&format!("src/{SENSITIVE_ALLOWANCE_SOURCE_PATH}"), nested)]);
        let error = SharedAdmissionPolicy::derive_from_tree_with_allowances(
            None,
            &tree,
            |_| Ok(9),
            |_| panic!("a nested file must be refused before its body is read"),
        )
        .expect_err("a nested allowance file must be refused");
        assert!(
            error
                .to_string()
                .contains("sensitive allowances are read only from the repository root"),
            "unexpected nested-file error: {error}"
        );
    }

    #[test]
    fn a_malformed_allowance_file_fails_the_derivation_rather_than_reading_empty() {
        let header = SENSITIVE_ALLOWANCE_FORMAT_HEADER;
        let digest = hex::encode([0x71; 32]);
        for (body, expected) in [
            (
                format!("notekeeper/a.py\t{digest}\tblob\ttroy\treason\n"),
                "must be the format header",
            ),
            (format!("{header}\n"), ""),
            (
                format!("{header}\nnotekeeper/a.py\t{digest}\tzip\ttroy\treason\n"),
                "must be one of blob, blob+x, symlink",
            ),
            (
                format!("{header}\nnotekeeper/a.py\tabcd\tblob\ttroy\treason\n"),
                "must be 32 bytes of hex",
            ),
            (
                format!("{header}\nnotekeeper/a.py\t{digest}\tblob\ttroy\n"),
                "expected five tab-separated fields",
            ),
            (
                format!("{header}\nnotekeeper/a.py\t{digest}\tblob\ttroy\t   \n"),
                "requires a reason",
            ),
            (
                format!("{header}\nnotekeeper/a.py\t{digest}\tblob\t\treason\n"),
                "approver must not be empty",
            ),
            (
                format!(
                    "{header}\nnotekeeper/a.py\t{digest}\tblob\ttroy\tfirst\n\
                     notekeeper/a.py\t{digest}\tblob\ttroy\tsecond\n"
                ),
                "is already approved on an earlier line",
            ),
        ] {
            let parsed = parse_sensitive_allowances(body.as_bytes());
            if expected.is_empty() {
                assert_eq!(
                    parsed.unwrap(),
                    Vec::new(),
                    "a header with no entries is a valid empty approval set"
                );
                continue;
            }
            let error = parsed.expect_err(&format!("must refuse: {body:?}"));
            assert!(
                error.to_string().contains(expected),
                "expected {expected:?} for {body:?}, got: {error}"
            );
        }
        let error =
            parse_sensitive_allowances(&[0xff, 0xfe]).expect_err("invalid UTF-8 is refused");
        assert!(
            error.to_string().contains("is not valid UTF-8"),
            "unexpected utf8 error: {error}"
        );
    }

    #[test]
    fn frozen_local_overlay_refresh_is_explicit_and_self_inverting() {
        let workspace_id = WorkspaceId::new();
        let old =
            FrozenLocalOverlay::new(workspace_id, 0, AdmissionCase::Sensitive, Vec::new()).unwrap();
        let new = FrozenLocalOverlay::new(
            workspace_id,
            1,
            AdmissionCase::Sensitive,
            vec![LocalAdmissionRuleSource {
                kind: LocalAdmissionRuleSourceKind::KinLocal,
                body_hash: Hash256::from_bytes([0x41; 32]),
                body_len: 17,
                precedence: 0,
            }],
        )
        .unwrap();
        let delta = FrozenLocalOverlayDelta::update(old.clone(), new.clone());
        delta.validate().unwrap();
        let inverse = delta.inverse();
        inverse.validate().unwrap();
        assert_eq!(inverse.old, Some(new));
        assert_eq!(inverse.new, Some(old));
        assert_eq!(inverse.inverse(), delta);
    }

    #[test]
    fn frozen_local_overlay_identity_binds_case_behavior() {
        let workspace_id = WorkspaceId::new();
        let sensitive =
            FrozenLocalOverlay::new(workspace_id, 0, AdmissionCase::Sensitive, Vec::new()).unwrap();
        let folded =
            FrozenLocalOverlay::new(workspace_id, 0, AdmissionCase::FoldAscii, Vec::new()).unwrap();

        assert_ne!(sensitive.hash, folded.hash);
        assert_ne!(sensitive.stamp(), folded.stamp());
        sensitive.validate().unwrap();
        folded.validate().unwrap();
    }
}
