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
        mut source_body_len: impl FnMut(Hash256) -> Result<u64>,
    ) -> Result<(Self, Option<AdmissionPolicyDelta>)> {
        let mut sources = Vec::new();
        for artifact in tree.artifacts() {
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

        sources.sort_by(compare_rule_sources);
        for (index, source) in sources.iter_mut().enumerate() {
            source.precedence = u32::try_from(index).map_err(|_| {
                ModelError::InvalidOperation(
                    "shared admission source count exceeds u32".to_string(),
                )
            })?;
        }

        let Some(old) = first_parent else {
            let policy = Self::new(0, sources, Vec::new())?;
            let delta = AdmissionPolicyDelta::initialize(policy.clone());
            delta.validate()?;
            return Ok((policy, Some(delta)));
        };

        if old.sources == sources {
            return Ok((old.clone(), None));
        }

        let generation = old.generation.checked_add(1).ok_or_else(|| {
            ModelError::InvalidOperation("shared admission-policy generation exhausted".to_string())
        })?;
        let policy = Self::new(generation, sources, old.sensitive_allowances.clone())?;
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

    fn allowance(hash: u8, kind: SensitiveArtifactKind) -> SensitiveArtifactAllowance {
        SensitiveArtifactAllowance {
            path: RepoPath::from_utf8(".env").unwrap(),
            content_hash: Hash256::from_bytes([hash; 32]),
            kind,
            approved_by: AuthorId::new("security"),
            reason: "intentional fixture".to_string(),
        }
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

        let (policy, delta) =
            SharedAdmissionPolicy::derive_from_tree(None, &tree, |hash| match hash {
                value if value == root_hash => Ok(11),
                value if value == nested_git_hash => Ok(12),
                value if value == nested_kin_hash => Ok(13),
                other => panic!("unexpected source hash {other}"),
            })
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

    #[test]
    fn shared_policy_transition_preserves_allowances_and_skips_noops() {
        let old_hash = Hash256::from_bytes([0x37; 32]);
        let old_tree = ResolvedTree::from_artifacts([ResolvedArtifact::new(
            ArtifactId::new(),
            RepoPath::from_utf8(".gitignore").unwrap(),
            TreeEntry::blob(old_hash, false),
        )])
        .unwrap();
        let (mut old, _) =
            SharedAdmissionPolicy::derive_from_tree(None, &old_tree, |_| Ok(4)).unwrap();
        old = SharedAdmissionPolicy::new(
            old.generation,
            old.sources,
            vec![allowance(
                0x38,
                SensitiveArtifactKind::Blob { executable: false },
            )],
        )
        .unwrap();

        let (same, no_delta) =
            SharedAdmissionPolicy::derive_from_tree(Some(&old), &old_tree, |_| Ok(4)).unwrap();
        assert_eq!(same, old);
        assert_eq!(no_delta, None);

        let new_hash = Hash256::from_bytes([0x39; 32]);
        let changed_tree = ResolvedTree::from_artifacts([ResolvedArtifact::new(
            ArtifactId::new(),
            RepoPath::from_utf8(".gitignore").unwrap(),
            TreeEntry::blob(new_hash, false),
        )])
        .unwrap();
        let (changed, delta) =
            SharedAdmissionPolicy::derive_from_tree(Some(&old), &changed_tree, |_| Ok(7)).unwrap();
        assert_eq!(changed.generation, old.generation + 1);
        assert_eq!(changed.sensitive_allowances, old.sensitive_allowances);
        assert_eq!(
            delta,
            Some(AdmissionPolicyDelta::update(old, changed.clone()))
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
