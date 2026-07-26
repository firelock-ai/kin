// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Persisted, graph-native repository admission policy.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

use crate::{
    AuthorId, Hash256, ModelError, RepoPath, RepositoryId, Result, WorkspaceHead, WorkspaceId,
};

pub const ADMISSION_POLICY_SEMANTICS_VERSION: u32 = 1;

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
    pub sources: Vec<LocalAdmissionRuleSource>,
    pub hash: LocalOverlayHash,
}

#[derive(Serialize)]
struct LocalOverlayIdentity<'a> {
    sources: &'a [LocalAdmissionRuleSource],
}

impl FrozenLocalOverlay {
    pub fn new(
        workspace_id: WorkspaceId,
        generation: u64,
        mut sources: Vec<LocalAdmissionRuleSource>,
    ) -> Result<Self> {
        sources.sort_by_key(|source| source.precedence);
        let hash = LocalOverlayHash(hash_json(
            b"kin-local-admission-overlay-v1\0",
            &LocalOverlayIdentity { sources: &sources },
        )?);
        let overlay = Self {
            workspace_id,
            generation,
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
            b"kin-local-admission-overlay-v1\0",
            &LocalOverlayIdentity {
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

/// Authority captured by one complete filesystem observation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AdmissionScanToken {
    pub repository_id: RepositoryId,
    pub workspace_id: WorkspaceId,
    /// Persisted workspace generation observed before scanning.
    pub workspace_generation: u64,
    pub workspace_head: WorkspaceHead,
    /// Persisted graph-owned workspace tree used as the scan baseline.
    pub baseline_tree_hash: Hash256,
    /// Exact candidate tree whose bytes and entry kinds were scanned.
    ///
    /// Binding both tree hashes prevents replaying a successful scan over
    /// different candidate bytes that happen to share the same baseline.
    pub observed_tree_hash: Hash256,
    /// Matcher semantics used for ignore resolution and sensitive scanning.
    pub matcher_semantics_version: u32,
    pub shared_policy: AdmissionPolicyStamp,
    pub local_overlay: LocalOverlayStamp,
}

impl AdmissionScanToken {
    pub fn validate(&self) -> Result<()> {
        if self.matcher_semantics_version != ADMISSION_POLICY_SEMANTICS_VERSION {
            return Err(ModelError::InvalidOperation(format!(
                "admission scan used matcher semantics version {}, expected {}",
                self.matcher_semantics_version, ADMISSION_POLICY_SEMANTICS_VERSION
            )));
        }
        Ok(())
    }
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
    fn frozen_local_overlay_refresh_is_explicit_and_self_inverting() {
        let workspace_id = WorkspaceId::new();
        let old = FrozenLocalOverlay::new(workspace_id, 0, Vec::new()).unwrap();
        let new = FrozenLocalOverlay::new(
            workspace_id,
            1,
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
}
