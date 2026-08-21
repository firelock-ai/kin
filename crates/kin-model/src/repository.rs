// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Repository-authority transaction contracts shared by storage and transport.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

use crate::{
    identity::canonical_json_bytes, validate_semantic_change_id, validate_transaction_delta,
    AuthorId, DefaultRefMutation, EffectiveAdmissionPolicyStamp, EntityDelta, ExternalChangeAlias,
    ExternalObjectKind, ExternalObjectRecord, ExternalReferenceDelta, FrozenLocalOverlayDelta,
    GitExternalAuthorityDelta, GitObjectId, Hash256, MergeTransactionDelta, ModelError,
    OperationId, RefMutation, RefName, RefTarget, RelationDelta, RepositoryId, RepositoryRef,
    ResolvedTree, Result, SealedObservationBinding, SemanticChange, SemanticChangeId,
    SharedAdmissionPolicy, TransactionDelta, TreeDelta, WorkspaceHead, WorkspaceId,
};

/// Clean-slate transaction schema whose persistence authority owns both exact
/// workspace trees and their uncommitted semantic overlays.
///
/// Version 3 persisted only a dirty workspace tree and therefore reconstructed
/// entity/relation state from `base_target` after restart. It has no
/// compatibility decoder: a repository that cannot prove the complete
/// workspace graph must be re-imported rather than silently losing semantics.
pub const REPOSITORY_TRANSACTION_SCHEMA_VERSION: u32 = 4;
pub const REPOSITORY_ROOT_SCHEMA_VERSION: u32 = 1;
pub const WORKSPACE_SEMANTIC_DELTA_SCHEMA_VERSION: u32 = 1;
pub const WORKSPACE_SEMANTIC_OVERLAY_SCHEMA_VERSION: u32 = 1;

/// One canonical entity/relation transition for mutable workspace authority.
///
/// [`WorkspaceMutation::semantic_delta`] carries the incremental transition
/// from the expected workspace graph to its successor. The same representation
/// is stored cumulatively in [`WorkspaceState::semantic_overlay`] relative to
/// `base_target`. Exact repository membership remains independently
/// authoritative in [`WorkspaceState::tree`].
#[derive(Debug, Clone, PartialEq, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceSemanticDelta {
    version: u32,
    entity_deltas: Vec<EntityDelta>,
    relation_deltas: Vec<RelationDelta>,
    /// Deliberately last for additive positional-wire compatibility.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    external_reference_deltas: Vec<ExternalReferenceDelta>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WorkspaceSemanticDeltaWire {
    version: u32,
    entity_deltas: Vec<EntityDelta>,
    relation_deltas: Vec<RelationDelta>,
    #[serde(default)]
    external_reference_deltas: Vec<ExternalReferenceDelta>,
}

impl<'de> Deserialize<'de> for WorkspaceSemanticDelta {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = WorkspaceSemanticDeltaWire::deserialize(deserializer)?;
        let delta = Self {
            version: wire.version,
            entity_deltas: wire.entity_deltas,
            relation_deltas: wire.relation_deltas,
            external_reference_deltas: wire.external_reference_deltas,
        };
        delta.validate().map_err(serde::de::Error::custom)?;
        Ok(delta)
    }
}

impl WorkspaceSemanticDelta {
    pub fn new(
        entity_deltas: Vec<EntityDelta>,
        relation_deltas: Vec<RelationDelta>,
    ) -> Result<Self> {
        Self::new_with_external_references(entity_deltas, relation_deltas, Vec::new())
    }

    pub fn new_with_external_references(
        mut entity_deltas: Vec<EntityDelta>,
        mut relation_deltas: Vec<RelationDelta>,
        mut external_reference_deltas: Vec<ExternalReferenceDelta>,
    ) -> Result<Self> {
        entity_deltas.sort_by_key(EntityDelta::target_id);
        relation_deltas.sort_by_key(RelationDelta::target_id);
        external_reference_deltas.sort_by_key(ExternalReferenceDelta::target_id);
        let delta = Self {
            version: WORKSPACE_SEMANTIC_DELTA_SCHEMA_VERSION,
            entity_deltas,
            relation_deltas,
            external_reference_deltas,
        };
        delta.validate()?;
        Ok(delta)
    }

    pub fn validate(&self) -> Result<()> {
        if self.version != WORKSPACE_SEMANTIC_DELTA_SCHEMA_VERSION {
            return Err(ModelError::InvalidOperation(format!(
                "unsupported workspace semantic delta version {}",
                self.version
            )));
        }
        if self
            .entity_deltas
            .windows(2)
            .any(|pair| pair[0].target_id() >= pair[1].target_id())
        {
            return Err(ModelError::InvalidOperation(
                "workspace semantic entity deltas are not in canonical unique target order"
                    .to_string(),
            ));
        }
        if self
            .relation_deltas
            .windows(2)
            .any(|pair| pair[0].target_id() >= pair[1].target_id())
        {
            return Err(ModelError::InvalidOperation(
                "workspace semantic relation deltas are not in canonical unique target order"
                    .to_string(),
            ));
        }
        if self
            .external_reference_deltas
            .windows(2)
            .any(|pair| pair[0].target_id() >= pair[1].target_id())
        {
            return Err(ModelError::InvalidOperation(
                "workspace semantic external-reference deltas are not in canonical unique target order"
                    .to_string(),
            ));
        }
        validate_transaction_delta(&self.transaction_delta())
    }

    pub fn identity_hash(&self) -> Result<Hash256> {
        self.validate()?;
        let mut canonical = self.clone();
        canonical.sort_canonical();
        let encoded = canonical_json_bytes(&canonical)?;
        let mut hasher = Sha256::new();
        hasher.update(b"kin-workspace-semantic-delta-v1\0");
        hasher.update(
            u64::try_from(encoded.len())
                .map_err(|_| {
                    ModelError::InvalidOperation("workspace semantic delta exceeds u64".to_string())
                })?
                .to_le_bytes(),
        );
        hasher.update(encoded);
        let result = hasher.finalize();
        let mut bytes = [0_u8; 32];
        bytes.copy_from_slice(&result);
        Ok(Hash256::from_bytes(bytes))
    }

    pub fn entity_deltas(&self) -> &[EntityDelta] {
        &self.entity_deltas
    }

    pub fn relation_deltas(&self) -> &[RelationDelta] {
        &self.relation_deltas
    }

    pub fn external_reference_deltas(&self) -> &[ExternalReferenceDelta] {
        &self.external_reference_deltas
    }

    pub fn transaction_delta(&self) -> TransactionDelta {
        TransactionDelta {
            entity_deltas: self.entity_deltas.clone(),
            relation_deltas: self.relation_deltas.clone(),
            tree_deltas: Vec::new(),
            admission_policy_delta: None,
            external_reference_deltas: self.external_reference_deltas.clone(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.entity_deltas.is_empty()
            && self.relation_deltas.is_empty()
            && self.external_reference_deltas.is_empty()
    }

    fn sort_canonical(&mut self) {
        self.entity_deltas.sort_by_key(EntityDelta::target_id);
        self.relation_deltas.sort_by_key(RelationDelta::target_id);
        self.external_reference_deltas
            .sort_by_key(ExternalReferenceDelta::target_id);
    }
}

impl Default for WorkspaceSemanticDelta {
    fn default() -> Self {
        Self {
            version: WORKSPACE_SEMANTIC_DELTA_SCHEMA_VERSION,
            entity_deltas: Vec::new(),
            relation_deltas: Vec::new(),
            external_reference_deltas: Vec::new(),
        }
    }
}

/// Canonical cumulative entity/relation state relative to a workspace base.
///
/// This is intentionally a different type from [`WorkspaceSemanticDelta`].
/// Storage must derive it by diffing the requested successor workspace against
/// its new immutable base; an incremental mutation cannot be persisted here by
/// accident.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct WorkspaceSemanticOverlay(WorkspaceSemanticDelta);

impl WorkspaceSemanticOverlay {
    pub fn new(
        entity_deltas: Vec<EntityDelta>,
        relation_deltas: Vec<RelationDelta>,
    ) -> Result<Self> {
        Ok(Self(WorkspaceSemanticDelta::new(
            entity_deltas,
            relation_deltas,
        )?))
    }

    pub fn new_with_external_references(
        entity_deltas: Vec<EntityDelta>,
        relation_deltas: Vec<RelationDelta>,
        external_reference_deltas: Vec<ExternalReferenceDelta>,
    ) -> Result<Self> {
        Ok(Self(WorkspaceSemanticDelta::new_with_external_references(
            entity_deltas,
            relation_deltas,
            external_reference_deltas,
        )?))
    }

    pub fn validate(&self) -> Result<()> {
        if self.0.version != WORKSPACE_SEMANTIC_OVERLAY_SCHEMA_VERSION {
            return Err(ModelError::InvalidOperation(format!(
                "unsupported workspace semantic overlay version {}",
                self.0.version
            )));
        }
        self.0.validate()
    }

    pub fn identity_hash(&self) -> Result<Hash256> {
        self.validate()?;
        let encoded = canonical_json_bytes(self)?;
        let mut hasher = Sha256::new();
        hasher.update(b"kin-workspace-semantic-overlay-v1\0");
        hasher.update(
            u64::try_from(encoded.len())
                .map_err(|_| {
                    ModelError::InvalidOperation(
                        "workspace semantic overlay exceeds u64".to_string(),
                    )
                })?
                .to_le_bytes(),
        );
        hasher.update(encoded);
        let result = hasher.finalize();
        let mut bytes = [0_u8; 32];
        bytes.copy_from_slice(&result);
        Ok(Hash256::from_bytes(bytes))
    }

    pub fn entity_deltas(&self) -> &[EntityDelta] {
        self.0.entity_deltas()
    }

    pub fn relation_deltas(&self) -> &[RelationDelta] {
        self.0.relation_deltas()
    }

    pub fn external_reference_deltas(&self) -> &[ExternalReferenceDelta] {
        self.0.external_reference_deltas()
    }

    pub fn transaction_delta(&self) -> TransactionDelta {
        self.0.transaction_delta()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

/// One versioned digest in the repository authority root bundle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AuthorityRoot {
    pub version: u32,
    pub hash: Hash256,
}

impl AuthorityRoot {
    pub const fn new(version: u32, hash: Hash256) -> Self {
        Self { version, hash }
    }
}

/// Exhaustive root partition for replicated and local repository authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RootBundle {
    pub version: u32,
    pub generation: u64,
    pub history: AuthorityRoot,
    pub ref_state: AuthorityRoot,
    pub ref_log: AuthorityRoot,
    pub collaboration: AuthorityRoot,
    pub replication: AuthorityRoot,
    /// Local workspace/session/overlay authority. Never compare this field when
    /// deciding whether two replicas have identical replicated truth.
    pub local_state: AuthorityRoot,
}

impl RootBundle {
    pub fn validate(&self) -> Result<()> {
        if self.version != REPOSITORY_ROOT_SCHEMA_VERSION {
            return Err(ModelError::InvalidOperation(format!(
                "unsupported repository root bundle version {}",
                self.version
            )));
        }
        for (name, root) in [
            ("history", &self.history),
            ("ref_state", &self.ref_state),
            ("ref_log", &self.ref_log),
            ("collaboration", &self.collaboration),
            ("replication", &self.replication),
            ("local_state", &self.local_state),
        ] {
            if root.version != REPOSITORY_ROOT_SCHEMA_VERSION {
                return Err(ModelError::InvalidOperation(format!(
                    "unsupported {name} authority root version {}",
                    root.version
                )));
            }
        }
        Ok(())
    }

    /// Whether two authority bundles name the same replicated repository truth.
    ///
    /// `generation` advances for every repository transaction, including
    /// local-only workspace transitions, and `local_state` deliberately roots
    /// workspace/session/overlay authority. Neither field participates in
    /// replica truth equality. Schema version and every replicated partition
    /// remain exact.
    pub fn has_same_replicated_truth(&self, other: &Self) -> bool {
        self.version == other.version
            && self.history == other.history
            && self.ref_state == other.ref_state
            && self.ref_log == other.ref_log
            && self.collaboration == other.collaboration
            && self.replication == other.replication
    }
}

/// VFS/projection binding for one exact workspace snapshot.
///
/// `workspace_tree_hash` is the projected graph-owned tree. It is deliberately
/// distinct from `base_tree_hash`: a dirty workspace must never pretend that
/// its tree is the commit named by `base_target`. Both base fields are absent
/// for an unborn symbolic ref.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceSnapshotBinding {
    pub repository_id: RepositoryId,
    pub workspace_id: WorkspaceId,
    pub workspace_head: WorkspaceHead,
    pub base_target: Option<RefTarget>,
    pub base_tree_hash: Option<Hash256>,
    pub workspace_tree_hash: Hash256,
    pub workspace_semantic_overlay_hash: Hash256,
    pub roots: RootBundle,
    pub workspace_generation: u64,
    pub admission_policy: EffectiveAdmissionPolicyStamp,
}

impl WorkspaceSnapshotBinding {
    /// Validate the repository/workspace authority fields carried over a
    /// projection boundary.
    pub fn validate(&self) -> Result<()> {
        self.roots.validate()?;
        if self.base_target.is_some() != self.base_tree_hash.is_some() {
            return Err(ModelError::InvalidOperation(
                "workspace snapshot base target and tree must both be present or absent"
                    .to_string(),
            ));
        }
        validate_head_base(
            &self.workspace_head,
            &self.base_target,
            self.base_tree_hash,
            "workspace snapshot",
        )
    }

    pub fn is_dirty(&self) -> bool {
        self.workspace_semantic_overlay_hash
            != WorkspaceSemanticOverlay::default()
                .identity_hash()
                .expect("empty workspace semantic overlay has a canonical identity")
            || self.base_tree_hash.map_or_else(
                || {
                    self.workspace_tree_hash
                        != compute_resolved_tree_hash(&ResolvedTree::default())
                            .expect("empty tree has a canonical identity")
                },
                |base| base != self.workspace_tree_hash,
            )
    }
}

/// Graph-owned exact working state for one local workspace or agent session.
///
/// This state is not derived from a branch on demand. The full repository tree
/// is persisted independently so unsupported languages, configuration, binary
/// assets, symlinks, gitlinks, and dirty changes all remain authoritative.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceState {
    pub repository_id: RepositoryId,
    pub workspace_id: WorkspaceId,
    pub generation: u64,
    pub head: WorkspaceHead,
    /// Resolved target of `head`, or `None` for an unborn symbolic ref.
    pub base_target: Option<RefTarget>,
    /// Tree at `base_target`, or `None` for an unborn symbolic ref.
    pub base_tree_hash: Option<Hash256>,
    /// Exact graph-owned working tree, including uncommitted state.
    pub tree: ResolvedTree,
    pub tree_hash: Hash256,
    /// Complete uncommitted semantic state relative to `base_target`.
    pub semantic_overlay: WorkspaceSemanticOverlay,
    pub semantic_overlay_hash: Hash256,
    /// Complete shared matcher policy active for this exact workspace tree.
    ///
    /// This may be newer than committed history when a dirty workspace edits
    /// `.gitignore` or `.kinignore`.
    pub shared_admission_policy: SharedAdmissionPolicy,
    pub admission_policy: EffectiveAdmissionPolicyStamp,
}

impl WorkspaceState {
    /// Build and validate complete workspace authority in one call.
    ///
    /// The semantic overlay is deliberately explicit even when empty. A
    /// caller must never persist a dirty exact tree while accidentally
    /// inheriting base semantics through a convenience constructor.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        repository_id: RepositoryId,
        workspace_id: WorkspaceId,
        generation: u64,
        head: WorkspaceHead,
        base_target: Option<RefTarget>,
        base_tree_hash: Option<Hash256>,
        tree: ResolvedTree,
        semantic_overlay: WorkspaceSemanticOverlay,
        shared_admission_policy: SharedAdmissionPolicy,
        admission_policy: EffectiveAdmissionPolicyStamp,
    ) -> Result<Self> {
        let tree_hash = compute_resolved_tree_hash(&tree)?;
        let semantic_overlay_hash = semantic_overlay.identity_hash()?;
        let state = Self {
            repository_id,
            workspace_id,
            generation,
            head,
            base_target,
            base_tree_hash,
            tree,
            tree_hash,
            semantic_overlay,
            semantic_overlay_hash,
            shared_admission_policy,
            admission_policy,
        };
        state.validate()?;
        Ok(state)
    }

    pub fn validate(&self) -> Result<()> {
        self.shared_admission_policy.validate()?;
        if self.shared_admission_policy.stamp() != self.admission_policy.shared {
            return Err(ModelError::InvalidOperation(format!(
                "workspace {} shared admission policy does not match its effective policy stamp",
                self.workspace_id
            )));
        }
        if self.base_target.is_some() != self.base_tree_hash.is_some() {
            return Err(ModelError::InvalidOperation(
                "workspace base target and base tree must both be present or absent".to_string(),
            ));
        }
        validate_head_base(
            &self.head,
            &self.base_target,
            self.base_tree_hash,
            "workspace",
        )?;
        let computed = compute_resolved_tree_hash(&self.tree)?;
        if computed != self.tree_hash {
            return Err(ModelError::InvalidOperation(format!(
                "workspace tree hash {} recomputes to {}",
                self.tree_hash, computed
            )));
        }
        let computed_overlay = self.semantic_overlay.identity_hash()?;
        if computed_overlay != self.semantic_overlay_hash {
            return Err(ModelError::InvalidOperation(format!(
                "workspace semantic overlay hash {} recomputes to {}",
                self.semantic_overlay_hash, computed_overlay
            )));
        }
        Ok(())
    }

    pub fn snapshot_binding(&self, roots: RootBundle) -> Result<WorkspaceSnapshotBinding> {
        self.validate()?;
        roots.validate()?;
        let binding = WorkspaceSnapshotBinding {
            repository_id: self.repository_id.clone(),
            workspace_id: self.workspace_id,
            workspace_head: self.head.clone(),
            base_target: self.base_target.clone(),
            base_tree_hash: self.base_tree_hash,
            workspace_tree_hash: self.tree_hash,
            workspace_semantic_overlay_hash: self.semantic_overlay_hash,
            roots,
            workspace_generation: self.generation,
            admission_policy: self.admission_policy,
        };
        binding.validate()?;
        Ok(binding)
    }

    pub fn is_dirty(&self) -> bool {
        !self.semantic_overlay.is_empty()
            || self
                .base_tree_hash
                .map_or(!self.tree.is_empty(), |base| base != self.tree_hash)
    }
}

/// Exact compare-and-swap expectation for persisted workspace authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
// This is a persisted wire contract used far more often as data than as a
// stack-local enum. Keeping the exact expectation inline avoids a boxed
// authority sub-object and an unnecessary public schema seam.
#[allow(clippy::large_enum_variant)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum WorkspaceExpectation {
    MustNotExist,
    MustEqual {
        generation: u64,
        head: WorkspaceHead,
        base_target: Option<RefTarget>,
        base_tree_hash: Option<Hash256>,
        tree_hash: Hash256,
        semantic_overlay_hash: Hash256,
        admission_policy: EffectiveAdmissionPolicyStamp,
    },
}

/// One exact graph-owned workspace transition.
///
/// The authority implementation applies `tree_deltas` and `semantic_delta` to
/// the graph identified by `expected`, derives the successor's cumulative
/// base-relative semantic overlay, verifies the exact result, and commits it
/// in the same repository transaction as history and ref updates.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct WorkspaceMutation {
    pub workspace_id: WorkspaceId,
    pub expected: WorkspaceExpectation,
    pub new_generation: u64,
    pub new_head: WorkspaceHead,
    pub new_base_target: Option<RefTarget>,
    pub new_base_tree_hash: Option<Hash256>,
    pub tree_deltas: Vec<TreeDelta>,
    pub new_tree_hash: Hash256,
    /// Incremental entity/relation transition from the expected workspace
    /// graph to the successor workspace graph. Durable storage derives and
    /// persists the cumulative base-relative overlay from this exact delta.
    pub semantic_delta: WorkspaceSemanticDelta,
    /// Complete shared policy active for the resulting workspace tree.
    ///
    /// A dirty or unborn workspace may contain a new `.gitignore` before any
    /// semantic change records that policy. Persisting only its stamp would
    /// leave storage unable to reproduce or validate the matcher inputs.
    pub new_shared_admission_policy: SharedAdmissionPolicy,
    pub new_admission_policy: EffectiveAdmissionPolicyStamp,
}

impl WorkspaceMutation {
    pub fn validate_against(
        &self,
        repository_id: &RepositoryId,
        current: Option<&WorkspaceState>,
        derived_semantic_overlay: WorkspaceSemanticOverlay,
    ) -> Result<WorkspaceState> {
        self.validate_shape()?;
        let (current_tree, expected_next_generation) = match (&self.expected, current) {
            (WorkspaceExpectation::MustNotExist, None) => (ResolvedTree::default(), 0),
            (WorkspaceExpectation::MustNotExist, Some(_)) => {
                return Err(ModelError::Conflict(format!(
                    "workspace {} already exists",
                    self.workspace_id
                )));
            }
            (
                WorkspaceExpectation::MustEqual {
                    generation,
                    head,
                    base_target,
                    base_tree_hash,
                    tree_hash,
                    semantic_overlay_hash,
                    admission_policy,
                },
                Some(current),
            ) => {
                current.validate()?;
                if current.repository_id != *repository_id
                    || current.workspace_id != self.workspace_id
                    || current.generation != *generation
                    || current.head != *head
                    || current.base_target != *base_target
                    || current.base_tree_hash != *base_tree_hash
                    || current.tree_hash != *tree_hash
                    || current.semantic_overlay_hash != *semantic_overlay_hash
                    || current.admission_policy != *admission_policy
                {
                    return Err(ModelError::Conflict(format!(
                        "workspace {} no longer matches its expected generation, head, base, tree, semantic overlay, and policy",
                        self.workspace_id
                    )));
                }
                (
                    current.tree.clone(),
                    current.generation.checked_add(1).ok_or_else(|| {
                        ModelError::InvalidOperation(format!(
                            "workspace {} generation overflow",
                            self.workspace_id
                        ))
                    })?,
                )
            }
            (WorkspaceExpectation::MustEqual { .. }, None) => {
                return Err(ModelError::Conflict(format!(
                    "workspace {} does not exist",
                    self.workspace_id
                )));
            }
        };

        if self.new_generation != expected_next_generation {
            return Err(ModelError::InvalidOperation(format!(
                "workspace {} generation must become {}, not {}",
                self.workspace_id, expected_next_generation, self.new_generation
            )));
        }

        let tree = current_tree.apply(&self.tree_deltas).map_err(|error| {
            ModelError::InvalidOperation(format!(
                "workspace {} tree transition is invalid: {error}",
                self.workspace_id
            ))
        })?;
        let computed_tree_hash = compute_resolved_tree_hash(&tree)?;
        if computed_tree_hash != self.new_tree_hash {
            return Err(ModelError::InvalidOperation(format!(
                "workspace {} new tree hash {} recomputes to {}",
                self.workspace_id, self.new_tree_hash, computed_tree_hash
            )));
        }

        WorkspaceState::new(
            repository_id.clone(),
            self.workspace_id,
            self.new_generation,
            self.new_head.clone(),
            self.new_base_target.clone(),
            self.new_base_tree_hash,
            tree,
            derived_semantic_overlay,
            self.new_shared_admission_policy.clone(),
            self.new_admission_policy,
        )
    }

    fn validate_shape(&self) -> Result<()> {
        self.semantic_delta.validate()?;
        self.new_shared_admission_policy.validate()?;
        if self.new_shared_admission_policy.stamp() != self.new_admission_policy.shared {
            return Err(ModelError::InvalidOperation(format!(
                "workspace {} shared admission policy does not match its effective policy stamp",
                self.workspace_id
            )));
        }

        let expected_tree = match &self.expected {
            WorkspaceExpectation::MustNotExist => {
                if self.new_generation != 0 {
                    return Err(ModelError::InvalidOperation(format!(
                        "new workspace {} must start at generation zero",
                        self.workspace_id
                    )));
                }
                ResolvedTree::default()
            }
            WorkspaceExpectation::MustEqual {
                generation,
                head,
                base_target,
                base_tree_hash,
                ..
            } => {
                if base_target.is_some() != base_tree_hash.is_some() {
                    return Err(ModelError::InvalidOperation(
                        "expected workspace base target and tree must both be present or absent"
                            .to_string(),
                    ));
                }
                validate_head_base(head, base_target, *base_tree_hash, "expected workspace")?;
                let next_generation = generation.checked_add(1).ok_or_else(|| {
                    ModelError::InvalidOperation(format!(
                        "workspace {} generation overflow",
                        self.workspace_id
                    ))
                })?;
                if self.new_generation != next_generation {
                    return Err(ModelError::InvalidOperation(format!(
                        "workspace {} generation must advance from {} to {}",
                        self.workspace_id, generation, next_generation
                    )));
                }
                // The actual old tree is storage authority. Duplicate targets
                // can still be rejected without loading it.
                ResolvedTree::default()
            }
        };

        let mut touched = BTreeSet::new();
        for delta in &self.tree_deltas {
            if !touched.insert(delta.artifact_id()) {
                return Err(ModelError::InvalidOperation(format!(
                    "workspace {} mutates artifact {:?} more than once",
                    self.workspace_id,
                    delta.artifact_id()
                )));
            }
        }
        if matches!(&self.expected, WorkspaceExpectation::MustNotExist) {
            let computed = expected_tree.apply(&self.tree_deltas).map_err(|error| {
                ModelError::InvalidOperation(format!(
                    "new workspace {} tree transition is invalid: {error}",
                    self.workspace_id
                ))
            })?;
            if compute_resolved_tree_hash(&computed)? != self.new_tree_hash {
                return Err(ModelError::InvalidOperation(format!(
                    "new workspace {} tree hash does not match its initial deltas",
                    self.workspace_id
                )));
            }
        }
        if self.new_base_target.is_some() != self.new_base_tree_hash.is_some() {
            return Err(ModelError::InvalidOperation(
                "new workspace base target and tree must both be present or absent".to_string(),
            ));
        }
        validate_head_base(
            &self.new_head,
            &self.new_base_target,
            self.new_base_tree_hash,
            "new workspace",
        )?;
        if let WorkspaceExpectation::MustEqual {
            head,
            base_target,
            base_tree_hash,
            tree_hash,
            admission_policy,
            ..
        } = &self.expected
        {
            if self.tree_deltas.is_empty()
                && self.new_head == *head
                && self.new_base_target == *base_target
                && self.new_base_tree_hash == *base_tree_hash
                && self.new_tree_hash == *tree_hash
                && self.semantic_delta.is_empty()
                && self.new_admission_policy == *admission_policy
            {
                return Err(ModelError::InvalidOperation(format!(
                    "workspace {} mutation is a no-op",
                    self.workspace_id
                )));
            }
        }
        Ok(())
    }
}

fn validate_head_base(
    head: &WorkspaceHead,
    base_target: &Option<RefTarget>,
    base_tree_hash: Option<Hash256>,
    label: &str,
) -> Result<()> {
    if matches!(base_target, Some(RefTarget::Symbolic { .. })) {
        return Err(ModelError::InvalidOperation(format!(
            "{label} base target must be resolved, not symbolic"
        )));
    }
    if let WorkspaceHead::Detached { target } = head {
        if matches!(target, RefTarget::Symbolic { .. }) {
            return Err(ModelError::InvalidOperation(format!(
                "{label} detached HEAD target must be resolved, not symbolic"
            )));
        }
        if base_target != &Some(target.clone()) || base_tree_hash.is_none() {
            return Err(ModelError::InvalidOperation(format!(
                "{label} detached HEAD must bind its exact target and tree"
            )));
        }
    }
    Ok(())
}

/// Append-only record of one committed repository operation.
///
/// This type is persisted through a positional MessagePack encoding. Any
/// future optional authority field must be appended after every existing field
/// and carry a compatibility round-trip proving older, shorter records still
/// decode. Inserting an optional field earlier shifts all following values.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepositoryOperationRecord {
    pub operation_id: OperationId,
    pub repository_id: RepositoryId,
    /// Canonical identity of the complete committed transaction, including
    /// history, raw-object descriptors, Git authority, aliases, refs,
    /// workspace, and policy.
    pub transaction_hash: Hash256,
    pub actor: AuthorId,
    pub committed_at: crate::Timestamp,
    /// Exact authority transition retained in the append-only audit record.
    pub git_authority_delta: Option<GitExternalAuthorityDelta>,
    pub ref_mutations: Vec<RefMutation>,
    pub default_ref_mutation: Option<DefaultRefMutation>,
    pub workspace_mutation: Option<WorkspaceMutation>,
    pub local_overlay_delta: Option<FrozenLocalOverlayDelta>,
    pub roots_before: RootBundle,
    pub roots_after: RootBundle,
    /// Exact transition of this workspace's durable merge record, when the
    /// operation opened, resolved, or terminated a merge.
    ///
    /// Optional and omitted when absent, so an operation that touches no merge
    /// serializes to the bytes it always did and keeps its identity under the
    /// existing hash domain.
    ///
    /// Deliberately last. Operation records are persisted inside a MessagePack
    /// snapshot, where a struct is an array and position decides the mapping,
    /// so an optional field is only additive at the end: an already-written
    /// record simply runs out of elements and takes the default. Anywhere else
    /// it would shift every field after it and silently mis-decode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub merge_transaction_delta: Option<MergeTransactionDelta>,
}

#[derive(Serialize)]
struct RepositoryOperationIdentity<'a> {
    operation_id: OperationId,
    repository_id: &'a RepositoryId,
    transaction_hash: Hash256,
    actor: &'a AuthorId,
    committed_at: &'a crate::Timestamp,
    git_authority_delta: &'a Option<GitExternalAuthorityDelta>,
    ref_mutations: &'a [RefMutation],
    default_ref_mutation: &'a Option<DefaultRefMutation>,
    workspace_mutation: &'a Option<WorkspaceMutation>,
    local_overlay_delta: &'a Option<FrozenLocalOverlayDelta>,
    #[serde(skip_serializing_if = "Option::is_none")]
    merge_transaction_delta: &'a Option<MergeTransactionDelta>,
}

impl RepositoryOperationRecord {
    pub fn validate(&self) -> Result<()> {
        if self.operation_id.as_uuid().is_nil() {
            return Err(ModelError::InvalidOperation(
                "repository operation id must not be nil".to_string(),
            ));
        }
        self.roots_before.validate()?;
        self.roots_after.validate()?;
        let next_generation = self.roots_before.generation.checked_add(1).ok_or_else(|| {
            ModelError::InvalidOperation("repository operation generation overflow".to_string())
        })?;
        if self.roots_after.generation != next_generation {
            return Err(ModelError::InvalidOperation(format!(
                "repository operation roots must advance generation from {} to {}",
                self.roots_before.generation, next_generation
            )));
        }
        if let Some(delta) = &self.git_authority_delta {
            delta
                .validate_for_repository(&self.repository_id)
                .map_err(|error| {
                    ModelError::InvalidOperation(format!(
                        "invalid Git external-authority operation delta: {error}"
                    ))
                })?;
        }
        let mut refs = BTreeSet::new();
        for mutation in &self.ref_mutations {
            mutation.validate()?;
            if !refs.insert(mutation.name.clone()) {
                return Err(ModelError::InvalidOperation(format!(
                    "repository operation mutates ref {} more than once",
                    mutation.name
                )));
            }
        }
        if let Some(mutation) = &self.default_ref_mutation {
            mutation.validate()?;
        }
        if let Some(mutation) = &self.workspace_mutation {
            mutation.validate_shape()?;
        }
        if let Some(delta) = &self.local_overlay_delta {
            delta.validate()?;
        }
        if let Some(delta) = &self.merge_transaction_delta {
            delta.validate()?;
        }
        Ok(())
    }

    /// Canonical ref-log leaf identity.
    ///
    /// Root bundles are transition evidence and intentionally excluded: the
    /// ref-log root is itself part of those bundles, so including them would
    /// make the identity circular.
    pub fn identity_hash(&self) -> Result<Hash256> {
        self.validate()?;
        let mut canonical = self.clone();
        canonical
            .ref_mutations
            .sort_by(|left, right| left.name.cmp(&right.name));
        if let Some(workspace) = &mut canonical.workspace_mutation {
            workspace.tree_deltas.sort_by_key(TreeDelta::artifact_id);
            workspace.semantic_delta.sort_canonical();
        }
        hash_serialized(
            b"kin-repository-operation-v4\0",
            &RepositoryOperationIdentity {
                operation_id: canonical.operation_id,
                repository_id: &canonical.repository_id,
                transaction_hash: canonical.transaction_hash,
                actor: &canonical.actor,
                committed_at: &canonical.committed_at,
                git_authority_delta: &canonical.git_authority_delta,
                ref_mutations: &canonical.ref_mutations,
                default_ref_mutation: &canonical.default_ref_mutation,
                workspace_mutation: &canonical.workspace_mutation,
                local_overlay_delta: &canonical.local_overlay_delta,
                merge_transaction_delta: &canonical.merge_transaction_delta,
            },
        )
    }
}

/// One atomic repository-authority transition.
///
/// This type is persisted through a positional MessagePack encoding. Any
/// future optional authority field must be appended after every existing field
/// and carry compatibility tests for every combination of adjacent optional
/// tail fields. A later tail value must keep an explicit `nil` placeholder for
/// any absent earlier value so positions never shift.
#[derive(Debug, Clone, PartialEq, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepositoryTransaction {
    pub schema_version: u32,
    pub operation_id: OperationId,
    pub repository_id: RepositoryId,
    pub expected_generation: u64,
    pub expected_roots: RootBundle,
    pub actor: AuthorId,
    pub reason: String,
    pub external_objects: Vec<ExternalObjectRecord>,
    /// Exact compare-and-swap of repository-scoped Git authority. Closure
    /// records may already exist in CAS and need not be repeated above.
    pub git_authority_delta: Option<GitExternalAuthorityDelta>,
    pub changes: Vec<SemanticChange>,
    pub aliases: Vec<ExternalChangeAlias>,
    pub ref_mutations: Vec<RefMutation>,
    pub default_ref_mutation: Option<DefaultRefMutation>,
    pub workspace_mutation: Option<WorkspaceMutation>,
    pub local_overlay_delta: Option<FrozenLocalOverlayDelta>,
    /// Exact transition of one workspace's durable merge record.
    ///
    /// A merge that composes cleanly publishes without one. This carries the
    /// merges that did not: opening a conflict set, settling an entry, and
    /// terminating by publishing the merge change or aborting back to the
    /// recorded restore point. Optional and omitted when absent, so a
    /// transaction that touches no merge keeps its existing identity.
    #[serde(default)]
    pub merge_transaction_delta: Option<MergeTransactionDelta>,
    /// Fingerprint and coverage of the admitted content closure observed by
    /// the enforcement layer.
    ///
    /// Repository storage validates only the binding's internal shape and
    /// binds it into transaction identity. It cannot re-derive the fingerprint;
    /// admission remains responsible for verifying it against graph-owned
    /// content before committing this transaction.
    ///
    /// Deliberately last. Positional serialization emits an explicit absent
    /// merge slot when this field is present without a merge delta.
    #[serde(default)]
    pub sealed_observation: Option<SealedObservationBinding>,
}

#[derive(Serialize)]
struct RepositoryTransactionHumanReadable<'a> {
    schema_version: u32,
    operation_id: OperationId,
    repository_id: &'a RepositoryId,
    expected_generation: u64,
    expected_roots: &'a RootBundle,
    actor: &'a AuthorId,
    reason: &'a str,
    external_objects: &'a [ExternalObjectRecord],
    git_authority_delta: &'a Option<GitExternalAuthorityDelta>,
    changes: &'a [SemanticChange],
    aliases: &'a [ExternalChangeAlias],
    ref_mutations: &'a [RefMutation],
    default_ref_mutation: &'a Option<DefaultRefMutation>,
    workspace_mutation: &'a Option<WorkspaceMutation>,
    local_overlay_delta: &'a Option<FrozenLocalOverlayDelta>,
    #[serde(skip_serializing_if = "Option::is_none")]
    merge_transaction_delta: &'a Option<MergeTransactionDelta>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sealed_observation: &'a Option<SealedObservationBinding>,
}

impl Serialize for RepositoryTransaction {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            return RepositoryTransactionHumanReadable {
                schema_version: self.schema_version,
                operation_id: self.operation_id,
                repository_id: &self.repository_id,
                expected_generation: self.expected_generation,
                expected_roots: &self.expected_roots,
                actor: &self.actor,
                reason: &self.reason,
                external_objects: &self.external_objects,
                git_authority_delta: &self.git_authority_delta,
                changes: &self.changes,
                aliases: &self.aliases,
                ref_mutations: &self.ref_mutations,
                default_ref_mutation: &self.default_ref_mutation,
                workspace_mutation: &self.workspace_mutation,
                local_overlay_delta: &self.local_overlay_delta,
                merge_transaction_delta: &self.merge_transaction_delta,
                sealed_observation: &self.sealed_observation,
            }
            .serialize(serializer);
        }

        use serde::ser::SerializeSeq;

        const LEGACY_FIELD_COUNT: usize = 15;
        let has_merge_slot =
            self.merge_transaction_delta.is_some() || self.sealed_observation.is_some();
        let field_count = LEGACY_FIELD_COUNT
            + usize::from(has_merge_slot)
            + usize::from(self.sealed_observation.is_some());
        let mut sequence = serializer.serialize_seq(Some(field_count))?;
        sequence.serialize_element(&self.schema_version)?;
        sequence.serialize_element(&self.operation_id)?;
        sequence.serialize_element(&self.repository_id)?;
        sequence.serialize_element(&self.expected_generation)?;
        sequence.serialize_element(&self.expected_roots)?;
        sequence.serialize_element(&self.actor)?;
        sequence.serialize_element(&self.reason)?;
        sequence.serialize_element(&self.external_objects)?;
        sequence.serialize_element(&self.git_authority_delta)?;
        sequence.serialize_element(&self.changes)?;
        sequence.serialize_element(&self.aliases)?;
        sequence.serialize_element(&self.ref_mutations)?;
        sequence.serialize_element(&self.default_ref_mutation)?;
        sequence.serialize_element(&self.workspace_mutation)?;
        sequence.serialize_element(&self.local_overlay_delta)?;
        if has_merge_slot {
            sequence.serialize_element(&self.merge_transaction_delta)?;
        }
        if self.sealed_observation.is_some() {
            sequence.serialize_element(&self.sealed_observation)?;
        }
        sequence.end()
    }
}

/// Canonically ordered view of a transaction that borrows rather than clones.
///
/// [`RepositoryTransaction::canonical_hash`] must sort several collections
/// before it serializes, and the only way to sort an owned `Vec` is to own it.
/// The implementation this replaced cloned the entire transaction to get
/// something mutable, which on a whole-history import is a second copy of every
/// change, every tree delta and every external object, charged at the point
/// admission already holds its largest working set. Measured at 259 MiB
/// transient on a 32-commit fixture, and it ran on every commit.
///
/// This holds `&` to the original plus one `Vec` of references per sorted
/// collection, so the cost is a pointer per element instead of a deep copy.
///
/// # The obligation these types carry
///
/// The bytes are a durable identity. `transaction_hash` is stored in every
/// [`RepositoryCommitReceipt`] and compared on idempotent replay, so a view that
/// serializes one byte differently from the owned type invalidates receipts
/// already on disk. Each type below therefore mirrors its owned counterpart's
/// serialization exactly: the same struct name, the same field names in the
/// same order, the same field count, and the same skip rules. Where the owned
/// type hand-writes its encoding, the view hand-writes the same one; where the
/// owned type derives, the view reproduces what that derive emits.
///
/// Enforced by `the_canonicalization_matches_the_implementation_it_replaced`
/// and `the_canonical_view_serializes_positionally_identical_bytes`. The first
/// runs the production hash against the retained cloning reference over 64
/// permutations. The second is not redundant: the hash encodes through
/// `canonical_json_bytes`, whose object encoder sorts keys, so field ORDER is
/// invisible to it. The positional test drives the non-human-readable branch,
/// where order, struct name and field count are all load-bearing.
struct CanonicalTransaction<'a> {
    source: &'a RepositoryTransaction,
    changes: Vec<CanonicalChange<'a>>,
    external_objects: Vec<&'a ExternalObjectRecord>,
    aliases: Vec<&'a ExternalChangeAlias>,
    ref_mutations: Vec<&'a RefMutation>,
    workspace_mutation: Option<CanonicalWorkspaceMutation<'a>>,
}

impl<'a> CanonicalTransaction<'a> {
    fn new(source: &'a RepositoryTransaction) -> Self {
        let mut changes: Vec<CanonicalChange<'a>> =
            source.changes.iter().map(CanonicalChange::new).collect();
        changes.sort_by_key(|change| change.source.id);

        let mut external_objects: Vec<&'a ExternalObjectRecord> =
            source.external_objects.iter().collect();
        external_objects.sort_by_key(|record| record.object);

        let mut aliases: Vec<&'a ExternalChangeAlias> = source.aliases.iter().collect();
        aliases.sort_by_key(|alias| alias.oid);

        let mut ref_mutations: Vec<&'a RefMutation> = source.ref_mutations.iter().collect();
        ref_mutations.sort_by(|left, right| left.name.cmp(&right.name));

        Self {
            source,
            changes,
            external_objects,
            aliases,
            ref_mutations,
            workspace_mutation: source
                .workspace_mutation
                .as_ref()
                .map(CanonicalWorkspaceMutation::new),
        }
    }
}

impl Serialize for CanonicalTransaction<'_> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let source = self.source;

        if serializer.is_human_readable() {
            use serde::ser::SerializeStruct;

            // Mirrors the derive on `RepositoryTransactionHumanReadable`,
            // including its name: a serializer that records struct names must
            // see the same one. Its two tail fields skip independently on their
            // own `Option::is_none`, which is NOT the positional branch's rule.
            const HUMAN_READABLE_FIELD_COUNT: usize = 15;
            let field_count = HUMAN_READABLE_FIELD_COUNT
                + usize::from(source.merge_transaction_delta.is_some())
                + usize::from(source.sealed_observation.is_some());
            let mut state =
                serializer.serialize_struct("RepositoryTransactionHumanReadable", field_count)?;
            state.serialize_field("schema_version", &source.schema_version)?;
            state.serialize_field("operation_id", &source.operation_id)?;
            state.serialize_field("repository_id", &source.repository_id)?;
            state.serialize_field("expected_generation", &source.expected_generation)?;
            state.serialize_field("expected_roots", &source.expected_roots)?;
            state.serialize_field("actor", &source.actor)?;
            state.serialize_field("reason", source.reason.as_str())?;
            state.serialize_field("external_objects", &self.external_objects)?;
            state.serialize_field("git_authority_delta", &source.git_authority_delta)?;
            state.serialize_field("changes", &self.changes)?;
            state.serialize_field("aliases", &self.aliases)?;
            state.serialize_field("ref_mutations", &self.ref_mutations)?;
            state.serialize_field("default_ref_mutation", &source.default_ref_mutation)?;
            state.serialize_field("workspace_mutation", &self.workspace_mutation)?;
            state.serialize_field("local_overlay_delta", &source.local_overlay_delta)?;
            if source.merge_transaction_delta.is_some() {
                state
                    .serialize_field("merge_transaction_delta", &source.merge_transaction_delta)?;
            }
            if source.sealed_observation.is_some() {
                state.serialize_field("sealed_observation", &source.sealed_observation)?;
            }
            return state.end();
        }

        use serde::ser::SerializeSeq;

        // Mirrors the positional branch of `impl Serialize for
        // RepositoryTransaction`, whose element count varies with which
        // optional tail fields are present.
        const LEGACY_FIELD_COUNT: usize = 15;
        let has_merge_slot =
            source.merge_transaction_delta.is_some() || source.sealed_observation.is_some();
        let field_count = LEGACY_FIELD_COUNT
            + usize::from(has_merge_slot)
            + usize::from(source.sealed_observation.is_some());
        let mut sequence = serializer.serialize_seq(Some(field_count))?;
        sequence.serialize_element(&source.schema_version)?;
        sequence.serialize_element(&source.operation_id)?;
        sequence.serialize_element(&source.repository_id)?;
        sequence.serialize_element(&source.expected_generation)?;
        sequence.serialize_element(&source.expected_roots)?;
        sequence.serialize_element(&source.actor)?;
        sequence.serialize_element(&source.reason)?;
        sequence.serialize_element(&self.external_objects)?;
        sequence.serialize_element(&source.git_authority_delta)?;
        sequence.serialize_element(&self.changes)?;
        sequence.serialize_element(&self.aliases)?;
        sequence.serialize_element(&self.ref_mutations)?;
        sequence.serialize_element(&source.default_ref_mutation)?;
        sequence.serialize_element(&self.workspace_mutation)?;
        sequence.serialize_element(&source.local_overlay_delta)?;
        if has_merge_slot {
            sequence.serialize_element(&source.merge_transaction_delta)?;
        }
        if source.sealed_observation.is_some() {
            sequence.serialize_element(&source.sealed_observation)?;
        }
        sequence.end()
    }
}

/// Canonically ordered view of one [`SemanticChange`].
///
/// Mirrors that type's derive rather than a hand-written encoding, so the
/// obligation is field order, the struct name, and the trailing
/// `skip_serializing_if = "Vec::is_empty"` on `external_reference_deltas`.
struct CanonicalChange<'a> {
    source: &'a SemanticChange,
    entity_deltas: Vec<&'a EntityDelta>,
    relation_deltas: Vec<&'a RelationDelta>,
    tree_deltas: Vec<&'a TreeDelta>,
    external_reference_deltas: Vec<&'a ExternalReferenceDelta>,
}

impl<'a> CanonicalChange<'a> {
    fn new(source: &'a SemanticChange) -> Self {
        let mut entity_deltas: Vec<&'a EntityDelta> = source.entity_deltas.iter().collect();
        entity_deltas.sort_by_key(|delta| EntityDelta::target_id(delta));

        let mut relation_deltas: Vec<&'a RelationDelta> = source.relation_deltas.iter().collect();
        relation_deltas.sort_by_key(|delta| RelationDelta::target_id(delta));

        let mut tree_deltas: Vec<&'a TreeDelta> = source.tree_deltas.iter().collect();
        tree_deltas.sort_by_key(|delta| TreeDelta::artifact_id(delta));

        let mut external_reference_deltas: Vec<&'a ExternalReferenceDelta> =
            source.external_reference_deltas.iter().collect();
        external_reference_deltas.sort_by_key(|delta| ExternalReferenceDelta::target_id(delta));

        Self {
            source,
            entity_deltas,
            relation_deltas,
            tree_deltas,
            external_reference_deltas,
        }
    }
}

impl Serialize for CanonicalChange<'_> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        let source = self.source;
        const ALWAYS_PRESENT_FIELD_COUNT: usize = 14;
        let field_count =
            ALWAYS_PRESENT_FIELD_COUNT + usize::from(!self.external_reference_deltas.is_empty());
        let mut state = serializer.serialize_struct("SemanticChange", field_count)?;
        state.serialize_field("id", &source.id)?;
        state.serialize_field("origin", &source.origin)?;
        state.serialize_field("parents", &source.parents)?;
        state.serialize_field("timestamp", &source.timestamp)?;
        state.serialize_field("author", &source.author)?;
        state.serialize_field("message", &source.message)?;
        state.serialize_field("entity_deltas", &self.entity_deltas)?;
        state.serialize_field("relation_deltas", &self.relation_deltas)?;
        state.serialize_field("tree_deltas", &self.tree_deltas)?;
        state.serialize_field("admission_policy_delta", &source.admission_policy_delta)?;
        state.serialize_field("projected_files", &source.projected_files)?;
        state.serialize_field("spec_link", &source.spec_link)?;
        state.serialize_field("evidence", &source.evidence)?;
        state.serialize_field("risk_summary", &source.risk_summary)?;
        if !self.external_reference_deltas.is_empty() {
            state.serialize_field("external_reference_deltas", &self.external_reference_deltas)?;
        }
        state.end()
    }
}

/// Canonically ordered view of one [`WorkspaceMutation`].
///
/// Mirrors that type's derive: eleven fields, none skipped.
struct CanonicalWorkspaceMutation<'a> {
    source: &'a WorkspaceMutation,
    tree_deltas: Vec<&'a TreeDelta>,
    semantic_delta: CanonicalWorkspaceSemanticDelta<'a>,
}

impl<'a> CanonicalWorkspaceMutation<'a> {
    fn new(source: &'a WorkspaceMutation) -> Self {
        let mut tree_deltas: Vec<&'a TreeDelta> = source.tree_deltas.iter().collect();
        tree_deltas.sort_by_key(|delta| TreeDelta::artifact_id(delta));
        Self {
            source,
            tree_deltas,
            semantic_delta: CanonicalWorkspaceSemanticDelta::new(&source.semantic_delta),
        }
    }
}

impl Serialize for CanonicalWorkspaceMutation<'_> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        let source = self.source;
        let mut state = serializer.serialize_struct("WorkspaceMutation", 11)?;
        state.serialize_field("workspace_id", &source.workspace_id)?;
        state.serialize_field("expected", &source.expected)?;
        state.serialize_field("new_generation", &source.new_generation)?;
        state.serialize_field("new_head", &source.new_head)?;
        state.serialize_field("new_base_target", &source.new_base_target)?;
        state.serialize_field("new_base_tree_hash", &source.new_base_tree_hash)?;
        state.serialize_field("tree_deltas", &self.tree_deltas)?;
        state.serialize_field("new_tree_hash", &source.new_tree_hash)?;
        state.serialize_field("semantic_delta", &self.semantic_delta)?;
        state.serialize_field(
            "new_shared_admission_policy",
            &source.new_shared_admission_policy,
        )?;
        state.serialize_field("new_admission_policy", &source.new_admission_policy)?;
        state.end()
    }
}

/// Canonically ordered view of one [`WorkspaceSemanticDelta`].
///
/// The only collection here that a valid transaction can carry out of order is
/// none of them: `WorkspaceSemanticDelta::validate` REJECTS non-canonical order
/// rather than canonicalizing it, so this view's sorting is defensive against
/// input that cannot legally arrive. It is still exercised, because the
/// differential drives `canonical_hash` directly and can therefore feed it
/// orderings no valid transaction may carry.
struct CanonicalWorkspaceSemanticDelta<'a> {
    source: &'a WorkspaceSemanticDelta,
    entity_deltas: Vec<&'a EntityDelta>,
    relation_deltas: Vec<&'a RelationDelta>,
    external_reference_deltas: Vec<&'a ExternalReferenceDelta>,
}

impl<'a> CanonicalWorkspaceSemanticDelta<'a> {
    fn new(source: &'a WorkspaceSemanticDelta) -> Self {
        let mut entity_deltas: Vec<&'a EntityDelta> = source.entity_deltas.iter().collect();
        entity_deltas.sort_by_key(|delta| EntityDelta::target_id(delta));

        let mut relation_deltas: Vec<&'a RelationDelta> = source.relation_deltas.iter().collect();
        relation_deltas.sort_by_key(|delta| RelationDelta::target_id(delta));

        let mut external_reference_deltas: Vec<&'a ExternalReferenceDelta> =
            source.external_reference_deltas.iter().collect();
        external_reference_deltas.sort_by_key(|delta| ExternalReferenceDelta::target_id(delta));

        Self {
            source,
            entity_deltas,
            relation_deltas,
            external_reference_deltas,
        }
    }
}

impl Serialize for CanonicalWorkspaceSemanticDelta<'_> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;

        const ALWAYS_PRESENT_FIELD_COUNT: usize = 3;
        let field_count =
            ALWAYS_PRESENT_FIELD_COUNT + usize::from(!self.external_reference_deltas.is_empty());
        let mut state = serializer.serialize_struct("WorkspaceSemanticDelta", field_count)?;
        state.serialize_field("version", &self.source.version)?;
        state.serialize_field("entity_deltas", &self.entity_deltas)?;
        state.serialize_field("relation_deltas", &self.relation_deltas)?;
        if !self.external_reference_deltas.is_empty() {
            state.serialize_field("external_reference_deltas", &self.external_reference_deltas)?;
        }
        state.end()
    }
}

impl RepositoryTransaction {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != REPOSITORY_TRANSACTION_SCHEMA_VERSION {
            return Err(ModelError::InvalidOperation(format!(
                "unsupported repository transaction version {}",
                self.schema_version
            )));
        }
        if self.operation_id.as_uuid().is_nil() {
            return Err(ModelError::InvalidOperation(
                "repository transaction operation id must not be nil".to_string(),
            ));
        }
        if self.reason.trim().is_empty() {
            return Err(ModelError::InvalidOperation(
                "repository transaction requires a reason".to_string(),
            ));
        }
        if self.external_objects.is_empty()
            && self.git_authority_delta.is_none()
            && self.changes.is_empty()
            && self.aliases.is_empty()
            && self.ref_mutations.is_empty()
            && self.default_ref_mutation.is_none()
            && self.workspace_mutation.is_none()
            && self.local_overlay_delta.is_none()
            && self.merge_transaction_delta.is_none()
        {
            return Err(ModelError::InvalidOperation(
                "repository transaction must contain at least one mutation".to_string(),
            ));
        }
        self.expected_roots.validate()?;
        if self.expected_generation != self.expected_roots.generation {
            return Err(ModelError::InvalidOperation(format!(
                "expected generation {} does not match root bundle generation {}",
                self.expected_generation, self.expected_roots.generation
            )));
        }

        let mut changes = BTreeMap::new();
        for change in &self.changes {
            validate_semantic_change_id(change)?;
            if changes.insert(change.id, change).is_some() {
                return Err(ModelError::InvalidOperation(format!(
                    "repository transaction contains duplicate change {}",
                    change.id
                )));
            }
        }

        let mut objects = BTreeSet::new();
        for object in &self.external_objects {
            if !objects.insert(object.object) {
                return Err(ModelError::InvalidOperation(format!(
                    "repository transaction contains duplicate external object {}",
                    object.object.oid
                )));
            }
        }

        if let Some(delta) = &self.git_authority_delta {
            delta
                .validate_for_repository(&self.repository_id)
                .map_err(|error| {
                    ModelError::InvalidOperation(format!(
                        "invalid Git external-authority transaction delta: {error}"
                    ))
                })?;
        }

        let mut aliases = BTreeMap::new();
        for alias in &self.aliases {
            if alias.repository_id != self.repository_id {
                return Err(ModelError::InvalidOperation(format!(
                    "external alias repository {} does not match transaction repository {}",
                    alias.repository_id, self.repository_id
                )));
            }
            if let Some(previous) = aliases.insert(alias.oid, alias.change_id) {
                if previous != alias.change_id {
                    return Err(ModelError::Conflict(format!(
                        "transaction attempts to bind external commit {} to both {} and {}",
                        alias.oid, previous, alias.change_id
                    )));
                }
                return Err(ModelError::InvalidOperation(format!(
                    "repository transaction repeats external alias {}",
                    alias.oid
                )));
            }
            if let Some(change) = changes.get(&alias.change_id) {
                alias.validate_change(change)?;
            }
        }

        for change in &self.changes {
            if let crate::ChangeOrigin::GitCommit { oid } = change.origin {
                let commit = crate::ExternalObjectId::new(ExternalObjectKind::Commit, oid);
                if !objects.contains(&commit) {
                    return Err(ModelError::InvalidOperation(format!(
                        "Git-origin change {} lacks raw commit object {}",
                        change.id, oid
                    )));
                }
                if aliases.get(&oid) != Some(&change.id) {
                    return Err(ModelError::InvalidOperation(format!(
                        "Git-origin change {} lacks its final alias for {}",
                        change.id, oid
                    )));
                }
            }
        }

        let mut refs = BTreeSet::new();
        for mutation in &self.ref_mutations {
            mutation.validate()?;
            if !refs.insert(mutation.name.clone()) {
                return Err(ModelError::InvalidOperation(format!(
                    "repository transaction mutates ref {} more than once",
                    mutation.name
                )));
            }
        }
        if let Some(mutation) = &self.default_ref_mutation {
            mutation.validate()?;
        }

        if let Some(workspace) = &self.workspace_mutation {
            workspace.validate_shape()?;
        }

        if let Some(overlay_delta) = &self.local_overlay_delta {
            overlay_delta.validate()?;
            let new_overlay = overlay_delta.new.as_ref().ok_or_else(|| {
                ModelError::InvalidOperation(
                    "repository transaction cannot remove a required local overlay".to_string(),
                )
            })?;
            let workspace = self.workspace_mutation.as_ref().ok_or_else(|| {
                ModelError::InvalidOperation(
                    "local overlay mutation is not bound to a workspace mutation".to_string(),
                )
            })?;
            if workspace.workspace_id != new_overlay.workspace_id
                || workspace.new_admission_policy.local != new_overlay.stamp()
            {
                return Err(ModelError::InvalidOperation(
                    "local overlay mutation and workspace state must bind the same workspace and new overlay stamp"
                        .to_string(),
                ));
            }
        }

        if let Some(merge_delta) = &self.merge_transaction_delta {
            merge_delta.validate()?;
            for record in [merge_delta.old.as_ref(), merge_delta.new.as_ref()]
                .into_iter()
                .flatten()
            {
                if record.repository_id != self.repository_id {
                    return Err(ModelError::InvalidOperation(format!(
                        "merge transaction record repository {} does not match transaction \
                         repository {}",
                        record.repository_id, self.repository_id
                    )));
                }
            }
            if let Some(workspace) = &self.workspace_mutation {
                if merge_delta.workspace_id() != Some(workspace.workspace_id) {
                    return Err(ModelError::InvalidOperation(
                        "merge transaction record and workspace mutation must bind the same \
                         workspace"
                            .to_string(),
                    ));
                }
            }
        }

        if let Some(binding) = &self.sealed_observation {
            binding.validate()?;
        }

        Ok(())
    }

    pub fn transaction_hash(&self) -> Result<Hash256> {
        // Deliberately first, and deliberately still here: hash-implies-valid is
        // contract other callers rely on, so the canonicalization below is split
        // out beneath it rather than in front of it.
        self.validate()?;
        self.canonical_hash()
    }

    /// Canonical identity of this transaction, without validating it.
    ///
    /// Split from [`Self::transaction_hash`] so the canonicalization can be
    /// exercised against transactions built purely to vary ordering, which need
    /// not satisfy `validate`. Callers outside tests want `transaction_hash`,
    /// which validates first.
    fn canonical_hash(&self) -> Result<Hash256> {
        hash_serialized(
            b"kin-repository-transaction-v4\0",
            &CanonicalTransaction::new(self),
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RepositoryCommitOutcome {
    Committed,
    IdempotentReplay,
}

/// Durable result returned for a committed or idempotently replayed operation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepositoryCommitReceipt {
    pub operation_id: OperationId,
    pub repository_id: RepositoryId,
    pub transaction_hash: Hash256,
    pub outcome: RepositoryCommitOutcome,
    pub generation: u64,
    pub roots_before: RootBundle,
    pub roots_after: RootBundle,
    pub operation: RepositoryOperationRecord,
}

impl RepositoryCommitReceipt {
    pub fn validate(&self) -> Result<()> {
        self.operation.validate()?;
        if self.operation_id != self.operation.operation_id
            || self.repository_id != self.operation.repository_id
            || self.transaction_hash != self.operation.transaction_hash
            || self.roots_before != self.operation.roots_before
            || self.roots_after != self.operation.roots_after
        {
            return Err(ModelError::InvalidOperation(
                "repository receipt does not match its operation record".to_string(),
            ));
        }
        if self.generation != self.roots_after.generation {
            return Err(ModelError::InvalidOperation(format!(
                "repository receipt generation {} does not match roots-after generation {}",
                self.generation, self.roots_after.generation
            )));
        }
        Ok(())
    }
}

/// Storage boundary implemented by the durable repository authority.
pub trait RepositoryAuthorityStore: Send + Sync {
    type Error: std::error::Error + Send + Sync + 'static;

    fn commit_repository_transaction(
        &self,
        transaction: RepositoryTransaction,
    ) -> std::result::Result<RepositoryCommitReceipt, Self::Error>;

    fn get_repository_ref(
        &self,
        repository_id: &RepositoryId,
        name: &RefName,
    ) -> std::result::Result<Option<RepositoryRef>, Self::Error>;

    fn list_repository_refs(
        &self,
        repository_id: &RepositoryId,
    ) -> std::result::Result<Vec<RepositoryRef>, Self::Error>;

    fn resolve_external_alias(
        &self,
        repository_id: &RepositoryId,
        oid: &GitObjectId,
    ) -> std::result::Result<Option<SemanticChangeId>, Self::Error>;

    fn workspace_snapshot_binding(
        &self,
        repository_id: &RepositoryId,
        workspace_id: &WorkspaceId,
    ) -> std::result::Result<Option<WorkspaceSnapshotBinding>, Self::Error>;

    fn get_workspace_state(
        &self,
        repository_id: &RepositoryId,
        workspace_id: &WorkspaceId,
    ) -> std::result::Result<Option<WorkspaceState>, Self::Error>;
}

/// Canonical identity of an exact resolved repository tree.
pub fn compute_resolved_tree_hash(tree: &ResolvedTree) -> Result<Hash256> {
    hash_serialized(b"kin-resolved-tree-v1\0", tree)
}

fn hash_serialized(domain: &[u8], value: &impl Serialize) -> Result<Hash256> {
    let payload = canonical_json_bytes(value)?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(
        u64::try_from(payload.len())
            .map_err(|_| {
                ModelError::InvalidOperation("repository transaction exceeds u64".to_string())
            })?
            .to_le_bytes(),
    );
    hasher.update(payload);
    let digest = hasher.finalize();
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(&digest);
    Ok(Hash256::from_bytes(bytes))
}

#[cfg(test)]
mod tests {
    use std::convert::Infallible;

    use sha1::Sha1;

    use super::*;
    use crate::{
        AdmissionCase, AdmissionPolicyStamp, AdmissionRuleSource, AdmissionRuleSourceKind,
        ArtifactId, Entity, EntityId, EntityKind, EntityMetadata, ExternalObjectId,
        ExternalReference, FingerprintAlgorithm, FrozenLocalOverlay, GitExternalAuthority,
        GitObjectBodyLoader, GitObjectFormat, GitRawRef, GitRawTarget, LanguageId,
        LocalOverlayHash, LocalOverlayStamp, LocatedEntry, RefExpectation, RefUpdatePolicy,
        RepoPath, SemanticFingerprint, SharedAdmissionPolicy, TreeEntry, Visibility,
    };
    use uuid::Uuid;

    #[derive(Default)]
    struct TestBodies(BTreeMap<Hash256, Vec<u8>>);

    impl GitObjectBodyLoader for TestBodies {
        type Error = Infallible;

        fn load_body(
            &mut self,
            body_hash: &Hash256,
        ) -> std::result::Result<Option<Vec<u8>>, Self::Error> {
            Ok(self.0.get(body_hash).cloned())
        }
    }

    fn root(byte: u8) -> AuthorityRoot {
        AuthorityRoot::new(
            REPOSITORY_ROOT_SCHEMA_VERSION,
            Hash256::from_bytes([byte; 32]),
        )
    }

    fn roots() -> RootBundle {
        RootBundle {
            version: REPOSITORY_ROOT_SCHEMA_VERSION,
            generation: 7,
            history: root(1),
            ref_state: root(2),
            ref_log: root(3),
            collaboration: root(4),
            replication: root(5),
            local_state: root(6),
        }
    }

    fn blob_git_authority(repository_id: RepositoryId, body: &[u8]) -> GitExternalAuthority {
        let mut envelope = format!("blob {}\0", body.len()).into_bytes();
        envelope.extend_from_slice(body);
        let digest = Sha1::digest(&envelope);
        let mut oid = [0_u8; 20];
        oid.copy_from_slice(&digest);
        let object = ExternalObjectId::new(ExternalObjectKind::Blob, GitObjectId::sha1(oid));
        let record =
            ExternalObjectRecord::from_raw(ExternalObjectKind::Blob, object.oid, body).unwrap();
        let mut bodies = TestBodies::default();
        bodies.0.insert(record.body_hash, body.to_vec());
        let main = RefName::branch(b"main").unwrap();
        GitExternalAuthority::from_raw_parts(
            repository_id,
            GitObjectFormat::Sha1,
            vec![GitRawRef {
                name: main.clone(),
                target: GitRawTarget::Direct { object },
            }],
            GitRawTarget::Symbolic { target: main },
            vec![record],
            &mut bodies,
        )
        .unwrap()
    }

    fn authority_only_transaction(delta: GitExternalAuthorityDelta) -> RepositoryTransaction {
        let mut transaction = workspace_transaction();
        transaction.reason = "replace external Git authority atomically".to_string();
        transaction.git_authority_delta = Some(delta);
        transaction.workspace_mutation = None;
        transaction.local_overlay_delta = None;
        transaction
    }

    #[test]
    fn replicated_truth_equality_excludes_generation_and_local_state_only() {
        let expected = roots();
        let mut local_only = expected.clone();
        local_only.generation = expected.generation + 9;
        local_only.local_state = root(0x70);
        assert!(expected.has_same_replicated_truth(&local_only));
        assert_ne!(expected, local_only);

        let mut variants = Vec::new();
        let mut version = expected.clone();
        version.version += 1;
        variants.push(version);
        let mut history = expected.clone();
        history.history = root(0x71);
        variants.push(history);
        let mut ref_state = expected.clone();
        ref_state.ref_state = root(0x72);
        variants.push(ref_state);
        let mut ref_log = expected.clone();
        ref_log.ref_log = root(0x73);
        variants.push(ref_log);
        let mut collaboration = expected.clone();
        collaboration.collaboration = root(0x74);
        variants.push(collaboration);
        let mut replication = expected.clone();
        replication.replication = root(0x75);
        variants.push(replication);

        for changed in variants {
            assert!(!expected.has_same_replicated_truth(&changed));
        }
    }

    #[test]
    fn root_bundle_rejects_mixed_partition_schema_versions() {
        let mut invalid = roots();
        invalid.replication.version += 1;
        let error = invalid.validate().unwrap_err();
        assert!(error
            .to_string()
            .contains("unsupported replication authority root version"));
    }

    fn admission_policy(
        workspace_id: WorkspaceId,
    ) -> (
        SharedAdmissionPolicy,
        EffectiveAdmissionPolicyStamp,
        FrozenLocalOverlayDelta,
    ) {
        let shared = SharedAdmissionPolicy::empty(0);
        let local =
            FrozenLocalOverlay::new(workspace_id, 0, AdmissionCase::Sensitive, Vec::new()).unwrap();
        (
            shared.clone(),
            EffectiveAdmissionPolicyStamp {
                shared: shared.stamp(),
                local: local.stamp(),
            },
            FrozenLocalOverlayDelta::initialize(local),
        )
    }

    fn add_artifact(
        artifact_id: ArtifactId,
        path: impl Into<Vec<u8>>,
        byte: u8,
        executable: bool,
    ) -> TreeDelta {
        TreeDelta::Added {
            artifact_id,
            new: LocatedEntry::new(
                RepoPath::from_bytes(path).unwrap(),
                TreeEntry::blob(Hash256::from_bytes([byte; 32]), executable),
            ),
        }
    }

    fn semantic_entity(id: u128, name: &str) -> Entity {
        Entity {
            id: EntityId(Uuid::from_u128(id)),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([id as u8; 32]),
                signature_hash: Hash256::from_bytes([id as u8; 32]),
                behavior_hash: Hash256::from_bytes([id as u8; 32]),
                equivalence_hash: Hash256::from_bytes([id as u8; 32]),
                stability_score: 1.0,
            },
            file_origin: None,
            span: None,
            signature: format!("fn {name}()"),
            visibility: Visibility::Private,
            role: Default::default(),
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    fn create_workspace_mutation(
        workspace_id: WorkspaceId,
        shared_policy: SharedAdmissionPolicy,
        policy: EffectiveAdmissionPolicyStamp,
        deltas: Vec<TreeDelta>,
    ) -> WorkspaceMutation {
        let tree = ResolvedTree::default().apply(&deltas).unwrap();
        WorkspaceMutation {
            workspace_id,
            expected: WorkspaceExpectation::MustNotExist,
            new_generation: 0,
            new_head: WorkspaceHead::Symbolic {
                target: RefName::branch(b"main").unwrap(),
            },
            new_base_target: None,
            new_base_tree_hash: None,
            tree_deltas: deltas,
            new_tree_hash: compute_resolved_tree_hash(&tree).unwrap(),
            semantic_delta: WorkspaceSemanticDelta::default(),
            new_shared_admission_policy: shared_policy,
            new_admission_policy: policy,
        }
    }

    fn workspace_transaction() -> RepositoryTransaction {
        let repository_id = RepositoryId::new("repo").unwrap();
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(9));
        let (shared_policy, policy, local_overlay_delta) = admission_policy(workspace_id);
        let mutation = create_workspace_mutation(
            workspace_id,
            shared_policy,
            policy,
            vec![
                add_artifact(
                    ArtifactId(Uuid::from_u128(10)),
                    b"compose.yaml".to_vec(),
                    0x41,
                    false,
                ),
                add_artifact(
                    ArtifactId(Uuid::from_u128(11)),
                    b"assets/data-\xff.bin".to_vec(),
                    0x42,
                    false,
                ),
            ],
        );
        RepositoryTransaction {
            schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
            operation_id: OperationId::from_uuid(Uuid::from_u128(12)),
            repository_id: repository_id.clone(),
            expected_generation: 7,
            expected_roots: roots(),
            actor: AuthorId::new("actor"),
            reason: "capture exact workspace".to_string(),
            external_objects: Vec::new(),
            git_authority_delta: None,
            changes: Vec::new(),
            aliases: Vec::new(),
            ref_mutations: Vec::new(),
            default_ref_mutation: None,
            workspace_mutation: Some(mutation),
            local_overlay_delta: Some(local_overlay_delta),
            merge_transaction_delta: None,
            sealed_observation: None,
        }
    }

    /// Thread-local peak-live-bytes probe for the canonicalization measurement.
    ///
    /// Thread-local rather than process-wide on purpose: `cargo test` runs this
    /// binary's tests in parallel threads, and a global counter would be moved
    /// by whatever else happens to be running, which is the difference between
    /// a measurement and a coincidence.
    ///
    /// Counts live heap rather than RSS. RSS keeps counting pages the allocator
    /// freed but has not returned to the OS, so it is not reproducible across
    /// allocators or platforms; live bytes are.
    mod alloc_probe {
        use std::alloc::{GlobalAlloc, Layout, System};
        use std::cell::Cell;

        thread_local! {
            static ARMED: Cell<bool> = const { Cell::new(false) };
            static LIVE: Cell<isize> = const { Cell::new(0) };
            static PEAK: Cell<isize> = const { Cell::new(0) };
        }

        pub struct CountingAllocator;

        fn record(delta: isize) {
            // `try_with` because a thread tearing down has no thread-local
            // left to reach, and an allocator must not panic there.
            let _ = ARMED.try_with(|armed| {
                if !armed.get() {
                    return;
                }
                let _ = LIVE.try_with(|live| {
                    let now = live.get() + delta;
                    live.set(now);
                    let _ = PEAK.try_with(|peak| {
                        if now > peak.get() {
                            peak.set(now);
                        }
                    });
                });
            });
        }

        unsafe impl GlobalAlloc for CountingAllocator {
            unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
                let pointer = unsafe { System.alloc(layout) };
                if !pointer.is_null() {
                    record(layout.size() as isize);
                }
                pointer
            }

            unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
                record(-(layout.size() as isize));
                unsafe { System.dealloc(pointer, layout) }
            }

            unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
                let moved = unsafe { System.realloc(pointer, layout, new_size) };
                if !moved.is_null() {
                    record(new_size as isize - layout.size() as isize);
                }
                moved
            }
        }

        /// Peak live bytes allocated by `body` on this thread.
        pub fn peak_live_bytes(body: impl FnOnce()) -> usize {
            LIVE.with(|live| live.set(0));
            PEAK.with(|peak| peak.set(0));
            ARMED.with(|armed| armed.set(true));
            body();
            ARMED.with(|armed| armed.set(false));
            usize::try_from(PEAK.with(Cell::get)).unwrap_or(0)
        }
    }

    #[global_allocator]
    static COUNTING_ALLOCATOR: alloc_probe::CountingAllocator = alloc_probe::CountingAllocator;

    fn measure_peak_live_bytes(body: impl FnOnce()) -> usize {
        alloc_probe::peak_live_bytes(body)
    }

    fn sealed_observation() -> SealedObservationBinding {
        SealedObservationBinding::new(Hash256::from_bytes([0x73; 32]), 3, 21, 7, 98, 1, 1).unwrap()
    }

    fn messagepack_array_len(bytes: &[u8]) -> usize {
        match bytes {
            [tag @ 0x90..=0x9f, ..] => usize::from(*tag & 0x0f),
            [0xdc, high, low, ..] => usize::from(u16::from_be_bytes([*high, *low])),
            [0xdd, a, b, c, d, ..] => {
                usize::try_from(u32::from_be_bytes([*a, *b, *c, *d])).unwrap()
            }
            _ => panic!("expected a MessagePack array"),
        }
    }

    /// A transaction that touches no merge or seal must hash exactly as it did
    /// before either binding existed.
    ///
    /// The two pinned digests were measured on the commit that introduced this
    /// test, before `merge_transaction_delta` was added. They are what makes
    /// the field additive in fact rather than in intent: every repository
    /// already on disk keeps its operation identities and its authority roots,
    /// so no re-import is owed. A change that moves either digest has broken
    /// that promise and must carry a schema version instead.
    #[test]
    fn a_transaction_without_a_merge_keeps_its_pre_merge_identity() {
        let transaction = workspace_transaction();
        assert!(transaction.merge_transaction_delta.is_none());
        assert!(transaction.sealed_observation.is_none());
        assert_eq!(
            transaction.transaction_hash().unwrap().to_string(),
            "3d1a5564f1284d98aeacb1b2c6166bc2ae49586661897933dc0cb45bb7f583df",
            "adding an absent merge record must not move transaction identity"
        );
        assert!(
            !serde_json::to_string(&transaction)
                .unwrap()
                .contains("merge_transaction_delta"),
            "an absent merge record must not appear on the wire"
        );
        assert!(
            !serde_json::to_string(&transaction)
                .unwrap()
                .contains("sealed_observation"),
            "an absent sealed observation must not appear on the wire"
        );

        let mut roots_after = roots();
        roots_after.generation = roots().generation + 1;
        let operation = RepositoryOperationRecord {
            operation_id: transaction.operation_id,
            repository_id: transaction.repository_id.clone(),
            transaction_hash: transaction.transaction_hash().unwrap(),
            actor: transaction.actor.clone(),
            committed_at: crate::Timestamp::from(
                chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            ),
            git_authority_delta: None,
            ref_mutations: Vec::new(),
            default_ref_mutation: None,
            workspace_mutation: transaction.workspace_mutation.clone(),
            local_overlay_delta: transaction.local_overlay_delta.clone(),
            merge_transaction_delta: None,
            roots_before: roots(),
            roots_after,
        };
        assert_eq!(
            operation.identity_hash().unwrap().to_string(),
            "eae3a8c100dcc231fd552ce1d20c5e258e489e09139076cfa431ebaf6bfa916b",
            "adding an absent merge record must not move operation identity"
        );
    }

    /// Operation records live inside a MessagePack snapshot, where a struct is
    /// an array and position decides the mapping.
    ///
    /// An optional field is therefore additive only at the end: a record
    /// written before it existed runs out of elements and takes the default,
    /// and a record with nothing to say encodes to the same element count it
    /// always did. This proves both directions against the real encoder rather
    /// than trusting the JSON contract to describe the on-disk one, which it
    /// does not.
    #[test]
    fn an_operation_record_round_trips_through_positional_encoding() {
        let transaction = workspace_transaction();
        let mut roots_after = roots();
        roots_after.generation = roots().generation + 1;
        let operation = RepositoryOperationRecord {
            operation_id: transaction.operation_id,
            repository_id: transaction.repository_id.clone(),
            transaction_hash: transaction.transaction_hash().unwrap(),
            actor: transaction.actor.clone(),
            committed_at: crate::Timestamp::from(
                chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            ),
            git_authority_delta: None,
            ref_mutations: Vec::new(),
            default_ref_mutation: None,
            workspace_mutation: transaction.workspace_mutation.clone(),
            local_overlay_delta: transaction.local_overlay_delta.clone(),
            roots_before: roots(),
            roots_after,
            merge_transaction_delta: None,
        };

        // An absent merge record is not written at all, so the encoded array
        // has the arity a pre-merge binary produced, and decodes.
        let bytes = rmp_serde::to_vec(&operation).unwrap();
        let decoded: RepositoryOperationRecord = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(decoded, operation);
        assert!(decoded.merge_transaction_delta.is_none());

        let mut with_merge = operation.clone();
        with_merge.merge_transaction_delta = Some(MergeTransactionDelta::open(
            crate::merge::tests::sample_record(
                operation.repository_id.clone(),
                operation.workspace_mutation.as_ref().unwrap().workspace_id,
            ),
        ));
        let bytes_with_merge = rmp_serde::to_vec(&with_merge).unwrap();
        assert!(bytes_with_merge.len() > bytes.len());
        let decoded: RepositoryOperationRecord = rmp_serde::from_slice(&bytes_with_merge).unwrap();
        assert_eq!(decoded, with_merge);
    }

    /// The same, for the transaction that carries the delta over the wire.
    #[test]
    fn a_transaction_round_trips_through_positional_encoding() {
        let transaction = workspace_transaction();
        let bytes = rmp_serde::to_vec(&transaction).unwrap();
        assert_eq!(messagepack_array_len(&bytes), 15);
        let decoded: RepositoryTransaction = rmp_serde::from_slice(&bytes).unwrap();
        assert!(decoded.merge_transaction_delta.is_none());
        assert!(decoded.sealed_observation.is_none());
        assert_eq!(
            decoded.transaction_hash().unwrap(),
            transaction.transaction_hash().unwrap()
        );

        let mut with_merge = transaction.clone();
        with_merge.merge_transaction_delta = Some(MergeTransactionDelta::open(
            crate::merge::tests::sample_record(
                transaction.repository_id.clone(),
                transaction
                    .workspace_mutation
                    .as_ref()
                    .unwrap()
                    .workspace_id,
            ),
        ));
        let decoded: RepositoryTransaction =
            rmp_serde::from_slice(&rmp_serde::to_vec(&with_merge).unwrap()).unwrap();
        assert_eq!(
            messagepack_array_len(&rmp_serde::to_vec(&with_merge).unwrap()),
            16
        );
        assert_eq!(
            decoded.transaction_hash().unwrap(),
            with_merge.transaction_hash().unwrap()
        );
    }

    #[test]
    fn positional_transaction_tail_round_trips_all_merge_and_seal_combinations() {
        let transaction = workspace_transaction();
        let merge = MergeTransactionDelta::open(crate::merge::tests::sample_record(
            transaction.repository_id.clone(),
            transaction
                .workspace_mutation
                .as_ref()
                .unwrap()
                .workspace_id,
        ));
        let seal = sealed_observation();
        let combinations = [
            (None, None, 15),
            (Some(merge.clone()), None, 16),
            (None, Some(seal), 17),
            (Some(merge), Some(seal), 17),
        ];

        for (merge_transaction_delta, sealed_observation, expected_arity) in combinations {
            let mut candidate = transaction.clone();
            candidate.merge_transaction_delta = merge_transaction_delta;
            candidate.sealed_observation = sealed_observation;
            let encoded = rmp_serde::to_vec(&candidate).unwrap();
            assert_eq!(messagepack_array_len(&encoded), expected_arity);
            let decoded: RepositoryTransaction = rmp_serde::from_slice(&encoded).unwrap();
            assert_eq!(decoded, candidate);
        }

        let mut seal_only = transaction;
        seal_only.sealed_observation = Some(seal);
        let json = serde_json::to_value(&seal_only).unwrap();
        assert!(json.get("merge_transaction_delta").is_none());
        assert_eq!(
            json.get("sealed_observation")
                .and_then(|value| value.get("fingerprint")),
            Some(&serde_json::to_value(seal.fingerprint).unwrap())
        );
    }

    #[test]
    fn json_transaction_tail_round_trips_all_merge_and_seal_combinations() {
        let transaction = workspace_transaction();
        let merge = MergeTransactionDelta::open(crate::merge::tests::sample_record(
            transaction.repository_id.clone(),
            transaction
                .workspace_mutation
                .as_ref()
                .unwrap()
                .workspace_id,
        ));
        let seal = sealed_observation();
        let combinations = [
            (None, None),
            (Some(merge.clone()), None),
            (None, Some(seal)),
            (Some(merge), Some(seal)),
        ];

        for (merge_transaction_delta, sealed_observation) in combinations {
            let mut candidate = transaction.clone();
            candidate.merge_transaction_delta = merge_transaction_delta;
            candidate.sealed_observation = sealed_observation;
            let encoded = serde_json::to_vec(&candidate).unwrap();
            let decoded: RepositoryTransaction = serde_json::from_slice(&encoded).unwrap();
            assert_eq!(decoded, candidate);
        }
    }

    #[test]
    fn legacy_v064_transaction_messagepack_bytes_are_preserved_exactly() {
        #[derive(Serialize)]
        struct V064RepositoryTransaction<'a> {
            schema_version: u32,
            operation_id: OperationId,
            repository_id: &'a RepositoryId,
            expected_generation: u64,
            expected_roots: &'a RootBundle,
            actor: &'a AuthorId,
            reason: &'a str,
            external_objects: &'a [ExternalObjectRecord],
            git_authority_delta: &'a Option<GitExternalAuthorityDelta>,
            changes: &'a [SemanticChange],
            aliases: &'a [ExternalChangeAlias],
            ref_mutations: &'a [RefMutation],
            default_ref_mutation: &'a Option<DefaultRefMutation>,
            workspace_mutation: &'a Option<WorkspaceMutation>,
            local_overlay_delta: &'a Option<FrozenLocalOverlayDelta>,
            #[serde(skip_serializing_if = "Option::is_none")]
            merge_transaction_delta: &'a Option<MergeTransactionDelta>,
        }

        fn legacy_wire(transaction: &RepositoryTransaction) -> V064RepositoryTransaction<'_> {
            V064RepositoryTransaction {
                schema_version: transaction.schema_version,
                operation_id: transaction.operation_id,
                repository_id: &transaction.repository_id,
                expected_generation: transaction.expected_generation,
                expected_roots: &transaction.expected_roots,
                actor: &transaction.actor,
                reason: &transaction.reason,
                external_objects: &transaction.external_objects,
                git_authority_delta: &transaction.git_authority_delta,
                changes: &transaction.changes,
                aliases: &transaction.aliases,
                ref_mutations: &transaction.ref_mutations,
                default_ref_mutation: &transaction.default_ref_mutation,
                workspace_mutation: &transaction.workspace_mutation,
                local_overlay_delta: &transaction.local_overlay_delta,
                merge_transaction_delta: &transaction.merge_transaction_delta,
            }
        }

        fn legacy_bytes(transaction: &RepositoryTransaction) -> Vec<u8> {
            rmp_serde::to_vec(&legacy_wire(transaction)).unwrap()
        }

        let mut transaction = workspace_transaction();
        let legacy_json = serde_json::to_value(legacy_wire(&transaction)).unwrap();
        assert_eq!(serde_json::to_value(&transaction).unwrap(), legacy_json);
        let legacy = legacy_bytes(&transaction);
        assert_eq!(rmp_serde::to_vec(&transaction).unwrap(), legacy);
        assert_eq!(
            rmp_serde::from_slice::<RepositoryTransaction>(&legacy).unwrap(),
            transaction
        );

        transaction.merge_transaction_delta = Some(MergeTransactionDelta::open(
            crate::merge::tests::sample_record(
                transaction.repository_id.clone(),
                transaction
                    .workspace_mutation
                    .as_ref()
                    .unwrap()
                    .workspace_id,
            ),
        ));
        let legacy_json = serde_json::to_value(legacy_wire(&transaction)).unwrap();
        assert_eq!(serde_json::to_value(&transaction).unwrap(), legacy_json);
        let legacy = legacy_bytes(&transaction);
        assert_eq!(rmp_serde::to_vec(&transaction).unwrap(), legacy);
        assert_eq!(
            rmp_serde::from_slice::<RepositoryTransaction>(&legacy).unwrap(),
            transaction
        );
    }

    /// The same transaction carrying a merge record must not be mistakable for
    /// one that does not, at either identity.
    #[test]
    fn a_merge_record_participates_in_transaction_and_operation_identity() {
        let mut transaction = workspace_transaction();
        let baseline = transaction.transaction_hash().unwrap();
        let record = crate::merge::tests::sample_record(
            transaction.repository_id.clone(),
            transaction
                .workspace_mutation
                .as_ref()
                .unwrap()
                .workspace_id,
        );
        transaction.merge_transaction_delta = Some(MergeTransactionDelta::open(record.clone()));
        transaction.validate().unwrap();
        let with_merge = transaction.transaction_hash().unwrap();
        assert_ne!(with_merge, baseline);
        assert_eq!(
            with_merge.to_string(),
            "26fc5b4ecb312a18be0ff24cd07ce7c5b23ac7e040d897eaecfc02b60d098c57",
            "the v0.6.4 merge-only transaction identity must survive the seal field"
        );

        let mut roots_after = roots();
        roots_after.generation = roots().generation + 1;
        let mut operation = RepositoryOperationRecord {
            operation_id: transaction.operation_id,
            repository_id: transaction.repository_id.clone(),
            transaction_hash: with_merge,
            actor: transaction.actor.clone(),
            committed_at: crate::Timestamp::from(
                chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            ),
            git_authority_delta: None,
            ref_mutations: Vec::new(),
            default_ref_mutation: None,
            workspace_mutation: transaction.workspace_mutation.clone(),
            local_overlay_delta: transaction.local_overlay_delta.clone(),
            merge_transaction_delta: transaction.merge_transaction_delta.clone(),
            roots_before: roots(),
            roots_after,
        };
        let bound = operation.identity_hash().unwrap();
        operation.merge_transaction_delta = None;
        assert_ne!(operation.identity_hash().unwrap(), bound);
    }

    #[test]
    fn a_sealed_observation_is_shape_validated_and_participates_in_identity() {
        let mut transaction = workspace_transaction();
        let baseline = transaction.transaction_hash().unwrap();
        transaction.sealed_observation = Some(sealed_observation());
        transaction.validate().unwrap();
        let sealed = transaction.transaction_hash().unwrap();
        assert_ne!(sealed, baseline);

        let mut changed = transaction.clone();
        changed.sealed_observation.as_mut().unwrap().fingerprint = Hash256::from_bytes([0x74; 32]);
        assert_ne!(changed.transaction_hash().unwrap(), sealed);

        let mut malformed = transaction;
        malformed.sealed_observation.as_mut().unwrap().opaque_bodies = 8;
        assert!(malformed
            .validate()
            .unwrap_err()
            .to_string()
            .contains("more opaque bodies"));
    }

    #[test]
    fn a_sealed_observation_binds_a_real_mutation_but_is_not_one_by_itself() {
        let mut transaction = workspace_transaction();
        transaction.workspace_mutation = None;
        transaction.local_overlay_delta = None;
        transaction.sealed_observation = Some(sealed_observation());
        assert!(transaction
            .validate()
            .unwrap_err()
            .to_string()
            .contains("must contain at least one mutation"));
    }

    /// A merge record alone is a real mutation, and an invalid one is refused
    /// by the transaction that carries it rather than only by the store.
    #[test]
    fn a_transaction_carrying_only_a_merge_record_is_a_mutation_and_is_validated() {
        let mut transaction = workspace_transaction();
        let workspace_id = transaction
            .workspace_mutation
            .as_ref()
            .unwrap()
            .workspace_id;
        transaction.workspace_mutation = None;
        transaction.local_overlay_delta = None;
        transaction.merge_transaction_delta = None;
        assert!(transaction
            .validate()
            .unwrap_err()
            .to_string()
            .contains("must contain at least one mutation"));

        let record =
            crate::merge::tests::sample_record(transaction.repository_id.clone(), workspace_id);
        transaction.merge_transaction_delta = Some(MergeTransactionDelta::open(record.clone()));
        transaction.validate().unwrap();

        let mut forged = record;
        forged.hash = Hash256::from_bytes([0x99; 32]);
        transaction.merge_transaction_delta = Some(MergeTransactionDelta::open(forged));
        assert!(transaction
            .validate()
            .unwrap_err()
            .to_string()
            .contains("recomputes to"));
    }

    #[test]
    fn workspace_snapshot_keeps_dirty_tree_distinct_from_base_commit() {
        let binding = WorkspaceSnapshotBinding {
            repository_id: RepositoryId::new("repo").unwrap(),
            workspace_id: WorkspaceId::new(),
            workspace_head: WorkspaceHead::Symbolic {
                target: RefName::branch(b"main").unwrap(),
            },
            base_target: Some(RefTarget::change(SemanticChangeId::from_hash(
                Hash256::from_bytes([0x11; 32]),
            ))),
            base_tree_hash: Some(Hash256::from_bytes([0x22; 32])),
            workspace_tree_hash: Hash256::from_bytes([0x23; 32]),
            workspace_semantic_overlay_hash: WorkspaceSemanticOverlay::default()
                .identity_hash()
                .unwrap(),
            roots: roots(),
            workspace_generation: 9,
            admission_policy: EffectiveAdmissionPolicyStamp {
                shared: AdmissionPolicyStamp {
                    hash: crate::AdmissionPolicyHash(Hash256::from_bytes([0x24; 32])),
                    generation: 1,
                },
                local: LocalOverlayStamp {
                    hash: LocalOverlayHash(Hash256::from_bytes([0x25; 32])),
                    generation: 2,
                },
            },
        };
        binding.validate().unwrap();
        assert!(binding.is_dirty());
    }

    #[test]
    fn workspace_semantic_delta_is_canonical_and_rejects_duplicate_targets() {
        let first = semantic_entity(0x90, "first");
        let second = semantic_entity(0x91, "second");
        let forward = WorkspaceSemanticDelta::new(
            vec![
                EntityDelta::Added { new: first.clone() },
                EntityDelta::Added {
                    new: second.clone(),
                },
            ],
            Vec::new(),
        )
        .unwrap();
        let reversed = WorkspaceSemanticDelta::new(
            vec![
                EntityDelta::Added {
                    new: second.clone(),
                },
                EntityDelta::Added { new: first.clone() },
            ],
            Vec::new(),
        )
        .unwrap();
        assert_eq!(
            forward.identity_hash().unwrap(),
            reversed.identity_hash().unwrap()
        );
        let forward_overlay = WorkspaceSemanticOverlay::new(
            vec![
                EntityDelta::Added { new: first.clone() },
                EntityDelta::Added {
                    new: second.clone(),
                },
            ],
            Vec::new(),
        )
        .unwrap();
        let reversed_overlay = WorkspaceSemanticOverlay::new(
            vec![
                EntityDelta::Added {
                    new: second.clone(),
                },
                EntityDelta::Added { new: first.clone() },
            ],
            Vec::new(),
        )
        .unwrap();
        assert_eq!(
            forward_overlay.identity_hash().unwrap(),
            reversed_overlay.identity_hash().unwrap()
        );
        assert_ne!(
            forward.identity_hash().unwrap(),
            forward_overlay.identity_hash().unwrap(),
            "incremental and cumulative identities must use distinct domains"
        );

        let error = WorkspaceSemanticDelta::new(
            vec![
                EntityDelta::Added { new: first.clone() },
                EntityDelta::Removed { old: first },
            ],
            Vec::new(),
        )
        .unwrap_err();
        assert!(error.to_string().contains("canonical unique target order"));

        let mut encoded = serde_json::to_value(&forward).unwrap();
        encoded
            .get_mut("entity_deltas")
            .unwrap()
            .as_array_mut()
            .unwrap()
            .reverse();
        assert!(
            serde_json::from_value::<WorkspaceSemanticDelta>(encoded).is_err(),
            "noncanonical persisted semantic deltas must fail during decode"
        );
    }

    #[test]
    fn workspace_semantic_delta_persists_external_references_without_moving_legacy_wire() {
        #[derive(Serialize)]
        struct LegacyWorkspaceSemanticDelta<'a> {
            version: u32,
            entity_deltas: &'a [EntityDelta],
            relation_deltas: &'a [RelationDelta],
        }

        let first = ExternalReference::new_resolved("python-module-v1", "requests", "get").unwrap();
        let second =
            ExternalReference::new_resolved("npm-package-v1", "@mui/utils", "merge").unwrap();
        let forward = WorkspaceSemanticDelta::new_with_external_references(
            Vec::new(),
            Vec::new(),
            vec![
                ExternalReferenceDelta::Added { new: first.clone() },
                ExternalReferenceDelta::Added {
                    new: second.clone(),
                },
            ],
        )
        .unwrap();
        let reversed = WorkspaceSemanticDelta::new_with_external_references(
            Vec::new(),
            Vec::new(),
            vec![
                ExternalReferenceDelta::Added {
                    new: second.clone(),
                },
                ExternalReferenceDelta::Added { new: first.clone() },
            ],
        )
        .unwrap();
        assert_eq!(forward, reversed);
        assert_eq!(
            forward.identity_hash().unwrap(),
            reversed.identity_hash().unwrap()
        );
        assert_eq!(
            forward.transaction_delta().external_reference_deltas,
            forward.external_reference_deltas()
        );
        assert_eq!(
            WorkspaceSemanticOverlay::new_with_external_references(
                Vec::new(),
                Vec::new(),
                forward.external_reference_deltas().to_vec(),
            )
            .unwrap()
            .external_reference_deltas(),
            forward.external_reference_deltas()
        );

        let duplicate = WorkspaceSemanticDelta::new_with_external_references(
            Vec::new(),
            Vec::new(),
            vec![
                ExternalReferenceDelta::Added { new: first.clone() },
                ExternalReferenceDelta::Removed { old: first },
            ],
        )
        .unwrap_err();
        assert!(duplicate
            .to_string()
            .contains("canonical unique target order"));

        let legacy = WorkspaceSemanticDelta::default();
        let legacy_wire = LegacyWorkspaceSemanticDelta {
            version: legacy.version,
            entity_deltas: legacy.entity_deltas(),
            relation_deltas: legacy.relation_deltas(),
        };
        assert_eq!(
            serde_json::to_value(&legacy).unwrap(),
            serde_json::to_value(&legacy_wire).unwrap()
        );
        let legacy_bytes = rmp_serde::to_vec(&legacy_wire).unwrap();
        assert_eq!(rmp_serde::to_vec(&legacy).unwrap(), legacy_bytes);
        assert_eq!(
            rmp_serde::from_slice::<WorkspaceSemanticDelta>(&legacy_bytes).unwrap(),
            legacy
        );
    }

    #[test]
    fn semantic_only_workspace_transition_is_durable_dirty_authority() {
        let repository_id = RepositoryId::new("repo").unwrap();
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(0x92));
        let (shared_policy, policy, _) = admission_policy(workspace_id);
        let clean =
            create_workspace_mutation(workspace_id, shared_policy.clone(), policy, Vec::new())
                .validate_against(&repository_id, None, WorkspaceSemanticOverlay::default())
                .unwrap();
        assert!(!clean.is_dirty());

        let entity_delta = EntityDelta::Added {
            new: semantic_entity(0x93, "uncommitted"),
        };
        let delta = WorkspaceSemanticDelta::new(vec![entity_delta.clone()], Vec::new()).unwrap();
        let overlay = WorkspaceSemanticOverlay::new(vec![entity_delta], Vec::new()).unwrap();
        let overlay_hash = overlay.identity_hash().unwrap();
        let mutation = WorkspaceMutation {
            workspace_id,
            expected: WorkspaceExpectation::MustEqual {
                generation: clean.generation,
                head: clean.head.clone(),
                base_target: clean.base_target.clone(),
                base_tree_hash: clean.base_tree_hash,
                tree_hash: clean.tree_hash,
                semantic_overlay_hash: clean.semantic_overlay_hash,
                admission_policy: clean.admission_policy,
            },
            new_generation: clean.generation + 1,
            new_head: clean.head.clone(),
            new_base_target: clean.base_target.clone(),
            new_base_tree_hash: clean.base_tree_hash,
            tree_deltas: Vec::new(),
            new_tree_hash: clean.tree_hash,
            semantic_delta: delta,
            new_shared_admission_policy: shared_policy,
            new_admission_policy: clean.admission_policy,
        };
        let dirty = mutation
            .validate_against(&repository_id, Some(&clean), overlay)
            .unwrap();
        assert!(dirty.is_dirty());
        assert_eq!(dirty.tree, clean.tree);
        assert_eq!(dirty.semantic_overlay_hash, overlay_hash);

        let encoded = serde_json::to_value(&dirty).unwrap();
        let mut legacy = encoded.clone();
        legacy.as_object_mut().unwrap().remove("semantic_overlay");
        assert!(serde_json::from_value::<WorkspaceState>(legacy).is_err());
        assert_eq!(
            serde_json::from_value::<WorkspaceState>(encoded).unwrap(),
            dirty
        );
    }

    #[test]
    fn workspace_snapshot_binding_requires_complete_base_authority() {
        let mut binding = WorkspaceSnapshotBinding {
            repository_id: RepositoryId::new("repo").unwrap(),
            workspace_id: WorkspaceId::new(),
            workspace_head: WorkspaceHead::Symbolic {
                target: RefName::branch(b"main").unwrap(),
            },
            base_target: Some(RefTarget::change(SemanticChangeId::from_hash(
                Hash256::from_bytes([0x31; 32]),
            ))),
            base_tree_hash: Some(Hash256::from_bytes([0x32; 32])),
            workspace_tree_hash: Hash256::from_bytes([0x32; 32]),
            workspace_semantic_overlay_hash: WorkspaceSemanticOverlay::default()
                .identity_hash()
                .unwrap(),
            roots: roots(),
            workspace_generation: 3,
            admission_policy: EffectiveAdmissionPolicyStamp {
                shared: AdmissionPolicyStamp {
                    hash: crate::AdmissionPolicyHash(Hash256::from_bytes([0x33; 32])),
                    generation: 1,
                },
                local: LocalOverlayStamp {
                    hash: LocalOverlayHash(Hash256::from_bytes([0x34; 32])),
                    generation: 2,
                },
            },
        };
        binding.validate().unwrap();

        binding.base_tree_hash = None;
        let error = binding.validate().unwrap_err();
        assert!(error
            .to_string()
            .contains("base target and tree must both be present or absent"));
    }

    #[test]
    fn workspace_snapshot_binding_rejects_detached_target_mismatch() {
        let head_target =
            RefTarget::change(SemanticChangeId::from_hash(Hash256::from_bytes([0x41; 32])));
        let mut binding = WorkspaceSnapshotBinding {
            repository_id: RepositoryId::new("repo").unwrap(),
            workspace_id: WorkspaceId::new(),
            workspace_head: WorkspaceHead::Detached {
                target: head_target.clone(),
            },
            base_target: Some(head_target),
            base_tree_hash: Some(Hash256::from_bytes([0x42; 32])),
            workspace_tree_hash: Hash256::from_bytes([0x42; 32]),
            workspace_semantic_overlay_hash: WorkspaceSemanticOverlay::default()
                .identity_hash()
                .unwrap(),
            roots: roots(),
            workspace_generation: 4,
            admission_policy: EffectiveAdmissionPolicyStamp {
                shared: AdmissionPolicyStamp {
                    hash: crate::AdmissionPolicyHash(Hash256::from_bytes([0x43; 32])),
                    generation: 1,
                },
                local: LocalOverlayStamp {
                    hash: LocalOverlayHash(Hash256::from_bytes([0x44; 32])),
                    generation: 2,
                },
            },
        };
        binding.validate().unwrap();

        binding.base_target = Some(RefTarget::change(SemanticChangeId::from_hash(
            Hash256::from_bytes([0x45; 32]),
        )));
        let error = binding.validate().unwrap_err();
        assert!(error
            .to_string()
            .contains("detached HEAD must bind its exact target and tree"));
    }

    #[test]
    fn unborn_dirty_ignore_policy_is_authoritative_without_fake_history() {
        let mut transaction = workspace_transaction();
        let ignore_hash = Hash256::from_bytes([0x66; 32]);
        let shared_policy = SharedAdmissionPolicy::new(
            0,
            vec![AdmissionRuleSource {
                kind: AdmissionRuleSourceKind::GitIgnore,
                path: RepoPath::from_utf8(".gitignore").unwrap(),
                base_directory: None,
                body_hash: ignore_hash,
                body_len: 8,
                precedence: 0,
            }],
            Vec::new(),
        )
        .unwrap();
        let workspace = transaction.workspace_mutation.as_mut().unwrap();
        workspace.tree_deltas.push(add_artifact(
            ArtifactId(Uuid::from_u128(13)),
            b".gitignore".to_vec(),
            0x66,
            false,
        ));
        let candidate = ResolvedTree::default()
            .apply(&workspace.tree_deltas)
            .unwrap();
        workspace.new_tree_hash = compute_resolved_tree_hash(&candidate).unwrap();
        workspace.new_shared_admission_policy = shared_policy.clone();
        workspace.new_admission_policy.shared = shared_policy.stamp();

        assert!(transaction.changes.is_empty());
        assert!(workspace.new_base_target.is_none());
        assert_ne!(
            shared_policy.stamp(),
            SharedAdmissionPolicy::empty(0).stamp()
        );
        transaction.validate().unwrap();

        let mut mismatched = transaction;
        mismatched
            .workspace_mutation
            .as_mut()
            .unwrap()
            .new_shared_admission_policy = SharedAdmissionPolicy::empty(0);
        let error = mismatched.validate().unwrap_err();
        assert!(error
            .to_string()
            .contains("shared admission policy does not match its effective policy stamp"));
    }

    #[test]
    fn workspace_shared_policy_is_bound_by_transaction_and_operation_identities() {
        let original = workspace_transaction();
        original.validate().unwrap();
        let original_hash = original.transaction_hash().unwrap();

        let mut updated = original.clone();
        let shared_policy = SharedAdmissionPolicy::empty(1);
        let workspace = updated.workspace_mutation.as_mut().unwrap();
        workspace.new_shared_admission_policy = shared_policy.clone();
        workspace.new_admission_policy.shared = shared_policy.stamp();
        updated.validate().unwrap();
        assert_ne!(updated.transaction_hash().unwrap(), original_hash);

        let mut roots_after = roots();
        roots_after.generation = 8;
        let operation = RepositoryOperationRecord {
            operation_id: original.operation_id,
            repository_id: original.repository_id.clone(),
            transaction_hash: original_hash,
            actor: original.actor.clone(),
            committed_at: crate::Timestamp::from(
                chrono::DateTime::parse_from_rfc3339("2026-01-02T03:04:05Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            ),
            git_authority_delta: None,
            ref_mutations: Vec::new(),
            default_ref_mutation: None,
            workspace_mutation: original.workspace_mutation,
            local_overlay_delta: None,
            merge_transaction_delta: None,
            roots_before: roots(),
            roots_after,
        };
        let operation_identity = operation.identity_hash().unwrap();
        let mut updated_operation = operation;
        updated_operation.workspace_mutation = updated.workspace_mutation;
        assert_ne!(
            updated_operation.identity_hash().unwrap(),
            operation_identity
        );
    }

    #[test]
    fn unborn_workspace_persists_arbitrary_files_then_commits_without_losing_tree() {
        let repository_id = RepositoryId::new("repo").unwrap();
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(21));
        let (shared_policy, policy, _) = admission_policy(workspace_id);
        let create = create_workspace_mutation(
            workspace_id,
            shared_policy.clone(),
            policy,
            vec![
                add_artifact(
                    ArtifactId(Uuid::from_u128(22)),
                    b"Dockerfile".to_vec(),
                    0x51,
                    true,
                ),
                add_artifact(
                    ArtifactId(Uuid::from_u128(23)),
                    b"infra/compose-\xfe.yaml".to_vec(),
                    0x52,
                    false,
                ),
            ],
        );
        let dirty = create
            .validate_against(&repository_id, None, WorkspaceSemanticOverlay::default())
            .unwrap();
        assert!(dirty.is_dirty());
        assert_eq!(dirty.shared_admission_policy, shared_policy);
        assert!(dirty
            .tree
            .artifact_at_path(&RepoPath::from_bytes(b"infra/compose-\xfe.yaml".to_vec()).unwrap())
            .is_some());

        let committed_change = SemanticChangeId::from_hash(Hash256::from_bytes([0x53; 32]));
        let commit = WorkspaceMutation {
            workspace_id,
            expected: WorkspaceExpectation::MustEqual {
                generation: dirty.generation,
                head: dirty.head.clone(),
                base_target: dirty.base_target.clone(),
                base_tree_hash: dirty.base_tree_hash,
                tree_hash: dirty.tree_hash,
                semantic_overlay_hash: dirty.semantic_overlay_hash,
                admission_policy: dirty.admission_policy,
            },
            new_generation: 1,
            new_head: dirty.head.clone(),
            new_base_target: Some(RefTarget::change(committed_change)),
            new_base_tree_hash: Some(dirty.tree_hash),
            tree_deltas: Vec::new(),
            new_tree_hash: dirty.tree_hash,
            semantic_delta: WorkspaceSemanticDelta::default(),
            new_shared_admission_policy: shared_policy,
            new_admission_policy: dirty.admission_policy,
        };
        let clean = commit
            .validate_against(
                &repository_id,
                Some(&dirty),
                WorkspaceSemanticOverlay::default(),
            )
            .unwrap();
        assert!(!clean.is_dirty());
        assert_eq!(clean.tree, dirty.tree);
        assert_eq!(clean.base_target, Some(RefTarget::change(committed_change)));
    }

    #[test]
    fn workspace_mutation_rejects_stale_head_tree_or_generation() {
        let repository_id = RepositoryId::new("repo").unwrap();
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(31));
        let (shared_policy, policy, _) = admission_policy(workspace_id);
        let current =
            create_workspace_mutation(workspace_id, shared_policy.clone(), policy, Vec::new())
                .validate_against(&repository_id, None, WorkspaceSemanticOverlay::default())
                .unwrap();
        let stale = WorkspaceMutation {
            workspace_id,
            expected: WorkspaceExpectation::MustEqual {
                generation: current.generation + 1,
                head: current.head.clone(),
                base_target: None,
                base_tree_hash: None,
                tree_hash: Hash256::from_bytes([0x99; 32]),
                semantic_overlay_hash: current.semantic_overlay_hash,
                admission_policy: current.admission_policy,
            },
            new_generation: current.generation + 2,
            new_head: WorkspaceHead::Detached {
                target: RefTarget::change(SemanticChangeId::from_hash(Hash256::from_bytes(
                    [0x61; 32],
                ))),
            },
            new_base_target: Some(RefTarget::change(SemanticChangeId::from_hash(
                Hash256::from_bytes([0x61; 32]),
            ))),
            new_base_tree_hash: Some(current.tree_hash),
            tree_deltas: Vec::new(),
            new_tree_hash: current.tree_hash,
            semantic_delta: WorkspaceSemanticDelta::default(),
            new_shared_admission_policy: shared_policy,
            new_admission_policy: current.admission_policy,
        };
        assert!(matches!(
            stale.validate_against(
                &repository_id,
                Some(&current),
                current.semantic_overlay.clone()
            ),
            Err(ModelError::Conflict(_))
        ));
    }

    #[test]
    fn detached_workspace_preserves_exact_external_tag_target() {
        let repository_id = RepositoryId::new("repo").unwrap();
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(35));
        let (shared_policy, policy, _) = admission_policy(workspace_id);
        let tree = ResolvedTree::default();
        let tree_hash = compute_resolved_tree_hash(&tree).unwrap();
        let target = RefTarget::external_object(crate::ExternalObjectId::new(
            ExternalObjectKind::Tag,
            GitObjectId::sha1([0x71; 20]),
        ));
        let state = WorkspaceState::new(
            repository_id,
            workspace_id,
            3,
            WorkspaceHead::Detached {
                target: target.clone(),
            },
            Some(target.clone()),
            Some(tree_hash),
            tree,
            WorkspaceSemanticOverlay::default(),
            shared_policy,
            policy,
        )
        .unwrap();

        assert_eq!(state.base_target, Some(target));
        assert!(!state.is_dirty());
        let encoded = serde_json::to_vec(&state).unwrap();
        assert_eq!(
            serde_json::from_slice::<WorkspaceState>(&encoded).unwrap(),
            state
        );
        let mut mismatched = state;
        mismatched.shared_admission_policy = SharedAdmissionPolicy::empty(1);
        assert!(mismatched.validate().is_err());
    }

    /// A transaction carrying every collection `transaction_hash` canonicalizes.
    ///
    /// Deliberately built with each collection OUT of its canonical order, so a
    /// test that reorders one of them is comparing two genuinely different
    /// literals rather than two copies of the same sorted vector.
    fn canonicalizable_transaction() -> RepositoryTransaction {
        let repository_id = RepositoryId::new("repo").unwrap();
        let workspace_id = WorkspaceId::from_uuid(Uuid::from_u128(9));
        let (shared_policy, policy, local_overlay_delta) = admission_policy(workspace_id);
        let mutation = create_workspace_mutation(
            workspace_id,
            shared_policy,
            policy,
            vec![
                add_artifact(
                    ArtifactId(Uuid::from_u128(11)),
                    b"assets/data-\xff.bin".to_vec(),
                    0x42,
                    false,
                ),
                add_artifact(
                    ArtifactId(Uuid::from_u128(10)),
                    b"compose.yaml".to_vec(),
                    0x41,
                    false,
                ),
            ],
        );

        let first = native_change(0xa0, 220, 210, 120, 110);
        let second = native_change(0xb0, 240, 230, 140, 130);
        let (low, high) = if first.id <= second.id {
            (first, second)
        } else {
            (second, first)
        };
        let low_oid = match low.origin {
            crate::ChangeOrigin::GitCommit { oid } => oid,
            crate::ChangeOrigin::Native => unreachable!("fixture changes are Git-origin"),
        };
        let high_oid = match high.origin {
            crate::ChangeOrigin::GitCommit { oid } => oid,
            crate::ChangeOrigin::Native => unreachable!("fixture changes are Git-origin"),
        };

        let commit_object = |oid: GitObjectId| ExternalObjectRecord {
            object: ExternalObjectId::new(ExternalObjectKind::Commit, oid),
            body_hash: Hash256::from_bytes([0x5a; 32]),
            body_len: 42,
        };
        let alias = |oid: GitObjectId, change_id: SemanticChangeId| {
            ExternalChangeAlias::new(repository_id.clone(), oid, change_id)
        };
        let ref_mutation = |name: &[u8], byte: u8| RefMutation {
            name: RefName::branch(name).unwrap(),
            expected: RefExpectation::MustNotExist,
            new_target: Some(RefTarget::change(SemanticChangeId::from_hash(
                Hash256::from_bytes([byte; 32]),
            ))),
            policy: RefUpdatePolicy::FastForwardOnly,
        };

        RepositoryTransaction {
            schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
            operation_id: OperationId::from_uuid(Uuid::from_u128(12)),
            repository_id: repository_id.clone(),
            expected_generation: 7,
            expected_roots: roots(),
            actor: AuthorId::new("actor"),
            reason: "canonicalization fixture".to_string(),
            // every vector below is out of canonical order on purpose
            external_objects: vec![commit_object(high_oid), commit_object(low_oid)],
            git_authority_delta: None,
            changes: vec![high.clone(), low.clone()],
            aliases: vec![alias(high_oid, high.id), alias(low_oid, low.id)],
            ref_mutations: vec![ref_mutation(b"zeta", 0x71), ref_mutation(b"alpha", 0x70)],
            default_ref_mutation: None,
            workspace_mutation: Some(mutation),
            local_overlay_delta: Some(local_overlay_delta),
            merge_transaction_delta: None,
            sealed_observation: None,
        }
    }

    /// A native change whose own delta vectors are out of canonical order.
    ///
    /// Valid despite that, because `compute_semantic_change_id` canonicalizes
    /// before hashing, which is the property that makes reordering a change's
    /// deltas testable at all.
    fn native_change(
        seed: u8,
        entity_high: u128,
        entity_low: u128,
        artifact_high: u128,
        artifact_low: u128,
    ) -> SemanticChange {
        let mut change = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
            origin: crate::ChangeOrigin::GitCommit {
                oid: GitObjectId::sha1([seed; 20]),
            },
            parents: Vec::new(),
            timestamp: crate::Timestamp::from(
                chrono::DateTime::parse_from_rfc3339("2026-01-02T03:04:05Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            ),
            author: AuthorId::new("actor"),
            message: format!("native change {seed}"),
            entity_deltas: vec![
                crate::EntityDelta::Added {
                    new: semantic_entity(entity_high, "later"),
                },
                crate::EntityDelta::Added {
                    new: semantic_entity(entity_low, "earlier"),
                },
            ],
            relation_deltas: Vec::new(),
            tree_deltas: vec![
                add_artifact(
                    ArtifactId(Uuid::from_u128(artifact_high)),
                    format!("z-{seed}.rs").into_bytes(),
                    seed,
                    false,
                ),
                add_artifact(
                    ArtifactId(Uuid::from_u128(artifact_low)),
                    format!("a-{seed}.rs").into_bytes(),
                    seed,
                    false,
                ),
            ],
            admission_policy_delta: None,
            projected_files: Vec::new(),
            spec_link: None,
            evidence: Vec::new(),
            risk_summary: None,
            // Out of canonical order like every other vector here, so the sort
            // that orders them has something to do.
            external_reference_deltas: vec![
                ExternalReferenceDelta::Added {
                    new: ExternalReference::new_resolved("python-module-v1", "zzz-later", "sym")
                        .unwrap(),
                },
                ExternalReferenceDelta::Added {
                    new: ExternalReference::new_resolved("python-module-v1", "aaa-early", "sym")
                        .unwrap(),
                },
            ],
        };
        change.id = crate::compute_semantic_change_id(&change).unwrap();
        change
    }

    /// The canonicalization as it stood before it was optimized, kept verbatim
    /// as the reference the production implementation is diffed against.
    ///
    /// Clones the whole transaction and sorts the copy. That is precisely the
    /// cost the production version exists to avoid, which is why this stays: an
    /// optimization of a durable identity is only safe if it can be shown to
    /// produce the same bytes as the implementation it replaces, on inputs
    /// chosen to vary exactly what it changed.
    fn reference_canonical_hash(transaction: &RepositoryTransaction) -> Result<Hash256> {
        hash_serialized(
            b"kin-repository-transaction-v4\0",
            &reference_canonical_transaction(transaction),
        )
    }

    /// The owned, sorted transaction the reference implementation built.
    ///
    /// Split out of [`reference_canonical_hash`] so the same reference can be
    /// serialized directly, which is what
    /// `the_canonical_view_serializes_positionally_identical_bytes` needs: the
    /// hash encodes through `canonical_json_bytes`, whose object encoder sorts
    /// keys, so comparing hashes alone cannot see a field order difference.
    fn reference_canonical_transaction(
        transaction: &RepositoryTransaction,
    ) -> RepositoryTransaction {
        let mut canonical = transaction.clone();
        canonical.changes.sort_by_key(|change| change.id);
        for change in &mut canonical.changes {
            change
                .entity_deltas
                .sort_by_key(crate::EntityDelta::target_id);
            change
                .relation_deltas
                .sort_by_key(crate::RelationDelta::target_id);
            change.tree_deltas.sort_by_key(TreeDelta::artifact_id);
            change
                .external_reference_deltas
                .sort_by_key(ExternalReferenceDelta::target_id);
        }
        canonical
            .external_objects
            .sort_by_key(|record| record.object);
        canonical.aliases.sort_by_key(|alias| alias.oid);
        canonical
            .ref_mutations
            .sort_by(|left, right| left.name.cmp(&right.name));
        if let Some(workspace) = &mut canonical.workspace_mutation {
            workspace.tree_deltas.sort_by_key(TreeDelta::artifact_id);
            workspace.semantic_delta.sort_canonical();
        }
        canonical
    }

    /// Deterministic permutation, so a failure is reproducible from its seed.
    fn permute<T>(items: &mut [T], seed: u64) {
        if items.len() < 2 {
            return;
        }
        let mut state = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
        for index in (1..items.len()).rev() {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            let pick = usize::try_from(state >> 33).unwrap_or(0) % (index + 1);
            items.swap(index, pick);
        }
    }

    /// Permute every collection the canonicalization sorts, including the ones
    /// `validate` would refuse out of order.
    ///
    /// Reachable only because `canonical_hash` does not validate: the workspace
    /// semantic delta's vectors are rejected by `WorkspaceSemanticDelta::validate`
    /// when non-canonical, so no valid transaction can carry them shuffled, and
    /// no fixture-based test can reach that sort at all.
    fn permute_every_canonicalized_collection(transaction: &mut RepositoryTransaction, seed: u64) {
        permute(&mut transaction.changes, seed);
        for (index, change) in transaction.changes.iter_mut().enumerate() {
            let seed = seed.wrapping_add(index as u64).wrapping_mul(31);
            permute(&mut change.entity_deltas, seed);
            permute(&mut change.relation_deltas, seed ^ 0x11);
            permute(&mut change.tree_deltas, seed ^ 0x22);
            permute(&mut change.external_reference_deltas, seed ^ 0x33);
        }
        permute(&mut transaction.external_objects, seed ^ 0x44);
        permute(&mut transaction.aliases, seed ^ 0x55);
        permute(&mut transaction.ref_mutations, seed ^ 0x66);
        if let Some(workspace) = &mut transaction.workspace_mutation {
            permute(&mut workspace.tree_deltas, seed ^ 0x77);
            permute(&mut workspace.semantic_delta.entity_deltas, seed ^ 0x88);
            permute(&mut workspace.semantic_delta.relation_deltas, seed ^ 0x99);
            permute(
                &mut workspace.semantic_delta.external_reference_deltas,
                seed ^ 0xaa,
            );
        }
    }

    /// [`canonicalizable_transaction`] plus a workspace semantic delta held out
    /// of canonical order.
    ///
    /// Deliberately NOT a valid transaction. `WorkspaceSemanticDelta::validate`
    /// refuses non-canonical order, so this shape can never reach
    /// `transaction_hash`, and the `sort_canonical()` call inside the
    /// canonicalization is unreachable from any valid fixture. Driving
    /// `canonical_hash` directly is the only way to exercise it.
    fn differential_fixture() -> RepositoryTransaction {
        let mut transaction = canonicalizable_transaction();
        let workspace = transaction.workspace_mutation.as_mut().unwrap();
        workspace.semantic_delta.external_reference_deltas = vec![
            ExternalReferenceDelta::Added {
                new: ExternalReference::new_resolved("npm-package-v1", "zzz-pkg", "merge").unwrap(),
            },
            ExternalReferenceDelta::Added {
                new: ExternalReference::new_resolved("npm-package-v1", "aaa-pkg", "merge").unwrap(),
            },
        ];
        assert!(
            transaction.validate().is_err(),
            "this fixture is meant to be unvalidatable; if it validates, the \
             sort_canonical path it exists to reach is reachable another way"
        );
        transaction
    }

    /// The optimized canonicalization must produce the same bytes as the one it
    /// replaced, on inputs that vary exactly what it changed.
    ///
    /// This is the bar for touching `transaction_hash` at all. The identity is
    /// durable: it is stored in every `RepositoryCommitReceipt` and compared on
    /// idempotent replay, so an implementation that hashes differently by one
    /// byte invalidates receipts already on disk. A pinned digest cannot carry
    /// that load alone, because it fixes one value for one fixture; this fixes
    /// equality against the previous implementation across many orderings.
    ///
    /// It drives `canonical_hash` rather than `transaction_hash` on purpose, so
    /// the inputs need not satisfy `validate` and can therefore include
    /// orderings no valid transaction may carry. That is what reaches the
    /// workspace semantic delta's `sort_canonical()`, which no fixture-based
    /// test can exercise, because `WorkspaceSemanticDelta::validate` refuses
    /// non-canonical order outright.
    ///
    /// Coverage was measured, not assumed. Each of the ten sorts was removed in
    /// turn and this test was required to fail: nine did. The exception is the
    /// per-change `relation_deltas` sort, which this fixture cannot reach
    /// because it carries no relations, and an empty collection makes its sort
    /// unobservable. Populating it needs a `Relation` fixture this module does
    /// not have. That gap is named here rather than left for a reader to
    /// discover, because a test that appears to cover ten sorts and covers nine
    /// is worse than one that says which nine.
    #[test]
    fn the_canonicalization_matches_the_implementation_it_replaced() {
        let base = differential_fixture();
        for seed in 0..64_u64 {
            let mut permuted = base.clone();
            permute_every_canonicalized_collection(&mut permuted, seed);
            assert_eq!(
                permuted.canonical_hash().unwrap(),
                reference_canonical_hash(&permuted).unwrap(),
                "optimized canonicalization disagrees with the implementation it \
                 replaced, at permutation seed {seed}"
            );
            assert_eq!(
                permuted.canonical_hash().unwrap(),
                base.canonical_hash().unwrap(),
                "canonicalization is order-dependent at permutation seed {seed}"
            );
        }
    }

    /// The canonical view must produce the same bytes POSITIONALLY, not merely
    /// the same hash.
    ///
    /// This is not a duplicate of
    /// [`the_canonicalization_matches_the_implementation_it_replaced`]. That
    /// test compares hashes, and the hash is built by `canonical_json_bytes`,
    /// which routes through `serde_json::to_value` and then an encoder that
    /// SORTS object keys (`identity.rs`, the `Value::Object` arm). Field order
    /// is therefore invisible to it: swapping two fields in a mirror view type
    /// keeps every one of those 64 permutations green.
    ///
    /// A field order the mirror got wrong is exactly the failure mode these
    /// view types can have, so the guard against it has to be a serializer that
    /// can see order. MessagePack is not human-readable, so it drives the
    /// positional branch of the transaction's own `Serialize` impl, where the
    /// element count varies with the optional tail fields, and it encodes each
    /// struct as an ordered array. Order, element count and skip rules are all
    /// load-bearing here.
    #[test]
    fn the_canonical_view_serializes_positionally_identical_bytes() {
        let base = differential_fixture();
        for seed in 0..64_u64 {
            let mut permuted = base.clone();
            permute_every_canonicalized_collection(&mut permuted, seed);
            let view = rmp_serde::to_vec(&CanonicalTransaction::new(&permuted)).unwrap();
            let reference = rmp_serde::to_vec(&reference_canonical_transaction(&permuted)).unwrap();
            assert_eq!(
                view, reference,
                "canonical view bytes differ from the cloning implementation at \
                 permutation seed {seed}"
            );
        }
    }

    /// Both optional tail combinations, because the element count depends on
    /// them and the two branches compute it by different rules.
    ///
    /// The positional branch emits an explicit absent merge slot when a sealed
    /// observation is present without a merge delta; the human-readable branch
    /// skips each independently. A mirror that copied one rule onto both would
    /// pass every permutation above, since the differential fixture carries
    /// neither field.
    #[test]
    fn the_canonical_view_matches_across_every_optional_tail_combination() {
        let base = canonicalizable_transaction();
        for (label, merge, sealed) in [
            ("neither", false, false),
            ("merge only", true, false),
            ("sealed only", false, true),
            ("both", true, true),
        ] {
            let mut transaction = base.clone();
            if merge {
                let workspace_id = transaction
                    .workspace_mutation
                    .as_ref()
                    .unwrap()
                    .workspace_id;
                transaction.merge_transaction_delta = Some(MergeTransactionDelta::open(
                    crate::merge::tests::sample_record(
                        transaction.repository_id.clone(),
                        workspace_id,
                    ),
                ));
            }
            if sealed {
                transaction.sealed_observation = Some(sealed_observation());
            }
            assert_eq!(
                rmp_serde::to_vec(&CanonicalTransaction::new(&transaction)).unwrap(),
                rmp_serde::to_vec(&reference_canonical_transaction(&transaction)).unwrap(),
                "positional bytes differ with {label}"
            );
            assert_eq!(
                serde_json::to_value(CanonicalTransaction::new(&transaction)).unwrap(),
                serde_json::to_value(reference_canonical_transaction(&transaction)).unwrap(),
                "human-readable form differs with {label}"
            );
            assert_eq!(
                transaction.canonical_hash().unwrap(),
                reference_canonical_hash(&transaction).unwrap(),
                "hash differs with {label}"
            );
        }
    }

    /// The view must BORROW the transaction, which is the whole point of it.
    ///
    /// Hash equality cannot show this: a version that cloned the transaction
    /// and sorted the copy would satisfy every differential above while costing
    /// exactly what this change exists to remove. Pointer identity can show it,
    /// and it is exact rather than statistical, so it neither flakes nor needs
    /// a threshold.
    ///
    /// Each element the view claims to reference is required to be the very
    /// element inside the caller's transaction, not an equal copy of it.
    #[test]
    fn the_canonical_view_borrows_the_transaction_rather_than_cloning_it() {
        let transaction = canonicalizable_transaction();
        let view = CanonicalTransaction::new(&transaction);

        assert!(
            std::ptr::eq(view.source, &transaction),
            "canonical view does not point at the transaction it was built from"
        );

        let borrows_one_of = |target: *const SemanticChange| {
            transaction
                .changes
                .iter()
                .any(|change| std::ptr::eq(change, target))
        };
        assert_eq!(view.changes.len(), transaction.changes.len());
        for change in &view.changes {
            assert!(
                borrows_one_of(change.source),
                "canonical change is a copy rather than a reference into the transaction"
            );
        }

        assert!(
            view.external_objects.iter().all(|record| transaction
                .external_objects
                .iter()
                .any(|source| std::ptr::eq(*record, source))),
            "external object records were copied rather than referenced"
        );
        assert!(
            view.aliases.iter().all(|alias| transaction
                .aliases
                .iter()
                .any(|source| std::ptr::eq(*alias, source))),
            "aliases were copied rather than referenced"
        );
        assert!(
            view.ref_mutations.iter().all(|mutation| transaction
                .ref_mutations
                .iter()
                .any(|source| std::ptr::eq(*mutation, source))),
            "ref mutations were copied rather than referenced"
        );

        let workspace = view
            .workspace_mutation
            .as_ref()
            .expect("fixture carries a workspace mutation");
        assert!(
            std::ptr::eq(
                workspace.source,
                transaction.workspace_mutation.as_ref().unwrap()
            ),
            "workspace mutation view is a copy rather than a reference"
        );
        assert!(
            std::ptr::eq(
                workspace.semantic_delta.source,
                &transaction
                    .workspace_mutation
                    .as_ref()
                    .unwrap()
                    .semantic_delta
            ),
            "workspace semantic delta view is a copy rather than a reference"
        );

        // The sort still has to have happened; a view that borrowed and did
        // nothing else would pass everything above.
        assert!(
            view.changes
                .windows(2)
                .all(|pair| pair[0].source.id <= pair[1].source.id),
            "canonical view did not sort the changes it borrowed"
        );
    }

    /// A transaction large enough that a whole-transaction clone is visible in
    /// the heap, which the 32-commit fixtures above are not.
    fn large_transaction(change_count: usize) -> RepositoryTransaction {
        let mut transaction = canonicalizable_transaction();
        transaction.changes = (0..change_count)
            .map(|index| {
                let seed = u8::try_from(index % 251).unwrap_or(0);
                let base = u128::try_from(index).unwrap_or(0) * 16 + 1_000;
                native_change(seed, base + 3, base + 2, base + 1, base)
            })
            .collect();
        transaction
    }

    /// The canonicalization must not allocate a copy of the transaction, and
    /// the saving must be the clone rather than noise.
    ///
    /// This is the quantitative half of
    /// [`the_canonical_view_borrows_the_transaction_rather_than_cloning_it`].
    /// That test proves the view holds references; this one prices what the
    /// references save, and calibrates the threshold against the clone's own
    /// measured cost so there is no magic constant to drift.
    ///
    /// # What this measured, which is not what removing the clone was expected
    /// to buy
    ///
    /// On a 200-change transaction, debug profile, macOS, live heap:
    ///
    /// | quantity | bytes |
    /// |---|---|
    /// | cloning the transaction, alone | 603_850 |
    /// | building the borrowing view, alone | 51_200 |
    /// | the `serde_json::Value` tree the encoder builds | 6_667_601 |
    /// | whole hash, cloning implementation | 9_339_027 |
    /// | whole hash, borrowing implementation | 8_765_641 |
    ///
    /// The clone is gone: the saving of 573_386 bytes is 94.9 percent of what
    /// the clone cost. But it is 6.1 percent of the call's peak, because
    /// `canonical_json_bytes` materializes a whole `serde_json::Value` tree,
    /// and that tree is eleven times the size of the transaction it encodes.
    /// The clone was never the dominant term inside this call.
    ///
    /// So the assertion is deliberately NOT a peak ceiling. A ceiling here
    /// would be pinning the encoder, would drift with any serde change, and
    /// would say nothing about whether a clone came back. The invariants that
    /// matter are that the view costs a small fraction of a clone, and that
    /// removing the clone removed approximately the clone.
    ///
    /// The counter is thread-local, so tests running in parallel in this same
    /// binary cannot contaminate it.
    #[test]
    fn the_canonicalization_does_not_allocate_a_copy_of_the_transaction() {
        let transaction = large_transaction(200);

        // Warm any lazily-initialized state so it is not charged to one arm.
        transaction.canonical_hash().unwrap();
        reference_canonical_hash(&transaction).unwrap();

        let clone_cost = measure_peak_live_bytes(|| {
            let copy = transaction.clone();
            std::hint::black_box(&copy);
        });
        let view_cost = measure_peak_live_bytes(|| {
            let view = CanonicalTransaction::new(&transaction);
            std::hint::black_box(&view);
        });
        let cloning = measure_peak_live_bytes(|| {
            reference_canonical_hash(&transaction).unwrap();
        });
        let borrowing = measure_peak_live_bytes(|| {
            transaction.canonical_hash().unwrap();
        });
        println!("clone {clone_cost} view {view_cost} cloning {cloning} borrowing {borrowing}");

        assert!(
            clone_cost > 0 && view_cost > 0 && cloning > 0 && borrowing > 0,
            "the allocation probe measured nothing, so it cannot fail: clone \
             {clone_cost}, view {view_cost}, cloning {cloning}, borrowing {borrowing}"
        );
        assert!(
            view_cost * 4 < clone_cost,
            "building the canonical view cost {view_cost} bytes against a clone's \
             {clone_cost}, which is not the shape of a view over references"
        );
        let saved = cloning.saturating_sub(borrowing);
        assert!(
            saved * 4 >= clone_cost * 3,
            "removing the clone saved {saved} bytes of a clone that costs \
             {clone_cost}; the canonicalization is allocating a copy again \
             ({cloning} cloning against {borrowing} borrowing)"
        );
    }

    /// Transaction identity must not depend on the order a caller built its
    /// collections in.
    ///
    /// `transaction_hash` canonicalizes by sorting before it serializes, and
    /// until this test nothing asserted that any of those sorts work. The pinned
    /// digest in `a_transaction_without_a_merge_keeps_its_pre_merge_identity` is
    /// built from `workspace_transaction()`, whose `changes`, `aliases`,
    /// `external_objects` and `ref_mutations` are all empty, so it pins a value
    /// for a transaction that has nothing to canonicalize. A sort that was
    /// dropped or keyed wrong keeps that digest green while changing the
    /// identity of every repository that actually carries history, and identity
    /// here is durable: it is stored in every `RepositoryCommitReceipt` and
    /// compared on idempotent replay.
    ///
    /// Each collection is reordered on its own so a removed sort fails by name
    /// rather than as one undifferentiated mismatch.
    ///
    /// Not covered, and stated rather than implied: the per-change
    /// `relation_deltas` and `external_reference_deltas` orderings, which this
    /// fixture leaves empty, and the workspace semantic delta's own three
    /// vectors, whose order cannot be varied here because
    /// `WorkspaceSemanticDelta::validate` REJECTS non-canonical order outright
    /// rather than canonicalizing it. That last one is guarded by rejection, not
    /// by invariance, which is a different contract and a different test.

    #[test]
    fn transaction_identity_ignores_the_order_of_every_collection_it_canonicalizes() {
        let base = canonicalizable_transaction();
        base.validate().unwrap();
        let expected = base.transaction_hash().unwrap();

        let check = |reordered: RepositoryTransaction, collection: &str| {
            reordered.validate().unwrap_or_else(|error| {
                panic!("reordering {collection} produced an invalid transaction: {error}")
            });
            assert_eq!(
                reordered.transaction_hash().unwrap(),
                expected,
                "transaction identity moved when only the order of {collection} changed, so \
                 transaction_hash does not canonicalize {collection}"
            );
        };

        let mut changes = base.clone();
        changes.changes.reverse();
        assert_ne!(
            changes.changes, base.changes,
            "the fixture must have >1 change"
        );
        check(changes, "changes");

        let mut entity_deltas = base.clone();
        for change in &mut entity_deltas.changes {
            assert!(
                change.entity_deltas.len() > 1,
                "each fixture change must carry more than one entity delta"
            );
            change.entity_deltas.reverse();
        }
        check(entity_deltas, "per-change entity deltas");

        let mut change_trees = base.clone();
        for change in &mut change_trees.changes {
            assert!(
                change.tree_deltas.len() > 1,
                "each fixture change must carry more than one tree delta"
            );
            change.tree_deltas.reverse();
        }
        check(change_trees, "per-change tree deltas");

        let mut objects = base.clone();
        objects.external_objects.reverse();
        assert_ne!(
            objects.external_objects, base.external_objects,
            "the fixture must have >1 external object"
        );
        check(objects, "external objects");

        let mut aliases = base.clone();
        aliases.aliases.reverse();
        assert_ne!(
            aliases.aliases, base.aliases,
            "the fixture must have >1 alias"
        );
        check(aliases, "aliases");

        let mut refs = base.clone();
        refs.ref_mutations.reverse();
        assert_ne!(
            refs.ref_mutations, base.ref_mutations,
            "the fixture must have >1 ref mutation"
        );
        check(refs, "ref mutations");

        let mut workspace_trees = base.clone();
        let workspace = workspace_trees.workspace_mutation.as_mut().unwrap();
        assert!(
            workspace.tree_deltas.len() > 1,
            "the fixture workspace must carry more than one tree delta"
        );
        workspace.tree_deltas.reverse();
        check(workspace_trees, "workspace tree deltas");
    }

    #[test]
    fn transaction_hash_binds_the_exact_workspace_candidate_tree() {
        let transaction = workspace_transaction();
        transaction.validate().unwrap();
        let original_hash = transaction.transaction_hash().unwrap();

        let mut changed = transaction;
        let workspace = changed.workspace_mutation.as_mut().unwrap();
        workspace.tree_deltas[0] = add_artifact(
            workspace.tree_deltas[0].artifact_id(),
            b"compose.yaml".to_vec(),
            0x77,
            false,
        );
        let candidate = ResolvedTree::default()
            .apply(&workspace.tree_deltas)
            .unwrap();
        workspace.new_tree_hash = compute_resolved_tree_hash(&candidate).unwrap();

        changed.validate().unwrap();
        assert_ne!(changed.transaction_hash().unwrap(), original_hash);
    }

    #[test]
    fn git_authority_delta_is_an_atomic_transaction_mutation_without_readding_cas_records() {
        assert_eq!(REPOSITORY_TRANSACTION_SCHEMA_VERSION, 4);
        let repository_id = RepositoryId::new("repo").unwrap();
        let old = blob_git_authority(repository_id.clone(), b"services:\n  old: {}\n");
        let new = blob_git_authority(repository_id, b"services:\n  new: {}\n");

        let initial =
            authority_only_transaction(GitExternalAuthorityDelta::initialize(old.clone()));
        assert!(initial.external_objects.is_empty());
        assert!(!old.closure.objects.is_empty());
        initial.validate().unwrap();

        let update =
            authority_only_transaction(GitExternalAuthorityDelta::update(old.clone(), new.clone()));
        update.validate().unwrap();
        let update_hash = update.transaction_hash().unwrap();
        assert_eq!(
            update_hash.to_string(),
            "ad3ef05a2450e78e1ed19de548e309408ea840ce8916385f382c89a5aeac33b5",
            "repository transaction v4 identity is schema-pinned"
        );
        assert_ne!(initial.transaction_hash().unwrap(), update_hash);

        let removal = authority_only_transaction(GitExternalAuthorityDelta::remove(new.clone()));
        removal.validate().unwrap();
        assert_ne!(
            update.transaction_hash().unwrap(),
            removal.transaction_hash().unwrap()
        );

        let inverse = authority_only_transaction(GitExternalAuthorityDelta::remove(old).inverse());
        inverse.validate().unwrap();
        assert_ne!(
            removal.transaction_hash().unwrap(),
            inverse.transaction_hash().unwrap()
        );
    }

    #[test]
    fn transaction_schema_and_repository_identity_fail_closed_for_git_authority() {
        let authority = blob_git_authority(RepositoryId::new("repo").unwrap(), b"authority body");
        let transaction =
            authority_only_transaction(GitExternalAuthorityDelta::initialize(authority.clone()));
        transaction.validate().unwrap();

        let mut wrong_repository = transaction.clone();
        wrong_repository.repository_id = RepositoryId::new("other").unwrap();
        let error = wrong_repository.validate().unwrap_err();
        assert!(error
            .to_string()
            .contains("does not match enclosing repository"));

        let mut no_op = transaction.clone();
        no_op.git_authority_delta = Some(GitExternalAuthorityDelta::update(
            authority.clone(),
            authority,
        ));
        assert!(no_op.validate().unwrap_err().to_string().contains("no-op"));

        let mut legacy = transaction.clone();
        legacy.schema_version = 3;
        assert!(legacy
            .validate()
            .unwrap_err()
            .to_string()
            .contains("unsupported repository transaction version 3"));

        let value = serde_json::to_value(&transaction).unwrap();
        assert!(value.get("git_authority_delta").is_some());
        let schema = serde_json::to_value(schemars::schema_for!(RepositoryTransaction)).unwrap();
        assert!(schema.pointer("/properties/git_authority_delta").is_some());
    }

    #[test]
    fn operation_record_validates_and_binds_the_exact_git_authority_delta() {
        let repository_id = RepositoryId::new("repo").unwrap();
        let old = blob_git_authority(repository_id.clone(), b"old");
        let new = blob_git_authority(repository_id.clone(), b"new");
        let delta = GitExternalAuthorityDelta::update(old.clone(), new.clone());
        let transaction = authority_only_transaction(delta.clone());
        let transaction_hash = transaction.transaction_hash().unwrap();
        let mut roots_after = roots();
        roots_after.generation = 8;
        let operation = RepositoryOperationRecord {
            operation_id: transaction.operation_id,
            repository_id,
            transaction_hash,
            actor: transaction.actor,
            committed_at: crate::Timestamp::from(
                chrono::DateTime::parse_from_rfc3339("2026-01-02T03:04:05Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            ),
            git_authority_delta: Some(delta),
            ref_mutations: Vec::new(),
            default_ref_mutation: None,
            workspace_mutation: None,
            local_overlay_delta: None,
            merge_transaction_delta: None,
            roots_before: roots(),
            roots_after,
        };
        operation.validate().unwrap();
        let identity = operation.identity_hash().unwrap();
        assert_eq!(
            identity.to_string(),
            "88697dcc0db93d8577850c9500a84f80345185b11782d48ca93cd822966ef8e7",
            "repository operation v4 identity is schema-pinned"
        );

        let mut changed = operation.clone();
        changed.git_authority_delta = Some(GitExternalAuthorityDelta::remove(new.clone()));
        assert_ne!(changed.identity_hash().unwrap(), identity);

        let mut wrong_repository = operation.clone();
        wrong_repository.repository_id = RepositoryId::new("other").unwrap();
        assert!(wrong_repository
            .validate()
            .unwrap_err()
            .to_string()
            .contains("does not match enclosing repository"));

        let mut malformed = operation;
        malformed.git_authority_delta = Some(GitExternalAuthorityDelta::update(old.clone(), old));
        assert!(malformed
            .identity_hash()
            .unwrap_err()
            .to_string()
            .contains("no-op"));
    }

    #[test]
    fn operation_identity_excludes_circular_roots_and_canonicalizes_ref_order() {
        let target =
            RefTarget::change(SemanticChangeId::from_hash(Hash256::from_bytes([0x81; 32])));
        let first = RefMutation {
            name: RefName::branch(b"a").unwrap(),
            expected: RefExpectation::MustNotExist,
            new_target: Some(target.clone()),
            policy: RefUpdatePolicy::FastForwardOnly,
        };
        let second = RefMutation {
            name: RefName::branch(b"b").unwrap(),
            expected: RefExpectation::MustNotExist,
            new_target: Some(target),
            policy: RefUpdatePolicy::FastForwardOnly,
        };
        let mut roots_after = roots();
        roots_after.generation = 8;
        let record = RepositoryOperationRecord {
            operation_id: OperationId::from_uuid(Uuid::from_u128(41)),
            repository_id: RepositoryId::new("repo").unwrap(),
            transaction_hash: Hash256::from_bytes([0x82; 32]),
            actor: AuthorId::new("actor"),
            committed_at: crate::Timestamp::from(
                chrono::DateTime::parse_from_rfc3339("2026-01-02T03:04:05Z")
                    .unwrap()
                    .with_timezone(&chrono::Utc),
            ),
            git_authority_delta: None,
            ref_mutations: vec![second, first],
            default_ref_mutation: None,
            workspace_mutation: None,
            local_overlay_delta: None,
            merge_transaction_delta: None,
            roots_before: roots(),
            roots_after,
        };
        let expected = record.identity_hash().unwrap();

        let mut equivalent = record.clone();
        equivalent.ref_mutations.reverse();
        equivalent.roots_before.history = root(0xa1);
        equivalent.roots_after.ref_log = root(0xa2);
        assert_eq!(equivalent.identity_hash().unwrap(), expected);
    }

    #[test]
    fn transaction_rejects_duplicate_ref_targets() {
        let name = RefName::branch(b"main").unwrap();
        let target =
            RefTarget::change(SemanticChangeId::from_hash(Hash256::from_bytes([0x31; 32])));
        let transaction = RepositoryTransaction {
            schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
            operation_id: OperationId::from_uuid(Uuid::from_bytes([1; 16])),
            repository_id: RepositoryId::new("repo").unwrap(),
            expected_generation: 7,
            expected_roots: roots(),
            actor: AuthorId::new("actor"),
            reason: "test".to_string(),
            external_objects: Vec::new(),
            git_authority_delta: None,
            changes: Vec::new(),
            aliases: Vec::new(),
            ref_mutations: vec![
                RefMutation {
                    name: name.clone(),
                    expected: RefExpectation::MustNotExist,
                    new_target: Some(target.clone()),
                    policy: RefUpdatePolicy::FastForwardOnly,
                },
                RefMutation {
                    name,
                    expected: RefExpectation::MustNotExist,
                    new_target: Some(target),
                    policy: RefUpdatePolicy::FastForwardOnly,
                },
            ],
            default_ref_mutation: None,
            workspace_mutation: None,
            local_overlay_delta: None,
            merge_transaction_delta: None,
            sealed_observation: None,
        };
        assert!(transaction.validate().is_err());
    }
}
