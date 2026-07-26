// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Repository-authority transaction contracts shared by storage and transport.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

use crate::{
    identity::canonical_json_bytes, validate_semantic_change_id, AdmissionScanToken, AuthorId,
    DefaultRefMutation, EffectiveAdmissionPolicyStamp, ExternalChangeAlias, ExternalObjectKind,
    ExternalObjectRecord, FrozenLocalOverlayDelta, GitObjectId, Hash256, ModelError, OperationId,
    RefMutation, RefName, RefTarget, RepositoryId, RepositoryRef, ResolvedTree, Result,
    SemanticChange, SemanticChangeId, SharedAdmissionPolicy, TreeDelta, WorkspaceHead, WorkspaceId,
};

pub const REPOSITORY_TRANSACTION_SCHEMA_VERSION: u32 = 1;
pub const REPOSITORY_ROOT_SCHEMA_VERSION: u32 = 1;

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
    pub roots: RootBundle,
    pub workspace_generation: u64,
    pub admission_policy: EffectiveAdmissionPolicyStamp,
}

impl WorkspaceSnapshotBinding {
    pub fn is_dirty(&self) -> bool {
        self.base_tree_hash.map_or_else(
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
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
    /// Complete shared matcher policy active for this exact workspace tree.
    ///
    /// This may be newer than committed history when a dirty workspace edits
    /// `.gitignore` or `.kinignore`.
    pub shared_admission_policy: SharedAdmissionPolicy,
    pub admission_policy: EffectiveAdmissionPolicyStamp,
}

impl WorkspaceState {
    /// Build and validate the complete state in one call. The explicit
    /// arguments make every authority-bearing field visible at call sites.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        repository_id: RepositoryId,
        workspace_id: WorkspaceId,
        generation: u64,
        head: WorkspaceHead,
        base_target: Option<RefTarget>,
        base_tree_hash: Option<Hash256>,
        tree: ResolvedTree,
        shared_admission_policy: SharedAdmissionPolicy,
        admission_policy: EffectiveAdmissionPolicyStamp,
    ) -> Result<Self> {
        let tree_hash = compute_resolved_tree_hash(&tree)?;
        let state = Self {
            repository_id,
            workspace_id,
            generation,
            head,
            base_target,
            base_tree_hash,
            tree,
            tree_hash,
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
        Ok(())
    }

    pub fn snapshot_binding(&self, roots: RootBundle) -> Result<WorkspaceSnapshotBinding> {
        self.validate()?;
        roots.validate()?;
        Ok(WorkspaceSnapshotBinding {
            repository_id: self.repository_id.clone(),
            workspace_id: self.workspace_id,
            workspace_head: self.head.clone(),
            base_target: self.base_target.clone(),
            base_tree_hash: self.base_tree_hash,
            workspace_tree_hash: self.tree_hash,
            roots,
            workspace_generation: self.generation,
            admission_policy: self.admission_policy,
        })
    }

    pub fn is_dirty(&self) -> bool {
        self.base_tree_hash
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
        admission_policy: EffectiveAdmissionPolicyStamp,
    },
}

/// One exact graph-owned workspace transition.
///
/// The authority implementation applies `tree_deltas` to the tree identified
/// by `expected`, verifies `new_tree_hash`, and commits the resulting state in
/// the same repository transaction as history and ref updates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
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
                    || current.admission_policy != *admission_policy
                {
                    return Err(ModelError::Conflict(format!(
                        "workspace {} no longer matches its expected generation, head, base, tree, and policy",
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
            self.new_shared_admission_policy.clone(),
            self.new_admission_policy,
        )
    }

    fn validate_shape(&self) -> Result<()> {
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

    fn expected_scan_baseline(&self) -> Hash256 {
        match &self.expected {
            WorkspaceExpectation::MustNotExist => {
                compute_resolved_tree_hash(&ResolvedTree::default())
                    .expect("empty tree has a canonical identity")
            }
            WorkspaceExpectation::MustEqual { tree_hash, .. } => *tree_hash,
        }
    }

    fn expected_scan_generation_and_head(&self) -> (u64, &WorkspaceHead) {
        match &self.expected {
            WorkspaceExpectation::MustNotExist => (0, &self.new_head),
            WorkspaceExpectation::MustEqual {
                generation, head, ..
            } => (*generation, head),
        }
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RepositoryOperationRecord {
    pub operation_id: OperationId,
    pub repository_id: RepositoryId,
    /// Canonical identity of the complete committed transaction, including
    /// history, raw-object descriptors, aliases, refs, workspace, and policy.
    pub transaction_hash: Hash256,
    pub actor: AuthorId,
    pub committed_at: crate::Timestamp,
    pub ref_mutations: Vec<RefMutation>,
    pub default_ref_mutation: Option<DefaultRefMutation>,
    pub workspace_mutation: Option<WorkspaceMutation>,
    pub local_overlay_delta: Option<FrozenLocalOverlayDelta>,
    pub roots_before: RootBundle,
    pub roots_after: RootBundle,
}

#[derive(Serialize)]
struct RepositoryOperationIdentity<'a> {
    operation_id: OperationId,
    repository_id: &'a RepositoryId,
    transaction_hash: Hash256,
    actor: &'a AuthorId,
    committed_at: &'a crate::Timestamp,
    ref_mutations: &'a [RefMutation],
    default_ref_mutation: &'a Option<DefaultRefMutation>,
    workspace_mutation: &'a Option<WorkspaceMutation>,
    local_overlay_delta: &'a Option<FrozenLocalOverlayDelta>,
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
        }
        hash_serialized(
            b"kin-repository-operation-v1\0",
            &RepositoryOperationIdentity {
                operation_id: canonical.operation_id,
                repository_id: &canonical.repository_id,
                transaction_hash: canonical.transaction_hash,
                actor: &canonical.actor,
                committed_at: &canonical.committed_at,
                ref_mutations: &canonical.ref_mutations,
                default_ref_mutation: &canonical.default_ref_mutation,
                workspace_mutation: &canonical.workspace_mutation,
                local_overlay_delta: &canonical.local_overlay_delta,
            },
        )
    }
}

/// One atomic repository-authority transition.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
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
    pub changes: Vec<SemanticChange>,
    pub aliases: Vec<ExternalChangeAlias>,
    pub ref_mutations: Vec<RefMutation>,
    pub default_ref_mutation: Option<DefaultRefMutation>,
    pub workspace_mutation: Option<WorkspaceMutation>,
    pub local_overlay_delta: Option<FrozenLocalOverlayDelta>,
    /// Required proof binding for every workspace mutation. This proves only
    /// the observed candidate workspace tree; history-only import and
    /// replication require their own object/history admission proof.
    pub admission_scan_token: Option<AdmissionScanToken>,
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
            && self.changes.is_empty()
            && self.aliases.is_empty()
            && self.ref_mutations.is_empty()
            && self.default_ref_mutation.is_none()
            && self.workspace_mutation.is_none()
            && self.local_overlay_delta.is_none()
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
            if self.admission_scan_token.is_none() {
                return Err(ModelError::InvalidOperation(format!(
                    "workspace {} mutation requires an admission scan token",
                    workspace.workspace_id
                )));
            }
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

        if let Some(token) = &self.admission_scan_token {
            token.validate()?;
            if token.repository_id != self.repository_id {
                return Err(ModelError::InvalidOperation(format!(
                    "admission scan repository {} does not match transaction repository {}",
                    token.repository_id, self.repository_id
                )));
            }
            let workspace = self.workspace_mutation.as_ref().ok_or_else(|| {
                ModelError::InvalidOperation(
                    "admission scan token is not bound to a workspace mutation".to_string(),
                )
            })?;
            if workspace.workspace_id != token.workspace_id {
                return Err(ModelError::InvalidOperation(
                    "workspace mutation and admission scan name different workspaces".to_string(),
                ));
            }
            let (generation, head) = workspace.expected_scan_generation_and_head();
            if token.workspace_generation != generation
                || &token.workspace_head != head
                || token.baseline_tree_hash != workspace.expected_scan_baseline()
                || token.observed_tree_hash != workspace.new_tree_hash
                || token.shared_policy != workspace.new_admission_policy.shared
                || token.local_overlay != workspace.new_admission_policy.local
            {
                return Err(ModelError::Conflict(format!(
                    "admission scan token does not bind workspace {} generation, head, baseline, candidate tree, and policy exactly",
                    workspace.workspace_id
                )));
            }
        }
        Ok(())
    }

    pub fn transaction_hash(&self) -> Result<Hash256> {
        self.validate()?;
        let mut canonical = self.clone();
        canonical.changes.sort_by_key(|change| change.id);
        for change in &mut canonical.changes {
            change
                .entity_deltas
                .sort_by_key(crate::EntityDelta::target_id);
            change
                .relation_deltas
                .sort_by_key(crate::RelationDelta::target_id);
            change.tree_deltas.sort_by_key(TreeDelta::artifact_id);
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
        }
        hash_serialized(b"kin-repository-transaction-v1\0", &canonical)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RepositoryCommitOutcome {
    Committed,
    IdempotentReplay,
}

/// Durable result returned for a committed or idempotently replayed operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
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
    use super::*;
    use crate::{
        AdmissionPolicyStamp, AdmissionRuleSource, AdmissionRuleSourceKind, ArtifactId,
        FrozenLocalOverlay, LocalOverlayHash, LocalOverlayStamp, LocatedEntry, RefExpectation,
        RefUpdatePolicy, RepoPath, SharedAdmissionPolicy, TreeEntry,
        ADMISSION_POLICY_SEMANTICS_VERSION,
    };
    use uuid::Uuid;

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
        let local = FrozenLocalOverlay::new(workspace_id, 0, Vec::new()).unwrap();
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
            changes: Vec::new(),
            aliases: Vec::new(),
            ref_mutations: Vec::new(),
            default_ref_mutation: None,
            admission_scan_token: Some(AdmissionScanToken {
                repository_id,
                workspace_id,
                workspace_generation: 0,
                workspace_head: mutation.new_head.clone(),
                baseline_tree_hash: compute_resolved_tree_hash(&ResolvedTree::default()).unwrap(),
                observed_tree_hash: mutation.new_tree_hash,
                matcher_semantics_version: ADMISSION_POLICY_SEMANTICS_VERSION,
                shared_policy: policy.shared,
                local_overlay: policy.local,
            }),
            workspace_mutation: Some(mutation),
            local_overlay_delta: Some(local_overlay_delta),
        }
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
        assert!(binding.is_dirty());
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

        let token = transaction.admission_scan_token.as_mut().unwrap();
        token.observed_tree_hash = workspace.new_tree_hash;
        token.shared_policy = shared_policy.stamp();

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
        updated.admission_scan_token.as_mut().unwrap().shared_policy = shared_policy.stamp();
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
            ref_mutations: Vec::new(),
            default_ref_mutation: None,
            workspace_mutation: original.workspace_mutation,
            local_overlay_delta: None,
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
        let dirty = create.validate_against(&repository_id, None).unwrap();
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
                admission_policy: dirty.admission_policy,
            },
            new_generation: 1,
            new_head: dirty.head.clone(),
            new_base_target: Some(RefTarget::change(committed_change)),
            new_base_tree_hash: Some(dirty.tree_hash),
            tree_deltas: Vec::new(),
            new_tree_hash: dirty.tree_hash,
            new_shared_admission_policy: shared_policy,
            new_admission_policy: dirty.admission_policy,
        };
        let clean = commit
            .validate_against(&repository_id, Some(&dirty))
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
                .validate_against(&repository_id, None)
                .unwrap();
        let stale = WorkspaceMutation {
            workspace_id,
            expected: WorkspaceExpectation::MustEqual {
                generation: current.generation + 1,
                head: current.head.clone(),
                base_target: None,
                base_tree_hash: None,
                tree_hash: Hash256::from_bytes([0x99; 32]),
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
            new_shared_admission_policy: shared_policy,
            new_admission_policy: current.admission_policy,
        };
        assert!(matches!(
            stale.validate_against(&repository_id, Some(&current)),
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

    #[test]
    fn scan_token_cannot_be_replayed_over_different_candidate_tree() {
        let transaction = workspace_transaction();
        transaction.validate().unwrap();

        let mut replay = transaction.clone();
        let workspace = replay.workspace_mutation.as_mut().unwrap();
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

        let error = replay.validate().unwrap_err();
        assert!(error
            .to_string()
            .contains("baseline, candidate tree, and policy exactly"));
    }

    #[test]
    fn workspace_mutation_cannot_omit_admission_scan() {
        let mut transaction = workspace_transaction();
        transaction.admission_scan_token = None;
        let error = transaction.validate().unwrap_err();
        assert!(error
            .to_string()
            .contains("mutation requires an admission scan token"));
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
            ref_mutations: vec![second, first],
            default_ref_mutation: None,
            workspace_mutation: None,
            local_overlay_delta: None,
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
            admission_scan_token: None,
        };
        assert!(transaction.validate().is_err());
    }
}
