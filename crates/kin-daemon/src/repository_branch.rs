// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Daemon-owned repository-v6 branch authority.

use anyhow::{bail, Context, Result};
use axum::http::StatusCode;
use kin_cli::commands::branch::{
    BranchListEntry, BranchListReport, BranchRequest, BranchResponse, BRANCH_LIST_SCHEMA,
};
use kin_cli::commands::transfer::WorkspaceFollow;
use kin_db::{LocalFileBackend, LocalRepositoryAuthorityFreeze, RepositoryAuthorityManager};
use kin_model::{
    compute_resolved_tree_hash, AuthorId, ChangeStore, EffectiveAdmissionPolicyStamp, EntityStore,
    OperationId, RefExpectation, RefMutation, RefName, RefTarget, RefUpdatePolicy,
    RepositoryCommitOutcome, RepositoryCommitReceipt, RepositoryTransaction, ResolvedTree,
    RootBundle, TransactionDelta, WorkspaceExpectation, WorkspaceHead, WorkspaceMutation,
    REPOSITORY_TRANSACTION_SCHEMA_VERSION,
};

use crate::local_repository_authority::{
    require_fresh_daemon_workspace, ActiveLocalRepositoryAuthority, RepositoryAuthorityBindRefusal,
};
use crate::state::{DaemonEvent, DaemonState};

const CREATE_REASON: &str = "create exact repository branch";
const DELETE_REASON: &str = "delete exact repository branch";
const SWITCH_REASON: &str = "switch exact repository workspace branch";
const FOLLOW_REASON: &str = "follow exact repository ref admitted by transfer";

/// Why a workspace is being transitioned onto a ref's current target.
///
/// Both transitions publish the same workspace mutation against the same
/// compare-and-swap; they differ in what a caller asked for, and therefore in
/// which refusal is the honest one.
///
/// A switch is a gesture someone typed, with a caller standing by to resolve
/// whatever it reports, so it carries uncommitted graph-owned state onto the
/// branch being entered and refuses only where the carry would lose work. A
/// follow is the second half of a transfer whose history is already durable and
/// which nobody is watching, so it keeps the stricter rule and refuses over any
/// uncommitted state rather than replaying it unattended. The follow reports
/// that once the transition is known to be needed, which is why the
/// already-at-target case is settled first here and last there.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum TransitionPolicy {
    /// A caller named the ref to stand on.
    Switch,
    /// A transfer moved the ref this workspace already tracks.
    FollowMovedRef,
}

struct BranchExecution {
    response: BranchResponse,
    receipt: RepositoryCommitReceipt,
    authority_freeze: LocalRepositoryAuthorityFreeze,
    daemon_delta: TransactionDelta,
    previous_tree: ResolvedTree,
    desired_tree: ResolvedTree,
    projection_changed: bool,
}

enum BranchCommandOutcome {
    Commit(BranchExecution),
    ReadOnly(BranchResponse),
}

#[derive(Debug)]
struct BranchConflict(String);

impl std::fmt::Display for BranchConflict {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for BranchConflict {}

/// The workspace stands on a different ref than the one a transfer moved.
///
/// Distinct from a conflict on purpose: nothing is wrong and nothing needs
/// resolving, so a follow reports it as inapplicable rather than as a working
/// tree that fell behind.
#[derive(Debug)]
struct WorkspaceTracksAnotherRef(String);

impl std::fmt::Display for WorkspaceTracksAnotherRef {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for WorkspaceTracksAnotherRef {}

/// How a planned workspace mutation refused.
///
/// The tracks-another-ref case is deliberately not carried as an HTTP status.
/// It is not an answer any client can be given: it means a transfer moved a ref
/// this workspace does not stand on, which only `follow_moved_ref` asks about
/// and only it reads back. Giving it a status would let a branch route answer
/// with it and still compile, and the status it needed to be distinguishable by
/// was one that may not carry a body. Keeping it a variant instead of a code is
/// what makes the illegal response unrepresentable rather than merely
/// documented.
enum WorkspaceMutationRefusal {
    /// A refusal a client is told, as the status and message it is told with.
    Client(StatusCode, String),
    /// The same, for the one refusal an admission pass clears: a TRACKED path
    /// whose working copy moved away from the projection the graph holds.
    ClientClearsWithAdmission(StatusCode, String),
    /// This workspace stands on a different ref than the one a transfer moved.
    TracksAnotherRef(String),
}

impl From<(StatusCode, String)> for WorkspaceMutationRefusal {
    fn from((status, message): (StatusCode, String)) -> Self {
        Self::Client(status, message)
    }
}

/// A refusal a branch command answers with, and whether one admission clears it.
///
/// The flag is read from the projection conflict's own kind rather than from
/// its wording. A predicate on the sentence is a check a copy edit breaks in
/// silence, and these two refusals differ by exactly one word in a paragraph.
pub(crate) struct BranchRefusal {
    pub(crate) status: StatusCode,
    pub(crate) message: String,
    /// True only for a TRACKED path whose content moved away from the
    /// projection: the graph has not been told, and one admission pass tells
    /// it. An untracked path standing where a member must go is never this, and
    /// no admission makes it carry.
    pub(crate) clears_with_admission: bool,
}

impl From<(StatusCode, String)> for BranchRefusal {
    fn from((status, message): (StatusCode, String)) -> Self {
        Self {
            status,
            message,
            clears_with_admission: false,
        }
    }
}

impl From<BranchRefusal> for (StatusCode, String) {
    fn from(refusal: BranchRefusal) -> Self {
        (refusal.status, refusal.message)
    }
}

impl WorkspaceMutationRefusal {
    /// Answer a client, carrying whether one admission pass would clear it.
    ///
    /// A branch command always transitions under `TransitionPolicy::Switch`,
    /// which never raises the tracks-another-ref case, so that arm is
    /// unreachable from a branch route; it maps to a conflict rather than
    /// panicking, because an answer that is merely wrong beats one that takes
    /// the daemon down.
    fn into_client_refusal(self) -> BranchRefusal {
        match self {
            Self::Client(status, message) => BranchRefusal {
                status,
                message,
                clears_with_admission: false,
            },
            Self::ClientClearsWithAdmission(status, message) => BranchRefusal {
                status,
                message,
                clears_with_admission: true,
            },
            Self::TracksAnotherRef(detail) => BranchRefusal {
                status: StatusCode::CONFLICT,
                message: detail,
                clears_with_admission: false,
            },
        }
    }
}

#[derive(Debug)]
struct BranchBadRequest(String);

impl std::fmt::Display for BranchBadRequest {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for BranchBadRequest {}

fn branch_conflict(message: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(BranchConflict(message.into()))
}

fn branch_bad_request(message: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(BranchBadRequest(message.into()))
}

/// The clause a remedy ends with, naming what the caller actually asked for.
///
/// A caller who ran a pull is not switching branches, and telling them to
/// finish doing so describes an operation they never started. Every refusal
/// this transition can raise reads its verb from here, so a new refusal cannot
/// pick up branch language by copying a neighbour.
fn transition_remedy(policy: TransitionPolicy) -> &'static str {
    match policy {
        TransitionPolicy::Switch => "before switching branches",
        TransitionPolicy::FollowMovedRef => {
            "before this workspace can follow the ref the transfer moved"
        }
    }
}

/// The same distinction as a bare operation noun, for refusals phrased as
/// "reopen before {operation}".
fn transition_operation(policy: TransitionPolicy) -> &'static str {
    match policy {
        TransitionPolicy::Switch => "switching branches",
        TransitionPolicy::FollowMovedRef => "following the ref this transfer moved",
    }
}

/// Refuse a follow over uncommitted state that graph authority already owns.
///
/// Only a follow reaches this. A switch plans the same state against the branch
/// it was asked for and refuses through [`pending_state_conflict`], naming the
/// paths that actually block it. Only admitted state reaches either: unadmitted
/// working-copy bytes are reported as projection drift instead, so the wording
/// never describes host content that has not crossed the repository-v6
/// compare-and-swap.
fn graph_owned_changes(
    workspace: &kin_model::WorkspaceState,
    policy: TransitionPolicy,
) -> anyhow::Error {
    branch_conflict(format!(
        "workspace {} has graph-owned changes; commit or explicitly preserve them {}",
        workspace.workspace_id,
        transition_remedy(policy)
    ))
}

/// Whether this replica's working tree stands behind `name`, decided from
/// persisted authority on both sides and nothing else.
///
/// A pull that admitted nothing moved no ref, so nothing that pull did can have
/// left a tree behind. It can still find one behind: the run that admitted the
/// history is the one whose workspace transition did not complete, and its
/// retry admits nothing precisely because the first attempt already admitted
/// everything. Answering that retry with "no ref moved" is true about the retry
/// and silent about the workspace, and the exit status a caller chains on then
/// says the pull is complete while the working tree still shows the old head.
///
/// Reads the workspace's base target against the ref's current target. Both are
/// graph truth, so this states what the replica holds rather than what this
/// invocation did, and it never consults the working copy.
pub(crate) fn workspace_behind_ref(state: &DaemonState, name: &RefName) -> Result<Option<String>> {
    let authority = ActiveLocalRepositoryAuthority::open_bound(state)
        .map_err(RepositoryAuthorityBindRefusal::into_error)
        .context("open repository authority to report whether the workspace follows the ref")?;
    let lease = authority.manager.read_authority();
    let workspace = local_workspace(&authority, lease.metadata())?;
    if !matches!(&workspace.head, WorkspaceHead::Symbolic { target } if target == name) {
        return Ok(None);
    }
    let Some(target) = lease
        .resolve_ref_target(name)
        .with_context(|| format!("resolve repository branch {name} from one authority lease"))?
    else {
        return Ok(None);
    };
    if workspace.base_target.as_ref() == Some(&target) {
        return Ok(None);
    }
    let standing = match &workspace.base_target {
        Some(base) => render_target(base),
        None => "no admitted head".to_string(),
    };
    Ok(Some(format!(
        "workspace {} stands at {standing} while {name} is at {}, so an earlier run moved that ref \
         without this workspace following it. Run `kin branch switch {name}` to move this working \
         tree onto it.",
        workspace.workspace_id,
        render_target(&target)
    )))
}

pub(crate) fn execute(
    state: &DaemonState,
    request: &BranchRequest,
) -> std::result::Result<BranchResponse, BranchRefusal> {
    if matches!(request, BranchRequest::List) {
        let authority = ActiveLocalRepositoryAuthority::open_bound(state)
            .map_err(|refusal| BranchRefusal::from(branch_bind_refusal(refusal)))?;
        return list(&authority).map_err(|error| BranchRefusal::from(internal_branch_error(error)));
    }

    run_workspace_mutation(state, |state, authority| match request {
        BranchRequest::List => unreachable!("list returned before mutation gates"),
        BranchRequest::Create {
            name,
            operation_id,
            actor,
        } => create(state, authority, name, *operation_id, actor).map(BranchCommandOutcome::Commit),
        BranchRequest::Delete {
            name,
            operation_id,
            actor,
        } => delete(state, authority, name, *operation_id, actor).map(BranchCommandOutcome::Commit),
        BranchRequest::Switch {
            name,
            operation_id,
            actor,
        } => switch(
            state,
            authority,
            name,
            *operation_id,
            actor,
            TransitionPolicy::Switch,
        ),
    })
    .map_err(WorkspaceMutationRefusal::into_client_refusal)
}

/// Move the graph-owned workspace onto the current target of the ref it already
/// tracks, after a transfer admitted history onto that ref.
///
/// Publication and the workspace transition are two repository transactions on
/// purpose. The first is atomic per pack and is already durable when this runs,
/// so this cannot revoke it and never reports a transition failure as a failed
/// transfer. It answers only what the working tree did.
pub(crate) fn follow_moved_ref(
    state: &DaemonState,
    name: &RefName,
    actor: &AuthorId,
) -> WorkspaceFollow {
    // A fresh operation id every time is deliberate. Idempotence here is a
    // property of state, not of a caller-stable identifier: the already-current
    // check settles a repeated pull, and the workspace compare-and-swap settles
    // a concurrent one. A retried pull is a new negotiation, so there is no
    // earlier operation for it to replay.
    let outcome = run_workspace_mutation(state, |state, authority| {
        switch(
            state,
            authority,
            name,
            OperationId::new(),
            actor,
            TransitionPolicy::FollowMovedRef,
        )
    });
    match outcome {
        Ok(response) if response.mutated => WorkspaceFollow::Advanced {
            detail: response.lines.join("; "),
            authority_generation: response.authority_generation.unwrap_or_default(),
        },
        Ok(response) => WorkspaceFollow::AlreadyCurrent {
            authority_generation: response.authority_generation.unwrap_or_default(),
        },
        Err(WorkspaceMutationRefusal::TracksAnotherRef(detail)) => {
            WorkspaceFollow::NotApplicable { detail }
        }
        Err(WorkspaceMutationRefusal::Client(_, detail)) => WorkspaceFollow::Behind { detail },
        // A follow is not a switch and never admits, so the one refusal an
        // admission would clear is reported here exactly as any other client
        // refusal is. Spelled out rather than folded into the arm above, because
        // the compiler asking this question is the point of the variant.
        Err(WorkspaceMutationRefusal::ClientClearsWithAdmission(_, detail)) => {
            WorkspaceFollow::Behind { detail }
        }
    }
}

/// Run one planned workspace mutation under the daemon's authority, persistence,
/// and graph-mutation gates, then finalize every view derived from it.
fn run_workspace_mutation<Plan>(
    state: &DaemonState,
    plan: Plan,
) -> std::result::Result<BranchResponse, WorkspaceMutationRefusal>
where
    Plan: FnOnce(&DaemonState, &ActiveLocalRepositoryAuthority) -> Result<BranchCommandOutcome>,
{
    let graph_mutation = state.begin_graph_authority_mutation();
    let persistence = state.persist_lock.lock().map_err(|_| {
        WorkspaceMutationRefusal::Client(
            StatusCode::INTERNAL_SERVER_ERROR,
            "daemon persistence lock poisoned".to_string(),
        )
    })?;
    let previous_graph_root = hex::encode(state.graph.compute_root_hash());
    let authority =
        ActiveLocalRepositoryAuthority::open_bound(state).map_err(branch_bind_refusal)?;
    let outcome = plan(state, &authority).map_err(classify_branch_error)?;
    let execution = match outcome {
        BranchCommandOutcome::Commit(execution) => execution,
        BranchCommandOutcome::ReadOnly(response) => {
            drop(persistence);
            drop(graph_mutation);
            return Ok(response);
        }
    };

    #[cfg(test)]
    if state
        .repository_command_fail_after_authority_once
        .swap(false, std::sync::atomic::Ordering::SeqCst)
    {
        return Err(WorkspaceMutationRefusal::Client(
            StatusCode::INTERNAL_SERVER_ERROR,
            "injected failure after branch authority commit".to_string(),
        ));
    }

    #[cfg(test)]
    if state
        .repository_command_enrich_after_authority_once
        .swap(false, std::sync::atomic::Ordering::SeqCst)
    {
        state.install_derived_enrichment();
    }

    let finalization = state
        .finalize_local_repository_commit(
            &execution.receipt,
            &execution.authority_freeze,
            &execution.daemon_delta,
            &execution.previous_tree,
            &execution.desired_tree,
        )
        .map_err(repository_finalization_error)?;
    if finalization.graph_changed {
        let current_graph_root = hex::encode(state.graph.compute_root_hash());
        state.bump_version();
        state.emit_event(DaemonEvent::GraphRootChanged {
            old_root_hash: Some(previous_graph_root),
            new_root_hash: current_graph_root,
        });
    } else if finalization.generation_advanced {
        state.mark_dirty();
    }
    if finalization.generation_advanced {
        state.emit_event(DaemonEvent::RepositoryAuthorityChanged {
            repository_id: execution.receipt.repository_id.to_string(),
            operation_id: execution.receipt.operation_id,
            previous_generation: execution.receipt.roots_before.generation,
            new_generation: execution.receipt.generation,
        });
    }
    if execution.projection_changed && !finalization.graph_changed {
        state.invalidate_projection();
    }

    drop(persistence);
    drop(graph_mutation);
    Ok(execution.response)
}

fn list(authority: &ActiveLocalRepositoryAuthority) -> Result<BranchResponse> {
    let lease = authority.manager.read_authority();
    let metadata = lease.metadata();
    let workspace = metadata
        .workspaces
        .iter()
        .find(|workspace| workspace.workspace_id == authority.workspace_id)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "repository {} has no workspace {} in repository-v6 authority",
                authority.repository_id,
                authority.workspace_id
            )
        })?;
    let active_ref = match &workspace.head {
        WorkspaceHead::Symbolic { target } => Some(target),
        WorkspaceHead::Detached { .. } => None,
    };
    let default_ref = metadata.ref_state.default_ref.clone();
    let branches = metadata
        .ref_state
        .refs
        .iter()
        .filter(|repository_ref| repository_ref.name.is_branch())
        .map(|repository_ref| BranchListEntry {
            name: repository_ref.name.clone(),
            target: repository_ref.target.clone(),
            active: active_ref == Some(&repository_ref.name),
            default: default_ref.as_ref() == Some(&repository_ref.name),
        })
        .collect::<Vec<_>>();
    let report = BranchListReport {
        schema: BRANCH_LIST_SCHEMA.to_string(),
        authority: "repository-v6".to_string(),
        repository_id: authority.repository_id.clone(),
        authority_generation: lease.roots().generation,
        roots: lease.roots().clone(),
        workspace_id: workspace.workspace_id,
        workspace_generation: workspace.generation,
        workspace_head: workspace.head.clone(),
        repository_ref_count: metadata.ref_state.refs.len(),
        branch_count: branches.len(),
        default_ref,
        branches,
    };
    Ok(BranchResponse {
        lines: render_lines(&report),
        mutated: false,
        report: Some(report),
        operation_id: None,
        authority_generation: None,
        idempotent: false,
    })
}

fn create(
    state: &DaemonState,
    authority: &ActiveLocalRepositoryAuthority,
    name: &RefName,
    operation_id: OperationId,
    actor: &AuthorId,
) -> Result<BranchExecution> {
    require_branch_ref(name)?;
    let lease = authority.manager.read_authority();
    if let Some(receipt) = operation_receipt(lease.metadata(), operation_id) {
        let roots = lease.roots().clone();
        drop(lease);
        return replay_ref_operation(
            authority,
            &roots,
            receipt,
            name,
            operation_id,
            actor,
            CREATE_REASON,
            true,
        );
    }
    let metadata = lease.metadata();
    if metadata
        .ref_state
        .refs
        .iter()
        .any(|repository_ref| &repository_ref.name == name)
    {
        return Err(branch_conflict(format!("branch {name} already exists")));
    }
    let workspace = local_workspace(authority, metadata)?.clone();
    let workspace_graph = lease
        .workspace_graph_snapshot(&workspace.workspace_id)
        .context("materialize branch-creation workspace authority")?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "repository {} has no graph snapshot for workspace {}",
                authority.repository_id,
                workspace.workspace_id
            )
        })?;
    require_fresh_daemon_workspace(state, lease.roots(), &workspace_graph, "creating a branch")
        .map_err(|error| branch_conflict(error.to_string()))?;
    let target = workspace.base_target.clone().ok_or_else(|| {
        branch_conflict(format!(
            "cannot create branch {name} from unborn workspace {}",
            workspace.workspace_id
        ))
    })?;
    if matches!(target, RefTarget::Symbolic { .. }) {
        bail!(
            "workspace {} base target is symbolic instead of resolved",
            workspace.workspace_id
        );
    }
    let transaction = ref_transaction(
        authority,
        lease.roots().clone(),
        operation_id,
        actor.clone(),
        CREATE_REASON,
        RefMutation {
            name: name.clone(),
            expected: RefExpectation::MustNotExist,
            new_target: Some(target),
            policy: RefUpdatePolicy::FastForwardOnly,
        },
    );
    let tree = workspace.tree;
    drop(lease);
    let (receipt, authority_freeze) = commit_and_freeze_exact(&authority.manager, transaction)
        .with_context(|| format!("create repository-v6 branch {name}"))?;
    let target = receipt
        .operation
        .ref_mutations
        .first()
        .and_then(|mutation| mutation.new_target.as_ref())
        .expect("validated branch creation receipt contains its target");
    Ok(BranchExecution {
        response: BranchResponse {
            lines: vec![format!(
                "Created {} at {} (authority generation {})",
                name,
                render_target(target),
                receipt.generation
            )],
            mutated: matches!(receipt.outcome, RepositoryCommitOutcome::Committed),
            report: None,
            operation_id: Some(receipt.operation_id),
            authority_generation: Some(receipt.generation),
            idempotent: matches!(receipt.outcome, RepositoryCommitOutcome::IdempotentReplay),
        },
        receipt,
        authority_freeze,
        daemon_delta: TransactionDelta::default(),
        previous_tree: tree.clone(),
        desired_tree: tree,
        projection_changed: false,
    })
}

fn delete(
    state: &DaemonState,
    authority: &ActiveLocalRepositoryAuthority,
    name: &RefName,
    operation_id: OperationId,
    actor: &AuthorId,
) -> Result<BranchExecution> {
    require_branch_ref(name)?;
    let lease = authority.manager.read_authority();
    if let Some(receipt) = operation_receipt(lease.metadata(), operation_id) {
        let roots = lease.roots().clone();
        drop(lease);
        return replay_ref_operation(
            authority,
            &roots,
            receipt,
            name,
            operation_id,
            actor,
            DELETE_REASON,
            false,
        );
    }
    let metadata = lease.metadata();
    let target = metadata
        .ref_state
        .refs
        .iter()
        .find(|repository_ref| &repository_ref.name == name)
        .map(|repository_ref| repository_ref.target.clone())
        .ok_or_else(|| branch_conflict(format!("branch {name} does not exist")))?;
    if metadata.ref_state.default_ref.as_ref() == Some(name) {
        return Err(branch_conflict(format!(
            "cannot delete default branch {name}; move the repository default ref atomically first"
        )));
    }
    if let Some(workspace) = metadata.workspaces.iter().find(
        |workspace| matches!(&workspace.head, WorkspaceHead::Symbolic { target } if target == name),
    ) {
        return Err(branch_conflict(format!(
            "cannot delete branch {name}; workspace {} has it checked out",
            workspace.workspace_id
        )));
    }
    let workspace = local_workspace(authority, metadata)?;
    let workspace_graph = lease
        .workspace_graph_snapshot(&workspace.workspace_id)
        .context("materialize branch-deletion workspace authority")?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "repository {} has no graph snapshot for workspace {}",
                authority.repository_id,
                workspace.workspace_id
            )
        })?;
    require_fresh_daemon_workspace(state, lease.roots(), &workspace_graph, "deleting a branch")
        .map_err(|error| branch_conflict(error.to_string()))?;
    let tree = workspace.tree.clone();
    let transaction = ref_transaction(
        authority,
        lease.roots().clone(),
        operation_id,
        actor.clone(),
        DELETE_REASON,
        RefMutation {
            name: name.clone(),
            expected: RefExpectation::MustEqual { target },
            new_target: None,
            policy: RefUpdatePolicy::ForceWithLease,
        },
    );
    drop(lease);
    let (receipt, authority_freeze) = commit_and_freeze_exact(&authority.manager, transaction)
        .with_context(|| format!("delete repository-v6 branch {name}"))?;
    Ok(BranchExecution {
        response: BranchResponse {
            lines: vec![format!(
                "Deleted {} (authority generation {})",
                name, receipt.generation
            )],
            mutated: matches!(receipt.outcome, RepositoryCommitOutcome::Committed),
            report: None,
            operation_id: Some(receipt.operation_id),
            authority_generation: Some(receipt.generation),
            idempotent: matches!(receipt.outcome, RepositoryCommitOutcome::IdempotentReplay),
        },
        receipt,
        authority_freeze,
        daemon_delta: TransactionDelta::default(),
        previous_tree: tree.clone(),
        desired_tree: tree,
        projection_changed: false,
    })
}

fn replay_ref_operation(
    authority: &ActiveLocalRepositoryAuthority,
    current_roots: &RootBundle,
    receipt: RepositoryCommitReceipt,
    name: &RefName,
    operation_id: OperationId,
    actor: &AuthorId,
    reason: &str,
    creating: bool,
) -> Result<BranchExecution> {
    receipt
        .validate()
        .context("validate persisted branch receipt")?;
    let [mutation] = receipt.operation.ref_mutations.as_slice() else {
        bail!("branch operation {operation_id} did not commit exactly one ref mutation");
    };
    if &mutation.name != name || mutation.new_target.is_some() != creating {
        return Err(branch_conflict(format!(
            "branch operation {operation_id} was already committed for a different request"
        )));
    }
    if current_roots != &receipt.roots_after {
        return Err(branch_conflict(format!(
            "branch operation {operation_id} committed at generation {}, but authority is now at \
             generation {}; reopen against current authority before retrying",
            receipt.generation, current_roots.generation
        )));
    }
    let transaction = ref_transaction(
        authority,
        receipt.roots_before.clone(),
        operation_id,
        actor.clone(),
        reason,
        mutation.clone(),
    );
    if transaction.transaction_hash()? != receipt.transaction_hash {
        return Err(branch_conflict(format!(
            "branch operation {operation_id} was already committed for a different request"
        )));
    }
    let lease = authority.manager.read_authority();
    let tree = local_workspace(authority, lease.metadata())?.tree.clone();
    drop(lease);
    let (replayed, authority_freeze) = commit_and_freeze_exact(&authority.manager, transaction)?;
    validate_identical_replay(&receipt, &replayed)?;
    let line = if creating {
        let target = mutation
            .new_target
            .as_ref()
            .expect("creating branch replay has a target");
        format!(
            "Created {} at {} (authority generation {}, idempotent replay)",
            name,
            render_target(target),
            replayed.generation
        )
    } else {
        format!(
            "Deleted {} (authority generation {}, idempotent replay)",
            name, replayed.generation
        )
    };
    Ok(BranchExecution {
        response: BranchResponse {
            lines: vec![line],
            mutated: false,
            report: None,
            operation_id: Some(replayed.operation_id),
            authority_generation: Some(replayed.generation),
            idempotent: true,
        },
        receipt: replayed,
        authority_freeze,
        daemon_delta: TransactionDelta::default(),
        previous_tree: tree.clone(),
        desired_tree: tree,
        projection_changed: false,
    })
}

fn switch(
    state: &DaemonState,
    authority: &ActiveLocalRepositoryAuthority,
    name: &RefName,
    operation_id: OperationId,
    actor: &AuthorId,
    policy: TransitionPolicy,
) -> Result<BranchCommandOutcome> {
    require_branch_ref(name)?;
    let lease = authority.manager.read_authority();
    if let Some(receipt) = operation_receipt(lease.metadata(), operation_id) {
        let roots = lease.roots().clone();
        drop(lease);
        return replay_switch(state, authority, &roots, receipt, name, actor)
            .map(BranchCommandOutcome::Commit);
    }
    let roots = lease.roots().clone();
    let metadata = lease.metadata();
    let workspace = local_workspace(authority, metadata)?.clone();
    // A switch no longer refuses merely because the workspace holds pending
    // state. Ambient observation admits every new non-ignored file, so a
    // scratch note is uncommitted graph truth within seconds of being written,
    // and refusing on that alone would block the most frequent gesture of a
    // working day over a file Git would have carried without comment. The
    // pending state is planned against the destination further down instead,
    // and only the cases that would actually lose work refuse.
    //
    // A follow keeps the older, stricter rule. It is the second half of a
    // transfer rather than a gesture anyone typed, so there is no muscle memory
    // to honour and no caller standing by to resolve a conflict; it defers the
    // refusal until the transition is known to be needed, because the history
    // it would refuse over is already durable and a workspace already at the
    // moved ref has nothing to refuse about.
    if policy == TransitionPolicy::FollowMovedRef
        && !matches!(&workspace.head, WorkspaceHead::Symbolic { target } if target == name)
    {
        return Err(anyhow::Error::new(WorkspaceTracksAnotherRef(format!(
            "workspace {} does not track {name}, so a head admitted onto that ref moves no working \
             tree here",
            workspace.workspace_id
        ))));
    }
    let target = lease
        .resolve_ref_target(name)
        .with_context(|| format!("resolve repository branch {name} from one authority lease"))?
        .ok_or_else(|| branch_conflict(format!("repository branch {name} does not exist")))?;
    let target_change_id = lease
        .resolve_target_change_id(&target)
        .with_context(|| format!("resolve exact semantic target for branch {name}"))?;
    // The workspace's own base, so the difference between it and the workspace
    // tree is exactly the pending work a switch has to decide about. An unborn
    // symbolic head has no base, and every member of its tree is pending.
    let base_change_id = workspace
        .base_target
        .as_ref()
        .map(|base| lease.resolve_target_change_id(base))
        .transpose()
        .context("resolve the exact authority target this workspace is based on")?;
    let target_shared_policy = metadata
        .admission_policies
        .iter()
        .find(|resolved| resolved.change_id == target_change_id)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "target change {target_change_id} has no repository-v6 admission-policy record"
            )
        })?
        .policy
        .clone()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "target change {target_change_id} has unresolved admission policy and cannot \
                 become a clean workspace"
            )
        })?;
    let current_workspace_graph = lease
        .workspace_graph_snapshot(&workspace.workspace_id)
        .context("materialize current graph-owned workspace semantics")?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "repository {} has no graph snapshot for workspace {}",
                authority.repository_id,
                workspace.workspace_id
            )
        })?;
    require_fresh_daemon_workspace(
        state,
        &roots,
        &current_workspace_graph,
        transition_operation(policy),
    )
    .map_err(|error| branch_conflict(error.to_string()))?;
    let mut snapshot = lease.snapshot().clone();
    snapshot.repository_authority = None;
    drop(lease);

    let graph = kin_db::InMemoryGraph::from_snapshot(snapshot)
        .context("prepare graph-owned branch target")?;
    let mut desired_state = graph
        .resolve_graph_at(&target_change_id)
        .with_context(|| format!("resolve exact graph for branch {name}"))?;
    let target_tree = desired_state.tree.clone();
    let target_tree_hash =
        compute_resolved_tree_hash(&target_tree).context("hash exact branch target tree")?;
    // Plan what the pending workspace does across the transition. The result
    // replaces the desired state wholesale, so everything downstream (the
    // preflight, the published mutation, and the materialization) works from
    // one description of where this workspace lands: the destination branch's
    // members with the pending work replayed on top.
    let carried = plan_switch_carry(
        &graph,
        &workspace,
        base_change_id.as_ref(),
        &desired_state,
        name,
        policy,
    )?;
    if let Some(plan) = &carried {
        desired_state.tree = plan.tree.clone();
        desired_state.entities = plan.entities.clone();
        desired_state.relations = plan.relations.clone();
    }
    let desired_tree = desired_state.tree.clone();
    let desired_tree_hash = compute_resolved_tree_hash(&desired_tree)
        .context("hash the exact tree this branch transition lands on")?;
    let tree_deltas = kin_core::exact_tree_correction(&workspace.tree, &desired_tree)
        .context("plan exact branch workspace transition")?;
    let semantic_delta = kin_core::diff_workspace_semantics(
        &current_workspace_graph.entities,
        &current_workspace_graph.relations,
        &desired_state.entities,
        &desired_state.relations,
    )
    .context("plan exact branch semantic transition")?;
    let daemon_semantic_delta = crate::local_repository_authority::plan_daemon_semantic_delta(
        state,
        &desired_state.entities,
        &desired_state.relations,
    )
    .context("plan the branch semantic transition for the daemon view")?;
    let daemon_delta = TransactionDelta {
        entity_deltas: daemon_semantic_delta.entity_deltas().to_vec(),
        relation_deltas: daemon_semantic_delta.relation_deltas().to_vec(),
        tree_deltas: tree_deltas.clone(),
        admission_policy_delta: None,
        external_reference_deltas: Vec::new(),
    };
    preflight_switch_delta(state, &workspace.tree, &desired_state, &daemon_delta)?;
    let already_active = matches!(
        &workspace.head,
        WorkspaceHead::Symbolic { target } if target == name
    ) && workspace.base_target.as_ref() == Some(&target)
        && workspace.tree_hash == desired_tree_hash
        && tree_deltas.is_empty()
        && semantic_delta.is_empty()
        && workspace.shared_admission_policy == target_shared_policy
        && workspace.admission_policy.shared == target_shared_policy.stamp();
    if already_active {
        let (verified_entries, authority_freeze) =
            kin_core::verify_repository_workspace_projection(
                state.layout.working_dir(),
                &workspace.tree,
                &authority.manager,
            )
            // A switch to the ref this workspace already tracks is not a
            // transition, so there is nothing for pending work to carry onto and
            // an admission clears nothing the caller asked for. It would still
            // publish, moving the authority generation as a side effect of a
            // command that changes nothing, so the drift refusal keeps its plain
            // kind here and the retry never sees it.
            //
            // Measured, not assumed: this is where the same-target drift refusal
            // is actually raised. `preflight_switch_delta` above never refuses
            // on it, which a probe said and a reading of the two call sites did
            // not.
            .map_err(forget_that_admission_would_clear_it)
            .with_context(|| format!("verify exact projection for already-active branch {name}"))?;
        let generation = authority_freeze.roots().generation;
        drop(authority_freeze);
        return Ok(BranchCommandOutcome::ReadOnly(BranchResponse {
            lines: vec![format!(
                "Already on {} at change {} ({} projected entries verified, authority generation {})",
                name, target_change_id, verified_entries, generation
            )],
            mutated: false,
            report: None,
            operation_id: Some(operation_id),
            authority_generation: Some(generation),
            idempotent: true,
        }));
    }
    // The workspace is genuinely behind the ref, so a follow now has to decide
    // what to do with graph-owned state the caller never committed. Moving the
    // tree out from under it would discard work the compare-and-swap already
    // owns, so the transition stops here and the transfer reports it.
    if policy == TransitionPolicy::FollowMovedRef && workspace.is_dirty() {
        return Err(graph_owned_changes(&workspace, policy));
    }
    let transaction = RepositoryTransaction {
        schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
        operation_id,
        repository_id: authority.repository_id.clone(),
        expected_generation: roots.generation,
        expected_roots: roots,
        actor: actor.clone(),
        reason: match policy {
            TransitionPolicy::Switch => SWITCH_REASON,
            TransitionPolicy::FollowMovedRef => FOLLOW_REASON,
        }
        .to_string(),
        external_objects: Vec::new(),
        git_authority_delta: None,
        changes: Vec::new(),
        aliases: Vec::new(),
        ref_mutations: Vec::new(),
        default_ref_mutation: None,
        workspace_mutation: Some(WorkspaceMutation {
            workspace_id: workspace.workspace_id,
            expected: WorkspaceExpectation::MustEqual {
                generation: workspace.generation,
                head: workspace.head.clone(),
                base_target: workspace.base_target.clone(),
                base_tree_hash: workspace.base_tree_hash,
                tree_hash: workspace.tree_hash,
                semantic_overlay_hash: workspace.semantic_overlay_hash,
                admission_policy: workspace.admission_policy,
            },
            new_generation: workspace.generation.checked_add(1).ok_or_else(|| {
                crate::error::workspace_generation_exhausted(
                    workspace.workspace_id,
                    workspace.generation,
                )
            })?,
            new_head: WorkspaceHead::Symbolic {
                target: name.clone(),
            },
            new_base_target: Some(target),
            // The base is always the branch that was entered. The tree may sit
            // ahead of it, which is precisely what a carried pending workspace
            // is: work that has not been committed to the branch now under it.
            new_base_tree_hash: Some(target_tree_hash),
            tree_deltas,
            new_tree_hash: desired_tree_hash,
            semantic_delta,
            new_shared_admission_policy: target_shared_policy.clone(),
            new_admission_policy: EffectiveAdmissionPolicyStamp {
                shared: target_shared_policy.stamp(),
                local: workspace.admission_policy.local,
            },
        }),
        local_overlay_delta: None,
        merge_transaction_delta: None,
        sealed_observation: None,
        collaboration_delta: None,
    };
    // Validate the derived view before materializing anything over it. This
    // reads the working copy only at paths the workspace tree already tracks
    // and compares them against the content repository authority owns, so it
    // reports edits made outside Kin's seams without treating any of them as
    // graph-owned state. Untracked host paths are never read and never gate
    // the transition.
    let drift = kin_core::report_repository_workspace_projection_drift(
        state.layout.working_dir(),
        &workspace.tree,
        &authority.manager,
    )
    .with_context(|| format!("validate exact workspace projection before moving onto {name}"))?;
    if let Some(first) = drift.first() {
        // Tracked drift by construction, which the comment above states as this
        // reader's contract: it reads only paths the workspace tree already
        // tracks, and untracked host paths are never read. Naming the kind here
        // is what lets one admission pass clear this refusal, and the aggregate
        // is where it has to be named, because the per-path kinds are collected
        // as messages and this error is a new one built from them.
        return Err(kin_core::KinError::tracked_projection_drift(format!(
            "{first}; {} tracked path(s) diverge from the graph-owned workspace projection; \
             reconcile them into graph authority or discard them {}",
            drift.len(),
            transition_remedy(policy)
        ))
        .into());
    }
    let (materialized, receipt, authority_freeze) =
        kin_core::tree::transition_repository_workspace_tree_and_commit_repository_transaction(
            state.layout.working_dir(),
            &workspace.tree,
            &desired_tree,
            &authority.manager,
            transaction,
        )
        .with_context(|| format!("switch repository-v6 workspace to branch {name}"))?;
    Ok(BranchCommandOutcome::Commit(BranchExecution {
        response: BranchResponse {
            lines: vec![format!(
                "{} {} at change {} ({} projected entries, authority generation {}){}",
                match policy {
                    TransitionPolicy::Switch => "Switched to",
                    TransitionPolicy::FollowMovedRef => "Followed",
                },
                name,
                target_change_id,
                materialized,
                receipt.generation,
                carried.as_deref().map_or_else(String::new, render_carried)
            )],
            mutated: matches!(receipt.outcome, RepositoryCommitOutcome::Committed),
            report: None,
            operation_id: Some(receipt.operation_id),
            authority_generation: Some(receipt.generation),
            idempotent: matches!(receipt.outcome, RepositoryCommitOutcome::IdempotentReplay),
        },
        receipt,
        authority_freeze,
        daemon_delta,
        previous_tree: workspace.tree,
        desired_tree,
        projection_changed: true,
    }))
}

/// Decide what a switch does with pending workspace state, or refuse.
///
/// Returns `None` when there is nothing pending, or when the policy is a follow
/// rather than a switch. A follow is handled by the older refusal further down
/// and never carries: see the note at the head of [`switch`].
fn plan_switch_carry(
    graph: &kin_db::InMemoryGraph,
    workspace: &kin_model::WorkspaceState,
    base_change_id: Option<&kin_model::SemanticChangeId>,
    target_state: &kin_model::graph::ResolvedGraphState,
    name: &RefName,
    policy: TransitionPolicy,
) -> Result<Option<Box<kin_core::WorkspaceCarryPlan>>> {
    if policy != TransitionPolicy::Switch || !workspace.is_dirty() {
        return Ok(None);
    }
    let base_tree = match base_change_id {
        Some(change_id) => {
            graph
                .resolve_graph_at(change_id)
                .context("resolve the exact graph this workspace is based on")?
                .tree
        }
        None => ResolvedTree::default(),
    };
    match kin_core::plan_workspace_carry(
        &base_tree,
        &workspace.tree,
        &workspace.semantic_overlay,
        &target_state.tree,
        &target_state.entities,
        &target_state.relations,
    )
    .with_context(|| format!("plan pending workspace state against {name}"))?
    {
        kin_core::WorkspaceCarry::Carried(plan) => Ok(Some(plan)),
        kin_core::WorkspaceCarry::Refused(conflicts) => {
            Err(pending_state_conflict(workspace, name, &conflicts, policy))
        }
        kin_core::WorkspaceCarry::SemanticallyRefused(refusal) => Err(pending_semantics_conflict(
            workspace, name, &refusal, policy,
        )),
    }
}

/// Refuse a switch whose pending graph work the destination cannot take.
///
/// The tree-side twin above names each blocked path, because a path is what the
/// caller edited. This one has no path to name: the pending work is entity and
/// relation deltas a background pass derived, so it names how many there are and
/// of what kind. It is a conflict rather than an internal error, which is what
/// this refusal used to reach clients as, with the graph invariant in the body
/// and no count anywhere.
fn pending_semantics_conflict(
    workspace: &kin_model::WorkspaceState,
    name: &RefName,
    refusal: &kin_core::WorkspaceSemanticCarryRefusal,
    policy: TransitionPolicy,
) -> anyhow::Error {
    branch_conflict(format!(
        "workspace {} cannot move onto {name}: {}, {}",
        workspace.workspace_id,
        refusal.reason(),
        transition_remedy(policy)
    ))
}

/// Refuse a switch that would lose pending work, naming every blocked path.
///
/// The message states which side each path would have cost, because "commit or
/// stash" is only actionable once a caller knows whether the obstacle is their
/// own edit or a member of the branch they asked for.
fn pending_state_conflict(
    workspace: &kin_model::WorkspaceState,
    name: &RefName,
    conflicts: &[kin_core::WorkspaceCarryConflict],
    policy: TransitionPolicy,
) -> anyhow::Error {
    let detail = conflicts
        .iter()
        .map(|conflict| format!("{} ({})", conflict.path, conflict.kind.reason()))
        .collect::<Vec<_>>()
        .join("; ");
    branch_conflict(format!(
        "workspace {} holds pending changes that cannot move onto {name}: {detail}. Pending work \
         at any other path moves across with you. Commit these, or set them aside with `kin stash \
         push`, {}",
        workspace.workspace_id,
        transition_remedy(policy)
    ))
}

/// Report what a carry did, so the switch line says where pending work went.
///
/// A caller who just moved branches with uncommitted work needs to see that it
/// came along, and needs the absorbed case named separately: those paths are
/// tracked members of the branch now rather than pending work, which is a real
/// change in what a later commit would publish.
///
/// Retired edges are reported for the same reason and are the one clause that is
/// a loss rather than a move. An edge into a node the transition retired cannot
/// be read by any query, so keeping it would only hand a dangling endpoint to
/// the storage layer, but a graph that quietly holds fewer edges than it did is
/// exactly the thing this product must never do without saying so.
fn render_carried(plan: &kin_core::WorkspaceCarryPlan) -> String {
    let mut clauses = Vec::new();
    if !plan.carried.is_empty() {
        clauses.push(format!(
            "{} pending path(s) carried across and still uncommitted: {}",
            plan.carried.len(),
            render_paths(&plan.carried)
        ));
    }
    if !plan.absorbed.is_empty() {
        clauses.push(format!(
            "{} pending path(s) already tracked at identical content on this branch: {}",
            plan.absorbed.len(),
            render_paths(&plan.absorbed)
        ));
    }
    if !plan.retired_relations.is_empty() {
        clauses.push(format!(
            "{} relation(s) retired because this transition removed an endpoint they pointed at",
            plan.retired_relations.len()
        ));
    }
    if clauses.is_empty() {
        return String::new();
    }
    format!("; {}", clauses.join("; "))
}

/// At most five paths, so one crowded switch cannot bury its own headline.
fn render_paths(paths: &[kin_model::RepoPath]) -> String {
    const SHOWN: usize = 5;
    let listed = paths
        .iter()
        .take(SHOWN)
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    match paths.len().checked_sub(SHOWN) {
        Some(remaining) if remaining > 0 => format!("{listed} and {remaining} more"),
        _ => listed,
    }
}

fn replay_switch(
    state: &DaemonState,
    authority: &ActiveLocalRepositoryAuthority,
    current_roots: &RootBundle,
    receipt: RepositoryCommitReceipt,
    name: &RefName,
    actor: &AuthorId,
) -> Result<BranchExecution> {
    receipt
        .validate()
        .context("validate persisted branch-switch receipt")?;
    if !receipt.operation.ref_mutations.is_empty() {
        bail!(
            "branch switch operation {} unexpectedly mutated repository refs",
            receipt.operation_id
        );
    }
    let mutation = receipt
        .operation
        .workspace_mutation
        .as_ref()
        .cloned()
        .ok_or_else(|| {
            anyhow::anyhow!(
                "branch switch operation {} has no workspace mutation",
                receipt.operation_id
            )
        })?;
    if !matches!(&mutation.new_head, WorkspaceHead::Symbolic { target } if target == name) {
        return Err(branch_conflict(format!(
            "branch operation {} was already committed for a different request",
            receipt.operation_id
        )));
    }
    if current_roots != &receipt.roots_after {
        return Err(branch_conflict(format!(
            "branch operation {} committed at generation {}, but authority is now at generation {}; \
             reopen against current authority before retrying",
            receipt.operation_id,
            receipt.generation,
            current_roots.generation
        )));
    }
    let transaction = RepositoryTransaction {
        schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
        operation_id: receipt.operation_id,
        repository_id: authority.repository_id.clone(),
        expected_generation: receipt.roots_before.generation,
        expected_roots: receipt.roots_before.clone(),
        actor: actor.clone(),
        reason: SWITCH_REASON.to_string(),
        external_objects: Vec::new(),
        git_authority_delta: None,
        changes: Vec::new(),
        aliases: Vec::new(),
        ref_mutations: Vec::new(),
        default_ref_mutation: None,
        workspace_mutation: Some(mutation.clone()),
        local_overlay_delta: None,
        merge_transaction_delta: None,
        sealed_observation: None,
        collaboration_delta: None,
    };
    if transaction.transaction_hash()? != receipt.transaction_hash {
        return Err(branch_conflict(format!(
            "branch operation {} was already committed for a different request",
            receipt.operation_id
        )));
    }
    let lease = authority.manager.read_authority();
    let workspace = local_workspace(authority, lease.metadata())?;
    if workspace.generation != mutation.new_generation
        || workspace.tree_hash != mutation.new_tree_hash
        || workspace.head != mutation.new_head
    {
        return Err(branch_conflict(format!(
            "branch switch operation {} no longer matches current workspace authority",
            receipt.operation_id
        )));
    }
    let desired_tree = workspace.tree.clone();
    let inverse = mutation
        .tree_deltas
        .iter()
        .map(kin_model::TreeDelta::inverse)
        .collect::<Vec<_>>();
    let previous_tree = desired_tree
        .apply(&inverse)
        .context("reconstruct pre-switch workspace tree from persisted receipt")?;
    // A replay recovers the daemon after authority already moved, so the
    // workspace graph the lease holds now is the switch target. Planning the
    // daemon side from the live graph to that target keeps the recovery honest
    // when derived enrichment landed before the crash.
    let target_graph = lease
        .workspace_graph_snapshot(&workspace.workspace_id)
        .context("materialize the replayed branch-switch workspace authority")?
        .ok_or_else(|| {
            anyhow::anyhow!(
                "repository {} has no graph snapshot for workspace {}",
                authority.repository_id,
                workspace.workspace_id
            )
        })?;
    let daemon_semantic_delta = crate::local_repository_authority::plan_daemon_semantic_delta(
        state,
        &target_graph.entities,
        &target_graph.relations,
    )
    .context("plan the replayed branch semantic transition for the daemon view")?;
    let daemon_delta = TransactionDelta {
        entity_deltas: daemon_semantic_delta.entity_deltas().to_vec(),
        relation_deltas: daemon_semantic_delta.relation_deltas().to_vec(),
        tree_deltas: mutation.tree_deltas.clone(),
        admission_policy_delta: None,
        external_reference_deltas: Vec::new(),
    };
    drop(lease);
    let (replayed, authority_freeze) =
        kin_core::tree::replay_repository_workspace_transaction_and_recover_projection(
            state.layout.working_dir(),
            &authority.manager,
            transaction,
        )
        .context("replay branch switch and recover its exact projection")?;
    validate_identical_replay(&receipt, &replayed)?;
    Ok(BranchExecution {
        response: BranchResponse {
            lines: vec![format!(
                "Switched to {} (authority generation {}, idempotent replay)",
                name, replayed.generation
            )],
            mutated: false,
            report: None,
            operation_id: Some(replayed.operation_id),
            authority_generation: Some(replayed.generation),
            idempotent: true,
        },
        receipt: replayed,
        authority_freeze,
        daemon_delta,
        previous_tree,
        desired_tree,
        projection_changed: true,
    })
}

fn preflight_switch_delta(
    state: &DaemonState,
    previous_tree: &ResolvedTree,
    desired: &kin_model::graph::ResolvedGraphState,
    delta: &TransactionDelta,
) -> Result<()> {
    let desired_tree = &desired.tree;
    let live_tree = state.graph.resolved_tree();
    if live_tree != *previous_tree && live_tree != *desired_tree {
        return Err(branch_conflict(
            "daemon query tree matches neither branch-switch base nor desired authority",
        ));
    }
    let preflight = kin_db::InMemoryGraph::from_snapshot(state.graph.to_snapshot())
        .map_err(|error| crate::error::name_stranded_endpoint_recovery(anyhow::Error::new(error)))
        .context("prepare branch-switch daemon graph preflight")?;
    preflight
        .apply_transaction_delta(delta)
        .map_err(|error| crate::error::name_stranded_endpoint_recovery(anyhow::Error::new(error)))
        .context("apply branch-switch daemon graph preflight")?;
    let snapshot = preflight.to_snapshot();
    if snapshot.resolved_tree != *desired_tree
        || snapshot.entities != desired.entities
        || snapshot.relations != desired.relations
    {
        bail!(
            "the switch preflighted to a graph and tree that do not match the target branch's \
             head, so kin refused the switch; your workspace is unchanged, so run `kin status` \
             and try again"
        );
    }
    Ok(())
}

fn ref_transaction(
    authority: &ActiveLocalRepositoryAuthority,
    roots: RootBundle,
    operation_id: OperationId,
    actor: AuthorId,
    reason: &str,
    mutation: RefMutation,
) -> RepositoryTransaction {
    RepositoryTransaction {
        schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
        operation_id,
        repository_id: authority.repository_id.clone(),
        expected_generation: roots.generation,
        expected_roots: roots,
        actor,
        reason: reason.to_string(),
        external_objects: Vec::new(),
        git_authority_delta: None,
        changes: Vec::new(),
        aliases: Vec::new(),
        ref_mutations: vec![mutation],
        default_ref_mutation: None,
        workspace_mutation: None,
        local_overlay_delta: None,
        merge_transaction_delta: None,
        sealed_observation: None,
        collaboration_delta: None,
    }
}

fn commit_and_freeze_exact(
    manager: &RepositoryAuthorityManager<LocalFileBackend>,
    transaction: RepositoryTransaction,
) -> Result<(RepositoryCommitReceipt, LocalRepositoryAuthorityFreeze)> {
    match manager.commit_repository_transaction_and_freeze(transaction.clone()) {
        Ok(committed) => Ok(committed),
        Err(first_error) => manager
            .commit_repository_transaction_and_freeze(transaction)
            .map_err(|second_error| {
                anyhow::Error::new(second_error).context(format!(
                    "commit and freeze repository branch authority after first attempt failed: \
                     {first_error}"
                ))
            }),
    }
}

fn validate_identical_replay(
    installed: &RepositoryCommitReceipt,
    replayed: &RepositoryCommitReceipt,
) -> Result<()> {
    if replayed.transaction_hash != installed.transaction_hash
        || replayed.roots_before != installed.roots_before
        || replayed.roots_after != installed.roots_after
        || replayed.generation != installed.generation
        || !matches!(replayed.outcome, RepositoryCommitOutcome::IdempotentReplay)
    {
        bail!(
            "repository authority returned a non-identical replay for branch operation {}",
            installed.operation_id
        );
    }
    Ok(())
}

/// The whole receipt for `operation_id`.
///
/// Delegates to kin-core, because a persisted receipt names its operation
/// record rather than repeating it (kin-db 0.7.89, FIR-3064) and the pairing
/// that puts the two halves back together belongs in one place. This crate had
/// two copies of the old lookup, in this file and in `repository_stash.rs`,
/// which is exactly the drift a shared rule prevents.
fn operation_receipt(
    metadata: &kin_db::PersistedRepositoryAuthority,
    operation_id: OperationId,
) -> Option<RepositoryCommitReceipt> {
    kin_core::rejoined_receipt(metadata, operation_id)
}

fn local_workspace<'a>(
    authority: &ActiveLocalRepositoryAuthority,
    metadata: &'a kin_db::PersistedRepositoryAuthority,
) -> Result<&'a kin_model::WorkspaceState> {
    metadata
        .workspaces
        .iter()
        .find(|workspace| workspace.workspace_id == authority.workspace_id)
        .ok_or_else(|| {
            anyhow::anyhow!(
                "repository {} has no workspace {} in repository-v6 authority",
                authority.repository_id,
                authority.workspace_id
            )
        })
}

fn require_branch_ref(name: &RefName) -> Result<()> {
    if !name.is_branch() {
        return Err(branch_bad_request(format!(
            "branch command requires a ref below refs/heads/, found {name}"
        )));
    }
    Ok(())
}

fn render_lines(report: &BranchListReport) -> Vec<String> {
    if report.branches.is_empty() {
        return vec![format!(
            "(no branches; workspace head is {})",
            render_head(&report.workspace_head)
        )];
    }
    report
        .branches
        .iter()
        .map(|branch| {
            let active = if branch.active { "*" } else { " " };
            let default = if branch.default { " [default]" } else { "" };
            format!(
                "{active} {} -> {}{default}",
                branch.name,
                render_target(&branch.target)
            )
        })
        .collect()
}

fn render_head(head: &WorkspaceHead) -> String {
    match head {
        WorkspaceHead::Symbolic { target } => format!("symbolic {target}"),
        WorkspaceHead::Detached { target } => format!("detached {}", render_target(target)),
    }
}

fn render_target(target: &RefTarget) -> String {
    match target {
        RefTarget::Change { change_id } => format!("change {change_id}"),
        RefTarget::ExternalObject { object } => format!("{:?} {}", object.kind, object.oid),
        RefTarget::Symbolic { target } => format!("symbolic {target}"),
    }
}

/// The projection conflict's kind, wherever in the chain it sits.
///
/// Walks the causes rather than reading only the head, because these errors
/// travel wrapped in context by the time a route classifies them.
fn projection_conflict_kind(error: &anyhow::Error) -> Option<kin_core::ProjectionConflictKind> {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<kin_core::KinError>())
        .and_then(kin_core::KinError::projection_conflict_kind)
}

/// Drop the claim that one admission pass would clear this refusal.
///
/// For a refusal raised where no transition is being made, the claim is true
/// and useless: admitting would publish and change the generation while the
/// caller's command still does nothing. Everything else about the error, its
/// status and its sentence, is untouched.
fn forget_that_admission_would_clear_it(error: kin_core::KinError) -> kin_core::KinError {
    match error {
        kin_core::KinError::ProjectionConflict(detail) => {
            kin_core::KinError::projection_conflict(detail.message)
        }
        other => other,
    }
}

fn classify_branch_error(error: anyhow::Error) -> WorkspaceMutationRefusal {
    // Read the kind BEFORE the error is flattened to a status and a sentence,
    // because that is the last moment it exists. Tracked drift is the one
    // refusal an admission pass clears; every other projection conflict, and
    // every other error, keeps the answer it has always had.
    if matches!(
        projection_conflict_kind(&error),
        Some(kin_core::ProjectionConflictKind::TrackedDrift)
    ) {
        let (status, message) = client_branch_refusal(error);
        return WorkspaceMutationRefusal::ClientClearsWithAdmission(status, message);
    }
    // Nothing to do is not a failure, and a follow tells it apart from one by
    // the variant rather than by reading a message it would have to
    // pattern-match. It is raised only under `TransitionPolicy::FollowMovedRef`,
    // and it carries no status because no client is ever answered with it.
    if error.downcast_ref::<WorkspaceTracksAnotherRef>().is_some() {
        return WorkspaceMutationRefusal::TracksAnotherRef(crate::error::cause_first(&error));
    }
    client_branch_refusal(error).into()
}

fn client_branch_refusal(error: anyhow::Error) -> (StatusCode, String) {
    if error.downcast_ref::<BranchBadRequest>().is_some() {
        return (StatusCode::BAD_REQUEST, crate::error::cause_first(&error));
    }
    if error.downcast_ref::<BranchConflict>().is_some() {
        return (StatusCode::CONFLICT, crate::error::cause_first(&error));
    }
    if let Some(core) = error.downcast_ref::<kin_core::KinError>() {
        let status = match core {
            kin_core::KinError::Model(model) => branch_model_status(model),
            kin_core::KinError::RepositoryConflict(_)
            | kin_core::KinError::ProjectionConflict(_) => StatusCode::CONFLICT,
            kin_core::KinError::RepositoryCommitIndeterminate(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        return (status, crate::error::cause_first(&error));
    }
    if let Some(database) = error.downcast_ref::<kin_db::KinDbError>() {
        let status = match database {
            kin_db::KinDbError::Model(model) => branch_model_status(model),
            kin_db::KinDbError::SnapshotPersistenceIndeterminate(_)
            | kin_db::KinDbError::StorageError(_)
            | kin_db::KinDbError::LockError(_)
            | kin_db::KinDbError::ConcurrentAccessError(_) => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        return (status, crate::error::cause_first(&error));
    }
    if let Some(model) = error.downcast_ref::<kin_model::ModelError>() {
        return (
            branch_model_status(model),
            crate::error::cause_first(&error),
        );
    }
    if error.downcast_ref::<std::io::Error>().is_some() {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            crate::error::cause_first(&error),
        );
    }
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        crate::error::cause_first(&error),
    )
}

fn branch_model_status(error: &kin_model::ModelError) -> StatusCode {
    match error {
        kin_model::ModelError::InvalidHash(_) | kin_model::ModelError::InvalidOperation(_) => {
            StatusCode::BAD_REQUEST
        }
        kin_model::ModelError::Conflict(_)
        | kin_model::ModelError::RefNotFound(_)
        | kin_model::ModelError::WorkspaceNotFound(_)
        | kin_model::ModelError::ChangeNotFound(_) => StatusCode::CONFLICT,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    }
}

fn repository_finalization_error(error: crate::error::DaemonError) -> (StatusCode, String) {
    use crate::error::DaemonError;
    let status = match &error {
        DaemonError::Graph(kin_db::KinDbError::Model(kin_model::ModelError::InvalidOperation(
            _,
        )))
        | DaemonError::Core(kin_core::KinError::Model(kin_model::ModelError::InvalidOperation(
            _,
        ))) => StatusCode::BAD_REQUEST,
        DaemonError::Graph(kin_db::KinDbError::Model(kin_model::ModelError::Conflict(_)))
        | DaemonError::IncompatibleRepo(_) => StatusCode::CONFLICT,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (status, error.to_string())
}

fn internal_branch_error(error: impl std::fmt::Display) -> (StatusCode, String) {
    (StatusCode::INTERNAL_SERVER_ERROR, error.to_string())
}

/// Answer a pinned-namespace refusal as a conflict for the same reason checkout
/// does: the branch request is well formed, but the repository authority this
/// daemon pinned is no longer the one at that path.
fn branch_bind_refusal(refusal: RepositoryAuthorityBindRefusal) -> (StatusCode, String) {
    let identity = refusal.is_identity_refusal();
    let error = refusal.into_error();
    if identity {
        (StatusCode::CONFLICT, crate::error::cause_first(&error))
    } else {
        internal_branch_error(crate::error::cause_first(&error))
    }
}
