// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Exact repository-authority commit path for MCP transactions.
//!
//! This planner never reads source from the working filesystem and never
//! mutates the daemon's live query graph before repository-v6 authority
//! commits. Existing source bodies come from repository CAS, entity bodies are
//! spliced in memory, and final semantics are re-derived from those exact
//! bytes. The repository transaction and exact working-tree projection share
//! the projection WAL in `repository_commit`.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use kin_model::{
    Entity, EntityDelta, EntityStore, FileLayout, FilePathId, GraphNodeId, Hash256, LocatedEntry,
    OperationId, Relation, RelationDelta, RelationOrigin, RepoPath, SourceRegion, TransactionDelta,
    TreeDelta, TreeEntry,
};
use sha2::{Digest, Sha256};

use crate::local_repository_authority::LocalRepositoryAuthorityContext;
use crate::repository_commit::{
    commit_native_plan_with_projection, load_native_commit_base, load_native_source_blob,
    plan_native_commit_from_base, recover_native_commit, NativeCommitBase, NativeCommitResult,
};
use crate::state::DaemonState;

struct ExactMcpPlan {
    native: crate::repository_commit::NativeCommitPlan,
    layouts: Vec<FileLayout>,
}

fn authority_context(state: &DaemonState) -> Result<LocalRepositoryAuthorityContext, String> {
    LocalRepositoryAuthorityContext::from_state(state)
        .map_err(|error| format!("open startup-pinned repository authority: {error}"))
}

/// Commit one daemon-owned MCP transaction through exact repository authority.
///
/// The caller holds `DaemonState::coordination_gate` and the graph-authority
/// mutation guard for the complete call.
pub(crate) fn commit_exact_transaction(
    state: &Arc<DaemonState>,
    sessions: &kin_mcp::SessionRegistry,
    arguments: &HashMap<String, serde_json::Value>,
    coordination: Option<&kin_mcp::CoordinationWritePreflight>,
) -> kin_mcp::ToolCallResult {
    match commit_exact_transaction_inner(state, sessions, arguments, coordination) {
        Ok(result) => result,
        Err(error) => kin_mcp::ToolCallResult::error(error),
    }
}

fn commit_exact_transaction_inner(
    state: &Arc<DaemonState>,
    sessions: &kin_mcp::SessionRegistry,
    arguments: &HashMap<String, serde_json::Value>,
    coordination: Option<&kin_mcp::CoordinationWritePreflight>,
) -> Result<kin_mcp::ToolCallResult, String> {
    if state.storage_backend.is_some() {
        return Err(
            "exact MCP repository commits are not yet available for hosted snapshot backends"
                .to_string(),
        );
    }
    let transaction_id = arguments
        .get("transaction_id")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| "missing required parameter: transaction_id".to_string())?
        .to_string();

    if let Some(inline) = arguments.get("operations") {
        let operations: Vec<kin_mcp::McpMutationOperation> = serde_json::from_value(inline.clone())
            .map_err(|error| format!("invalid operations array: {error}"))?;
        kin_mcp::session::validate_staged_operations(&operations)?;
        sessions
            .stage_transaction(&transaction_id, operations)
            .map_err(|error| format!("cannot stage inline transaction operations: {error}"))?;
    }

    let mut transaction = sessions
        .get_transaction(&transaction_id)
        .ok_or_else(|| format!("Transaction not found: {transaction_id}"))?;
    if !matches!(
        transaction.state.as_str(),
        "active" | "validated" | "committing" | "committed"
    ) {
        return Err(format!(
            "Cannot commit transaction {} in state: {}",
            transaction_id, transaction.state
        ));
    }
    let rejected = kin_mcp::session::uncommittable_operations(&transaction.staged_operations);
    if !rejected.is_empty() {
        return Err(format!(
            "Cannot commit transaction {}: {} staged operation(s) are not committable:\n  - {}",
            transaction_id,
            rejected.len(),
            rejected.join("\n  - ")
        ));
    }
    if transaction.staged_operations.is_empty() {
        return Err(format!(
            "Cannot commit transaction {transaction_id}: exact repository commits reject empty transactions"
        ));
    }

    let operation_uuid = uuid::Uuid::parse_str(&transaction_id).map_err(|error| {
        format!(
            "transaction id {transaction_id} is not a stable repository operation UUID: {error}"
        )
    })?;
    let operation_id = OperationId::from_uuid(operation_uuid);
    let payload_hash = transaction_payload_hash(&transaction)?;
    let authority_context = authority_context(state)?;

    // A non-terminal committing marker means authority may already have moved.
    // Recover by the caller-stable operation ID before attempting any new plan.
    if matches!(transaction.state.as_str(), "committing" | "committed") {
        if transaction.commit_payload_hash.as_deref() != Some(payload_hash.as_str()) {
            return Err(format!(
                "Cannot recover transaction {transaction_id}: staged payload does not match its durable committing fence"
            ));
        }
        if let Some(recovered) = recover_native_commit(&authority_context, operation_id)
            .map_err(|error| format!("recover exact MCP repository receipt: {error}"))?
        {
            return finalize_committed_transaction(
                state,
                sessions,
                transaction,
                recovered,
                Vec::new(),
                coordination,
            );
        }
        if transaction.state == "committed" {
            return Err(format!(
                "transaction {transaction_id} is terminal but repository authority has no matching receipt"
            ));
        }

        // Repository-v6 publishes the receipt in the same atomic successor as
        // authority. Its absence proves the fenced attempt did not move
        // authority (it may only have copied immutable CAS bodies), so this
        // attempt can be safely reset and replanned against current roots.
        transaction = sessions
            .reset_transaction_commit(&transaction_id)
            .map_err(|error| format!("reset receipt-less committing fence: {error}"))?;
        persist_registry_checked(state, sessions)
            .map_err(|error| format!("persist receipt-less committing reset: {error}"))?;
    }

    let base = load_native_commit_base(&authority_context)
        .map_err(|error| format!("load exact MCP commit base: {error}"))?;
    require_live_graph_matches_authority(state.graph.as_ref(), &base.graph)?;
    let plan =
        plan_exact_transaction(state, &authority_context, &transaction, operation_id, &base)?;

    // Publication fence: from this point until receipt recovery or an explicit
    // reset, the staged operation set is immutable and durable.
    sessions
        .prepare_transaction_commit(&transaction_id, &payload_hash)
        .map_err(|error| format!("prepare exact MCP transaction: {error}"))?;
    if let Err(error) = persist_registry_checked(state, sessions) {
        let _ = sessions.reset_transaction_commit(&transaction_id);
        return Err(format!(
            "persist exact MCP committing fence before repository mutation: {error}"
        ));
    }

    let committed = match commit_native_plan_with_projection(
        &state.layout,
        state.blobs.as_ref(),
        &authority_context,
        plan.native,
    ) {
        Ok(committed) => committed,
        Err(commit_error) => match recover_native_commit(&authority_context, operation_id) {
            Ok(Some(recovered)) => recovered,
            Ok(None) => {
                sessions
                        .reset_transaction_commit(&transaction_id)
                        .map_err(|reset_error| {
                            format!(
                                "repository commit failed ({commit_error}); reset committing fence: {reset_error}"
                            )
                        })?;
                persist_registry_checked(state, sessions).map_err(|persist_error| {
                        format!(
                            "repository commit failed ({commit_error}); persist reset transaction: {persist_error}"
                        )
                    })?;
                return Err(format!(
                    "exact MCP repository commit failed before authority moved: {commit_error}"
                ));
            }
            Err(recovery_error) => {
                return Err(format!(
                        "exact MCP repository commit returned {commit_error}; receipt recovery also failed: {recovery_error}"
                    ));
            }
        },
    };

    #[cfg(test)]
    if state
        .mcp_fail_after_authority_once
        .swap(false, Ordering::SeqCst)
    {
        return Err(format!(
            "injected crash boundary after repository receipt for transaction {transaction_id}"
        ));
    }

    finalize_committed_transaction(
        state,
        sessions,
        transaction,
        committed,
        plan.layouts,
        coordination,
    )
}

fn transaction_payload_hash(transaction: &kin_mcp::McpTransaction) -> Result<String, String> {
    let value = serde_json::to_value(serde_json::json!({
        "transaction_id": transaction.transaction_id,
        "session_id": transaction.session_id,
        "scope": transaction.scope,
        "operations": transaction.staged_operations,
    }))
    .map_err(|error| format!("serialize exact transaction payload: {error}"))?;
    let mut hasher = Sha256::new();
    hasher.update(b"kin-exact-mcp-transaction-v1\0");
    hash_canonical_json(&mut hasher, &value);
    Ok(hex::encode(hasher.finalize()))
}

fn hash_canonical_json(hasher: &mut Sha256, value: &serde_json::Value) {
    match value {
        serde_json::Value::Null => hasher.update([0]),
        serde_json::Value::Bool(value) => hasher.update([1, u8::from(*value)]),
        serde_json::Value::Number(value) => {
            hasher.update([2]);
            hash_bytes(hasher, value.to_string().as_bytes());
        }
        serde_json::Value::String(value) => {
            hasher.update([3]);
            hash_bytes(hasher, value.as_bytes());
        }
        serde_json::Value::Array(values) => {
            hasher.update([4]);
            hasher.update((values.len() as u64).to_le_bytes());
            for value in values {
                hash_canonical_json(hasher, value);
            }
        }
        serde_json::Value::Object(values) => {
            hasher.update([5]);
            hasher.update((values.len() as u64).to_le_bytes());
            let mut keys = values.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            for key in keys {
                hash_bytes(hasher, key.as_bytes());
                hash_canonical_json(hasher, &values[key]);
            }
        }
    }
}

fn hash_bytes(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn persist_registry_checked(
    state: &DaemonState,
    sessions: &kin_mcp::SessionRegistry,
) -> Result<(), String> {
    let mut store = state
        .mcp_transactions
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    for transaction in sessions.list_transactions() {
        store.insert(transaction.transaction_id.clone(), transaction);
    }
    crate::state::write_persisted_mcp_transactions_checked(&state.layout, &store)
        .map_err(|error| error.to_string())
}

fn require_live_graph_matches_authority(
    live: &kin_db::InMemoryGraph,
    authority: &kin_db::InMemoryGraph,
) -> Result<(), String> {
    if semantic_workspace_matches(live, authority) {
        return Ok(());
    }
    Err(
        "daemon query graph does not match the clean repository workspace authority; refusing to absorb an unrelated dirty overlay into the MCP commit"
            .to_string(),
    )
}

fn semantic_workspace_matches(left: &kin_db::InMemoryGraph, right: &kin_db::InMemoryGraph) -> bool {
    let left = left.to_snapshot();
    let right = right.to_snapshot();
    left.entities == right.entities
        && left.relations == right.relations
        && left.resolved_tree == right.resolved_tree
}

fn plan_exact_transaction(
    state: &DaemonState,
    authority_context: &LocalRepositoryAuthorityContext,
    transaction: &kin_mcp::McpTransaction,
    operation_id: OperationId,
    base: &NativeCommitBase,
) -> Result<ExactMcpPlan, String> {
    let prospective = kin_db::InMemoryGraph::from_snapshot(base.graph.to_snapshot())
        .map_err(|error| format!("create prospective exact graph: {error}"))?;
    let mut edits: BTreeMap<String, (FilePathId, Vec<(Entity, Vec<u8>)>)> = BTreeMap::new();
    let mut relation_operations = Vec::new();
    let mut edited_entities = HashSet::new();

    for operation in &transaction.staged_operations {
        let verb = operation.verb.trim().to_ascii_lowercase();
        let payload = operation
            .payload
            .as_ref()
            .ok_or_else(|| format!("operation '{}' has no payload", operation.verb))?;
        match payload {
            kin_mcp::McpMutationPayload::Entity(payload_entity) => {
                if operation.target.trim() != payload_entity.id.to_string() {
                    return Err(format!(
                        "exact entity mutation target must be the repository entity ID {}; got {:?}",
                        payload_entity.id, operation.target
                    ));
                }
                if !matches!(verb.as_str(), "update" | "modify") {
                    return Err(format!(
                        "entity verb '{}' is not yet supported by exact MCP commits; create/insertion/delete operations fail before mutation",
                        operation.verb
                    ));
                }
                let body = operation.body.as_ref().ok_or_else(|| {
                    format!(
                        "source-bound entity {} requires an exact UTF-8 body; metadata-only source mutations are rejected",
                        payload_entity.id
                    )
                })?;
                if !edited_entities.insert(payload_entity.id) {
                    return Err(format!(
                        "entity {} is edited more than once in one transaction; overlapping source authority is ambiguous",
                        payload_entity.id
                    ));
                }
                let existing = base
                    .graph
                    .get_entity(&payload_entity.id)
                    .map_err(|error| format!("load exact entity {}: {error}", payload_entity.id))?
                    .ok_or_else(|| {
                        format!(
                            "entity {} is absent from repository authority; insertion is not supported",
                            payload_entity.id
                        )
                    })?;
                if payload_entity.name != existing.name || payload_entity.kind != existing.kind {
                    return Err(format!(
                        "exact body edits cannot rename or re-kind entity {}; staged {} {:?}, authority has {} {:?}",
                        existing.id,
                        payload_entity.name,
                        payload_entity.kind,
                        existing.name,
                        existing.kind
                    ));
                }
                if payload_entity
                    .file_origin
                    .as_ref()
                    .is_some_and(|origin| Some(origin) != existing.file_origin.as_ref())
                {
                    return Err(format!(
                        "staged file origin for entity {} does not match repository authority",
                        existing.id
                    ));
                }
                if payload_entity
                    .span
                    .as_ref()
                    .is_some_and(|span| Some(span) != existing.span.as_ref())
                {
                    return Err(format!(
                        "staged source span for entity {} does not match repository authority",
                        existing.id
                    ));
                }
                let file_id = existing.file_origin.clone().ok_or_else(|| {
                    format!(
                        "entity {} has no exact source origin; graph-only entity mutation is not supported",
                        existing.id
                    )
                })?;
                let span = existing.span.as_ref().ok_or_else(|| {
                    format!(
                        "entity {} has no exact source span; mutation requires a full body and authoritative span",
                        existing.id
                    )
                })?;
                if span.file != file_id {
                    return Err(format!(
                        "entity {} source span file {} disagrees with origin {}",
                        existing.id, span.file, file_id
                    ));
                }
                if span.start_byte >= span.end_byte {
                    return Err(format!(
                        "entity {} has an empty or inverted exact source span {}..{}",
                        existing.id, span.start_byte, span.end_byte
                    ));
                }
                let path = RepoPath::from_utf8(file_id.0.clone()).map_err(|error| {
                    format!("invalid entity repository path {file_id}: {error}")
                })?;
                let artifact = base.tree.artifact_at_path(&path).ok_or_else(|| {
                    format!(
                        "entity {} source {} is absent from exact workspace tree",
                        existing.id, file_id
                    )
                })?;
                if !matches!(artifact.entry, TreeEntry::Blob { .. }) {
                    return Err(format!(
                        "entity {} source {} is not a regular blob entry",
                        existing.id, file_id
                    ));
                }
                edits
                    .entry(file_id.0.clone())
                    .or_insert_with(|| (file_id, Vec::new()))
                    .1
                    .push((existing, body.as_bytes().to_vec()));
            }
            kin_mcp::McpMutationPayload::Relation { .. } => {
                relation_operations.push((verb, payload.clone()));
            }
            kin_mcp::McpMutationPayload::Blob(_) => {
                return Err("blob payloads are not supported by exact MCP transactions".to_string());
            }
        }
    }

    let mut layouts = Vec::new();
    let pipeline = kin_index::IndexPipeline::new();
    for (_, (file_id, file_edits)) in edits {
        let path = RepoPath::from_utf8(file_id.0.clone())
            .map_err(|error| format!("invalid exact source path {file_id}: {error}"))?;
        let artifact = prospective
            .resolved_tree()
            .artifact_at_path(&path)
            .cloned()
            .ok_or_else(|| {
                format!("exact source artifact disappeared during planning: {file_id}")
            })?;
        let (old_hash, executable) = match artifact.entry {
            TreeEntry::Blob { hash, executable } => (hash, executable),
            TreeEntry::Symlink { .. } => {
                return Err(format!(
                    "exact source entity {} resolves through a symlink",
                    file_id
                ))
            }
            TreeEntry::Gitlink { .. } => {
                return Err(format!(
                    "exact source entity {} resolves through a gitlink",
                    file_id
                ))
            }
        };
        let original = load_native_source_blob(authority_context, old_hash)
            .map_err(|error| format!("load exact source body for {file_id}: {error}"))?;
        std::str::from_utf8(&original).map_err(|error| {
            format!(
                "entity source {} is not valid UTF-8 at byte {}; exact body splicing is unavailable",
                file_id,
                error.valid_up_to()
            )
        })?;
        let splices = file_edits
            .iter()
            .map(|(entity, body)| {
                let span = entity
                    .span
                    .as_ref()
                    .expect("validated source edit always has a span");
                kin_projection::Splice {
                    byte_range: span.start_byte..span.end_byte,
                    new_content: body.clone(),
                }
            })
            .collect();
        let projected = kin_projection::apply_splices(&original, splices)
            .map_err(|error| format!("splice exact source {file_id}: {error}"))?;
        if projected == original {
            return Err(format!(
                "exact body edit for {file_id} is a no-op; no repository commit was created"
            ));
        }
        let digest = state
            .blobs
            .write(&projected)
            .map_err(|error| format!("store projected source {file_id}: {error}"))?;
        let new_hash = Hash256::from_bytes(digest.0);
        prospective
            .apply_transaction_delta(&TransactionDelta {
                tree_deltas: vec![TreeDelta::Updated {
                    artifact_id: artifact.artifact_id,
                    old: artifact.located_entry(),
                    new: LocatedEntry::new(path, TreeEntry::blob(new_hash, executable)),
                }],
                ..TransactionDelta::default()
            })
            .map_err(|error| format!("install prospective exact tree for {file_id}: {error}"))?;

        let indexed = pipeline
            .index_any_content(&file_id, &projected, digest)
            .map_err(|error| format!("reparse projected exact source {file_id}: {error}"))?;
        let kin_index::IndexedAny::EntitySource(indexed) = indexed else {
            return Err(format!(
                "projected entity source {file_id} no longer classifies as supported source; commit rejected"
            ));
        };
        let mut reconciler = kin_reconcile::Reconciler::new(PathBuf::new());
        let reconcile = reconciler
            .reconcile_indexed_content(&indexed, state.blobs.as_ref(), &prospective)
            .map_err(|error| format!("derive exact semantics for {file_id}: {error}"))?;
        if let Some(delta) = reconcile.delta.entity_deltas.iter().find(|delta| {
            matches!(
                delta,
                EntityDelta::Added { .. } | EntityDelta::Removed { .. }
            )
        }) {
            return Err(format!(
                "body edit for {file_id} would create or remove source entities ({delta:?}); insertion/deletion is not yet supported"
            ));
        }
        prospective
            .apply_transaction_delta(&reconcile.delta)
            .map_err(|error| format!("apply reparsed exact semantics for {file_id}: {error}"))?;
        for (entity, _) in &file_edits {
            let parsed = prospective
                .get_entity(&entity.id)
                .map_err(|error| format!("load reparsed entity {}: {error}", entity.id))?
                .ok_or_else(|| {
                    format!(
                        "reparsed exact bytes did not preserve existing entity {}",
                        entity.id
                    )
                })?;
            if parsed.name != entity.name || parsed.kind != entity.kind {
                return Err(format!(
                    "reparsed exact bytes changed entity {} identity; rename/re-kind is unsupported",
                    entity.id
                ));
            }
        }
        let layout = reconciler
            .projection()
            .get_layout(&file_id)
            .cloned()
            .ok_or_else(|| format!("reparse produced no exact file layout for {file_id}"))?;
        prospective
            .upsert_file_layout(&layout)
            .map_err(|error| format!("install prospective layout for {file_id}: {error}"))?;
        layouts.push(layout);
    }

    apply_relation_operations(&prospective, relation_operations)?;
    if semantic_workspace_matches(&prospective, &base.graph) {
        return Err(
            "exact MCP transaction produced no semantic, relation, or tree change".to_string(),
        );
    }

    let message = format!("MCP transaction {}", transaction.transaction_id);
    let native = plan_native_commit_from_base(
        &prospective,
        state.blobs.as_ref(),
        authority_context,
        operation_id,
        kin_model::Timestamp::now(),
        kin_model::AuthorId::new(format!("mcp:{}", transaction.session_id)),
        message,
        base,
    )
    .map_err(|error| format!("plan exact MCP repository commit: {error}"))?;
    Ok(ExactMcpPlan { native, layouts })
}

fn apply_relation_operations(
    prospective: &kin_db::InMemoryGraph,
    operations: Vec<(String, kin_mcp::McpMutationPayload)>,
) -> Result<(), String> {
    for (verb, payload) in operations {
        let kin_mcp::McpMutationPayload::Relation { from, to, kind } = payload else {
            return Err("internal exact relation planner received a non-relation payload".into());
        };
        for endpoint in [from, to] {
            if prospective
                .get_entity(&endpoint)
                .map_err(|error| format!("load relation endpoint {endpoint}: {error}"))?
                .is_none()
            {
                return Err(format!(
                    "relation endpoint {endpoint} is absent from prospective repository authority"
                ));
            }
        }
        let mut matching = prospective
            .get_all_relations_for_entity(&from)
            .map_err(|error| format!("load existing relations for {from}: {error}"))?
            .into_iter()
            .filter(|relation| {
                relation.kind == kind
                    && relation.src == GraphNodeId::Entity(from)
                    && relation.dst == GraphNodeId::Entity(to)
            })
            .collect::<Vec<_>>();
        matching.sort_by_key(|relation| relation.id);

        let delta = match verb.as_str() {
            "create" | "add" | "insert" => {
                if !matching.is_empty() {
                    return Err(format!(
                        "relation {:?} from {} to {} already exists; use upsert or remove the duplicate operation",
                        kind, from, to
                    ));
                }
                TransactionDelta {
                    relation_deltas: vec![RelationDelta::Added {
                        new: Relation {
                            id: kin_model::RelationId::new(),
                            kind,
                            src: GraphNodeId::Entity(from),
                            dst: GraphNodeId::Entity(to),
                            confidence: 1.0,
                            origin: RelationOrigin::Manual,
                            created_in: None,
                            import_source: None,
                            evidence: Vec::new(),
                        },
                    }],
                    ..TransactionDelta::default()
                }
            }
            "upsert" if matching.is_empty() => TransactionDelta {
                relation_deltas: vec![RelationDelta::Added {
                    new: Relation {
                        id: kin_model::RelationId::new(),
                        kind,
                        src: GraphNodeId::Entity(from),
                        dst: GraphNodeId::Entity(to),
                        confidence: 1.0,
                        origin: RelationOrigin::Manual,
                        created_in: None,
                        import_source: None,
                        evidence: Vec::new(),
                    },
                }],
                ..TransactionDelta::default()
            },
            "upsert" => continue,
            "delete" | "remove" => {
                let [old] = matching.as_slice() else {
                    return Err(if matching.is_empty() {
                        format!(
                            "relation {:?} from {} to {} does not exist in repository authority",
                            kind, from, to
                        )
                    } else {
                        format!(
                            "relation {:?} from {} to {} is ambiguous across {} matching edges",
                            kind,
                            from,
                            to,
                            matching.len()
                        )
                    });
                };
                TransactionDelta {
                    relation_deltas: vec![RelationDelta::Removed { old: old.clone() }],
                    ..TransactionDelta::default()
                }
            }
            _ => {
                return Err(format!(
                    "relation verb '{verb}' is not supported by exact MCP commits"
                ))
            }
        };
        prospective
            .apply_transaction_delta(&delta)
            .map_err(|error| format!("apply prospective relation operation: {error}"))?;
    }
    Ok(())
}

fn finalize_committed_transaction(
    state: &Arc<DaemonState>,
    sessions: &kin_mcp::SessionRegistry,
    transaction: kin_mcp::McpTransaction,
    committed: NativeCommitResult,
    planned_layouts: Vec<FileLayout>,
    coordination: Option<&kin_mcp::CoordinationWritePreflight>,
) -> Result<kin_mcp::ToolCallResult, String> {
    let authority_context = authority_context(state)?;
    let authority = load_native_commit_base(&authority_context)
        .map_err(|error| format!("reload committed MCP repository authority: {error}"))?;
    if authority.roots != committed.receipt.roots_after {
        return Err(format!(
            "repository authority advanced beyond MCP receipt generation {}; reopen the daemon before finalizing transaction {}",
            committed.receipt.generation, transaction.transaction_id
        ));
    }

    install_authority_graph(state.graph.as_ref(), &authority.graph, &committed)?;
    let layouts = if planned_layouts.is_empty() && committed.file_count > 0 {
        rebuild_changed_layouts(state, &authority, &committed.change)?
    } else {
        planned_layouts
    };
    for layout in layouts {
        state.graph.upsert_file_layout(&layout).map_err(|error| {
            format!("install committed exact layout {}: {error}", layout.file_id)
        })?;
    }
    if !semantic_workspace_matches(state.graph.as_ref(), &authority.graph) {
        return Err(format!(
            "derived daemon graph does not match repository authority after transaction {}",
            transaction.transaction_id
        ));
    }

    let observed_generation = state.snapshot_generation.load(Ordering::SeqCst);
    if observed_generation < committed.receipt.generation {
        state
            .record_repository_authority_commit(committed.receipt.generation)
            .map_err(|error| format!("record committed repository generation: {error}"))?;
    } else if observed_generation > committed.receipt.generation {
        return Err(format!(
            "daemon generation {observed_generation} is ahead of recovered MCP receipt {}; reopen before terminalizing",
            committed.receipt.generation
        ));
    }

    let terminal = if transaction.state == "committed" {
        transaction
    } else {
        sessions
            .commit_transaction(&transaction.transaction_id)
            .map_err(|error| format!("terminalize exact MCP transaction: {error}"))?
    };
    let modified_files = changed_file_ids(&committed.change)?;
    let root_hash = hex::encode(state.graph.compute_root_hash());
    let result = serde_json::json!({
        "transaction_id": terminal.transaction_id,
        "state": "committed",
        "status": "committed",
        "ops_applied": terminal.staged_operations.len(),
        "entity_deltas": committed.entity_count,
        "relation_deltas": committed.relation_count,
        "empty": false,
        "change_id": committed.change.id.to_string(),
        "repository_generation": committed.receipt.generation,
        "repository_operation_id": committed.receipt.operation_id.to_string(),
        "new_root_hash": root_hash,
        "modified_files": modified_files.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "collision_warnings": [],
        "conflicts": [],
        "semantic_authority": "reparsed_exact_repository_bytes",
        "coordination": coordination,
    });
    let json = serde_json::to_string_pretty(&result)
        .map_err(|error| format!("serialize exact MCP commit response: {error}"))?;
    Ok(kin_mcp::ToolCallResult::text(json))
}

fn install_authority_graph(
    live: &kin_db::InMemoryGraph,
    authority: &kin_db::InMemoryGraph,
    committed: &NativeCommitResult,
) -> Result<(), String> {
    live.create_changes(vec![committed.change.clone()])
        .map_err(|error| format!("install committed semantic change: {error}"))?;
    if semantic_workspace_matches(live, authority) {
        return Ok(());
    }
    let correction = transaction_delta_between(live, authority)?;
    live.apply_transaction_delta(&correction)
        .map_err(|error| format!("install committed authority delta into derived graph: {error}"))
}

fn transaction_delta_between(
    current: &kin_db::InMemoryGraph,
    desired: &kin_db::InMemoryGraph,
) -> Result<TransactionDelta, String> {
    let current = current.to_snapshot();
    let desired = desired.to_snapshot();
    let mut entity_deltas = Vec::new();
    for (id, entity) in &desired.entities {
        match current.entities.get(id) {
            None => entity_deltas.push(EntityDelta::Added {
                new: entity.clone(),
            }),
            Some(old) if old != entity => entity_deltas.push(EntityDelta::Modified {
                old: old.clone(),
                new: entity.clone(),
            }),
            Some(_) => {}
        }
    }
    for (id, entity) in &current.entities {
        if !desired.entities.contains_key(id) {
            entity_deltas.push(EntityDelta::Removed {
                old: entity.clone(),
            });
        }
    }
    entity_deltas.sort_by_key(EntityDelta::target_id);

    let mut relation_deltas = Vec::new();
    for (id, relation) in &desired.relations {
        match current.relations.get(id) {
            None => relation_deltas.push(RelationDelta::Added {
                new: relation.clone(),
            }),
            Some(old) if old != relation => relation_deltas.push(RelationDelta::Modified {
                old: old.clone(),
                new: relation.clone(),
            }),
            Some(_) => {}
        }
    }
    for (id, relation) in &current.relations {
        if !desired.relations.contains_key(id) {
            relation_deltas.push(RelationDelta::Removed {
                old: relation.clone(),
            });
        }
    }
    relation_deltas.sort_by_key(RelationDelta::target_id);
    let tree_deltas =
        kin_core::exact_tree_correction(&current.resolved_tree, &desired.resolved_tree).map_err(
            |error| format!("derive exact tree correction from committed authority: {error}"),
        )?;
    Ok(TransactionDelta {
        entity_deltas,
        relation_deltas,
        tree_deltas,
        admission_policy_delta: None,
    })
}

fn changed_file_ids(change: &kin_model::SemanticChange) -> Result<Vec<FilePathId>, String> {
    let mut files = change
        .tree_deltas
        .iter()
        .filter_map(|delta| delta.new_state().map(|located| located.path.clone()))
        .map(|path| {
            path.as_utf8()
                .map(|path| FilePathId::new(path.to_string()))
                .ok_or_else(|| {
                    format!(
                        "MCP source change contains non-UTF-8 path {}; source entity paths must be UTF-8",
                        path
                    )
                })
        })
        .collect::<Result<Vec<_>, _>>()?;
    files.sort_by(|left, right| left.0.cmp(&right.0));
    files.dedup();
    Ok(files)
}

fn rebuild_changed_layouts(
    state: &DaemonState,
    authority: &NativeCommitBase,
    change: &kin_model::SemanticChange,
) -> Result<Vec<FileLayout>, String> {
    let authority_context = authority_context(state)?;
    let pipeline = kin_index::IndexPipeline::new();
    let mut layouts = Vec::new();
    for file_id in changed_file_ids(change)? {
        let path = RepoPath::from_utf8(file_id.0.clone())
            .map_err(|error| format!("invalid recovered source path {file_id}: {error}"))?;
        let artifact = authority
            .tree
            .artifact_at_path(&path)
            .ok_or_else(|| format!("recovered authority has no changed artifact {file_id}"))?;
        let hash = artifact.entry.blob_identity().ok_or_else(|| {
            format!("recovered changed artifact {file_id} is an unmaterializable gitlink")
        })?;
        let body = load_native_source_blob(&authority_context, hash)
            .map_err(|error| format!("load recovered exact body for {file_id}: {error}"))?;
        let indexed = pipeline
            .index_any_content(
                &file_id,
                &body,
                kin_blobs::Hash256::from_bytes(*hash.as_bytes()),
            )
            .map_err(|error| format!("reindex recovered exact body for {file_id}: {error}"))?;
        let kin_index::IndexedAny::EntitySource(indexed) = indexed else {
            continue;
        };
        let mut layout = indexed.file_layout;
        stabilize_layout_ids(&mut layout, &indexed.entities, &authority.graph)?;
        layouts.push(layout);
    }
    Ok(layouts)
}

fn stabilize_layout_ids(
    layout: &mut FileLayout,
    parsed_entities: &[Entity],
    authority: &kin_db::InMemoryGraph,
) -> Result<(), String> {
    let layout_file_id = layout.file_id.clone();
    let authority_entities = authority
        .query_entities(&kin_model::EntityFilter {
            file_path: Some(layout_file_id.clone()),
            ..kin_model::EntityFilter::default()
        })
        .map_err(|error| format!("load authority entities for {}: {error}", layout_file_id))?;
    for region in &mut layout.regions {
        let SourceRegion::EntityRef { entity_id, .. } = region else {
            continue;
        };
        let parsed = parsed_entities
            .iter()
            .find(|entity| entity.id == *entity_id)
            .ok_or_else(|| {
                format!(
                    "layout {} references parser entity {} that was not returned",
                    layout_file_id, entity_id
                )
            })?;
        let mut matches = authority_entities
            .iter()
            .filter(|entity| entity.name == parsed.name && entity.kind == parsed.kind);
        let stable = matches.next().ok_or_else(|| {
            format!(
                "recovered layout entity {} {:?} has no authority identity in {}",
                parsed.name, parsed.kind, layout_file_id
            )
        })?;
        if matches.next().is_some() {
            return Err(format!(
                "recovered layout entity {} {:?} is ambiguous in {}",
                parsed.name, parsed.kind, layout_file_id
            ));
        }
        *entity_id = stable.id;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;
    use std::process::Command;
    use std::sync::OnceLock;

    use kin_model::{AuthorId, EntityFilter, LocatedEntry, SemanticChangeId, Timestamp, TreeDelta};

    fn install_test_registry_override() {
        static REGISTRY_PATH: OnceLock<PathBuf> = OnceLock::new();
        let _guard = crate::test_env_lock();
        let path = REGISTRY_PATH.get_or_init(|| {
            let root = std::env::temp_dir().join(format!(
                "kin-daemon-exact-mcp-registry-{}",
                uuid::Uuid::new_v4()
            ));
            std::fs::create_dir_all(&root).unwrap();
            let path = root.join("registry.toml");
            kin_core::registry::KinRegistry { repos: Vec::new() }
                .save_to(&path)
                .unwrap();
            path
        });
        std::env::set_var("KIN_REGISTRY_PATH", path);
    }

    fn test_state() -> (tempfile::TempDir, Arc<DaemonState>) {
        install_test_registry_override();
        let dir = tempfile::tempdir().unwrap();
        let layout = kin_core::init(dir.path()).unwrap().layout;
        let state = Arc::new(DaemonState::open(layout).unwrap());
        (dir, state)
    }

    fn test_authority_context(layout: &kin_core::KinLayout) -> LocalRepositoryAuthorityContext {
        LocalRepositoryAuthorityContext::from_layout_for_test(layout).unwrap()
    }

    fn load_native_commit_base(
        layout: &kin_core::KinLayout,
    ) -> crate::error::Result<NativeCommitBase> {
        crate::repository_commit::load_native_commit_base(&test_authority_context(layout))
    }

    fn load_native_source_blob(
        layout: &kin_core::KinLayout,
        hash: Hash256,
    ) -> crate::error::Result<Vec<u8>> {
        crate::repository_commit::load_native_source_blob(&test_authority_context(layout), hash)
    }

    fn commit_native_plan_with_projection(
        layout: &kin_core::KinLayout,
        blobs: &kin_blobs::BlobStore,
        plan: crate::repository_commit::NativeCommitPlan,
    ) -> crate::error::Result<NativeCommitResult> {
        crate::repository_commit::commit_native_plan_with_projection(
            layout,
            blobs,
            &test_authority_context(layout),
            plan,
        )
    }

    fn git(repo: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .current_dir(repo)
            .args(args)
            .output()
            .unwrap_or_else(|error| panic!("run git {args:?}: {error}"));
        assert!(
            output.status.success(),
            "git {args:?} failed\nstdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap().trim().to_string()
    }

    fn install_exact_source(
        state: &Arc<DaemonState>,
        file: &str,
        content: &[u8],
        entity_name: &str,
    ) -> (Entity, SemanticChangeId) {
        let file_id = FilePathId::new(file);
        let blob_hash = state.blobs.write(content).unwrap();
        let source_hash = Hash256::from_bytes(blob_hash.0);
        let path = RepoPath::from_utf8(file).unwrap();
        state
            .graph
            .apply_transaction_delta(&TransactionDelta {
                tree_deltas: vec![TreeDelta::Added {
                    artifact_id: kin_model::ArtifactId::new(),
                    new: LocatedEntry::new(path, TreeEntry::blob(source_hash, false)),
                }],
                ..TransactionDelta::default()
            })
            .unwrap();

        let indexed = kin_index::IndexPipeline::new()
            .index_any_content(&file_id, content, blob_hash)
            .unwrap();
        let kin_index::IndexedAny::EntitySource(indexed) = indexed else {
            panic!("{file} must classify as supported source");
        };
        let mut reconciler = kin_reconcile::Reconciler::new(PathBuf::new());
        let reconciled = reconciler
            .reconcile_indexed_content(&indexed, state.blobs.as_ref(), state.graph.as_ref())
            .unwrap();
        state
            .graph
            .apply_transaction_delta(&reconciled.delta)
            .unwrap();
        let layout = reconciler
            .projection()
            .get_layout(&file_id)
            .cloned()
            .expect("source reconcile must produce an exact layout");
        state.graph.upsert_file_layout(&layout).unwrap();
        let entity = state
            .graph
            .query_entities(&EntityFilter {
                name_pattern: Some(entity_name.to_string()),
                file_path: Some(file_id),
                ..EntityFilter::default()
            })
            .unwrap()
            .into_iter()
            .find(|entity| entity.name == entity_name)
            .expect("source fixture must contain requested entity");

        let plan = crate::repository_commit::plan_native_commit(
            state.graph.as_ref(),
            state.blobs.as_ref(),
            &authority_context(state).unwrap(),
            OperationId::new(),
            Timestamp::now(),
            AuthorId::new("exact-mcp-test"),
            format!("install exact source {file}"),
        )
        .unwrap();
        let committed =
            commit_native_plan_with_projection(&state.layout, state.blobs.as_ref(), plan).unwrap();
        state
            .graph
            .create_changes(vec![committed.change.clone()])
            .unwrap();
        state
            .record_repository_authority_commit(committed.receipt.generation)
            .unwrap();
        (entity, committed.change.id)
    }

    fn commit_live_graph(
        state: &Arc<DaemonState>,
        message: &str,
        project_tree: bool,
    ) -> NativeCommitResult {
        let plan = crate::repository_commit::plan_native_commit(
            state.graph.as_ref(),
            state.blobs.as_ref(),
            &authority_context(state).unwrap(),
            OperationId::new(),
            Timestamp::now(),
            AuthorId::new("exact-mcp-test"),
            message.to_string(),
        )
        .unwrap();
        let committed = if project_tree {
            commit_native_plan_with_projection(&state.layout, state.blobs.as_ref(), plan).unwrap()
        } else {
            crate::repository_commit::commit_native_plan(
                state.blobs.as_ref(),
                &authority_context(state).unwrap(),
                plan,
            )
            .unwrap()
        };
        state
            .graph
            .create_changes(vec![committed.change.clone()])
            .unwrap();
        state
            .record_repository_authority_commit(committed.receipt.generation)
            .unwrap();
        committed
    }

    fn stage_entity_edit(
        sessions: &kin_mcp::SessionRegistry,
        entity: &Entity,
        body: &str,
    ) -> (String, HashMap<String, serde_json::Value>) {
        let transaction = sessions
            .begin_transaction("exact-mcp-test", "file:src/lib.rs")
            .unwrap();
        sessions
            .stage_transaction(
                &transaction.transaction_id,
                vec![kin_mcp::McpMutationOperation {
                    verb: "update".to_string(),
                    target: entity.id.to_string(),
                    payload: Some(kin_mcp::McpMutationPayload::Entity(entity.clone())),
                    body: Some(body.to_string()),
                    description: "replace exact entity body".to_string(),
                }],
            )
            .unwrap();
        let arguments = HashMap::from([(
            "transaction_id".to_string(),
            serde_json::json!(transaction.transaction_id),
        )]);
        (transaction.transaction_id, arguments)
    }

    fn result_text(result: &kin_mcp::ToolCallResult) -> &str {
        match result
            .content
            .first()
            .expect("tool result must have content")
        {
            kin_mcp::ContentBlock::Text { text } => text,
        }
    }

    #[test]
    fn transaction_fence_hash_is_independent_of_metadata_map_order() {
        let (_dir, state) = test_state();
        let (entity, _) = install_exact_source(
            &state,
            "src/lib.rs",
            b"pub fn value() -> u8 { 1 }\n",
            "value",
        );
        let mut left = entity.clone();
        left.metadata
            .extra
            .insert("z".to_string(), serde_json::json!(1));
        left.metadata
            .extra
            .insert("a".to_string(), serde_json::json!({"y": 2, "b": 3}));
        let mut right = entity.clone();
        right
            .metadata
            .extra
            .insert("a".to_string(), serde_json::json!({"b": 3, "y": 2}));
        right
            .metadata
            .extra
            .insert("z".to_string(), serde_json::json!(1));
        let transaction = |payload: Entity| kin_mcp::McpTransaction {
            transaction_id: uuid::Uuid::nil().to_string(),
            session_id: "session".to_string(),
            scope: "file:src/lib.rs".to_string(),
            state: "active".to_string(),
            staged_operations: vec![kin_mcp::McpMutationOperation {
                verb: "update".to_string(),
                target: entity.id.to_string(),
                payload: Some(kin_mcp::McpMutationPayload::Entity(payload)),
                body: Some("pub fn value() -> u8 { 2 }".to_string()),
                description: String::new(),
            }],
            commit_payload_hash: None,
        };
        assert_eq!(
            transaction_payload_hash(&transaction(left)).unwrap(),
            transaction_payload_hash(&transaction(right)).unwrap()
        );
    }

    #[test]
    fn source_body_commit_publishes_exact_bytes_and_reparsed_semantics() {
        let (_dir, state) = test_state();
        let initial = b"pub fn value() -> u8 { 1 }\n";
        let (entity, _) = install_exact_source(&state, "src/lib.rs", initial, "value");
        let before = load_native_commit_base(&state.layout).unwrap();
        let sessions = kin_mcp::SessionRegistry::new();
        let (transaction_id, arguments) =
            stage_entity_edit(&sessions, &entity, "pub fn value() -> u8 { 2 }");

        let result = commit_exact_transaction(&state, &sessions, &arguments, None);
        assert_ne!(
            result.is_error,
            Some(true),
            "exact source commit failed: {}",
            result_text(&result)
        );
        let response: serde_json::Value = serde_json::from_str(result_text(&result)).unwrap();
        assert_eq!(
            response["semantic_authority"],
            "reparsed_exact_repository_bytes"
        );
        assert_eq!(
            response["modified_files"],
            serde_json::json!(["src/lib.rs"])
        );
        assert_eq!(
            sessions.get_transaction(&transaction_id).unwrap().state,
            "committed"
        );

        let expected = b"pub fn value() -> u8 { 2 }\n";
        assert_eq!(
            std::fs::read(state.layout.working_dir().join("src/lib.rs")).unwrap(),
            expected
        );
        let after = load_native_commit_base(&state.layout).unwrap();
        assert!(after.roots.generation > before.roots.generation);
        let artifact = after
            .tree
            .artifact_at_path(&RepoPath::from_utf8("src/lib.rs").unwrap())
            .unwrap();
        let hash = artifact.entry.blob_identity().unwrap();
        assert_eq!(
            load_native_source_blob(&state.layout, hash).unwrap(),
            expected
        );
        assert!(semantic_workspace_matches(
            state.graph.as_ref(),
            &after.graph
        ));

        let reparsed = state.graph.get_entity(&entity.id).unwrap().unwrap();
        let authority_entity = after.graph.get_entity(&entity.id).unwrap().unwrap();
        assert_eq!(reparsed, authority_entity);
        assert_ne!(
            reparsed.fingerprint, entity.fingerprint,
            "semantic fingerprint must come from reparsing the exact new bytes"
        );
    }

    #[test]
    fn dirty_checkout_rejects_before_authority_and_preserves_local_bytes() {
        let (_dir, state) = test_state();
        let (entity, _) = install_exact_source(
            &state,
            "src/lib.rs",
            b"pub fn value() -> u8 { 1 }\n",
            "value",
        );
        let before = load_native_commit_base(&state.layout).unwrap();
        let live_before = state.graph.compute_root_hash();
        let dirty = b"pub fn value() -> u8 { 99 }\n";
        std::fs::write(state.layout.working_dir().join("src/lib.rs"), dirty).unwrap();

        let sessions = kin_mcp::SessionRegistry::new();
        let (transaction_id, arguments) =
            stage_entity_edit(&sessions, &entity, "pub fn value() -> u8 { 2 }");
        let result = commit_exact_transaction(&state, &sessions, &arguments, None);
        assert_eq!(result.is_error, Some(true));
        assert!(
            result_text(&result).contains("before authority moved"),
            "{}",
            result_text(&result)
        );
        assert_eq!(
            sessions.get_transaction(&transaction_id).unwrap().state,
            "active"
        );
        let after = load_native_commit_base(&state.layout).unwrap();
        assert_eq!(after.roots, before.roots);
        assert_eq!(state.graph.compute_root_hash(), live_before);
        assert_eq!(
            std::fs::read(state.layout.working_dir().join("src/lib.rs")).unwrap(),
            dirty,
            "failed exact commit must preserve the caller's unrelated local edit"
        );
    }

    #[test]
    fn unsupported_source_mutations_fail_before_repository_mutation() {
        let (_dir, state) = test_state();
        let (entity, _) = install_exact_source(
            &state,
            "src/lib.rs",
            b"pub fn value() -> u8 { 1 }\n",
            "value",
        );
        let before = load_native_commit_base(&state.layout).unwrap();

        let create_sessions = kin_mcp::SessionRegistry::new();
        let create = create_sessions
            .begin_transaction("exact-mcp-test", "file:src/lib.rs")
            .unwrap();
        let mut inserted = entity.clone();
        inserted.id = kin_model::EntityId::new();
        inserted.name = "inserted".to_string();
        create_sessions
            .stage_transaction(
                &create.transaction_id,
                vec![kin_mcp::McpMutationOperation {
                    verb: "create".to_string(),
                    target: inserted.id.to_string(),
                    payload: Some(kin_mcp::McpMutationPayload::Entity(inserted)),
                    body: Some("pub fn inserted() {}".to_string()),
                    description: String::new(),
                }],
            )
            .unwrap();
        let create_result = commit_exact_transaction(
            &state,
            &create_sessions,
            &HashMap::from([(
                "transaction_id".to_string(),
                serde_json::json!(create.transaction_id),
            )]),
            None,
        );
        assert_eq!(create_result.is_error, Some(true));
        assert!(result_text(&create_result).contains("insertion"));
        assert_eq!(
            create_sessions
                .get_transaction(&create.transaction_id)
                .unwrap()
                .state,
            "active"
        );

        let metadata_sessions = kin_mcp::SessionRegistry::new();
        let metadata = metadata_sessions
            .begin_transaction("exact-mcp-test", "file:src/lib.rs")
            .unwrap();
        metadata_sessions
            .stage_transaction(
                &metadata.transaction_id,
                vec![kin_mcp::McpMutationOperation {
                    verb: "update".to_string(),
                    target: entity.id.to_string(),
                    payload: Some(kin_mcp::McpMutationPayload::Entity(entity)),
                    body: None,
                    description: String::new(),
                }],
            )
            .unwrap();
        let metadata_result = commit_exact_transaction(
            &state,
            &metadata_sessions,
            &HashMap::from([(
                "transaction_id".to_string(),
                serde_json::json!(metadata.transaction_id),
            )]),
            None,
        );
        assert_eq!(metadata_result.is_error, Some(true));
        assert!(result_text(&metadata_result).contains("requires an exact UTF-8 body"));

        let after = load_native_commit_base(&state.layout).unwrap();
        assert_eq!(after.roots, before.roots);
    }

    #[test]
    fn non_utf8_source_and_overlapping_regions_fail_before_mutation() {
        let (_dir, state) = test_state();
        let (entity, _) = install_exact_source(
            &state,
            "src/lib.rs",
            b"pub fn value() -> u8 { 1 }\n",
            "value",
        );

        let mut shadow = entity.clone();
        shadow.id = kin_model::EntityId::new();
        shadow.name = "shadow".to_string();
        shadow.signature = "pub fn shadow() -> u8".to_string();
        state
            .graph
            .apply_transaction_delta(&TransactionDelta {
                entity_deltas: vec![EntityDelta::Added {
                    new: shadow.clone(),
                }],
                ..TransactionDelta::default()
            })
            .unwrap();
        commit_live_graph(&state, "install overlapping authority fixture", false);
        let overlap_before = load_native_commit_base(&state.layout).unwrap();

        let overlap_sessions = kin_mcp::SessionRegistry::new();
        let overlap_tx = overlap_sessions
            .begin_transaction("exact-mcp-test", "file:src/lib.rs")
            .unwrap();
        overlap_sessions
            .stage_transaction(
                &overlap_tx.transaction_id,
                vec![
                    kin_mcp::McpMutationOperation {
                        verb: "update".to_string(),
                        target: entity.id.to_string(),
                        payload: Some(kin_mcp::McpMutationPayload::Entity(entity.clone())),
                        body: Some("pub fn value() -> u8 { 2 }".to_string()),
                        description: String::new(),
                    },
                    kin_mcp::McpMutationOperation {
                        verb: "update".to_string(),
                        target: shadow.id.to_string(),
                        payload: Some(kin_mcp::McpMutationPayload::Entity(shadow.clone())),
                        body: Some("pub fn shadow() -> u8 { 3 }".to_string()),
                        description: String::new(),
                    },
                ],
            )
            .unwrap();
        let overlap_result = commit_exact_transaction(
            &state,
            &overlap_sessions,
            &HashMap::from([(
                "transaction_id".to_string(),
                serde_json::json!(overlap_tx.transaction_id),
            )]),
            None,
        );
        assert_eq!(overlap_result.is_error, Some(true));
        assert!(
            result_text(&overlap_result).contains("overlap"),
            "{}",
            result_text(&overlap_result)
        );
        assert_eq!(
            load_native_commit_base(&state.layout).unwrap().roots,
            overlap_before.roots
        );

        // Remove the intentionally ambiguous entity, then move the exact tree
        // to bytes that cannot be represented by an MCP UTF-8 entity body.
        state
            .graph
            .apply_transaction_delta(&TransactionDelta {
                entity_deltas: vec![EntityDelta::Removed { old: shadow }],
                ..TransactionDelta::default()
            })
            .unwrap();
        let artifact = state
            .graph
            .resolved_tree()
            .artifact_at_path(&RepoPath::from_utf8("src/lib.rs").unwrap())
            .cloned()
            .unwrap();
        let non_utf8 = [0xff, 0xfe, 0xfd];
        let digest = state.blobs.write(&non_utf8).unwrap();
        state
            .graph
            .apply_transaction_delta(&TransactionDelta {
                tree_deltas: vec![TreeDelta::Updated {
                    artifact_id: artifact.artifact_id,
                    old: artifact.located_entry(),
                    new: LocatedEntry::new(
                        RepoPath::from_utf8("src/lib.rs").unwrap(),
                        TreeEntry::blob(Hash256::from_bytes(digest.0), false),
                    ),
                }],
                ..TransactionDelta::default()
            })
            .unwrap();
        commit_live_graph(&state, "install non-UTF-8 exact source fixture", true);
        let non_utf8_before = load_native_commit_base(&state.layout).unwrap();

        let utf8_sessions = kin_mcp::SessionRegistry::new();
        let (_, utf8_arguments) =
            stage_entity_edit(&utf8_sessions, &entity, "pub fn value() -> u8 { 2 }");
        let utf8_result = commit_exact_transaction(&state, &utf8_sessions, &utf8_arguments, None);
        assert_eq!(utf8_result.is_error, Some(true));
        assert!(
            result_text(&utf8_result).contains("not valid UTF-8"),
            "{}",
            result_text(&utf8_result)
        );
        assert_eq!(
            load_native_commit_base(&state.layout).unwrap().roots,
            non_utf8_before.roots
        );
    }

    #[test]
    fn untouched_gitlink_does_not_block_an_unrelated_exact_source_commit() {
        install_test_registry_override();
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        git(repo, &["init", "--initial-branch=subtarget"]);
        git(repo, &["config", "user.email", "kin@example.invalid"]);
        git(repo, &["config", "user.name", "Kin"]);
        git(repo, &["config", "commit.gpgsign", "false"]);
        std::fs::write(repo.join(".subtarget"), b"subrepository target\n").unwrap();
        git(repo, &["add", ".subtarget"]);
        git(repo, &["commit", "-s", "-m", "subrepository target"]);
        let gitlink_target = git(repo, &["rev-parse", "HEAD"]);
        git(repo, &["switch", "--orphan", "main"]);
        if repo.join(".subtarget").exists() {
            std::fs::remove_file(repo.join(".subtarget")).unwrap();
        }
        std::fs::create_dir_all(repo.join("src")).unwrap();
        std::fs::create_dir_all(repo.join("modules/dependency")).unwrap();
        let initial = b"pub fn value() -> u8 { 1 }\n";
        std::fs::write(repo.join("src/lib.rs"), initial).unwrap();
        git(repo, &["add", "src/lib.rs"]);
        git(
            repo,
            &[
                "update-index",
                "--add",
                "--cacheinfo",
                &format!("160000,{gitlink_target},modules/dependency"),
            ],
        );
        git(repo, &["commit", "-s", "-m", "source with exact gitlink"]);

        let layout = kin_core::init_from_git(repo).unwrap().layout;
        let state = Arc::new(DaemonState::open(layout).unwrap());
        let file_id = FilePathId::new("src/lib.rs");
        let mut entities = state
            .graph
            .query_entities(&EntityFilter {
                name_pattern: Some("value".to_string()),
                file_path: Some(file_id.clone()),
                ..EntityFilter::default()
            })
            .unwrap();
        if entities.iter().all(|entity| entity.name != "value") {
            let blob_hash = state.blobs.write(initial).unwrap();
            let indexed = kin_index::IndexPipeline::new()
                .index_any_content(&file_id, initial, blob_hash)
                .unwrap();
            let kin_index::IndexedAny::EntitySource(indexed) = indexed else {
                panic!("Rust source fixture must produce semantic entities");
            };
            assert!(
                state
                    .graph
                    .resolved_tree()
                    .artifact_at_path(&RepoPath::from_utf8("src/lib.rs").unwrap())
                    .is_some(),
                "daemon query graph must begin from the imported exact workspace tree"
            );
            let layout = indexed.file_layout.clone();
            state
                .graph
                .apply_transaction_delta(&TransactionDelta {
                    entity_deltas: indexed
                        .entities
                        .into_iter()
                        .map(|new| EntityDelta::Added { new })
                        .collect(),
                    relation_deltas: indexed
                        .relations
                        .into_iter()
                        .map(|new| RelationDelta::Added { new })
                        .collect(),
                    ..TransactionDelta::default()
                })
                .unwrap();
            state.graph.upsert_file_layout(&layout).unwrap();
            commit_live_graph(&state, "install source semantics", false);
            entities = state
                .graph
                .query_entities(&EntityFilter {
                    name_pattern: Some("value".to_string()),
                    file_path: Some(file_id),
                    ..EntityFilter::default()
                })
                .unwrap();
        }
        let entity = entities
            .into_iter()
            .find(|entity| entity.name == "value")
            .expect("source fixture must contain value");

        let before = load_native_commit_base(&state.layout).unwrap();
        let gitlink_path = RepoPath::from_utf8("modules/dependency").unwrap();
        let gitlink = before
            .tree
            .artifact_at_path(&gitlink_path)
            .cloned()
            .expect("Git import must retain the exact Gitlink");
        assert!(matches!(gitlink.entry, TreeEntry::Gitlink { .. }));
        let retained = state
            .layout
            .working_dir()
            .join("modules/dependency/local-only.txt");
        std::fs::write(&retained, b"independently managed bytes\n").unwrap();

        let sessions = kin_mcp::SessionRegistry::new();
        let (_, arguments) = stage_entity_edit(&sessions, &entity, "pub fn value() -> u8 { 2 }");
        let result = commit_exact_transaction(&state, &sessions, &arguments, None);
        assert_ne!(
            result.is_error,
            Some(true),
            "unrelated exact source commit failed: {}",
            result_text(&result)
        );

        let after = load_native_commit_base(&state.layout).unwrap();
        assert!(after.roots.generation > before.roots.generation);
        assert_eq!(
            after.tree.get(&gitlink.artifact_id).unwrap().entry,
            gitlink.entry,
            "MCP commit must preserve the exact Gitlink target"
        );
        assert_eq!(
            std::fs::read(&retained).unwrap(),
            b"independently managed bytes\n",
            "unrelated MCP edits must not traverse or rewrite retained Gitlink content"
        );
    }

    #[test]
    fn receiptless_restart_fence_resets_and_replans_safely() {
        let (_dir, state) = test_state();
        let (entity, _) = install_exact_source(
            &state,
            "src/lib.rs",
            b"pub fn value() -> u8 { 1 }\n",
            "value",
        );
        let before = load_native_commit_base(&state.layout).unwrap();
        let sessions = kin_mcp::SessionRegistry::new();
        let (transaction_id, arguments) =
            stage_entity_edit(&sessions, &entity, "pub fn value() -> u8 { 2 }");
        let transaction = sessions.get_transaction(&transaction_id).unwrap();
        let payload_hash = transaction_payload_hash(&transaction).unwrap();
        sessions
            .prepare_transaction_commit(&transaction_id, &payload_hash)
            .unwrap();
        persist_registry_checked(&state, &sessions).unwrap();

        let result = commit_exact_transaction(&state, &sessions, &arguments, None);
        assert_ne!(
            result.is_error,
            Some(true),
            "receipt-less fence recovery failed: {}",
            result_text(&result)
        );
        let after = load_native_commit_base(&state.layout).unwrap();
        assert_eq!(after.roots.generation, before.roots.generation + 1);
        assert_eq!(
            sessions.get_transaction(&transaction_id).unwrap().state,
            "committed"
        );
    }

    #[test]
    fn repository_receipt_recovers_after_restart_without_double_commit() {
        let (dir, state) = test_state();
        let (entity, _) = install_exact_source(
            &state,
            "src/lib.rs",
            b"pub fn value() -> u8 { 1 }\n",
            "value",
        );
        let sessions = kin_mcp::SessionRegistry::new();
        let (transaction_id, arguments) =
            stage_entity_edit(&sessions, &entity, "pub fn value() -> u8 { 2 }");
        state
            .mcp_fail_after_authority_once
            .store(true, Ordering::SeqCst);

        let interrupted = commit_exact_transaction(&state, &sessions, &arguments, None);
        assert_eq!(interrupted.is_error, Some(true));
        assert!(result_text(&interrupted).contains("after repository receipt"));
        assert_eq!(
            sessions.get_transaction(&transaction_id).unwrap().state,
            "committing"
        );
        let committed_generation = load_native_commit_base(&state.layout)
            .unwrap()
            .roots
            .generation;
        let layout = state.layout.clone();
        drop(state);
        drop(sessions);

        install_test_registry_override();
        let reopened = Arc::new(DaemonState::open(layout).unwrap());
        let restored = reopened
            .mcp_transactions
            .lock()
            .unwrap()
            .values()
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].state, "committing");
        let recovered_sessions = kin_mcp::SessionRegistry::new();
        recovered_sessions.replace_transactions(restored);
        let recovered = commit_exact_transaction(&reopened, &recovered_sessions, &arguments, None);
        assert_ne!(
            recovered.is_error,
            Some(true),
            "receipt recovery failed: {}",
            result_text(&recovered)
        );
        assert_eq!(
            load_native_commit_base(&reopened.layout)
                .unwrap()
                .roots
                .generation,
            committed_generation,
            "receipt recovery must not publish a second repository generation"
        );
        assert_eq!(
            recovered_sessions
                .get_transaction(&transaction_id)
                .unwrap()
                .state,
            "committed"
        );
        assert_eq!(
            std::fs::read(reopened.layout.working_dir().join("src/lib.rs")).unwrap(),
            b"pub fn value() -> u8 { 2 }\n"
        );
        let authority = load_native_commit_base(&reopened.layout).unwrap();
        assert!(semantic_workspace_matches(
            reopened.graph.as_ref(),
            &authority.graph
        ));
        drop(dir);
    }
}
