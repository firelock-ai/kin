// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Durable request identity for daemon-owned one-shot mutations. The request
//! record is private recovery metadata; repository authority owns publication.

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use kin_model::{OperationId, RootBundle, SessionId, Timestamp};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::local_repository_authority::LocalRepositoryAuthorityContext;
use crate::repository_commit::{recover_native_commit, NativeCommitResult};
use crate::state::DaemonState;

pub(crate) const TOOL: &str = kin_mcp::handlers::sessions::DURABLE_MUTATE_TOOL;
const SCHEMA: &str = "kin.mutate.request.v2";
const OWNER: &str = "local-bearer-v1";
const MAX_REQUEST_BYTES: usize = 1024 * 1024;
const MAX_RECORD_BYTES: u64 = 2 * 1024 * 1024;
const HARD_MAX_RECORDS: usize = 1_000_000;
const HARD_MAX_BYTES: u64 = 16 * 1024 * 1024 * 1024;

#[derive(Default)]
pub(crate) struct RequestIndex {
    loaded: bool,
    records: HashMap<String, (String, u64)>,
    transactions: HashMap<String, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct RequestIdentity {
    repository_id: String,
    owner_namespace: String,
    session_id: String,
    request_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RequestBinding {
    schema: String,
    // A checksum detects damaged recovery metadata; it is not a signature or
    // authorization against a local owner who can rewrite the whole record.
    #[serde(default)]
    record_digest: String,
    identity: RequestIdentity,
    workspace_id: String,
    request_hash: String,
    transaction_id: String,
    operations_count: usize,
    request: Option<Value>,
    receipt: Option<PublicationProof>,
}

/// Fixed-size publication evidence. The full response's changed-file list can
/// grow with carried repository work, so it is reconstructed from authority,
/// never charged against the bounded permanent request record.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct PublicationProof {
    schema: String,
    repository_id: String,
    operation_id: String,
    transaction_hash: String,
    generation: u64,
    roots_before: RootBundle,
    roots_after: RootBundle,
}

impl PublicationProof {
    fn from_commit(committed: &NativeCommitResult) -> Self {
        Self {
            schema: "kin.mutate.publication.v1".to_string(),
            repository_id: committed.receipt.repository_id.to_string(),
            operation_id: committed.receipt.operation_id.to_string(),
            transaction_hash: committed.receipt.transaction_hash.to_string(),
            generation: committed.receipt.generation,
            roots_before: committed.receipt.roots_before.clone(),
            roots_after: committed.receipt.roots_after.clone(),
        }
    }
}

/// Versioned keyed response. These roots belong to the original publication,
/// even if a later request has advanced the repository or changed its files.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct MutationReceipt {
    schema: String,
    status: String,
    state: String,
    request_id: String,
    transaction_id: String,
    ops_applied: usize,
    change_id: String,
    modified_files: Vec<String>,
    entity_deltas: usize,
    relation_deltas: usize,
    repository_id: String,
    repository_operation_id: String,
    repository_generation: u64,
    repository_transaction_hash: String,
    roots_before: RootBundle,
    roots_after: RootBundle,
}

struct PreparedRequest {
    identity: RequestIdentity,
    workspace_id: String,
    key: String,
    hash: String,
    arguments: HashMap<String, Value>,
}

#[derive(Clone, Copy)]
struct Limits {
    records: usize,
    bytes: u64,
}

impl Limits {
    fn from_env() -> Result<Self, String> {
        fn limit(name: &str, default: u64, maximum: u64) -> Result<u64, String> {
            match std::env::var(name) {
                Err(std::env::VarError::NotPresent) => Ok(default),
                Ok(value) => value.parse::<u64>().ok().filter(|n| *n > 0 && *n <= maximum)
                    .ok_or_else(|| format!("request_admission_config_invalid: {name} must be an integer in 1..={maximum}; existing request bindings are retained")),
                Err(error) => Err(format!("request_admission_config_invalid: {name}: {error}")),
            }
        }
        Ok(Self {
            records: limit("KIN_MUTATE_MAX_REQUESTS", 65_536, HARD_MAX_RECORDS as u64)? as usize,
            bytes: limit(
                "KIN_MUTATE_MAX_STORAGE_BYTES",
                512 * 1024 * 1024,
                HARD_MAX_BYTES,
            )?,
        })
    }
}

fn directory(state: &DaemonState) -> PathBuf {
    state.layout.root().join("mutate_requests")
}

fn path(state: &DaemonState, key: &str) -> PathBuf {
    directory(state).join(format!("{key}.json"))
}

fn recovery(error: impl std::fmt::Display) -> String {
    format!("request_recovery_required: {error}; preserve .kin/mutate_requests and restore verified request records before retrying; do not reuse a lost key as a new mutation")
}

fn digest(domain: &[u8], value: &Value) -> String {
    let mut hash = Sha256::new();
    hash.update(domain);
    crate::mcp_commit::hash_canonical_json(&mut hash, value);
    hex::encode(hash.finalize())
}

fn key(identity: &RequestIdentity) -> String {
    digest(
        b"kin-mutate-key-v1\0",
        &serde_json::to_value(identity).expect("serializable identity"),
    )
}

fn request_hash(identity: &RequestIdentity, workspace: &str, request: &Value) -> String {
    digest(
        b"kin-mutate-request-v1\0",
        &serde_json::json!({
            "identity": identity, "workspace_id": workspace, "arguments": request,
        }),
    )
}

fn binding_digest(binding: &RequestBinding) -> String {
    let mut record = serde_json::to_value(binding).expect("serializable request binding");
    record.as_object_mut().unwrap().remove("record_digest");
    digest(b"kin-mutate-binding-v2\0", &record)
}

fn validate_binding(binding: &RequestBinding, expected_key: &str) -> Result<(), String> {
    if binding.schema != SCHEMA {
        return Err(recovery(
            "unsupported request record schema; checksum-free records cannot be safely upgraded automatically",
        ));
    }
    if binding.record_digest != binding_digest(binding) {
        return Err(recovery("request record integrity digest mismatch"));
    }
    if binding.identity.owner_namespace != OWNER
        || key(&binding.identity) != expected_key
        || uuid::Uuid::parse_str(&binding.identity.session_id).is_err()
        || uuid::Uuid::parse_str(&binding.transaction_id).is_err()
        || binding.request_hash.len() != 64
        || !binding
            .request_hash
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit())
        || binding.operations_count == 0
        || binding.operations_count > kin_mcp::session::MAX_STAGED_OPERATIONS_PER_TRANSACTION
    {
        return Err(recovery("invalid request record identity or schema"));
    }
    if let Some(request) = &binding.request {
        if request
            .get("operations")
            .and_then(Value::as_array)
            .map(Vec::len)
            != Some(binding.operations_count)
        {
            return Err(recovery(
                "request record operation count does not match its payload",
            ));
        }
        if binding.request_hash != request_hash(&binding.identity, &binding.workspace_id, request) {
            return Err(recovery(
                "request record payload does not match its immutable hash",
            ));
        }
    } else if binding.receipt.is_none() {
        return Err(recovery("unfinished request is missing its bound payload"));
    }
    Ok(())
}

fn read_binding(state: &DaemonState, key: &str) -> Result<Option<(RequestBinding, u64)>, String> {
    let file = path(state, key);
    let metadata = match std::fs::symlink_metadata(&file) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(recovery(error)),
    };
    if !metadata.file_type().is_file() || metadata.len() > MAX_RECORD_BYTES {
        return Err(recovery(format!(
            "{} is not a bounded regular request record",
            file.display()
        )));
    }
    let bytes = std::fs::read(&file).map_err(recovery)?;
    let binding: RequestBinding = serde_json::from_slice(&bytes).map_err(recovery)?;
    validate_binding(&binding, key)?;
    if binding.identity.repository_id != state.cached_repo_id {
        return Err(recovery("request record belongs to another repository"));
    }
    Ok(Some((binding, bytes.len() as u64)))
}

fn checked_directory(state: &DaemonState, create: bool) -> Result<bool, String> {
    let directory = directory(state);
    match std::fs::symlink_metadata(&directory) {
        Ok(metadata) if metadata.file_type().is_dir() => Ok(true),
        Ok(_) => Err(recovery(
            "mutate_requests must be a real directory, not a symlink or another file type",
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound && !create => Ok(false),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            std::fs::create_dir(&directory).map_err(recovery)?;
            checked_directory(state, false)
        }
        Err(error) => Err(recovery(error)),
    }
}

fn load_index(state: &DaemonState, index: &mut RequestIndex) -> Result<(), String> {
    let exists = checked_directory(state, false)?;
    if index.loaded {
        if !exists && !index.records.is_empty() {
            return Err(recovery("the retained request directory is missing"));
        }
        return Ok(());
    }
    let entries = match std::fs::read_dir(directory(state)) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            *index = RequestIndex {
                loaded: true,
                ..Default::default()
            };
            return Ok(());
        }
        Err(error) => return Err(recovery(error)),
    };
    let mut next = RequestIndex::default();
    let mut bytes = 0_u64;
    for entry in entries {
        let entry = entry.map_err(recovery)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| recovery("non-UTF-8 request filename"))?;
        if name.ends_with(".tmp") {
            continue;
        }
        let Some(key) = name.strip_suffix(".json") else {
            return Err(recovery("unrecognized request recovery file"));
        };
        if key.len() != 64 || !key.bytes().all(|c| c.is_ascii_hexdigit()) {
            return Err(recovery("invalid request record filename"));
        }
        let (binding, size) = read_binding(state, key)?
            .ok_or_else(|| recovery("request record disappeared during recovery"))?;
        bytes = bytes.saturating_add(size);
        if next.records.len() >= HARD_MAX_RECORDS || bytes > HARD_MAX_BYTES {
            return Err(recovery(
                "request directory exceeds the supported recovery bound",
            ));
        }
        if next
            .transactions
            .insert(binding.transaction_id.clone(), key.to_string())
            .is_some()
        {
            return Err(recovery("multiple request records claim one transaction"));
        }
        let charge = if binding.request.is_some() {
            MAX_RECORD_BYTES
        } else {
            size
        };
        next.records
            .insert(key.to_string(), (binding.transaction_id, charge));
    }
    next.loaded = true;
    *index = next;
    Ok(())
}

fn lookup(state: &DaemonState, key: &str) -> Result<Option<RequestBinding>, String> {
    let mut index = state
        .mcp_mutate_requests
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    load_index(state, &mut index)?;
    match read_binding(state, key)? {
        Some((record, _)) => Ok(Some(record)),
        None if index.records.contains_key(key) => {
            Err(recovery("a retained request record is missing"))
        }
        None => Ok(None),
    }
}

/// Lower-level transaction calls never change a one-shot request's transaction,
/// even after its ordinary staging mirror has evicted the terminal record.
pub(crate) fn ensure_unbound(state: &DaemonState, transaction_id: &str) -> Result<(), String> {
    let mut index = state
        .mcp_mutate_requests
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    load_index(state, &mut index)?;
    let canonical = uuid::Uuid::parse_str(transaction_id)
        .map(|id| id.to_string())
        .unwrap_or_else(|_| transaction_id.to_string());
    if index.transactions.contains_key(&canonical) {
        return Err("request_bound_transaction: this transaction belongs to a durable kin_mutate request; retry kin_mutate with the original session_id, request_id and complete arguments".to_string());
    }
    Ok(())
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> std::io::Result<()> {
    std::fs::File::open(path)?.sync_all()
}
#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

pub(crate) fn fault(_state: &DaemonState, _phase: u8) -> Result<(), String> {
    #[cfg(test)]
    if _state
        .mcp_mutate_fail_once
        .compare_exchange(
            _phase,
            0,
            std::sync::atomic::Ordering::SeqCst,
            std::sync::atomic::Ordering::SeqCst,
        )
        .is_ok()
    {
        return Err(format!("injected request persistence phase {_phase}"));
    }
    Ok(())
}

fn persist(state: &DaemonState, binding: &RequestBinding, completed: bool) -> Result<(), String> {
    let record_key = key(&binding.identity);
    let mut checked = binding.clone();
    checked.record_digest = binding_digest(&checked);
    let bytes = serde_json::to_vec(&checked).map_err(recovery)?;
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err(recovery("request record exceeds its storage bound"));
    }
    let mut index = state
        .mcp_mutate_requests
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    load_index(state, &mut index)?;
    if !index.records.contains_key(&record_key) {
        let limits = Limits::from_env()?;
        let retained_bytes = index.records.values().map(|(_, size)| size).sum::<u64>();
        if index.records.len() >= limits.records
            || retained_bytes.saturating_add(MAX_RECORD_BYTES) > limits.bytes
        {
            return Err(format!("request_admission_quota_exceeded: {} retained bindings reserve {retained_bytes} bytes; a pending request reserves {MAX_RECORD_BYTES} bytes until compact receipt persistence. Limits are KIN_MUTATE_MAX_REQUESTS={} and KIN_MUTATE_MAX_STORAGE_BYTES={}. Raise these validated limits to admit new keys; existing keys remain recoverable and must not be deleted to free capacity", index.records.len(), limits.records, limits.bytes));
        }
    }
    let file = path(state, &record_key);
    // Never open a predictable entry with truncate: it could be recovery
    // evidence or a link to unrelated bytes. Exclusive creation also refuses
    // any pre-existing entry even if a UUID name happened to collide.
    let tmp = directory(state).join(format!("{record_key}.{}.tmp", uuid::Uuid::new_v4()));
    let mut owns_tmp = false;
    let phase = if completed { 10 } else { 0 };
    let written = (|| -> Result<(), String> {
        checked_directory(state, true)?;
        sync_directory(state.layout.root()).map_err(recovery)?;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        fault(state, phase + 1)?;
        let mut output = options.open(&tmp).map_err(recovery)?;
        owns_tmp = true;
        output.write_all(&bytes).map_err(recovery)?;
        fault(state, phase + 2)?;
        output.sync_all().map_err(recovery)?;
        fault(state, phase + 3)?;
        std::fs::rename(&tmp, &file).map_err(recovery)?;
        owns_tmp = false;
        fault(state, phase + 4)?;
        sync_directory(&directory(state)).map_err(recovery)?;
        Ok(())
    })();
    if let Err(error) = written {
        index.loaded = false;
        if owns_tmp {
            let _ = std::fs::remove_file(&tmp);
        }
        return Err(recovery(error));
    }
    let charge = if binding.request.is_some() {
        MAX_RECORD_BYTES
    } else {
        bytes.len() as u64
    };
    index
        .records
        .insert(record_key.clone(), (binding.transaction_id.clone(), charge));
    index
        .transactions
        .insert(binding.transaction_id.clone(), record_key);
    Ok(())
}

fn prepare(
    state: &DaemonState,
    headers: &axum::http::HeaderMap,
    mut arguments: HashMap<String, Value>,
    authenticated: bool,
) -> Result<PreparedRequest, String> {
    if !authenticated {
        return Err("durable_request_auth_required: keyed kin_mutate requires the daemon's enforced local bearer authentication; auth-disabled and offline operation provide no durable owner guarantee".to_string());
    }
    let request_id = kin_mcp::handlers::sessions::checked_mutate_request_id(&arguments)?
        .ok_or("request_id is required for durable mutation")?
        .to_string();
    let session_id = headers
        .get("X-Kin-Session")
        .and_then(|s| s.to_str().ok())
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
        .ok_or("request_owner_mismatch: a canonical session UUID in X-Kin-Session is required")?;
    let body_session = arguments
        .get("session_id")
        .and_then(Value::as_str)
        .and_then(|s| uuid::Uuid::parse_str(s.trim()).ok());
    if body_session != Some(session_id) {
        return Err("request_owner_mismatch: body session_id must match X-Kin-Session".to_string());
    }
    let authority = LocalRepositoryAuthorityContext::from_state(state).map_err(recovery)?;
    arguments.insert(
        "session_id".to_string(),
        Value::String(session_id.to_string()),
    );
    arguments
        .entry("scope".to_string())
        .or_insert_with(|| Value::String("repository".to_string()));
    let identity = RequestIdentity {
        repository_id: authority.repository_id().to_string(),
        owner_namespace: OWNER.to_string(),
        session_id: session_id.to_string(),
        request_id,
    };
    let workspace_id = authority.workspace_id().to_string();
    let value = serde_json::to_value(&arguments).map_err(recovery)?;
    if serde_json::to_vec(&value).map_err(recovery)?.len() > MAX_REQUEST_BYTES {
        return Err(format!(
            "request_too_large: canonical keyed mutation exceeds {MAX_REQUEST_BYTES} bytes"
        ));
    }
    Ok(PreparedRequest {
        key: key(&identity),
        hash: request_hash(&identity, &workspace_id, &value),
        identity,
        workspace_id,
        arguments,
    })
}

/// A keyed request cannot promise a condition that its typed operation drops.
/// Metadata maps survive serialization and remain extensible application data.
fn require_consumed_fields(
    supplied: &Value,
    decoded: &Value,
    location: &str,
) -> Result<(), String> {
    match (supplied, decoded) {
        (Value::Object(fields), Value::Object(accepted)) => {
            for (name, value) in fields {
                let field = format!("{location}.{name}");
                let Some(decoded) = accepted.get(name) else {
                    return Err(format!("unsupported_request_field: {field} is not supported by the keyed mutation schema; no constraint is enforced by merely including it"));
                };
                require_consumed_fields(value, decoded, &field)?;
            }
        }
        (Value::Array(values), Value::Array(accepted)) => {
            for (i, (value, decoded)) in values.iter().zip(accepted).enumerate() {
                require_consumed_fields(value, decoded, &format!("{location}[{i}]"))?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_request_fields(arguments: &HashMap<String, Value>) -> Result<(), String> {
    const FIELDS: &[&str] = &["session_id", "request_id", "operations", "scope", "summary"];
    for name in arguments.keys() {
        if !FIELDS.contains(&name.as_str()) {
            return Err(format!("unsupported_request_field: {name} is not supported by kin_mutate_durable_v1; accepted fields are {}; caller-read freshness constraints require a separately supported operation", FIELDS.join(", ")));
        }
    }
    if arguments.get("scope").and_then(Value::as_str) != Some("repository") {
        return Err("unsupported_request_scope: keyed kin_mutate v1 supports only scope=repository in the daemon's bound workspace; another scope is not selected or enforced".to_string());
    }
    if arguments
        .get("summary")
        .is_some_and(|summary| !summary.is_string())
    {
        return Err("invalid_request_field: summary must be a string when supplied".to_string());
    }
    Ok(())
}

pub(crate) async fn call(
    state: Arc<DaemonState>,
    headers: axum::http::HeaderMap,
    arguments: HashMap<String, Value>,
    authenticated: bool,
) -> crate::mcp_commit::McpCommitOutcome {
    let prepared = match prepare(&state, &headers, arguments, authenticated) {
        Ok(request) => request,
        Err(error) => return Ok(kin_mcp::ToolCallResult::error(error)),
    };
    let inflight_key = format!("mutate:{}", prepared.key);
    let outcome = match crate::mcp_commit::InflightMcpCommits::claim(
        &state,
        &inflight_key,
        prepared.hash.clone(),
    ) {
        crate::mcp_commit::McpCommitRole::Join(outcome) => outcome,
        crate::mcp_commit::McpCommitRole::Alone => return Ok(execute(state, prepared).await),
        crate::mcp_commit::McpCommitRole::Lead(lease) => {
            let outcome = lease.subscribe();
            tokio::spawn(async move {
                lease.publish(Ok(execute(state, prepared).await));
            });
            outcome
        }
    };
    crate::mcp_commit::await_mcp_commit_outcome(outcome, &inflight_key).await
}

fn receipt(
    binding: &RequestBinding,
    committed: &NativeCommitResult,
) -> Result<MutationReceipt, String> {
    committed.receipt.validate().map_err(recovery)?;
    if committed.receipt.operation_id.to_string() != binding.transaction_id
        || committed.receipt.repository_id.to_string() != binding.identity.repository_id
    {
        return Err(recovery(
            "repository receipt disagrees with the scoped request binding",
        ));
    }
    Ok(MutationReceipt {
        schema: "kin.mutate.receipt.v1".to_string(),
        status: "committed".to_string(),
        state: "committed".to_string(),
        request_id: binding.identity.request_id.clone(),
        transaction_id: binding.transaction_id.clone(),
        ops_applied: binding.operations_count,
        change_id: committed.change.id.to_string(),
        modified_files: crate::mcp_commit::changed_file_ids(&committed.change)?
            .iter()
            .map(ToString::to_string)
            .collect(),
        entity_deltas: committed.entity_count,
        relation_deltas: committed.relation_count,
        repository_id: committed.receipt.repository_id.to_string(),
        repository_operation_id: committed.receipt.operation_id.to_string(),
        repository_generation: committed.receipt.generation,
        repository_transaction_hash: committed.receipt.transaction_hash.to_string(),
        roots_before: committed.receipt.roots_before.clone(),
        roots_after: committed.receipt.roots_after.clone(),
    })
}

fn complete(
    state: &DaemonState,
    binding: &mut RequestBinding,
    committed: &NativeCommitResult,
    replay: bool,
) -> Result<kin_mcp::ToolCallResult, String> {
    let original = receipt(binding, committed)?;
    let proof = PublicationProof::from_commit(committed);
    if binding
        .receipt
        .as_ref()
        .is_some_and(|cached| cached != &proof)
    {
        return Err(recovery(
            "cached mutation receipt disagrees with repository authority",
        ));
    }
    if binding.receipt.is_none() {
        binding.receipt = Some(proof);
        binding.request = None;
        persist(state, binding, true)?;
    }
    let mut payload = serde_json::to_value(original).map_err(recovery)?;
    payload["already_applied"] = Value::Bool(replay);
    Ok(kin_mcp::ToolCallResult::text(
        serde_json::to_string(&payload).map_err(recovery)?,
    ))
}

async fn execute(state: Arc<DaemonState>, request: PreparedRequest) -> kin_mcp::ToolCallResult {
    let _coordination = state.coordination_gate.lock().await;
    execute_locked(&state, request).unwrap_or_else(kin_mcp::ToolCallResult::error)
}

fn execute_locked(
    state: &Arc<DaemonState>,
    request: PreparedRequest,
) -> Result<kin_mcp::ToolCallResult, String> {
    if !state
        .is_initialized
        .load(std::sync::atomic::Ordering::Relaxed)
    {
        return Err("daemon not fully initialized".to_string());
    }
    let recovered =
        crate::state::recover_mcp_transaction_lifecycle(&state.layout).map_err(recovery)?;
    match crate::state::load_persisted_mcp_transactions_checked(&state.layout) {
        Ok(store) => {
            *state
                .mcp_transactions
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = store
        }
        Err(error) if recovered => return Err(recovery(error)),
        // A pending operation checks the mirror again before beginning. Only
        // published-receipt recovery may continue with an unreadable primary.
        Err(_) => {}
    }
    let mut binding = lookup(state, &request.key)?;
    let authority = LocalRepositoryAuthorityContext::from_state(state).map_err(recovery)?;
    if let Some(binding) = &mut binding {
        if binding.identity != request.identity
            || binding.workspace_id != request.workspace_id
            || binding.request_hash != request.hash
        {
            return Err("request_id_payload_mismatch: this scoped request_id is already bound to different arguments; use the exact original request to recover it or a new request_id for different work".to_string());
        }
        let operation = OperationId::from_uuid(
            uuid::Uuid::parse_str(&binding.transaction_id).map_err(recovery)?,
        );
        if let Some(committed) = recover_native_commit(&authority, operation).map_err(recovery)? {
            let result = complete(state, binding, &committed, true)?;
            crate::api::forget_mcp_transaction(state, &binding.transaction_id);
            return Ok(result);
        }
        if binding.receipt.is_some() {
            return Err(recovery(
                "cached success has no repository operation receipt",
            ));
        }
    }
    validate_request_fields(&request.arguments)?;
    // Receipt retrieval does not heartbeat or revive an expired session. New
    // execution requires a currently registered owner and current capabilities.
    let session_id =
        SessionId(uuid::Uuid::parse_str(&request.identity.session_id).map_err(recovery)?);
    let _active = state.coordinator.begin_call(&session_id);
    let session = state.coordinator.get_session(&session_id).map_err(recovery)?.ok_or("request_session_expired: the bound session is not registered; an unpublished request cannot be resumed under a new session")?;
    let now = chrono::Utc::now();
    let last = chrono::DateTime::parse_from_rfc3339(&session.last_heartbeat.to_string())
        .map_err(recovery)?;
    let pid_alive = session.pid.map(kin_cli::daemon_client::is_process_alive);
    if pid_alive == Some(false)
        || (pid_alive != Some(true)
            && (now.signed_duration_since(last).to_std().unwrap_or_default()
                > state.coordinator.session_idle_ttl()))
    {
        return Err("request_session_expired: the bound session lease is stale; only an already-published receipt can be recovered".to_string());
    }
    if !session.capabilities.can_write || !session.capabilities.can_commit {
        return Err(
            "request_capability_refused: the registered session requires can_write and can_commit"
                .to_string(),
        );
    }
    state.coordinator.heartbeat(&session_id).map_err(recovery)?;
    let operations = kin_mcp::handlers::sessions::checked_mutate_operations(&request.arguments)
        .map_err(|error| {
            error
                .content
                .iter()
                .map(|kin_mcp::ContentBlock::Text { text }| text.as_str())
                .collect::<Vec<_>>()
                .join("\n")
        })?;
    let parsed = kin_mcp::session::parse_staged_operations(operations)?;
    require_consumed_fields(
        operations,
        &serde_json::to_value(&parsed).map_err(recovery)?,
        "operations",
    )?;
    if parsed.len() > kin_mcp::session::MAX_STAGED_OPERATIONS_PER_TRANSACTION {
        return Err(
            "transaction_limit_exceeded: keyed request exceeds the operation count limit"
                .to_string(),
        );
    }
    if parsed.is_empty() {
        return Err("keyed kin_mutate requires at least one operation".to_string());
    }
    let scope = request
        .arguments
        .get("scope")
        .and_then(Value::as_str)
        .ok_or("scope must be a string")?;
    crate::state::load_persisted_mcp_transactions_checked(&state.layout).map_err(recovery)?;
    let mut binding = binding.unwrap_or_else(|| RequestBinding {
        schema: SCHEMA.to_string(),
        record_digest: String::new(),
        identity: request.identity.clone(),
        workspace_id: request.workspace_id.clone(),
        request_hash: request.hash.clone(),
        transaction_id: uuid::Uuid::new_v4().to_string(),
        operations_count: parsed.len(),
        request: Some(serde_json::to_value(&request.arguments).expect("serializable request")),
        receipt: None,
    });
    // Re-sync an existing pending reservation too: it may have been renamed
    // into view by an earlier attempt whose final directory sync failed.
    persist(state, &binding, false)?;
    fault(state, 5)?;
    let sessions = crate::api::mcp_session_registry_snapshot(state).map_err(|(_, error)| error)?;
    if sessions.get_transaction(&binding.transaction_id).is_none() {
        let unfinished = sessions
            .list_transactions()
            .iter()
            .filter(|tx| {
                tx.session_id == request.identity.session_id
                    && kin_mcp::session::is_unfinished_transaction_state(&tx.state)
            })
            .count();
        if unfinished >= kin_mcp::session::MAX_ACTIVE_TRANSACTIONS_PER_SESSION {
            return Err("transaction_limit_exceeded: finish existing transactions before resuming this request".to_string());
        }
        let transaction = kin_mcp::McpTransaction {
            transaction_id: binding.transaction_id.clone(),
            session_id: request.identity.session_id.clone(),
            scope: scope.to_string(),
            state: "active".to_string(),
            staged_operations: Vec::new(),
            commit_payload_hash: None,
            last_activity_at: Timestamp::now(),
        };
        let mut transactions = sessions.list_transactions();
        transactions.push(transaction);
        sessions.replace_transactions(transactions);
        crate::api::persist_mcp_lifecycle_transactions(state, &sessions).map_err(recovery)?;
    }
    fault(state, 6)?;
    let transaction = sessions
        .get_transaction(&binding.transaction_id)
        .ok_or("bound transaction is missing")?;
    if matches!(transaction.state.as_str(), "active" | "validated") {
        let mut transactions = sessions.list_transactions();
        let transaction = transactions
            .iter_mut()
            .find(|tx| tx.transaction_id == binding.transaction_id)
            .ok_or("bound transaction is missing")?;
        transaction.staged_operations = parsed;
        transaction.state = "active".to_string();
        transaction.commit_payload_hash = None;
        transaction.last_activity_at = Timestamp::now();
        sessions.replace_transactions(transactions);
        crate::api::persist_mcp_lifecycle_transactions(state, &sessions).map_err(recovery)?;
    }
    let mut commit_arguments = HashMap::from([
        (
            "transaction_id".to_string(),
            Value::String(binding.transaction_id.clone()),
        ),
        (
            "session_id".to_string(),
            Value::String(request.identity.session_id.clone()),
        ),
    ]);
    if let Some(summary) = kin_mcp::handlers::sessions::commit_message_argument(&request.arguments)
    {
        commit_arguments.insert("message".to_string(), Value::String(summary));
    }
    let (_, _, scopes, _) =
        crate::api::transaction_coordination_context(state, &sessions, &commit_arguments);
    let preflight = sessions.evaluate_transaction_write(&request.identity.session_id, scopes);
    if !preflight.allowed {
        return Err(format!(
            "coordination enforcement rejected bound request: {}",
            serde_json::to_string(&preflight).map_err(recovery)?
        ));
    }
    let _mutation = state.begin_graph_authority_mutation();
    let result = crate::mcp_commit::commit_bound_transaction(
        state,
        &sessions,
        &commit_arguments,
        Some(&preflight),
        &binding,
    );
    crate::api::persist_mcp_transactions(state, &sessions);
    #[cfg(test)]
    if let Some(hold) = state.mcp_mutate_publication_hold.lock().unwrap().take() {
        state
            .mcp_mutate_publication_reached
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let _ = hold.recv();
    }
    fault(state, 7)?;
    let committed = recover_native_commit(
        &authority,
        OperationId::from_uuid(uuid::Uuid::parse_str(&binding.transaction_id).map_err(recovery)?),
    )
    .map_err(recovery)?;
    match committed {
        Some(committed) => {
            if result.is_error == Some(true) {
                // Authority already published. Never label that as an
                // uncommitted failure or hide unfinished derived-state work.
                // Receipt replay reads authority only; a new exact commit
                // still passes the existing daemon-workspace freshness guard.
                let original = receipt(&binding, &committed)?;
                let cache_error = complete(state, &mut binding, &committed, false).err();
                return Ok(kin_mcp::ToolCallResult::error(serde_json::json!({
                    "schema": "kin.mutate.recovery.v1",
                    "code": "publication_completed_daemon_recovery_required",
                    "published": true,
                    "receipt": original,
                    "finalization_error": result,
                    "receipt_cache_error": cache_error,
                    "remedy": "Reopen the daemon to recover current repository authority. Retry the same session_id, request_id and complete request only to retrieve this original receipt; do not publish a replacement."
                }).to_string()));
            }
            let result = complete(state, &mut binding, &committed, false)?;
            crate::api::forget_mcp_transaction(state, &binding.transaction_id);
            Ok(result)
        }
        None if result.is_error == Some(true) => Ok(result),
        None => Err(recovery(
            "mutation answered success without its repository operation receipt",
        )),
    }
}

pub(crate) fn validate_bound_commit(
    state: &DaemonState,
    binding: &RequestBinding,
    transaction_id: &str,
) -> Result<(), String> {
    let stored = lookup(state, &key(&binding.identity))?
        .ok_or_else(|| recovery("request reservation is missing before publication"))?;
    if stored.transaction_id != transaction_id
        || stored.request_hash != binding.request_hash
        || stored.receipt.is_some()
    {
        return Err(recovery("request reservation changed before publication"));
    }
    Ok(())
}
