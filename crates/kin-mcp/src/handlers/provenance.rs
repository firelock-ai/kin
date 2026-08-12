// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::HashMap;
use std::collections::HashSet;

use kin_model::change::{ChangeOrigin, SemanticChange};
use kin_model::graph::GraphStore;
use kin_model::provenance::{Approval, AuditEvent};
use kin_model::work::WorkScope;

use crate::error::{McpError, Result};
use crate::types::ToolCallResult;

use super::common::*;

/// How many recent audit events to consider before narrowing them to the
/// queried entity.
///
/// The store filters by actor, never by scope, so narrowing by scope has to
/// happen here, which means taking a window of recent events first and filtering
/// second. The consequence is stated in the tool description rather than hidden:
/// an entity whose last write is older than this many events returns an empty
/// list even though it was written. Filtering before limiting would need a
/// scope-aware query in the store, which is kin-db's surface, not this one.
///
/// Bounded so one entity's answer does not grow with the repository's whole
/// audit history, and wide enough that an entity's own recent activity survives
/// a busy period from other lanes.
const AUDIT_SCAN: usize = 512;

/// How many of the queried entity's own events to return.
const AUDIT_RETURNED: usize = 20;

/// How many changes one page carries when the caller names no `limit`.
const CHANGES_DEFAULT_LIMIT: u64 = 20;

/// The largest page a caller may ask for.
///
/// A page is bounded in entries rather than in bytes because a summary entry has
/// a bounded shape: every field is a hash, a timestamp, an identity, a message,
/// or a delta count, and none of them grows with the size of the change. The
/// payloads that do grow arrive only under `compact: false`, which is why that
/// mode is opt-in and documented as unbounded.
const CHANGES_MAX_LIMIT: u64 = 200;

pub const PROVENANCE_QUERY_DESC: &str = "\
Answer who-and-whether-approved for an entity: it returns the entity's change count, \
its latest change, any approvals recorded on that change, a bounded page of its changes \
newest first, and recent audit events recorded against that entity. Reach for it to \
establish accountability and trust before relying on a piece of code, to answer \"who \
last touched this, and has it been signed off?\", or when assembling an audit trail. It \
builds on entity_history (the raw change list) by adding approval status and audit \
context in one call. latest_change is the newest change by timestamp across every \
origin, so a native or agent write that lands after an imported Git commit is the one \
reported. Changes come back as summaries with delta counts rather than delta payloads, \
and every hash is a 64-character hex string that matches what `kin log` prints. Page \
older changes with offset/limit, following next_offset until it is null; pass \
compact=false to add the full entity, relation, and tree delta payloads, which is \
unbounded in size and not for agent context. Every field is scoped to the entity you \
asked about: recent_audit_events never carries another entity's writes. It is drawn from \
the repository's recent audit activity and then narrowed, so it is the entity's own \
recent writes rather than its complete write history, and an entity whose last write is \
older than the scan window comes back with an empty list. Treat a populated list as \
authoritative about who wrote this entity, and an empty one as no recent record rather \
than as proof nothing ever wrote it; change_count and latest_change are the \
complete-history fields. An entity_id that names no entity fails loudly and carries the \
standard negative object rather than returning an empty history, so \"nothing is recorded \
about this code\" and \"that id resolves to nothing\" are never the same answer.";

/// The change origin, with the Git object id rendered the way Git prints it.
///
/// The model's own encoding serializes the object id as a byte array, which no
/// caller can compare against a commit hash without reassembling it.
fn change_origin_json(origin: &ChangeOrigin) -> serde_json::Value {
    match origin {
        ChangeOrigin::Native => serde_json::json!({ "type": "native" }),
        ChangeOrigin::GitCommit { oid } => serde_json::json!({
            "type": "git_commit",
            "oid": oid.to_string(),
        }),
    }
}

/// One change as provenance, not as a payload.
///
/// A `SemanticChange` carries every entity, relation, and tree delta it applied,
/// and a single commit that touched one file carries a delta for every entity in
/// that file. Serializing the whole struct to answer "who changed this" spends
/// megabytes on data the question never asked for, so the summary reports the
/// deltas by count and returns their contents only when `include_deltas` is set.
///
/// Hashes are hex here rather than the model's byte arrays: these are the ids a
/// caller correlates against `kin log`, and a 32-element integer array cannot be
/// compared against printed output without being reassembled by hand.
fn change_summary(change: &SemanticChange, include_deltas: bool) -> Result<serde_json::Value> {
    let mut summary = serde_json::json!({
        "id": change.id.to_string(),
        "origin": change_origin_json(&change.origin),
        "parents": change
            .parents
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        "timestamp": change.timestamp,
        "author": change.author.to_string(),
        "message": change.message,
        "entity_delta_count": change.entity_deltas.len(),
        "relation_delta_count": change.relation_deltas.len(),
        "tree_delta_count": change.tree_deltas.len(),
    });

    if include_deltas {
        let object = summary
            .as_object_mut()
            .expect("change summary is constructed as a JSON object");
        object.insert(
            "entity_deltas".into(),
            serde_json::to_value(&change.entity_deltas).map_err(McpError::Json)?,
        );
        object.insert(
            "relation_deltas".into(),
            serde_json::to_value(&change.relation_deltas).map_err(McpError::Json)?,
        );
        object.insert(
            "tree_deltas".into(),
            serde_json::to_value(&change.tree_deltas).map_err(McpError::Json)?,
        );
    }

    Ok(summary)
}

/// An audit event with its content-addressed ids rendered as hex.
///
/// `event_id` and `actor_id` are both `Hash256`, so the model's encoding turns
/// each into 32 integers. The actor id in particular is what a caller carries
/// back to `get_actor`, and it has to be printable to be usable.
fn audit_event_json(event: &AuditEvent) -> serde_json::Value {
    serde_json::json!({
        "event_id": event.event_id.to_string(),
        "actor_id": event.actor_id.to_string(),
        "action": event.action,
        // A Change-scoped event would otherwise externally tag a Hash256 and
        // ship {"Change": [32 integers]}; Display prints change:<hex> and
        // entity:<uuid>, which a caller can match against the changes page.
        "target_scope": event.target_scope.as_ref().map(|scope| scope.to_string()),
        "timestamp": event.timestamp,
        "details": event.details,
    })
}

/// An approval with its content-addressed ids rendered as hex.
///
/// `approval_id`, `change_id`, and `approver` are all `Hash256` newtypes, so
/// model serde turns each into 32 integers. The change id in particular is what
/// a caller compares against `latest_change.id` to confirm which change was
/// signed off, and a string can never equal an integer array.
fn approval_json(approval: &Approval) -> serde_json::Value {
    serde_json::json!({
        "approval_id": approval.approval_id.to_string(),
        "change_id": approval.change_id.to_string(),
        "approver": approval.approver.to_string(),
        "decision": approval.decision,
        "reason": approval.reason,
        "timestamp": approval.timestamp,
    })
}

pub fn handle_provenance_query<G: GraphStore>(
    args: &HashMap<String, serde_json::Value>,
    store: &G,
) -> Result<ToolCallResult> {
    let id_str = get_string_param(args, "entity_id")?;
    let entity_id = parse_entity_id(&id_str)?;
    let offset = get_optional_u64(args, "offset", 0) as usize;
    let limit =
        get_optional_u64(args, "limit", CHANGES_DEFAULT_LIMIT).clamp(1, CHANGES_MAX_LIMIT) as usize;
    let include_deltas = !get_optional_bool(args, "compact", true);

    let history = store
        .get_entity_history(&entity_id)
        .map_err(McpError::graph)?;

    // An id that resolves to nothing and has nothing recorded against it is a
    // resolution miss, not an empty provenance record.
    //
    // Both cases used to answer identically — change_count 0, latest_change
    // null, empty approvals and audit events, no error — so an agent that
    // fat-fingered an id, or passed an artifact_id, read "nothing is recorded
    // about this code" and moved on. `get_entity_source` fails loudly on the
    // same id; this tool succeeded.
    //
    // Both halves of the condition are load-bearing. A retired entity is absent
    // from the graph while its history survives, and its provenance is exactly
    // what a caller is entitled to ask for, so a live-entity check alone would
    // refuse the question this tool exists to answer. An entity that resolves
    // with no changes yet recorded is a real, reportable emptiness. Only the
    // conjunction means nothing was looked up.
    if history.is_empty()
        && store
            .get_entity(&entity_id)
            .map_err(McpError::graph)?
            .is_none()
    {
        return Ok(ToolCallResult::error(format!(
            "no entity exists with ID '{id_str}' and no change history is recorded against it, \
             so no provenance was looked up. This entity ID is invalid or stale; retrying the \
             same ID will not succeed. Resolve the symbol first with semantic_search or \
             find_references and query provenance for the id it returns."
        )));
    }

    // Newest first, decided here rather than taken from the store.
    //
    // `get_entity_history` returns the entity's changes oldest first, so reading
    // the head of that list as the latest change reports the change that
    // introduced the entity and hides every write since. The direction of that
    // error is what made it hard to see: an entity's oldest change is usually an
    // imported Git commit, so the answer looked like ordinary history while it
    // silently dropped the native and agent writes that came after.
    //
    // Ordering by timestamp here also keeps the answer independent of whatever
    // order the store happens to return, which is what failed before. Ties break
    // on the change id so a page boundary is stable across calls.
    let mut ordered = history.iter().collect::<Vec<_>>();
    ordered.sort_by(|a, b| b.timestamp.cmp(&a.timestamp).then_with(|| b.id.cmp(&a.id)));

    let latest = ordered.first().copied();

    let mut approvals_json = serde_json::json!([]);
    if let Some(latest) = latest {
        let approvals = store
            .get_approvals_for_change(&latest.id)
            .map_err(McpError::graph)?;
        approvals_json = serde_json::Value::Array(approvals.iter().map(approval_json).collect());
    }

    let changes = ordered
        .iter()
        .skip(offset)
        .take(limit)
        .map(|change| change_summary(change, include_deltas))
        .collect::<Result<Vec<_>>>()?;
    let returned = changes.len();
    let next_offset = match offset.saturating_add(returned) {
        reached if reached < ordered.len() => serde_json::json!(reached),
        _ => serde_json::Value::Null,
    };

    // Audit events for THIS entity, not the repository's most recent activity.
    //
    // The store has no scope filter, so an unnarrowed query returns whatever
    // happened last anywhere. Returning that under an `entity_id` key answers
    // "who touched this entity" with a different entity's commit, by a different
    // agent, and nothing in the response says otherwise. The events carry the
    // scope needed to narrow them, so narrow them here.
    //
    // A commit that changed no entity is scoped to its change instead, so those
    // are kept when the change is one of this entity's own.
    let entity_changes = history
        .iter()
        .map(|change| change.id)
        .collect::<HashSet<_>>();
    let events = store
        .query_audit_events(None, AUDIT_SCAN)
        .map_err(McpError::graph)?
        .into_iter()
        .filter(|event| match &event.target_scope {
            Some(WorkScope::Entity(id)) => *id == entity_id,
            Some(WorkScope::Change(id)) => entity_changes.contains(id),
            _ => false,
        })
        .take(AUDIT_RETURNED)
        .map(|event| audit_event_json(&event))
        .collect::<Vec<_>>();

    let latest_change = match latest {
        Some(change) => change_summary(change, include_deltas)?,
        None => serde_json::Value::Null,
    };

    let result = serde_json::json!({
        "entity_id": id_str,
        "change_count": ordered.len(),
        "latest_change": latest_change,
        "approvals": approvals_json,
        "changes": changes,
        "offset": offset,
        "returned": returned,
        "truncated": !next_offset.is_null(),
        "next_offset": next_offset,
        "compact": !include_deltas,
        "recent_audit_events": events,
    });

    let json = serde_json::to_string_pretty(&result).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::change::EntityDelta;
    use kin_model::entity::{
        Entity, EntityKind, EntityMetadata, EntityRole, FingerprintAlgorithm, SemanticFingerprint,
        Visibility,
    };
    use kin_model::graph::{ChangeStore, EntityStore as _, ProvenanceStore};
    use kin_model::ids::{AuthorId, EntityId, GitObjectId, Hash256, LanguageId, SemanticChangeId};
    use kin_model::provenance::{
        ActorId, Approval, ApprovalDecision, ApprovalId, AuditEvent, AuditEventId,
    };
    use kin_model::timestamp::Timestamp;

    /// A timestamp written the way the response prints it, so a test's intended
    /// ordering is readable rather than derived.
    fn at(rfc3339: &str) -> Timestamp {
        serde_json::from_value(serde_json::json!(rfc3339)).expect("test timestamp must parse")
    }

    fn entity_named(name: &str, signature: &str) -> Entity {
        let zero = Hash256::from_bytes([0; 32]);
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.into(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: zero,
                signature_hash: zero,
                behavior_hash: zero,
                equivalence_hash: zero,
                stability_score: 1.0,
            },
            file_origin: None,
            span: None,
            signature: signature.into(),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    fn change(
        parent: Option<SemanticChangeId>,
        origin: ChangeOrigin,
        timestamp: Timestamp,
        author: &str,
        message: &str,
        entity_deltas: Vec<EntityDelta>,
    ) -> SemanticChange {
        let mut change = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
            origin,
            parents: parent.into_iter().collect(),
            timestamp,
            author: AuthorId::new(author),
            message: message.into(),
            entity_deltas,
            relation_deltas: vec![],
            tree_deltas: vec![],
            admission_policy_delta: parent.is_none().then(|| {
                kin_model::AdmissionPolicyDelta::initialize(
                    kin_model::SharedAdmissionPolicy::empty(0),
                )
            }),
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            external_reference_deltas: Vec::new(),
        };
        change.id = kin_model::compute_semantic_change_id(&change).unwrap();
        change
    }

    fn rendered(result: &ToolCallResult) -> &str {
        let crate::types::ContentBlock::Text { text } = &result.content[0];
        text
    }

    fn query(
        store: &kin_db::InMemoryGraph,
        entity: &EntityId,
        extra: &[(&str, serde_json::Value)],
    ) -> serde_json::Value {
        let mut args = HashMap::from([(
            "entity_id".to_string(),
            serde_json::json!(entity.to_string()),
        )]);
        for (key, value) in extra {
            args.insert((*key).to_string(), value.clone());
        }
        let result = handle_provenance_query(&args, store).unwrap();
        serde_json::from_str(rendered(&result)).unwrap()
    }

    fn is_hex_hash(value: &serde_json::Value) -> bool {
        value
            .as_str()
            .is_some_and(|s| s.len() == 64 && s.chars().all(|c| c.is_ascii_hexdigit()))
    }

    /// An imported Git commit, then an agent write on the same entity.
    ///
    /// This is the shape the defect was found in: the entity's oldest change is
    /// a Git commit from months earlier and its newest is a native write that
    /// landed minutes ago. `get_entity_history` hands back the changes oldest
    /// first, so reading the head of that list reported the Git commit and
    /// dropped the agent write entirely.
    fn git_then_agent_store() -> (kin_db::InMemoryGraph, EntityId, SemanticChangeId) {
        let store = kin_db::InMemoryGraph::new();
        let subject = entity_named("store_locate_cache", "fn store_locate_cache()");
        let mut revised = subject.clone();
        revised.signature = "fn store_locate_cache(&self) -> bool".into();

        let imported = change(
            None,
            ChangeOrigin::GitCommit {
                oid: GitObjectId::sha1([0x43; 20]),
            },
            at("2026-04-07T09:12:00Z"),
            "Troy Fortin <troy@firelock.ai>",
            "Add temporal revision graph primitives",
            vec![EntityDelta::Added {
                new: subject.clone(),
            }],
        );
        let agent = change(
            Some(imported.id),
            ChangeOrigin::Native,
            at("2026-08-10T22:45:27Z"),
            "claude-code/kin-dogfood-0517-fold <mcp-agent:9d7f1f17>",
            "Narrow the locate cache to the requested scope",
            vec![EntityDelta::Modified {
                old: subject.clone(),
                new: revised,
            }],
        );
        let agent_id = agent.id;
        store.create_change(&imported).unwrap();
        store.create_change(&agent).unwrap();
        (store, subject.id, agent_id)
    }

    #[test]
    fn latest_change_is_the_newest_write_not_the_entity_s_first() {
        let (store, entity, agent_change) = git_then_agent_store();

        let response = query(&store, &entity, &[]);

        assert_eq!(
            response["latest_change"]["id"].as_str().unwrap(),
            agent_change.to_string(),
            "latest_change must be the newest change, not the one that introduced \
             the entity: {response}"
        );
        assert!(
            response["latest_change"]["author"]
                .as_str()
                .unwrap()
                .contains("mcp-agent:"),
            "the agent that wrote last must be the author reported: {response}"
        );
        assert_eq!(response["latest_change"]["origin"]["type"], "native");
        assert_eq!(response["change_count"], 2);
    }

    /// The control the selector must not break: when an entity's newest change
    /// really is a Git commit, that is still what comes back. A fix that simply
    /// preferred native origins would pass the test above and fail this one.
    #[test]
    fn latest_change_stays_the_git_commit_when_the_git_commit_is_newest() {
        let store = kin_db::InMemoryGraph::new();
        let subject = entity_named("parse_manifest", "fn parse_manifest()");
        let mut revised = subject.clone();
        revised.signature = "fn parse_manifest(path: &Path)".into();

        let native = change(
            None,
            ChangeOrigin::Native,
            at("2026-04-07T09:12:00Z"),
            "claude-code/early-session <mcp-agent:1111>",
            "Introduce the manifest parser",
            vec![EntityDelta::Added {
                new: subject.clone(),
            }],
        );
        let imported = change(
            Some(native.id),
            ChangeOrigin::GitCommit {
                oid: GitObjectId::sha1([0x7f; 20]),
            },
            at("2026-08-10T22:45:27Z"),
            "Troy Fortin <troy@firelock.ai>",
            "Take a path argument",
            vec![EntityDelta::Modified {
                old: subject.clone(),
                new: revised,
            }],
        );
        let imported_id = imported.id;
        store.create_change(&native).unwrap();
        store.create_change(&imported).unwrap();

        let response = query(&store, &subject.id, &[]);

        assert_eq!(
            response["latest_change"]["id"].as_str().unwrap(),
            imported_id.to_string(),
            "the newest change is the Git commit here, and it must be reported: {response}"
        );
        assert_eq!(response["latest_change"]["origin"]["type"], "git_commit");
        assert_eq!(
            response["latest_change"]["origin"]["oid"].as_str().unwrap(),
            "7f".repeat(20),
            "a Git object id must print the 40-character way Git prints it, not as \
             a byte array: {response}"
        );
    }

    #[test]
    fn every_hash_the_tool_reports_is_hex() {
        let (store, entity, agent_change) = git_then_agent_store();
        store
            .record_audit_event(&AuditEvent {
                event_id: AuditEventId::from_hash(Hash256::from_bytes([0x5c; 32])),
                actor_id: ActorId::from_hash(Hash256::from_bytes([0x9a; 32])),
                action: "kin_transaction_commit".into(),
                target_scope: Some(WorkScope::Entity(entity)),
                timestamp: at("2026-08-10T22:45:27Z"),
                details: None,
            })
            .unwrap();
        // A Change-scoped event is the shape a relation-only commit records,
        // and the handler's filter deliberately keeps it; without one in the
        // fixture the target_scope rendering could regress to tagged byte
        // arrays with every assertion below still green.
        store
            .record_audit_event(&AuditEvent {
                event_id: AuditEventId::from_hash(Hash256::from_bytes([0x5d; 32])),
                actor_id: ActorId::from_hash(Hash256::from_bytes([0x9a; 32])),
                action: "kin_transaction_commit".into(),
                target_scope: Some(WorkScope::Change(agent_change)),
                timestamp: at("2026-08-10T22:46:01Z"),
                details: None,
            })
            .unwrap();
        // An approval on the newest change, for the same reason: its three ids
        // ride model serde unless the handler renders them, and the caller's
        // whole use of change_id is equality against latest_change.id.
        store
            .create_approval(&Approval {
                approval_id: ApprovalId::from_hash(Hash256::from_bytes([0x77; 32])),
                change_id: agent_change,
                approver: ActorId::from_hash(Hash256::from_bytes([0x9a; 32])),
                decision: ApprovalDecision::Approved,
                reason: "reviewed".into(),
                timestamp: at("2026-08-10T22:47:00Z"),
            })
            .unwrap();

        let response = query(&store, &entity, &[]);

        assert!(
            is_hex_hash(&response["latest_change"]["id"]),
            "a change id must be a hex string, not a byte array: {response}"
        );
        for parent in response["latest_change"]["parents"].as_array().unwrap() {
            assert!(is_hex_hash(parent), "a parent id must be hex: {response}");
        }
        for change in response["changes"].as_array().unwrap() {
            assert!(
                is_hex_hash(&change["id"]),
                "a change id must be hex: {response}"
            );
        }
        let events = response["recent_audit_events"].as_array().unwrap();
        assert!(
            !events.is_empty(),
            "the fixture recorded events: {response}"
        );
        for event in events {
            assert!(
                is_hex_hash(&event["event_id"]) && is_hex_hash(&event["actor_id"]),
                "audit ids must be hex so they can be carried back to get_actor: {response}"
            );
            assert!(
                event["target_scope"].is_string() || event["target_scope"].is_null(),
                "a target scope must be printable, never a tagged byte array: {response}"
            );
        }
        assert!(
            events.iter().any(|event| event["target_scope"]
                .as_str()
                .is_some_and(|scope| scope.starts_with("change:"))),
            "the Change-scoped event must render as change:<hex>: {response}"
        );

        let approvals = response["approvals"].as_array().unwrap();
        assert_eq!(
            approvals.len(),
            1,
            "the seeded approval must appear: {response}"
        );
        let approval = &approvals[0];
        assert!(
            is_hex_hash(&approval["approval_id"])
                && is_hex_hash(&approval["change_id"])
                && is_hex_hash(&approval["approver"]),
            "approval ids must be hex: {response}"
        );
        assert_eq!(
            approval["change_id"], response["latest_change"]["id"],
            "the approval must be comparable to the change it approves: {response}"
        );
    }

    /// A deep history whose changes carry the deltas a real commit carries.
    ///
    /// Every change here mentions the subject entity and 40 others, which is the
    /// shape a file-granular commit actually has: editing one function produces
    /// a change carrying a delta for every entity in that file. Serializing even
    /// one of those in full is what made a single-entity provenance answer five
    /// megabytes.
    fn deep_history_store(changes: usize) -> (kin_db::InMemoryGraph, EntityId) {
        let store = kin_db::InMemoryGraph::new();
        let subject = entity_named("subject", &"fn subject()".repeat(64));
        let mut parent = None;
        for index in 0..changes {
            let mut revised = subject.clone();
            revised.signature = format!("fn subject() -> u{index}{}", "x".repeat(2048));
            let mut deltas = vec![EntityDelta::Modified {
                old: subject.clone(),
                new: revised,
            }];
            for filler in 0..40 {
                deltas.push(EntityDelta::Added {
                    new: entity_named(&format!("filler_{index}_{filler}"), &"x".repeat(2048)),
                });
            }
            let next = change(
                parent,
                ChangeOrigin::Native,
                at(&format!("2026-01-{:02}T00:00:00Z", index + 1)),
                "kin-mcp-test",
                &format!("change {index}"),
                deltas,
            );
            parent = Some(next.id);
            store.create_change(&next).unwrap();
        }
        (store, subject.id)
    }

    #[test]
    fn the_default_response_is_bounded_on_a_deep_history() {
        let (store, entity) = deep_history_store(28);

        let args = HashMap::from([(
            "entity_id".to_string(),
            serde_json::json!(entity.to_string()),
        )]);
        let result = handle_provenance_query(&args, &store).unwrap();
        let bytes = rendered(&result).len();
        let response: serde_json::Value = serde_json::from_str(rendered(&result)).unwrap();

        assert!(
            bytes < 64 * 1024,
            "a single-entity provenance answer must fit in an agent's context; \
             got {bytes} bytes"
        );
        assert_eq!(
            response["changes"].as_array().unwrap().len(),
            CHANGES_DEFAULT_LIMIT as usize,
            "the default page is bounded: {}",
            &response["returned"]
        );
        assert_eq!(response["change_count"], 28);
        assert_eq!(response["truncated"], true);
        assert_eq!(response["next_offset"], 20);
        assert_eq!(response["compact"], true);
        assert!(
            response["latest_change"]["entity_deltas"].is_null(),
            "the compact default must report deltas by count, not by payload"
        );
        assert_eq!(response["latest_change"]["entity_delta_count"], 41);
    }

    #[test]
    fn the_continuation_reaches_the_oldest_change() {
        let (store, entity) = deep_history_store(28);

        let first = query(&store, &entity, &[]);
        let second = query(&store, &entity, &[("offset", first["next_offset"].clone())]);

        assert_eq!(second["returned"], 8);
        assert_eq!(
            second["next_offset"],
            serde_json::Value::Null,
            "the last page must end the continuation: {second}"
        );
        assert_eq!(second["truncated"], false);
        assert_eq!(
            second["changes"].as_array().unwrap().last().unwrap()["message"],
            "change 0",
            "paging must reach the entity's oldest change: {second}"
        );

        let first_ids = first["changes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|change| change["id"].clone())
            .collect::<HashSet<_>>();
        for change in second["changes"].as_array().unwrap() {
            assert!(
                !first_ids.contains(&change["id"]),
                "pages must not repeat a change: {second}"
            );
        }
    }

    #[test]
    fn a_smaller_page_is_honored_and_an_oversized_one_is_clamped() {
        let (store, entity) = deep_history_store(28);

        let small = query(&store, &entity, &[("limit", serde_json::json!(5))]);
        assert_eq!(small["returned"], 5);
        assert_eq!(small["next_offset"], 5);

        let oversized = query(&store, &entity, &[("limit", serde_json::json!(10_000))]);
        assert_eq!(
            oversized["returned"], 28,
            "a limit past the ceiling returns what exists, not an error: {oversized}"
        );
    }

    #[test]
    fn the_full_delta_payload_is_available_but_never_the_default() {
        let (store, entity, _) = git_then_agent_store();

        let compact = query(&store, &entity, &[]);
        assert!(compact["latest_change"]["entity_deltas"].is_null());

        let full = query(&store, &entity, &[("compact", serde_json::json!(false))]);
        assert_eq!(full["compact"], false);
        assert_eq!(
            full["latest_change"]["entity_deltas"]
                .as_array()
                .unwrap()
                .len(),
            1,
            "the explicit full mode must carry the delta payloads: {full}"
        );
        assert!(
            is_hex_hash(&full["latest_change"]["id"]),
            "the tool's own ids stay hex in full mode: {full}"
        );
    }

    #[test]
    fn an_entity_with_no_history_reports_nothing_rather_than_failing() {
        // The entity has to actually be in the graph for this to be the case it
        // names. It previously used a bare id against an empty store, which is
        // the resolution miss below rather than an emptiness, and asserting
        // success on it is what locked the two cases together.
        let store = kin_db::InMemoryGraph::new();
        let entity = entity_named("freshly_admitted", "fn freshly_admitted()");
        store.upsert_entity(&entity).unwrap();

        let response = query(&store, &entity.id, &[]);

        assert_eq!(response["change_count"], 0);
        assert!(response["latest_change"].is_null());
        assert_eq!(response["changes"].as_array().unwrap().len(), 0);
        assert_eq!(response["truncated"], false);
        assert_eq!(response["next_offset"], serde_json::Value::Null);
    }

    #[test]
    fn an_unresolvable_id_is_a_reported_miss_rather_than_an_empty_record() {
        // An id resolving to no entity with nothing recorded against it
        // returned a clean success, so a resolution failure and "no
        // provenance recorded" were the same answer on this surface while
        // get_entity_source failed loudly on the same id.
        let store = kin_db::InMemoryGraph::new();
        let fabricated = EntityId::new();
        let args = HashMap::from([(
            "entity_id".to_string(),
            serde_json::json!(fabricated.to_string()),
        )]);
        let result = handle_provenance_query(&args, &store).unwrap();

        assert_eq!(result.is_error, Some(true));
        let message = rendered(&result);
        assert!(message.contains("no entity exists with ID"), "{message}");
        assert!(
            message.contains("no provenance was looked up"),
            "the miss must say the lookup never ran: {message}"
        );

        // The message has to be one the envelope recognizes as a resolution
        // miss, or the tool fails loudly and still carries no negative object.
        let negative = crate::negative::resolution_miss_for(
            "kin_provenance_query",
            message,
            &crate::Envelope::daemon(),
        )
        .expect("the miss must carry the standard negative object");
        assert_eq!(negative["kind"], serde_json::json!("entity_not_resolved"));
        assert_eq!(negative["result_count"], serde_json::json!(0));

        // Positive control: a real entity in the same store still answers, so
        // the guard reads the id rather than refusing every call.
        let live = entity_named("still_here", "fn still_here()");
        store.upsert_entity(&live).unwrap();
        let response = query(&store, &live.id, &[]);
        assert_eq!(response["change_count"], 0);

        // Second control, and the reason the guard is a conjunction: a retired
        // entity is gone from the graph while its history survives, and its
        // provenance is exactly what a caller is entitled to ask for.
        let (history_only, retired, newest) = git_then_agent_store();
        assert!(
            history_only.get_entity(&retired).unwrap().is_none(),
            "the fixture's entity is history-only, which is what makes it the control"
        );
        let response = query(&history_only, &retired, &[]);
        assert_eq!(response["change_count"], 2);
        assert_eq!(
            response["latest_change"]["id"].as_str().unwrap(),
            newest.to_string()
        );
    }
}
