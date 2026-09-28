// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Trusted semantic qualification of DB-held binding-history transitions.
//! This proves tracking of previously observed local bindings, not completeness
//! of dynamic dispatch, imports, or parsing. All bodies come from authority CAS.

use crate::binding_debt::{
    claims_local_binding_debt, decode_local_binding_debt, LocalBindingDebt, LocalBindingObligation,
};
use kin_db::storage::binding_history::{
    BindingHistoryDecision, BindingHistoryTransition, BindingHistoryVerifier, RederivationVerifier,
    BINDING_HISTORY_PROTOCOL,
};
use kin_db::{GraphSnapshot, InMemoryGraph, KinDbError};
use kin_model::{ArtifactId, ChangeStore, FilePathId, Hash256, Relation, RepoPath, TreeEntry};
use std::collections::{BTreeMap, HashMap};

pub struct LocalBindingHistoryVerifier;

/// Select actual withdrawn bindings that the ordinary history verifier cannot
/// yet discharge. A publisher can record these exact old relations as debt
/// with the shared obligation planner, then run normal admission unchanged.
///
/// `withdrawn` must contain the exact predecessor payloads from the proposed
/// relation deltas. Selection never scans for additional candidate withdrawals.
/// Both snapshots and the CAS loader must belong to the same held publication;
/// this neither establishes a witness nor declares an obligation resolved.
/// Existing outstanding debt must still be preserved, not silently re-minted.
/// Hash-verified incomplete parses leave an obligation unaccounted; missing or
/// mismatched source evidence remains an error rather than inferred debt.
pub fn unaccounted_binding_withdrawals(
    before: &GraphSnapshot,
    after: &GraphSnapshot,
    withdrawn: &[Relation],
    load_body: &dyn Fn(Hash256) -> Result<Option<Vec<u8>>, KinDbError>,
) -> Result<Vec<Relation>, KinDbError> {
    let invalid =
        |reason: String| KinDbError::StorageError(format!("binding withdrawal planning: {reason}"));
    for relation in withdrawn {
        if before.relations.get(&relation.id) != Some(relation) {
            return Err(invalid(
                "withdrawn relation is not the exact predecessor payload".into(),
            ));
        }
    }
    let existing_debt = debts(before).map_err(invalid)?;
    let mut verifier = TransitionVerifier {
        load_body,
        parsed: HashMap::new(),
        bodies: HashMap::new(),
    };
    let unaccounted = verifier
        .unaccounted(before, after, withdrawn.iter())
        .map_err(invalid)?;
    let mut selected = Vec::new();
    for (_, obligation) in unaccounted {
        if existing_debt.values().any(|debt| {
            debt.obligations
                .iter()
                .any(|old| old.retired_relation.id == obligation.retired_relation.id)
        }) {
            return Err(invalid(
                "existing binding debt is not accounted for by the successor".into(),
            ));
        }
        if !withdrawn
            .iter()
            .any(|old| old == &obligation.retired_relation)
        {
            return Err(invalid(
                "unaccounted binding is outside the proposed withdrawals".into(),
            ));
        }
        selected.push(obligation.retired_relation);
    }
    Ok(selected)
}

/// Recheck already-recorded obligations against the same held successor that
/// will be published. Removing the debt only in this speculative view makes
/// the normal history verifier prove each occurrence instead of accepting the
/// debt itself as its accounting. Unproved obligations retain their exact bytes.
/// The caller still publishes exact deltas through normal history admission.
pub fn settled_binding_debt_deltas(
    snapshot: &GraphSnapshot,
    load_body: &dyn Fn(Hash256) -> Result<Option<Vec<u8>>, KinDbError>,
) -> Result<Vec<kin_model::RelationDelta>, KinDbError> {
    let invalid =
        |reason: String| KinDbError::StorageError(format!("binding debt revalidation: {reason}"));
    let held = debts(snapshot).map_err(invalid)?;
    if held.is_empty() {
        return Ok(vec![]);
    }
    let mut without_debt = snapshot.clone();
    without_debt.verified_binding_history = None;
    for artifact in held.keys() {
        without_debt
            .relations
            .remove(&crate::binding_debt::local_binding_debt_id(*artifact));
    }
    let mut verifier = TransitionVerifier {
        load_body,
        parsed: HashMap::new(),
        bodies: HashMap::new(),
    };
    let unaccounted = verifier
        .unaccounted(snapshot, &without_debt, std::iter::empty())
        .map_err(invalid)?;
    let mut changes = Vec::new();
    for (artifact, mut debt) in held {
        let original_count = debt.obligations.len();
        debt.obligations.retain(|obligation| {
            unaccounted.iter().any(|(file, owed)| {
                file == &debt.source_file && same_obligation(obligation, owed, file)
            })
        });
        if debt.obligations.len() == original_count {
            continue;
        }
        let id = crate::binding_debt::local_binding_debt_id(artifact);
        let old = snapshot
            .relations
            .get(&id)
            .ok_or_else(|| invalid("debt identity is absent".into()))?
            .clone();
        if debt.obligations.is_empty() {
            changes.push(kin_model::RelationDelta::Removed { old });
        } else {
            let mut new =
                crate::binding_debt::build_local_binding_debt(artifact, debt).map_err(invalid)?;
            new.created_in = old.created_in;
            changes.push(kin_model::RelationDelta::Modified { old, new });
        }
    }
    Ok(changes)
}

/// Exact captured live debt which a held publication may shrink or remove.
/// A retry can have no new semantic delta: prove any missing live obligations
/// against the durable successor's source and resolution records again. Newer
/// or otherwise unproved live obligations refuse the mirror rather than vanish.
pub fn settled_live_binding_debts(
    live: &GraphSnapshot,
    published: &GraphSnapshot,
    load_body: &dyn Fn(Hash256) -> Result<Option<Vec<u8>>, KinDbError>,
) -> Result<Vec<Relation>, KinDbError> {
    let invalid = |reason: String| {
        KinDbError::StorageError(format!("published binding debt mirror: {reason}"))
    };
    let live_debts = debts(live).map_err(invalid)?;
    let durable_debts = debts(published).map_err(invalid)?;
    let mut shrinking = Vec::new();
    for (artifact, debt) in live_debts {
        if source_entry(published, &debt.source_file).map_err(invalid)?
            != Some((artifact, debt.observed_source_digest))
        {
            return Err(invalid(
                "published debt source seal does not match the captured body".into(),
            ));
        }
        if debt.obligations.iter().all(|old| {
            durable_debts.get(&artifact).is_some_and(|new| {
                new.obligations
                    .iter()
                    .any(|new| same_obligation(old, new, &debt.source_file))
            })
        }) {
            continue;
        }
        let old = live.relations[&crate::binding_debt::local_binding_debt_id(artifact)].clone();
        shrinking.push((artifact, debt, old));
    }
    if shrinking.is_empty() {
        return Ok(vec![]);
    }
    let mut proof = published.clone();
    proof.verified_binding_history = None;
    for (_, _, old) in &shrinking {
        proof.relations.insert(old.id, old.clone());
    }
    let settled = settled_binding_debt_deltas(&proof, load_body)?;
    // A retry's captured live validation may have moved beyond the published
    // context. Both views must still settle every obligation we remove.
    let live_settled = settled_binding_debt_deltas(live, load_body)?;
    let mut authorized = Vec::new();
    for (artifact, debt, old) in shrinking {
        for settled in [&settled, &live_settled] {
            let remainder = match settled.iter().find(|change| change.target_id() == old.id) {
                Some(kin_model::RelationDelta::Removed { .. }) => Vec::new(),
                Some(kin_model::RelationDelta::Modified { new, .. }) => {
                    decode_local_binding_debt(&debt.source_file, artifact, new)
                        .map_err(invalid)?
                        .ok_or_else(|| invalid("settled debt payload is absent".into()))?
                        .obligations
                }
                _ => debt.obligations.clone(),
            };
            if remainder.iter().any(|owed| {
                !durable_debts.get(&artifact).is_some_and(|new| {
                    new.obligations
                        .iter()
                        .any(|new| same_obligation(owed, new, &debt.source_file))
                })
            }) {
                return Err(invalid(
                    "durable debt does not retain every current live obligation, and durable and live proof do not settle every omitted live obligation".into(),
                ));
            }
        }
        authorized.push(old);
    }
    Ok(authorized)
}

impl BindingHistoryVerifier for LocalBindingHistoryVerifier {
    fn verify_graph_transition(
        &self,
        before: &GraphSnapshot,
        after: &GraphSnapshot,
        load_body: &dyn Fn(Hash256) -> Result<Option<Vec<u8>>, KinDbError>,
    ) -> Result<bool, KinDbError> {
        let mut verifier = TransitionVerifier {
            load_body,
            parsed: HashMap::new(),
            bodies: HashMap::new(),
        };
        Ok(match verifier.check(before, after) {
            Ok(()) => true,
            Err(reason) => {
                tracing::debug!(%reason, "binding history derivation remains unproven");
                false
            }
        })
    }

    fn verify_transition(
        &self,
        transition: BindingHistoryTransition<'_>,
    ) -> Result<BindingHistoryDecision, KinDbError> {
        let mut workspaces = Vec::new();
        for workspace in &transition.successor().metadata().workspaces {
            let Some(_) = transition.eligibility(workspace.workspace_id) else {
                continue;
            };
            let Some(after) = transition
                .successor()
                .workspace_graph_snapshot(&workspace.workspace_id)?
            else {
                continue;
            };
            let before = transition
                .predecessor()
                .workspace_graph_snapshot(&workspace.workspace_id)?
                .unwrap_or_else(GraphSnapshot::empty);
            let load_body = |digest| transition.load_source_blob(digest);
            let mut verifier = TransitionVerifier {
                load_body: &load_body,
                parsed: HashMap::new(),
                bodies: HashMap::new(),
            };
            let result = (|| {
                verifier.check_new_history(transition)?;
                if let Some(observed) = transition.observed_predecessor(workspace.workspace_id) {
                    if !kin_db::storage::binding_history::is_checked_derivation_of(
                        &before, observed,
                    )
                    .map_err(text)?
                    {
                        return Err("live predecessor has no exact checked authority anchor".into());
                    }
                    verifier.check(&before, observed)?;
                    verifier.check(observed, &after)
                } else {
                    verifier.check(&before, &after)
                }
            })();
            match result {
                Ok(()) => workspaces.push(workspace.workspace_id),
                Err(reason) => {
                    tracing::debug!(%reason, workspace = %workspace.workspace_id,
                    "binding history remains unproven");
                }
            }
        }
        Ok(BindingHistoryDecision::Qualified {
            protocol: BINDING_HISTORY_PROTOCOL,
            workspaces,
        })
    }
}

/// Qualifies a workspace whose committed graph is exactly this build's complete
/// derivation of its own tree, starting a binding-history lineage there.
///
/// Handed only to
/// [`kin_db::RepositoryAuthorityManager::commit_rederived_repository_transaction`],
/// which `kin upgrade` calls after re-deriving every head. A lineage normally
/// has to reach back to the store's genesis, which a store written before
/// binding history existed never can. A complete re-derivation is the same
/// guarantee a genesis gives: every binding in the graph was derived together,
/// from the exact bytes the tree names, so no binding observed earlier can be
/// missing from it without the derivation being the reason.
///
/// Nothing the store supplies stands in for that. The verifier reads the
/// committed successor graph, re-derives its tree itself from authority CAS,
/// and qualifies the workspace only when every entity and every relation a
/// derivation authors is exactly what the derivation produced and the graph
/// owes no local binding debt. Relations no derivation authors, language-server
/// and manual edges and co-change edges, are neither required nor refused.
///
/// Why a graph was refused is kept, so the upgrade can say it rather than
/// only that binding history stayed unproven.
#[derive(Default)]
pub struct RederivationBindingHistoryVerifier {
    refusals: std::sync::Mutex<Vec<String>>,
}

impl RederivationBindingHistoryVerifier {
    /// Why each graph this verifier was offered and refused did not qualify,
    /// in the order they were offered.
    pub fn refusals(&self) -> Vec<String> {
        self.refusals
            .lock()
            .map(|refusals| refusals.clone())
            .unwrap_or_default()
    }
}

impl RederivationVerifier for RederivationBindingHistoryVerifier {
    fn verify_rederived_graph(
        &self,
        after: &GraphSnapshot,
        load_body: &dyn Fn(Hash256) -> Result<Option<Vec<u8>>, KinDbError>,
    ) -> Result<bool, KinDbError> {
        let mut load = |hash: Hash256| load_body(hash).map_err(text);
        match verify_rederived_graph(after, &mut load) {
            Ok(()) => Ok(true),
            Err(reason) => {
                tracing::debug!(
                    %reason,
                    "the committed graph is not an exact re-derivation of its tree; binding \
                     history stays unproven"
                );
                if let Ok(mut refusals) = self.refusals.lock() {
                    refusals.push(reason);
                }
                Ok(false)
            }
        }
    }
}

/// Whether a relation is one a derivation of source authors.
///
/// Language-server and manual edges are asserted by something other than a
/// parse, and co-change edges are mined from history, so no derivation of a
/// tree produces them and a re-derivation neither requires nor retires them.
pub fn relation_is_derived(relation: &Relation) -> bool {
    !matches!(
        relation.origin,
        kin_model::RelationOrigin::Manual | kin_model::RelationOrigin::Lsp
    ) && relation.kind != kin_model::RelationKind::CoChanges
}

/// Whether `after` is exactly this build's complete derivation of its own
/// tree, owing no local binding debt, re-derived from `load_body`.
///
/// Identity is part of the comparison. The derivation is offered `after`'s
/// entities as the identities to keep and settles to a fixed point, so a graph
/// whose identities are not the ones a derivation assigns, as well as one whose
/// payloads or edges differ, is refused.
pub fn verify_rederived_graph(
    after: &GraphSnapshot,
    load_body: &mut dyn FnMut(Hash256) -> Result<Option<Vec<u8>>, String>,
) -> Result<(), String> {
    if !debts(after)?.is_empty() {
        return Err("the graph owes local binding debt".into());
    }
    let derived = crate::history::rederive_tree_semantics_from(
        &after.resolved_tree,
        after.entities.values(),
        load_body,
    )
    .map_err(text)?;
    let differing_entities = after
        .entities
        .iter()
        .filter(|(id, entity)| derived.entities.get(id) != Some(entity))
        .count()
        + derived
            .entities
            .keys()
            .filter(|id| !after.entities.contains_key(id))
            .count();
    if differing_entities > 0 {
        return Err(format!(
            "{differing_entities} entity identities or payloads differ from a derivation of the \
             tree"
        ));
    }
    let derived_relations: BTreeMap<_, _> = after
        .relations
        .iter()
        .filter(|(_, relation)| relation_is_derived(relation))
        .collect();
    let differing_relations = derived_relations
        .iter()
        .filter(|(id, relation)| derived.relations.get(id) != Some(relation))
        .count()
        + derived
            .relations
            .keys()
            .filter(|id| !derived_relations.contains_key(id))
            .count();
    if differing_relations > 0 {
        return Err(format!(
            "{differing_relations} derived relations differ from a derivation of the tree"
        ));
    }
    Ok(())
}

struct TransitionVerifier<'a> {
    load_body: &'a dyn Fn(Hash256) -> Result<Option<Vec<u8>>, KinDbError>,
    parsed: HashMap<(FilePathId, Hash256), std::sync::Arc<crate::IndexedFile>>,
    /// The bodies `parsed` was read from, which a language-server obligation's
    /// cited token is read against.
    bodies: HashMap<Hash256, std::sync::Arc<Vec<u8>>>,
}

fn text(error: impl std::fmt::Display) -> String {
    error.to_string()
}

fn from_resolved(state: kin_model::graph::ResolvedGraphState) -> GraphSnapshot {
    let mut snapshot = GraphSnapshot::empty();
    snapshot.entities = state.entities;
    snapshot.relations = state.relations;
    snapshot.external_references = state.external_references;
    snapshot.resolved_tree = state.tree;
    snapshot
}

fn source_entry(
    snapshot: &GraphSnapshot,
    file: &FilePathId,
) -> Result<Option<(ArtifactId, Hash256)>, String> {
    let path = RepoPath::from_utf8(file.0.clone()).map_err(text)?;
    let Some(id) = snapshot.resolved_tree.artifact_id_at_path(&path) else {
        return Ok(None);
    };
    let entry = snapshot
        .resolved_tree
        .get(&id)
        .ok_or("artifact identity has no entry")?;
    match entry.entry {
        TreeEntry::Blob { hash, .. } => Ok(Some((id, hash))),
        _ => Err("binding source is not a blob".into()),
    }
}

/// A resolver may add corroboration, retire a redundant proof method, refresh
/// its context, or migrate its edge ID while retaining the same binding. This
/// proves retention only, not confidence, current resolution, or completeness.
/// Every old occurrence must keep one of its own prior corroborating records.
fn lsp_successor_retains_binding(
    before: &GraphSnapshot,
    after: &GraphSnapshot,
    old: &Relation,
    new: &Relation,
) -> bool {
    use kin_model::RelationOrigin;

    let canonical = old
        .src
        .as_entity()
        .zip(old.dst.as_entity())
        .map(|(source, target)| kin_model::language_server_relation_id(old.kind, source, target));
    if old.origin != RelationOrigin::Lsp
        || old.evidence.is_empty()
        || (new.id != old.id && Some(new.id) != canonical)
        || !old.confidence.is_finite()
        || !new.confidence.is_finite()
        || !(0.0..=1.0).contains(&old.confidence)
        || !(0.0..=1.0).contains(&new.confidence)
    {
        return false;
    }
    // Confidence can change without withdrawing the observed binding. Preserve
    // the reported successor value; every other relation-level field is exact.
    let mut normalized = new.clone();
    normalized.id = old.id;
    normalized.confidence = old.confidence;
    normalized.evidence.clone_from(&old.evidence);
    if normalized != *old {
        return false;
    }
    let (Some(source_id), Some(target_id)) = (old.src.as_entity(), old.dst.as_entity()) else {
        return false;
    };
    let (Some(source), Some(target)) = (
        before.entities.get(&source_id),
        before.entities.get(&target_id),
    ) else {
        return false;
    };
    // Both declarations and their exact admitted bodies stay fixed. Matching
    // an old byte offset in a new body is not retention of that occurrence.
    for entity in [source, target] {
        if after.entities.get(&entity.id) != Some(entity) {
            return false;
        }
        let Some(file) = entity.file_origin.as_ref() else {
            return false;
        };
        let Ok(Some((artifact, digest))) = source_entry(before, file) else {
            return false;
        };
        if source_entry(after, file) != Ok(Some((artifact, digest)))
            || entity
                .metadata
                .extra
                .get("blob_hash")
                .and_then(|value| value.as_str())
                != Some(digest.to_string().as_str())
        {
            return false;
        }
    }
    for (index, record) in old.evidence.iter().enumerate() {
        let Some(_) = record.source_span.as_ref() else {
            // Spanless records cannot be grouped as the same occurrence. Keep
            // every exact record, including its multiplicity, without refresh.
            let required = old.evidence[..=index]
                .iter()
                .filter(|old| *old == record)
                .count();
            if new.evidence.iter().filter(|new| *new == record).count() < required {
                return false;
            }
            continue;
        };
        if old.evidence[..index]
            .iter()
            .any(|prior| same_occurrence_group(record, prior))
        {
            continue;
        }
        // A new method or another site cannot substitute for lost evidence.
        // One exact old corroboration must survive at this full span and count.
        if !old
            .evidence
            .iter()
            .filter(|prior| same_occurrence_group(record, prior))
            .any(|prior| {
                new.evidence.iter().any(|current| {
                    evidence_retains_record(before, after, source.language, prior, current)
                })
            })
        {
            return false;
        }
    }
    true
}

/// Different proof methods can corroborate one occurrence. Counts, argument
/// shapes and paths describe the occurrence itself and must never be collapsed.
fn same_occurrence_group(
    left: &kin_model::RelationEvidence,
    right: &kin_model::RelationEvidence,
) -> bool {
    use kin_model::ResolutionRecordId;
    let context_token = |record: &kin_model::RelationEvidence| {
        record
            .token
            .as_deref()
            .and_then(ResolutionRecordId::from_context_token)
            .is_some()
    };
    left.source_span == right.source_span
        && left.occurrence_count == right.occurrence_count
        && left.call_shape == right.call_shape
        && left.source_path == right.source_path
        && left.resolved_path == right.resolved_path
        && (left.token == right.token || (context_token(left) && context_token(right)))
}

/// Only a token's validated context identity may differ in a retained record.
fn evidence_retains_record(
    before: &GraphSnapshot,
    after: &GraphSnapshot,
    language: kin_model::LanguageId,
    old: &kin_model::RelationEvidence,
    new: &kin_model::RelationEvidence,
) -> bool {
    use kin_model::{ResolutionRecord, ResolutionRecordId};

    if old == new {
        return true;
    }
    let mut normalized = new.clone();
    normalized.token.clone_from(&old.token);
    if normalized != *old || old.token == new.token {
        return false;
    }
    let (Some(old_id), Some(new_id)) = (
        old.token
            .as_deref()
            .and_then(ResolutionRecordId::from_context_token),
        new.token
            .as_deref()
            .and_then(ResolutionRecordId::from_context_token),
    ) else {
        return false;
    };
    let (Some(old_context), Some(new_context)) = (
        before
            .resolution_records
            .get(&old_id)
            .and_then(ResolutionRecord::as_proof_context),
        after
            .resolution_records
            .get(&new_id)
            .and_then(ResolutionRecord::as_proof_context),
    ) else {
        return false;
    };
    if old_context.language != language
        || new_context.language != language
        || ResolutionRecordId::proof_context(old_context) != old_id
        || ResolutionRecordId::proof_context(new_context) != new_id
    {
        return false;
    }
    after
        .resolution_records
        .get(&ResolutionRecordId::context_validation(language))
        .and_then(ResolutionRecord::as_context_validation)
        .is_some_and(|validation| {
            validation.language == language && validation.current_context() == Some(new_id)
        })
}

fn debts(snapshot: &GraphSnapshot) -> Result<BTreeMap<ArtifactId, LocalBindingDebt>, String> {
    let mut debts = BTreeMap::new();
    for relation in snapshot.relations.values() {
        if !claims_local_binding_debt(relation) {
            continue;
        }
        let kin_model::GraphNodeId::Artifact(artifact) = relation.src else {
            return Err("debt has no source artifact".into());
        };
        let entry = snapshot
            .resolved_tree
            .get(&artifact)
            .ok_or("debt source artifact is absent")?;
        let file = FilePathId::new(
            entry
                .path
                .as_utf8()
                .ok_or("debt source path is not UTF-8")?,
        );
        let Some(debt) = decode_local_binding_debt(&file, artifact, relation)? else {
            return Err("claimed debt is unrecognized".into());
        };
        if source_entry(snapshot, &file)?.map(|(_, hash)| hash) != Some(debt.observed_source_digest)
            || debts.insert(artifact, debt).is_some()
        {
            return Err("debt source observation is stale or duplicated".into());
        }
    }
    // A reserved identity occupied without a marker is also a refusal.
    for entry in snapshot.resolved_tree.artifacts_by_path() {
        if let Some(relation) = snapshot
            .relations
            .get(&crate::binding_debt::local_binding_debt_id(
                entry.artifact_id,
            ))
        {
            let file = FilePathId::new(
                entry
                    .path
                    .as_utf8()
                    .ok_or("reserved debt path is not UTF-8")?,
            );
            decode_local_binding_debt(&file, entry.artifact_id, relation)?;
        }
    }
    Ok(debts)
}

impl TransitionVerifier<'_> {
    fn parse(
        &mut self,
        file: &FilePathId,
        hash: Hash256,
    ) -> Result<std::sync::Arc<crate::IndexedFile>, String> {
        let key = (file.clone(), hash);
        if let Some(parsed) = self.parsed.get(&key) {
            return Ok(parsed.clone());
        }
        let bytes = (self.load_body)(hash)
            .map_err(text)?
            .ok_or("binding source CAS is absent")?;
        let digest = kin_blobs::Hash256::from_hex(&hash.to_string()).map_err(text)?;
        if kin_blobs::digest(&bytes) != digest {
            return Err("binding source CAS digest differs".into());
        }
        let file = crate::IndexPipeline::new()
            .index_file_content_with_tests(file, &bytes, digest)
            .map_err(text)?
            .indexed_file;
        let file = std::sync::Arc::new(file);
        self.parsed.insert(key, file.clone());
        self.bodies.insert(hash, std::sync::Arc::new(bytes));
        Ok(file)
    }

    /// The body a successful `parse` of `hash` read.
    fn body(&self, hash: Hash256) -> Result<std::sync::Arc<Vec<u8>>, String> {
        self.bodies
            .get(&hash)
            .cloned()
            .ok_or_else(|| "binding source body was not read".into())
    }

    fn check_new_history(
        &mut self,
        transition: BindingHistoryTransition<'_>,
    ) -> Result<(), String> {
        // A fresh store is not a fresh history. Qualify every admitted parent
        // transition; an unaccounted withdrawal anywhere leaves it Unknown.
        let changes = transition.successor().snapshot().changes.clone();
        let previous = &transition.predecessor().snapshot().changes;
        if changes.len() == previous.len() {
            return Ok(());
        }
        let candidates = if transition.transaction().changes.is_empty() {
            // Streamed Git bootstrap carries its immutable history separately.
            changes.change_ids().map_err(text)?
        } else {
            transition
                .transaction()
                .changes
                .iter()
                .map(|change| change.id)
                .collect()
        };
        let introduced: Vec<_> = candidates
            .into_iter()
            .map(|id| previous.read_change(&id).map(|old| (id, old.is_none())))
            .collect::<Result<Vec<_>, _>>()
            .map_err(text)?
            .into_iter()
            .filter_map(|(id, new)| new.then_some(id))
            .collect();
        if introduced.is_empty() {
            return Ok(());
        }
        let mut snapshot = GraphSnapshot::empty();
        snapshot.changes = changes.clone();
        let graph = InMemoryGraph::from_snapshot_without_text_index(snapshot).map_err(text)?;
        for id in introduced {
            let change = changes
                .read_change(&id)
                .map_err(text)?
                .ok_or("history change is absent")?;
            let after = from_resolved(graph.resolve_graph_at(&id).map_err(text)?);
            if change.parents.is_empty() {
                self.check(&GraphSnapshot::empty(), &after)?;
            } else {
                for parent in change.parents {
                    let before = from_resolved(graph.resolve_graph_at(&parent).map_err(text)?);
                    self.check(&before, &after)?;
                }
            }
        }
        Ok(())
    }

    fn check(&mut self, before: &GraphSnapshot, after: &GraphSnapshot) -> Result<(), String> {
        let unaccounted = self.unaccounted(before, after, before.relations.values())?;
        if let Some((current_file, obligation)) = unaccounted.first() {
            tracing::debug!(
                relation = %obligation.retired_relation.id,
                kind = ?obligation.retired_relation.kind,
                origin = ?obligation.retired_relation.origin,
                source = %obligation.retired_relation.src,
                target = %obligation.retired_relation.dst,
                source_file = %obligation.prior_source_file.as_ref()
                    .unwrap_or(current_file).0,
                current_file = %current_file.0,
                source_name = %obligation.source_name,
                target_file = %obligation.target_file.0,
                target_name = %obligation.target_name,
                source_digest = %obligation.source_digest,
                evidence = ?obligation.retired_relation.evidence.iter()
                    .map(|evidence| (&evidence.source_span, &evidence.parser_rule))
                    .collect::<Vec<_>>(),
                "prior local binding obligation was not discharged"
            );
            return Err(
                "prior local binding was neither retained, recorded, nor discharged".into(),
            );
        }
        Ok(())
    }

    fn unaccounted<'a>(
        &mut self,
        before: &GraphSnapshot,
        after: &GraphSnapshot,
        prior_relations: impl Iterator<Item = &'a Relation>,
    ) -> Result<Vec<(FilePathId, LocalBindingObligation)>, String> {
        let old_debts = debts(before)?;
        let new_debts = debts(after)?;
        let mut required: BTreeMap<ArtifactId, Vec<LocalBindingObligation>> = BTreeMap::new();
        for (artifact, mut debt) in old_debts {
            // Removed sources no longer assert anything about their callers.
            if after.resolved_tree.get(&artifact).is_some() {
                for obligation in &mut debt.obligations {
                    obligation
                        .prior_source_file
                        .get_or_insert_with(|| debt.source_file.clone());
                }
                required.insert(artifact, debt.obligations);
            }
        }
        for relation in prior_relations {
            let retained = after.relations.get(&relation.id).is_some_and(|new| {
                new == relation || lsp_successor_retains_binding(before, after, relation, new)
            }) || relation
                .src
                .as_entity()
                .zip(relation.dst.as_entity())
                .and_then(|(source, target)| {
                    after.relations.get(&kin_model::language_server_relation_id(
                        relation.kind,
                        source,
                        target,
                    ))
                })
                .is_some_and(|new| lsp_successor_retains_binding(before, after, relation, new));
            if retained {
                continue;
            }
            let (Some(source_id), Some(target_id)) =
                (relation.src.as_entity(), relation.dst.as_entity())
            else {
                continue;
            };
            let (Some(source), Some(target)) = (
                before.entities.get(&source_id),
                before.entities.get(&target_id),
            ) else {
                return Err("prior local relation has absent endpoint".into());
            };
            let (Some(source_file), Some(target_file)) = (&source.file_origin, &target.file_origin)
            else {
                continue;
            };
            if source_file == target_file {
                continue;
            }
            let (source_artifact, source_digest) =
                source_entry(before, source_file)?.ok_or("prior source artifact absent")?;
            if after.resolved_tree.get(&source_artifact).is_none() {
                continue;
            }
            let (target_artifact, _) =
                source_entry(before, target_file)?.ok_or("prior target artifact absent")?;
            if source
                .metadata
                .extra
                .get("blob_hash")
                .and_then(|v| v.as_str())
                != Some(source_digest.to_string().as_str())
            {
                return Err("prior local binding source is not current".into());
            }
            let obligation = LocalBindingObligation {
                retired_relation: relation.clone(),
                source_name: source.name.clone(),
                source_digest,
                prior_source_file: Some(source_file.clone()),
                target_artifact,
                target_file: target_file.clone(),
                target_name: target.name.clone(),
            };
            let entries = required.entry(source_artifact).or_default();
            if let Some(existing) = entries
                .iter()
                .find(|old| old.retired_relation.id == relation.id)
            {
                if !same_obligation(existing, &obligation, source_file) {
                    return Err("prior obligation identity collides".into());
                }
            } else {
                entries.push(obligation);
            }
        }
        for (artifact, debt) in &new_debts {
            let old = required
                .get(artifact)
                .ok_or("new debt has no observed predecessor binding")?;
            for obligation in &debt.obligations {
                if !old
                    .iter()
                    .any(|prior| same_obligation(prior, obligation, &debt.source_file))
                {
                    return Err("new debt does not retain the exact prior binding".into());
                }
            }
        }
        if required.is_empty() {
            return Ok(vec![]);
        }
        let graph = InMemoryGraph::from_snapshot_without_text_index(after.clone()).map_err(text)?;
        let produced: Vec<Relation> = after.relations.values().cloned().collect();
        let mut unaccounted = Vec::new();
        for (artifact, obligations) in required {
            let entry = after
                .resolved_tree
                .get(&artifact)
                .ok_or("surviving source artifact absent")?;
            let current_file = FilePathId::new(
                entry
                    .path
                    .as_utf8()
                    .ok_or("surviving source path is not UTF-8")?,
            );
            for mut obligation in obligations {
                if new_debts.get(&artifact).is_some_and(|debt| {
                    debt.obligations
                        .iter()
                        .any(|new| same_obligation(&obligation, new, &current_file))
                }) {
                    continue;
                }
                let old_file = obligation
                    .prior_source_file
                    .as_ref()
                    .unwrap_or(&current_file);
                let old = self.parse(old_file, obligation.source_digest)?;
                let old_source = self.body(obligation.source_digest)?;
                if old_file == &current_file {
                    obligation.prior_source_file = None;
                }
                let (_, current_digest) =
                    source_entry(after, &current_file)?.ok_or("current source is absent")?;
                let current = self.parse(&current_file, current_digest)?;
                let entities: Vec<_> = after
                    .entities
                    .values()
                    .filter(|entity| entity.file_origin.as_ref() == Some(&current_file))
                    .cloned()
                    .collect();
                if entities.iter().any(|entity| {
                    entity
                        .metadata
                        .extra
                        .get("blob_hash")
                        .and_then(|v| v.as_str())
                        != Some(current_digest.to_string().as_str())
                }) {
                    return Err("current source declaration body differs".into());
                }
                // A sealed partial parse is supported evidence, but cannot
                // discharge a prior binding. Preserve its exact obligation
                // without turning parser coverage into a publication error.
                // CAS and current source seals above remain mandatory.
                if !matches!(old.parse_state, kin_model::ParseState::Valid)
                    || !matches!(current.parse_state, kin_model::ParseState::Valid)
                {
                    unaccounted.push((current_file.clone(), obligation));
                    continue;
                }
                if !crate::binding_debt::obligation_is_satisfied(
                    &graph,
                    artifact,
                    &obligation,
                    &old,
                    &old_source,
                    &current,
                    &entities,
                    &produced,
                    &mut |id| Ok(after.entities.get(&id).cloned()),
                )? {
                    unaccounted.push((current_file.clone(), obligation));
                }
            }
        }
        Ok(unaccounted)
    }
}

fn same_obligation(
    left: &LocalBindingObligation,
    right: &LocalBindingObligation,
    current: &FilePathId,
) -> bool {
    left.retired_relation == right.retired_relation
        && left.source_name == right.source_name
        && left.source_digest == right.source_digest
        && left.target_artifact == right.target_artifact
        && left.target_file == right.target_file
        && left.target_name == right.target_name
        && left.prior_source_file.as_ref().unwrap_or(current)
            == right.prior_source_file.as_ref().unwrap_or(current)
}

#[cfg(test)]
mod context_refresh_tests {
    use super::*;
    use kin_model::{
        ContextValidation, ContextValidationState, EntityId, EntityKind, GraphNodeId, LanguageId,
        ProofContext, RelationEvidence, RelationId, RelationKind, RelationOrigin, ResolutionRecord,
        ResolutionRecordId, ResolvedArtifact, ResolvedTree, SourceSpan,
    };

    const SOURCE: &str = "def run(request):\n    assert request.endpoint is not None\n";
    const TARGET: &str =
        "class Request:\n    @property\n    def endpoint(self):\n        return self._endpoint\n";

    fn context(version: &str) -> ProofContext {
        ProofContext {
            language: LanguageId::Python,
            resolver: "lsp:pyright".into(),
            resolver_version: version.into(),
            configuration_hash: Hash256::from_bytes([1; 32]),
            environment_hash: Hash256::from_bytes([2; 32]),
            environment_summary: "recorded Python environment".into(),
        }
    }

    struct Fixture {
        before: GraphSnapshot,
        after: GraphSnapshot,
        relation: RelationId,
        bodies: HashMap<Hash256, Vec<u8>>,
    }

    impl Fixture {
        fn new() -> Self {
            Self::from_sources(
                SOURCE,
                TARGET,
                "run",
                "Request.endpoint",
                "endpoint",
                RelationKind::Calls,
                "lsp_call_hierarchy",
            )
        }

        fn decorator() -> Self {
            let mut fixture = Self::from_sources(
                "class Blueprint:\n    @setupmethod\n    def app_template_global(self):\n        pass\n",
                "def setupmethod(f):\n    return f\n",
                "Blueprint.app_template_global", "setupmethod", "setupmethod",
                RelationKind::References, "lsp_references",
            );
            for graph in [&mut fixture.before, &mut fixture.after] {
                graph.relations.get_mut(&fixture.relation).unwrap().evidence[0].token = None;
            }
            let edge = fixture.before.relations.get_mut(&fixture.relation).unwrap();
            let mut definition = edge.evidence[0].clone();
            definition.parser_rule = Some("lsp_definition".into());
            edge.evidence.push(definition);
            fixture
        }

        fn from_sources(
            source_body: &str,
            target_body: &str,
            source_name: &str,
            target_name: &str,
            token: &str,
            kind: RelationKind,
            rule: &str,
        ) -> Self {
            let mut before = GraphSnapshot::empty();
            let mut artifacts = Vec::new();
            let mut bodies = HashMap::new();
            for (path, body) in [("caller.py", source_body), ("target.py", target_body)] {
                let digest = kin_blobs::digest(body.as_bytes());
                let indexed = crate::IndexPipeline::new()
                    .index_file_content_with_tests(&FilePathId::new(path), body.as_bytes(), digest)
                    .unwrap()
                    .indexed_file;
                assert!(matches!(indexed.parse_state, kin_model::ParseState::Valid));
                if path == "caller.py" && kind == RelationKind::Calls {
                    assert!(
                        !indexed.extracted_relations.iter().any(|relation| {
                            relation.kind == RelationKind::Calls && relation.src_name == "run"
                        }),
                        "the real parser leaves this implicit property outside its call census"
                    );
                }
                let digest = Hash256::from_bytes(digest.0);
                bodies.insert(digest, body.as_bytes().to_vec());
                artifacts.push(ResolvedArtifact::new(
                    ArtifactId::new(),
                    RepoPath::from_utf8(path).unwrap(),
                    TreeEntry::blob(digest, false),
                ));
                before
                    .entities
                    .extend(indexed.entities.into_iter().map(|e| (e.id, e)));
            }
            before.resolved_tree = ResolvedTree::from_artifacts(artifacts).unwrap();
            let source = before
                .entities
                .values()
                .find(|e| e.name == source_name)
                .unwrap();
            let target = before
                .entities
                .values()
                .find(|e| e.name == target_name)
                .unwrap();
            let start = source_body.find(token).unwrap();
            let prefix = &source_body[..start];
            let line = u32::try_from(prefix.bytes().filter(|byte| *byte == b'\n').count()).unwrap();
            let column = u32::try_from(prefix.rsplit('\n').next().unwrap().len()).unwrap();
            let old_context = context("old");
            let old_id = ResolutionRecordId::proof_context(&old_context);
            let relation = Relation {
                id: RelationId::new(),
                kind,
                src: GraphNodeId::Entity(source.id),
                dst: GraphNodeId::Entity(target.id),
                confidence: 0.95,
                origin: RelationOrigin::Lsp,
                created_in: None,
                import_source: None,
                evidence: vec![RelationEvidence {
                    source_span: Some(SourceSpan {
                        file: FilePathId::new("caller.py"),
                        start_byte: start,
                        end_byte: start + token.len(),
                        start_line: line,
                        start_col: column,
                        end_line: line,
                        end_col: column + u32::try_from(token.len()).unwrap(),
                    }),
                    parser_rule: Some(rule.into()),
                    token: Some(old_id.context_token()),
                    ..Default::default()
                }],
            };
            let id = relation.id;
            before.relations.insert(id, relation);
            before
                .resolution_records
                .insert(old_id, ResolutionRecord::ProofContext(old_context));
            let mut after = before.clone();
            let current = context("current");
            let current_id = ResolutionRecordId::proof_context(&current);
            after
                .resolution_records
                .insert(current_id, ResolutionRecord::ProofContext(current.clone()));
            let validation = ResolutionRecord::ContextValidation(ContextValidation {
                language: LanguageId::Python,
                state: ContextValidationState::Validated { context: current },
            });
            after.resolution_records.insert(validation.id(), validation);
            after.relations.get_mut(&id).unwrap().evidence[0].token =
                Some(current_id.context_token());
            Self {
                before,
                after,
                relation: id,
                bodies,
            }
        }

        fn verifies(&self, after: &GraphSnapshot) -> bool {
            LocalBindingHistoryVerifier
                .verify_graph_transition(&self.before, after, &|digest| {
                    Ok(self.bodies.get(&digest).cloned())
                })
                .unwrap()
        }
    }

    struct RefinementFixture {
        fixture: Fixture,
        caller: EntityId,
        ledger: ResolutionRecordId,
        replacement: RelationId,
    }

    fn inferred_call_refinement_fixture(external: bool) -> RefinementFixture {
        inferred_call_refinement_body(
            external,
            "def run(options):\n    options.pop(\"a\", options.pop(\"b\", None))\n    options.pop(\"c\", None)\n",
            "run",
        )
    }

    fn inferred_call_refinement_body(
        external: bool,
        body: &str,
        caller_name: &str,
    ) -> RefinementFixture {
        use kin_model::{CallSite, CallSiteLedger, CallSiteState, ExternalReference};
        let mut before = GraphSnapshot::empty();
        let mut bodies = HashMap::new();
        let mut entries = Vec::new();
        let mut calls = Vec::new();
        for (path, content) in [
            ("caller.py", body),
            ("old.py", "class Old:\n    def pop(self):\n        pass\n"),
            (
                "actual.py",
                "class Actual:\n    def pop(self):\n        pass\n",
            ),
        ] {
            let digest = kin_blobs::digest(content.as_bytes());
            let parsed = crate::IndexPipeline::new()
                .index_file_content_with_tests(&FilePathId::new(path), content.as_bytes(), digest)
                .unwrap()
                .indexed_file;
            assert!(matches!(parsed.parse_state, kin_model::ParseState::Valid));
            if path == "caller.py" {
                calls = parsed
                    .extracted_relations
                    .into_iter()
                    .filter(|raw| {
                        raw.kind == RelationKind::Calls
                            && raw.src_name == caller_name
                            && raw.dst_name.rsplit('.').next() == Some("pop")
                    })
                    .collect();
            }
            before
                .entities
                .extend(parsed.entities.into_iter().map(|e| (e.id, e)));
            let hash = Hash256::from_bytes(digest.0);
            bodies.insert(hash, content.as_bytes().to_vec());
            entries.push(ResolvedArtifact::new(
                ArtifactId::new(),
                RepoPath::from_utf8(path).unwrap(),
                TreeEntry::blob(hash, false),
            ));
        }
        assert_eq!(calls.len(), 3);
        before.resolved_tree = ResolvedTree::from_artifacts(entries).unwrap();
        let caller = before
            .entities
            .values()
            .find(|e| {
                e.name == caller_name
                    && e.span.as_ref().is_some_and(|span| {
                        let site = calls[0].site.as_ref().unwrap();
                        span.start_byte <= site.start_byte && site.end_byte <= span.end_byte
                    })
            })
            .unwrap()
            .clone();
        let old_target = before
            .entities
            .values()
            .find(|e| e.name == "Old.pop")
            .unwrap()
            .id;
        let actual = before
            .entities
            .values()
            .find(|e| e.name == "Actual.pop")
            .unwrap()
            .id;
        let file = FilePathId::new("caller.py");
        let relation = Relation {
            id: RelationId::new(),
            kind: RelationKind::Calls,
            src: GraphNodeId::Entity(caller.id),
            dst: GraphNodeId::Entity(old_target),
            confidence: 0.5,
            origin: RelationOrigin::Inferred,
            created_in: None,
            import_source: None,
            evidence: calls
                .iter()
                .map(|raw| RelationEvidence {
                    source_span: Some(raw.site.as_ref().unwrap().to_source_span(&file)),
                    parser_rule: Some("calls".into()),
                    ..Default::default()
                })
                .collect(),
        };
        let retired = relation.id;
        before.relations.insert(retired, relation.clone());
        let mut after = before.clone();
        after.relations.remove(&retired);
        let context = context("current");
        let context_id = ResolutionRecordId::proof_context(&context);
        let validation = ResolutionRecord::ContextValidation(ContextValidation {
            language: LanguageId::Python,
            state: ContextValidationState::Validated {
                context: context.clone(),
            },
        });
        after.resolution_records.insert(validation.id(), validation);
        after
            .resolution_records
            .insert(context_id, ResolutionRecord::ProofContext(context));
        let (destination, state) = if external {
            let reference =
                ExternalReference::new_resolved("python-v1", "builtins/dict", "pop").unwrap();
            let id = reference.id;
            after.external_references.insert(id, reference);
            (
                GraphNodeId::ExternalReference(id),
                CallSiteState::ProvenExternal { target: id },
            )
        } else {
            (
                GraphNodeId::Entity(actual),
                CallSiteState::ProvenTarget { target: actual },
            )
        };
        let adapter = kin_parser::AdapterRegistry::default();
        let tree = adapter
            .get_by_language(LanguageId::Python)
            .unwrap()
            .parse(body.as_bytes())
            .unwrap();
        let mut sites = Vec::new();
        let mut evidence = Vec::new();
        for raw in calls {
            let span = raw.site.unwrap().to_source_span(&file);
            let call = tree
                .root_node()
                .named_descendant_for_byte_range(span.start_byte, span.end_byte)
                .unwrap();
            let token = call
                .child_by_field_name("function")
                .unwrap()
                .child_by_field_name("attribute")
                .unwrap();
            let token_span = kin_parser::adapter::span_from_node(&token, &file);
            let (offset, length) = kin_model::site_key(
                caller.span.as_ref().unwrap().start_byte,
                token_span.start_byte,
                token_span.end_byte,
            )
            .unwrap();
            sites.push(CallSite {
                offset,
                length,
                state: state.clone(),
            });
            evidence.push(RelationEvidence {
                source_span: Some(token_span),
                parser_rule: Some("lsp_definition".into()),
                token: Some(context_id.context_token()),
                ..Default::default()
            });
        }
        sites.sort_by_key(|site| site.key());
        let replacement = Relation {
            id: RelationId::new(),
            dst: destination,
            origin: RelationOrigin::Lsp,
            confidence: 1.0,
            evidence,
            ..relation
        };
        let replacement_id = replacement.id;
        after.relations.insert(replacement.id, replacement);
        let record = ResolutionRecord::CallSites(CallSiteLedger {
            caller: caller.id,
            behavior_hash: caller.fingerprint.behavior_hash,
            body_hash: source_entry(&after, &file).unwrap().unwrap().1,
            context: context_id,
            census: sites.len() as u32,
            sites,
        });
        let ledger = record.id();
        after.resolution_records.insert(ledger, record);
        RefinementFixture {
            fixture: Fixture {
                before,
                after,
                relation: retired,
                bodies,
            },
            caller: caller.id,
            ledger,
            replacement: replacement_id,
        }
    }

    #[test]
    fn inferred_call_refinement_proves_each_exact_callee_to_local_or_external_target() {
        for external in [false, true] {
            let case = inferred_call_refinement_fixture(external);
            assert!(case.fixture.verifies(&case.fixture.after));
            let old = case.fixture.before.relations[&case.fixture.relation].clone();
            assert!(classify(&case.fixture, &case.fixture.after, &[old])
                .unwrap()
                .is_empty());
        }
    }

    #[test]
    fn inferred_call_refinement_uses_exact_getter_occurrences_among_same_named_methods() {
        let body = "class SessionMixin:\n    @property\n    def permanent(self):\n        self.pop(\"a\", self.pop(\"b\", None))\n        return self.pop(\"c\", None)\n\n    @permanent.setter\n    def permanent(self, value):\n        self[\"permanent\"] = value\n";
        let case = inferred_call_refinement_body(true, body, "SessionMixin.permanent");
        assert_eq!(
            case.fixture
                .after
                .entities
                .values()
                .filter(|e| e.name == "SessionMixin.permanent")
                .count(),
            2
        );
        assert!(case.fixture.verifies(&case.fixture.after));
        let debt = debt_for_withdrawal(&case.fixture);
        let mut held = case.fixture.after.clone();
        held.relations.insert(debt.id, debt.clone());
        assert_eq!(
            settled_binding_debt_deltas(&held, &|hash| Ok(case.fixture.bodies.get(&hash).cloned()))
                .unwrap(),
            vec![kin_model::RelationDelta::Removed { old: debt }]
        );
        // Even a valid getter ledger cannot authorize an equally placed sibling
        // or crossing ownership interval. These are not uniquely owned sites.
        for crossing in [false, true] {
            let mut after = case.fixture.after.clone();
            let mut duplicate = after.entities[&case.caller].clone();
            duplicate.id = EntityId::new();
            if crossing {
                let span = duplicate.span.as_mut().unwrap();
                span.start_byte += 1;
                span.end_byte += 1;
            }
            after.entities.insert(duplicate.id, duplicate);
            assert!(!case.fixture.verifies(&after), "crossing={crossing}");
        }
    }

    #[test]
    fn inferred_call_refinement_refuses_unverified_stale_or_unbacked_answers() {
        for control in 0..10 {
            let mut case = inferred_call_refinement_fixture(false);
            let after = &mut case.fixture.after;
            match control {
                0 => {
                    after
                        .resolution_records
                        .remove(&ResolutionRecordId::context_validation(LanguageId::Python));
                }
                1 => {
                    let validation = ResolutionRecord::ContextValidation(ContextValidation {
                        language: LanguageId::Python,
                        state: ContextValidationState::Validated {
                            context: context("other"),
                        },
                    });
                    after.resolution_records.insert(validation.id(), validation);
                }
                2 => {
                    if let ResolutionRecord::CallSites(ledger) =
                        after.resolution_records.get_mut(&case.ledger).unwrap()
                    {
                        ledger.body_hash = Hash256::from_bytes([17; 32]);
                    }
                }
                3 => {
                    if let ResolutionRecord::CallSites(ledger) =
                        after.resolution_records.get_mut(&case.ledger).unwrap()
                    {
                        ledger.behavior_hash = Hash256::from_bytes([18; 32]);
                    }
                }
                4 => {
                    after.relations.get_mut(&case.replacement).unwrap().origin =
                        RelationOrigin::Inferred;
                }
                5 => {
                    after.relations.get_mut(&case.replacement).unwrap().evidence[0].token = None;
                }
                6 => {
                    after
                        .relations
                        .get_mut(&case.replacement)
                        .unwrap()
                        .evidence
                        .remove(0);
                }
                7 => {
                    after
                        .entities
                        .get_mut(&case.caller)
                        .unwrap()
                        .metadata
                        .extra
                        .insert(
                            "blob_hash".into(),
                            serde_json::json!(Hash256::from_bytes([19; 32]).to_string()),
                        );
                }
                8 => {
                    let context_id = if let ResolutionRecord::CallSites(ledger) =
                        &after.resolution_records[&case.ledger]
                    {
                        ledger.context
                    } else {
                        unreachable!()
                    };
                    after.resolution_records.remove(&context_id);
                }
                9 => {
                    if let ResolutionRecord::CallSites(ledger) =
                        after.resolution_records.get_mut(&case.ledger).unwrap()
                    {
                        ledger.sites[0].state =
                            kin_model::CallSiteState::Binding { may_call: None };
                    }
                }
                _ => unreachable!(),
            }
            assert!(
                !case.fixture.verifies(&case.fixture.after),
                "control {control}"
            );
        }
    }

    #[test]
    fn inferred_call_refinement_never_uses_a_nested_argument_or_weakens_stronger_origins() {
        let mut case = inferred_call_refinement_fixture(false);
        let ResolutionRecord::CallSites(ledger) = case
            .fixture
            .after
            .resolution_records
            .get_mut(&case.ledger)
            .unwrap()
        else {
            unreachable!()
        };
        // The inner pop is proven but the enclosing call is not. Identical
        // spelling inside the arguments cannot discharge the outer occurrence.
        ledger.sites[0].state = kin_model::CallSiteState::Unresolved {
            reason: kin_model::UnresolvedReason::NoAnswer,
        };
        assert!(!case.fixture.verifies(&case.fixture.after));
        for origin in [
            RelationOrigin::Lsp,
            RelationOrigin::Manual,
            RelationOrigin::Parsed,
        ] {
            let mut case = inferred_call_refinement_fixture(false);
            case.fixture
                .before
                .relations
                .get_mut(&case.fixture.relation)
                .unwrap()
                .origin = origin;
            assert!(!case.fixture.verifies(&case.fixture.after), "{origin:?}");
        }
    }

    #[test]
    fn existing_binding_debt_rechecks_current_proof_without_new_withdrawals() {
        let mut case = inferred_call_refinement_fixture(true);
        let debt = debt_for_withdrawal(&case.fixture);
        let mut held = case.fixture.after.clone();
        held.relations.insert(debt.id, debt.clone());
        let load = |digest| Ok(case.fixture.bodies.get(&digest).cloned());
        let changes = settled_binding_debt_deltas(&held, &load).unwrap();
        assert_eq!(
            changes,
            vec![kin_model::RelationDelta::Removed { old: debt.clone() }]
        );
        assert!(LocalBindingHistoryVerifier
            .verify_graph_transition(&held, &case.fixture.after, &load)
            .unwrap());
        // No new current-context proof leaves the exact existing debt intact.
        held.resolution_records.remove(&case.ledger);
        assert!(settled_binding_debt_deltas(&held, &load)
            .unwrap()
            .is_empty());
        // A single remaining occurrence keeps the whole old obligation owed.
        let record = case
            .fixture
            .after
            .resolution_records
            .get_mut(&case.ledger)
            .expect("the fixture retains its call-site ledger");
        let ResolutionRecord::CallSites(ledger) = record else {
            unreachable!()
        };
        ledger.sites[0].state = kin_model::CallSiteState::ProvenOutside;
        case.fixture.after.relations.insert(debt.id, debt);
        assert!(
            settled_binding_debt_deltas(&case.fixture.after, &|digest| Ok(case
                .fixture
                .bodies
                .get(&digest)
                .cloned()))
            .unwrap()
            .is_empty()
        );
    }

    #[test]
    fn inferred_call_refinement_requires_the_same_source_digest_even_with_current_proof() {
        let mut case = inferred_call_refinement_fixture(false);
        let file = FilePathId::new("caller.py");
        let (_, old_digest) = source_entry(&case.fixture.after, &file).unwrap().unwrap();
        let body = String::from_utf8(case.fixture.bodies[&old_digest].clone())
            .unwrap()
            .replace("\"a\"", "\"z\"");
        let digest = kin_blobs::digest(body.as_bytes());
        let parsed = crate::IndexPipeline::new()
            .index_file_content_with_tests(&file, body.as_bytes(), digest)
            .unwrap()
            .indexed_file;
        let hash = Hash256::from_bytes(digest.0);
        case.fixture.bodies.insert(hash, body.into_bytes());
        let fresh = parsed
            .entities
            .into_iter()
            .find(|entity| entity.name == "run")
            .unwrap();
        let caller = case.fixture.after.entities.get_mut(&case.caller).unwrap();
        caller.fingerprint = fresh.fingerprint;
        caller.metadata = fresh.metadata;
        let ResolutionRecord::CallSites(ledger) = case
            .fixture
            .after
            .resolution_records
            .get_mut(&case.ledger)
            .unwrap()
        else {
            unreachable!()
        };
        ledger.body_hash = hash;
        ledger.behavior_hash = caller.fingerprint.behavior_hash;
        let entries: Vec<_> = case
            .fixture
            .after
            .resolved_tree
            .artifacts_by_path()
            .map(|entry| {
                let mut entry = entry.clone();
                if entry.path.as_utf8() == Some("caller.py") {
                    entry.entry = TreeEntry::blob(hash, false);
                }
                entry
            })
            .collect();
        case.fixture.after.resolved_tree = ResolvedTree::from_artifacts(entries).unwrap();
        assert!(!case.fixture.verifies(&case.fixture.after));
    }

    #[test]
    fn binding_debt_cleanup_preserves_each_unsettled_obligation_exactly() {
        let case = inferred_call_refinement_fixture(false);
        let full = debt_for_withdrawal(&case.fixture);
        let artifact = match full.src {
            GraphNodeId::Artifact(artifact) => artifact,
            _ => unreachable!(),
        };
        let mut debt = decode_local_binding_debt(&FilePathId::new("caller.py"), artifact, &full)
            .unwrap()
            .unwrap();
        let mut uncertain = debt.obligations[0].clone();
        uncertain
            .retired_relation
            .evidence
            .sort_by_key(|e| e.source_span.as_ref().unwrap().start_byte);
        let mut settled = uncertain.clone();
        settled.retired_relation.id = RelationId::new();
        settled.retired_relation.evidence =
            vec![uncertain.retired_relation.evidence.pop().unwrap()];
        uncertain.retired_relation.evidence.truncate(1);
        debt.obligations = vec![uncertain.clone(), settled];
        let held_debt = crate::binding_debt::build_local_binding_debt(artifact, debt).unwrap();
        let mut held = case.fixture.after.clone();
        held.relations.insert(held_debt.id, held_debt.clone());
        let ResolutionRecord::CallSites(ledger) =
            held.resolution_records.get_mut(&case.ledger).unwrap()
        else {
            unreachable!()
        };
        ledger.sites[0].state = kin_model::CallSiteState::Binding { may_call: None };
        let load = |digest| Ok(case.fixture.bodies.get(&digest).cloned());
        let changes = settled_binding_debt_deltas(&held, &load).unwrap();
        let [kin_model::RelationDelta::Modified { old, new }] = changes.as_slice() else {
            panic!("{changes:?}")
        };
        assert_eq!(old, &held_debt);
        let remaining = decode_local_binding_debt(&FilePathId::new("caller.py"), artifact, new)
            .unwrap()
            .unwrap();
        assert_eq!(remaining.obligations, vec![uncertain]);
        let mut after = held.clone();
        after.relations.insert(new.id, new.clone());
        assert!(LocalBindingHistoryVerifier
            .verify_graph_transition(&held, &after, &load)
            .unwrap());
    }

    #[test]
    fn published_binding_debt_mirror_rechecks_live_validation_and_new_obligations() {
        let case = inferred_call_refinement_fixture(false);
        let debt = debt_for_withdrawal(&case.fixture);
        let mut live = case.fixture.after.clone();
        live.relations.insert(debt.id, debt.clone());
        let load = |digest| Ok(case.fixture.bodies.get(&digest).cloned());
        assert_eq!(
            settled_live_binding_debts(&live, &case.fixture.after, &load).unwrap(),
            vec![debt.clone()]
        );
        let mut reintroduced = live.clone();
        let mut old_guess = case.fixture.before.relations[&case.fixture.relation].clone();
        old_guess.id = RelationId::new();
        reintroduced.relations.insert(old_guess.id, old_guess);
        assert!(
            settled_live_binding_debts(&reintroduced, &case.fixture.after, &load).is_err(),
            "the exact weak occurrence must be retired before its live debt can clear"
        );
        let mut unverified = live.clone();
        let validation = ResolutionRecord::ContextValidation(ContextValidation {
            language: LanguageId::Python,
            state: ContextValidationState::Unverified {
                reason: "resolver changed after publication".into(),
            },
        });
        unverified
            .resolution_records
            .insert(validation.id(), validation);
        assert!(settled_live_binding_debts(&unverified, &case.fixture.after, &load).is_err());
        let artifact = match debt.src {
            GraphNodeId::Artifact(artifact) => artifact,
            _ => unreachable!(),
        };
        let mut newer = decode_local_binding_debt(&FilePathId::new("caller.py"), artifact, &debt)
            .unwrap()
            .unwrap();
        let mut added = newer.obligations[0].clone();
        added.retired_relation.id = RelationId::new();
        added.retired_relation.origin = RelationOrigin::Lsp;
        newer.obligations.push(added);
        let newer = crate::binding_debt::build_local_binding_debt(artifact, newer).unwrap();
        live.relations.insert(newer.id, newer);
        assert!(
            settled_live_binding_debts(&live, &case.fixture.after, &load).is_err(),
            "new strong live evidence cannot be erased by an older publication"
        );
    }

    fn legacy_range_fixture(source_body: &str) -> Fixture {
        let mut fixture = Fixture::from_sources(
            source_body,
            TARGET,
            "run",
            "Request.endpoint",
            "endpoint",
            RelationKind::Calls,
            "lsp_call_hierarchy",
        );
        // Before source-byte spans existed, real server ranges kept zero-based
        // lines and UTF-16 columns, with byte offsets 0..0 and no context token.
        // Context stamping was introduced only after real-byte spans.
        let record = &mut fixture
            .before
            .relations
            .get_mut(&fixture.relation)
            .unwrap()
            .evidence[0];
        record.token = None;
        let span = record.source_span.as_mut().unwrap();
        assert_eq!(&source_body[span.start_byte..span.end_byte], "endpoint");
        let line = source_body.lines().nth(span.start_line as usize).unwrap();
        span.start_col = line[..span.start_col as usize].encode_utf16().count() as u32;
        span.end_col = line[..span.end_col as usize].encode_utf16().count() as u32;
        span.start_byte = 0;
        span.end_byte = 0;
        fixture.before.resolution_records.clear();
        fixture
    }

    #[test]
    fn binding_history_retains_untyped_legacy_ranges_through_canonical_rekey() {
        for source_body in [
            SOURCE,
            "def run(request):\n    label = \"é😀\"; assert request.endpoint is not None\n",
        ] {
            let fixture = legacy_range_fixture(source_body);
            let old = fixture.before.relations[&fixture.relation].clone();
            let offered = fixture.after.relations[&fixture.relation].clone();
            assert!(offered.evidence[0].source_span.as_ref().unwrap().end_byte > 0);
            assert!(offered.evidence[0].token.is_some());
            for append_current in [false, true] {
                let mut after = fixture.after.clone();
                after.relations.remove(&old.id);
                let mut merged = old.clone();
                merged.id = kin_model::language_server_relation_id(
                    old.kind,
                    old.src.as_entity().unwrap(),
                    old.dst.as_entity().unwrap(),
                );
                // The union preserves the old untyped record. A fresh ledger
                // can additionally carry its exact current proof. Neither
                // outcome restamps the legacy range or loses its history.
                if append_current {
                    merged.evidence.extend(offered.evidence.clone());
                }
                after.relations.insert(merged.id, merged);
                assert!(classify(&fixture, &after, std::slice::from_ref(&old))
                    .unwrap()
                    .is_empty());
                assert!(fixture.verifies(&after));
            }
        }
    }

    #[test]
    fn binding_history_forced_legacy_range_withdrawal_remains_a_policy_boundary() {
        let fixture = legacy_range_fixture(SOURCE);
        let old = fixture.before.relations[&fixture.relation].clone();
        // Deliberately force replacement of the old record. The ordinary union
        // preserves it, so this is a withdrawal-policy boundary, not evidence
        // that a shipped producer performs this transition during a refresh.
        assert_eq!(
            classify(&fixture, &fixture.after, std::slice::from_ref(&old)).unwrap(),
            vec![old.clone()]
        );
        assert!(!fixture.verifies(&fixture.after));
        let source = &fixture.before.entities[&old.src.as_entity().unwrap()];
        let target = &fixture.before.entities[&old.dst.as_entity().unwrap()];
        let source_file = source.file_origin.clone().unwrap();
        let target_file = target.file_origin.clone().unwrap();
        let (artifact, digest) = source_entry(&fixture.before, &source_file)
            .unwrap()
            .unwrap();
        let (target_artifact, _) = source_entry(&fixture.before, &target_file)
            .unwrap()
            .unwrap();
        let error = crate::binding_debt::build_local_binding_debt(
            artifact,
            LocalBindingDebt {
                source_file,
                observed_source_digest: digest,
                obligations: vec![LocalBindingObligation {
                    retired_relation: old,
                    source_name: source.name.clone(),
                    source_digest: digest,
                    prior_source_file: None,
                    target_artifact,
                    target_file,
                    target_name: target.name.clone(),
                }],
            },
        )
        .unwrap_err();
        assert_eq!(
            error,
            "binding debt contains an invalid or duplicated prior local binding"
        );
    }

    #[test]
    fn binding_history_retains_only_exact_validated_property_context_refresh() {
        let fixture = Fixture::new();
        assert!(
            fixture.verifies(&fixture.after),
            "a context refresh retains this exact implicit property binding"
        );
        let mut changed = fixture.after.clone();
        changed.relations.get_mut(&fixture.relation).unwrap().dst = GraphNodeId::Entity(
            changed
                .entities
                .values()
                .find(|e| e.kind == EntityKind::Class)
                .unwrap()
                .id,
        );
        assert!(
            !fixture.verifies(&changed),
            "a different target is not retention"
        );

        for case in ["span", "dropped", "rule", "count", "lexical token"] {
            let mut changed = fixture.after.clone();
            let edge = changed.relations.get_mut(&fixture.relation).unwrap();
            match case {
                "span" => edge.evidence[0].source_span.as_mut().unwrap().start_byte += 1,
                "dropped" => edge.evidence.clear(),
                "rule" => edge.evidence[0].parser_rule = Some("other_rule".into()),
                "count" => edge.evidence[0].occurrence_count += 1,
                "lexical token" => edge.evidence[0].token = Some("endpoint".into()),
                _ => unreachable!(),
            }
            assert!(
                !fixture.verifies(&changed),
                "changed {case} must use strict obligation proof"
            );
        }
    }

    #[test]
    fn binding_history_context_refresh_requires_both_contexts_and_current_validation() {
        let fixture = Fixture::new();
        let current = ResolutionRecordId::proof_context(&context("current"));
        let validation_id = ResolutionRecordId::context_validation(LanguageId::Python);
        let mut missing_context = fixture.after.clone();
        missing_context.resolution_records.remove(&current);
        assert!(!fixture.verifies(&missing_context));
        let mut missing_validation = fixture.after.clone();
        missing_validation.resolution_records.remove(&validation_id);
        assert!(!fixture.verifies(&missing_validation));
        for state in [
            ContextValidationState::Unverified {
                reason: "server not measured".into(),
            },
            ContextValidationState::Validated {
                context: context("newer"),
            },
        ] {
            let mut stale = fixture.after.clone();
            stale.resolution_records.insert(
                validation_id,
                ResolutionRecord::ContextValidation(ContextValidation {
                    language: LanguageId::Python,
                    state,
                }),
            );
            assert!(
                !fixture.verifies(&stale),
                "unverified or superseded context cannot qualify refresh"
            );
        }
        let mut missing_old = Fixture::new();
        missing_old.before.resolution_records.clear();
        assert!(!missing_old.verifies(&missing_old.after));
    }

    #[test]
    fn binding_history_context_refresh_does_not_reuse_offsets_after_source_or_target_changes() {
        let fixture = Fixture::new();
        for path in ["caller.py", "target.py"] {
            let mut changed = fixture.after.clone();
            let artifacts = changed
                .resolved_tree
                .artifacts()
                .cloned()
                .map(|mut artifact| {
                    if artifact.path.as_utf8() == Some(path) {
                        artifact.entry = TreeEntry::blob(Hash256::from_bytes([9; 32]), false);
                    }
                    artifact
                });
            changed.resolved_tree = ResolvedTree::from_artifacts(artifacts).unwrap();
            assert!(
                !fixture.verifies(&changed),
                "changed admitted body at {path} cannot reuse old offsets"
            );
        }
        let mut changed = fixture.after.clone();
        let source = changed.relations[&fixture.relation]
            .src
            .as_entity()
            .unwrap();
        changed
            .entities
            .get_mut(&source)
            .unwrap()
            .metadata
            .extra
            .remove("blob_hash");
        assert!(
            !fixture.verifies(&changed),
            "an unbound source declaration cannot qualify retention"
        );
    }

    #[test]
    fn binding_history_retains_decorator_occurrences_with_remaining_corroboration() {
        let fixture = Fixture::decorator();
        assert!(
            fixture.verifies(&fixture.after),
            "retiring definition corroboration keeps the identical references proof"
        );
        let mut refined = fixture.after.clone();
        let edge = refined.relations.get_mut(&fixture.relation).unwrap();
        edge.confidence = 0.85;
        let mut added = edge.evidence[0].clone();
        added.parser_rule = Some("lsp_member_on_module".into());
        edge.evidence.push(added);
        assert!(
            fixture.verifies(&refined),
            "weaker reported confidence does not withdraw the binding"
        );
        assert_eq!(refined.relations[&fixture.relation].confidence, 0.85);

        let mut removed = refined.clone();
        removed
            .relations
            .get_mut(&fixture.relation)
            .unwrap()
            .evidence
            .retain(|record| record.parser_rule.as_deref() != Some("lsp_references"));
        assert!(
            !lsp_successor_retains_binding(
                &fixture.before,
                &removed,
                &fixture.before.relations[&fixture.relation],
                &removed.relations[&fixture.relation],
            ),
            "a new method alone cannot use the prior-corroboration retention shortcut"
        );
        assert!(
            fixture.verifies(&removed),
            "the parser-recorded decorator can independently re-resolve to its retained target"
        );

        // Unlike the decorator, this implicit property has no parser occurrence
        // that can independently discharge replacement of every prior method.
        let implicit = Fixture::new();
        let mut replaced = implicit.after.clone();
        replaced
            .relations
            .get_mut(&implicit.relation)
            .unwrap()
            .evidence[0]
            .parser_rule = Some("lsp_member_on_module".into());
        assert!(
            !implicit.verifies(&replaced),
            "a new method without a prior corroboration or independent occurrence proof stays owed"
        );
    }

    #[test]
    fn binding_history_retention_tracks_full_occurrence_shape_and_multiplicity() {
        for case in [
            "count",
            "shape",
            "source path",
            "resolved path",
            "lexical token",
            "line",
            "byte",
        ] {
            let mut fixture = Fixture::new();
            let edge = fixture.before.relations.get_mut(&fixture.relation).unwrap();
            let mut extra = edge.evidence[0].clone();
            extra.parser_rule = Some("lsp_other_corroboration".into());
            match case {
                "count" => extra.occurrence_count += 2,
                "shape" => {
                    extra.call_shape = Some(kin_model::CallArgShape::new(1, vec![], false, false))
                }
                "source path" => extra.source_path = Some("request".into()),
                "resolved path" => extra.resolved_path = Some("target.py".into()),
                "lexical token" => extra.token = Some("endpoint".into()),
                "line" => extra.source_span.as_mut().unwrap().start_line += 1,
                "byte" => extra.source_span.as_mut().unwrap().start_byte += 1,
                _ => unreachable!(),
            }
            edge.evidence.push(extra);
            assert!(
                !fixture.verifies(&fixture.after),
                "the surviving same-span proof cannot hide a different {case} witness"
            );
        }
    }

    #[test]
    fn binding_history_retention_never_substitutes_an_added_occurrence() {
        let fixture = Fixture::new();
        let mut added = fixture.after.clone();
        let edge = added.relations.get_mut(&fixture.relation).unwrap();
        let mut another = edge.evidence[0].clone();
        another.source_span.as_mut().unwrap().start_byte += 1;
        another.source_span.as_mut().unwrap().start_col += 1;
        edge.evidence.push(another.clone());
        edge.confidence = 0.85;
        assert!(
            fixture.verifies(&added),
            "a new occurrence does not remove the old one"
        );
        edge_remove_prior(&mut added, fixture.relation, another);
        assert!(
            !fixture.verifies(&added),
            "confidence refinement and a new site cannot cover a lost old occurrence"
        );
        for confidence in [f32::NAN, f32::INFINITY, -0.1, 1.1] {
            let mut invalid = fixture.after.clone();
            invalid
                .relations
                .get_mut(&fixture.relation)
                .unwrap()
                .confidence = confidence;
            assert!(
                !fixture.verifies(&invalid),
                "invalid confidence cannot qualify retention"
            );
        }
    }

    fn edge_remove_prior(graph: &mut GraphSnapshot, id: RelationId, only: RelationEvidence) {
        graph.relations.get_mut(&id).unwrap().evidence = vec![only];
    }

    #[test]
    fn binding_history_retention_requires_exact_spanless_records() {
        let mut fixture = Fixture::new();
        let mut spanless = fixture.before.relations[&fixture.relation].evidence[0].clone();
        spanless.source_span = None;
        fixture
            .before
            .relations
            .get_mut(&fixture.relation)
            .unwrap()
            .evidence
            .extend([spanless.clone(), spanless.clone()]);
        let mut retained = fixture.after.clone();
        retained
            .relations
            .get_mut(&fixture.relation)
            .unwrap()
            .evidence
            .push(spanless.clone());
        assert!(
            !fixture.verifies(&retained),
            "spanless duplicates must not collapse"
        );
        retained
            .relations
            .get_mut(&fixture.relation)
            .unwrap()
            .evidence
            .push(spanless);
        assert!(fixture.verifies(&retained));
        let token = retained.relations[&fixture.relation].evidence[0]
            .token
            .clone();
        retained
            .relations
            .get_mut(&fixture.relation)
            .unwrap()
            .evidence[1]
            .token = token;
        assert!(
            !fixture.verifies(&retained),
            "even validated refresh cannot place spanless evidence"
        );
    }

    #[test]
    fn binding_history_retention_recognizes_only_canonical_language_server_migration() {
        let fixture = Fixture::new();
        let mut migrated = fixture.after.clone();
        let mut edge = migrated.relations.remove(&fixture.relation).unwrap();
        edge.id = kin_model::language_server_relation_id(
            edge.kind,
            edge.src.as_entity().unwrap(),
            edge.dst.as_entity().unwrap(),
        );
        let canonical = edge.id;
        migrated.relations.insert(canonical, edge.clone());
        assert!(
            fixture.verifies(&migrated),
            "the exact production identity can retain an old edge"
        );
        migrated.relations.remove(&canonical);
        edge.id = RelationId::new();
        migrated.relations.insert(edge.id, edge.clone());
        assert!(
            !fixture.verifies(&migrated),
            "an arbitrary replacement ID is not migration"
        );
        migrated.relations.remove(&edge.id);
        edge.id = RelationId::resolver(edge.kind, &edge.src, &edge.dst);
        migrated.relations.insert(edge.id, edge);
        assert!(
            !fixture.verifies(&migrated),
            "the external resolver domain is not the LSP identity"
        );
    }

    #[test]
    fn binding_history_retention_preserves_existing_outstanding_debt() {
        let mut fixture = Fixture::new();
        let relation = fixture.before.relations[&fixture.relation].clone();
        let source = &fixture.before.entities[&relation.src.as_entity().unwrap()];
        let target = &fixture.before.entities[&relation.dst.as_entity().unwrap()];
        let file = source.file_origin.clone().unwrap();
        let target_file = target.file_origin.clone().unwrap();
        let (artifact, digest) = source_entry(&fixture.before, &file).unwrap().unwrap();
        let (target_artifact, _) = source_entry(&fixture.before, &target_file)
            .unwrap()
            .unwrap();
        let debt = crate::binding_debt::build_local_binding_debt(
            artifact,
            LocalBindingDebt {
                source_file: file,
                observed_source_digest: digest,
                obligations: vec![LocalBindingObligation {
                    retired_relation: relation,
                    source_name: source.name.clone(),
                    source_digest: digest,
                    prior_source_file: None,
                    target_artifact,
                    target_file,
                    target_name: target.name.clone(),
                }],
            },
        )
        .unwrap();
        fixture.before.relations.insert(debt.id, debt.clone());
        assert!(
            !fixture.verifies(&fixture.after),
            "retention of an edge does not silently discharge a recorded old debt"
        );
        let mut retained = fixture.after.clone();
        retained.relations.insert(debt.id, debt);
        assert!(
            fixture.verifies(&retained),
            "exact outstanding debt remains accounted for"
        );
    }

    fn classify(
        fixture: &Fixture,
        after: &GraphSnapshot,
        withdrawn: &[Relation],
    ) -> Result<Vec<Relation>, KinDbError> {
        unaccounted_binding_withdrawals(&fixture.before, after, withdrawn, &|digest| {
            Ok(fixture.bodies.get(&digest).cloned())
        })
    }

    fn partial_parse_withdrawal_fixture(old_partial: bool, current_partial: bool) -> Fixture {
        // This is the real incomplete-Python pipeline fixture. It retains
        // caller entities and a positional call despite the unclosed call.
        const PARTIAL: &str = "def target(ext, args):\n    return ext, args\n\n\ndef caller():\n    target(1, 2)\n    return target(3, args=4\n";
        let valid = PARTIAL.replace("args=4\n", "args=4)\n");
        let mut fixture = Fixture::from_sources(
            &valid,
            "def external_target():\n    pass\n",
            "caller",
            "external_target",
            "target(1, 2)",
            RelationKind::Calls,
            "lsp_call_hierarchy",
        );
        for (graph, partial) in [
            (&mut fixture.before, old_partial),
            (&mut fixture.after, current_partial),
        ] {
            let body = if partial { PARTIAL } else { &valid };
            let digest = kin_blobs::digest(body.as_bytes());
            let indexed = crate::IndexPipeline::new()
                .index_file_content_with_tests(
                    &FilePathId::new("caller.py"),
                    body.as_bytes(),
                    digest,
                )
                .unwrap()
                .indexed_file;
            assert_eq!(
                matches!(
                    indexed.parse_state,
                    kin_model::ParseState::Incomplete { .. }
                ),
                partial
            );
            if !partial {
                assert!(matches!(indexed.parse_state, kin_model::ParseState::Valid));
            }
            let caller = indexed
                .entities
                .iter()
                .find(|entity| entity.name == "caller")
                .unwrap()
                .id;
            assert!(
                indexed
                    .relations
                    .iter()
                    .any(|edge| edge.kind == RelationKind::Calls
                        && edge.src == GraphNodeId::Entity(caller)),
                "a real call survives parsing"
            );
            graph.entities.retain(|_, entity| {
                entity.file_origin.as_ref() != Some(&FilePathId::new("caller.py"))
            });
            graph.entities.extend(
                indexed
                    .entities
                    .into_iter()
                    .map(|entity| (entity.id, entity)),
            );
            graph.relations.get_mut(&fixture.relation).unwrap().src = GraphNodeId::Entity(caller);
            let digest = Hash256::from_bytes(digest.0);
            fixture.bodies.insert(digest, body.as_bytes().to_vec());
            let artifacts: Vec<_> = graph
                .resolved_tree
                .artifacts_by_path()
                .map(|entry| {
                    let mut entry = entry.clone();
                    if entry.path.as_utf8() == Some("caller.py") {
                        entry.entry = TreeEntry::blob(digest, false);
                    }
                    entry
                })
                .collect();
            graph.resolved_tree = ResolvedTree::from_artifacts(artifacts).unwrap();
        }
        fixture.after.relations.remove(&fixture.relation);
        fixture
    }

    fn debt_for_withdrawal(fixture: &Fixture) -> Relation {
        let old = &fixture.before.relations[&fixture.relation];
        let source = &fixture.before.entities[&old.src.as_entity().unwrap()];
        let target = &fixture.before.entities[&old.dst.as_entity().unwrap()];
        let file = source.file_origin.clone().unwrap();
        let target_file = target.file_origin.clone().unwrap();
        let (artifact, current_digest) = source_entry(&fixture.after, &file).unwrap().unwrap();
        let (_, source_digest) = source_entry(&fixture.before, &file).unwrap().unwrap();
        let (target_artifact, _) = source_entry(&fixture.before, &target_file)
            .unwrap()
            .unwrap();
        crate::binding_debt::build_local_binding_debt(
            artifact,
            LocalBindingDebt {
                source_file: file,
                observed_source_digest: current_digest,
                obligations: vec![LocalBindingObligation {
                    retired_relation: old.clone(),
                    source_name: source.name.clone(),
                    source_digest,
                    prior_source_file: None,
                    target_artifact,
                    target_file,
                    target_name: target.name.clone(),
                }],
            },
        )
        .unwrap()
    }

    #[test]
    fn binding_history_withdrawal_classifier_records_sealed_partial_parse_debt() {
        for (old_partial, current_partial) in [(true, true), (true, false), (false, true)] {
            let fixture = partial_parse_withdrawal_fixture(old_partial, current_partial);
            let old = fixture.before.relations[&fixture.relation].clone();
            assert_eq!(
                classify(&fixture, &fixture.after, std::slice::from_ref(&old)).unwrap(),
                vec![old.clone()]
            );
            assert!(
                !fixture.verifies(&fixture.after),
                "partial parsing cannot discharge the withdrawal"
            );
            let mut accounted = fixture.after.clone();
            let debt = debt_for_withdrawal(&fixture);
            accounted.relations.insert(debt.id, debt);
            assert!(
                fixture.verifies(&accounted),
                "exact debt tracks the binding without certifying resolution"
            );
            assert!(classify(&fixture, &accounted, &[old]).unwrap().is_empty());
        }
    }

    #[test]
    fn binding_history_withdrawal_classifier_partial_parse_keeps_input_errors_fatal() {
        let fixture = partial_parse_withdrawal_fixture(true, true);
        let old = fixture.before.relations[&fixture.relation].clone();
        for missing in [true, false] {
            let error = unaccounted_binding_withdrawals(
                &fixture.before,
                &fixture.after,
                std::slice::from_ref(&old),
                &|_| {
                    Ok(if missing {
                        None
                    } else {
                        Some(b"wrong body".to_vec())
                    })
                },
            )
            .unwrap_err()
            .to_string();
            assert!(
                error.contains(if missing {
                    "CAS is absent"
                } else {
                    "CAS digest differs"
                }),
                "{error}"
            );
        }
        let mut stale = fixture.after.clone();
        for entity in stale
            .entities
            .values_mut()
            .filter(|entity| entity.file_origin.as_ref() == Some(&FilePathId::new("caller.py")))
        {
            entity.metadata.extra.remove("blob_hash");
        }
        assert!(classify(&fixture, &stale, std::slice::from_ref(&old))
            .unwrap_err()
            .to_string()
            .contains("current source declaration body differs"));
        let mut malformed = fixture.after.clone();
        let mut debt = debt_for_withdrawal(&fixture);
        debt.evidence[0].token = Some("not debt JSON".into());
        malformed.relations.insert(debt.id, debt);
        assert!(classify(&fixture, &malformed, std::slice::from_ref(&old))
            .unwrap_err()
            .to_string()
            .contains("malformed binding debt"));
        let reads = std::cell::Cell::new(0);
        assert_eq!(
            unaccounted_binding_withdrawals(&fixture.before, &fixture.after, &[old], &|hash| {
                reads.set(reads.get() + 1);
                Ok(fixture.bodies.get(&hash).cloned())
            })
            .unwrap()
            .len(),
            1
        );
        assert_eq!(
            reads.get(),
            1,
            "verified partial old/current body is cached too"
        );
    }

    #[test]
    fn binding_history_withdrawal_classifier_reuses_retention_and_independent_discharge() {
        let property = Fixture::new();
        let old = property.before.relations[&property.relation].clone();
        assert!(classify(&property, &property.after, &[old])
            .unwrap()
            .is_empty());
        let decorator = Fixture::decorator();
        let mut changed_method = decorator.after.clone();
        changed_method
            .relations
            .get_mut(&decorator.relation)
            .unwrap()
            .evidence[0]
            .parser_rule = Some("lsp_member_on_module".into());
        let old = decorator.before.relations[&decorator.relation].clone();
        assert!(decorator.verifies(&changed_method));
        assert!(
            classify(&decorator, &changed_method, &[old])
                .unwrap()
                .is_empty(),
            "independently discharged decorator bindings must not acquire new debt"
        );
    }

    #[test]
    fn binding_history_withdrawal_classifier_selects_only_exact_unaccounted_candidates() {
        let fixture = Fixture::new();
        let old = fixture.before.relations[&fixture.relation].clone();
        let mut withdrawn = fixture.after.clone();
        withdrawn.relations.remove(&fixture.relation);
        assert!(!fixture.verifies(&withdrawn));
        assert_eq!(
            classify(&fixture, &withdrawn, std::slice::from_ref(&old)).unwrap(),
            vec![old.clone()]
        );
        assert!(
            classify(&fixture, &withdrawn, &[]).unwrap().is_empty(),
            "candidate selection is not a claim about every transition in the graph"
        );
        let mut forged = old.clone();
        forged.evidence[0].occurrence_count += 1;
        assert!(classify(&fixture, &withdrawn, &[forged]).is_err());
        assert!(
            unaccounted_binding_withdrawals(&fixture.before, &withdrawn, &[old], &|_| Ok(None))
                .is_err(),
            "unreadable proof inputs cannot be turned into a measured withdrawal"
        );
    }

    #[test]
    fn binding_history_withdrawal_classifier_reuses_each_affected_file_parse() {
        let mut fixture = Fixture::new();
        let old = fixture.before.relations[&fixture.relation].clone();
        let mut another = old.clone();
        another.id = RelationId::new();
        another.dst = GraphNodeId::Entity(
            fixture
                .before
                .entities
                .values()
                .find(|entity| entity.kind == EntityKind::Class)
                .unwrap()
                .id,
        );
        fixture.before.relations.insert(another.id, another.clone());
        let mut after = fixture.after.clone();
        after.relations.remove(&fixture.relation);
        let reads = std::cell::Cell::new(0);
        let selected =
            unaccounted_binding_withdrawals(&fixture.before, &after, &[old, another], &|digest| {
                reads.set(reads.get() + 1);
                Ok(fixture.bodies.get(&digest).cloned())
            })
            .unwrap();
        assert_eq!(selected.len(), 2);
        assert_eq!(
            reads.get(),
            1,
            "old and current exact source for both withdrawals share one CAS parse"
        );
    }

    #[test]
    fn binding_history_withdrawal_classifier_preserves_recorded_debt_without_reminting() {
        let mut fixture = Fixture::new();
        let old = fixture.before.relations[&fixture.relation].clone();
        let source = &fixture.before.entities[&old.src.as_entity().unwrap()];
        let target = &fixture.before.entities[&old.dst.as_entity().unwrap()];
        let file = source.file_origin.clone().unwrap();
        let target_file = target.file_origin.clone().unwrap();
        let (artifact, digest) = source_entry(&fixture.before, &file).unwrap().unwrap();
        let (target_artifact, _) = source_entry(&fixture.before, &target_file)
            .unwrap()
            .unwrap();
        let debt = crate::binding_debt::build_local_binding_debt(
            artifact,
            LocalBindingDebt {
                source_file: file,
                observed_source_digest: digest,
                obligations: vec![LocalBindingObligation {
                    retired_relation: old.clone(),
                    source_name: source.name.clone(),
                    source_digest: digest,
                    prior_source_file: None,
                    target_artifact,
                    target_file,
                    target_name: target.name.clone(),
                }],
            },
        )
        .unwrap();
        let mut recorded = fixture.after.clone();
        recorded.relations.remove(&fixture.relation);
        recorded.relations.insert(debt.id, debt.clone());
        assert!(fixture.verifies(&recorded));
        assert!(
            classify(&fixture, &recorded, std::slice::from_ref(&old))
                .unwrap()
                .is_empty(),
            "new exact debt already accounts for the selected withdrawal"
        );
        fixture.before.relations.insert(debt.id, debt.clone());
        assert!(
            classify(&fixture, &recorded, std::slice::from_ref(&old))
                .unwrap()
                .is_empty(),
            "already recorded debt is preserved rather than selected again"
        );
        recorded.relations.remove(&debt.id);
        assert!(!fixture.verifies(&recorded));
        assert!(
            classify(&fixture, &recorded, &[old]).is_err(),
            "lost existing debt must be preserved, not silently recreated from a new plan"
        );
    }
}
