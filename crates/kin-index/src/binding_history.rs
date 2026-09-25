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
        if !matches!(file.parse_state, kin_model::ParseState::Valid) {
            return Err("binding source is not a complete parse".into());
        }
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
        for relation in before.relations.values() {
            if after.relations.get(&relation.id) == Some(relation) {
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
            return Ok(());
        }
        let graph = InMemoryGraph::from_snapshot_without_text_index(after.clone()).map_err(text)?;
        let produced: Vec<Relation> = after.relations.values().cloned().collect();
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
                    return Err(
                        "prior local binding was neither retained, recorded, nor discharged".into(),
                    );
                }
            }
        }
        Ok(())
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
