// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Request-independent publication of one completely prepared session target.
//! Files are observed only at the explicit session ingestion boundary. After
//! acknowledgement, finalization consumes the saved semantic plan and retains
//! writer custody until projection cleanup and live adoption both finish.

use std::collections::BTreeSet;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use kin_cli::commands::reconcile::{
    self, ReconcileChangeKind, ReconcileRequest, ReconcileSummary, SessionReconcileObservation,
};
use kin_db::{
    GraphSnapshot, LocalFileBackend, LocalRepositoryAuthorityFreeze, RepositoryAuthorityManager,
};
use kin_model::{EntityStore, FilePathId, GraphNodeId, RepoPath, RepositoryTransaction, TreeEntry};
use kin_reconcile::Reconciler;

use crate::prepared_publication::{Armed, FinalizedResponsePermit};
use crate::state::{ChangeType, DaemonEvent, GraphAuthorityMutationGuard, LspEnrichmentRequest};
use crate::DaemonState;

type HttpError = (StatusCode, String);
type Authority = RepositoryAuthorityManager<LocalFileBackend>;

struct SessionCustody<'a> {
    // Each guard remains inside Armed throughout the storage/projection call.
    _coordination: tokio::sync::MutexGuard<'a, ()>,
    _persistence: std::sync::MutexGuard<'a, ()>,
    reconciler: tokio::sync::RwLockWriteGuard<'a, Reconciler>,
    _graph_mutation: GraphAuthorityMutationGuard,
}

fn refused(error: impl std::fmt::Display) -> HttpError {
    (StatusCode::CONFLICT, error.to_string())
}

fn core_error(error: impl std::fmt::Display) -> kin_core::KinError {
    kin_core::KinError::Other(format!("session publication: {error}"))
}

pub(crate) async fn execute(
    state: Arc<DaemonState>,
    request: ReconcileRequest,
) -> Result<Response, HttpError> {
    // Disconnecting a client must not cancel a publication or drop its guards.
    tokio::task::spawn_blocking(move || execute_blocking(&state, request))
        .await
        .map_err(|error| (StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?
}

fn execute_blocking(state: &DaemonState, request: ReconcileRequest) -> Result<Response, HttpError> {
    // Whole-process crash controls register their engine observers here,
    // on the actual blocking publication thread, and nowhere else. Test-only:
    // a released binary carries no observer, no environment trigger and no
    // branch, because this statement does not exist outside `cfg(test)`.
    #[cfg(all(test, unix))]
    let _crash_observers = crate::api::tests::session_crash_prefix_test::install_child_observers(
        state,
        &request.session_dir,
    );
    let coordination = state.coordination_gate.blocking_lock();
    state
        .prepared_publication
        .ensure_serving()
        .map_err(crate::prepared_publication::write_refusal)?;
    if !state.is_initialized.load(Ordering::Acquire) {
        return Err((
            StatusCode::SERVICE_UNAVAILABLE,
            "daemon not fully initialized".into(),
        ));
    }
    if state.storage_backend.is_some() {
        return Err(refused(
            "exact local session reconciliation is unavailable for hosted snapshot authority",
        ));
    }
    let persistence = state
        .persist_lock
        .lock()
        .map_err(|_| refused("repository persistence lock is poisoned"))?;
    let reconciler = state.reconciler.blocking_write();
    let custody = SessionCustody {
        _coordination: coordination,
        _persistence: persistence,
        reconciler,
        _graph_mutation: state.begin_graph_authority_mutation(),
    };
    let binding = state
        .local_repository_authority_binding()
        .map_err(refused)?;
    let authority = crate::api::held_repository_authority(state)?;
    // Startup owns active recovery. Arm before any request-owned session IO:
    // a missing/tampered disposable directory cannot let an active daemon keep
    // serving a partially published repository.
    if let Some(active) = authority
        .active_prepared_session_publication()
        .map_err(refused)?
    {
        let armed = state
            .prepared_publication
            .begin(active.operation_id(), custody)
            .map_err(crate::prepared_publication::write_refusal)?
            .arm();
        drop(armed);
        return Err(refused(
            "active session publication requires startup recovery",
        ));
    }
    // Lookup precedes planning: a retry owns the original immutable operation.
    let prepared = reconcile::lookup_prepared_session_workspace(
        &state.layout,
        &binding,
        &request.session_dir,
        &authority,
    )
    .map_err(crate::api::session_reconcile_error)?;
    if let Some(prepared) = prepared {
        let observation = reconcile::observe_prepared_session_workspace(
            &state.layout,
            &binding,
            &state.blobs,
            &prepared,
        )
        .map_err(crate::api::session_reconcile_error)?;
        let mut summary = summary(&observation, Some(prepared.transaction()))?;
        let armed = state
            .prepared_publication
            .begin(prepared.operation_id(), custody)
            .map_err(crate::prepared_publication::write_refusal)?
            .arm();
        let recovered = kin_core::tree::recover_prepared_session_workspace(
            state.layout.working_dir(),
            &authority,
            prepared,
            armed,
            |_, _| {
                Err(core_error(
                    "active preparation requires startup recovery before serving",
                ))
            },
            |_, _, freeze, _| verify_completed_runtime(state, freeze),
        )
        .map_err(refused)?;
        let (armed, receipt, freeze, _) = recovered.into_parts();
        summary.authority_generation = receipt.generation;
        summary.idempotent_replay = true;
        // Core has completed WAL cleanup. No fallible work follows disarming.
        drop(freeze);
        return Ok(finalized_response(armed, summary));
    }

    let observation = reconcile::observe_session_workspace_under(
        &state.layout,
        &binding,
        &request.session_dir,
        &state.blobs,
        request.confirm_mass_deletion,
        request.write_back,
    )
    .map_err(crate::api::session_reconcile_error)?;
    if observation.deltas().is_empty() {
        // Nothing to admit, so the live tree and generation need not still
        // equal the session base: the observation authenticated that base
        // against persisted authority history, and a base other writers have
        // since advanced closes here with no transaction, receipt, projection
        // WAL, semantic plan or live graph change. The acknowledgement still
        // re-proves the exact retained inputs and pinned namespace it answers
        // for. A no-op never changes the serving epoch, so ordinary response
        // custody remains valid without minting a prepared-publication permit.
        observation
            .revalidate_publication_inputs(&state.layout, &state.blobs)
            .map_err(crate::api::session_reconcile_error)?;
        binding
            .revalidate_pinned_namespace()
            .map_err(crate::api::session_reconcile_error)?;
        return Ok(Json(unchanged_summary(&observation)?).into_response());
    }
    if state.graph.resolved_tree() != observation.base().source_workspace.tree
        || state.snapshot_generation.load(Ordering::SeqCst)
            != observation.base().authority_roots.generation
    {
        return Err(refused(
            "daemon query tree or generation changed from the session base; reopen from authority",
        ));
    }
    let plan = crate::session_publication_plan::prepare(
        state,
        &custody.reconciler,
        &authority,
        &observation,
        state.graph.semantic_observation(),
    )
    .map_err(refused)?;
    if !plan.source_state().collision_warnings().is_empty() {
        tracing::warn!(warnings = ?plan.source_state().collision_warnings(), "session publication touches another active intent");
    }
    let mut summary = summary(&observation, Some(plan.transaction()))?;
    let nonsemantic = prepare_nonsemantic_facets(
        state,
        plan.source_state().nonsemantic_paths(),
        plan.successor(),
    )?;
    let retained = observation
        .publication_binding()
        .map_err(crate::api::session_reconcile_error)?;
    let (transaction, observed, sources) = plan.into_parts();
    let preflight = state
        .prepared_publication
        .begin(transaction.operation_id, custody)
        .map_err(crate::prepared_publication::write_refusal)?;
    let (_, committed) = kin_core::tree::publish_prepared_session_workspace(
        state.layout.working_dir(),
        &observation.base().source_workspace.tree,
        observation.desired_tree(),
        &authority,
        transaction,
        observation.base().source_workspace.workspace_id,
        retained.binding().clone(),
        retained.locator().clone(),
        &observed,
        || {
            observation
                .revalidate_publication_inputs(&state.layout, &state.blobs)
                .map_err(core_error)?;
            binding.revalidate_pinned_namespace().map_err(core_error)?;
            if !same_observation(&observed, &state.graph.semantic_observation()) {
                return Err(core_error(
                    "live semantic predecessor changed before acknowledgement",
                ));
            }
            Ok(preflight.arm())
        },
        |armed| {
            drop(armed.verified_no_acknowledgement_or_mutation());
        },
        |receipt, freeze, armed| {
            // The authority committed and returned its freeze; no live
            // finalization, adoption or facet write has run yet.
            #[cfg(all(test, unix))]
            crate::api::tests::session_crash_prefix_test::reached(
                crate::api::tests::session_crash_prefix_test::CrashPoint::AuthorityBeforeFinalization,
            );
            state
                .finalize_local_repository_commit(
                    receipt,
                    freeze,
                    sources.live_delta(),
                    &observation.base().source_workspace.tree,
                    observation.desired_tree(),
                )
                .map_err(core_error)?;
            adopt_sources(state, armed.custody_mut(), sources, nonsemantic, freeze)?;
            state.bump_version();
            state.emit_event(DaemonEvent::GraphRootChanged {
                old_root_hash: Some(summary.previous_tree_hash.to_string()),
                new_root_hash: summary.desired_tree_hash.to_string(),
            });
            Ok(())
        },
    )
    .map_err(refused)?;
    let (armed, receipt, freeze) = committed.into_parts();
    // Live adoption, facet persistence and projection WAL cleanup are all
    // done; the caller does not have the reply.
    #[cfg(all(test, unix))]
    crate::api::tests::session_crash_prefix_test::reached(
        crate::api::tests::session_crash_prefix_test::CrashPoint::CleanupBeforeReply,
    );
    summary.authority_generation = receipt.generation;
    drop(freeze);
    Ok(finalized_response(armed, summary))
}

fn finalized_response(armed: Armed<SessionCustody<'_>>, summary: ReconcileSummary) -> Response {
    let (custody, permit): (_, FinalizedResponsePermit) = armed.verified_finalized();
    drop(custody);
    let mut response = Json(summary).into_response();
    response.extensions_mut().insert(permit);
    response
}

fn same_observation(left: &GraphSnapshot, right: &GraphSnapshot) -> bool {
    same_semantics(left, right) && left.verified_binding_history == right.verified_binding_history
}

fn same_semantics(left: &GraphSnapshot, right: &GraphSnapshot) -> bool {
    left.entities == right.entities
        && left.relations == right.relations
        && left.external_references == right.external_references
        && left.resolved_tree == right.resolved_tree
}

fn prepare_nonsemantic_facets(
    state: &DaemonState,
    paths: &[RepoPath],
    successor: &GraphSnapshot,
) -> Result<Vec<kin_index::IndexedAny>, HttpError> {
    let pipeline = kin_index::IndexPipeline::new();
    let mut prepared = Vec::new();
    for path in paths {
        let Some(file) = path.as_utf8().map(FilePathId::new) else {
            continue;
        };
        if successor
            .entities
            .values()
            .any(|entity| entity.file_origin.as_ref() == Some(&file))
        {
            return Err(refused(format!(
                "non-source facet would retire prepared entities in {file}"
            )));
        }
        let artifact = successor
            .resolved_tree
            .artifact_at_path(path)
            .ok_or_else(|| refused("prepared facet path is absent from the exact target"))?;
        let TreeEntry::Blob { hash, .. } = artifact.entry else {
            continue;
        };
        let digest = kin_blobs::Hash256::from_bytes(*hash.as_bytes());
        let body = state.blobs.read(&digest).map_err(refused)?;
        let indexed = pipeline
            .index_any_content(&file, &body, digest)
            .map_err(refused)?;
        if matches!(indexed, kin_index::IndexedAny::EntitySource(_)) {
            return Err(refused("source extraction changed after session planning"));
        }
        prepared.push(indexed);
    }
    Ok(prepared)
}

fn adopt_sources(
    state: &DaemonState,
    custody: &mut SessionCustody<'_>,
    sources: crate::session_publication_plan::PreparedSessionSourceState,
    facets: Vec<kin_index::IndexedAny>,
    freeze: &LocalRepositoryAuthorityFreeze,
) -> kin_core::Result<()> {
    let adopted = sources.adopt(&mut custody.reconciler);
    // Clear old derived keys only. The prepared semantic transition has already
    // decided entity retirement; a moved surviving declaration must remain.
    for file in &adopted.facet_invalidations {
        crate::loop_runner::clear_incompatible_facets_in(
            &state.graph,
            file,
            crate::loop_runner::EnrichmentFacet::EntitySource,
        )
        .map_err(core_error)?;
        // Exact tree application already retires moved/deleted artifact facets.
        // An absent path cannot authorize another enrichment deletion.
        if state
            .graph
            .get_file_layout(file)
            .map_err(core_error)?
            .is_some()
        {
            state.graph.delete_file_layout(file).map_err(core_error)?;
        }
    }
    for source in &adopted.sources {
        crate::loop_runner::clear_incompatible_facets_in(
            &state.graph,
            &source.file_id,
            crate::loop_runner::EnrichmentFacet::EntitySource,
        )
        .map_err(core_error)?;
        state
            .persist_projection_truth_from_reconcile(
                &custody.reconciler,
                &kin_reconcile::ReconcileOutcome::Updated {
                    file_id: source.file_id.clone(),
                    added: Vec::new(),
                    modified: Vec::new(),
                    removed: Vec::new(),
                    collision_warnings: Vec::new(),
                },
            )
            .map_err(core_error)?;
    }
    for facet in facets {
        crate::loop_runner::persist_prepared_non_entity_enrichment(state, facet)
            .map_err(core_error)?;
    }
    let workspace = state
        .local_repository_workspace_id()
        .ok_or_else(|| core_error("missing workspace identity"))?;
    let canonical = freeze
        .authority()
        .workspace_graph_snapshot(&workspace)
        .map_err(core_error)?
        .ok_or_else(|| core_error("frozen authority has no session workspace"))?;
    if !same_semantics(&canonical, &state.graph.semantic_observation()) {
        return Err(core_error(
            "session cache/facet finalization changed prepared semantic authority",
        ));
    }
    let canonical =
        kin_db::InMemoryGraph::from_snapshot_without_text_index(canonical).map_err(core_error)?;
    state.graph.restore_binding_history_from(&canonical);

    // The owed derivation ledger is left as it is. The prepared publication
    // this adopts is immutable write-ahead, so it carries no payment. A record
    // for a body this adoption parsed stays on record until the next commit
    // pays it, and drives no second parse meanwhile, because the graph now
    // holds a parse-coverage certificate bound to that body.
    let settled_paths: BTreeSet<String> = adopted
        .sources
        .iter()
        .map(|source| source.file_id.0.clone())
        .chain(
            adopted
                .facet_invalidations
                .iter()
                .map(|file| file.0.clone()),
        )
        .chain(
            adopted
                .nonsemantic_paths
                .iter()
                .filter_map(|path| path.as_utf8().map(str::to_owned)),
        )
        .collect();
    let parsed: Vec<_> = settled_paths
        .iter()
        .map(|path| kin_core::retained_parse::ObservedParse::settled(path.clone()))
        .collect();
    kin_core::retained_parse::record(&state.layout, &parsed);
    // Pending old LSP results cannot mark these new source bodies complete.
    // Persist retirement before queuing fresh work, even without an LSP sender.
    crate::daemon::retire_enrichment_marker_checked(
        state,
        &settled_paths.into_iter().collect::<Vec<_>>(),
    )
    .map_err(core_error)?;
    for delta in &adopted.live_delta.entity_deltas {
        let (entity, change_type, node) = match delta {
            kin_model::EntityDelta::Added { new } => (
                new,
                ChangeType::Created,
                crate::state::graph_node_summary(&state.graph, &new.id),
            ),
            kin_model::EntityDelta::Modified { new, .. } => (
                new,
                ChangeType::Modified,
                crate::state::graph_node_summary(&state.graph, &new.id),
            ),
            kin_model::EntityDelta::Removed { old } => (old, ChangeType::Deleted, None),
        };
        state.emit_event(DaemonEvent::EntityChanged {
            entity_id: entity.id,
            node,
            change_type,
            file_path: entity.file_origin.as_ref().map(|file| file.0.clone()),
            session_id: None,
        });
    }
    for event in crate::state::relation_change_events(&adopted.live_delta, None) {
        state.emit_event(event);
    }
    for source in adopted.sources {
        let entities = state
            .graph
            .query_entities(&kin_model::EntityFilter {
                file_path: Some(source.file_id.clone()),
                ..Default::default()
            })
            .map_err(core_error)?;
        state.queue_lsp_enrichment(LspEnrichmentRequest {
            file_id: source.file_id,
            changed_entity_ids: entities.into_iter().map(|entity| entity.id).collect(),
        });
    }
    Ok(())
}

fn verify_completed_runtime(
    state: &DaemonState,
    freeze: &LocalRepositoryAuthorityFreeze,
) -> kin_core::Result<()> {
    let workspace = state
        .local_repository_workspace_id()
        .ok_or_else(|| core_error("missing workspace identity"))?;
    if freeze.authority().metadata().repository_id.as_str() != state.cached_repo_id
        || state.snapshot_generation.load(Ordering::SeqCst) != freeze.roots().generation
    {
        return Err(core_error(
            "completed replay runtime generation or repository differs from current authority",
        ));
    }
    let canonical = freeze
        .authority()
        .workspace_graph_snapshot(&workspace)
        .map_err(core_error)?
        .ok_or_else(|| core_error("completed replay workspace is absent"))?;
    if state.graph.resolved_tree() != canonical.resolved_tree {
        return Err(core_error(
            "completed replay live tree differs from current authority",
        ));
    }
    // Startup recovery and armed fresh finalization establish derived cache
    // completion. Preserve valid later LSP evidence and all historical layouts.
    Ok(())
}

/// Summary of a session that had nothing to admit.
///
/// Its base may be authentic history that other writers have since advanced,
/// so the generations are the current ones its authentication read, never the
/// snapshot the base recorded. Nothing was published: the summary stays
/// unchanged with empty change counts, and it is not an idempotent replay.
fn unchanged_summary(
    observation: &SessionReconcileObservation,
) -> Result<ReconcileSummary, HttpError> {
    let current = observation.current_generations().ok_or_else(|| {
        refused("an unchanged session observation carries no authenticated authority generations")
    })?;
    let mut summary = summary(observation, None)?;
    summary.authority_generation = current.authority;
    summary.workspace_generation = current.workspace;
    Ok(summary)
}

fn summary(
    observation: &SessionReconcileObservation,
    transaction: Option<&RepositoryTransaction>,
) -> Result<ReconcileSummary, HttpError> {
    let changes = observation.changes();
    let mutation = transaction.and_then(|transaction| transaction.workspace_mutation.as_ref());
    // Count changed regular-file facets and published source certificates.
    // Source and non-source enrichment keep their existing summary meaning.
    // The saved transaction makes the count stable across historical replay.
    let mut enriched: BTreeSet<_> = mutation
        .into_iter()
        .flat_map(|mutation| mutation.semantic_delta.relation_deltas())
        .filter_map(|delta| delta.new_state())
        .filter_map(|relation| {
            let GraphNodeId::Artifact(id) = relation.src else {
                return None;
            };
            let artifact = observation.desired_tree().get(&id)?;
            let path = artifact.path.as_utf8()?;
            kin_index::is_parse_coverage_relation(relation, path, id).then_some(id)
        })
        .collect();
    if let Some(mutation) = mutation {
        enriched.extend(mutation.tree_deltas.iter().filter_map(|delta| {
            let new = delta.new_state()?;
            (matches!(new.entry, TreeEntry::Blob { .. }) && new.path.as_utf8().is_some())
                .then_some(delta.artifact_id())
        }));
    }
    if transaction.is_some() {
        // Rust project inputs refresh the owned source set together, including
        // unchanged certificates. Recover that same bounded census from the
        // retained exact trees so replay reports the original work.
        if let Some(project) = kin_index::rust_project::affected_source_batch(
            &observation.base().source_workspace.tree,
            observation.desired_tree(),
            Default::default(),
        )
        .map_err(refused)?
        {
            for file in project.affected_sources {
                let path = RepoPath::from_utf8(file.0).map_err(refused)?;
                if let Some(artifact) = observation.desired_tree().artifact_at_path(&path) {
                    enriched.insert(artifact.artifact_id);
                }
            }
        }
    }
    Ok(ReconcileSummary {
        schema: reconcile::RECONCILE_SUMMARY_SCHEMA.into(),
        operation_id: observation.base().reconcile_operation_id,
        repository_id: observation.base().repository_id.clone(),
        authority_generation: observation.base().authority_roots.generation,
        workspace_generation: mutation
            .map_or(observation.base().source_workspace.generation, |m| {
                m.new_generation
            }),
        previous_tree_hash: observation.base().source_workspace.tree_hash,
        desired_tree_hash: kin_model::compute_resolved_tree_hash(observation.desired_tree())
            .map_err(refused)?,
        idempotent_replay: false,
        changed: !observation.deltas().is_empty(),
        added: changes
            .iter()
            .filter(|change| change.kind == ReconcileChangeKind::Added)
            .count(),
        modified: changes
            .iter()
            .filter(|change| change.kind == ReconcileChangeKind::Modified)
            .count(),
        removed: changes
            .iter()
            .filter(|change| change.kind == ReconcileChangeKind::Removed)
            .count(),
        observed_materialized_artifacts: observation.observed_materialized_artifacts(),
        preserved_graph_only_artifacts: observation.preserved_graph_only_artifacts(),
        observed_body_bytes: observation.observed_body_bytes(),
        semantic_files_enriched: enriched.len(),
        semantic_enrichment_failures: 0,
        changes,
        withheld: observation.withheld().to_vec(),
    })
}

/// Recover before any graph, layout, reconciler cache or serving registration
/// is hydrated. No runtime readers exist yet, so startup owns plain custody.
///
/// A publication recovered here never reaches live finalization, so the
/// language-server completion markers finalization retires are retired here
/// instead, for every file the publication changed.
pub(crate) fn recover_before_hydration(
    layout: &kin_core::KinLayout,
    binding: &kin_core::LocalRepositoryAuthorityBinding,
    authority: &Authority,
) -> crate::error::Result<()> {
    #[cfg(all(test, unix))]
    crate::api::tests::session_crash_prefix_test::record_startup_phase(
        crate::api::tests::session_crash_prefix_test::StartupPhase::Resolver,
    );
    if let Some(prepared) = authority.active_prepared_session_publication()? {
        let changed = recovered_publication_paths(&prepared);
        let blobs = kin_blobs::BlobStore::new(layout.ingest_cas_dir())?;
        let recovered = kin_core::tree::recover_prepared_session_workspace(
            layout.working_dir(),
            authority,
            prepared,
            (),
            |_, prepared| {
                reconcile::observe_prepared_session_workspace(layout, binding, &blobs, prepared)
                    .map(|_| ())
                    .map_err(core_error)
            },
            |_, _, _, _| retire_recovered_markers(layout, &changed),
        )?;
        drop(recovered);
    } else {
        // A committed publication whose WAL survived may have stopped before
        // live finalization, and the engine hands each one back before it
        // removes the WAL. Retiring is idempotent, so one that finished too
        // costs nothing.
        kin_core::tree::recover_repository_projection_before_hydration_with_session_finalizer(
            layout.working_dir(),
            authority,
            |prepared, _| retire_recovered_markers(layout, &recovered_publication_paths(prepared)),
        )?;
    }
    Ok(())
}

fn retire_recovered_markers(
    layout: &kin_core::KinLayout,
    changed: &[String],
) -> kin_core::Result<()> {
    crate::daemon::retire_enrichment_marker_before_hydration(layout, changed).map_err(core_error)
}

/// Every path whose language-server answers a recovered publication made
/// stale: each location its tree transition names, before and after, each
/// file a declaration it changed lives in, and each site of a binding it
/// withdrew or rewrote. A binding it only added cannot have made an earlier
/// answer stale. Retiring a path it did not need to costs that file one more
/// sweep, never a wrong skip.
fn recovered_publication_paths(
    prepared: &kin_db::storage::PreparedSessionPublication,
) -> Vec<String> {
    let Some(mutation) = prepared.transaction().workspace_mutation.as_ref() else {
        return Vec::new();
    };
    let mut paths = BTreeSet::new();
    for delta in &mutation.tree_deltas {
        for located in delta.old_state().into_iter().chain(delta.new_state()) {
            if let Some(path) = located.path.as_utf8() {
                paths.insert(path.to_owned());
            }
        }
    }
    for delta in mutation.semantic_delta.entity_deltas() {
        for entity in delta.old_state().into_iter().chain(delta.new_state()) {
            if let Some(file) = &entity.file_origin {
                paths.insert(file.0.clone());
            }
        }
    }
    for delta in mutation.semantic_delta.relation_deltas() {
        let stale = match delta {
            kin_model::RelationDelta::Added { .. } => continue,
            kin_model::RelationDelta::Removed { old } => [Some(old), None],
            kin_model::RelationDelta::Modified { old, new } => [Some(old), Some(new)],
        };
        for relation in stale.into_iter().flatten() {
            for evidence in &relation.evidence {
                if let Some(span) = &evidence.source_span {
                    paths.insert(span.file.0.clone());
                }
            }
        }
    }
    paths.into_iter().collect()
}
