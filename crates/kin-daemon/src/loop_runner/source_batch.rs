// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Coherent source repair under the caller's coordination, graph-authority and
//! reconciler guards. Only admitted CAS bodies supply semantic input.

use super::*;

/// `paths`, and every path the owed derivation ledger names whose parse the
/// answering graph still lacks, so one batch covers both.
///
/// A ledger that will not read adds nothing here. The drain that follows every
/// batch on the admission seam reads it again and refuses in words.
pub(super) fn with_owed_paths(
    state: &DaemonState,
    mut paths: BTreeSet<RepoPath>,
) -> BTreeSet<RepoPath> {
    let recorded = crate::semantic_debt::outstanding(state);
    paths.extend(crate::semantic_debt::owed_against_tree(state, &recorded));
    paths
}

/// Which observation a coherent batch may ground a withdrawn binding in.
#[derive(Clone, Copy)]
pub(super) enum BatchPredecessor<'a> {
    /// An actual observation made before this tree moved, or none, in which
    /// case a withdrawn binding refuses the batch.
    Observed(Option<&'a kin_db::GraphSnapshot>),
    /// A daemon's startup re-derivation. The only observation from before this
    /// start is the store as the daemon loaded it; the parse that bound a
    /// stale caller did not survive the restart.
    StartupLoaded,
}

/// Which caller asks for a coherent batch, and so how many complete sources
/// form one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum BatchScope {
    /// Exact tree admission, before publication. The batch's semantics cross
    /// authority in the same publication as its bytes, so one complete source
    /// is a batch. A pass that carries a single source, including the tail of a
    /// grouped edit the watcher split across passes, then publishes that
    /// source's parse instead of leaving it to the live graph alone.
    ExactAdmission,
    /// Readmission after a publication, the drain and the startup repair. A
    /// single path there stays with the sequential reconciler, whose outcomes
    /// and refusals those callers are built on, so only two or more complete
    /// sources form a batch.
    Readmission,
}

impl BatchScope {
    fn minimum_sources(self) -> usize {
        match self {
            Self::ExactAdmission => 1,
            Self::Readmission => 2,
        }
    }
}

/// Return only sources actually handled. Partial/LKG and non-source outcomes
/// remain the ordinary reconciler's responsibility. A failed complete batch is
/// an error, never permission to hide its failure with per-file success.
pub(super) fn prepare(
    state: &DaemonState,
    reconciler: &mut kin_reconcile::Reconciler,
    graph: &kin_db::InMemoryGraph,
    paths: &BTreeSet<RepoPath>,
    predecessor: BatchPredecessor<'_>,
    observed_host: &BTreeSet<RepoPath>,
    scope: BatchScope,
) -> Result<Option<PreparedLiveBatch>> {
    let minimum_sources = scope.minimum_sources();
    // The loaded store is not an observation of an earlier tree, so project
    // nomination treats the previous tree as unknown and nominates every Rust
    // source, exactly as a batch with no predecessor does.
    let observed = match predecessor {
        BatchPredecessor::Observed(observed) => observed,
        BatchPredecessor::StartupLoaded => None,
    };
    let current_tree = graph.resolved_tree();
    // Cargo/module inputs can change a caller without changing its own bytes.
    // Nominate those callers from the exact admitted trees, not from the set
    // of host files that happened to produce watcher events or declarations.
    let project_requested = paths.iter().any(|path| {
        path.as_bytes().ends_with(b".rs")
            || path.as_bytes().rsplit(|byte| *byte == b'/').next() == Some(b"Cargo.toml")
    });
    let unknown_previous = kin_model::ResolvedTree::default();
    let project = if project_requested {
        kin_index::rust_project::affected_source_batch(
            observed
                .map(|previous| &previous.resolved_tree)
                .unwrap_or(&unknown_previous),
            &current_tree,
            Default::default(),
        )
        .map_err(|error| DaemonError::SemanticReadmissionFailed(error.to_string()))?
    } else {
        None
    };
    let mut paths = paths.clone();
    if let Some(project) = &project {
        for file in &project.affected_sources {
            paths.insert(
                RepoPath::from_utf8(file.0.clone())
                    .map_err(|error| invalid_tree_transition(error.to_string()))?,
            );
        }
    }
    if project.is_none() && paths.len() < minimum_sources {
        return Ok(None);
    }
    // Only exact admission forms a batch around one source, and only because
    // the two-source minimum would otherwise have left that source to the
    // sequential reconciler. A failure of such a batch that the sequential
    // reconciler handles for that source itself hands the source back to it,
    // which publishes the bytes and refuses or discloses the semantics exactly
    // as it did before one source could form a batch; see `HandedBack`.
    // Nothing has been written by then: indexing reads the content it is given,
    // the batch is prepared in a private graph and reconciler, and the
    // preflight only reads. Every other failure, host drift above all, and
    // every failure of two or more sources still refuses the admission.
    let below_pair =
        |count: usize| project.is_none() && count < BatchScope::Readmission.minimum_sources();
    let hand_back = |class: HandedBack,
                     error: DaemonError,
                     paths: &BTreeSet<RepoPath>|
     -> Result<Option<PreparedLiveBatch>> {
        tracing::warn!(
            paths = ?paths.iter().map(|path| path.to_string()).collect::<Vec<_>>(),
            ?class,
            %error,
            "a one-source coherent batch could not be prepared; the sequential \
             reconciler takes the source, as it did before one source formed a batch"
        );
        Ok(None)
    };
    let before = graph.semantic_observation();
    let mut files = Vec::new();
    let pipeline = IndexPipeline::new();
    for path in &paths {
        let Some(file) = semantic_file_id(path) else {
            continue;
        };
        let Some(artifact) = before.resolved_tree.artifact_at_path(path) else {
            continue;
        };
        let TreeEntry::Blob { hash, .. } = artifact.entry else {
            continue;
        };
        let digest = kin_blobs::Hash256::from_bytes(*hash.as_bytes());
        let content = match state.blobs.read(&digest) {
            Ok(content) => content,
            Err(error) => {
                let error = DaemonError::SemanticReadmissionFailed(format!(
                    "cannot read canonical source {path} ({hash}) while preparing semantic \
                     readmission: {error}; no complete source batch was admitted"
                ));
                return if below_pair(paths.len()) {
                    hand_back(HandedBack::UnreadableSource, error, &paths)
                } else {
                    Err(error)
                };
            }
        };
        let index = || pipeline.index_any_content(&file, &content, digest);
        // The injected canonical index failure reaches the one-source batch
        // too, so it models the same fault on both derivation paths.
        #[cfg(test)]
        let index = || {
            if below_pair(paths.len())
                && state.readmission_index_failure.lock().unwrap().as_ref() == Some(&file)
            {
                return Err(kin_index::IndexError::Parse(
                    kin_parser::ParseError::ParseFailed {
                        file: file.0.clone(),
                        reason: "injected canonical readmission failure".to_string(),
                    },
                ));
            }
            index()
        };
        let indexed = match index() {
            Ok(indexed) => indexed,
            Err(error) => {
                let error = DaemonError::from(error);
                return if below_pair(paths.len()) {
                    hand_back(HandedBack::IndexFailure, error, &paths)
                } else {
                    Err(error)
                };
            }
        };
        let IndexedAny::EntitySource(indexed) = indexed else {
            continue;
        };
        if !matches!(indexed.parse_state, kin_model::ParseState::Valid)
            || indexed.file_layout.parse_completeness != ParseCompleteness::Full
        {
            // An unrelated partial source must not force complete mutually
            // edited sources back through the sequential reconciliation path.
            continue;
        }
        files.push(file);
    }
    if project.is_none() && files.len() < minimum_sources {
        return Ok(None);
    }
    let one_source = below_pair(files.len());
    let assembled = assemble_batch(
        state,
        reconciler,
        graph,
        predecessor,
        observed_host,
        &before,
        &files,
    );
    match assembled {
        Ok(batch) => {
            #[cfg(test)]
            super::record_prepared_batch_for_test(state, &batch.handled);
            Ok(Some(batch))
        }
        Err(error) => match HandedBack::of(&error) {
            Some(class) if one_source => hand_back(class, error, &paths),
            _ => Err(error),
        },
    }
}

/// The failures of a one-source batch that the sequential reconciler handles
/// for that source itself, and so the only ones such a batch hands back to it.
/// Each names the line of `loop_runner` that handles it sequentially.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HandedBack {
    /// The canonical body the tree names cannot be read. Sequentially,
    /// `readmit_semantics_for_paths_with` records the path unresolved ("the
    /// body this path's exact tree entry names is not readable") and the
    /// ambient pass skips the event ("failed to admit exact repository-tree
    /// entry").
    UnreadableSource,
    /// Indexing the canonical body failed. Sequentially, "canonical source
    /// could not be parsed" records it unresolved, and the ambient pass drops
    /// the event ("reconciliation error for event").
    IndexFailure,
    /// A source the batch reads to prove bindings could not be read.
    /// Sequentially, the per-file reconcile meets the same read and records
    /// the path ("published bytes could not be re-parsed", "reconciliation
    /// error for event").
    DependentRead,
    /// The traffic checker refused a hard collision. Sequentially, the
    /// per-file reconcile's own traffic check refuses the same scope and
    /// records the path the same way.
    TrafficCollision,
}

impl HandedBack {
    /// The class of a failure after indexing, when the sequential reconciler
    /// handles it. The two failures before that point, an unreadable body and a
    /// failed index, are classed where they happen. Host drift, a path that will
    /// not map to the host, and every invariant refusal are not handed back.
    fn of(error: &DaemonError) -> Option<Self> {
        match error {
            DaemonError::Reconcile(kin_reconcile::ReconcileError::Blob(_)) => {
                Some(Self::DependentRead)
            }
            DaemonError::Reconcile(kin_reconcile::ReconcileError::CollisionBlocked { .. }) => {
                Some(Self::TrafficCollision)
            }
            _ => None,
        }
    }
}

/// Prepare, preflight and host-check one batch of complete sources. Nothing it
/// does is visible outside the returned batch until the caller applies it: the
/// batch is derived in a private graph and reconciler, and the preflight reads.
fn assemble_batch(
    state: &DaemonState,
    reconciler: &kin_reconcile::Reconciler,
    graph: &kin_db::InMemoryGraph,
    predecessor: BatchPredecessor<'_>,
    observed_host: &BTreeSet<RepoPath>,
    before: &kin_db::GraphSnapshot,
    files: &[FilePathId],
) -> Result<PreparedLiveBatch> {
    let prepared = match predecessor {
        BatchPredecessor::Observed(observed) => {
            // The predecessor is an actual observation made before this tree
            // moved. A history head cannot stand in for never-committed live
            // dependencies.
            let predecessors: Vec<_> = observed
                .into_iter()
                .map(|prior| kin_model::graph::ResolvedGraphState {
                    entities: prior.entities.clone(),
                    relations: prior.relations.clone(),
                    external_references: prior.external_references.clone(),
                    tree: prior.resolved_tree.clone(),
                    ..Default::default()
                })
                .collect();
            kin_reconcile::Reconciler::prepare_admitted_source_batch(
                before.clone(),
                files,
                &state.blobs,
                &predecessors,
            )?
        }
        BatchPredecessor::StartupLoaded => {
            kin_reconcile::Reconciler::prepare_admitted_source_rederivation(
                before.clone(),
                files,
                &state.blobs,
            )?
        }
    };
    let delta = semantic_delta(before, prepared.snapshot())?;
    let adoption =
        reconciler.preflight_admitted_source_batch(&prepared, graph, &delta, &state.blobs)?;
    let collisions = adoption.collision_warnings().to_vec();
    let mut layouts_changed = BTreeSet::new();
    let mut handled = BTreeSet::new();
    for source in prepared.sources() {
        let path = RepoPath::from_utf8(source.file_id.0.clone())
            .map_err(|error| invalid_tree_transition(error.to_string()))?;
        if observed_host.contains(&path) {
            let host = kin_index::host_path_from_repo_path(state.layout.working_dir(), &path)?;
            if !host_entry_matches_tree(state, &host, &path, &before.resolved_tree)? {
                return Err(DaemonError::SemanticReadmissionFailed(format!(
                    "host entry changed during coherent source reconciliation: {path}"
                )));
            }
        }
        let previous = state.graph.get_file_layout(&source.file_id)?;
        if previous
            .as_ref()
            .map(serde_json::to_value)
            .transpose()
            .map_err(|e| DaemonError::Io(std::io::Error::other(e)))?
            != Some(
                serde_json::to_value(&source.layout)
                    .map_err(|e| DaemonError::Io(std::io::Error::other(e)))?,
            )
        {
            layouts_changed.insert(source.file_id.0.clone());
        }
        handled.insert(path);
    }
    Ok(PreparedLiveBatch {
        prepared,
        adoption,
        delta,
        handled,
        layouts_changed,
        collisions,
    })
}

pub(super) fn semantic_delta(
    before: &kin_db::GraphSnapshot,
    after: &kin_db::GraphSnapshot,
) -> Result<TransactionDelta> {
    let semantics = kin_core::diff_workspace_semantics(
        &before.entities,
        &before.relations,
        &after.entities,
        &after.relations,
    )?;
    let mut external_reference_deltas = Vec::new();
    for (id, old) in &before.external_references {
        match after.external_references.get(id) {
            None => external_reference_deltas
                .push(kin_model::ExternalReferenceDelta::Removed { old: old.clone() }),
            Some(new) if old != new => {
                return Err(invalid_tree_transition(
                    "source batch rewrote an immutable external reference".to_string(),
                ));
            }
            _ => {}
        }
    }
    for (id, new) in &after.external_references {
        if !before.external_references.contains_key(id) {
            external_reference_deltas
                .push(kin_model::ExternalReferenceDelta::Added { new: new.clone() });
        }
    }
    Ok(TransactionDelta {
        entity_deltas: semantics.entity_deltas().to_vec(),
        relation_deltas: semantics.relation_deltas().to_vec(),
        external_reference_deltas,
        ..Default::default()
    })
}

pub(super) struct PreparedLiveBatch {
    prepared: kin_reconcile::PreparedAdmittedSourceBatch,
    adoption: kin_reconcile::PreparedBatchAdoption,
    delta: TransactionDelta,
    handled: BTreeSet<RepoPath>,
    layouts_changed: BTreeSet<String>,
    collisions: Vec<kin_model::IntentSummary>,
}

impl std::fmt::Debug for PreparedLiveBatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreparedLiveBatch")
            .field("paths", &self.handled)
            .finish_non_exhaustive()
    }
}

impl PreparedLiveBatch {
    pub(super) fn snapshot(&self) -> &kin_db::GraphSnapshot {
        self.prepared.snapshot()
    }

    pub(super) fn finish(
        self,
        state: &DaemonState,
        reconciler: &mut kin_reconcile::Reconciler,
        pass: &mut crate::state::PassDelta,
    ) -> Result<BTreeSet<RepoPath>> {
        let Self {
            prepared,
            adoption,
            delta,
            handled,
            layouts_changed,
            collisions,
        } = self;
        reconciler.adopt_admitted_source_batch(adoption);
        if delta != TransactionDelta::default() || !layouts_changed.is_empty() {
            // Retire the language-server marker before fallible post-apply
            // persistence: an interrupted layout write must not leave a sweep
            // skipping semantic work that has already landed.
            state.bump_version();
            for source in prepared.sources() {
                crate::daemon::retire_enrichment_marker(
                    state,
                    std::slice::from_ref(&source.file_id.0),
                );
            }
        }
        let mut per_file: HashMap<FilePathId, (Vec<EntityId>, Vec<EntityId>, Vec<EntityId>)> =
            HashMap::new();
        for change in &delta.entity_deltas {
            let (entity, kind) = match change {
                kin_model::EntityDelta::Added { new } => {
                    pass.nodes_added += 1;
                    (new, ChangeType::Created)
                }
                kin_model::EntityDelta::Modified { new, .. } => {
                    pass.nodes_modified += 1;
                    (new, ChangeType::Modified)
                }
                kin_model::EntityDelta::Removed { old } => {
                    pass.nodes_removed += 1;
                    (old, ChangeType::Deleted)
                }
            };
            if let Some(file) = &entity.file_origin {
                let ids = per_file.entry(file.clone()).or_default();
                match kind {
                    ChangeType::Created => ids.0.push(entity.id),
                    ChangeType::Modified => ids.1.push(entity.id),
                    ChangeType::Deleted => ids.2.push(entity.id),
                }
            }
            state.emit_event(DaemonEvent::EntityChanged {
                entity_id: entity.id,
                node: crate::state::graph_node_summary(state.graph.as_ref(), &entity.id),
                change_type: kind,
                file_path: entity.file_origin.as_ref().map(|file| file.0.clone()),
                session_id: None,
            });
        }
        for event in crate::state::relation_change_events(&delta, None) {
            pass.count(&event);
            state.emit_event(event);
        }
        for (file_id, (added, modified, _)) in &per_file {
            let ids: Vec<_> = added.iter().chain(modified).copied().collect();
            if !ids.is_empty() {
                state.queue_lsp_enrichment(LspEnrichmentRequest {
                    file_id: file_id.clone(),
                    changed_entity_ids: ids,
                });
            }
        }
        let finish = (|| -> Result<()> {
            for source in prepared.sources() {
                clear_incompatible_facets(state, &source.file_id, EnrichmentFacet::EntitySource)?;
                let (added, modified, removed) =
                    per_file.remove(&source.file_id).unwrap_or_default();
                let outcome = kin_reconcile::ReconcileOutcome::Updated {
                    file_id: source.file_id.clone(),
                    added,
                    modified,
                    removed,
                    collision_warnings: collisions.clone(),
                };
                state.persist_projection_truth_from_reconcile(reconciler, &outcome)?;
            }
            let observations: Vec<_> = prepared
                .sources()
                .iter()
                .map(|source| kin_core::retained_parse::ObservedParse::settled(&source.file_id.0))
                .collect();
            kin_core::retained_parse::record(&state.layout, &observations);
            Ok(())
        })();
        finish.map_err(|error| {
            DaemonError::SemanticReadmissionFailed(format!(
            "coherent source batch was applied; its projection persistence needs retry: {error}"
        ))
        })?;
        Ok(handled)
    }
}

pub(super) fn try_readmit(
    state: &DaemonState,
    reconciler: &mut kin_reconcile::Reconciler,
    paths: &BTreeSet<RepoPath>,
    predecessor: Option<&kin_db::GraphSnapshot>,
    observed_host: &BTreeSet<RepoPath>,
    pass: &mut crate::state::PassDelta,
) -> Result<BTreeSet<RepoPath>> {
    try_readmit_from(
        state,
        reconciler,
        paths,
        BatchPredecessor::Observed(predecessor),
        observed_host,
        pass,
    )
    .map(|(handled, _)| handled)
}

/// What a startup re-derivation removed without the record or the exact proof
/// a live edit would need, for the start to count and disclose. Both counts
/// are zero for any other batch.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct StartupRetirements {
    /// Withdrawn cross-file bindings dropped without a withdrawal record.
    pub withdrawn_unrecorded: usize,
    /// Stored external-import edges retired because this build's parser does
    /// not reproduce them from the bytes they were recorded against.
    pub external_unreproduced: usize,
}

/// [`try_readmit`] for a startup re-derivation. Also returns what it removed
/// without a withdrawal record or an exact recount, for the start to disclose.
pub(super) fn try_readmit_at_startup(
    state: &DaemonState,
    reconciler: &mut kin_reconcile::Reconciler,
    paths: &BTreeSet<RepoPath>,
    pass: &mut crate::state::PassDelta,
) -> Result<(BTreeSet<RepoPath>, StartupRetirements)> {
    try_readmit_from(
        state,
        reconciler,
        paths,
        BatchPredecessor::StartupLoaded,
        &BTreeSet::new(),
        pass,
    )
}

fn try_readmit_from(
    state: &DaemonState,
    reconciler: &mut kin_reconcile::Reconciler,
    paths: &BTreeSet<RepoPath>,
    predecessor: BatchPredecessor<'_>,
    observed_host: &BTreeSet<RepoPath>,
    pass: &mut crate::state::PassDelta,
) -> Result<(BTreeSet<RepoPath>, StartupRetirements)> {
    let Some(prepared) = prepare(
        state,
        reconciler,
        state.graph.as_ref(),
        paths,
        predecessor,
        observed_host,
        BatchScope::Readmission,
    )?
    else {
        return Ok((BTreeSet::new(), StartupRetirements::default()));
    };
    let retirements = StartupRetirements {
        withdrawn_unrecorded: prepared.prepared.withdrawn_bindings_unrecorded(),
        external_unreproduced: prepared.prepared.external_edges_retired_unreproduced(),
    };
    apply_reconcile_delta(&prepared.delta, |delta| {
        state.graph.apply_transaction_delta(delta)
    })?;
    prepared
        .finish(state, reconciler, pass)
        .map(|handled| (handled, retirements))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Exactly two failures after indexing are handed back to the sequential
    /// reconciler. A new error variant must be placed deliberately, never join
    /// or leave the set by accident, and host drift must never be in it.
    #[test]
    fn only_named_preparation_failures_are_handed_back() {
        use kin_reconcile::ReconcileError;
        assert_eq!(
            HandedBack::of(&DaemonError::Reconcile(ReconcileError::Blob(
                "blob not found".into()
            ))),
            Some(HandedBack::DependentRead)
        );
        assert_eq!(
            HandedBack::of(&DaemonError::Reconcile(ReconcileError::CollisionBlocked {
                reason: "hard collision".into(),
                blocking_intents: Vec::new(),
            })),
            Some(HandedBack::TrafficCollision)
        );
        for refused in [
            DaemonError::SemanticReadmissionFailed(
                "host entry changed during coherent source reconciliation: pkg/a.py".into(),
            ),
            DaemonError::Index(kin_index::IndexError::Parse(
                kin_parser::ParseError::ParseFailed {
                    file: "pkg/a.py".into(),
                    reason: "a host path that will not map".into(),
                },
            )),
            DaemonError::Io(std::io::Error::other("layout encoding")),
            DaemonError::Reconcile(ReconcileError::InvalidTransaction(
                "live graph changed after batch preparation".into(),
            )),
            DaemonError::Reconcile(ReconcileError::Graph("graph".into())),
            DaemonError::Reconcile(ReconcileError::Parse("parse".into())),
            DaemonError::Reconcile(ReconcileError::Index("index".into())),
            DaemonError::Reconcile(ReconcileError::TrafficCheck("checker".into())),
            DaemonError::Reconcile(ReconcileError::FileModifiedDuringReconcile {
                path: "pkg/a.py".into(),
                expected_hash: "a".into(),
                actual_hash: "b".into(),
            }),
        ] {
            assert_eq!(HandedBack::of(&refused), None, "{refused}");
        }
    }
}
