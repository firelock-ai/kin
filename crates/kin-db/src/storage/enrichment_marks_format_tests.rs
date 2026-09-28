// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

// Language-server enrichment marks. A workspace that holds marks, or a logged
// operation that recorded some, moves the snapshot and frame versions, so an
// older binary refuses such a store at the header instead of failing inside
// the envelope; a store that never carried marks keeps its version and bytes.

/// One enrichment publication's shape: a workspace mutation that moves no
/// tree and records `marks` in the first workspace.
fn enrichment_marks_transaction<B: StorageBackend + ?Sized + 'static>(
    manager: &RepositoryAuthorityManager<B>,
    operation: u128,
    marks: kin_model::EnrichmentMarksDelta,
) -> RepositoryTransaction {
    let current = manager.read_authority().metadata().workspaces[0].clone();
    let mutation = WorkspaceMutation {
        workspace_id: current.workspace_id,
        expected: WorkspaceExpectation::MustEqual {
            generation: current.generation,
            head: current.head.clone(),
            base_target: current.base_target.clone(),
            base_tree_hash: current.base_tree_hash,
            tree_hash: current.tree_hash,
            semantic_overlay_hash: current.semantic_overlay_hash,
            admission_policy: current.admission_policy,
        },
        new_generation: current.generation + 1,
        new_head: current.head.clone(),
        new_base_target: current.base_target.clone(),
        new_base_tree_hash: current.base_tree_hash,
        tree_deltas: Vec::new(),
        new_tree_hash: current.tree_hash,
        semantic_delta: WorkspaceSemanticDelta::default()
            .with_enrichment_marks(marks)
            .unwrap(),
        new_shared_admission_policy: current.shared_admission_policy.clone(),
        new_admission_policy: current.admission_policy,
    };
    let mut transaction = transaction_shell(manager, operation);
    transaction.workspace_mutation = Some(mutation);
    transaction
}

/// A mark for the first file the first workspace's tree holds, bound to its
/// body and to the relations its enrichment owns in the workspace graph.
fn holding_enrichment_mark<B: StorageBackend + ?Sized + 'static>(
    manager: &RepositoryAuthorityManager<B>,
) -> kin_model::EnrichmentMark {
    let lease = manager.read_authority();
    let workspace = lease.metadata().workspaces[0].clone();
    let (path, body) = workspace
        .tree
        .artifacts()
        .find_map(|artifact| match &artifact.entry {
            TreeEntry::Blob { hash, .. } => artifact
                .path
                .as_utf8()
                .map(|path| (path.to_string(), *hash)),
            _ => None,
        })
        .expect("the fixture tree holds a file");
    let graph = lease
        .workspace_graph_snapshot(&workspace.workspace_id)
        .unwrap()
        .unwrap();
    let entity_file = |id: &kin_model::EntityId| {
        graph
            .entities
            .get(id)
            .and_then(|entity| entity.file_origin.as_ref())
            .map(|file| file.0.as_str())
    };
    kin_model::EnrichmentMark {
        relations: kin_model::enrichment_relations_digest(
            &path,
            graph.relations.values(),
            entity_file,
            kin_model::enrichment_ledgers_by_file(graph.resolution_records.values(), entity_file)
                .remove(&path)
                .unwrap_or_default(),
        ),
        path,
        body,
        version: 5,
    }
}

/// Marks declare versions a binary older than them refuses at the header:
/// snapshot 21 without a section, where the release before marks reads at most
/// 20, and frame 6, where it reads at most 5. Measured before this step: that
/// release opened a store holding marks and failed inside a frame with "array
/// had incorrect length, expected 4". A store that never carried marks keeps
/// its version and its bytes.
#[test]
fn enrichment_marks_move_versions_and_a_store_without_them_moves_nothing() {
    let directory = TempDir::new().unwrap();
    let (backend, manager) = framed_local_repository(&directory);
    let quiet = manager.read_authority().snapshot().clone();
    let quiet_version = quiet.wire_version();
    assert!(
        quiet_version < GraphSnapshot::ENRICHMENT_MARKS_VERSION,
        "control: a store without marks declares v{quiet_version}"
    );
    let quiet_bytes = quiet.to_bytes().unwrap();

    let mark = holding_enrichment_mark(&manager);
    manager
        .commit_repository_transaction(enrichment_marks_transaction(
            &manager,
            0x0e3a_0001,
            kin_model::EnrichmentMarksDelta {
                retire_all: false,
                marks: vec![mark.clone()],
            },
        ))
        .unwrap();
    assert_eq!(
        manager.read_authority().metadata().workspaces[0].enrichment_marks,
        vec![mark.clone()],
        "control: the mark holds and is recorded"
    );
    let frame = std::fs::read(frame_path(&directory, 2)).unwrap();
    assert_eq!(
        header_version(&frame),
        crate::storage::AuthorityFrame::ENRICHMENT_MARKS_VERSION,
        "a frame that records marks declares version 6"
    );
    let marked = manager.read_authority().snapshot().clone();
    let marked_bytes = marked.to_bytes().unwrap();
    let expected = if marked.materialized_graph.is_some() {
        GraphSnapshot::ENRICHMENT_MARKS_SECTION_VERSION
    } else {
        GraphSnapshot::ENRICHMENT_MARKS_VERSION
    };
    assert_eq!(header_version(&marked_bytes), expected);
    assert!(
        header_version(&marked_bytes) > 20,
        "a binary that reads at most snapshot version 20 must refuse this at the header"
    );
    let decoded = GraphSnapshot::from_bytes(&marked_bytes).unwrap();
    assert_eq!(
        decoded.repository_authority.as_ref().unwrap().workspaces[0].enrichment_marks,
        vec![mark]
    );
    drop(manager);
    let reopened = RepositoryAuthorityManager::open(repository_id(), backend).unwrap();
    assert_eq!(
        reopened.read_authority().metadata().workspaces[0]
            .enrichment_marks
            .len(),
        1,
        "the journal replays the frame that recorded the mark"
    );

    // Without its marks and the operation that recorded them, the same state
    // serializes exactly as the store that never had any.
    assert_eq!(
        GraphSnapshot::from_bytes(&quiet_bytes)
            .unwrap()
            .wire_version(),
        quiet_version
    );
    let mut stripped = marked.clone();
    let envelope = stripped.repository_authority.as_mut().unwrap();
    envelope.workspaces[0].enrichment_marks.clear();
    envelope
        .operation_log
        .retain(|operation| !operation.carries_enrichment_marks());
    assert_eq!(stripped.wire_version(), quiet_version);
}

/// Full proof-input marks use the existing tuple wire shape, survive a real
/// journal reopen, and retire on same-ID validation changes. Merely reading an
/// older mark does not manufacture a version-eight completion.
#[test]
fn enrichment_proof_marks_reopen_without_promoting_legacy_and_retire_changed_context() {
    let directory = TempDir::new().unwrap();
    let (backend, manager) = framed_local_repository(&directory);
    let path = "src/lib.rs";
    let lease = manager.read_authority();
    let workspace = &lease.metadata().workspaces[0];
    let graph = lease
        .workspace_graph_snapshot(&workspace.workspace_id)
        .unwrap()
        .unwrap();
    let body = match workspace
        .tree
        .artifact_at_path(&RepoPath::from_utf8(path).unwrap())
        .unwrap()
        .entry
    {
        TreeEntry::Blob { hash, .. } => hash,
        _ => panic!(),
    };
    let entity_file = |id: &kin_model::EntityId| {
        graph
            .entities
            .get(id)
            .and_then(|entity| entity.file_origin.as_ref())
            .map(|file| file.0.as_str())
    };
    let legacy = kin_model::EnrichmentMark {
        path: path.into(),
        body,
        version: 7,
        relations: kin_model::enrichment_relations_digest(
            path,
            graph.relations.values(),
            entity_file,
            kin_model::enrichment_ledgers_by_file(graph.resolution_records.values(), entity_file)
                .remove(path)
                .unwrap_or_default(),
        ),
    };
    let full = kin_model::EnrichmentMark {
        version: kin_model::ENRICHMENT_PROOF_MARK_VERSION,
        relations: kin_model::enrichment_proof_inputs_by_file(
            [path],
            graph.entities.values(),
            graph.relations.values(),
            graph.resolution_records.values(),
        )
        .unwrap()[path],
        ..legacy.clone()
    };
    drop(lease);
    manager
        .commit_repository_transaction(enrichment_marks_transaction(
            &manager,
            0x0e3b_0001,
            kin_model::EnrichmentMarksDelta {
                retire_all: false,
                marks: vec![legacy.clone()],
            },
        ))
        .unwrap();
    drop(manager);
    let manager = RepositoryAuthorityManager::open(repository_id(), Arc::clone(&backend)).unwrap();
    assert_eq!(
        manager.read_authority().metadata().workspaces[0].enrichment_marks,
        [legacy]
    );
    manager
        .commit_repository_transaction(enrichment_marks_transaction(
            &manager,
            0x0e3b_0002,
            kin_model::EnrichmentMarksDelta {
                retire_all: false,
                marks: vec![full.clone()],
            },
        ))
        .unwrap();
    drop(manager);
    let manager = RepositoryAuthorityManager::open(repository_id(), Arc::clone(&backend)).unwrap();
    assert_eq!(
        manager.read_authority().metadata().workspaces[0].enrichment_marks,
        [full]
    );
    let mut transaction = enrichment_marks_transaction(&manager, 0x0e3b_0003, Default::default());
    let validation = kin_model::ResolutionRecord::ContextValidation(kin_model::ContextValidation {
        language: LanguageId::Rust,
        state: kin_model::ContextValidationState::Unverified {
            reason: "selected environment changed".into(),
        },
    });
    let mutation = transaction.workspace_mutation.as_mut().unwrap();
    mutation.semantic_delta = mutation
        .semantic_delta
        .clone()
        .with_resolution_records(vec![kin_model::ResolutionRecordDelta::Added {
            new: validation,
        }])
        .unwrap();
    manager.commit_repository_transaction(transaction).unwrap();
    assert!(manager.read_authority().metadata().workspaces[0]
        .enrichment_marks
        .is_empty());
    drop(manager);
    let reopened = RepositoryAuthorityManager::open(repository_id(), backend).unwrap();
    assert!(
        reopened.read_authority().metadata().workspaces[0]
            .enrichment_marks
            .is_empty(),
        "reopen cannot restore obsolete completion"
    );
}
