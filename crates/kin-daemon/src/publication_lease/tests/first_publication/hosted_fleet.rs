// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

// Actual GCS generation fencing and daemon rollout over emulated object storage
// and Firestore. Fresh backend objects prove cache-independent recovery here;
// this fixture does not prove live cloud durability or a process restart.
use super::*;
use crate::state::DaemonState;

fn hosted_image(
    raw: Arc<VersionedMemoryStore>,
    spine: Arc<kin_spine::test_support::FakeSpineStore>,
    fleet: &[String],
) -> (Arc<PublicationControl>, DaemonState, tempfile::TempDir) {
    let object_store: Arc<dyn ObjectStore> = raw.clone();
    let control = Arc::new(
        PublicationControl::new(
            SCOPE,
            READER_A,
            fleet.to_vec(),
            Arc::new(ObjectStorePublicationControlStore::new(object_store, "v2")),
        )
        .unwrap(),
    );
    let repo = tempfile::tempdir().unwrap();
    let layout = kin_core::init_adopting(repo.path(), &RepositoryId::new("kin").unwrap())
        .unwrap()
        .layout;
    let state = DaemonState::open_with_backend_and_publication_control(
        layout,
        Box::new(GcsBackend::from_store(Box::new(raw), "v2")),
        "kin",
        Some(fleet.iter().cloned().collect()),
        control.clone(),
    )
    .unwrap();
    state.install_hosted_durable_spine_for_test(Arc::new(
        kin_spine::FirestoreSpineBackend::with_store(spine),
    ));
    assert!(state.hosted_spine_readiness_required());
    (control, state, repo)
}

fn extend_and_reopen(git_import: bool) {
    // Keep backend ownership outside async frames, including failed assertions.
    // GCS may own a fallback runtime created by a blocking publication worker.
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut environment = kin_core::test_env::EnvVarGuard::new();
    environment.apply("GOOGLE_CLOUD_PROJECT", Some("fixture-project"));
    environment.apply("KIN_GCS_BUCKET", Some("fixture"));
    environment.apply("KIN_GCS_PREFIX", Some("v2"));
    environment.apply::<_, &str>("KIN_DISABLE_SPINE", None);
    let temp = tempfile::tempdir().unwrap();
    let raw = Arc::new(VersionedMemoryStore::new());
    let spine = Arc::new(kin_spine::test_support::FakeSpineStore::cold());
    let backend: Arc<dyn StorageBackend> =
        Arc::new(GcsBackend::from_store(Box::new(raw.clone()), "v2"));
    let old_ids = canonical_repositories(&staging_fleet()).unwrap();
    environment.apply("KIN_REPO_IDS", Some(&old_ids.join(",")));
    let mut originals = BTreeMap::new();
    for name in &old_ids {
        let id = RepositoryId::new(name.clone()).unwrap();
        let original = source(&temp.path().join(name), &id, false);
        let roots = original.read_authority().roots().clone();
        publish_first_repository(original, &id, FirstPublicationMode::Native, backend.clone())
            .unwrap();
        originals.insert(
            name.clone(),
            (roots, backend.load_snapshot(name).unwrap().unwrap().0),
        );
    }
    let (old, old_state, _old_repo) = hosted_image(raw.clone(), spine.clone(), &old_ids);
    let first = old.bootstrap_runtime_if_absent().unwrap().unwrap();
    runtime
        .block_on(old_state.complete_hosted_startup_rollout(
            &old,
            first,
            Some(format!("sha256:{}", "d".repeat(64))),
        ))
        .expect("the original five-member fleet must be genuinely ready");
    runtime
        .block_on(old_state.hosted_readiness_spine_authority())
        .unwrap();
    let original_seal = spine.legacy_migration_seal.lock().unwrap().clone().unwrap();
    let (paused_bytes, paused_generation) = backend.load_snapshot("kin").unwrap().unwrap();
    // An identical payload is an idempotent retry. A pending write must carry
    // different, valid snapshot bytes so the generation fence is what refuses.
    let pending_write = kin_db::GraphSnapshot::empty().to_bytes().unwrap();
    kin_db::GraphSnapshot::from_bytes(&pending_write).unwrap();
    assert_ne!(pending_write, paused_bytes);

    let id = RepositoryId::new("private-sixth").unwrap();
    let mut target = old_ids.clone();
    target.push(id.to_string());
    let target = canonical_repositories(&target).unwrap();
    environment.apply("KIN_REPO_IDS", Some(&target.join(",")));
    let (candidate, candidate_state, _candidate_repo) =
        hosted_image(raw.clone(), spine.clone(), &target);
    assert_eq!(
        candidate.runtime_reader_identity(),
        old.runtime_reader_identity(),
        "membership alone must fence the old runtime"
    );
    assert!(candidate.bootstrap_runtime_if_absent().unwrap().is_none());
    assert!(candidate
        .assert_runtime_admitted(kin_db::GraphSnapshot::CURRENT_VERSION)
        .is_err());
    assert!(runtime
        .block_on(candidate_state.hosted_readiness_spine_authority())
        .is_err());
    let before = candidate.status().unwrap();
    let mut request = rollout_request_for_fleet(target.clone(), "fixture", "prepared-sixth", None);
    request.previous_repositories = Some(old_ids.clone());
    let mut wrong_previous = request.clone();
    wrong_previous.previous_repositories.as_mut().unwrap().pop();
    assert!(
        candidate.acquire_rollout(wrong_previous).is_err(),
        "previous membership must be exact"
    );
    assert_eq!(candidate.status().unwrap(), before);
    let missing = candidate.acquire_rollout(request.clone()).unwrap_err();
    assert!(
        missing
            .to_string()
            .contains("has no graph authority object"),
        "{missing}"
    );
    assert!(candidate
        .assert_runtime_admitted(kin_db::GraphSnapshot::CURRENT_VERSION)
        .is_err());
    for (name, (_, bytes)) in &originals {
        assert_eq!(&backend.load_snapshot(name).unwrap().unwrap().0, bytes);
    }
    assert_eq!(
        backend.load_snapshot("kin").unwrap().unwrap().1,
        paused_generation,
        "an incomplete capture must not rewrite old authority"
    );

    let prepared = source(&temp.path().join("sixth-source"), &id, git_import);
    let expected_roots = prepared.read_authority().roots().clone();
    let expected_refs =
        serde_json::to_value(&prepared.read_authority().metadata().ref_state).unwrap();
    let expected_git = prepared
        .read_authority()
        .metadata()
        .git_external_authority
        .clone();
    let mode = if git_import {
        FirstPublicationMode::GitImported
    } else {
        FirstPublicationMode::Native
    };
    publish_first_repository(prepared, &id, mode, backend.clone()).unwrap();
    let lease = candidate.acquire_rollout(request.clone()).unwrap();
    let retried = candidate.acquire_rollout(request).unwrap();
    assert_eq!(retried.token, lease.token);
    assert_eq!(retried.fence, lease.fence);
    assert_eq!(lease.fence_repositories, target);
    assert_eq!(lease.authority_fence.len(), 6);
    let proof = proof(&lease);
    let full_fence = candidate.spine_rollout_fence(&proof).unwrap();
    for omitted in ["kin", "private-sixth"] {
        let rows = full_fence
            .repositories
            .iter()
            .filter(|row| row.repo_id != omitted)
            .cloned()
            .collect::<Vec<_>>();
        let subset = rows
            .iter()
            .map(|row| row.repo_id.clone())
            .collect::<Vec<_>>();
        let incomplete = kin_spine::SpineRolloutFence::new_exact(
            SCOPE.to_string(),
            lease.fence,
            &lease.token,
            &subset,
            rows,
        )
        .unwrap();
        assert!(
            runtime
                .block_on(candidate_state.advance_hosted_spine_rollout_fence(incomplete))
                .is_err(),
            "a validly encoded partial fence must not advance: {omitted}"
        );
    }
    assert!(runtime
        .block_on(candidate_state.hosted_readiness_spine_authority())
        .is_err());
    runtime
        .block_on(candidate_state.complete_hosted_startup_rollout(&candidate, lease, None))
        .expect("the actual daemon must publish and admit all six members");
    runtime
        .block_on(candidate_state.hosted_readiness_spine_authority())
        .unwrap();
    let status = candidate.status().unwrap();
    assert_eq!(status.repositories, target);
    assert_eq!(
        status
            .last_authority_fence
            .iter()
            .map(|row| row.repo_id.clone())
            .collect::<Vec<_>>(),
        target
    );
    assert!(status.active_lease.is_none());
    let mut heads = spine
        .publication_state
        .lock()
        .unwrap()
        .heads
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    heads.sort();
    assert_eq!(heads, target, "the spine must commit the exact target set");
    assert!(
        old.assert_runtime_admitted(kin_db::GraphSnapshot::CURRENT_VERSION)
            .is_err(),
        "the same-image old fleet must be fenced"
    );
    assert!(runtime
        .block_on(old_state.hosted_readiness_spine_authority())
        .is_err());
    let stale = backend
        .save_snapshot("kin", &pending_write, paused_generation)
        .expect_err("a paused writer must lose its pre-fence generation");
    assert!(stale.to_string().contains("generation mismatch"), "{stale}");
    assert_eq!(
        spine
            .legacy_migration_seal
            .lock()
            .unwrap()
            .as_ref()
            .unwrap(),
        &original_seal
    );
    drop(candidate_state);
    drop(candidate);
    drop(old_state);
    drop(old);
    drop(backend);

    // Corrupt one durable input, not the cache or proof. Fresh adoption must
    // refuse before a missing head can masquerade as an admitted empty repo.
    let removed = spine
        .publication_state
        .lock()
        .unwrap()
        .heads
        .remove("private-sixth")
        .unwrap();
    let (damaged, damaged_state, _damaged_repo) = hosted_image(raw.clone(), spine.clone(), &target);
    let RuntimeSpineAuthority::Completed(evidence) = damaged.runtime_spine_authority().unwrap()
    else {
        panic!("rollout must have completed")
    };
    assert!(
        runtime
            .block_on(damaged_state.adopt_hosted_spine_rollout_fence(evidence))
            .is_err(),
        "fresh adoption must prove all six committed heads"
    );
    drop(damaged_state);
    drop(damaged);
    spine
        .publication_state
        .lock()
        .unwrap()
        .heads
        .insert("private-sixth".to_string(), removed);

    let (fresh, fresh_state, _fresh_repo) = hosted_image(raw.clone(), spine, &target);
    let RuntimeSpineAuthority::Completed(evidence) = fresh.runtime_spine_authority().unwrap()
    else {
        panic!("rollout must have completed")
    };
    runtime
        .block_on(fresh_state.adopt_hosted_spine_rollout_fence(evidence))
        .expect("fresh reader must prove the six-member durable fleet");
    fresh
        .assert_runtime_admitted(kin_db::GraphSnapshot::CURRENT_VERSION)
        .unwrap();
    runtime
        .block_on(fresh_state.hosted_readiness_spine_authority())
        .unwrap();
    assert!(fresh_state.serves_repo_id("private-sixth"));
    assert!(!fresh_state.serves_repo_id("unadmitted-seventh"));
    let reopened_backend: Arc<dyn StorageBackend> =
        Arc::new(GcsBackend::from_store(Box::new(raw), "v2"));
    for (name, (roots, bytes)) in originals {
        assert_eq!(
            reopened_backend.load_snapshot(&name).unwrap().unwrap().0,
            bytes
        );
        let authority = RepositoryAuthorityManager::open(
            RepositoryId::new(name).unwrap(),
            reopened_backend.clone(),
        )
        .unwrap();
        assert_eq!(authority.read_authority().roots(), &roots);
    }
    let sixth = RepositoryAuthorityManager::open(id, reopened_backend).unwrap();
    assert_eq!(sixth.read_authority().roots(), &expected_roots);
    assert_eq!(
        serde_json::to_value(&sixth.read_authority().metadata().ref_state).unwrap(),
        expected_refs
    );
    assert_eq!(
        sixth.read_authority().metadata().git_external_authority,
        expected_git
    );
    if git_import {
        for body in [OLD_BODY, NEW_BODY] {
            assert_eq!(
                sixth.load_source_blob(hash(body)).unwrap().as_deref(),
                Some(body)
            );
        }
    } else {
        assert!(sixth.read_authority().snapshot().entities.is_empty());
    }
}

#[test]
#[serial_test::serial]
fn hosted_fleet_admits_prepared_native_sixth_and_reopens() {
    extend_and_reopen(false);
}

#[test]
#[serial_test::serial]
fn hosted_fleet_admits_prepared_git_sixth_and_reopens() {
    extend_and_reopen(true);
}
