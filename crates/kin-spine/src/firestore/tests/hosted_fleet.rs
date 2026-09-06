// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use super::*;

#[cfg(feature = "firestore")]
#[test]
fn legacy_seal_allows_a_later_additive_fleet_without_resealing() {
    let (_, original, _, seal) = five_repository_seal_fixture();
    seal.validate_against_active(&original).unwrap();
    let bytes = serde_json::to_vec(&seal).unwrap();
    let expanded = LoadedSpineRolloutFence {
        fence: test_rollout_fence(
            8,
            "six-repo-rollout",
            &[
                "kin",
                "kin-db",
                "kin-lsp",
                "kin-model",
                "kin-search",
                "private-sixth",
            ],
        ),
        update_time: "later-revision".to_string(),
    };
    seal.validate_against_active(&expanded)
        .expect("a later fenced addition must retain the historical legacy drain seal");
    assert_eq!(serde_json::to_vec(&seal).unwrap(), bytes);
}

fn active_with(fence: u64, ids: &[&str]) -> LoadedSpineRolloutFence {
    LoadedSpineRolloutFence {
        fence: test_rollout_fence(fence, "fleet-transition", ids),
        update_time: "next-revision".to_string(),
    }
}

#[cfg(feature = "firestore")]
#[test]
fn legacy_seal_rejects_removing_an_original_member() {
    let (_, _, _, seal) = five_repository_seal_fixture();
    let removed = active_with(
        8,
        &["kin", "kin-db", "kin-model", "kin-search", "private-sixth"],
    );
    let error = seal.validate_against_active(&removed).unwrap_err();
    assert!(error.to_string().contains("retain every sealed"), "{error}");
}

#[cfg(feature = "firestore")]
#[test]
fn legacy_seal_rejects_changed_same_fence_membership_and_evidence() {
    let (_, original, _, seal) = five_repository_seal_fixture();
    let same_fence = active_with(
        7,
        &[
            "kin",
            "kin-db",
            "kin-lsp",
            "kin-model",
            "kin-search",
            "private-sixth",
        ],
    );
    assert!(
        seal.validate_against_active(&same_fence).is_err(),
        "same-fence addition must refuse"
    );
    let mut changed_revision = original.clone();
    changed_revision.update_time = "other-revision".to_string();
    assert!(
        seal.validate_against_active(&changed_revision).is_err(),
        "same-fence revision must be exact"
    );
    let changed_payload = active_with(7, &["kin", "kin-db", "kin-lsp", "kin-model", "kin-search"]);
    assert!(
        seal.validate_against_active(&changed_payload).is_err(),
        "same-fence payload must be exact"
    );
}

#[cfg(feature = "firestore")]
#[test]
fn legacy_seal_rejects_rollback_and_foreign_scope() {
    let (_, _, _, seal) = five_repository_seal_fixture();
    let lower = active_with(6, &["kin", "kin-db", "kin-lsp", "kin-model", "kin-search"]);
    assert!(
        seal.validate_against_active(&lower).is_err(),
        "a seal cannot attest an older fence"
    );
    let next = active_with(
        8,
        &[
            "kin",
            "kin-db",
            "kin-lsp",
            "kin-model",
            "kin-search",
            "private-sixth",
        ],
    );
    let foreign = LoadedSpineRolloutFence {
        fence: SpineRolloutFence::new_exact(
            "gcs://other-bucket/other-prefix".to_string(),
            8,
            "foreign",
            &seal.repository_ids,
            next.fence.repositories[..5].to_vec(),
        )
        .unwrap(),
        update_time: "foreign-revision".to_string(),
    };
    assert!(
        seal.validate_against_active(&foreign).is_err(),
        "foreign scope must refuse even with valid payload"
    );
}

#[cfg(feature = "firestore")]
#[test]
fn legacy_seal_rejects_invalid_active_fence_and_missing_revision() {
    let (_, original, _, seal) = five_repository_seal_fixture();
    let mut invalid = active_with(
        8,
        &[
            "kin",
            "kin-db",
            "kin-lsp",
            "kin-model",
            "kin-search",
            "private-sixth",
        ],
    );
    invalid.fence.payload_sha256 = format!("sha256:{}", "0".repeat(64));
    assert!(
        seal.validate_against_active(&invalid).is_err(),
        "the active payload must validate"
    );
    let mut missing = original;
    missing.update_time.clear();
    assert!(seal.validate_against_active(&missing).is_err());
}

#[cfg(feature = "firestore")]
#[test]
fn legacy_seal_keeps_original_head_and_drain_evidence_validated_after_expansion() {
    let (_, _, _, seal) = five_repository_seal_fixture();
    let next = active_with(
        8,
        &[
            "kin",
            "kin-db",
            "kin-lsp",
            "kin-model",
            "kin-search",
            "private-sixth",
        ],
    );
    let mut malformed_digest = seal.clone();
    malformed_digest.head_set_sha256 = format!("sha256:{}", "0".repeat(64));
    assert!(
        malformed_digest.validate_against_active(&next).is_err(),
        "the original head-set digest must still validate"
    );
    let mut missing_head = seal.clone();
    missing_head.sealed_heads.pop();
    assert!(missing_head.validate_against_active(&next).is_err());
    let mut changed_drain = seal.clone();
    changed_drain
        .writer_drain
        .rollout_fence_evidence
        .rollout_fence += 1;
    assert!(changed_drain.validate_against_active(&next).is_err());
    let mut duplicate = seal;
    duplicate
        .repository_ids
        .insert(0, duplicate.repository_ids[0].clone());
    assert!(duplicate.validate_against_active(&next).is_err());
}

#[test]
fn legacy_seal_expansion_still_requires_every_new_committed_head() {
    let store = Arc::new(FakeSpineStore::cold());
    let backend = FirestoreSpineBackend::with_store(store.clone());
    assert!(matches!(
        backend
            .advance_rollout_fence(test_rollout_fence(1, "original", &["repo"]))
            .unwrap(),
        SpineRolloutFenceCommit::Advanced(_)
    ));
    publish_success(
        &backend,
        metadata_publication("repo", 1, "old-root", Vec::new()),
    );
    backend
        .complete_legacy_migration(test_writer_drain(&store))
        .unwrap();
    backend.hydrate().unwrap();
    let original_seal = store.legacy_migration_seal.lock().unwrap().clone();
    assert!(matches!(
        backend
            .advance_rollout_fence(test_rollout_fence(2, "expanded", &["repo", "sixth"]))
            .unwrap(),
        SpineRolloutFenceCommit::Advanced(_)
    ));
    assert!(
        backend.legacy_migration_complete().unwrap(),
        "the historical seal remains valid"
    );
    let cold = FirestoreSpineBackend::with_store(store.clone());
    let missing = cold.hydrate().unwrap_err();
    assert!(
        missing
            .to_string()
            .contains("head set does not equal the active exact fleet"),
        "{missing}"
    );
    publish_success(
        &backend,
        metadata_publication("sixth", 1, "new-root", Vec::new()),
    );
    cold.hydrate()
        .expect("all current complete publications make the additive fence readable");
    assert_eq!(*store.legacy_migration_seal.lock().unwrap(), original_seal);
}

#[test]
fn legacy_seal_fleet_validator_preserves_additive_authority_without_features() {
    let original = active_with(7, &["kin", "kin-db", "kin-lsp", "kin-model", "kin-search"]);
    let ids = original
        .fence
        .repositories
        .iter()
        .map(|row| row.repo_id.clone())
        .collect::<Vec<_>>();
    let evidence = original.evidence();
    let validate = |active: &LoadedSpineRolloutFence| {
        validate_legacy_seal_fleet(&original.fence.scope, &ids, &evidence, active)
    };
    validate(&original).unwrap();
    let later = active_with(
        8,
        &[
            "kin",
            "kin-db",
            "kin-lsp",
            "kin-model",
            "kin-search",
            "private-sixth",
        ],
    );
    validate(&later).expect("the production validator must allow a later additive fleet");
    let removed = active_with(
        8,
        &["kin", "kin-db", "kin-model", "kin-search", "private-sixth"],
    );
    assert!(validate(&removed).is_err(), "sealed members must remain");
    let same = active_with(
        7,
        &[
            "kin",
            "kin-db",
            "kin-lsp",
            "kin-model",
            "kin-search",
            "private-sixth",
        ],
    );
    assert!(
        validate(&same).is_err(),
        "same-fence membership must stay exact"
    );
    let mut revision = original.clone();
    revision.update_time = "different-revision".to_string();
    assert!(
        validate(&revision).is_err(),
        "same-fence revision must stay exact"
    );
    let lower = active_with(6, &["kin", "kin-db", "kin-lsp", "kin-model", "kin-search"]);
    assert!(validate(&lower).is_err(), "rollback must refuse");
    let foreign = LoadedSpineRolloutFence {
        fence: SpineRolloutFence::new_exact(
            "gcs://foreign/scope".to_string(),
            8,
            "foreign",
            &ids,
            original.fence.repositories.clone(),
        )
        .unwrap(),
        update_time: "foreign-revision".to_string(),
    };
    assert!(validate(&foreign).is_err(), "scope must stay bound");
    let mut invalid = later;
    invalid.fence.payload_sha256 = format!("sha256:{}", "0".repeat(64));
    assert!(
        validate(&invalid).is_err(),
        "active fence payload must validate"
    );
}
