// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use super::*;

#[test]
#[serial_test::serial]
fn hosted_fleet_contract_accepts_six_prepared_repository_ids() {
    let mut environment = kin_core::test_env::EnvVarGuard::new();
    environment.apply("GOOGLE_CLOUD_PROJECT", Some("fixture-project"));
    environment.apply("KIN_GCS_BUCKET", Some("fixture-bucket"));
    environment.apply("KIN_GCS_PREFIX", Some("fixture-prefix"));
    let (mut state, _repo) = hosted_state_for_contract(true);
    let (_, original) = state
        .hosted_spine_contract()
        .expect("five-member positive control");
    state
        .allowed_repo_ids
        .as_mut()
        .unwrap()
        .insert("private-sixth".to_string());
    let (_, target) = state
        .hosted_spine_contract()
        .expect("a complete six-member configured fleet must be accepted");
    assert_eq!(target.len(), 6);
    assert!(original.iter().all(|id| target.contains(id)));
    assert!(target.contains(&"private-sixth".to_string()));
}

#[test]
#[serial_test::serial]
fn hosted_fleet_contract_retains_canonical_bounds() {
    let mut environment = kin_core::test_env::EnvVarGuard::new();
    environment.apply("GOOGLE_CLOUD_PROJECT", Some("fixture-project"));
    environment.apply("KIN_GCS_BUCKET", Some("fixture-bucket"));
    environment.apply("KIN_GCS_PREFIX", Some("fixture-prefix"));
    let (mut state, _repo) = hosted_state_for_contract(true);
    for size in [1, 5, 6, 64] {
        let fleet = (0..size)
            .map(|i| format!("repo-{i:02}"))
            .collect::<Vec<_>>();
        state.allowed_repo_ids = Some(fleet.iter().cloned().collect());
        assert_eq!(state.hosted_spine_contract().unwrap().1, fleet);
    }
    for size in [0, 65] {
        state.allowed_repo_ids = Some((0..size).map(|i| format!("repo-{i}")).collect());
        assert!(
            state.hosted_spine_contract().is_err(),
            "invalid fleet size {size}"
        );
    }
    for invalid in ["", " bad", "bad/name", "bad\\name", "repo name"] {
        state.allowed_repo_ids = Some([invalid.to_string()].into_iter().collect());
        assert!(
            state.hosted_spine_contract().is_err(),
            "invalid repo ID {invalid:?}"
        );
    }
    state.allowed_repo_ids = None;
    assert!(state.hosted_spine_contract().is_err());
    let duplicate = vec!["kin".to_string(), "kin".to_string()];
    assert!(crate::publication_lease::canonical_repositories(&duplicate).is_err());
}
