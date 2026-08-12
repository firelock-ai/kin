// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

pub mod backend;
pub mod capability;
pub mod commands;
pub mod daemon_client;
pub mod model_residency;
pub mod output_style;
pub mod profile;
pub mod progress;
pub mod provenance;
pub mod resource_profile;
pub mod retrieval_profile;

#[cfg(all(test, unix))]
#[test]
fn kin_process_group_guardian_worker() {
    let requested = std::env::var_os(kin_daemon_spawn::PROCESS_GROUP_GUARDIAN_MODE_ENV).is_some();
    let dispatched = kin_daemon_spawn::run_process_group_guardian_if_requested()
        .expect("run exact process-group guardian worker");
    assert_eq!(dispatched, requested);
}
