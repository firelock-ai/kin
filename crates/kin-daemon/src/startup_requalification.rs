// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Check a store's binding history before this daemon opens it.
//!
//! A store an earlier build wrote before binding history existed can record
//! this build's replay semantics and still carry no checked lineage, so every
//! reference answer over it stays qualified and its standing reads current.
//! `kin upgrade` re-qualifies such a store, and a daemon runs that same
//! re-qualification when it starts, so nobody has to run it by hand.
//!
//! It runs where `kin upgrade` runs it: while this process holds the
//! repository's runtime authority, which the caller has already taken, and
//! before any state is open, so no daemon is serving the authority the
//! re-qualification replaces and the state this daemon then opens is the one
//! it committed. It runs to completion however long the store takes. Meanwhile
//! the daemon's readiness answers warming, and each step it takes is reported
//! through [`WarmingProgress`], so a client polling readiness is told what it
//! is waiting for. The shared function decides everything else; this only runs
//! it, reports its progress and says in the daemon log what it did.

use kin_cli::commands::upgrade::{requalify_at_daemon_start, DaemonStartRequalification};

use crate::api::WarmingProgress;

/// What a start reports while it reads whether the store needs the work.
const CHECKING: &str = "checking this store's binding history before opening it";

/// What a start reports before each step of a re-qualification.
const REPORTED_AS: &str = "re-qualifying this store's binding history before opening it";

/// Re-qualify the store at `layout` when its workspace graph carries no
/// checked binding history, before this daemon opens it, reporting each step
/// through `progress` and through the startup record a client waiting on this
/// start reads.
///
/// Never fails the start. Whatever does not finish is left as it was, and
/// `kin upgrade` finishes it.
pub fn before_open(
    layout: &kin_core::KinLayout,
    progress: &WarmingProgress,
) -> DaemonStartRequalification {
    run(layout, progress, &|_| {})
}

/// [`before_open`], also handing each reported step to `observe` once every
/// reader can see it.
fn run(
    layout: &kin_core::KinLayout,
    progress: &WarmingProgress,
    observe: &dyn Fn(&str),
) -> DaemonStartRequalification {
    // The warming answer carries the whole sentence; the startup record
    // carries the step, beside the phase a waiting client prints.
    let say = |requalifying: bool, step: &str| {
        let said = if requalifying {
            format!("{REPORTED_AS}: {step}")
        } else {
            step.to_string()
        };
        progress.report(&said);
        kin_cli::daemon_client::record_startup_requalification(layout.root(), requalifying, step);
        tracing::info!("startup: {said}");
        observe(&said);
    };
    say(false, CHECKING);
    let step = |line: &str| say(true, line.strip_prefix("kin upgrade: ").unwrap_or(line));
    let outcome = requalify_at_daemon_start(layout, &step);
    progress.clear();
    kin_cli::daemon_client::clear_startup_requalification(layout.root());
    match &outcome {
        DaemonStartRequalification::AlreadyChecked => {
            tracing::debug!("this store's binding history is already checked");
        }
        DaemonStartRequalification::Requalified(report) => tracing::info!(
            authority_generation = ?report.authority_generation,
            heads = report.heads.len(),
            source_files = report.source_files,
            elapsed_ms = report.elapsed_ms,
            warnings = report.warnings.len(),
            "re-derived this store's served state before opening it, and its binding history is \
             checked from here"
        ),
        DaemonStartRequalification::NotAttempted(reason) => tracing::info!(
            %reason,
            "left this store's binding history as it stands; `kin upgrade` checks it"
        ),
        DaemonStartRequalification::Unfinished(reason) => tracing::warn!(
            %reason,
            "could not check this store's binding history before opening it; `kin upgrade` \
             checks it"
        ),
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Two real stores the published 0.7.21 release wrote, shared with the
    /// upgrade's own store tests.
    const FIXTURE: &[u8] =
        include_bytes!("../../kin-cli/tests/fixtures/published-0.7.21-stores.tar.gz");

    /// Whether the graph the store's workspace selects carries checked binding
    /// history, read from a freshly opened repository authority.
    fn lineage_checked(layout: &kin_core::KinLayout) -> bool {
        let (manager, _) = kin_core::LocalRepositoryAuthorityBinding::from_layout(layout)
            .unwrap()
            .open_manager_with_payload_stats()
            .unwrap();
        let lease = manager.read_authority();
        let workspace = lease.metadata().workspaces[0].workspace_id;
        lease
            .workspace_graph_snapshot(&workspace)
            .unwrap()
            .expect("the workspace has a committed graph")
            .verified_binding_history
            .is_some()
    }

    /// The change `main` names, read from a freshly opened repository authority.
    fn main_head(layout: &kin_core::KinLayout) -> kin_model::SemanticChangeId {
        let (manager, _) = kin_core::LocalRepositoryAuthorityBinding::from_layout(layout)
            .unwrap()
            .open_manager_with_payload_stats()
            .unwrap();
        let lease = manager.read_authority();
        let main = kin_model::RefName::branch(b"main").unwrap();
        let target = lease
            .metadata()
            .ref_state
            .refs
            .iter()
            .find(|reference| reference.name == main)
            .expect("the store has main")
            .target
            .clone();
        lease.resolve_target_change_id(&target).unwrap()
    }

    /// Bring the unpacked published store to a current one whose heads and
    /// workspace hold exactly this build's derivation and whose lineage an
    /// ordinary commit ended, the shape a pull or a clone leaves: `kin upgrade`
    /// re-derives it, then a ref commit that checks nothing ends the lineage.
    fn end_the_lineage_of_an_upgraded_store(layout: &kin_core::KinLayout) {
        use kin_model::{
            OperationId, RefExpectation, RefMutation, RefName, RefTarget, RefUpdatePolicy,
            RepositoryTransaction, REPOSITORY_TRANSACTION_SCHEMA_VERSION,
        };
        let author = kin_model::AuthorId::new("Kin Fixture <fixture@example.invalid>");
        let upgraded = kin_cli::commands::upgrade::upgrade_store(
            layout,
            author.clone(),
            &kin_cli::commands::upgrade::UpgradeHooks::default(),
            &|_| {},
        )
        .unwrap();
        assert_eq!(upgraded.binding_history_checked, Some(true));
        let (manager, _) = kin_core::LocalRepositoryAuthorityBinding::from_layout(layout)
            .unwrap()
            .open_manager_with_payload_stats()
            .unwrap();
        let lease = manager.read_authority();
        let roots = lease.roots().clone();
        let repository_id = lease.metadata().repository_id.clone();
        drop(lease);
        manager
            .commit_repository_transaction(RepositoryTransaction {
                schema_version: REPOSITORY_TRANSACTION_SCHEMA_VERSION,
                operation_id: OperationId::new(),
                repository_id,
                expected_generation: roots.generation,
                expected_roots: roots,
                actor: author,
                reason: "an ordinary commit that checks no binding history".to_string(),
                external_objects: Vec::new(),
                git_authority_delta: None,
                changes: Vec::new(),
                aliases: Vec::new(),
                ref_mutations: vec![RefMutation {
                    name: RefName::branch(b"lineage-probe").unwrap(),
                    expected: RefExpectation::MustNotExist,
                    new_target: Some(RefTarget::symbolic(RefName::branch(b"main").unwrap())),
                    policy: RefUpdatePolicy::FastForwardOnly,
                }],
                default_ref_mutation: None,
                workspace_mutation: None,
                local_overlay_delta: None,
                merge_transaction_delta: None,
                sealed_observation: None,
                collaboration_delta: None,
            })
            .unwrap();
        drop(manager);
        assert!(!lineage_checked(layout), "the fixture must start unproven");
    }

    /// A re-qualification held part way, for as long as the test likes, still
    /// runs to its commit once released, and while it is held the daemon's
    /// warming surface answers readiness as warming, not ready, naming the
    /// step it is on. No clock is involved: the hold is a barrier the test
    /// releases, so the proof costs no wall time and the product carries no
    /// deadline for it to race.
    ///
    /// The store is one the published build wrote, upgraded, then moved by a
    /// commit that ended its lineage: current, already this build's
    /// derivation, with no lineage. The lineage is read back through a fresh
    /// open of the store, twice, after the run, and main has not moved.
    ///
    /// Falsify by stopping the re-qualification at any deadline shorter than
    /// the hold: the lineage stays unproven. Falsify the reporting by dropping
    /// the progress from the warming answer: the held poll names no step.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_held_requalification_completes_while_readiness_reports_warming() {
        let root = tempfile::tempdir().unwrap();
        tar::Archive::new(flate2::read::GzDecoder::new(FIXTURE))
            .unpack(root.path())
            .unwrap();
        let layout = kin_core::KinLayout::new(root.path().join("clean/.kin"));
        end_the_lineage_of_an_upgraded_store(&layout);
        let head = main_head(&layout);
        // Held as a starting daemon holds it, before the check and the open.
        let _runtime = kin_cli::daemon_client::acquire_repository_runtime_authority(layout.root())
            .unwrap()
            .expect("take the repository's runtime authority");

        let (warming, _serving, port) = crate::api::bind_api_listener_pair(&layout, 0).unwrap();
        let (ready_tx, ready_rx) = tokio::sync::watch::channel(false);
        let progress = WarmingProgress::default();
        let server = tokio::spawn(crate::api::serve_warming_with_progress_until(
            warming,
            ready_rx,
            progress.clone(),
        ));

        // The hook holds the first derivation step until the test releases it.
        let (held_tx, held_rx) = tokio::sync::oneshot::channel::<String>();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let requalification = {
            let layout = layout.clone();
            let progress = progress.clone();
            let held_tx = Mutex::new(Some(held_tx));
            let release_rx = Mutex::new(release_rx);
            tokio::task::spawn_blocking(move || {
                run(&layout, &progress, &|said| {
                    if !said.starts_with(&format!("{REPORTED_AS}: re-deriving")) {
                        return;
                    }
                    if let Some(held) = held_tx.lock().unwrap().take() {
                        held.send(said.to_string()).unwrap();
                        release_rx.lock().unwrap().recv().unwrap();
                    }
                })
            })
        };

        let said = held_rx.await.expect("the run reaches a derivation step");
        let client = reqwest::Client::new();
        for _ in 0..3 {
            let response = client
                .get(format!("http://127.0.0.1:{port}/readiness"))
                .send()
                .await
                .expect("the warming surface answers while the run is held");
            assert_eq!(response.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
            let body: crate::api::ReadinessResponse = response.json().await.unwrap();
            assert!(!body.ready && body.warming, "{body:?}");
            assert_eq!(
                body.progress.as_deref(),
                Some(said.as_str()),
                "the held answer must name the step the run is on"
            );
            let health: serde_json::Value = client
                .get(format!("http://127.0.0.1:{port}/health"))
                .send()
                .await
                .unwrap()
                .json()
                .await
                .unwrap();
            assert_eq!(health["status"], "warming", "{health}");
            assert_eq!(
                health["progress"],
                body.progress.clone().unwrap(),
                "{health}"
            );
        }
        assert!(
            !requalification.is_finished(),
            "the run must still be held while the answers above were taken"
        );
        // No second start and no `kin upgrade` can run beside it: both need
        // the runtime authority this start holds.
        assert!(
            kin_cli::daemon_client::acquire_repository_runtime_authority_within(
                layout.root(),
                std::time::Duration::ZERO,
            )
            .unwrap()
            .is_none(),
            "the runtime authority must stay held while the run is"
        );
        assert!(!lineage_checked(&layout), "nothing is committed while held");
        // The same step is what a client waiting on this start reads, from the
        // record this process wrote.
        let record = kin_cli::daemon_client::read_startup_requalification(layout.root())
            .expect("the start records the step it is on");
        assert!(record.requalifying, "{record:?}");
        assert_eq!(format!("{REPORTED_AS}: {}", record.step), said);

        release_tx.send(()).unwrap();
        let outcome = requalification.await.unwrap();
        assert!(
            matches!(outcome, DaemonStartRequalification::Requalified(ref report)
                if report.binding_history_checked == Some(true)),
            "{outcome:?}"
        );
        assert_eq!(progress.current(), None, "the report ends with the run");
        assert_eq!(
            kin_cli::daemon_client::read_startup_requalification(layout.root()),
            None,
            "the startup record ends with the run"
        );
        for open in ["first", "second"] {
            assert!(
                lineage_checked(&layout),
                "the {open} reopen must read the lineage as checked"
            );
        }
        assert_eq!(main_head(&layout), head, "the re-qualification moved main");

        ready_tx.send(true).unwrap();
        server.await.unwrap();
    }
}
