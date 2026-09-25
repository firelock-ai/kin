// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use super::*;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;

async fn wait_for_worker_condition(mut ready: impl FnMut() -> bool) {
    tokio::time::timeout(Duration::from_secs(20), async {
        while !ready() {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .expect("owned worker did not reach its explicit boundary");
}

// The parent retains an open read/write FIFO, so cleanup never blocks opening
// a writer if an earlier assertion fails before the shell reaches its read.
struct RunnerRelease(std::fs::File);
impl Drop for RunnerRelease {
    fn drop(&mut self) {
        let _ = self.0.write_all(b"release\n");
    }
}

#[tokio::test]
async fn worker_publication_verify_cancel_keeps_gate_until_proof_publication() {
    let (repo, state) = mcp_lifecycle_fixture();
    std::fs::write(
        repo.path().join("source.py"),
        "def verified():\n    return 1\n",
    )
    .unwrap();
    waiting_admit(&state, "verification baseline").await;
    waiting_commit(&state, "verification baseline").await;
    let entity = waiting_entity(&state, "source.py", "verified");
    let control = tempfile::tempdir().unwrap();
    let started = control.path().join("started");
    let fifo = control.path().join("release");
    let fifo_c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: the owned NUL-terminated path lives across this call.
    assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
    let release = RunnerRelease(
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&fifo)
            .unwrap(),
    );
    let script = control.path().join("verify.sh");
    std::fs::write(
        &script,
        format!(
            "#!/bin/sh\nexec 3<> '{}'\nprintf ready > '{}'\nread token <&3\nexit 0\n",
            fifo.display(),
            started.display()
        ),
    )
    .unwrap();
    let worker_state = Arc::clone(&state);
    let runner = format!("/bin/sh {}", script.display());
    let task = tokio::spawn(async move {
        router(worker_state)
            .oneshot(
                Request::post("/verify/run")
                    .header("content-type", "application/json")
                    .body(Body::from(
                        serde_json::json!({"entity":"verified","runner":runner,"depth":0})
                            .to_string(),
                    ))
                    .unwrap(),
            )
            .await
    });
    wait_for_worker_condition(|| started.exists()).await;
    assert!(state.stable_graph_authority_epoch().is_none());
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    let gate_was_retained = state.coordination_gate.try_lock().is_err();
    drop(release);
    wait_for_worker_condition(|| state.stable_graph_authority_epoch().is_some()).await;
    let runs = state.graph.list_runs_proving_entity(&entity.id).unwrap();
    assert_eq!(
        runs.len(),
        1,
        "the detached real runner still installs its proof"
    );
    assert_eq!(runs[0].status, kin_model::VerificationStatus::Passing);
    assert!(
        gate_was_retained,
        "cancelling the request released coordination before the blocking proof writer finished"
    );
    let released = tokio::time::timeout(Duration::from_secs(20), state.coordination_gate.lock())
        .await
        .expect("completed verification worker did not release coordination");
    drop(released);
}

#[tokio::test]
async fn worker_publication_pull_cancel_keeps_gate_until_workspace_publication() {
    let baseline = b"services:\n  api: { image: baseline }\n";
    let successor = b"services:\n  api: { image: successor }\n";
    let fixture = workspace_follow_fixture("worker-publication-pull", baseline, successor).await;
    // Hold the existing persistence fence. Follow announces its authority
    // epoch before it waits here, giving an exact boundary without a timing
    // race or a new production-only scheduling hook.
    let held_state = Arc::clone(&fixture.state);
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let held = tokio::task::spawn_blocking(move || {
        let _persist = held_state.persist_lock.lock().unwrap();
        ready_tx.send(()).unwrap();
        let _ = release_rx.recv_timeout(Duration::from_secs(30));
    });
    ready_rx.await.unwrap();
    let request = pull_request(&fixture.peer_url, &fixture.state.cached_repo_id);
    let worker_state = Arc::clone(&fixture.state);
    let task = tokio::spawn(async move { transfer_command(worker_state, "pull", &request).await });
    wait_for_worker_condition(|| fixture.state.stable_graph_authority_epoch().is_none()).await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    let gate_was_retained = fixture.state.coordination_gate.try_lock().is_err();
    release_tx.send(()).unwrap();
    held.await.unwrap();
    wait_for_worker_condition(|| fixture.state.stable_graph_authority_epoch().is_some()).await;
    assert_eq!(
        std::fs::read(&fixture.projected).unwrap(),
        successor,
        "the detached follow still completes its exact workspace transition"
    );
    let authority =
        ActiveApiRepositoryAuthority::open_layout_for_test(&fixture.state.layout).unwrap();
    let lease = authority.manager.read_authority();
    let workspace = lease
        .metadata()
        .workspaces
        .iter()
        .find(|workspace| workspace.workspace_id == authority.workspace_id)
        .unwrap();
    assert_eq!(
        workspace.base_target,
        Some(kin_model::RefTarget::change(fixture.peer_head))
    );
    assert!(gate_was_retained, "cancelling the request released coordination before the blocking workspace writer finished");
    let released = tokio::time::timeout(
        Duration::from_secs(20),
        fixture.state.coordination_gate.lock(),
    )
    .await
    .expect("completed workspace worker did not release coordination");
    drop(released);
}

#[cfg(feature = "embeddings")]
#[tokio::test]
async fn worker_publication_embed_coverage_waits_and_reads_the_current_admitted_body() {
    let (repo, state) = mcp_lifecycle_fixture();
    let path = repo.path().join("source.py");
    let file_id = kin_model::FilePathId::new("source.py");
    std::fs::write(&path, b"\0\xffnot-source").unwrap();
    waiting_admit(&state, "opaque baseline").await;
    assert!(state.graph.get_opaque_artifact(&file_id).unwrap().is_some());
    // Reproduce the missing sidecar shape from bulk admission. The exact tree
    // and its current bytes remain product-admitted authority.
    state.graph.delete_opaque_artifact(&file_id).unwrap();
    let coordination = state.coordination_gate.lock().await;
    let worker_state = Arc::clone(&state);
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let mut worker = tokio::task::spawn_blocking(move || {
        started_tx.send(()).unwrap();
        prepare_foreground_embed_coverage(&worker_state)
    });
    started_rx.await.unwrap();
    let early = tokio::time::timeout(Duration::from_millis(250), &mut worker).await;
    let completed_before_release = early.is_ok();
    // Ordinary source admission occurs while the exact same gate is held.
    // The delayed coverage pass must read this successor, not the earlier
    // binary classification, and must leave its declaration/layout intact.
    std::fs::write(&path, "def current_source():\n    return 2\n").unwrap();
    crate::loop_runner::sync_filesystem_with_graph_under_coordination(&state)
        .await
        .unwrap();
    let source = waiting_entity(&state, "source.py", "current_source");
    drop(coordination);
    let created = match early {
        Ok(result) => result.unwrap().unwrap(),
        Err(_) => worker.await.unwrap().unwrap(),
    };
    assert_eq!(state.graph.get_entity(&source.id).unwrap(), Some(source));
    assert!(state.graph.get_file_layout(&file_id).unwrap().is_some());
    assert!(state.graph.get_opaque_artifact(&file_id).unwrap().is_none());
    assert!(
        !completed_before_release,
        "foreground coverage mutated the graph while another publication held coordination"
    );
    assert_eq!(
        created, 0,
        "the worker must classify the admitted successor source"
    );
}

#[cfg(feature = "embeddings")]
#[tokio::test]
async fn worker_publication_embed_coverage_recreates_current_records_without_a_model() {
    let (repo, state) = mcp_lifecycle_fixture();
    let file_id = kin_model::FilePathId::new("AGENTS.md");
    std::fs::write(repo.path().join("AGENTS.md"), "# Current doctrine\n").unwrap();
    waiting_admit(&state, "current non-source").await;
    state.graph.delete_opaque_artifact(&file_id).unwrap();
    let worker_state = Arc::clone(&state);
    let created =
        tokio::task::spawn_blocking(move || prepare_foreground_embed_coverage(&worker_state))
            .await
            .unwrap()
            .unwrap();
    assert_eq!(created, 1);
    let record = state.graph.get_opaque_artifact(&file_id).unwrap().unwrap();
    assert!(record
        .text_preview
        .as_deref()
        .unwrap_or_default()
        .contains("Current doctrine"));
    assert!(state.coordination_gate.try_lock().is_ok());
    assert!(state.stable_graph_authority_epoch().is_some());
    let worker_state = Arc::clone(&state);
    assert_eq!(
        tokio::task::spawn_blocking(move || prepare_foreground_embed_coverage(&worker_state))
            .await
            .unwrap()
            .unwrap(),
        0
    );
}
