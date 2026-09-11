// An admission and the runtime worker it runs on. Included into
// `loop_runner::tests`.

/// Clears the admission pause however the case ends, so a failing assertion
/// cannot leave a pause armed for an address a later allocation might reuse.
struct AdmissionPauseGuard;

impl Drop for AdmissionPauseGuard {
    fn drop(&mut self) {
        *ADMISSION_PAUSE_FOR_TEST
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
    }
}

/// An admission does not hold the runtime worker it runs on.
///
/// A multi-thread runtime with one worker, an admission held open for two
/// seconds through the test pause, and a task spawned while it is held. That
/// task can only run on a worker: if the admission kept its worker, the task
/// waits the pause out; handed off, it runs at once. Measured before this on a
/// real daemon over a 3.5 GiB store, a worker held by the reconcile loop's
/// admission for 121.9 s left every new connection to `/readiness` unanswered
/// until the publication finished.
///
/// Breaking it: run the admission inline on its worker again, and the spawned
/// task waits for the whole pause.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn an_admission_does_not_hold_the_runtime_worker_it_runs_on() {
    let parent = tempfile::tempdir().unwrap();
    let repo = tempfile::tempdir_in(parent.path()).unwrap();
    let state = open_test_state(&repo);
    state.is_initialized.store(true, Ordering::Relaxed);
    std::fs::write(
        state.layout.working_dir().join("held.py"),
        "def held():\n    return 1\n",
    )
    .unwrap();

    let _guard = AdmissionPauseGuard;
    *ADMISSION_PAUSE_FOR_TEST
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) =
        Some((Arc::as_ptr(&state) as usize, Duration::from_secs(2)));
    let admitting = {
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            exact_tree_admission(&state, None, TreePublication::Standalone)
                .map(|admission| admission.changed_paths.len())
        })
    };

    // The test's own thread is blocked on purpose: it is not a runtime worker,
    // and a runtime timer would need the very worker this case is about.
    std::thread::sleep(Duration::from_millis(400));
    let spawned = std::time::Instant::now();
    let answered = tokio::spawn(async { std::time::Instant::now() })
        .await
        .unwrap();
    let waited = answered.saturating_duration_since(spawned);
    let admitted = admitting.await.unwrap();

    assert!(
        admitted.is_ok(),
        "the admission itself must succeed, or this case measures a failure: {admitted:?}"
    );
    assert!(
        waited < Duration::from_millis(1000),
        "a task spawned while an admission ran waited {waited:?} for a worker, so the admission \
         is holding the runtime worker it runs on"
    );
}
