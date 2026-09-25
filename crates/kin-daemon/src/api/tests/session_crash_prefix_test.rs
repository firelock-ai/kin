// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Whole-process crash prefixes for one real session publication.
//!
//! Every control here spawns this test binary again as one owned daemon child,
//! drives one actual session publication through the production route inside
//! that child, stops the child dead with SIGKILL exactly at one observed engine
//! boundary, restarts on the same repository through the production startup
//! path and grades what the product did.
//!
//! What the child is: a controlled harness process running production
//! `DaemonState::open`, the production router and the production storage paths.
//! It is not an installed release daemon and it does not bind a socket; the
//! request is driven through the same router the listener serves. What the
//! crash is: a real `SIGKILL` delivered by the parent to a process it started
//! itself, while that process is stopped inside the boundary under every lock
//! the phase holds. No in-process fault injection decides any outcome below.
//!
//! The five prefixes are the ones the runtime adapter record requires:
//! immutable payload before acknowledgement, acknowledgement before the
//! projection WAL, partial primary before authority, authority before live
//! finalization, and WAL cleanup before the reply. Each carries a negative
//! control that stops one boundary later, so a crash after the prefix cannot be
//! graded as a crash before it.

use super::*;
use kin_model::OperationId;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Set only on a controlled child. Production code never reads these; the call
/// sites that do are `cfg(test)` and cannot exist in a released binary.
const STOP_ENV: &str = "KINTEST_SESSION_CRASH_STOP";
const CONTROL_ENV: &str = "KINTEST_SESSION_CRASH_CONTROL";
const REPO_ENV: &str = "KINTEST_SESSION_CRASH_REPO";
const SESSION_ENV: &str = "KINTEST_SESSION_CRASH_SESSION";

const CHILD_TEST: &str = "api::tests::session_crash_prefix_test::session_crash_prefix_child";

/// How long the parent waits for a child to reach its boundary. A cold child
/// opens the whole durable publication before it can serve anything.
const CHILD_DEADLINE: Duration = Duration::from_secs(180);

// ---------------------------------------------------------------------------
// The observed boundaries
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum CrashPoint {
    /// The immutable `.ksp` payload is visible and synced; the authority has
    /// not acknowledged it.
    PayloadBeforeAcknowledgement,
    /// The engine's prepare closure returned a verified handle, so the
    /// acknowledgement is installed; no projection WAL exists yet.
    AcknowledgedBeforeWal,
    /// Exactly one staged primary object has been published under the
    /// authenticated WAL; the authority has not committed.
    PartialPrimaryBeforeAuthority,
    /// The authority returned its receipt and freeze; no live finalization,
    /// adoption or facet write has run.
    AuthorityBeforeFinalization,
    /// Live finalization, adoption and WAL cleanup all finished; the response
    /// has not been produced.
    CleanupBeforeReply,
    /// The caller already holds the response. Durably indistinguishable from
    /// the prefix above by design: reply loss is replay.
    AfterReply,
}

impl CrashPoint {
    fn name(self) -> &'static str {
        match self {
            Self::PayloadBeforeAcknowledgement => "payload-before-acknowledgement",
            Self::AcknowledgedBeforeWal => "acknowledged-before-wal",
            Self::PartialPrimaryBeforeAuthority => "partial-primary-before-authority",
            Self::AuthorityBeforeFinalization => "authority-before-finalization",
            Self::CleanupBeforeReply => "cleanup-before-reply",
            Self::AfterReply => "after-reply",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        [
            Self::PayloadBeforeAcknowledgement,
            Self::AcknowledgedBeforeWal,
            Self::PartialPrimaryBeforeAuthority,
            Self::AuthorityBeforeFinalization,
            Self::CleanupBeforeReply,
            Self::AfterReply,
        ]
        .into_iter()
        .find(|point| point.name() == text)
    }

    /// The boundary immediately after this one. Killing there is the negative
    /// control: it must not be graded as a crash at `self`.
    fn just_after(self) -> Option<Self> {
        match self {
            Self::PayloadBeforeAcknowledgement => Some(Self::AcknowledgedBeforeWal),
            Self::AcknowledgedBeforeWal => Some(Self::PartialPrimaryBeforeAuthority),
            Self::PartialPrimaryBeforeAuthority => Some(Self::AuthorityBeforeFinalization),
            Self::AuthorityBeforeFinalization => Some(Self::CleanupBeforeReply),
            Self::CleanupBeforeReply => Some(Self::AfterReply),
            Self::AfterReply => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Child-side hooks. Production call sites are `cfg(all(test, unix))`.
// ---------------------------------------------------------------------------

fn configured(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|value| !value.is_empty())
}

fn configured_stop() -> Option<CrashPoint> {
    CrashPoint::parse(&configured(STOP_ENV)?)
}

fn configured_control() -> Option<PathBuf> {
    configured(CONTROL_ENV).map(PathBuf::from)
}

/// The exact operation this session was materialized under, read from the
/// retained session base rather than guessed from current state.
fn session_operation(session_dir: &Path) -> Option<OperationId> {
    let base: serde_json::Value =
        serde_json::from_slice(&std::fs::read(session_dir.join(".kin-session/base.json")).ok()?)
            .ok()?;
    let text = base["reconcile_operation_id"].as_str()?;
    Some(OperationId::from_uuid(uuid::Uuid::parse_str(text).ok()?))
}

pub(crate) struct ChildObservers {
    _payload: kin_db::session_publication_test_support::ObserverGuard,
    _projection: kin_core::session_publication_test_support::ObserverGuard,
}

/// Register the engine observers on the actual blocking publication thread.
///
/// Returns `None` in every process that is not a controlled child, which is
/// every process that has not been handed a stop boundary in its environment.
pub(crate) fn install_child_observers(
    state: &DaemonState,
    session_dir: &Path,
) -> Option<ChildObservers> {
    configured_stop()?;
    let operation = session_operation(session_dir)?;
    // The retained storage capability reports its resolved namespace path, and
    // a temporary root reaches that namespace through a symlinked ancestor on
    // this platform, so the payload observer has to name the resolved one. The
    // projection observer matches the exact path the runtime passes the engine.
    let primary = state.layout.working_dir().to_path_buf();
    let kindb = std::fs::canonicalize(state.layout.working_dir())
        .ok()?
        .join(".kin")
        .join("kindb")
        .join(&state.cached_repo_id);
    let payload = kin_db::session_publication_test_support::observe(kindb, operation, |_| {
        reached(CrashPoint::PayloadBeforeAcknowledgement);
    })
    .expect("payload observer registers once on the blocking publication thread");
    let projection = kin_core::session_publication_test_support::observe(
        primary,
        operation,
        |event| match event.point {
            kin_core::session_publication_test_support::Point::PreparationReturnedBeforeWal => {
                reached(CrashPoint::AcknowledgedBeforeWal)
            }
            kin_core::session_publication_test_support::Point::FirstPrimaryEntryPublished => {
                reached(CrashPoint::PartialPrimaryBeforeAuthority)
            }
        },
    )
    .expect("projection observer registers once on the blocking publication thread");
    Some(ChildObservers {
        _payload: payload,
        _projection: projection,
    })
}

/// Record that this boundary was reached, and stop dead on it when it is the
/// configured one. Stopping means parking forever under every lock the phase
/// holds: the parent kills this process here, so nothing after the boundary
/// can run, be flushed or be observed.
pub(crate) fn reached(point: CrashPoint) {
    let Some(control) = configured_control() else {
        return;
    };
    if let Ok(mut log) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(control.with_extension("progress"))
    {
        use std::io::Write as _;
        let _ = writeln!(log, "{}", point.name());
        let _ = log.flush();
    }
    if configured_stop() != Some(point) {
        return;
    }
    let pending = control.with_extension("pending");
    std::fs::write(&pending, point.name()).expect("write the controlled stop marker");
    std::fs::rename(&pending, &control).expect("publish the controlled stop marker");
    loop {
        std::thread::sleep(Duration::from_millis(20));
    }
}

// ---------------------------------------------------------------------------
// Startup phase ledger: does the resolver run before hydration?
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StartupPhase {
    /// `session_publication::recover_before_hydration` entered.
    Resolver,
    /// The workspace graph snapshot phase entered, which is hydration.
    Hydration,
}

thread_local! {
    static STARTUP_PHASES: std::cell::RefCell<Vec<StartupPhase>> = const { std::cell::RefCell::new(Vec::new()) };
}

pub(crate) fn record_startup_phase(phase: StartupPhase) {
    STARTUP_PHASES.with(|phases| {
        phases.borrow_mut().push(phase);
    });
}

fn take_startup_phases() -> Vec<StartupPhase> {
    STARTUP_PHASES.with(|phases| std::mem::take(&mut *phases.borrow_mut()))
}

// ---------------------------------------------------------------------------
// Durable classification: which prefix does the stopped repository hold?
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PrefixClass {
    /// Nothing of this operation is durable at all.
    Nothing,
    /// An immutable payload exists and no acknowledgement does.
    OrphanPayload,
    /// An acknowledged, uncommitted operation with no projection WAL.
    AcknowledgedNoWal,
    /// An acknowledged, uncommitted operation with a projection WAL.
    AcknowledgedWithWal,
    /// A committed operation whose projection WAL is still present.
    CommittedWithWal,
    /// A committed operation with no projection WAL left.
    CommittedClean,
}

struct DurableFacts {
    payload_present: bool,
    acknowledged: bool,
    committed_generation: Option<u64>,
    head_generation: Option<u64>,
    wal_present: bool,
}

fn kindb_namespace(root: &Path, repo_id: &str) -> PathBuf {
    std::fs::canonicalize(root)
        .unwrap_or_else(|_| root.to_path_buf())
        .join(".kin")
        .join("kindb")
        .join(repo_id)
}

fn has_wal(root: &Path) -> bool {
    std::fs::read_dir(root.join(".kin/reconciliation"))
        .map(|entries| {
            entries
                .flatten()
                .any(|entry| entry.file_name().to_string_lossy().starts_with("tx-"))
        })
        .unwrap_or(false)
}

fn durable_facts(root: &Path, repo_id: &str, operation: OperationId) -> DurableFacts {
    let namespace = kindb_namespace(root, repo_id);
    let payload_present = namespace
        .join("session-publications")
        .join(format!("{operation}.ksp"))
        .exists();
    let authority: Option<serde_json::Value> = std::fs::read(namespace.join("authority.json"))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok());
    let record = authority.as_ref().and_then(|authority| {
        authority["session_publications"]
            .as_array()
            .and_then(|entries| {
                entries
                    .iter()
                    .find(|entry| entry["operation"] == operation.to_string())
                    .cloned()
            })
    });
    DurableFacts {
        payload_present,
        acknowledged: record.is_some(),
        committed_generation: record
            .as_ref()
            .and_then(|entry| entry["committed_generation"].as_u64()),
        head_generation: authority
            .as_ref()
            .and_then(|authority| authority["head_generation"].as_u64()),
        wal_present: has_wal(root),
    }
}

/// A projection WAL is a repository-wide artifact, so it only refines the
/// class of an operation the authority has already admitted. An unacknowledged
/// operation is classified by its payload alone.
fn classify(facts: &DurableFacts) -> PrefixClass {
    match (
        facts.acknowledged,
        facts.committed_generation,
        facts.wal_present,
    ) {
        (true, None, false) => PrefixClass::AcknowledgedNoWal,
        (true, None, true) => PrefixClass::AcknowledgedWithWal,
        (true, Some(_), true) => PrefixClass::CommittedWithWal,
        (true, Some(_), false) => PrefixClass::CommittedClean,
        (false, _, _) if facts.payload_present => PrefixClass::OrphanPayload,
        (false, _, _) => PrefixClass::Nothing,
    }
}

/// What the durable prefix must look like after a kill at this boundary.
fn expected_class(point: CrashPoint) -> PrefixClass {
    match point {
        CrashPoint::PayloadBeforeAcknowledgement => PrefixClass::OrphanPayload,
        CrashPoint::AcknowledgedBeforeWal => PrefixClass::AcknowledgedNoWal,
        CrashPoint::PartialPrimaryBeforeAuthority => PrefixClass::AcknowledgedWithWal,
        CrashPoint::AuthorityBeforeFinalization => PrefixClass::CommittedWithWal,
        CrashPoint::CleanupBeforeReply | CrashPoint::AfterReply => PrefixClass::CommittedClean,
    }
}

// ---------------------------------------------------------------------------
// The fixture: one real repository with one materialized, edited session
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Evidence {
    /// An ordinary checked source edit and delete, with no language-server
    /// evidence anywhere in the captured interval.
    Checked,
    /// A never-committed accepted language-server lead is live when the session
    /// is captured, so the captured interval is honestly Unknown.
    Unknown,
}

const EDITED_BODY: &[u8] = b"def first():\n    return 19\n";
const ADDED_BODY: &[u8] = b"def added():\n    return 29\n";

struct Fixture {
    /// Held so the repository outlives every child and restart in the control.
    _repo: tempfile::TempDir,
    root: PathBuf,
    layout: kin_core::KinLayout,
    session: PathBuf,
    operation: OperationId,
    repo_id: String,
    evidence: Evidence,
    base_generation: u64,
    /// Whether the live interval the session captured still held a checked
    /// binding-history capability at the moment of capture.
    captured_history_present: bool,
    /// The accepted, never-committed language-server relation the Unknown
    /// control installed, so a restart can be asked whether it survived.
    lead: Option<kin_model::RelationId>,
}

/// Build one repository with committed source authority, materialize one
/// disposable session from it, and leave a real multi-file edit inside that
/// session. Everything here happens before any child exists; the parent then
/// releases the repository entirely so the child owns it.
async fn fixture(label: &str, evidence: Evidence) -> Fixture {
    let (repo, state) = lsp_publication_fixture().await;
    let singleton = session_runtime_lock(&state);
    let runtime = state
        .prepared_publication
        .register(&singleton, state.layout.root())
        .unwrap();
    let app = router(Arc::clone(&state));
    let session = state.layout.runs_dir().join(format!("session-{label}"));
    materialize_session_through_api(&app, &session).await;

    // Three shapes in one publication: an edit, a delete and an addition. The
    // target therefore stages several primary entries, which is what makes a
    // kill after the first published entry a genuinely partial primary.
    std::fs::write(session.join("first.py"), EDITED_BODY).unwrap();
    std::fs::remove_file(session.join("second.py")).unwrap();
    std::fs::write(session.join("added.py"), ADDED_BODY).unwrap();

    let lead = match evidence {
        Evidence::Unknown => Some(install_never_committed_lead(&state).await),
        Evidence::Checked => None,
    };
    let captured_history_present = state
        .graph
        .semantic_observation()
        .verified_binding_history
        .is_some();

    // The daemon's own layout root, not the temporary directory's name for it.
    // A session path is admitted only as a direct child of the layout's runs
    // directory, so the child has to open the repository by the same path.
    let layout = state.layout.clone();
    let root = layout.working_dir().to_path_buf();
    let repo_id = state.cached_repo_id.clone();
    let base_generation = state
        .snapshot_generation
        .load(std::sync::atomic::Ordering::SeqCst);
    let operation = session_operation(&session).expect("materialized session base");

    drop(app);
    drop(runtime);
    drop(singleton);
    drop(state);
    // Nothing of this operation may be durable before the child runs.
    let facts = durable_facts(&root, &repo_id, operation);
    assert_eq!(classify(&facts), PrefixClass::Nothing);

    Fixture {
        _repo: repo,
        root,
        layout,
        session,
        operation,
        repo_id,
        evidence,
        base_generation,
        captured_history_present,
        lead,
    }
}

/// Install one accepted language-server relation that authority never
/// committed. Its admission withdraws the runtime checked capability, so the
/// interval the session captures is honestly Unknown rather than blessed.
async fn install_never_committed_lead(state: &Arc<DaemonState>) -> kin_model::RelationId {
    use crate::daemon::lsp_publication::QueryInputs;
    let caller = waiting_entity(state, "caller.py", "run");
    let target = waiting_entity(state, "target.py", "work");
    let mut relation = lsp_publication_call(caller.id, target.id);
    let span = relation.evidence[0].source_span.as_mut().unwrap();
    span.start_byte = LSP_PUBLICATION_CALLER.rfind("callback").unwrap();
    span.end_byte = span.start_byte + "callback".len();
    let inputs = QueryInputs::capture(state).await.unwrap();
    let mut pending = crate::daemon::PendingEnrichment::default();
    inputs
        .absorb(state, &mut pending, vec![relation.clone()])
        .await
        .unwrap();
    inputs.flush(state, &mut pending).await.unwrap();
    assert!(
        state
            .graph
            .semantic_observation()
            .relations
            .contains_key(&relation.id),
        "the Unknown control requires a live lead"
    );
    assert!(
        !lsp_publication_durable(state)
            .relations
            .contains_key(&relation.id),
        "the Unknown control requires that lead to be absent from durable authority"
    );
    relation.id
}

// ---------------------------------------------------------------------------
// The child
// ---------------------------------------------------------------------------

/// The controlled daemon child. Opens the repository the parent released
/// through the production startup path, serves one real session publication
/// through the production router, and stops dead at its configured boundary.
#[test]
fn session_crash_prefix_child() {
    let Some(repo) = configured(REPO_ENV) else {
        return;
    };
    let session = PathBuf::from(configured(SESSION_ENV).expect("controlled session directory"));
    let control = configured_control().expect("controlled stop marker");
    let root = PathBuf::from(repo);
    let layout = kin_core::KinLayout::new(root.join(".kin"));
    let singleton = crate::lifecycle::acquire_singleton_lock(layout.root())
        .unwrap()
        .expect("the controlled child owns the repository");
    let state = Arc::new(DaemonState::open(layout).unwrap());
    state
        .is_initialized
        .store(true, std::sync::atomic::Ordering::Release);
    state
        .filesystem_reconcile_disabled
        .store(true, std::sync::atomic::Ordering::Relaxed);
    let _runtime = state
        .prepared_publication
        .register(&singleton, state.layout.root())
        .unwrap();
    let app = router(Arc::clone(&state));
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .unwrap();
    std::fs::write(
        control.with_extension("opened"),
        b"child opened the repository",
    )
    .unwrap();
    let (status, body) = runtime.block_on(post_session_reconcile(&app, &session));
    // Only a controlled stop after the reply reaches this line.
    reached(CrashPoint::AfterReply);
    std::fs::write(
        control.with_extension("replied"),
        format!("{status}\n{body}"),
    )
    .unwrap();
    panic!("the controlled child returned from its publication at {status}: {body}");
}

async fn post_session_reconcile(app: &axum::Router, session: &Path) -> (StatusCode, String) {
    let response = app
        .clone()
        .oneshot(
            Request::post("/reconcile")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({"session_dir": session, "confirm_mass_deletion": false}).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 512 * 1024)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&body).into_owned())
}

// ---------------------------------------------------------------------------
// The parent: stop a child dead at one boundary
// ---------------------------------------------------------------------------

struct Stopped {
    /// Every boundary the child reported reaching, in order.
    progress: Vec<String>,
    facts: DurableFacts,
    class: PrefixClass,
}

/// Run one publication in an owned child and SIGKILL it the moment the
/// configured boundary lands.
async fn stop_child_at(fixture: &Fixture, point: CrashPoint) -> Stopped {
    let control = fixture.root.join(format!("crash-control-{}", point.name()));
    let mut child = crate::prepared_publication::tests::spawn_child_test(
        CHILD_TEST,
        &fixture.root,
        &[
            (REPO_ENV, fixture.root.as_os_str().to_owned()),
            (SESSION_ENV, fixture.session.as_os_str().to_owned()),
            (CONTROL_ENV, control.as_os_str().to_owned()),
            (STOP_ENV, std::ffi::OsString::from(point.name())),
        ],
    );
    let deadline = Instant::now() + CHILD_DEADLINE;
    while !control.exists() {
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "the controlled child exited before reaching {}",
            point.name()
        );
        assert!(
            Instant::now() < deadline,
            "the controlled child never reached {}",
            point.name()
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(std::fs::read_to_string(&control).unwrap(), point.name());
    // SIGKILL, so no destructor, flush, shutdown path or signal handler in the
    // child can run after the boundary.
    child.0.kill().unwrap();
    let status = child.0.wait().unwrap();
    assert!(
        status.code().is_none(),
        "the controlled child was expected to die by signal, not exit {status:?}"
    );
    let progress = std::fs::read_to_string(control.with_extension("progress"))
        .unwrap_or_default()
        .lines()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    assert_eq!(
        progress.last().map(String::as_str),
        Some(point.name()),
        "the child stopped somewhere other than its configured boundary: {progress:?}"
    );
    assert!(
        !control.with_extension("replied").exists(),
        "the child answered the caller before the boundary at {}",
        point.name()
    );
    let facts = durable_facts(&fixture.root, &fixture.repo_id, fixture.operation);
    let class = classify(&facts);
    Stopped {
        progress,
        facts,
        class,
    }
}

// ---------------------------------------------------------------------------
// The parent: restart on the same repository and grade
// ---------------------------------------------------------------------------

struct Restarted {
    state: Arc<DaemonState>,
    singleton: crate::lifecycle::DaemonLock,
    phases: Vec<StartupPhase>,
    generation: u64,
    durable_history_present: bool,
    live_history_present: bool,
    lead_present: bool,
}

/// Restart on the same repository through the production startup path, which
/// is where the prepared-session resolver runs.
fn restart(fixture: &Fixture) -> Result<Restarted, String> {
    let _ = take_startup_phases();
    let state = match DaemonState::open(fixture.layout.clone()) {
        Ok(state) => Arc::new(state),
        Err(error) => return Err(error.to_string()),
    };
    let phases = take_startup_phases();
    state
        .is_initialized
        .store(true, std::sync::atomic::Ordering::Release);
    let singleton = crate::lifecycle::acquire_singleton_lock(state.layout.root())
        .unwrap()
        .expect("the restarted daemon owns the repository");
    let durable = lsp_publication_durable(&state);
    let live = state.graph.semantic_observation();
    assert_eq!(
        live.resolved_tree, durable.resolved_tree,
        "the live tree a restarted daemon answers from must be the stored one"
    );
    assert_eq!(
        live.entities, durable.entities,
        "live answers must agree with the stored graph after recovery"
    );
    assert_eq!(live.relations, durable.relations);
    let generation = state
        .snapshot_generation
        .load(std::sync::atomic::Ordering::SeqCst);
    Ok(Restarted {
        lead_present: fixture
            .lead
            .is_some_and(|lead| live.relations.contains_key(&lead)),
        state,
        singleton,
        phases,
        generation,
        durable_history_present: durable.verified_binding_history.is_some(),
        live_history_present: live.verified_binding_history.is_some(),
    })
}

/// The same fixture published to completion with no crash at all, warm and
/// then reopened cold. A crash control is compared with this rather than with
/// an assumption about what the route does when nothing interrupts it.
struct Uninterrupted {
    warm_history_present: bool,
    warm_lead_present: bool,
    cold_history_present: bool,
    cold_lead_present: bool,
}

async fn uninterrupted(label: &str, evidence: Evidence) -> Uninterrupted {
    let (repo, state) = lsp_publication_fixture().await;
    let singleton = session_runtime_lock(&state);
    let runtime = state
        .prepared_publication
        .register(&singleton, state.layout.root())
        .unwrap();
    let app = router(Arc::clone(&state));
    let session = state.layout.runs_dir().join(format!("session-{label}"));
    materialize_session_through_api(&app, &session).await;
    std::fs::write(session.join("first.py"), EDITED_BODY).unwrap();
    std::fs::remove_file(session.join("second.py")).unwrap();
    std::fs::write(session.join("added.py"), ADDED_BODY).unwrap();
    let lead = match evidence {
        Evidence::Unknown => Some(install_never_committed_lead(&state).await),
        Evidence::Checked => None,
    };
    let (status, body) = post_session_reconcile(&app, &session).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let warm = state.graph.semantic_observation();
    let warm_history_present = warm.verified_binding_history.is_some();
    let warm_lead_present = lead.is_some_and(|lead| warm.relations.contains_key(&lead));
    let layout = state.layout.clone();
    drop(app);
    drop(runtime);
    drop(singleton);
    drop(state);

    let reopened = DaemonState::open(layout).unwrap();
    let cold = reopened.graph.semantic_observation();
    let outcome = Uninterrupted {
        warm_history_present,
        warm_lead_present,
        cold_history_present: cold.verified_binding_history.is_some(),
        cold_lead_present: lead.is_some_and(|lead| cold.relations.contains_key(&lead)),
    };
    drop(reopened);
    drop(repo);
    outcome
}

impl Restarted {
    /// The resolver is required to run before hydration, so that no reader ever
    /// sees a half-projected primary or a pre-recovery graph.
    fn assert_resolver_preceded_hydration(&self) {
        let resolver = self
            .phases
            .iter()
            .position(|phase| *phase == StartupPhase::Resolver)
            .expect("startup ran the prepared-session resolver");
        let hydration = self
            .phases
            .iter()
            .position(|phase| *phase == StartupPhase::Hydration)
            .expect("startup hydrated a workspace graph");
        assert!(
            resolver < hydration,
            "the prepared-session resolver must run before hydration: {:?}",
            self.phases
        );
    }

    /// Arm the serving runtime for this restarted daemon. The fence admits one
    /// registration per state, so a control holds this for every request it
    /// makes rather than registering per request.
    fn serving(&self) -> crate::prepared_publication::RuntimeRegistration<'_> {
        self.state
            .prepared_publication
            .register(&self.singleton, self.state.layout.root())
            .unwrap()
    }

    async fn retry(&self, fixture: &Fixture) -> (StatusCode, serde_json::Value) {
        let app = router(Arc::clone(&self.state));
        let (status, body) = post_session_reconcile(&app, &fixture.session).await;
        let payload = serde_json::from_str(&body).unwrap_or(json!({ "error": body }));
        (status, payload)
    }
}

/// Every blob the stored graph holds must be exactly what the working copy
/// holds, with no half-projected body left behind.
fn assert_working_copy_agrees(state: &DaemonState, root: &Path) {
    let tree = state.graph.resolved_tree();
    let mut checked = 0usize;
    for artifact in tree.artifacts() {
        let kin_model::TreeEntry::Blob { hash, .. } = &artifact.entry else {
            continue;
        };
        let Some(path) = artifact.path.as_utf8() else {
            continue;
        };
        let stored = state
            .blobs
            .read(&kin_blobs::Hash256::from_bytes(*hash.as_bytes()))
            .unwrap_or_else(|error| panic!("stored body for {path} is unreadable: {error}"));
        let working = std::fs::read(root.join(path))
            .unwrap_or_else(|error| panic!("working copy is missing {path}: {error}"));
        assert_eq!(
            working, stored,
            "the working copy and the stored graph disagree on {path}"
        );
        checked += 1;
    }
    assert!(checked >= 3, "the control must compare several bodies");
    assert!(
        !root.join("second.py").exists(),
        "the session deleted second.py; the recovered working copy still has it"
    );
    assert!(
        !has_wal(root),
        "a projection WAL survived a completed restart"
    );
}

/// Live answers must come from the recovered graph, not from whatever bytes the
/// interrupted projection happened to leave on disk.
fn assert_live_answers_agree(state: &DaemonState) {
    let declared = |file: &str, name: &str| {
        state
            .graph
            .query_entities(&kin_db::EntityFilter {
                file_path: Some(FilePathId::new(file)),
                ..Default::default()
            })
            .unwrap()
            .into_iter()
            .filter(|entity| entity.name == name && entity.kind == kin_model::EntityKind::Function)
            .count()
    };
    assert_eq!(
        declared("first.py", "first"),
        1,
        "the recovered graph must answer the edited declaration"
    );
    assert_eq!(
        declared("added.py", "added"),
        1,
        "the recovered graph must answer the added declaration"
    );
    let removed = state
        .graph
        .query_entities(&kin_db::EntityFilter {
            file_path: Some(FilePathId::new("second.py")),
            ..Default::default()
        })
        .unwrap();
    assert!(
        removed.is_empty(),
        "the recovered graph still answers a retired declaration: {removed:?}"
    );
}

/// The whole grade for a prefix whose contract is that recovery completes the
/// original operation and a retry returns the original receipt.
async fn assert_recovered_and_replayed(fixture: &Fixture, restarted: &Restarted) {
    restarted.assert_resolver_preceded_hydration();
    assert!(
        restarted.generation > fixture.base_generation,
        "recovery must install the acknowledged operation"
    );
    assert_working_copy_agrees(&restarted.state, &fixture.root);
    assert_live_answers_agree(&restarted.state);
    let facts = durable_facts(&fixture.root, &fixture.repo_id, fixture.operation);
    assert_eq!(
        classify(&facts),
        PrefixClass::CommittedClean,
        "recovery must leave the operation committed with no WAL"
    );
    let committed = facts.committed_generation.expect("a committed operation");

    // A retry of the exact same session answers from the original receipt: the
    // same operation, the same receipt generation, no second commit and no
    // further authority movement.
    let _serving = restarted.serving();
    let (status, summary) = restarted.retry(fixture).await;
    assert_eq!(status, StatusCode::OK, "{summary}");
    assert_eq!(summary["idempotent_replay"], true, "{summary}");
    assert_eq!(
        summary["operation_id"].as_str().unwrap(),
        fixture.operation.to_string(),
        "a retry must return the original operation, not a new one"
    );
    let after = durable_facts(&fixture.root, &fixture.repo_id, fixture.operation);
    assert_eq!(
        after.committed_generation,
        Some(committed),
        "a retry re-committed the operation"
    );
    assert_eq!(
        after.head_generation, facts.head_generation,
        "a retry advanced repository authority"
    );
    assert_eq!(
        restarted
            .state
            .snapshot_generation
            .load(std::sync::atomic::Ordering::SeqCst),
        restarted.generation,
        "a retry advanced the live generation a second time"
    );
    assert_evidence_survived(fixture, restarted).await;
}

/// The live answer must match the frozen proof, and a crash must not change the
/// evidence outcome the same session reaches when nothing interrupts it.
async fn assert_evidence_survived(fixture: &Fixture, restarted: &Restarted) {
    assert_eq!(
        restarted.live_history_present, restarted.durable_history_present,
        "the restarted live capability disagrees with the stored proof"
    );
    if fixture.evidence == Evidence::Checked {
        return;
    }
    assert!(
        !fixture.captured_history_present,
        "the Unknown control must capture an interval with no checked capability"
    );
    let reference = uninterrupted("evidence-reference", fixture.evidence).await;
    eprintln!(
        "EVIDENCE captured_history={} warm_history={} warm_lead={} cold_history={} cold_lead={} crash_history={} crash_lead={}",
        fixture.captured_history_present,
        reference.warm_history_present,
        reference.warm_lead_present,
        reference.cold_history_present,
        reference.cold_lead_present,
        restarted.live_history_present,
        restarted.lead_present
    );
    assert_eq!(
        (restarted.live_history_present, restarted.lead_present),
        (reference.cold_history_present, reference.cold_lead_present),
        "a crash at this prefix changed the evidence outcome the same session reaches \
         uninterrupted, as (checked binding history present, accepted lead present)"
    );
}

// ---------------------------------------------------------------------------
// The five prefixes
// ---------------------------------------------------------------------------

/// Prefix 1. The immutable payload is durable and nothing acknowledged it.
///
/// Contract: primary and authority are unchanged, the orphan payload is not an
/// active operation, and the exact current input can be re-admitted.
#[tokio::test]
async fn crash_prefix_payload_before_acknowledgement_leaves_an_orphan_that_re_admits() {
    let fixture = fixture("crash-payload", Evidence::Checked).await;
    let stopped = stop_child_at(&fixture, CrashPoint::PayloadBeforeAcknowledgement).await;
    assert_eq!(stopped.class, PrefixClass::OrphanPayload);
    assert!(stopped.facts.payload_present);
    assert!(!stopped.facts.acknowledged);
    assert!(!stopped.facts.wal_present);
    assert_eq!(stopped.progress, vec!["payload-before-acknowledgement"]);
    // The interrupted publication changed neither the working copy nor the
    // primary tree, so the orphan certifies no history.
    assert_eq!(
        std::fs::read(fixture.root.join("first.py")).unwrap(),
        b"def first():\n    return 1\n"
    );
    assert!(fixture.root.join("second.py").exists());
    assert!(!fixture.root.join("added.py").exists());

    let restarted = restart(&fixture).expect("an orphan payload must not refuse startup");
    restarted.assert_resolver_preceded_hydration();
    assert_eq!(
        restarted.generation, fixture.base_generation,
        "an unacknowledged candidate must not advance authority"
    );
    assert!(!has_wal(&fixture.root));

    // Re-admission: the same session publishes for the first time, which is a
    // fresh publication of the original operation and not an idempotent replay.
    let _serving = restarted.serving();
    let (status, summary) = restarted.retry(&fixture).await;
    assert_eq!(status, StatusCode::OK, "{summary}");
    assert_eq!(summary["idempotent_replay"], false, "{summary}");
    assert_eq!(
        summary["operation_id"].as_str().unwrap(),
        fixture.operation.to_string()
    );
    let generation = summary["authority_generation"].as_u64().unwrap();
    assert!(generation > fixture.base_generation);
    assert_working_copy_agrees(&restarted.state, &fixture.root);
    assert_live_answers_agree(&restarted.state);

    // And only now is it a replay.
    let (status, replay) = restarted.retry(&fixture).await;
    assert_eq!(status, StatusCode::OK, "{replay}");
    assert_eq!(replay["idempotent_replay"], true, "{replay}");
    assert_eq!(replay["authority_generation"].as_u64(), Some(generation));
    drop(fixture);
}

/// Negative control for prefix 1: a kill one boundary later is acknowledged,
/// so it cannot be graded as an orphan payload.
#[tokio::test]
async fn crash_prefix_payload_negative_control_is_not_an_orphan() {
    let fixture = fixture("negative-payload", Evidence::Checked).await;
    let point = CrashPoint::PayloadBeforeAcknowledgement;
    let stopped = stop_child_at(&fixture, point.just_after().unwrap()).await;
    assert_ne!(
        stopped.class,
        expected_class(point),
        "a kill after the acknowledgement was graded as one before it"
    );
    assert_eq!(stopped.class, expected_class(point.just_after().unwrap()));
    assert!(stopped.facts.acknowledged);
    drop(fixture);
}

/// Prefix 2. The acknowledgement is installed and no projection WAL exists.
///
/// Contract: startup resolves the required operation before hydration, the same
/// operation and target commit exactly once, and Unknown remains Unknown.
#[tokio::test]
async fn crash_prefix_acknowledged_before_wal_commits_once_on_restart() {
    let fixture = fixture("crash-ack", Evidence::Checked).await;
    let stopped = stop_child_at(&fixture, CrashPoint::AcknowledgedBeforeWal).await;
    assert_eq!(stopped.class, PrefixClass::AcknowledgedNoWal);
    assert!(!stopped.facts.wal_present);
    assert_eq!(
        stopped.progress,
        vec!["payload-before-acknowledgement", "acknowledged-before-wal"]
    );
    let restarted = restart(&fixture).expect("an acknowledged operation must resolve");
    assert_recovered_and_replayed(&fixture, &restarted).await;
    drop(fixture);
}

/// Prefix 2, Unknown evidence. The captured live interval carried an accepted
/// language-server lead that authority had never committed, so it was honestly
/// Unknown. Recovering the acknowledged operation must reach the same evidence
/// outcome the identical uninterrupted session reaches.
#[tokio::test]
async fn crash_prefix_acknowledged_before_wal_keeps_unknown_evidence_unknown() {
    let fixture = fixture("crash-ack-unknown", Evidence::Unknown).await;
    let stopped = stop_child_at(&fixture, CrashPoint::AcknowledgedBeforeWal).await;
    assert_eq!(stopped.class, PrefixClass::AcknowledgedNoWal);
    let restarted = restart(&fixture).expect("an acknowledged operation must resolve");
    assert_recovered_and_replayed(&fixture, &restarted).await;
    drop(fixture);
}

/// Negative control for prefix 2: a kill one boundary later has published a
/// primary entry under a WAL, so it cannot be graded as WAL-free.
#[tokio::test]
async fn crash_prefix_acknowledged_negative_control_already_holds_a_wal() {
    let fixture = fixture("negative-ack", Evidence::Checked).await;
    let point = CrashPoint::AcknowledgedBeforeWal;
    let stopped = stop_child_at(&fixture, point.just_after().unwrap()).await;
    assert_ne!(
        stopped.class,
        expected_class(point),
        "a kill after the WAL was graded as one before it"
    );
    assert_eq!(stopped.class, expected_class(point.just_after().unwrap()));
    assert!(stopped.facts.wal_present);
    drop(fixture);
}

/// Prefix 3. One staged primary object is published under the authenticated
/// WAL and the authority has not committed.
///
/// Contract: the WAL recovers the prior namespace, the original prepared
/// operation replays, and nothing parses a half-projected working copy.
#[tokio::test]
async fn crash_prefix_partial_primary_before_authority_replays_the_original() {
    let fixture = fixture("crash-primary", Evidence::Checked).await;
    let stopped = stop_child_at(&fixture, CrashPoint::PartialPrimaryBeforeAuthority).await;
    assert_eq!(stopped.class, PrefixClass::AcknowledgedWithWal);
    assert!(stopped.facts.wal_present);
    assert_eq!(stopped.facts.committed_generation, None);
    assert_eq!(
        stopped.progress,
        vec![
            "payload-before-acknowledgement",
            "acknowledged-before-wal",
            "partial-primary-before-authority"
        ]
    );
    let restarted = restart(&fixture).expect("an interrupted projection must resolve");
    assert_recovered_and_replayed(&fixture, &restarted).await;
    drop(fixture);
}

/// Negative control for prefix 3: a kill one boundary later is committed, so it
/// cannot be graded as an uncommitted partial projection.
#[tokio::test]
async fn crash_prefix_partial_primary_negative_control_is_already_committed() {
    let fixture = fixture("negative-primary", Evidence::Checked).await;
    let point = CrashPoint::PartialPrimaryBeforeAuthority;
    let stopped = stop_child_at(&fixture, point.just_after().unwrap()).await;
    assert_ne!(
        stopped.class,
        expected_class(point),
        "a kill after the authority commit was graded as one before it"
    );
    assert_eq!(stopped.class, expected_class(point.just_after().unwrap()));
    assert!(stopped.facts.committed_generation.is_some());
    drop(fixture);
}

/// Prefix 4. The authority committed and no live finalization ran.
///
/// Contract: restart loads the exact committed target and finalizes the WAL
/// with no second generation, and an accepted never-committed withdrawal
/// matches the frozen proof warm and cold.
#[tokio::test]
async fn crash_prefix_authority_before_finalization_finalizes_without_a_second_generation() {
    let fixture = fixture("crash-authority", Evidence::Checked).await;
    finalize_after_authority_crash(&fixture).await;
    drop(fixture);
}

/// Prefix 4, Unknown evidence. The record requires an accepted never-committed
/// binding withdrawal to match the frozen proof warm and cold.
#[tokio::test]
async fn crash_prefix_authority_before_finalization_keeps_unknown_evidence_unknown() {
    let fixture = fixture("crash-authority-unknown", Evidence::Unknown).await;
    finalize_after_authority_crash(&fixture).await;
    drop(fixture);
}

async fn finalize_after_authority_crash(fixture: &Fixture) {
    let stopped = stop_child_at(fixture, CrashPoint::AuthorityBeforeFinalization).await;
    assert_eq!(stopped.class, PrefixClass::CommittedWithWal);
    let committed = stopped.facts.committed_generation.unwrap();
    assert!(committed > fixture.base_generation);
    assert!(stopped.facts.wal_present);
    let head = stopped.facts.head_generation;
    let restarted = restart(fixture).expect("a committed operation must finalize");
    let finalized = durable_facts(&fixture.root, &fixture.repo_id, fixture.operation);
    assert_eq!(
        finalized.committed_generation,
        Some(committed),
        "finalizing a committed operation must not mint a second generation"
    );
    assert_eq!(
        finalized.head_generation, head,
        "finalizing a committed operation must not advance repository authority"
    );
    assert_recovered_and_replayed(fixture, &restarted).await;
}

/// Negative control for prefix 4: a kill one boundary later has already cleaned
/// the WAL, so it cannot be graded as finalization-pending.
#[tokio::test]
async fn crash_prefix_authority_negative_control_has_no_wal_left() {
    let fixture = fixture("negative-authority", Evidence::Checked).await;
    let point = CrashPoint::AuthorityBeforeFinalization;
    let stopped = stop_child_at(&fixture, point.just_after().unwrap()).await;
    assert_ne!(
        stopped.class,
        expected_class(point),
        "a kill after WAL cleanup was graded as one before it"
    );
    assert_eq!(stopped.class, expected_class(point.just_after().unwrap()));
    assert!(!stopped.facts.wal_present);
    drop(fixture);
}

// ---------------------------------------------------------------------------
// Language-server completion markers across a crash
// ---------------------------------------------------------------------------

/// Kill one publication at `point` while the store marks every fixture file
/// as enriched, restart through the production startup path, and load the
/// marker the way a starting daemon does.
///
/// The marker tells the sweep a file's language-server answers are durable,
/// and the sweep skips a file it names without asking a server anything. The
/// session edits `first.py` and deletes `second.py`, so once recovery installs
/// the publication those answers describe bytes the tree no longer holds. Live
/// finalization is what retires them, and a kill at these prefixes means it
/// never ran, so recovery has to.
async fn assert_recovery_retires_changed_completion_markers(label: &str, point: CrashPoint) {
    // Unknown evidence leaves one accepted language-server relation in the
    // graph after restart. A graph holding none makes a starting daemon ignore
    // the whole marker, and the skip this grades could not happen at all.
    let fixture = fixture(label, Evidence::Unknown).await;
    std::fs::write(
        fixture.layout.root().join("lsp-enriched-files.json"),
        crate::daemon::encode_enriched_marker(
            &["caller.py", "first.py", "second.py", "target.py"].map(String::from),
        ),
    )
    .unwrap();
    stop_child_at(&fixture, point).await;
    let restarted = restart(&fixture).expect("a recoverable prefix must open");
    assert!(
        restarted.lead_present,
        "the control needs a surviving language-server relation for the marker to be honored"
    );
    crate::daemon::load_lsp_enriched_marker(&restarted.state);
    for changed in ["first.py", "second.py"] {
        assert!(
            !crate::daemon::file_already_enriched(&restarted.state, changed),
            "the recovered publication changed {changed}, so the next sweep must not skip it"
        );
    }
    for unchanged in ["caller.py", "target.py"] {
        assert!(
            crate::daemon::file_already_enriched(&restarted.state, unchanged),
            "the publication left {unchanged} alone, so recovery must keep its marker"
        );
    }
    drop(fixture);
}

/// Prefix 2 recovers through the active preparation: startup publishes it.
#[tokio::test]
async fn crash_prefix_acknowledged_before_wal_retires_changed_completion_markers() {
    assert_recovery_retires_changed_completion_markers(
        "markers-ack",
        CrashPoint::AcknowledgedBeforeWal,
    )
    .await;
}

/// Prefix 4 recovers through the committed WAL: authority already holds it.
#[tokio::test]
async fn crash_prefix_authority_before_finalization_retires_changed_completion_markers() {
    assert_recovery_retires_changed_completion_markers(
        "markers-authority",
        CrashPoint::AuthorityBeforeFinalization,
    )
    .await;
}

/// Prefix 5. Everything finished and the caller never got the reply.
///
/// Contract: the exact retry returns the original receipt.
#[tokio::test]
async fn crash_prefix_cleanup_before_reply_returns_the_original_receipt() {
    let fixture = fixture("crash-cleanup", Evidence::Checked).await;
    let stopped = stop_child_at(&fixture, CrashPoint::CleanupBeforeReply).await;
    assert_eq!(stopped.class, PrefixClass::CommittedClean);
    assert!(!stopped.facts.wal_present);
    let committed = stopped.facts.committed_generation.unwrap();
    assert_eq!(
        stopped.progress,
        vec![
            "payload-before-acknowledgement",
            "acknowledged-before-wal",
            "partial-primary-before-authority",
            "authority-before-finalization",
            "cleanup-before-reply"
        ]
    );
    let restarted = restart(&fixture).expect("a finished operation must open normally");
    let reopened = durable_facts(&fixture.root, &fixture.repo_id, fixture.operation);
    assert_eq!(
        reopened.committed_generation,
        Some(committed),
        "reopening a finished operation must not commit it again"
    );
    assert_eq!(reopened.head_generation, stopped.facts.head_generation);
    assert_recovered_and_replayed(&fixture, &restarted).await;
    drop(fixture);
}

/// Negative control for prefix 5. The boundary after the reply leaves exactly
/// the same durable prefix, because reply loss is replay; what must not happen
/// is that an independently advanced authority is rewound to serve the retry.
#[tokio::test]
async fn crash_prefix_cleanup_negative_control_never_rewinds_later_authority() {
    let fixture = fixture("negative-cleanup", Evidence::Checked).await;
    let point = CrashPoint::CleanupBeforeReply;
    let stopped = stop_child_at(&fixture, point.just_after().unwrap()).await;
    assert_eq!(
        stopped.class,
        expected_class(point),
        "reply loss and reply delivery hold the same durable prefix"
    );
    assert!(stopped
        .progress
        .contains(&"cleanup-before-reply".to_owned()));
    let restarted = restart(&fixture).expect("a delivered reply must open normally");
    let committed = stopped
        .facts
        .committed_generation
        .expect("the reply was delivered, so the operation committed");

    // Advance authority independently of the session, the way ordinary work
    // does after a reconcile lands.
    let _serving = restarted.serving();
    let app = router(Arc::clone(&restarted.state));
    std::fs::write(
        fixture.root.join("first.py"),
        b"def first():\n    return 23\n",
    )
    .unwrap();
    waiting_admit(
        &restarted.state,
        "newer authority after the delivered reply",
    )
    .await;
    waiting_commit(&restarted.state, "publish newer source before the retry").await;
    drop(app);
    let advanced = restarted
        .state
        .snapshot_generation
        .load(std::sync::atomic::Ordering::SeqCst);
    assert!(advanced > restarted.generation);
    let newer = durable_facts(&fixture.root, &fixture.repo_id, fixture.operation);
    assert!(newer.head_generation > Some(committed));

    let (status, replay) = restarted.retry(&fixture).await;
    assert_eq!(status, StatusCode::OK, "{replay}");
    assert_eq!(replay["idempotent_replay"], true, "{replay}");
    assert_eq!(
        replay["operation_id"].as_str().unwrap(),
        fixture.operation.to_string(),
        "a historical retry must return its own operation"
    );
    let after = durable_facts(&fixture.root, &fixture.repo_id, fixture.operation);
    assert_eq!(
        after.committed_generation,
        Some(committed),
        "a historical retry re-committed its old operation"
    );
    assert_eq!(
        after.head_generation, newer.head_generation,
        "a historical retry moved repository authority"
    );
    assert_eq!(
        restarted
            .state
            .snapshot_generation
            .load(std::sync::atomic::Ordering::SeqCst),
        advanced,
        "a historical retry must never rewind independently advanced authority"
    );
    assert_eq!(
        std::fs::read(fixture.root.join("first.py")).unwrap(),
        b"def first():\n    return 23\n",
        "a historical retry must not reinstall its old target"
    );
    drop(fixture);
}
