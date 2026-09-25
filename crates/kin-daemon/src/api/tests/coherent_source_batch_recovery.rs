// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

const RETRY_PARSING_PY: &str = r###"import re

TAG_RE = re.compile(r"(?<![\w#])#([A-Za-z][\w/-]*)")


def normalize_title(title):
    return title.strip().lower()


def strip_code(text):
    return text.replace("`", "")


def extract_tags(text):
    return TAG_RE.findall(strip_code(text))


def extract_links(text):
    return [normalize_title(part) for part in text.split("|")]


def parse_note(text, path):
    return {"path": str(path), "tags": extract_tags(text), "links": extract_links(text)}
"###;
const RETRY_STORAGE_PY: &str = r###"from .parsing import parse_note, normalize_title


class Database:
    def __init__(self, path):
        self.path = path
        self.notes = {}

    def ingest_note(self, note):
        key = normalize_title(note["path"])
        self.notes[key] = note
        return normalize_title(key)

    def ingest_dir(self, root):
        for name, text in root.items():
            self.ingest_note(parse_note(text, name))
        return len(self.notes)

    def all_notes(self):
        return list(self.notes.values())
"###;
const RETRY_LINKGRAPH_PY: &str = r###"from .parsing import normalize_title
from .storage import Database


class LinkGraph:
    def __init__(self, edges):
        self.edges = edges

    @staticmethod
    def from_db(db: Database):
        edges = {}
        for note in db.all_notes():
            edges[normalize_title(note["path"])] = [normalize_title(link)
                                                    for link in note["links"]]
        return LinkGraph(edges)

    def backlinks(self, title):
        return [src for src, dsts in self.edges.items() if title in dsts]
"###;
const RETRY_CLI_PY: &str = r###"from .linkgraph import LinkGraph
from .storage import Database


def main():
    db = Database(":memory:")
    db.ingest_dir({"a.md": "hello #tag b|c"})
    return LinkGraph.from_db(db).backlinks("b")
"###;

// Real handler controls for complete-source batch refusal and partial neighbors.

fn retry_batch_files() -> [(&'static str, &'static str); 4] {
    [("pkg/parsing.py", RETRY_PARSING_PY), ("pkg/storage.py", RETRY_STORAGE_PY),
     ("pkg/linkgraph.py", RETRY_LINKGRAPH_PY), ("pkg/cli.py", RETRY_CLI_PY)]
}

async fn retry_batch_fixture() -> (tempfile::TempDir, Arc<DaemonState>) {
    let (repo, state) = mcp_lifecycle_fixture();
    std::fs::create_dir(repo.path().join("pkg")).unwrap();
    std::fs::write(repo.path().join("pkg/__init__.py"), "").unwrap();
    for (path, body) in retry_batch_files() {
        std::fs::write(repo.path().join(path), body).unwrap();
        waiting_commit(&state, path).await;
    }
    retry_batch_assert_calls(&state, "normalize_title");
    (repo, state)
}

fn retry_batch_write_rename(repo: &std::path::Path) {
    for (path, body) in retry_batch_files().into_iter().take(3) {
        std::fs::write(repo.join(path), body.replace("normalize_title", "canonical_title")).unwrap();
    }
}

fn retry_batch_assert_calls(state: &DaemonState, target_name: &str) {
    let target = waiting_entity(state, "pkg/parsing.py", target_name);
    for (path, name) in [("pkg/storage.py", "Database.ingest_note"), ("pkg/linkgraph.py", "LinkGraph.from_db")] {
        let caller = waiting_entity(state, path, name);
        let calls = state.graph.get_relations(&caller.id, &[kin_model::RelationKind::Calls]).unwrap();
        assert_eq!(calls.iter().filter(|r| r.src.as_entity() == Some(caller.id)
            && r.dst.as_entity() == Some(target.id)).count(), 1,
            "exact actual caller retained for {path}/{name}: {calls:?}");
    }
}

struct RetryBatchTraffic {
    blocked: Arc<std::sync::atomic::AtomicBool>,
    visits: Arc<std::sync::atomic::AtomicUsize>,
}
impl kin_reconcile::TrafficChecker for RetryBatchTraffic {
    fn check_collisions(&self, _: &kin_model::IntentScope, _: Option<&kin_model::SessionId>)
        -> std::result::Result<kin_reconcile::CollisionCheck, String>
    {
        self.visits.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        Ok(if self.blocked.load(std::sync::atomic::Ordering::Relaxed) {
            kin_reconcile::CollisionCheck::Blocked {
                conflict: kin_model::IntentConflict::HardCollision,
                blocking_intents: vec![],
            }
        } else { kin_reconcile::CollisionCheck::Clear })
    }
}

async fn retry_batch_after_collision(cold: bool) {
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    let (repo, mut state) = retry_batch_fixture().await;
    let before = state.graph.semantic_observation();
    let roots_before = source_base_roots(&state);
    let blocked = Arc::new(AtomicBool::new(true));
    let visits = Arc::new(AtomicUsize::new(0));
    state.reconciler.write().await.set_traffic_checker(Box::new(RetryBatchTraffic {
        blocked: blocked.clone(), visits: visits.clone(),
    }));
    retry_batch_write_rename(repo.path());
    let response = router(Arc::clone(&state)).oneshot(
        Request::post("/commands/commit").header("content-type", "application/json")
            .body(Body::from(json!({"operation_id":kin_model::OperationId::new(),
                "timestamp":Timestamp::now(),"author":"Test Author <test@example.invalid>",
                "message":"must refuse one collision before publication"}).to_string())).unwrap()
    ).await.unwrap();
    let status = response.status();
    let bytes = axum::body::to_bytes(response.into_body(), 256 * 1024).await.unwrap();
    let text = String::from_utf8_lossy(&bytes);
    println!("coherent collision cold={cold}: {status} {text}");
    assert!(!status.is_success(), "{text}");
    assert!(visits.load(Ordering::Relaxed) > 0, "must reach actual reconciler traffic preflight");
    assert!(text.to_lowercase().contains("collision"), "must refuse this intended cause: {text}");
    let after_refusal = state.graph.semantic_observation();
    let roots_after_refusal = source_base_roots(&state);
    retry_batch_assert_calls(&state, "normalize_title");
    blocked.store(false, Ordering::Relaxed);
    if cold {
        let layout = state.layout.clone();
        drop(state);
        state = waiting_cold_start(layout).await;
    }
    // No caller/source rewrites, synthetic debt, retries, sleeps or checkpoint
    // injection: the second request sees exactly the refused host bytes.
    for (path, body) in retry_batch_files().into_iter().take(3) {
        assert_eq!(std::fs::read_to_string(repo.path().join(path)).unwrap(),
            body.replace("normalize_title", "canonical_title"));
    }
    waiting_commit(&state, "retry unchanged rename after collision clears").await;
    retry_batch_assert_calls(&state, "canonical_title");
    assert!(state.graph.list_all_entities().unwrap().iter().all(|e| e.name != "normalize_title"));
    assert_eq!(status, StatusCode::CONFLICT, "a traffic refusal is a conflict: {text}");
    // Keep these after the recovery assertion: the old ordering should first
    // expose the lost-predecessor retry, not merely fail on root movement.
    assert_eq!(roots_after_refusal, roots_before, "known preflight refusal precedes authority publication");
    assert_eq!(after_refusal.entities, before.entities);
    assert_eq!(after_refusal.relations, before.relations);
    assert_eq!(after_refusal.external_references, before.external_references);
    assert_eq!(after_refusal.resolved_tree, before.resolved_tree);
    let layout = state.layout.clone();
    drop(state);
    let reopened = waiting_cold_start(layout).await;
    retry_batch_assert_calls(&reopened, "canonical_title");
}

#[tokio::test]
async fn coherent_source_batch_collision_retry_unchanged_warm() {
    retry_batch_after_collision(false).await;
}

#[tokio::test]
async fn coherent_source_batch_collision_retry_unchanged_cold() {
    retry_batch_after_collision(true).await;
}

#[tokio::test]
async fn coherent_source_batch_complete_subset_preserves_unrelated_partial_debt() {
    let (repo, state) = retry_batch_fixture().await;
    let file = "unrelated.js";
    let good = "function healthy() { return 1; }\n";
    let broken = "function healthy( {\n// incomplete editor text keeps held spans within the body\n";
    std::fs::write(repo.path().join(file), good).unwrap();
    waiting_commit(&state, "unrelated healthy declaration").await;
    let prior = waiting_entity(&state, file, "healthy");
    std::fs::write(repo.path().join(file), broken).unwrap();
    waiting_admit(&state, "actual incomplete editor admission").await;
    let expected_body = kin_blobs::digest(broken.as_bytes()).to_string();
    assert!(crate::semantic_debt::outstanding(&state).iter()
        .any(|entry| entry.path == file && entry.body == expected_body),
        "actual publication must leave this exact partial body owed");
    assert!(kin_core::retained_parse::read(&state.layout).errors_for(file)
        .is_some_and(|count| count > 0));
    assert_eq!(waiting_entity(&state, file, "healthy"), prior);
    retry_batch_write_rename(repo.path());
    waiting_commit(&state, "complete complex rename beside unrelated partial source").await;
    let layout = state.layout.clone();
    let mut view = state;
    for phase in 0..2 {
        if phase == 1 {
            drop(view);
            view = waiting_cold_start(layout.clone()).await;
        }
        retry_batch_assert_calls(&view, "canonical_title");
        assert_eq!(waiting_entity(&view, file, "healthy"), prior,
            "unrelated last-known-good declaration is retained, not rederived from broken text");
        assert_eq!(std::fs::read_to_string(repo.path().join(file)).unwrap(), broken);
        assert!(kin_core::retained_parse::read(&view.layout).errors_for(file)
            .is_some_and(|count| count > 0), "partial disclosure survives phase {phase}");
        let target = waiting_entity(&view, "pkg/parsing.py", "canonical_title");
        let result = mcp_call(router(Arc::clone(&view)), "impact_analysis",
            json!({"entity_ids":[target.id.to_string()],"include_traffic":false})).await;
        assert_ne!(result.is_error, Some(true), "{}", mcp_result_text(&result));
        let raw = tool_result_payload(&result);
        let report = &raw["source_derivation"]["report"];
        assert!(report.is_object(), "real disclosure required: {raw}");
        assert!(matches!(report["parse_coverage"].as_str(), Some("incomplete" | "unproven")), "{raw}");
        assert_eq!(report["call_shape_parse_coverage_complete"], false, "{raw}");
        assert_eq!(raw["entity_impacts"][0]["call_shapes"]["all_consumers_shaped_calls"], false, "{raw}");
    }
}

struct RetryBatchHostEdit {
    path: std::path::PathBuf,
    once: Arc<std::sync::atomic::AtomicBool>,
}

impl kin_reconcile::TrafficChecker for RetryBatchHostEdit {
    fn check_collisions(
        &self,
        _: &kin_model::IntentScope,
        _: Option<&kin_model::SessionId>,
    ) -> std::result::Result<kin_reconcile::CollisionCheck, String> {
        if self.once.swap(false, std::sync::atomic::Ordering::Relaxed) {
            std::fs::write(&self.path, "# newer editor save during preflight\n")
                .map_err(|error| error.to_string())?;
        }
        Ok(kin_reconcile::CollisionCheck::Clear)
    }
}

#[tokio::test]
async fn coherent_source_batch_host_change_during_preflight_refuses_before_publication() {
    let (repo, state) = retry_batch_fixture().await;
    let before = state.graph.semantic_observation();
    let roots = source_base_roots(&state);
    let once = Arc::new(std::sync::atomic::AtomicBool::new(true));
    state.reconciler.write().await.set_traffic_checker(Box::new(RetryBatchHostEdit {
        path: repo.path().join("pkg/storage.py"),
        once: once.clone(),
    }));
    retry_batch_write_rename(repo.path());
    let response = router(Arc::clone(&state)).oneshot(
        Request::post("/commands/commit").header("content-type", "application/json")
            .body(Body::from(json!({"operation_id":kin_model::OperationId::new(),
                "timestamp":Timestamp::now(),"author":"Test Author <test@example.invalid>",
                "message":"must refuse stale host observation"}).to_string())).unwrap()
    ).await.unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 256 * 1024).await.unwrap();
    let text = String::from_utf8_lossy(&body);
    assert!(!once.load(std::sync::atomic::Ordering::Relaxed), "real preflight must run");
    assert!(!status.is_success(), "stale observed bytes must not publish: {text}");
    assert!(text.contains("host entry changed during coherent source reconciliation"), "{text}");
    assert_eq!(source_base_roots(&state), roots);
    let after = state.graph.semantic_observation();
    assert_eq!(after.entities, before.entities);
    assert_eq!(after.relations, before.relations);
    assert_eq!(after.external_references, before.external_references);
    assert_eq!(after.resolved_tree, before.resolved_tree);
    assert_eq!(std::fs::read_to_string(repo.path().join("pkg/storage.py")).unwrap(),
        "# newer editor save during preflight\n", "refusal cannot overwrite the newer save");
    retry_batch_assert_calls(&state, "normalize_title");
    retry_batch_write_rename(repo.path());
    waiting_commit(&state, "publish restored consistent rename").await;
    retry_batch_assert_calls(&state, "canonical_title");
}

#[tokio::test]
async fn coherent_source_batch_next_single_file_edit_retires_only_its_calls() {
    let (repo, state) = retry_batch_fixture().await;
    retry_batch_write_rename(repo.path());
    waiting_commit(&state, "coherent rename before ordinary edit").await;
    retry_batch_assert_calls(&state, "canonical_title");
    let body = RETRY_STORAGE_PY
        .replace("parse_note, normalize_title", "parse_note")
        .replace("normalize_title(note[\"path\"])", "str(note[\"path\"])")
        .replace("return normalize_title(key)", "return key");
    assert!(!body.contains("normalize_title"));
    assert!(!body.contains("canonical_title"));
    std::fs::write(repo.path().join("pkg/storage.py"), &body).unwrap();
    waiting_commit(&state, "ordinary edit removes this file's calls").await;
    let layout = state.layout.clone();
    let mut view = state;
    for cold in [false, true] {
        if cold {
            drop(view);
            view = waiting_cold_start(layout.clone()).await;
        }
        let target = waiting_entity(&view, "pkg/parsing.py", "canonical_title");
        for (path, name, count) in [("pkg/storage.py", "Database.ingest_note", 0),
            ("pkg/linkgraph.py", "LinkGraph.from_db", 1)] {
            let caller = waiting_entity(&view, path, name);
            let calls = view.graph.get_relations(&caller.id, &[kin_model::RelationKind::Calls]).unwrap();
            assert_eq!(calls.iter().filter(|r| r.src.as_entity() == Some(caller.id)
                && r.dst.as_entity() == Some(target.id)).count(), count,
                "actual subsequent source edit is reflected cold={cold} {path}: {calls:?}");
        }
        let storage = waiting_entity(&view, "pkg/storage.py", "Database.ingest_note");
        assert_eq!(storage.metadata.extra["blob_hash"], kin_blobs::digest(body.as_bytes()).to_string());
        assert_eq!(std::fs::read_to_string(repo.path().join("pkg/storage.py")).unwrap(), body);
    }
}

#[tokio::test]
async fn coherent_source_batch_ambient_rename_publishes_and_cold_reopens_without_commit() {
    use std::time::Duration;
    let (repo, state) = retry_batch_fixture().await;
    let previous_target = waiting_entity(&state, "pkg/parsing.py", "normalize_title").id;
    let callers = [
        ("pkg/storage.py", "Database.ingest_note"),
        ("pkg/linkgraph.py", "LinkGraph.from_db"),
    ].map(|(path, name)| (path, name, waiting_entity(&state, path, name).id));
    for (_, _, caller) in callers {
        assert_eq!(state.graph.get_relations(&caller, &[kin_model::RelationKind::Calls]).unwrap()
            .iter().filter(|r| r.dst.as_entity() == Some(previous_target)).count(), 1);
    }
    let layout = state.layout.clone();
    drop(state);
    let state = Arc::new(DaemonState::open(layout.clone()).unwrap());
    let (cancel, receiver) = tokio::sync::watch::channel(false);
    let (armed, ready) = tokio::sync::oneshot::channel();
    let mut task = tokio::spawn(crate::loop_runner::run_loop_armed(
        Arc::clone(&state),
        crate::loop_runner::LoopConfig { poll_interval_ms: 20, batch_size: 64 },
        receiver,
        Some(crate::loop_runner::WatchArmed::new(armed)),
    ));
    let arming = crate::daemon::await_watch_armed(ready, Duration::from_secs(10)).await;
    let roots_before = source_base_roots(&state);
    let renamed = [("pkg/parsing.py", RETRY_PARSING_PY), ("pkg/storage.py", RETRY_STORAGE_PY), ("pkg/linkgraph.py", RETRY_LINKGRAPH_PY)]
        .map(|(path, body)| (path, body.replace("normalize_title", "canonical_title")));
    let complete = |view: &DaemonState| {
        let snapshot = view.graph.semantic_observation();
        if snapshot.entities.values().any(|e| e.name == "normalize_title") { return false; }
        let Some(target) = snapshot.entities.values().find(|e| e.name == "canonical_title"
            && e.file_origin == Some(kin_model::FilePathId::new("pkg/parsing.py"))) else { return false; };
        callers.iter().all(|(path, name, caller)| {
            snapshot.entities.get(caller).is_some_and(|e| e.name == *name
                && e.file_origin == Some(kin_model::FilePathId::new(*path)))
                && snapshot.relations.values().filter(|r| r.kind == kin_model::RelationKind::Calls
                    && r.src.as_entity() == Some(*caller) && r.dst.as_entity() == Some(target.id)).count() == 1
        }) && renamed.iter().all(|(path, body)| {
            let digest = kin_model::Hash256::from_bytes(kin_blobs::digest(body.as_bytes()).0);
            let path = kin_model::RepoPath::from_utf8(*path).unwrap();
            snapshot.resolved_tree.artifact_at_path(&path)
                .is_some_and(|a| a.entry == kin_model::TreeEntry::blob(digest, false))
                && snapshot.entities.values().filter(|e| e.file_origin == Some(kin_model::FilePathId::new(path.as_utf8().unwrap())))
                    .all(|e| e.metadata.extra.get("blob_hash").and_then(|v| v.as_str()) == Some(digest.to_string().as_str()))
        })
    };
    let mut recovered = false;
    if arming == crate::daemon::WatchArming::Armed {
        // This is a real grouped host edit. Holding coordination prevents the
        // owned loop from publishing between these writes, not from observing
        // them. No synthetic event or semantic delta is inserted.
        {
            let _coordination = state.coordination_gate.lock().await;
            for (path, body) in &renamed {
                std::fs::write(repo.path().join(path), body).unwrap();
            }
        }
        recovered = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                if complete(&state)
                    && source_base_roots(&state).generation > roots_before.generation { break; }
                // Bounded observation of real watcher completion, no retrying
                // admission endpoint or extra file touch to conceal a failure.
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }).await.is_ok();
    }
    // Always stop this owned loop before assertions or cold reopen.
    let _ = cancel.send(true);
    let joined = tokio::time::timeout(Duration::from_secs(5), &mut task).await;
    if joined.is_err() { task.abort(); let _ = task.await; }
    assert_eq!(arming, crate::daemon::WatchArming::Armed);
    joined.expect("owned watcher stops").expect("watcher joins").expect("watcher succeeds");
    assert!(recovered, "actual watcher never published the coherent rename");
    assert!(complete(&state));
    assert!(source_base_roots(&state).generation > roots_before.generation);
    let target = waiting_entity(&state, "pkg/parsing.py", "canonical_title").id;
    drop(state);
    // Inspect actual persisted authority before any startup repair can help it.
    let reopened = Arc::new(DaemonState::open(layout).unwrap());
    assert!(complete(&reopened), "cold persisted authority must already contain both renamed callers");
    assert_eq!(waiting_entity(&reopened, "pkg/parsing.py", "canonical_title").id, target);
    for (path, body) in &renamed {
        assert_eq!(std::fs::read_to_string(repo.path().join(path)).unwrap(), *body);
    }
}

// Split grouped edits and single-file edits through the real watcher loop.
//
// A watcher delivers one grouped host edit in as many passes as its
// notifications happen to arrive in. Every pass that carries a complete source
// must publish that source's parse with its bytes, or a cold reopen answers
// from a parse no publication carried.

struct AmbientLoop {
    state: Arc<DaemonState>,
    cancel: tokio::sync::watch::Sender<bool>,
    task: tokio::task::JoinHandle<crate::error::Result<()>>,
}

impl AmbientLoop {
    async fn start(layout: kin_core::KinLayout) -> Self {
        let state = Arc::new(DaemonState::open(layout).unwrap());
        let (cancel, receiver) = tokio::sync::watch::channel(false);
        let (armed, ready) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(crate::loop_runner::run_loop_armed(
            Arc::clone(&state),
            crate::loop_runner::LoopConfig { poll_interval_ms: 20, batch_size: 64 },
            receiver,
            Some(crate::loop_runner::WatchArmed::new(armed)),
        ));
        assert_eq!(
            crate::daemon::await_watch_armed(ready, std::time::Duration::from_secs(10)).await,
            crate::daemon::WatchArming::Armed
        );
        Self { state, cancel, task }
    }

    /// One group of host writes, made while holding coordination so the loop
    /// observes them but cannot publish between them. Waits, with a bound, for
    /// authority to move and for `settled` to hold on the live graph.
    async fn edit(
        &self,
        writes: &[(std::path::PathBuf, String)],
        settled: impl Fn(&DaemonState) -> bool,
    ) {
        let before = source_base_roots(&self.state).generation;
        {
            let _coordination = self.state.coordination_gate.lock().await;
            for (path, body) in writes {
                std::fs::write(path, body).unwrap();
            }
        }
        let published = tokio::time::timeout(std::time::Duration::from_secs(20), async {
            while !(settled(&self.state) && source_base_roots(&self.state).generation > before) {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .is_ok();
        assert!(published, "the watcher never published this edit");
    }

    /// Stop the owned loop and hand the store back for a cold reopen.
    async fn stop(self) -> kin_core::KinLayout {
        let Self { state, cancel, mut task } = self;
        let _ = cancel.send(true);
        let joined = tokio::time::timeout(std::time::Duration::from_secs(5), &mut task).await;
        if joined.is_err() {
            task.abort();
            let _ = task.await;
        }
        joined.expect("owned watcher stops").expect("watcher joins").expect("watcher succeeds");
        state.layout.clone()
    }
}

/// The workspace graph persisted authority holds now, read from the store and
/// not from the daemon's live graph.
fn durable_workspace_graph(state: &DaemonState) -> kin_db::GraphSnapshot {
    let context =
        crate::local_repository_authority::LocalRepositoryAuthorityContext::from_state(state).unwrap();
    context
        .open()
        .unwrap()
        .read_authority()
        .workspace_graph_snapshot(&context.workspace_id())
        .unwrap()
        .unwrap()
}

/// The body `graph`'s parse-coverage certificate for `path` is bound to, found
/// by the certificate factory's own identity rule.
fn certified_body(graph: &kin_db::GraphSnapshot, path: &str) -> Option<kin_model::Hash256> {
    let artifact = graph
        .resolved_tree
        .artifact_at_path(&kin_model::RepoPath::from_utf8(path).unwrap())?;
    let id = kin_index::build_parse_coverage_relation(
        &kin_index::FileParseData {
            file_path: path.to_string(),
            entities: Vec::new(),
            relations: Vec::new(),
            imports: Vec::new(),
        },
        artifact.artifact_id,
        &kin_model::ParseCompleteness::Full,
        &std::collections::HashSet::<String>::new(),
    )
    .id;
    let certificate = graph.relations.get(&id)?;
    if !kin_index::is_parse_coverage_relation(certificate, path, artifact.artifact_id) {
        return None;
    }
    kin_index::parse_coverage_source_digest(certificate)
}

fn body_digest(body: &str) -> kin_model::Hash256 {
    kin_model::Hash256::from_bytes(kin_blobs::digest(body.as_bytes()).0)
}

fn renamed(body: &str) -> String {
    body.replace("normalize_title", "canonical_title")
}

/// Whether `graph` binds `caller` to the renamed target exactly once.
fn binds_renamed_target(graph: &kin_db::GraphSnapshot, caller: kin_model::EntityId) -> bool {
    let Some(target) = graph.entities.values().find(|entity| {
        entity.name == "canonical_title"
            && entity.file_origin == Some(kin_model::FilePathId::new("pkg/parsing.py"))
    }) else {
        return false;
    };
    graph
        .relations
        .values()
        .filter(|relation| {
            relation.kind == kin_model::RelationKind::Calls
                && relation.src.as_entity() == Some(caller)
                && relation.dst.as_entity() == Some(target.id)
        })
        .count()
        == 1
}

/// Every entity `caller` calls in `graph`.
fn calls_from(graph: &kin_db::GraphSnapshot, caller: kin_model::EntityId) -> std::collections::BTreeSet<kin_model::EntityId> {
    graph
        .relations
        .values()
        .filter(|relation| {
            relation.kind == kin_model::RelationKind::Calls && relation.src.as_entity() == Some(caller)
        })
        .filter_map(|relation| relation.dst.as_entity())
        .collect()
}

fn one_path(path: &str) -> std::collections::BTreeSet<kin_model::RepoPath> {
    std::collections::BTreeSet::from([kin_model::RepoPath::from_utf8(path).unwrap()])
}

/// A grouped rename the watcher splits into a two-file head and a one-file
/// tail. The head publishes both parses with its bytes and leaves both paths on
/// the ledger until a commit pays them. The tail is alone in its pass, and it
/// must still publish its own parse rather than leave it to the live graph: the
/// head's records are already derived in authority, so nothing pads the tail.
#[tokio::test]
async fn coherent_source_batch_split_rename_publishes_its_one_file_tail() {
    let (repo, state) = retry_batch_fixture().await;
    let storage_caller = waiting_entity(&state, "pkg/storage.py", "Database.ingest_note").id;
    let linkgraph_caller = waiting_entity(&state, "pkg/linkgraph.py", "LinkGraph.from_db").id;
    let layout = state.layout.clone();
    drop(state);
    let ambient = AmbientLoop::start(layout).await;
    let at = |path: &str| repo.path().join(path);
    let live = |view: &DaemonState| view.graph.semantic_observation();

    ambient
        .edit(
            &[
                (at("pkg/parsing.py"), renamed(RETRY_PARSING_PY)),
                (at("pkg/storage.py"), renamed(RETRY_STORAGE_PY)),
            ],
            |view| binds_renamed_target(&live(view), storage_caller),
        )
        .await;
    let durable = durable_workspace_graph(&ambient.state);
    let owed = crate::semantic_debt::outstanding(&ambient.state);
    for (path, body) in [("pkg/parsing.py", RETRY_PARSING_PY), ("pkg/storage.py", RETRY_STORAGE_PY)] {
        let digest = body_digest(&renamed(body));
        assert_eq!(certified_body(&durable, path), Some(digest), "the head publishes {path}'s parse");
        assert_eq!(certified_body(&live(&ambient.state), path), Some(digest));
        assert!(
            owed.iter().any(|record| record.path == path && record.body == digest.to_string()),
            "the head leaves {path} owed until a commit pays it: {owed:?}"
        );
    }
    assert!(binds_renamed_target(&durable, storage_caller));

    let mark = crate::loop_runner::prepared_batch_mark_for_test();
    ambient
        .edit(
            &[(at("pkg/linkgraph.py"), renamed(RETRY_LINKGRAPH_PY))],
            |view| binds_renamed_target(&live(view), linkgraph_caller),
        )
        .await;
    let durable = durable_workspace_graph(&ambient.state);
    assert_eq!(
        certified_body(&durable, "pkg/linkgraph.py"),
        Some(body_digest(&renamed(RETRY_LINKGRAPH_PY))),
        "the one-file tail publishes its parse with its bytes"
    );
    assert!(binds_renamed_target(&durable, linkgraph_caller));
    assert_eq!(
        crate::loop_runner::prepared_batches_since_for_test(&ambient.state, mark),
        vec![one_path("pkg/linkgraph.py")],
        "the tail derives its own file and pads no record the head already published"
    );
    let layout = ambient.stop().await;

    // Persisted authority, before any startup repair can help it.
    let reopened = Arc::new(DaemonState::open(layout).unwrap());
    let cold = reopened.graph.semantic_observation();
    assert!(
        binds_renamed_target(&cold, storage_caller) && binds_renamed_target(&cold, linkgraph_caller),
        "cold persisted authority must already contain both renamed callers"
    );
    assert!(cold.entities.values().all(|entity| entity.name != "normalize_title"));
}

/// The same rename split into three one-file passes. The first renames the
/// target under callers whose bytes still name the old one, so it withdraws
/// both cross-file bindings: that pass must be admitted, not refused, and the
/// withdrawal must be what authority holds.
#[tokio::test]
async fn coherent_source_batch_rename_split_into_one_file_passes_publishes_each() {
    let (repo, state) = retry_batch_fixture().await;
    let storage_caller = waiting_entity(&state, "pkg/storage.py", "Database.ingest_note").id;
    let linkgraph_caller = waiting_entity(&state, "pkg/linkgraph.py", "LinkGraph.from_db").id;
    let layout = state.layout.clone();
    drop(state);
    let ambient = AmbientLoop::start(layout).await;
    let at = |path: &str| repo.path().join(path);
    let live = |view: &DaemonState| view.graph.semantic_observation();
    let failures =
        |view: &DaemonState| view.background_work.reconcile().report(std::time::Instant::now()).admission_failures;
    let failed_before = failures(&ambient.state);
    // Nothing is owed before the first pass, so no record can pad a caller's
    // file into it: the callers in that pass's batch are its dependents.
    let owed = crate::semantic_debt::outstanding(&ambient.state);
    assert!(
        owed.iter().all(|record| record.path != "pkg/storage.py" && record.path != "pkg/linkgraph.py"),
        "no caller's file is on the ledger before the rename: {owed:?}"
    );

    // Renaming the target withdraws both callers' bindings, so that pass also
    // re-derives the two callers' unchanged admitted bytes as its dependents.
    // Each later pass derives exactly its own file.
    let every_file: std::collections::BTreeSet<_> = ["pkg/parsing.py", "pkg/storage.py", "pkg/linkgraph.py"]
        .into_iter()
        .map(|path| kin_model::RepoPath::from_utf8(path).unwrap())
        .collect();
    for (path, body, derived) in [
        ("pkg/parsing.py", RETRY_PARSING_PY, every_file),
        ("pkg/storage.py", RETRY_STORAGE_PY, one_path("pkg/storage.py")),
        ("pkg/linkgraph.py", RETRY_LINKGRAPH_PY, one_path("pkg/linkgraph.py")),
    ] {
        let digest = body_digest(&renamed(body));
        let mark = crate::loop_runner::prepared_batch_mark_for_test();
        ambient
            .edit(&[(at(path), renamed(body))], |view| certified_body(&live(view), path) == Some(digest))
            .await;
        let durable = durable_workspace_graph(&ambient.state);
        assert_eq!(certified_body(&durable, path), Some(digest), "{path}'s pass publishes its parse");
        assert_eq!(
            crate::loop_runner::prepared_batches_since_for_test(&ambient.state, mark),
            vec![derived],
            "{path}'s pass derives its own file and only the dependents it rebinds"
        );
        for caller in [storage_caller, linkgraph_caller] {
            assert_eq!(
                calls_from(&durable, caller),
                calls_from(&live(&ambient.state), caller),
                "after {path}, authority holds the calls the live graph holds"
            );
        }
        if path == "pkg/parsing.py" {
            assert!(!binds_renamed_target(&durable, storage_caller));
            assert!(!binds_renamed_target(&durable, linkgraph_caller));
        }
    }
    assert_eq!(failures(&ambient.state), failed_before, "no pass was refused");
    let layout = ambient.stop().await;

    let reopened = Arc::new(DaemonState::open(layout).unwrap());
    let cold = reopened.graph.semantic_observation();
    assert!(
        binds_renamed_target(&cold, storage_caller) && binds_renamed_target(&cold, linkgraph_caller),
        "cold persisted authority must already contain both renamed callers"
    );
}

/// An ordinary one-file edit is durable in cold authority without a commit,
/// with its exact bytes and its cross-file relations. It is made after an
/// earlier publication left two derived but unpaid records, and its pass
/// derives only the edited file: a record authority already derived is not
/// padded into every later batch.
#[tokio::test]
async fn a_single_file_ambient_edit_is_durable_and_pads_no_derived_debt() {
    let (repo, state) = retry_batch_fixture().await;
    let layout = state.layout.clone();
    drop(state);
    let ambient = AmbientLoop::start(layout).await;
    let at = |path: &str| repo.path().join(path);
    let live = |view: &DaemonState| view.graph.semantic_observation();

    let parsing = format!("{RETRY_PARSING_PY}\n# reviewed\n");
    let linkgraph = format!("{RETRY_LINKGRAPH_PY}\n# reviewed\n");
    ambient
        .edit(
            &[(at("pkg/parsing.py"), parsing.clone()), (at("pkg/linkgraph.py"), linkgraph.clone())],
            |view| {
                let snapshot = live(view);
                certified_body(&snapshot, "pkg/parsing.py") == Some(body_digest(&parsing))
                    && certified_body(&snapshot, "pkg/linkgraph.py") == Some(body_digest(&linkgraph))
            },
        )
        .await;
    let durable = durable_workspace_graph(&ambient.state);
    let owed = crate::semantic_debt::outstanding(&ambient.state);
    for (path, body) in [("pkg/parsing.py", &parsing), ("pkg/linkgraph.py", &linkgraph)] {
        assert_eq!(certified_body(&durable, path), Some(body_digest(body)), "{path} is derived in authority");
        assert!(
            owed.iter().any(|record| record.path == path && record.body == body_digest(body).to_string()),
            "{path} is still unpaid: {owed:?}"
        );
    }

    let storage = format!(
        "{RETRY_STORAGE_PY}\n\ndef title_of(note):\n    return normalize_title(note[\"path\"])\n"
    );
    let mark = crate::loop_runner::prepared_batch_mark_for_test();
    ambient
        .edit(&[(at("pkg/storage.py"), storage.clone())], |view| {
            certified_body(&live(view), "pkg/storage.py") == Some(body_digest(&storage))
        })
        .await;
    assert_eq!(
        certified_body(&durable_workspace_graph(&ambient.state), "pkg/storage.py"),
        Some(body_digest(&storage)),
        "the edit publishes its parse with its bytes"
    );
    assert_eq!(
        crate::loop_runner::prepared_batches_since_for_test(&ambient.state, mark),
        vec![one_path("pkg/storage.py")],
        "the edit derives its own file and pads neither derived record"
    );
    let layout = ambient.stop().await;

    let reopened = Arc::new(DaemonState::open(layout).unwrap());
    let cold = reopened.graph.semantic_observation();
    assert_eq!(certified_body(&cold, "pkg/storage.py"), Some(body_digest(&storage)));
    let title_of = cold
        .entities
        .values()
        .find(|entity| {
            entity.name == "title_of"
                && entity.file_origin == Some(kin_model::FilePathId::new("pkg/storage.py"))
        })
        .expect("the new function is durable without a commit");
    assert_eq!(
        title_of.metadata.extra.get("blob_hash").and_then(|value| value.as_str()),
        Some(body_digest(&storage).to_string().as_str())
    );
    let target = cold
        .entities
        .values()
        .find(|entity| entity.name == "normalize_title")
        .expect("the unchanged target");
    assert!(
        cold.relations.values().any(|relation| relation.kind == kin_model::RelationKind::Calls
            && relation.src.as_entity() == Some(title_of.id)
            && relation.dst.as_entity() == Some(target.id)),
        "its cross-file call is durable too"
    );
}

/// One pass carrying a complete source, a source whose parse is partial, and a
/// non-source file. Only the complete source is batched and published with its
/// parse. The partial source keeps its last readable declarations and its
/// disclosure, and the non-source file is admitted, both by the sequential path
/// exactly as before.
#[tokio::test]
async fn a_complete_source_beside_a_partial_one_publishes_alone() {
    let (repo, state) = retry_batch_fixture().await;
    let layout = state.layout.clone();
    drop(state);
    let ambient = AmbientLoop::start(layout).await;
    let at = |path: &str| repo.path().join(path);
    let live = |view: &DaemonState| view.graph.semantic_observation();

    let storage = format!(
        "{RETRY_STORAGE_PY}\n\ndef title_of(note):\n    return normalize_title(note[\"path\"])\n"
    );
    let cli = format!("{RETRY_CLI_PY}\n\ndef unfinished(:\n");
    let notes = "# Notes\n".to_string();
    let mark = crate::loop_runner::prepared_batch_mark_for_test();
    ambient
        .edit(
            &[
                (at("pkg/storage.py"), storage.clone()),
                (at("pkg/cli.py"), cli.clone()),
                (at("NOTES.md"), notes.clone()),
            ],
            |view| {
                let snapshot = live(view);
                let admitted = |path: &str, body: &str| {
                    snapshot
                        .resolved_tree
                        .artifact_at_path(&kin_model::RepoPath::from_utf8(path).unwrap())
                        .is_some_and(|artifact| artifact.entry == kin_model::TreeEntry::blob(body_digest(body), false))
                };
                certified_body(&snapshot, "pkg/storage.py") == Some(body_digest(&storage))
                    && admitted("pkg/cli.py", &cli)
                    && admitted("NOTES.md", &notes)
                    && kin_core::retained_parse::read(&view.layout).errors_for("pkg/cli.py").is_some()
            },
        )
        .await;
    assert_eq!(
        certified_body(&durable_workspace_graph(&ambient.state), "pkg/storage.py"),
        Some(body_digest(&storage)),
        "the complete source publishes its parse with its bytes"
    );
    let batches = crate::loop_runner::prepared_batches_since_for_test(&ambient.state, mark);
    assert!(
        batches.iter().all(|batch| batch == &one_path("pkg/storage.py")) && !batches.is_empty(),
        "only the complete source is batched: {batches:?}"
    );
    assert!(kin_core::retained_parse::read(&ambient.state.layout)
        .errors_for("pkg/cli.py")
        .is_some_and(|count| count > 0));
    let layout = ambient.stop().await;

    let reopened = Arc::new(DaemonState::open(layout).unwrap());
    let cold = reopened.graph.semantic_observation();
    assert_eq!(certified_body(&cold, "pkg/storage.py"), Some(body_digest(&storage)));
    assert!(cold.entities.values().any(|entity| entity.name == "main"
        && entity.file_origin == Some(kin_model::FilePathId::new("pkg/cli.py"))),
        "the partial source keeps its last readable declarations");
    assert!(cold
        .resolved_tree
        .artifact_at_path(&kin_model::RepoPath::from_utf8("NOTES.md").unwrap())
        .is_some());
}

/// Host drift on a one-source batch still refuses before publication. A
/// one-source batch hands its source back to the sequential reconciler only
/// for the failures that reconciler handles itself, and a host entry that
/// changed while the batch was checked is not one of them: publishing then
/// would publish bytes nobody observed. Falsify by handing every one-source
/// failure back: the refusal disappears and authority moves.
#[tokio::test]
async fn a_one_source_batch_refuses_host_drift_before_publication() {
    let (repo, state) = retry_batch_fixture().await;
    let before = state.graph.semantic_observation();
    let roots = source_base_roots(&state);
    let once = Arc::new(std::sync::atomic::AtomicBool::new(true));
    state.reconciler.write().await.set_traffic_checker(Box::new(RetryBatchHostEdit {
        path: repo.path().join("pkg/storage.py"),
        once: once.clone(),
    }));
    std::fs::write(
        repo.path().join("pkg/storage.py"),
        format!("{RETRY_STORAGE_PY}\n# one-source edit\n"),
    )
    .unwrap();
    let response = router(Arc::clone(&state)).oneshot(
        Request::post("/commands/commit").header("content-type", "application/json")
            .body(Body::from(json!({"operation_id":kin_model::OperationId::new(),
                "timestamp":Timestamp::now(),"author":"Test Author <test@example.invalid>",
                "message":"must refuse a drifted one-source batch"}).to_string())).unwrap()
    ).await.unwrap();
    let status = response.status();
    let body = axum::body::to_bytes(response.into_body(), 256 * 1024).await.unwrap();
    let text = String::from_utf8_lossy(&body);
    assert!(!once.load(std::sync::atomic::Ordering::Relaxed), "the batch's preflight must run");
    assert!(!status.is_success(), "drifted bytes must not publish: {text}");
    assert!(text.contains("host entry changed during coherent source reconciliation"), "{text}");
    assert_eq!(source_base_roots(&state), roots);
    let after = state.graph.semantic_observation();
    assert_eq!(after.entities, before.entities);
    assert_eq!(after.relations, before.relations);
    assert_eq!(after.resolved_tree, before.resolved_tree);
    assert_eq!(
        std::fs::read_to_string(repo.path().join("pkg/storage.py")).unwrap(),
        "# newer editor save during preflight\n",
        "the refusal cannot overwrite the newer save"
    );
}
