// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result};

use super::commit_progress::{
    daemon_death_explanation, PhaseTail, AUTHORITY_NOT_GIT_NOTE, DETACHED_HEAD_NOTE,
};

pub async fn run(message: String, quiet: bool) -> Result<()> {
    let layout = crate::commands::require_repository_layout()?;
    // Before attribution, before the daemon is resolved, before anything this
    // command does for itself. The ambient reconcile tick and this commit both
    // admit the whole working copy, and whichever publishes first makes the
    // other's publication redundant, so the tick is written to stand down for a
    // commit it knows about. It can only know about one that has reached it,
    // and reaching it is the slow part: a commit that has to start the daemon
    // waits for the store to open before it can say anything at all, by which
    // time the first reconcile round has already decided. Announcing here
    // reaches that round, because the announcement is on disk before the daemon
    // exists.
    let _announced = CommitAnnouncement::announce(layout.root());

    let result = run_daemon_commit(&layout, &message, quiet).await?;
    if !quiet {
        println!(
            "{}",
            render_commit_summary(&result, pending_enrichment(&layout).await.as_deref())
        );
    }
    Ok(())
}

/// What this store's cross-file sweep still owes, when it owes anything.
///
/// `kin commit` printed `(0 entities, 0 relations, 2 artifacts)` for a fully
/// parseable new module, because the counts are the change's own deltas and the
/// sweep that derives cross-file edges had not reached the file yet. The next
/// `kin diff` then showed `Relations: +123` on a tree with no file change. Both
/// readings are correct and neither one says the word "yet", so the surface
/// that reports success is the surface that leaves out the part that is still
/// moving. FIR-2776.
///
/// Read after the commit and not before it, because the question is what is
/// outstanding for the store the reader now has. Every failure answers `None`:
/// an enrichment probe must never be able to turn a landed commit into an
/// error, and a commit that already succeeded is not made wrong by a daemon
/// that would not say how its sweep is going.
async fn pending_enrichment(layout: &kin_core::KinLayout) -> Option<String> {
    let url = crate::daemon_client::resolve_daemon_url_if_running_async(layout).await?;
    let client = crate::daemon_client::DaemonClient::from_base_url_for_layout(url, layout).ok()?;
    let status = probe_sweep_status(&client).await?;
    let field = |name: &str| status.get(name).and_then(|value| value.as_u64());
    let done = field("files_done")?;
    let total = field("files_total")?;
    let running = status
        .get("running")
        .and_then(|value| value.as_bool())
        .unwrap_or(false);
    pending_enrichment_line(running, done, total)
}

/// Ask the daemon how its sweep is going, under a bound of this command's own.
///
/// A function rather than an inline `timeout`, so a test can drive the real
/// call against a real socket that never answers. Asserting the bound by
/// wrapping the client in the test would pin the constant and nothing else, and
/// would keep passing on the day this call site stopped using it.
///
/// The client's own ceiling is 300 s. The endpoint is an atomics read and
/// answers instantly on a daemon that is well, but the daemon this line is
/// ABOUT is a busy one, and five minutes of silence after a commit that already
/// landed is a worse surface than no line at all. An answer that does not
/// arrive in the window is treated exactly like one that could not be read.
async fn probe_sweep_status(
    client: &crate::daemon_client::DaemonClient,
) -> Option<serde_json::Value> {
    tokio::time::timeout(PENDING_ENRICHMENT_PROBE, client.lsp_sweep_status())
        .await
        .ok()?
        .ok()
}

/// The sentence, split from the probe so both branches are testable without a
/// daemon.
///
/// Two conditions, not one. `running` alone goes quiet on a sweep that was cut
/// short and never resumed, which is a store with work outstanding and nothing
/// in flight to finish it. An unwalked file count alone goes quiet in the
/// window between a sweep being queued and its first file landing.
///
/// A store whose sweep has walked everything it has prints nothing, and a store
/// that has never had a file to walk prints nothing either, because both
/// counters are zero and zero is not behind zero. That silence is the point: a
/// line under every commit is a line nobody reads by the third one.
fn pending_enrichment_line(running: bool, done: u64, total: u64) -> Option<String> {
    if !running && done >= total {
        return None;
    }
    if total == 0 {
        return None;
    }
    Some(format!(
        "Cross-file enrichment is still catching up ({done} of {total} files). The counts above \
         are this change's own deltas, so edges the sweep has not reached are not in it; they \
         reach durable authority at your next commit. Until then they live only in this daemon, \
         and a daemon that exits loses them from its live graph; its next start resumes the sweep \
         from where it stopped."
    ))
}

/// The announcement this command publishes for as long as it runs.
///
/// Withdrawn on drop, so every way the run can end withdraws it: a refusal, a
/// transport failure, and the success path all pass through the same one line.
/// What survives that is a killed process, and the announcement carries its own
/// expiry for exactly that case.
struct CommitAnnouncement {
    kin_root: std::path::PathBuf,
}

impl CommitAnnouncement {
    fn announce(kin_root: &std::path::Path) -> Self {
        kin_daemon_spawn::write_approaching_commit(
            kin_root,
            &kin_daemon_spawn::ApproachingCommit {
                pid: std::process::id(),
                announced_unix: unix_now(),
            },
        );
        Self {
            kin_root: kin_root.to_path_buf(),
        }
    }
}

impl Drop for CommitAnnouncement {
    fn drop(&mut self) {
        kin_daemon_spawn::clear_approaching_commit(&self.kin_root);
    }
}

/// What a successful `kin commit` prints.
///
/// The second line is said every time, because the surprise is permanent: the
/// working tree this change came from stays dirty and `git log` never moves.
/// Without it a brownfield user commits all day and reads `git status` as proof
/// that nothing happened.
fn render_commit_summary(result: &DaemonCommitResult, pending: Option<&str>) -> String {
    let landed = match &result.branch {
        Some(branch) => format!("on branch '{branch}'"),
        None => "on a detached HEAD, which no branch names".to_string(),
    };
    let summary = format!(
        "Created semantic change {} {} ({} entities, {} relations, {} artifacts)\n{}{}",
        result.change_id,
        landed,
        result.entity_count,
        result.relation_count,
        result.file_count,
        AUTHORITY_NOT_GIT_NOTE,
        match &result.branch {
            Some(_) => String::new(),
            None => format!("\n{DETACHED_HEAD_NOTE}"),
        },
    );
    match pending {
        Some(pending) => format!("{summary}\n{pending}"),
        None => summary,
    }
}

/// Result from the daemon-owned native commit transaction.
///
/// Commit construction deliberately has no CLI-local fallback. Repository
/// membership, stable artifact identities, exact blobs, semantic enrichment,
/// the immutable change, and ref publication all belong to the daemon's one
/// serialized authority path.
#[derive(Debug, serde::Deserialize)]
struct DaemonCommitResult {
    change_id: String,
    /// The branch this change was published onto.
    ///
    /// Absent when the workspace head is detached, which is a repository
    /// converted while Git's own HEAD was detached and never moved onto a
    /// branch since. The daemon advances that head to the new change and moves
    /// no ref, so there is no branch to name and inventing one here would be a
    /// worse answer than saying so.
    #[serde(default)]
    branch: Option<String>,
    entity_count: usize,
    relation_count: usize,
    file_count: usize,
}

/// How long the post-commit enrichment probe is allowed to take.
///
/// Short on purpose. The commit has landed by the time this runs, so every
/// second here is a second a user waits to be told their write succeeded, and
/// the sentence it buys is an advisory one.
const PENDING_ENRICHMENT_PROBE: std::time::Duration = std::time::Duration::from_secs(3);

/// How often the phase tail is read while the commit request is outstanding.
const PHASE_POLL_INTERVAL: std::time::Duration = std::time::Duration::from_millis(400);

async fn run_daemon_commit(
    layout: &kin_core::KinLayout,
    message: &str,
    quiet: bool,
) -> Result<DaemonCommitResult> {
    // Resolved here, in the caller's own environment and working directory,
    // rather than inside the daemon. The daemon is spawned with every `GIT_*`
    // variable scrubbed and does not share the caller's shell, so an identity it
    // resolved for itself would answer a different question than "who is running
    // this command". Resolution also comes before the daemon is contacted: a
    // commit that cannot be attributed must not reach the authority path at all.
    let author = crate::commands::require_commit_author_for(layout)?;
    let daemon_url = crate::daemon_client::resolve_daemon_url(layout)
        .await?
        .ok_or_else(|| crate::daemon_client::daemon_required_error("commit", layout))?;

    let client = build_commit_client(commit_reply_deadline())?;
    // Create these once per CLI invocation so transport retry logic can reuse
    // the byte-identical repository transaction.
    let operation_id = kin_model::OperationId::new();
    let timestamp = kin_model::Timestamp::now();
    let mut request = client
        .post(format!(
            "{}/commands/commit",
            daemon_url.trim_end_matches('/')
        ))
        .json(&serde_json::json!({
            "operation_id": operation_id,
            "timestamp": timestamp,
            "message": message,
            "author": author,
        }));
    if let Some(token) = crate::daemon_client::resolve_daemon_auth_token() {
        request = request.bearer_auth(token);
    }

    let kin_root = layout.root().to_path_buf();
    // Opened before the request so the first phase the daemon enters is already
    // inside the window this reads.
    let mut tail = PhaseTail::open(&kin_root);
    // Taken here for the same reason and over the same window as the phase
    // tail. The cgroup's kill and ceiling counters are cumulative for the
    // container's whole life, so the reading that matters is the difference
    // across this request rather than the total after it. FIR-1823: without a
    // before-reading, a kill from any earlier process in the same container
    // made this commit report itself as the thing that ran out of memory.
    let memory_baseline = crate::capability::memory_baseline();
    let response = stream_phases_while(quiet, &mut tail, request.send()).await;
    let response = match response {
        Ok(response) => response,
        Err(error) => {
            return resolve_commit_after_lost_reply(
                layout,
                &kin_root,
                operation_id,
                error,
                quiet,
                memory_baseline,
            );
        }
    };
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        if let Some(refusal) = commit_refusal_message(&body) {
            anyhow::bail!(refusal);
        }
        anyhow::bail!("daemon native commit failed (HTTP {status}): {body}");
    }
    response
        .json()
        .await
        .context("decode daemon native commit response")
}

/// How long the CLI waits for the daemon to answer a commit.
///
/// `None`, and that is the fix. The client used to carry a fixed 120-second
/// deadline, which is shorter than a one-file commit on a converted repository
/// of any size: on a psf/requests store the phases behind one docstring edit ran
/// for 213 seconds. Nothing about the deadline expiring cancelled the commit.
/// The daemon kept going, published the change minutes later, and the person who
/// had already read `operation timed out` retried, which is how a store ends up
/// carrying an empty change stacked on the real one.
///
/// A deadline can only be right if the CLI knows how long the work should take,
/// and it cannot: the cost is a property of the store. What the CLI can do is
/// show the phases the daemon is in, which it does for the whole wait, so a
/// commit that is working and a commit that is wedged no longer look the same.
/// A daemon that really is wedged is ended by the supervisor's reaper, and that
/// arrives here as a transport error carrying the reaper's own note.
fn commit_reply_deadline() -> Option<std::time::Duration> {
    None
}

/// The HTTP client a commit is sent with.
///
/// The connect timeout stays: refusing to connect is an immediate, local fact
/// about a daemon that is not listening, and waiting on it forever would trade
/// one bad failure mode for another. Only the reply deadline is the caller's to
/// choose, and production chooses none.
fn build_commit_client(deadline: Option<std::time::Duration>) -> reqwest::Result<reqwest::Client> {
    let mut builder =
        reqwest::Client::builder().connect_timeout(std::time::Duration::from_millis(500));
    if let Some(deadline) = deadline {
        builder = builder.timeout(deadline);
    }
    builder.build()
}

/// The one-line refusal a daemon body carries, when it carries one.
///
/// A refusal the daemon states in words is worth exactly those words. Wrapping
/// it in `daemon native commit failed (HTTP 409): {"error":...}` buries the
/// sentence a person needs inside a serialized envelope they have to read past.
///
/// Two refusals are worded: a successor that would record nothing, and a
/// working projection blocked on a file a person has to act on, such as the
/// eject journal a copied `.kin` carries in. The second reached a stranger as
/// `HTTP 500 Internal Server Error: Core error: ...` on 0.5.52, and the only
/// exit that read found was deleting the store (FIR-2664).
fn commit_refusal_message(body: &str) -> Option<String> {
    let parsed: serde_json::Value = serde_json::from_str(body).ok()?;
    let kind = parsed.get("error")?.as_str()?;
    if !matches!(kind, "nothing_to_commit" | "projection_blocked") {
        return None;
    }
    Some(parsed.get("message")?.as_str()?.to_string())
}

/// What the CLI can still learn about a commit whose reply never arrived.
#[derive(Debug)]
enum LostReply {
    /// The operation is in repository authority. The commit landed and the
    /// reply is the only thing that was lost.
    Landed(Box<DaemonCommitResult>),
    /// No receipt yet, and the daemon is still beating on an open transaction.
    /// The commit is running; it has not failed.
    StillRunning(String),
    /// No receipt, and nothing proves any work is still in flight.
    Gone {
        /// The marker the daemon left behind, when one is there.
        ///
        /// A daemon that is killed never retires its own marker, so this is
        /// the last thing it managed to say about the work it was doing: the
        /// phase it was in, how long it had been there, and how much memory it
        /// was holding. It is carried out of the classification rather than
        /// dropped because it is the entire evidence base for the sentence the
        /// caller gets.
        abandoned: Option<Box<kin_daemon_spawn::OpenTransaction>>,
        /// Whether the pid that published `abandoned` is still running. A dead
        /// pid is a process that stopped; a live one whose beat went quiet is a
        /// daemon that is wedged, and the two need different sentences.
        daemon_alive: bool,
    },
}

/// Decide what a lost reply means from the facts on disk.
///
/// Separated from the reads so the decision can be tested against every
/// combination of them, including the two that are easy to get wrong. A receipt
/// means landed no matter what the marker says, because a daemon that finished
/// this commit and went on to other work still publishes a marker. And a marker
/// is trusted only while the daemon that wrote it is still running: a daemon
/// killed mid-commit never retires its marker, and the kernel's OOM killer
/// leaves no note behind either, so a beat alone would report a dead daemon's
/// abandoned commit as still in flight.
fn classify_lost_reply(
    landed: Option<DaemonCommitResult>,
    open: Option<kin_daemon_spawn::OpenTransaction>,
    now_unix: u64,
    is_alive: impl Fn(u32) -> bool,
) -> LostReply {
    if let Some(result) = landed {
        return LostReply::Landed(Box::new(result));
    }
    let daemon_alive = open.as_ref().is_some_and(|open| is_alive(open.pid));
    match open {
        Some(open) if open.is_beating(now_unix) && daemon_alive => {
            LostReply::StillRunning(open.summary())
        }
        abandoned => LostReply::Gone {
            abandoned: abandoned.map(Box::new),
            daemon_alive,
        },
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_secs())
        .unwrap_or(0)
}

/// Report a commit whose reply was lost, by asking authority what happened.
///
/// The transport error is the last thing consulted rather than the first. A
/// commit is recorded by the repository transaction, not by the response that
/// describes it, so the honest question after a lost reply is whether this
/// operation reached authority. When it did, the commit succeeded and says so;
/// when it did not but the daemon is still beating on an open transaction, the
/// commit is still running and says that instead of reporting a failure that has
/// not happened.
fn resolve_commit_after_lost_reply(
    layout: &kin_core::KinLayout,
    kin_root: &std::path::Path,
    operation_id: kin_model::OperationId,
    error: reqwest::Error,
    quiet: bool,
    memory_baseline: crate::capability::MemoryBaseline,
) -> Result<DaemonCommitResult> {
    let lookup = landed_commit_for_operation(layout, operation_id);
    let unreadable_authority = lookup.as_ref().err().map(|error| format!("{error:#}"));
    let landed = lookup.unwrap_or(None);
    match classify_lost_reply(
        landed,
        kin_daemon_spawn::read_open_transaction(kin_root),
        unix_now(),
        kin_daemon_spawn::process_is_alive,
    ) {
        LostReply::Landed(result) => {
            if !quiet {
                eprintln!(
                    "The daemon's reply was lost, and repository authority holds this commit \
                     (operation {operation_id}). Reporting the change it recorded."
                );
            }
            Ok(*result)
        }
        LostReply::StillRunning(open) => anyhow::bail!(
            "the daemon is still committing ({open}) and this commit has not failed. \
             Operation {operation_id} appears in `kin log` when it lands; a `kin commit` \
             run before then waits for it and is refused rather than recorded."
        ),
        LostReply::Gone {
            abandoned,
            daemon_alive,
        } => {
            // A transport error names a socket. When the daemon was killed with
            // this request in flight, the socket is the symptom and the killer
            // left the cause in the repository.
            //
            // Two killers leave two different traces. A reaper writes a death
            // note, so that is read first and quoted as the killer's own words.
            // The kernel's OOM killer writes nothing at all, which is why the
            // reported failure named only HTTP: the daemon's own abandoned
            // marker and this host's memory accounting are the only evidence
            // that death leaves, and they are what the second reading uses.
            let cause = daemon_death_explanation(kin_root).or_else(|| {
                super::commit_progress::daemon_loss_explanation(
                    abandoned.as_deref(),
                    daemon_alive,
                    unix_now(),
                    &crate::capability::memory_evidence_since(memory_baseline),
                    // Sampled here rather than inside the explanation so the
                    // sentence stays a pure rendering of what was observed.
                    // The dead daemon is excluded by its own marker pid: it is
                    // already gone, and a pid the OS has reused would otherwise
                    // be reported as memory a reader could reclaim.
                    &super::commit_progress::other_resident_daemons(
                        abandoned.as_ref().map_or(0, |open| open.pid),
                    ),
                )
            });
            let error = match cause {
                Some(cause) => anyhow::Error::new(error).context(cause),
                None => {
                    anyhow::Error::new(error).context("send daemon-owned native commit request")
                }
            };
            Err(match unreadable_authority {
                Some(why) => error.context(format!(
                    "repository authority could not be read to check whether operation \
                     {operation_id} landed: {why}"
                )),
                None => error.context(format!(
                    "repository authority holds no receipt for operation {operation_id}: \
                     the change was not recorded"
                )),
            })
        }
    }
}

/// The change this operation id published, read from repository authority.
///
/// The same lookup the daemon performs to recover its own interrupted commits,
/// run from the CLI over the durable store rather than over a daemon that may no
/// longer be answering. It is deliberately not a daemon request: the state this
/// exists to report on is exactly the state in which the daemon cannot answer.
fn landed_commit_for_operation(
    layout: &kin_core::KinLayout,
    operation_id: kin_model::OperationId,
) -> Result<Option<DaemonCommitResult>> {
    let binding = kin_core::LocalRepositoryAuthorityBinding::from_layout(layout)?;
    let authority = super::repository_authority::ActiveRepositoryAuthority::open(&binding)?;
    let lease = authority.manager().read_authority();
    let Some(receipt) = lease
        .metadata()
        .receipts
        .iter()
        .find(|receipt| receipt.operation_id == operation_id)
    else {
        return Ok(None);
    };
    // The daemon's own recovery asks this of the same record, so the rule lives
    // in kin-core rather than once in each crate. A second copy is only ever
    // wrong in a way that looks like a passing run: both suites stay green while
    // one side writes a shape the other stopped reading.
    let Some(published) = kin_core::published_change(&receipt.operation) else {
        return Ok(None);
    };
    let (branch, change_id) = (
        published.branch.map(|name| name.to_string()),
        published.change_id,
    );
    let change = lease.snapshot().changes.get(&change_id).ok_or_else(|| {
        anyhow::anyhow!(
            "repository receipt for operation {operation_id} references missing change {change_id}"
        )
    })?;
    Ok(Some(DaemonCommitResult {
        change_id: change_id.to_string(),
        branch,
        entity_count: change.entity_deltas.len(),
        relation_count: change.relation_deltas.len(),
        file_count: change.tree_deltas.len(),
    }))
}

/// Await `work`, printing the phases the daemon reaches while it runs.
///
/// The daemon names each phase into `.kin/daemon.log` as it enters and leaves
/// it, and a commit-in-flight beat keeps naming the running one, so the caller
/// sees the same attribution the log carries instead of two to three minutes of
/// nothing.
async fn stream_phases_while<F: std::future::Future>(
    quiet: bool,
    tail: &mut PhaseTail,
    work: F,
) -> F::Output {
    if quiet {
        return work.await;
    }
    let mut progress = crate::progress::Progress::stderr();
    let outcome =
        drive_phases_while(tail, work, |phase| progress.update(format_args!("{phase}"))).await;
    progress.finish();
    outcome
}

/// The streaming loop, with the sink injected.
///
/// Separated from the terminal writer so a test can assert the thing that
/// actually matters — that phases reach the caller *while* the commit is still
/// running — rather than only that they reach it eventually. A version that
/// collected everything and printed it at the end would satisfy any assertion
/// made on the finished output and would fix nothing.
async fn drive_phases_while<F: std::future::Future>(
    tail: &mut PhaseTail,
    work: F,
    mut emit: impl FnMut(&str),
) -> F::Output {
    let mut ticker = tokio::time::interval(PHASE_POLL_INTERVAL);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    tokio::pin!(work);
    let outcome = loop {
        tokio::select! {
            outcome = &mut work => break outcome,
            _ = ticker.tick() => {
                for phase in tail.poll() {
                    emit(&phase);
                }
            }
        }
    };
    // Drain whatever the daemon wrote between the last tick and the reply, so
    // the phase that finished the commit is reported like every other one.
    for phase in tail.poll() {
        emit(&phase);
    }
    outcome
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;

    fn append(path: &std::path::Path, text: &str) {
        use std::io::Write as _;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        file.write_all(text.as_bytes()).unwrap();
    }

    /// A commit that takes two to three minutes printed nothing for all of it,
    /// so a working commit and a hung one looked identical — which is how a
    /// commit that had already been dead for 20 seconds still looked fine.
    ///
    /// The assertion is ordering, not presence: every phase must land before the
    /// request resolves. Falsify by moving the `tail.poll()` loop out of the
    /// select and running it only after `work` completes; the phases then all
    /// arrive after `request-finished` and the position check fails.
    #[tokio::test]
    async fn commit_phases_reach_the_caller_while_the_request_is_still_outstanding() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("daemon.log");
        std::fs::write(&log, "").unwrap();
        let mut tail = PhaseTail::open(dir.path());

        let seen = Rc::new(RefCell::new(Vec::<String>::new()));
        let recorder = Rc::clone(&seen);
        let slow_commit = async {
            for phase in ["publish_workspace_admission", "plan_transaction"] {
                append(
                    &log,
                    &format!(
                        "INFO kin_daemon::commit_liveness: commit phase in progress \
                         phase=\"{phase}\" elapsed_ms=5000\n"
                    ),
                );
                tokio::time::sleep(PHASE_POLL_INTERVAL * 2).await;
            }
            recorder.borrow_mut().push("request-finished".to_string());
        };

        let sink = Rc::clone(&seen);
        drive_phases_while(&mut tail, slow_commit, |phase| {
            sink.borrow_mut().push(phase.to_string())
        })
        .await;

        let seen = seen.borrow();
        let finished = seen
            .iter()
            .position(|line| line == "request-finished")
            .expect("the request must have completed");
        assert!(
            finished > 0,
            "at least one phase must print before the reply: {seen:?}"
        );
        for phase in ["publish_workspace_admission", "plan_transaction"] {
            let at = seen
                .iter()
                .position(|line| line.starts_with(phase))
                .unwrap_or_else(|| panic!("phase {phase} was never shown: {seen:?}"));
            assert!(
                at < finished,
                "phase {phase} reached the caller only after the reply: {seen:?}"
            );
        }
    }

    fn commit_body() -> serde_json::Value {
        serde_json::json!({
            "operation_id": kin_model::OperationId::new(),
            "timestamp": kin_model::Timestamp::now(),
            "message": "publish one docstring edit",
            "author": "Ada Lovelace <ada@example.com>",
        })
    }

    /// The commit line says where the change went, and on a detached head it
    /// says so in words plus the one command that puts the work on a branch.
    #[test]
    fn the_commit_summary_names_a_detached_head_and_how_to_leave_it() {
        let mut result = landed_result();
        result.branch = None;
        let text = render_commit_summary(&result, None);
        assert!(
            text.contains("on a detached HEAD"),
            "a detached commit must say so rather than name a branch: {text}"
        );
        assert!(
            !text.contains("on branch"),
            "no branch moved, so none may be named: {text}"
        );
        assert!(
            text.contains("kin branch create"),
            "the reader is told how to put this change on a branch: {text}"
        );
        // The line above this one ends in "push this branch to a Kin remote".
        // On a detached head there is no branch, so the pair has to resolve
        // itself rather than leave a reader holding two sentences that
        // disagree.
        assert!(
            text.contains("nothing to push yet"),
            "the detached note must settle the push sentence above it: {text}"
        );

        // The control, same renderer, same fixture but for the one field.
        let on_branch = render_commit_summary(&landed_result(), None);
        assert!(
            on_branch.contains("on branch 'refs/heads/main'"),
            "a branch commit still names its branch: {on_branch}"
        );
        assert!(
            !on_branch.contains("kin branch create"),
            "a commit already on a branch is not told how to make one: {on_branch}"
        );
    }

    fn landed_result() -> DaemonCommitResult {
        DaemonCommitResult {
            change_id: "5b8ca7b7".to_string(),
            branch: Some("refs/heads/main".to_string()),
            entity_count: 32,
            relation_count: 4,
            file_count: 1,
        }
    }

    fn open_commit(beat_unix: u64) -> kin_daemon_spawn::OpenTransaction {
        kin_daemon_spawn::OpenTransaction {
            pid: std::process::id(),
            operation: "commit".to_string(),
            phase: Some("reconcile_workspace_and_commit_authority".to_string()),
            elapsed_secs: 213,
            phase_elapsed_secs: 60,
            beat_unix,
            rss_bytes: None,
            peak_rss_bytes: None,
        }
    }

    /// The marker a dead daemon leaves is the only evidence of what it was
    /// doing, so the classification must carry it out rather than drop it.
    ///
    /// Falsify by returning `abandoned: None` from the `Gone` arm of
    /// [`classify_lost_reply`]: this fails, and with it every memory sentence
    /// the caller can produce, because there is then nothing left to read.
    #[test]
    fn a_dead_daemons_marker_is_carried_out_of_the_classification() {
        match classify_lost_reply(None, Some(open_commit(1_000)), 1_030, |_| false) {
            LostReply::Gone {
                abandoned,
                daemon_alive,
            } => {
                assert!(!daemon_alive, "the pid probe said this daemon is gone");
                let marker = abandoned.expect("the marker the daemon left must survive");
                assert_eq!(
                    marker.phase.as_deref(),
                    Some("reconcile_workspace_and_commit_authority")
                );
                assert_eq!(marker.elapsed_secs, 213);
            }
            other => panic!("a dead daemon's commit is gone, not {other:?}"),
        }
        match classify_lost_reply(None, None, 1_030, |_| true) {
            LostReply::Gone {
                abandoned,
                daemon_alive,
            } => {
                assert!(abandoned.is_none(), "no marker means no evidence to carry");
                assert!(
                    !daemon_alive,
                    "with no marker there is no pid to have found alive"
                );
            }
            other => panic!("no receipt and no marker is gone, not {other:?}"),
        }
    }

    /// A daemon stand-in that answers a commit only after `delay`.
    ///
    /// A real 120-second wait is not what this needs to prove. The defect is a
    /// client deadline shorter than the daemon's work, and any two durations in
    /// that order reproduce it.
    async fn slow_commit_daemon(
        delay: std::time::Duration,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let serving = tokio::spawn(async move {
            while let Ok((mut socket, _)) = listener.accept().await {
                tokio::spawn(async move {
                    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
                    let mut request = [0u8; 4096];
                    let _ = socket.read(&mut request).await;
                    tokio::time::sleep(delay).await;
                    let body = serde_json::to_string(&serde_json::json!({
                        "change_id": "5b8ca7b7",
                        "branch": "refs/heads/main",
                        "entity_count": 32,
                        "relation_count": 4,
                        "file_count": 1,
                    }))
                    .unwrap();
                    let reply = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                         content-length: {}\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = socket.write_all(reply.as_bytes()).await;
                    let _ = socket.flush().await;
                });
            }
        });
        (url, serving)
    }

    /// The reported defect, in the only two durations it needs.
    ///
    /// The shipped client carried a fixed 120-second deadline and a one-file
    /// commit on a converted psf/requests store ran for 213 seconds, so the CLI
    /// reported `operation timed out` for a commit that landed. Both arms run
    /// against the same daemon: the deadlined client proves this daemon really
    /// is slower than a deadline, and the production client proves the reply
    /// still arrives. Falsify by giving `build_commit_client` back a fixed
    /// timeout shorter than the work; the second arm then fails the same way
    /// the first one is asserted to.
    #[tokio::test]
    async fn a_commit_slower_than_a_client_deadline_still_reports_its_change() {
        let work = std::time::Duration::from_millis(600);
        let deadline = std::time::Duration::from_millis(150);
        let (url, serving) = slow_commit_daemon(work).await;
        let endpoint = format!("{url}/commands/commit");

        let expired = build_commit_client(Some(deadline))
            .unwrap()
            .post(&endpoint)
            .json(&commit_body())
            .send()
            .await
            .expect_err("a deadline shorter than the daemon's work must expire");
        assert!(
            expired.is_timeout(),
            "the control must fail on the deadline, not on the transport: {expired}"
        );

        assert!(
            commit_reply_deadline().is_none(),
            "a commit must not carry a deadline the CLI cannot justify"
        );
        let response = build_commit_client(commit_reply_deadline())
            .unwrap()
            .post(&endpoint)
            .json(&commit_body())
            .send()
            .await
            .expect("a commit with no reply deadline waits for the daemon");
        let result: DaemonCommitResult = response.json().await.unwrap();
        assert_eq!(result.change_id, "5b8ca7b7");
        assert_eq!(render_commit_summary(&result, None).lines().count(), 2);

        serving.abort();
    }

    /// A reply that never arrived says nothing about whether the commit did.
    ///
    /// Authority is what records a commit, so a receipt for this operation means
    /// the commit succeeded and only its reply was lost. That holds even while
    /// the daemon publishes a marker, because a daemon that finished this commit
    /// and moved on to other work is still mid-transaction.
    #[test]
    fn a_lost_reply_whose_operation_reached_authority_is_a_successful_commit() {
        match classify_lost_reply(
            Some(landed_result()),
            Some(open_commit(1_000)),
            1_005,
            |_| true,
        ) {
            LostReply::Landed(result) => {
                assert_eq!(result.change_id, "5b8ca7b7");
                assert_eq!(result.entity_count, 32);
            }
            other => panic!("a receipt is a landed commit, not {other:?}"),
        }
    }

    /// A commit still running is reported as running, never as failed.
    ///
    /// The stranger read `operation timed out`, concluded the edit was
    /// uncommitted, and retried. Both halves of that were wrong, and the retry
    /// is what wrote the empty change.
    #[test]
    fn a_lost_reply_with_a_beating_daemon_is_still_running_rather_than_failed() {
        match classify_lost_reply(None, Some(open_commit(1_000)), 1_030, |_| true) {
            LostReply::StillRunning(open) => assert!(
                open.contains("commit in phase reconcile_workspace_and_commit_authority for 213s"),
                "the report must name the phase and its age: {open}"
            ),
            other => panic!("a beating daemon is still committing, not {other:?}"),
        }

        let quiet = 1_000 + kin_daemon_spawn::TRANSACTION_BEAT_STALE_AFTER.as_secs() + 5;
        assert!(
            matches!(
                classify_lost_reply(None, Some(open_commit(1_000)), quiet, |_| true),
                LostReply::Gone { .. }
            ),
            "a marker that stopped beating proves nothing is in flight"
        );
        // The shape the reported OOM kills took: the daemon died holding the
        // marker, and the kernel that killed it wrote no note, so the marker is
        // the only thing left and it is still beating from seconds ago.
        assert!(
            matches!(
                classify_lost_reply(None, Some(open_commit(1_000)), 1_030, |_| false),
                LostReply::Gone { .. }
            ),
            "a marker belonging to a dead daemon is a leftover, not work in flight"
        );
        assert!(
            matches!(
                classify_lost_reply(None, None, 1_030, |_| true),
                LostReply::Gone { .. }
            ),
            "no receipt and no marker is a commit that failed, and must still report failure"
        );
    }

    /// A refusal the daemon states in words reaches the caller as those words.
    #[test]
    fn a_blocked_projection_refusal_is_reported_as_its_own_sentence() {
        let body = serde_json::json!({
            "error": "projection_blocked",
            "message": "exact eject journal /r/.kin/reconciliation/exact-eject-journal.json is \
                        bound elsewhere; remove the file and rerun",
        })
        .to_string();
        let refusal = commit_refusal_message(&body).expect("a worded refusal");
        assert!(refusal.starts_with("exact eject journal /r/"), "{refusal}");
        assert!(!refusal.contains("HTTP"), "{refusal}");
    }

    #[test]
    fn a_nothing_to_commit_refusal_is_reported_as_its_own_sentence() {
        let body = serde_json::json!({
            "error": "nothing_to_commit",
            "change_id": "5b8ca7b7",
            "message": "nothing to commit: this tree is already committed as 5b8ca7b7",
        })
        .to_string();
        assert_eq!(
            commit_refusal_message(&body).as_deref(),
            Some("nothing to commit: this tree is already committed as 5b8ca7b7")
        );
        assert!(
            commit_refusal_message(&serde_json::json!({"error": "lease_conflict"}).to_string())
                .is_none(),
            "another refusal keeps the envelope its own reader parses"
        );
        assert!(commit_refusal_message("daemon is starting").is_none());
    }

    /// `kin commit` is not a git commit and nothing said so, while `git status`
    /// stayed dirty forever afterward.
    #[test]
    fn a_successful_commit_says_the_change_is_in_kin_authority_and_not_in_git() {
        let summary = render_commit_summary(
            &DaemonCommitResult {
                change_id: "9ade4452cd80".to_string(),
                branch: Some("refs/heads/main".to_string()),
                entity_count: 0,
                relation_count: 0,
                file_count: 1,
            },
            None,
        );
        assert!(
            summary.contains("Created semantic change 9ade4452cd80"),
            "{summary}"
        );
        assert!(summary.contains("not in git"), "{summary}");
        assert!(
            summary.contains("git status"),
            "the note must name the surface that keeps disagreeing: {summary}"
        );
        assert!(summary.contains("kin eject"), "{summary}");
    }

    /// The measured FIR-2776 commit, and the store that must stay quiet.
    ///
    /// A fully parseable new module landed as `(0 entities, 0 relations, 2
    /// artifacts)` because the counts are the change's own deltas and the sweep
    /// deriving its cross-file edges had not reached the file. The next `kin
    /// diff` then reported `Relations: +123` on a tree nobody had touched. Both
    /// numbers were right; neither surface said the word "yet".
    ///
    /// The caught-up arm is the load-bearing half. A line printed under every
    /// commit is a line a user stops reading by the third one, and then it is
    /// worth nothing on the commit that needed it.
    #[test]
    fn a_commit_taken_while_the_sweep_is_behind_says_so_and_a_caught_up_one_says_nothing() {
        let behind = pending_enrichment_line(true, 312, 480)
            .expect("a sweep with files left to walk is work this commit did not record");
        assert!(
            behind.contains("312 of 480 files"),
            "the reader needs the distance, not the fact: {behind}"
        );
        assert!(
            behind.contains("deltas"),
            "the sentence has to say why the counts above look empty: {behind}"
        );
        assert!(
            behind.contains("next commit"),
            "and when the missing edges arrive: {behind}"
        );
        assert!(
            behind.contains("exits"),
            "and what happens if the daemon goes first: {behind}"
        );

        assert!(
            pending_enrichment_line(false, 480, 480).is_none(),
            "a store whose sweep has walked everything it has is not behind, and a warning it \
             always prints is a warning nobody reads"
        );
    }

    /// The two shapes a single condition would have missed.
    ///
    /// Keying on `running` alone goes quiet over a sweep that was cut short and
    /// is not coming back, which is precisely a store with outstanding work and
    /// nothing in flight to finish it. Keying on the file counts alone goes
    /// quiet in the window between a sweep being queued and its first file
    /// landing, and a commit taken in that window is the one this exists for.
    #[test]
    fn a_sweep_that_stopped_early_is_still_behind_and_an_empty_walk_is_not() {
        assert!(
            pending_enrichment_line(false, 12, 480).is_some(),
            "nothing is running and 468 files are unwalked; that is outstanding work"
        );
        assert!(
            pending_enrichment_line(true, 0, 0).is_none(),
            "a queued sweep with nothing to walk owes nothing"
        );
        assert!(
            pending_enrichment_line(false, 0, 0).is_none(),
            "and neither does a store that has never had a file to walk"
        );
    }

    /// The line is appended, and nothing else about the summary moves.
    ///
    /// Two lines when the sweep has caught up, three when it has not, and the
    /// first two byte-identical either way. The note about `git status` is the
    /// one sentence this command exists to keep saying, and an enrichment line
    /// that displaced it would trade one confusion for another.
    #[test]
    fn the_pending_line_is_added_beneath_the_summary_and_replaces_none_of_it() {
        let result = DaemonCommitResult {
            change_id: "9ade4452cd80".to_string(),
            branch: Some("refs/heads/main".to_string()),
            entity_count: 0,
            relation_count: 0,
            file_count: 2,
        };
        let quiet = render_commit_summary(&result, None);
        let noisy = render_commit_summary(&result, Some("Cross-file enrichment is behind."));

        assert_eq!(quiet.lines().count(), 2, "{quiet}");
        assert_eq!(noisy.lines().count(), 3, "{noisy}");
        assert_eq!(
            quiet.lines().take(2).collect::<Vec<_>>(),
            noisy.lines().take(2).collect::<Vec<_>>(),
            "the summary and the git-status note are unchanged by the third line"
        );
        assert!(
            noisy.ends_with("Cross-file enrichment is behind."),
            "{noisy}"
        );
    }

    /// A landed commit is never held hostage by the probe that annotates it.
    ///
    /// The daemon client's own ceiling is 300 s, and `/lsp/sweep/status` is an
    /// atomics read that answers instantly on a daemon that is well. The daemon
    /// this line is about is a busy one, so the well case is not the one to
    /// size for: five minutes of silence after a write that already succeeded
    /// is worse than no line at all.
    ///
    /// Driven against a socket that accepts and then says nothing, which is the
    /// shape a wedged daemon presents, so the bound is proved by a hang rather
    /// than asserted about a constant.
    #[tokio::test]
    async fn a_probe_that_never_answers_gives_up_long_before_the_client_would() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let silent = tokio::spawn(async move {
            // Accept and hold. Never reply.
            let _held = listener.accept().await;
            tokio::time::sleep(std::time::Duration::from_secs(600)).await;
        });

        let client =
            crate::daemon_client::DaemonClient::from_base_url(format!("http://{addr}")).unwrap();
        let started = std::time::Instant::now();
        let answered = probe_sweep_status(&client).await;
        let waited = started.elapsed();

        assert!(
            answered.is_none(),
            "a socket that never replies must trip the bound, not return a reading"
        );
        assert!(
            waited < std::time::Duration::from_secs(30),
            "the probe waited {waited:?}; the client's own ceiling is 300s and this line is not \
             worth any of it"
        );
        silent.abort();
    }

    /// The announcement this command publishes before it does anything else,
    /// and the withdrawal every exit path shares.
    ///
    /// A daemon reads this while its first reconcile round is deciding whether
    /// to publish, and that round happens before this command can send anything,
    /// so the announcement has to be on disk rather than in a request. What the
    /// round needs from it is only that it exists while the commit is running
    /// and is gone afterwards.
    #[test]
    fn a_commit_announces_itself_for_exactly_as_long_as_it_runs() {
        let repo = tempfile::tempdir().unwrap();

        assert!(
            kin_daemon_spawn::read_approaching_commit(repo.path()).is_none(),
            "nothing is announced before the command starts"
        );

        {
            let _announced = CommitAnnouncement::announce(repo.path());
            let announced = kin_daemon_spawn::read_approaching_commit(repo.path())
                .expect("a running commit announces itself where a cold daemon can read it");
            assert_eq!(
                announced.pid,
                std::process::id(),
                "the announcement names the client that made it"
            );
            assert!(
                announced.is_fresh(unix_now()),
                "an announcement made now is readable now, or the daemon would ignore every \
                 one of them and the tick would never learn a commit was coming"
            );
        }

        assert!(
            kin_daemon_spawn::read_approaching_commit(repo.path()).is_none(),
            "a commit that has ended must withdraw its announcement, or the next ambient tick \
             stands down for a commit that is never coming"
        );
    }

    /// The withdrawal has to survive the ways a commit ends badly, not only the
    /// way it ends well.
    ///
    /// Attribution refusals, transport failures and panics all leave by
    /// unwinding rather than by reaching the end of `run`, and every one of them
    /// would otherwise leave an announcement behind for a commit that is never
    /// coming. The expiry bounds what that costs, but the guard is what makes it
    /// cost nothing.
    #[test]
    fn a_commit_that_fails_mid_run_still_withdraws_its_announcement() {
        let repo = tempfile::tempdir().unwrap();
        let root = repo.path().to_path_buf();

        let failed = std::panic::catch_unwind(move || {
            let _announced = CommitAnnouncement::announce(&root);
            assert!(
                kin_daemon_spawn::read_approaching_commit(&root).is_some(),
                "the announcement is published before the failure below, which is what makes \
                 the assertion after it mean anything"
            );
            panic!("a commit that fails after announcing itself");
        });

        assert!(
            failed.is_err(),
            "the control must actually fail, or this test proves nothing about failing"
        );
        assert!(
            kin_daemon_spawn::read_approaching_commit(repo.path()).is_none(),
            "unwinding through the guard withdraws the announcement, so a commit that died on \
             its way to the daemon does not hold the next ambient tick down"
        );
    }
}
