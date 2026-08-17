// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result};

use super::commit_progress::{daemon_death_explanation, PhaseTail, AUTHORITY_NOT_GIT_NOTE};

pub async fn run(message: String, quiet: bool) -> Result<()> {
    let layout = crate::commands::require_repository_layout()?;

    let result = run_daemon_commit(&layout, &message, quiet).await?;
    if !quiet {
        println!("{}", render_commit_summary(&result));
    }
    Ok(())
}

/// What a successful `kin commit` prints.
///
/// The second line is said every time, because the surprise is permanent: the
/// working tree this change came from stays dirty and `git log` never moves.
/// Without it a brownfield user commits all day and reads `git status` as proof
/// that nothing happened.
fn render_commit_summary(result: &DaemonCommitResult) -> String {
    format!(
        "Created semantic change {} on branch '{}' ({} entities, {} relations, {} artifacts)\n{}",
        result.change_id,
        result.branch,
        result.entity_count,
        result.relation_count,
        result.file_count,
        AUTHORITY_NOT_GIT_NOTE,
    )
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
    branch: String,
    entity_count: usize,
    relation_count: usize,
    file_count: usize,
}

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

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .connect_timeout(std::time::Duration::from_millis(500))
        .build()?;
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
    let response = stream_phases_while(quiet, &mut tail, request.send()).await;
    let response = match response {
        Ok(response) => response,
        Err(error) => {
            // A transport error names a socket. When the daemon was killed with
            // this request in flight, the socket is the symptom and the killer
            // left the cause in the repository.
            return match daemon_death_explanation(&kin_root) {
                Some(cause) => Err(anyhow::Error::new(error).context(cause)),
                None => Err(anyhow::Error::new(error))
                    .context("send daemon-owned native commit request"),
            };
        }
    };
    if !response.status().is_success() {
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        anyhow::bail!("daemon native commit failed (HTTP {status}): {body}");
    }
    response
        .json()
        .await
        .context("decode daemon native commit response")
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

    /// `kin commit` is not a git commit and nothing said so, while `git status`
    /// stayed dirty forever afterward.
    #[test]
    fn a_successful_commit_says_the_change_is_in_kin_authority_and_not_in_git() {
        let summary = render_commit_summary(&DaemonCommitResult {
            change_id: "9ade4452cd80".to_string(),
            branch: "refs/heads/main".to_string(),
            entity_count: 0,
            relation_count: 0,
            file_count: 1,
        });
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
}
