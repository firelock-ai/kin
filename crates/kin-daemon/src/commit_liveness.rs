// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Proof that a daemon is mid-transaction, published where a killer can read it.
//!
//! The supervisor's rogue-daemon reaper decides whether a daemon is doing real
//! work by asking `/health` and reading `active_request_count` off the answer.
//! That question can only be answered by a daemon with a free runtime worker,
//! and the commit path is synchronous work on a runtime worker holding the
//! coordination gate, so the one daemon state the guard exists to protect is
//! the one state in which the guard cannot fire. Its fallback signal is growth
//! in `.kin/daemon.log`, and commit phases are timed by closures that log only
//! once the closure returns, so a single 86-second phase writes nothing for its
//! whole duration and reads as 86 seconds of no progress.
//!
//! Both halves failed together on a converted psf/requests store: a one-file
//! docstring commit was SIGKILLed 172 seconds in, leaving no shutdown line, no
//! panic, a stale endpoint record and an unexplained end to the log.
//!
//! This module publishes the missing fact on a path that does not depend on the
//! runtime being schedulable at all. A dedicated OS thread rewrites
//! `.kin/daemon.transaction` on a fixed beat while a transaction is open and
//! names the running phase in the log as it goes, so a reader gets a positive
//! statement — this pid, this operation, this phase, beating as of this second
//! — instead of inferring wedged-ness from silence.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// File a daemon publishes its open transaction into, beside the endpoint
/// record it already publishes.
pub const TRANSACTION_FILE_NAME: &str = "daemon.transaction";

/// How often the beat thread republishes the marker and names the running phase.
///
/// The reaper sweeps every 15s and needs four consecutive sweeps with no log
/// growth, so a 5s beat puts at least two lines in the log per sweep and the
/// stall streak can never accumulate while a transaction is open.
const BEAT_INTERVAL: Duration = Duration::from_secs(5);

/// How long a published beat stays trustworthy.
///
/// Twelve missed beats. A daemon whose OS thread has not been scheduled for a
/// minute is wedged in a way this marker should not shield, and the reap that
/// follows says so explicitly rather than treating the marker as absent.
pub const BEAT_STALE_AFTER: Duration = Duration::from_secs(60);

/// What one daemon publishes about the transaction it currently has open.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct OpenTransaction {
    /// The daemon that owns this transaction. A marker naming a different pid
    /// than the daemon being judged is a leftover and shields nobody.
    pub pid: u32,
    /// Which write path is open, e.g. `commit`.
    pub operation: String,
    /// Phase currently running, when one has been entered.
    pub phase: Option<String>,
    /// Wall seconds since the transaction opened.
    pub elapsed_secs: u64,
    /// Wall seconds since the running phase was entered.
    pub phase_elapsed_secs: u64,
    /// Unix seconds at the last beat. Freshness is decided against this.
    pub beat_unix: u64,
}

/// How a reader should treat a daemon's transaction marker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransactionLiveness {
    /// No marker, or one belonging to a different pid.
    None,
    /// A marker this daemon published, beating within [`BEAT_STALE_AFTER`].
    Open(Box<OpenTransactionSummary>),
    /// A marker this daemon published whose beat has gone quiet. The daemon is
    /// wedged rather than merely busy, and anything that ends it must say so.
    Stale(Box<OpenTransactionSummary>),
}

/// The part of an open transaction a reader reports back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenTransactionSummary {
    pub operation: String,
    pub phase: String,
    pub elapsed_secs: u64,
    pub beat_age_secs: u64,
}

impl std::fmt::Display for OpenTransactionSummary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} in phase {} for {}s (last beat {}s ago)",
            self.operation, self.phase, self.elapsed_secs, self.beat_age_secs
        )
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_secs())
        .unwrap_or(0)
}

/// Path of the marker for a repository working directory.
pub fn transaction_path(repo_root: &Path) -> PathBuf {
    repo_root.join(".kin").join(TRANSACTION_FILE_NAME)
}

/// Classify what `repo_root`'s marker says about the daemon running as `pid`.
///
/// Deliberately one-directional in the same sense the endpoint-ownership read
/// is: `Open` is positive proof of work in flight, and every other outcome — no
/// file, an unreadable file, a marker naming another pid — is merely the absence
/// of proof. Callers use it to withhold a kill, never to authorize one.
pub fn transaction_liveness(repo_root: &Path, pid: u32) -> TransactionLiveness {
    let Ok(raw) = std::fs::read_to_string(transaction_path(repo_root)) else {
        return TransactionLiveness::None;
    };
    let Ok(open) = serde_json::from_str::<OpenTransaction>(&raw) else {
        return TransactionLiveness::None;
    };
    if open.pid != pid {
        return TransactionLiveness::None;
    }
    let beat_age_secs = unix_now().saturating_sub(open.beat_unix);
    let summary = Box::new(OpenTransactionSummary {
        operation: open.operation,
        phase: open.phase.unwrap_or_else(|| "starting".to_string()),
        elapsed_secs: open.elapsed_secs,
        beat_age_secs,
    });
    if beat_age_secs > BEAT_STALE_AFTER.as_secs() {
        TransactionLiveness::Stale(summary)
    } else {
        TransactionLiveness::Open(summary)
    }
}

/// The transaction this process currently has open, shared with the beat thread.
struct ActiveTransaction {
    kin_root: PathBuf,
    operation: &'static str,
    opened: std::time::Instant,
    phase: Option<&'static str>,
    phase_entered: std::time::Instant,
}

impl ActiveTransaction {
    fn record(&self) -> OpenTransaction {
        OpenTransaction {
            pid: std::process::id(),
            operation: self.operation.to_string(),
            phase: self.phase.map(str::to_string),
            elapsed_secs: self.opened.elapsed().as_secs(),
            phase_elapsed_secs: self.phase_entered.elapsed().as_secs(),
            beat_unix: unix_now(),
        }
    }
}

fn active() -> &'static Mutex<Option<ActiveTransaction>> {
    static ACTIVE: OnceLock<Mutex<Option<ActiveTransaction>>> = OnceLock::new();
    ACTIVE.get_or_init(|| Mutex::new(None))
}

/// Publish the marker for whatever is currently open. A no-op when nothing is.
fn publish_beat() {
    let Ok(guard) = active().lock() else {
        return;
    };
    let Some(transaction) = guard.as_ref() else {
        return;
    };
    let record = transaction.record();
    let kin_root = transaction.kin_root.clone();
    let phase = transaction.phase;
    let phase_elapsed_ms = transaction.phase_entered.elapsed().as_millis();
    drop(guard);

    write_marker(&kin_root, &record);
    // The reaper's other signal is byte growth in this repo's `daemon.log`, and
    // this line is what makes a long phase grow it. It carries the same `phase`
    // and `elapsed_ms` fields the completion lines carry, so one parser reads
    // the phase table whether a phase has finished or is still running.
    if let Some(phase) = phase {
        tracing::info!(
            phase,
            elapsed_ms = phase_elapsed_ms,
            "commit phase in progress"
        );
    }
}

fn write_marker(kin_root: &Path, record: &OpenTransaction) {
    let Ok(body) = serde_json::to_string(record) else {
        return;
    };
    let path = kin_root.join(TRANSACTION_FILE_NAME);
    let tmp = kin_root.join(format!("{TRANSACTION_FILE_NAME}.tmp"));
    if std::fs::write(&tmp, body).is_ok() && std::fs::rename(&tmp, &path).is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
}

/// Start the beat thread once per process.
///
/// A plain OS thread, never a task: the whole point is to keep publishing while
/// the runtime has no worker free to poll anything, which is the exact state
/// that made the daemon look dead.
fn ensure_beat_thread() {
    static STARTED: OnceLock<()> = OnceLock::new();
    STARTED.get_or_init(|| {
        let _ = std::thread::Builder::new()
            .name("kin-transaction-beat".to_string())
            .spawn(|| loop {
                std::thread::sleep(BEAT_INTERVAL);
                publish_beat();
            });
    });
}

/// An open transaction, published for as long as this value lives.
///
/// Dropping it retires the marker. A daemon killed mid-transaction never drops
/// it, which is the intended asymmetry: the leftover marker is what tells the
/// next reader the daemon died with work in flight.
pub struct TransactionGuard {
    kin_root: PathBuf,
}

impl TransactionGuard {
    /// Open a transaction marker for `kin_root` (the `.kin` directory).
    pub fn open(kin_root: &Path, operation: &'static str) -> Self {
        let now = std::time::Instant::now();
        if let Ok(mut guard) = active().lock() {
            *guard = Some(ActiveTransaction {
                kin_root: kin_root.to_path_buf(),
                operation,
                opened: now,
                phase: None,
                phase_entered: now,
            });
        }
        ensure_beat_thread();
        publish_beat();
        Self {
            kin_root: kin_root.to_path_buf(),
        }
    }
}

impl Drop for TransactionGuard {
    fn drop(&mut self) {
        if let Ok(mut guard) = active().lock() {
            *guard = None;
        }
        let _ = std::fs::remove_file(self.kin_root.join(TRANSACTION_FILE_NAME));
    }
}

/// Name the phase the open transaction has just entered.
///
/// Called by the commit phase timers, which already know the name. Nothing
/// happens when no transaction is open, so the timers stay usable from paths
/// that do not publish a marker.
pub fn enter_phase(phase: &'static str) {
    let Ok(mut guard) = active().lock() else {
        return;
    };
    if let Some(transaction) = guard.as_mut() {
        transaction.phase = Some(phase);
        transaction.phase_entered = std::time::Instant::now();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn repo_with_kin(dir: &Path) -> PathBuf {
        let kin_root = dir.join(".kin");
        std::fs::create_dir_all(&kin_root).unwrap();
        kin_root
    }

    #[test]
    fn an_open_transaction_reads_as_open_for_its_own_pid_and_absent_for_another() {
        let dir = tempfile::tempdir().unwrap();
        let kin_root = repo_with_kin(dir.path());
        let guard = TransactionGuard::open(&kin_root, "commit");
        enter_phase("plan_transaction");
        publish_beat();

        let pid = std::process::id();
        match transaction_liveness(dir.path(), pid) {
            TransactionLiveness::Open(summary) => {
                assert_eq!(summary.operation, "commit");
                assert_eq!(summary.phase, "plan_transaction");
            }
            other => panic!("expected an open transaction, got {other:?}"),
        }
        // A marker naming a different daemon must shield nobody: it is the
        // leftover of a process that already died, and treating it as live is
        // how a marker turns into a permanent immunity.
        assert_eq!(
            transaction_liveness(dir.path(), pid.wrapping_add(1)),
            TransactionLiveness::None
        );

        drop(guard);
        assert_eq!(
            transaction_liveness(dir.path(), pid),
            TransactionLiveness::None,
            "a closed transaction must retire its marker"
        );
    }

    #[test]
    fn a_beat_older_than_the_stale_bound_reads_as_stale_rather_than_open() {
        let dir = tempfile::tempdir().unwrap();
        let kin_root = repo_with_kin(dir.path());
        let pid = std::process::id();
        let record = OpenTransaction {
            pid,
            operation: "commit".to_string(),
            phase: Some("git_projection_replay".to_string()),
            elapsed_secs: 400,
            phase_elapsed_secs: 300,
            beat_unix: unix_now().saturating_sub(BEAT_STALE_AFTER.as_secs() + 5),
        };
        write_marker(&kin_root, &record);

        match transaction_liveness(dir.path(), pid) {
            TransactionLiveness::Stale(summary) => {
                assert_eq!(summary.phase, "git_projection_replay");
                assert!(summary.beat_age_secs > BEAT_STALE_AFTER.as_secs());
            }
            other => panic!("expected a stale transaction, got {other:?}"),
        }
    }

    #[test]
    fn an_unreadable_or_absent_marker_never_reads_as_open() {
        let dir = tempfile::tempdir().unwrap();
        let kin_root = repo_with_kin(dir.path());
        let pid = std::process::id();
        assert_eq!(
            transaction_liveness(dir.path(), pid),
            TransactionLiveness::None
        );
        std::fs::write(kin_root.join(TRANSACTION_FILE_NAME), b"not json at all").unwrap();
        assert_eq!(
            transaction_liveness(dir.path(), pid),
            TransactionLiveness::None
        );
    }
}
