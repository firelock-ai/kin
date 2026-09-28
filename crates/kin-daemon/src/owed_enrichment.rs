// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Files a language-server sweep still owes, and when it may ask again.
//!
//! A file whose queries failed is not marked enriched, so the next sweep asks
//! again. That is right once and wrong forever. A file its server cannot answer
//! for was asked again by every sweep, and when one failure class caught every
//! file, which is what gopls's declined answers did to every Go file, every
//! daemon start swept the whole repository again. This record spaces the
//! retries out and names what is owed, so a status reader can see exactly which
//! files have no durable enrichment and why.
//!
//! An entry is keyed by the file's path and by the blob its bytes had when the
//! query failed. New bytes are a new question, so an entry whose blob no longer
//! matches does not delay anything and the file is asked about at once.
//!
//! Operational state beside the completion marker, not semantic authority:
//! nothing answers a query from it. An absent or unreadable record means
//! nothing is owed, which costs at most one retry sooner than the backoff would
//! have allowed.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use kin_core::KinLayout;
use tracing::warn;

/// What the sweep knows about one file it owes.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub(crate) struct OwedFile {
    /// The blob the file's bytes had at its last failed attempt.
    pub(crate) blob: String,
    /// Consecutive failed attempts over those bytes.
    pub(crate) attempts: u32,
    /// When the last attempt ended, in whole seconds since the Unix epoch.
    pub(crate) last_attempt_unix_s: u64,
    /// What failed, in the words the sweep logged.
    pub(crate) reason: String,
    /// The proof context the server answered under at those attempts, as
    /// its record id, when the sweep knew it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) context: Option<String>,
}

/// Every owed file, by repository path.
pub(crate) type OwedFiles = BTreeMap<String, OwedFile>;

/// The largest aggregate uses-type allowance, including later sweeps.
pub(crate) const USES_TYPE_MAX_BUDGET: Duration = Duration::from_secs(45);

/// Uses-type walks an entity's identifiers with multiple sequential RPCs.
/// A retry needs more time than the aggregate limit it already exhausted, but
/// never an unbounded pass. Only debt over these bytes and this resolver counts;
/// changing either starts a new question at the initial budget. The in-sweep
/// retries advance too, before their failure has reached the durable record.
pub(crate) fn uses_type_budget(
    owed: &OwedFiles,
    file: &str,
    blob: Option<&str>,
    context: &str,
    in_sweep_retries: u32,
) -> Duration {
    let failures = owed
        .get(file)
        .filter(|previous| {
            Some(previous.blob.as_str()) == blob && previous.context.as_deref() == Some(context)
        })
        .map_or(0, |previous| previous.attempts);
    match failures.saturating_add(in_sweep_retries) {
        0 => Duration::from_secs(5),
        1 => Duration::from_secs(15),
        _ => USES_TYPE_MAX_BUDGET,
    }
}

/// The first retry waits this long, and every failure after it doubles the wait.
const FIRST_RETRY: Duration = Duration::from_secs(5 * 60);

/// The longest a file waits between attempts.
const LONGEST_RETRY: Duration = Duration::from_secs(6 * 60 * 60);

/// How long a file waits after its `attempts`-th consecutive failure.
pub(crate) fn retry_interval(attempts: u32) -> Duration {
    let doublings = attempts.saturating_sub(1).min(16);
    FIRST_RETRY
        .saturating_mul(1u32 << doublings)
        .min(LONGEST_RETRY)
}

/// How long until the file may be asked about again, or `None` when now.
///
/// `blob` is the file's current blob. Bytes that changed since the failure
/// are asked about at once.
pub(crate) fn retry_after(owed: &OwedFile, blob: &str, now_unix_s: u64) -> Option<Duration> {
    if owed.blob != blob {
        return None;
    }
    let due = owed
        .last_attempt_unix_s
        .saturating_add(retry_interval(owed.attempts).as_secs());
    (due > now_unix_s).then(|| Duration::from_secs(due - now_unix_s))
}

/// When the idle worker should queue a pass for persisted debt. An expired
/// backoff is ready now; an empty record leaves the worker asleep until a
/// request or shutdown arrives.
pub(crate) fn next_retry_delay(owed: &OwedFiles, now_unix_s: u64) -> Option<Duration> {
    owed.values()
        .map(|file| {
            let due = file
                .last_attempt_unix_s
                .saturating_add(retry_interval(file.attempts).as_secs());
            Duration::from_secs(due.saturating_sub(now_unix_s))
        })
        .min()
}

/// Back off debt that was already due when a pass began but never reached a
/// query. No proof context answered this attempt, and no completion is earned.
/// Files whose deadline elapsed during the pass remain due for the next pass.
pub(crate) fn defer_unattempted(
    owed: &mut OwedFiles,
    due_before_unix_s: u64,
    reason: &str,
    now_unix_s: u64,
) {
    let due: Vec<_> = owed
        .iter()
        .filter(|(_, entry)| retry_after(entry, &entry.blob, due_before_unix_s).is_none())
        .map(|(file, entry)| (file.clone(), entry.blob.clone()))
        .collect();
    for (file, blob) in due {
        record_failure(owed, &file, &blob, None, reason.to_owned(), now_unix_s);
    }
}

/// How many consecutive failed attempts over the same bytes, under the same
/// proof context, a file gets before the sweep settles it with the sites its
/// server failed at, rather than owing it forever.
pub(crate) const SETTLE_AFTER_ATTEMPTS: u32 = 3;

/// Record one more failed attempt for `file` at `blob`, under the proof
/// context `context` names.
///
/// Attempts count consecutive failures over the same bytes and the same
/// context. A failure over new bytes, or under another context, starts again
/// at one.
pub(crate) fn record_failure(
    owed: &mut OwedFiles,
    file: &str,
    blob: &str,
    context: Option<&str>,
    reason: String,
    now_unix_s: u64,
) {
    let attempts = match owed.get(file) {
        Some(previous) if previous.blob == blob && previous.context.as_deref() == context => {
            previous.attempts.saturating_add(1)
        }
        _ => 1,
    };
    owed.insert(
        file.to_string(),
        OwedFile {
            blob: blob.to_string(),
            attempts,
            last_attempt_unix_s: now_unix_s,
            reason,
            context: context.map(str::to_string),
        },
    );
}

/// Whether the attempt a sweep is making now at `file`, over `blob` under
/// `context`, is its last allowed one: the record already holds
/// [`SETTLE_AFTER_ATTEMPTS`] less one failures over the same bytes and
/// context.
pub(crate) fn attempts_exhausted(
    owed: &OwedFiles,
    file: &str,
    blob: Option<&str>,
    context: &str,
) -> bool {
    let (Some(previous), Some(blob)) = (owed.get(file), blob) else {
        return false;
    };
    previous.blob == blob
        && previous.context.as_deref() == Some(context)
        && previous.attempts.saturating_add(1) >= SETTLE_AFTER_ATTEMPTS
}

/// Seconds since the Unix epoch, which is what the record stores.
pub(crate) fn now_unix_s() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

fn path(layout: &KinLayout) -> PathBuf {
    layout.root().join("lsp-owed-files.json")
}

/// The owed files a previous daemon recorded for this store.
pub(crate) fn load(layout: &KinLayout) -> OwedFiles {
    let Ok(bytes) = std::fs::read(path(layout)) else {
        return OwedFiles::new();
    };
    serde_json::from_slice(&bytes).unwrap_or_default()
}

/// Replace the record with `owed`, through a staged file and a rename, and
/// remove it when nothing is owed.
pub(crate) fn persist(layout: &KinLayout, owed: &OwedFiles) {
    let target = path(layout);
    if owed.is_empty() {
        match std::fs::remove_file(&target) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                warn!(%error, "could not clear the owed language-server enrichment record")
            }
        }
        return;
    }
    let bytes = match serde_json::to_vec(owed) {
        Ok(bytes) => bytes,
        Err(error) => {
            warn!(%error, "could not encode the owed language-server enrichment record");
            return;
        }
    };
    // Staged, synced, renamed and the directory synced, the same way the
    // daemon's other records are replaced, so a crash leaves the old record or
    // the new one and the rename survives a power loss.
    let staged = target.with_extension(format!("json.staged-{}", std::process::id()));
    let replaced = std::fs::File::create(&staged)
        .and_then(|mut file| {
            use std::io::Write as _;
            file.write_all(&bytes)?;
            file.sync_all()
        })
        .and_then(|()| std::fs::rename(&staged, &target))
        .and_then(|()| match target.parent() {
            Some(parent) => crate::state::sync_directory_metadata(parent),
            None => Ok(()),
        });
    if let Err(error) = replaced {
        let _ = std::fs::remove_file(&staged);
        warn!(%error, "could not write the owed language-server enrichment record");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uses_type_retries_escalate_only_for_the_same_inputs_and_stay_bounded() {
        let mut owed = OwedFiles::new();
        let budget = |owed: &OwedFiles, blob, context, retry| {
            uses_type_budget(owed, "large.py", blob, context, retry).as_secs()
        };
        assert_eq!(budget(&owed, Some("a"), "context", 0), 5);
        assert_eq!(budget(&owed, Some("a"), "context", 1), 15);
        assert_eq!(budget(&owed, Some("a"), "context", 2), 45);
        record_failure(
            &mut owed,
            "large.py",
            "a",
            Some("context"),
            "timeout".into(),
            1,
        );
        assert_eq!(budget(&owed, Some("a"), "context", 0), 15);
        assert_eq!(budget(&owed, Some("a"), "context", 1), 45);
        assert_eq!(budget(&owed, Some("b"), "context", 0), 5);
        assert_eq!(budget(&owed, None, "context", 0), 5);
        assert_eq!(budget(&owed, Some("a"), "new context", 0), 5);
        owed.get_mut("large.py").unwrap().attempts = u32::MAX;
        assert_eq!(budget(&owed, Some("a"), "context", 1), 45);
    }

    #[test]
    fn the_wait_doubles_per_failure_up_to_a_ceiling() {
        assert_eq!(retry_interval(1), Duration::from_secs(300));
        assert_eq!(retry_interval(2), Duration::from_secs(600));
        assert_eq!(retry_interval(3), Duration::from_secs(1200));
        assert_eq!(retry_interval(40), LONGEST_RETRY);
    }

    #[test]
    fn idle_retry_uses_the_earliest_persisted_deadline_and_stops_when_empty() {
        let mut owed = OwedFiles::new();
        assert_eq!(next_retry_delay(&owed, 1_000), None);
        record_failure(&mut owed, "a.ts", "a", None, "timeout".into(), 1_000);
        record_failure(&mut owed, "b.ts", "b", None, "timeout".into(), 1_100);
        assert_eq!(
            next_retry_delay(&owed, 1_050),
            Some(Duration::from_secs(250))
        );
        assert_eq!(next_retry_delay(&owed, 1_300), Some(Duration::ZERO));
        owed.remove("a.ts");
        assert_eq!(
            next_retry_delay(&owed, 1_300),
            Some(Duration::from_secs(100))
        );
        owed.clear();
        assert_eq!(next_retry_delay(&owed, 2_000), None);
    }

    #[test]
    fn a_failure_waits_its_backoff_unless_the_bytes_change() {
        let mut owed = OwedFiles::new();
        record_failure(
            &mut owed,
            "pkg/a.go",
            "blob-1",
            None,
            "timed out".into(),
            1_000,
        );
        let entry = &owed["pkg/a.go"];
        assert_eq!(entry.attempts, 1);
        assert_eq!(
            retry_after(entry, "blob-1", 1_000),
            Some(Duration::from_secs(300))
        );
        assert_eq!(retry_after(entry, "blob-1", 1_300), None);
        assert_eq!(retry_after(entry, "blob-2", 1_000), None);

        record_failure(
            &mut owed,
            "pkg/a.go",
            "blob-1",
            None,
            "timed out".into(),
            1_300,
        );
        assert_eq!(owed["pkg/a.go"].attempts, 2);
        record_failure(
            &mut owed,
            "pkg/a.go",
            "blob-2",
            None,
            "timed out".into(),
            1_400,
        );
        assert_eq!(owed["pkg/a.go"].attempts, 1, "new bytes start again");
    }

    #[test]
    fn blocked_passes_defer_due_debt_without_postponing_future_deadlines() {
        let mut owed = OwedFiles::new();
        record_failure(
            &mut owed,
            "due.py",
            "old",
            Some("previous-server"),
            "timeout".into(),
            1_000,
        );
        record_failure(
            &mut owed,
            "later.py",
            "later",
            None,
            "timeout".into(),
            1_200,
        );
        let later = owed["later.py"].clone();
        defer_unattempted(&mut owed, 1_300, "source authority unavailable", 1_600);
        assert_eq!(owed["due.py"].last_attempt_unix_s, 1_600);
        assert_eq!(
            owed["due.py"].context, None,
            "no server answered this attempt"
        );
        assert_eq!(owed["due.py"].reason, "source authority unavailable");
        assert_eq!(
            retry_after(&owed["due.py"], "old", 1_600),
            Some(Duration::from_secs(300))
        );
        assert!(!attempts_exhausted(
            &owed,
            "due.py",
            Some("old"),
            "previous-server"
        ));
        assert_eq!(
            owed["later.py"], later,
            "a deadline reached during the pass must be eligible for the next pass"
        );
        owed.remove("later.py");
        defer_unattempted(&mut owed, 1_900, "source authority unavailable", 1_900);
        assert_eq!(owed["due.py"].attempts, 2);
        assert_eq!(
            next_retry_delay(&owed, 1_900),
            Some(Duration::from_secs(600))
        );
    }

    #[test]
    fn a_file_is_settled_after_its_last_attempt_under_one_context() {
        let mut owed = OwedFiles::new();
        assert!(!attempts_exhausted(
            &owed,
            "pkg/a.go",
            Some("blob-1"),
            "ctx-1"
        ));
        for at in 0..SETTLE_AFTER_ATTEMPTS - 1 {
            assert!(
                !attempts_exhausted(&owed, "pkg/a.go", Some("blob-1"), "ctx-1"),
                "attempt {at} is not the last"
            );
            record_failure(
                &mut owed,
                "pkg/a.go",
                "blob-1",
                Some("ctx-1"),
                "timed out".into(),
                u64::from(at),
            );
        }
        assert!(
            attempts_exhausted(&owed, "pkg/a.go", Some("blob-1"), "ctx-1"),
            "the attempt after the ones recorded is the last"
        );
        assert!(
            !attempts_exhausted(&owed, "pkg/a.go", Some("blob-1"), "ctx-2"),
            "another context starts again"
        );
        assert!(
            !attempts_exhausted(&owed, "pkg/a.go", Some("blob-2"), "ctx-1"),
            "so do new bytes"
        );
        record_failure(
            &mut owed,
            "pkg/a.go",
            "blob-1",
            Some("ctx-2"),
            "timed out".into(),
            9,
        );
        assert_eq!(
            owed["pkg/a.go"].attempts, 1,
            "a new context counts from one"
        );
    }

    #[test]
    fn the_record_round_trips_and_an_empty_one_is_removed() {
        let root = tempfile::tempdir().unwrap();
        let layout = kin_core::init(root.path()).unwrap().layout;
        assert!(load(&layout).is_empty());
        let mut owed = OwedFiles::new();
        record_failure(
            &mut owed,
            "pkg/a.go",
            "blob-1",
            Some("ctx"),
            "timed out".into(),
            7,
        );
        persist(&layout, &owed);
        assert_eq!(load(&layout), owed);
        persist(&layout, &OwedFiles::new());
        assert!(!path(&layout).exists());
    }
}
