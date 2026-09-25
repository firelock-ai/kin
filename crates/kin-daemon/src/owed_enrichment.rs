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
}

/// Every owed file, by repository path.
pub(crate) type OwedFiles = BTreeMap<String, OwedFile>;

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

/// Record one more failed attempt for `file` at `blob`.
///
/// Attempts count consecutive failures over the same bytes. A failure over new
/// bytes starts again at one.
pub(crate) fn record_failure(
    owed: &mut OwedFiles,
    file: &str,
    blob: &str,
    reason: String,
    now_unix_s: u64,
) {
    let attempts = match owed.get(file) {
        Some(previous) if previous.blob == blob => previous.attempts.saturating_add(1),
        _ => 1,
    };
    owed.insert(
        file.to_string(),
        OwedFile {
            blob: blob.to_string(),
            attempts,
            last_attempt_unix_s: now_unix_s,
            reason,
        },
    );
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
    fn the_wait_doubles_per_failure_up_to_a_ceiling() {
        assert_eq!(retry_interval(1), Duration::from_secs(300));
        assert_eq!(retry_interval(2), Duration::from_secs(600));
        assert_eq!(retry_interval(3), Duration::from_secs(1200));
        assert_eq!(retry_interval(40), LONGEST_RETRY);
    }

    #[test]
    fn a_failure_waits_its_backoff_unless_the_bytes_change() {
        let mut owed = OwedFiles::new();
        record_failure(&mut owed, "pkg/a.go", "blob-1", "timed out".into(), 1_000);
        let entry = &owed["pkg/a.go"];
        assert_eq!(entry.attempts, 1);
        assert_eq!(
            retry_after(entry, "blob-1", 1_000),
            Some(Duration::from_secs(300))
        );
        assert_eq!(retry_after(entry, "blob-1", 1_300), None);
        assert_eq!(retry_after(entry, "blob-2", 1_000), None);

        record_failure(&mut owed, "pkg/a.go", "blob-1", "timed out".into(), 1_300);
        assert_eq!(owed["pkg/a.go"].attempts, 2);
        record_failure(&mut owed, "pkg/a.go", "blob-2", "timed out".into(), 1_400);
        assert_eq!(owed["pkg/a.go"].attempts, 1, "new bytes start again");
    }

    #[test]
    fn the_record_round_trips_and_an_empty_one_is_removed() {
        let root = tempfile::tempdir().unwrap();
        let layout = kin_core::init(root.path()).unwrap().layout;
        assert!(load(&layout).is_empty());
        let mut owed = OwedFiles::new();
        record_failure(&mut owed, "pkg/a.go", "blob-1", "timed out".into(), 7);
        persist(&layout, &owed);
        assert_eq!(load(&layout), owed);
        persist(&layout, &OwedFiles::new());
        assert!(!path(&layout).exists());
    }
}
