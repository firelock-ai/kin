// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! What an interrupted `kin init` leaves behind so the next command can speak
//! for it.
//!
//! A conversion of a mature repository runs for minutes and holds most of a
//! history in memory while it does. When the kernel kills it for exceeding a
//! memory cap the process gets `SIGKILL`, which runs no destructor, prints no
//! message and returns no error: the shell sees exit 137 and nothing else. The
//! rc0550 stranger met exactly that. Kin said nothing, `.kin` did not exist,
//! and 420 MB of staging sat beside the repository with nothing pointing at it.
//!
//! Nothing inside the dying process can fix that, because there is no code
//! running in it any more. What can fix it is a record written BEFORE the kill,
//! read by whatever runs next. That is this module: the ladder stamps its
//! current phase into the capture staging directory as each phase opens, and
//! [`abandoned_init_attempts`] reads back every record no live init still owns.
//!
//! Two properties make the record trustworthy rather than merely present.
//!
//! It lives inside the capture staging directory, so it can never outlive the
//! staging it describes, and it inherits that directory's lease: a record whose
//! lease can be taken exclusively belongs to a process that is gone, and one
//! whose lease is contended belongs to an init running right now. That is a
//! measurement of liveness rather than a guess from a pid, which is what keeps
//! a concurrent sibling conversion from being reported as a corpse.
//!
//! And it is never fsynced. A `SIGKILL` leaves the page cache intact, so the
//! bytes reach the next reader without one, and a conversion already fighting
//! for memory should not pay seventeen barriers for a file that only has to
//! survive its own process.

use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::error::{KinError, Result};
use crate::memory_pressure::{self, MemoryReading};

/// Name of the record inside a capture staging directory.
pub const ATTEMPT_RECORD_NAME: &str = "init-attempt.json";

/// Largest record this module will read back.
///
/// The writer produces a few hundred bytes. A file larger than this is not a
/// record Kin wrote, and reading it into memory to find that out is how a
/// post-mortem path becomes its own denial of service.
const MAX_RECORD_BYTES: u64 = 64 * 1024;

/// Current record layout. A reader that meets a version it does not know
/// reports the attempt without its phase detail rather than guessing at fields.
pub const ATTEMPT_RECORD_VERSION: u32 = 1;

/// What one `kin init` had reached when it was last able to say.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InitAttemptRecord {
    /// Layout of this record.
    pub version: u32,
    /// Repository root being converted.
    pub source: String,
    /// Where the conversion intended to publish `.kin`.
    pub destination: String,
    /// The process that wrote it. Disclosure only: liveness is decided by the
    /// staging lease, because a pid is reused and a lease is not.
    pub pid: u32,
    /// When the attempt started, seconds since the Unix epoch.
    pub started_unix: u64,
    /// Phase last entered, one-based. Zero means no phase had opened yet.
    pub phase_index: usize,
    /// Phases in the ladder this attempt was running.
    pub phase_total: usize,
    /// Human label of that phase, exactly as the progress ladder printed it.
    pub phase_label: String,
    /// When that phase opened, seconds since the Unix epoch.
    pub phase_started_unix: u64,
    /// The memory ceiling measured when the attempt started, and what published
    /// it. `None` when this process could not read one.
    pub memory_limit_bytes: Option<u64>,
    /// `container` or `machine`, from the same reading.
    pub memory_source: Option<String>,
    /// The repository stage directory, once the ladder has created one. Absent
    /// before the staging phase, which is why a kill early in the ladder leaves
    /// only the capture directory behind.
    pub stage_path: Option<String>,
}

impl InitAttemptRecord {
    /// Seconds this attempt had been running when its phase opened.
    ///
    /// Reported rather than "how long it ran", because the record cannot know
    /// when the kill landed. The distance from the start to the last phase it
    /// managed to write is a fact; anything past that is inference.
    pub fn seconds_to_last_phase(&self) -> u64 {
        self.phase_started_unix.saturating_sub(self.started_unix)
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|since| since.as_secs())
        .unwrap_or(0)
}

// --------------------------------------------------------------------- writer

/// The live attempt's record, rewritten as each phase opens.
///
/// Every write is best effort. A conversion must never fail because its own
/// post-mortem could not be written, so the errors are counted for the tests
/// and otherwise dropped.
#[derive(Debug)]
pub(crate) struct InitAttemptJournal {
    path: PathBuf,
    state: Mutex<JournalState>,
}

#[derive(Debug)]
struct JournalState {
    record: InitAttemptRecord,
    write_failures: usize,
}

impl InitAttemptJournal {
    /// Start a record for a conversion of `source` staging inside `capture_dir`.
    pub(crate) fn open(
        capture_dir: &Path,
        source: &Path,
        destination: &Path,
        phase_total: usize,
    ) -> Self {
        let reading = memory_pressure::read();
        let reading = reading.reading();
        let now = unix_now();
        let record = InitAttemptRecord {
            version: ATTEMPT_RECORD_VERSION,
            source: source.display().to_string(),
            destination: destination.display().to_string(),
            pid: std::process::id(),
            started_unix: now,
            phase_index: 0,
            phase_total,
            phase_label: String::new(),
            phase_started_unix: now,
            memory_limit_bytes: reading.map(|reading| reading.limit_bytes),
            memory_source: reading.map(|reading| reading.source.as_str().to_string()),
            stage_path: None,
        };
        let journal = Self {
            path: capture_dir.join(ATTEMPT_RECORD_NAME),
            state: Mutex::new(JournalState {
                record,
                write_failures: 0,
            }),
        };
        journal.flush();
        journal
    }

    /// Record that phase `index` of the ladder has opened.
    pub(crate) fn enter_phase(&self, index: usize, label: &str) {
        self.edit(|record| {
            record.phase_index = index;
            record.phase_label = label.to_string();
            record.phase_started_unix = unix_now();
        });
    }

    /// Record the repository stage directory the ladder just created, so a
    /// post-mortem can name and size both halves of what a kill leaves behind.
    pub(crate) fn record_stage_path(&self, stage: &Path) {
        self.edit(|record| record.stage_path = Some(stage.display().to_string()));
    }

    fn edit(&self, act: impl FnOnce(&mut InitAttemptRecord)) {
        if let Ok(mut state) = self.state.lock() {
            act(&mut state.record);
        }
        self.flush();
    }

    /// Replace the record on disk.
    ///
    /// Written to a temporary sibling and renamed, so a reader arriving between
    /// two phases sees one whole record rather than a truncated one. Not
    /// fsynced: see the module note.
    fn flush(&self) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        let Ok(bytes) = serde_json::to_vec_pretty(&state.record) else {
            state.write_failures += 1;
            return;
        };
        let staging = self.path.with_extension("writing");
        let wrote = File::create(&staging).and_then(|mut file| {
            file.write_all(&bytes)?;
            file.write_all(b"\n")
        });
        if wrote.is_err() || std::fs::rename(&staging, &self.path).is_err() {
            let _ = std::fs::remove_file(&staging);
            state.write_failures += 1;
        }
    }

    #[cfg(test)]
    pub(crate) fn write_failures(&self) -> usize {
        self.state
            .lock()
            .map(|state| state.write_failures)
            .unwrap_or(0)
    }

    #[cfg(test)]
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

// --------------------------------------------------------------------- reader

/// One conversion that started beside `parent` and never finished.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbandonedInit {
    /// The capture staging directory it left.
    pub capture_path: PathBuf,
    /// Bytes that directory holds.
    pub capture_bytes: u64,
    /// Its record, when one is readable. `None` is an older Kin's staging, or a
    /// record this build cannot parse, and is reported as such rather than
    /// silently skipped.
    pub record: Option<InitAttemptRecord>,
    /// Why the record could not be read, when it could not.
    pub record_unreadable: Option<String>,
    /// The repository stage directory the record named, when it still exists.
    pub stage_path: Option<PathBuf>,
    /// Bytes that directory holds.
    pub stage_bytes: u64,
    /// The stage's `.owner` sidecar, which sits beside the stage rather than
    /// inside it and so is a third thing a hand cleanup has to know about.
    pub owner_path: Option<PathBuf>,
}

impl AbandonedInit {
    /// Total disk this attempt is holding.
    pub fn reclaimable_bytes(&self) -> u64 {
        self.capture_bytes.saturating_add(self.stage_bytes)
    }

    /// Whether this attempt was converting `source`.
    pub fn converted(&self, source: &Path) -> bool {
        self.record
            .as_ref()
            .is_some_and(|record| Path::new(&record.source) == source)
    }

    /// Every path this attempt left behind, so a hand cleanup is complete.
    pub fn paths(&self) -> Vec<PathBuf> {
        let mut paths = vec![self.capture_path.clone()];
        paths.extend(self.stage_path.clone());
        paths.extend(self.owner_path.clone());
        paths
    }
}

/// Where a surface should look for interrupted-conversion staging, given the
/// directory an operator is standing in.
///
/// Both that directory and its parent, because init stages beside the
/// repository rather than inside it: an operator running a check from the
/// converted repository needs the parent scanned, and one running it from the
/// directory that holds their checkouts needs the working directory scanned.
/// Looking in only one answers correctly for one of those operators and reports
/// a clean disk to the other.
///
/// Canonical, because init canonicalizes its source before recording one, and a
/// surface quoting `/var/...` for a record that says `/private/var/...` prints
/// two paths for one directory in the same paragraph.
pub fn staging_scan_roots(cwd: &Path) -> Vec<PathBuf> {
    let cwd = cwd.canonicalize().unwrap_or_else(|_| cwd.to_path_buf());
    let mut roots = vec![cwd.clone()];
    if let Some(parent) = cwd.parent() {
        if parent != cwd {
            roots.push(parent.to_path_buf());
        }
    }
    roots
}

/// Every unfinished conversion staged beside `parent` that no live init owns.
///
/// Read-only, and deliberately so: `kin doctor` has to be able to name what is
/// on disk without deleting it, and `kin init` has to be able to report what it
/// is about to reclaim before it reclaims it.
///
/// A directory whose lease is contended belongs to a conversion running right
/// now and is not reported. A directory carrying no readable lease is reported
/// with its reason, because an older Kin wrote it and saying nothing about
/// 200 MB is the defect this module exists to end.
pub fn abandoned_init_attempts(parent: &Path) -> Result<Vec<AbandonedInit>> {
    let entries = match std::fs::read_dir(parent) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(KinError::io(parent, error)),
    };
    let mut entries = entries
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(|error| KinError::io(parent, error))?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    let mut abandoned = Vec::new();
    for entry in entries {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.starts_with(crate::init_staging::GIT_CAPTURE_PREFIX) {
            continue;
        }
        let candidate = entry.path();
        let Ok(metadata) = std::fs::symlink_metadata(&candidate) else {
            continue;
        };
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            continue;
        }
        // A live conversion's staging is not a post-mortem. Only a lease that
        // can be taken exclusively proves its holder is gone, and an
        // unanswerable lease is left alone here for the same reason the reaper
        // leaves it alone: this call cannot prove nothing is using it.
        if !matches!(
            crate::init_staging::capture_lease_is_abandoned(&candidate),
            Ok(true)
        ) {
            continue;
        }
        let (record, record_unreadable) = read_attempt_record(&candidate);
        let stage_path = record
            .as_ref()
            .and_then(|record| record.stage_path.as_ref())
            .map(PathBuf::from)
            .filter(|stage| stage.is_dir());
        let owner_path = stage_path
            .as_ref()
            .map(|stage| owner_sidecar_path(stage))
            .filter(|owner| owner.is_file());
        abandoned.push(AbandonedInit {
            capture_bytes: directory_bytes(&candidate),
            capture_path: candidate,
            record,
            record_unreadable,
            stage_bytes: stage_path.as_deref().map(directory_bytes).unwrap_or(0),
            stage_path,
            owner_path,
        });
    }
    Ok(abandoned)
}

/// Where a repository stage's ownership record sits.
///
/// Beside the stage rather than inside it, so publication can rename the stage
/// into place without carrying its own lease along. Reproduced here rather than
/// reached for, because this reader must work on a stage whose owning init is
/// long dead and there is nothing left to ask.
fn owner_sidecar_path(stage: &Path) -> PathBuf {
    let mut name = stage.as_os_str().to_os_string();
    name.push(".owner");
    PathBuf::from(name)
}

/// Read one capture directory's record, or say why it could not be read.
fn read_attempt_record(capture: &Path) -> (Option<InitAttemptRecord>, Option<String>) {
    let path = capture.join(ATTEMPT_RECORD_NAME);
    let metadata = match std::fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return (
                None,
                Some("it carries no phase record, so an older Kin staged it".to_string()),
            );
        }
        Err(error) => {
            return (
                None,
                Some(format!("its phase record is unreadable: {error}")),
            )
        }
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return (
            None,
            Some("its phase record is not a regular file".to_string()),
        );
    }
    if metadata.len() > MAX_RECORD_BYTES {
        return (
            None,
            Some(format!(
                "its phase record is {} bytes, past the {MAX_RECORD_BYTES} this reader accepts",
                metadata.len()
            )),
        );
    }
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        Err(error) => {
            return (
                None,
                Some(format!("its phase record is unreadable: {error}")),
            )
        }
    };
    match serde_json::from_slice::<InitAttemptRecord>(&bytes) {
        Ok(record) if record.version == ATTEMPT_RECORD_VERSION => (Some(record), None),
        Ok(record) => (
            None,
            Some(format!(
                "its phase record is layout version {}, which this build does not read",
                record.version
            )),
        ),
        Err(error) => (
            None,
            Some(format!("its phase record does not parse: {error}")),
        ),
    }
}

/// Disk a directory tree is holding, counting regular files only.
///
/// Allocated blocks where the platform publishes them, not the sum of file
/// lengths. The two differ by a lot on exactly the tree this reports on: a
/// content-addressed capture store is thousands of small bodies, each rounded
/// up to a filesystem block, so a 600-commit fixture whose files sum to 2.2 MB
/// occupies 14.2 MB by `du`. The operator's question is how much disk comes
/// back, so the answer has to be the one `du` gives them rather than the one
/// that understates it sixfold.
///
/// Never follows a symlink and never fails: a size that could not be measured
/// reads as the part that could. This is disclosure of disk usage at an IO
/// boundary, not an answer about repository content, and nothing semantic is
/// derived from it.
fn directory_bytes(root: &Path) -> u64 {
    let mut total = 0_u64;
    let mut stack = vec![root.to_path_buf()];
    while let Some(directory) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&directory) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            if metadata.file_type().is_symlink() {
                continue;
            }
            if metadata.is_dir() {
                stack.push(entry.path());
            } else if metadata.is_file() {
                total = total.saturating_add(occupied_bytes(&metadata));
            }
        }
    }
    total
}

/// Disk one file occupies.
///
/// Shared with `init::measure_stage_tree`, which sizes a stranded repository
/// stage for the same operator asking the same question one row further down
/// the same `kin doctor` output. Two definitions of "how much disk" would print
/// two answers for one machine.
#[cfg(unix)]
pub(crate) fn occupied_bytes(metadata: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt as _;

    // `blocks()` is in 512-byte units by POSIX definition, whatever the
    // filesystem's own block size is. A file the kernel reports zero blocks for
    // is either empty or held entirely inline in its inode, and its length is
    // the better answer there.
    let allocated = metadata.blocks().saturating_mul(512);
    if allocated == 0 {
        metadata.len()
    } else {
        allocated
    }
}

/// Disk one file occupies, where the platform publishes no allocation.
#[cfg(not(unix))]
pub(crate) fn occupied_bytes(metadata: &std::fs::Metadata) -> u64 {
    metadata.len()
}

/// Render a byte count the way a person reads one.
pub fn human_bytes(bytes: u64) -> String {
    const UNITS: [(&str, u64); 4] = [
        ("GB", 1024 * 1024 * 1024),
        ("MB", 1024 * 1024),
        ("KB", 1024),
        ("bytes", 1),
    ];
    for (unit, scale) in UNITS {
        if bytes >= scale && scale > 1 {
            return format!("{:.1} {unit}", bytes as f64 / scale as f64);
        }
    }
    format!("{bytes} bytes")
}

// ------------------------------------------------------------------ reporting

/// The prose one abandoned conversion is worth, in the register the commit
/// diagnosis register set: what stopped, where it stopped, under what ceiling,
/// what the kernel says about it, and what this run is going to do next.
///
/// Pure over its inputs so the wording is pinned by tests rather than by
/// running a conversion. `now_unix` and `current` are passed in for the same
/// reason: a post-mortem that reads the clock and the cgroup for itself cannot
/// be asserted on.
pub fn post_mortem_lines(
    attempt: &AbandonedInit,
    current: Option<&MemoryReading>,
    initializing: &Path,
) -> Vec<String> {
    let mut lines = Vec::new();
    match &attempt.record {
        Some(record) => {
            lines.push(format!(
                "a previous kin init of {} did not finish{}",
                record.source,
                elsewhere_clause(attempt, initializing),
            ));
            lines.push(format!(
                "  it stopped in phase {} of {}, {}, {} into the conversion",
                record.phase_index.max(1),
                record.phase_total,
                if record.phase_label.is_empty() {
                    "before the first phase opened"
                } else {
                    record.phase_label.as_str()
                },
                human_seconds(record.seconds_to_last_phase()),
            ));
            lines.push(memory_line(record));
        }
        None => {
            lines.push(format!(
                "a previous kin init left staging at {} behind{}",
                attempt.capture_path.display(),
                elsewhere_clause(attempt, initializing),
            ));
            if let Some(reason) = &attempt.record_unreadable {
                lines.push(format!(
                    "  it cannot say which phase it stopped in, because {reason}"
                ));
            }
        }
    }
    if let Some(reading) = current {
        if reading.kernel_has_killed_here() {
            let kills = reading.oom_kills.unwrap_or(0);
            lines.push(format!(
                "  the {} it ran in has recorded {} kernel out-of-memory {}, so a memory kill is \
                 the likely cause",
                reading.source.as_str(),
                kills,
                if kills == 1 { "kill" } else { "kills" },
            ));
        }
    }
    lines.push(format!(
        "  it is holding {} of staging: {}",
        human_bytes(attempt.reclaimable_bytes()),
        attempt
            .paths()
            .iter()
            .map(|path| path.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    ));
    lines
}

/// Name the repository being initialized, and say honestly how it relates to
/// the corpse.
///
/// `kin init .` in `/root/shallow` opened with "a previous kin init of
/// /root/repo did not finish", and a reader with one repository in mind reads
/// that as a sentence about the directory they are standing in. The cleanup is
/// right and worth announcing; the header just never said the two paths were
/// different repositories.
///
/// Three forms, because there are three states and only two of them were ever
/// distinguished. `converted` is `is_some_and` over the attempt's record, so it
/// is false both when the record names another source and when there is no
/// record at all, and those are not the same claim. With no record there is no
/// source path to compare and the staging may well belong to this repository,
/// so the difference is not asserted; but the current repository still has to
/// be named, because on that branch the opening sentence has no source to name
/// and this clause is the only thing that tells the reader what the run is
/// about. Silent only when the two paths match, because repeating one path
/// twice in one sentence is noise.
fn elsewhere_clause(attempt: &AbandonedInit, initializing: &Path) -> String {
    if attempt.record.is_none() {
        return format!(
            "; this run is initializing {}, and no record survives to say whether the staging \
             is from it",
            initializing.display()
        );
    }
    if attempt.converted(initializing) {
        return String::new();
    }
    format!(
        "; that is a different repository from the {} this run is initializing",
        initializing.display()
    )
}

/// The ceiling clause, kept apart because it has three honest forms and the
/// difference between them matters: a measured cap, a machine that could not be
/// read, and a record written by a build that did not measure one.
fn memory_line(record: &InitAttemptRecord) -> String {
    match (record.memory_limit_bytes, &record.memory_source) {
        (Some(limit), Some(source)) => format!(
            "  it started under a {} memory ceiling, read from the {source}",
            human_bytes(limit)
        ),
        (Some(limit), None) => {
            format!("  it started under a {} memory ceiling", human_bytes(limit))
        }
        _ => "  it could not read a memory ceiling for the machine it ran on".to_string(),
    }
}

/// Why the next conversion starts over instead of picking up where the last one
/// stopped.
///
/// Kin does not resume a killed conversion, and this says so rather than
/// letting an operator infer it from a progress bar that starts at one again.
/// The reason is structural, not a missing feature to be worked around: the
/// capture store is a content-addressed cache written without device barriers
/// because it was only ever meant to live inside one process, and the bootstrap
/// transaction is committed in one shot with no journal to replay. Adopting
/// either after a kill would trade an eleven-minute repeat for a store nobody
/// can prove is whole.
pub const RESTART_NOTICE: &str = "  this run restarts from phase 1 rather than resuming: a killed \
                                  conversion's staged capture is written without device barriers \
                                  and its bootstrap transaction carries no journal, so none of it \
                                  can be adopted without risking a store no proof would accept";

/// What an operator can do about the ceiling, when there is reason to think the
/// ceiling is what stopped them.
///
/// Gated on the kernel having actually recorded a kill, not merely on a ceiling
/// having been read. Every machine has a ceiling, so advice keyed on the
/// ceiling alone would tell an operator who pressed Ctrl-C that they are short
/// of memory, which is a confident wrong diagnosis dressed as help. The
/// measured number is only ever quoted, never invented.
pub fn ceiling_advice(
    record: &InitAttemptRecord,
    current: Option<&MemoryReading>,
) -> Option<String> {
    if !current.is_some_and(MemoryReading::kernel_has_killed_here) {
        return None;
    }
    let limit = record.memory_limit_bytes?;
    Some(format!(
        "  a conversion's peak follows history depth, so give it more than {} or convert a \
         repository with less history",
        human_bytes(limit)
    ))
}

/// Write one advisory line to stderr, tolerating a closed pipe.
///
/// `eprintln!` panics when its reader is gone, and a conversion's exit status
/// has to report the admission rather than the terminal going away.
fn disclose(line: &str) {
    let mut stderr = std::io::stderr().lock();
    let _ = writeln!(stderr, "{line}");
}

/// The same pipe-safe write, for the admission ladder's other disclosures.
///
/// Exported rather than duplicated so every line a conversion says about itself
/// goes out the one way that survives `kin init | head -1`. A second writer
/// using `eprintln!` would panic on the closed pipe and turn a refusal a reader
/// asked to truncate into a crash.
pub fn disclose_line(line: &str) {
    disclose(line);
}

/// Tell the operator about every conversion that died beside this one before
/// this run reaps its remains.
///
/// Called before the reap on purpose: the directories being described are the
/// ones about to be deleted, so describing them afterwards would mean reading a
/// path that no longer exists and reporting a size nobody can check.
pub fn report_previous_attempts(attempts: &[AbandonedInit], source: &Path) {
    if attempts.is_empty() {
        return;
    }
    let current = memory_pressure::read();
    let current = current.reading().copied();
    for attempt in attempts {
        let mut lines = post_mortem_lines(attempt, current.as_ref(), source);
        if let Some(first) = lines.first_mut() {
            *first = format!("warning: {first}");
        }
        for line in lines {
            disclose(&line);
        }
    }
    // The restart notice belongs to a conversion of THIS repository. A sibling
    // repository's corpse beside us is worth naming, but this run is not
    // restarting it and saying so would be a claim about work nobody asked for.
    let ours = attempts.iter().find(|attempt| attempt.converted(source));
    if let Some(ours) = ours {
        disclose(RESTART_NOTICE);
        if let Some(advice) = ours
            .record
            .as_ref()
            .and_then(|record| ceiling_advice(record, current.as_ref()))
        {
            disclose(&advice);
        }
    }
}

/// Say what the reap actually recovered, measured rather than assumed.
///
/// Reports what is gone by re-reading the filesystem, so a directory the reap
/// declined to touch is never counted as reclaimed. A retained path is named
/// with the reason the reaper had, because 200 MB nobody mentions is the defect
/// this module exists to end and a silent partial reclaim is the same defect
/// wearing a smaller number.
pub fn report_reclaimed(before: &[AbandonedInit]) {
    for line in reclaim_lines(before) {
        disclose(&line);
    }
}

/// What the reap recovered and what it did not, as lines.
///
/// Split from the writing so the wording is pinned by tests rather than by
/// running a conversion.
///
/// A path is counted as reclaimed only when it is actually gone from disk, so a
/// directory the reaper declined to touch is never folded into the total. What
/// stays gets named rather than summarised, because a staging directory this
/// run left alone belongs to a repository this run is not converting, and the
/// operator who owns it needs its path to act on it.
pub fn reclaim_lines(before: &[AbandonedInit]) -> Vec<String> {
    if before.is_empty() {
        return Vec::new();
    }
    let mut lines = Vec::new();
    let mut freed = 0_u64;
    let mut retained: Vec<String> = Vec::new();
    let mut retained_bytes = 0_u64;
    for attempt in before {
        if attempt.capture_path.exists() {
            retained.push(attempt.capture_path.display().to_string());
            retained_bytes = retained_bytes.saturating_add(attempt.capture_bytes);
        } else {
            freed = freed.saturating_add(attempt.capture_bytes);
        }
        match &attempt.stage_path {
            Some(stage) if stage.exists() => {
                retained.push(stage.display().to_string());
                retained_bytes = retained_bytes.saturating_add(attempt.stage_bytes);
            }
            Some(_) => freed = freed.saturating_add(attempt.stage_bytes),
            None => {}
        }
    }
    if freed > 0 {
        lines.push(format!(
            "  reclaimed {} of staging those attempts left behind",
            human_bytes(freed)
        ));
    }
    if !retained.is_empty() {
        lines.push(format!(
            "  {} is still on disk and this run did not reclaim it, because it belongs to \
             another repository's conversion or its owner could not be proven gone: {}",
            human_bytes(retained_bytes),
            retained.join(", ")
        ));
    }
    lines
}

/// Say what a reclaim pass over abandoned repository stages did.
///
/// The sibling of [`report_reclaimed`], for the half of the reap that list
/// cannot see. `reclaim_lines` measures the `.kin-git-capture-*` directories
/// this run scanned, and a killed conversion also strands a repository STAGE,
/// reclaimed by owner record rather than by capture lease. Those were reaped on
/// both paths with the count thrown away, so a stage whose capture record was
/// unreadable came off an operator's disk and appeared in no sentence anywhere.
pub fn report_reclaimed_stages(recovered: usize, retained: usize) {
    for line in reclaimed_stage_lines(recovered, retained) {
        disclose(&line);
    }
}

/// What that pass leaves an operator to read, as lines.
///
/// Split from the writing so the wording is pinned by a test rather than by
/// running a conversion and killing it, exactly as [`reclaim_lines`] is.
///
/// Silent when the pass touched nothing, which is every ordinary `kin init`.
/// That silence is load-bearing: a line printed under every conversion is a line
/// nobody reads by the third one, and this one has to be read on the first
/// conversion after a kill.
pub fn reclaimed_stage_lines(recovered: usize, retained: usize) -> Vec<String> {
    let mut lines = Vec::new();
    if recovered > 0 {
        lines.push(format!(
            "  reclaimed {recovered} repository staging {} an earlier `kin init` left behind here",
            if recovered == 1 {
                "directory"
            } else {
                "directories"
            }
        ));
    }
    if retained > 0 {
        // Named rather than folded into the line above, and never counted as
        // reclaimed. A directory this run declined to touch is still costing
        // the operator disk, and the reason it was left is the reason they can
        // act on it safely.
        let (noun, verb, pronoun) = if retained == 1 {
            ("directory", "is", "it")
        } else {
            ("directories", "are", "them")
        };
        lines.push(format!(
            "  {retained} more repository staging {noun} {verb} still on disk and this run left \
             {pronoun} alone, because it could not prove {pronoun} unused; delete {pronoun} by \
             hand once no `kin init` is running here"
        ));
    }
    lines
}

/// The `kin doctor` row's detail and fix lines for whatever staging is sitting
/// beside `parent`, or `None` when there is none.
///
/// Doctor reports and never reaps: an operator asking what is on their disk has
/// not asked Kin to delete anything, and a diagnostic that mutates is one an
/// operator learns not to run.
pub fn doctor_row(attempts: &[AbandonedInit]) -> Option<(String, String)> {
    if attempts.is_empty() {
        return None;
    }
    let total: u64 = attempts.iter().map(AbandonedInit::reclaimable_bytes).sum();
    let where_it_stopped = attempts
        .iter()
        .filter_map(|attempt| attempt.record.as_ref())
        .map(|record| {
            format!(
                "{} stopped in phase {} of {}, {}",
                record.source,
                record.phase_index.max(1),
                record.phase_total,
                if record.phase_label.is_empty() {
                    "before the first phase opened"
                } else {
                    record.phase_label.as_str()
                }
            )
        })
        .collect::<Vec<_>>();
    let detail = if where_it_stopped.is_empty() {
        format!(
            "{} of staging from {} interrupted `kin init` run(s) is reclaimable; none of it \
             carries a phase record, so an older Kin staged it",
            human_bytes(total),
            attempts.len()
        )
    } else {
        format!(
            "{} of staging from {} interrupted `kin init` run(s) is reclaimable: {}",
            human_bytes(total),
            attempts.len(),
            where_it_stopped.join("; ")
        )
    };
    let paths = attempts
        .iter()
        .flat_map(AbandonedInit::paths)
        .map(|path| path.display().to_string())
        .collect::<Vec<_>>();
    let fix = format!(
        "run `kin init` in that repository again, which reclaims this before it starts, or \
         delete {}",
        paths.join(" ")
    );
    Some((detail, fix))
}

fn human_seconds(seconds: u64) -> String {
    if seconds < 90 {
        return format!("{seconds} s");
    }
    format!("{} min {} s", seconds / 60, seconds % 60)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory_pressure::PressureSource;

    /// A pass that touched nothing says nothing.
    ///
    /// The load-bearing half. Every ordinary `kin init` reclaims no stage, so a
    /// line here would print under every conversion anyone ever runs and be
    /// skipped by the third one. It has to be readable on the first conversion
    /// after a kill, which means it cannot appear on the others.
    ///
    /// Falsify by dropping either `> 0` guard: this goes red and the two arms
    /// below stay green, which is exactly how a warning becomes wallpaper.
    #[test]
    fn a_reclaim_pass_that_touched_nothing_prints_nothing() {
        assert!(
            reclaimed_stage_lines(0, 0).is_empty(),
            "an ordinary conversion reclaims nothing and must say nothing"
        );
    }

    /// What was taken back, and what is still costing the operator disk.
    ///
    /// Two separate lines because they call for opposite actions: one is news
    /// about disk that came back on its own, the other is a directory the
    /// operator has to decide about. Folding them into one total would report
    /// the second as though this run had handled it.
    #[test]
    fn a_reclaim_says_what_it_took_back_and_names_what_it_left_with_the_reason() {
        let took = reclaimed_stage_lines(1, 0);
        assert_eq!(took.len(), 1, "{took:?}");
        assert!(
            took[0].contains("reclaimed 1 repository staging directory"),
            "the count and what it counts are both the point: {}",
            took[0]
        );

        let left = reclaimed_stage_lines(0, 2);
        assert_eq!(left.len(), 1, "{left:?}");
        assert!(
            left[0].contains("2 more repository staging directories are still on disk"),
            "a directory this run declined to touch is still costing disk: {}",
            left[0]
        );
        assert!(
            left[0].contains("could not prove them unused"),
            "and the reason it was left is what makes deleting it safe: {}",
            left[0]
        );
        assert!(
            left[0].contains("delete them by hand"),
            "every non-quiet line here carries what to do about it: {}",
            left[0]
        );

        // Printed, not read. A Rust line continuation drops the newline and the
        // indentation after it, and a literal assembled by anything that ate
        // the backslash first keeps the indentation as a run of spaces inside
        // the sentence. The source looks right either way, so the only reading
        // that settles it is the rendered line. This caught exactly that on the
        // line above.
        for line in [&took[0], &left[0]] {
            let body = line.trim_start();
            assert!(
                !body.contains("  "),
                "a rendered line carries a run of spaces, so its continuation was assembled \
                 wrong: {line:?}"
            );
        }

        let both = reclaimed_stage_lines(3, 1);
        assert_eq!(
            both.len(),
            2,
            "what came back and what stayed are never one line: {both:?}"
        );
        assert!(
            both[0].contains("reclaimed 3 repository staging directories"),
            "{both:?}"
        );
        assert!(
            both[1].contains("1 more repository staging directory is still on disk"),
            "{both:?}"
        );
    }

    fn record() -> InitAttemptRecord {
        InitAttemptRecord {
            version: ATTEMPT_RECORD_VERSION,
            source: "/work/requests".to_string(),
            destination: "/work/requests/.kin".to_string(),
            pid: 41,
            started_unix: 1000,
            phase_index: 13,
            phase_total: 17,
            phase_label: "commit bootstrap transaction".to_string(),
            phase_started_unix: 1707,
            memory_limit_bytes: Some(12 * 1024 * 1024 * 1024),
            memory_source: Some("container".to_string()),
            stage_path: None,
        }
    }

    fn attempt(record: Option<InitAttemptRecord>) -> AbandonedInit {
        AbandonedInit {
            capture_path: PathBuf::from("/work/.kin-git-capture-abdd7a1c"),
            capture_bytes: 210 * 1024 * 1024,
            record,
            record_unreadable: None,
            stage_path: Some(PathBuf::from("/work/.kin.init-22ef96e2")),
            stage_bytes: 210 * 1024 * 1024,
            owner_path: Some(PathBuf::from("/work/.kin.init-22ef96e2.owner")),
        }
    }

    fn reading(oom_kills: Option<u64>) -> MemoryReading {
        MemoryReading {
            source: PressureSource::Cgroup,
            limit_bytes: 12 * 1024 * 1024 * 1024,
            used_bytes: 1024,
            swap_used_bytes: None,
            swap_total_bytes: None,
            oom_kills,
            peak_bytes: None,
        }
    }

    #[test]
    fn a_post_mortem_names_the_phase_the_ceiling_and_the_staging() {
        let lines = post_mortem_lines(
            &attempt(Some(record())),
            Some(&reading(Some(1))),
            Path::new("/work/requests"),
        );
        let rendered = lines.join("\n");
        assert!(
            rendered.contains("phase 13 of 17, commit bootstrap transaction"),
            "the phase is the whole point of the record: {rendered}"
        );
        assert!(
            rendered.contains("11 min 47 s into the conversion"),
            "elapsed to the last phase must be reported: {rendered}"
        );
        assert!(
            rendered.contains("under a 12.0 GB memory ceiling, read from the container"),
            "the measured ceiling must be named: {rendered}"
        );
        assert!(
            rendered.contains("1 kernel out-of-memory kill"),
            "a kill the kernel recorded must be named: {rendered}"
        );
        assert!(
            rendered.contains("420.0 MB of staging"),
            "the reclaimable total must be named: {rendered}"
        );
        assert!(
            rendered.contains("/work/.kin-git-capture-abdd7a1c")
                && rendered.contains("/work/.kin.init-22ef96e2"),
            "both staging paths must be named: {rendered}"
        );
    }

    /// The kill clause is evidence, not decoration. A cgroup reporting zero
    /// kills must not have one asserted about it, because the same silence
    /// covers a conversion an operator killed by hand.
    #[test]
    fn a_cgroup_with_no_kills_is_never_told_it_had_one() {
        let quiet = post_mortem_lines(
            &attempt(Some(record())),
            Some(&reading(Some(0))),
            Path::new("/work/requests"),
        );
        assert!(
            !quiet.join("\n").contains("out-of-memory"),
            "zero recorded kills must produce no kill sentence: {quiet:?}"
        );
        let unknown = post_mortem_lines(
            &attempt(Some(record())),
            Some(&reading(None)),
            Path::new("/work/requests"),
        );
        assert!(
            !unknown.join("\n").contains("out-of-memory"),
            "an unreadable kill counter is not evidence of a kill: {unknown:?}"
        );
        let some = post_mortem_lines(
            &attempt(Some(record())),
            Some(&reading(Some(2))),
            Path::new("/work/requests"),
        );
        assert!(
            some.join("\n").contains("2 kernel out-of-memory kills"),
            "more than one kill pluralizes: {some:?}"
        );
    }

    /// A capture directory an older Kin left has no record. Reporting it as
    /// phase zero of zero would be an invented fact; reporting nothing at all
    /// is the defect. It gets its own sentence.
    #[test]
    fn staging_without_a_record_is_reported_without_inventing_a_phase() {
        let mut orphan = attempt(None);
        orphan.record_unreadable = Some("it carries no phase record".to_string());
        let rendered = post_mortem_lines(&orphan, None, Path::new("/work/requests")).join("\n");
        assert!(
            rendered.contains("left staging at /work/.kin-git-capture-abdd7a1c behind"),
            "the path is all this case can name: {rendered}"
        );
        assert!(
            rendered.contains("cannot say which phase"),
            "the reader must say why the phase is missing: {rendered}"
        );
        assert!(
            !rendered.contains("phase 0"),
            "an absent record must never render as a phase number: {rendered}"
        );
    }

    /// With no record there is no source path to compare, so the orphan branch
    /// cannot know whether the staging belongs to this repository or another
    /// one. It used to say it was another one, because `converted` is
    /// `is_some_and` and a missing record makes it false for a reason that is
    /// not a difference.
    ///
    /// The naming half is asserted by
    /// `the_post_mortem_names_the_repository_it_is_about_and_the_one_being_initialized`.
    /// This one asks only that no difference is claimed, so the two halves
    /// cannot each catch the other's mutation and read as two defences.
    #[test]
    fn staging_without_a_record_claims_no_difference_it_cannot_see() {
        let mut orphan = attempt(None);
        orphan.record_unreadable = Some("it carries no phase record".to_string());
        let rendered = post_mortem_lines(&orphan, None, Path::new("/work/shallow")).join("\n");
        assert!(
            !rendered.contains("a different repository"),
            "with no record there is nothing to compare, so nothing is claimed: {rendered}"
        );
        assert!(
            rendered.contains("no record survives to say whether the staging is from it"),
            "and the unknown is stated rather than left as a silence: {rendered}"
        );

        // The control, so the clause was made honest rather than deleted: with
        // a record naming another source, the difference is still named.
        let known = post_mortem_lines(&attempt(Some(record())), None, Path::new("/work/shallow"))
            .join("\n");
        assert!(
            known.contains(
                "a different repository from the /work/shallow this run is \
                            initializing"
            ),
            "a record that names another source still reports the difference: {known}"
        );
    }

    /// A build that measured no ceiling says so. The alternative is a sentence
    /// naming a limit nobody read, which is the failure mode the whole
    /// memory-pressure seam exists to prevent.
    #[test]
    fn an_unmeasured_ceiling_is_said_rather_than_guessed() {
        let mut unmeasured = record();
        unmeasured.memory_limit_bytes = None;
        unmeasured.memory_source = None;
        let rendered = post_mortem_lines(
            &attempt(Some(unmeasured.clone())),
            None,
            Path::new("/work/requests"),
        )
        .join("\n");
        assert!(
            rendered.contains("could not read a memory ceiling"),
            "an unmeasured ceiling must be disclosed: {rendered}"
        );
        assert!(
            ceiling_advice(&unmeasured, Some(&reading(Some(1)))).is_none(),
            "advice about a ceiling must never print without the ceiling"
        );
        assert!(
            ceiling_advice(&record(), Some(&reading(Some(1))))
                .is_some_and(|line| line.contains("12.0 GB")),
            "advice quotes the measured ceiling"
        );
        assert!(
            ceiling_advice(&record(), Some(&reading(Some(0)))).is_none(),
            "a conversion the kernel did not kill gets no advice about memory"
        );
        assert!(
            ceiling_advice(&record(), None).is_none(),
            "an unreadable machine is not evidence that memory was the problem"
        );
    }

    #[test]
    fn a_record_survives_a_round_trip_through_the_journal() {
        let root = tempfile::tempdir().unwrap();
        let capture = root.path().join(".kin-git-capture-round-trip");
        std::fs::create_dir(&capture).unwrap();
        let journal = InitAttemptJournal::open(
            &capture,
            Path::new("/work/requests"),
            Path::new("/work/requests/.kin"),
            17,
        );
        journal.enter_phase(5, "derive semantic history");
        journal.record_stage_path(Path::new("/work/.kin.init-22ef96e2"));
        assert_eq!(journal.write_failures(), 0, "every write must land");

        let (read_back, unreadable) = read_attempt_record(&capture);
        assert!(unreadable.is_none(), "a record just written must parse");
        let read_back = read_back.expect("the record must read back");
        assert_eq!(read_back.phase_index, 5);
        assert_eq!(read_back.phase_label, "derive semantic history");
        assert_eq!(
            read_back.stage_path.as_deref(),
            Some("/work/.kin.init-22ef96e2")
        );
        assert_eq!(read_back.phase_total, 17);
        assert_eq!(read_back.pid, std::process::id());
        assert!(
            !journal.path().with_extension("writing").exists(),
            "the temporary sibling must not be left behind"
        );
    }

    /// The reader must refuse a record it cannot vouch for rather than fill in
    /// defaults, because a defaulted phase number is a wrong answer that looks
    /// exactly like a right one.
    #[test]
    fn an_unparseable_or_future_record_is_unreadable_rather_than_defaulted() {
        let root = tempfile::tempdir().unwrap();

        let torn = root.path().join(".kin-git-capture-torn");
        std::fs::create_dir(&torn).unwrap();
        std::fs::write(torn.join(ATTEMPT_RECORD_NAME), b"{\"version\":1,\"sou").unwrap();
        let (record, why) = read_attempt_record(&torn);
        assert!(record.is_none(), "a truncated record is not a record");
        assert!(
            why.is_some_and(|why| why.contains("does not parse")),
            "the reason must name the parse failure"
        );

        let future = root.path().join(".kin-git-capture-future");
        std::fs::create_dir(&future).unwrap();
        let mut ahead = record_json();
        ahead["version"] = serde_json::json!(ATTEMPT_RECORD_VERSION + 1);
        std::fs::write(
            future.join(ATTEMPT_RECORD_NAME),
            serde_json::to_vec(&ahead).unwrap(),
        )
        .unwrap();
        let (record, why) = read_attempt_record(&future);
        assert!(record.is_none(), "a newer layout must not be guessed at");
        assert!(
            why.is_some_and(|why| why.contains("layout version")),
            "the reason must name the version"
        );

        let absent = root.path().join(".kin-git-capture-absent");
        std::fs::create_dir(&absent).unwrap();
        let (record, why) = read_attempt_record(&absent);
        assert!(record.is_none());
        assert!(
            why.is_some_and(|why| why.contains("older Kin")),
            "a capture with no record at all has its own reason"
        );
    }

    fn record_json() -> serde_json::Value {
        serde_json::to_value(record()).unwrap()
    }

    /// The size has to be the disk a tree occupies, because that is the number
    /// an operator is deciding about, and it must not walk out of the tree
    /// through a symlink to get it.
    #[test]
    fn a_directory_tree_is_sized_by_disk_without_following_symlinks() {
        let root = tempfile::tempdir().unwrap();
        let tree = root.path().join("tree");
        std::fs::create_dir(&tree).unwrap();
        std::fs::write(tree.join("a"), vec![0_u8; 1000]).unwrap();
        let nested = tree.join("nested");
        std::fs::create_dir(&nested).unwrap();
        std::fs::write(nested.join("b"), vec![0_u8; 2000]).unwrap();
        let sized = directory_bytes(&tree);
        assert!(
            sized >= 3000,
            "two files of 1000 and 2000 bytes occupy at least their own length, got {sized}"
        );
        // Both files sit far under one block, so on any ordinary filesystem the
        // occupied size exceeds the 3000 bytes of content. Asserting the
        // inequality rather than a constant stays true across block sizes while
        // still failing a reader that went back to summing lengths, which would
        // report exactly 3000.
        #[cfg(unix)]
        assert!(
            sized > 3000,
            "a tree of two sub-block files occupies more disk than their lengths sum to, got \
             {sized}"
        );

        let outside = root.path().join("outside");
        std::fs::write(&outside, vec![0_u8; 999_999]).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside, tree.join("link")).unwrap();
        #[cfg(unix)]
        assert_eq!(
            directory_bytes(&tree),
            sized,
            "a symlink out of the tree must not be counted"
        );

        assert_eq!(
            directory_bytes(&root.path().join("absent")),
            0,
            "a tree that is not there holds nothing, and asking must not fail"
        );
    }

    /// A capture directory a running conversion holds is not a corpse. Two
    /// sibling repositories under one parent convert at the same time all the
    /// time, and reporting the live one as an interrupted run would send an
    /// operator to delete a directory that is in use.
    #[test]
    fn a_live_conversions_staging_is_never_reported_as_abandoned() {
        let root = tempfile::tempdir().unwrap();
        let live = crate::init_staging::GitCaptureStaging::claim(root.path()).unwrap();
        let journal = InitAttemptJournal::open(
            live.path(),
            Path::new("/work/live"),
            Path::new("/work/live/.kin"),
            17,
        );
        journal.enter_phase(5, "derive semantic history");
        assert!(
            abandoned_init_attempts(root.path()).unwrap().is_empty(),
            "a held lease means a live init, which must not be reported"
        );

        // The same directory, once its holder is gone, is exactly what this
        // reader exists to find. Dropping the handle removes it, so the
        // abandoned side is built by hand from the same shapes.
        let corpse = root.path().join(".kin-git-capture-abandoned");
        std::fs::create_dir(&corpse).unwrap();
        std::fs::write(corpse.join("capture.lease"), b"").unwrap();
        std::fs::copy(
            live.path().join(ATTEMPT_RECORD_NAME),
            corpse.join(ATTEMPT_RECORD_NAME),
        )
        .unwrap();
        let found = abandoned_init_attempts(root.path()).unwrap();
        assert_eq!(
            found.len(),
            1,
            "a free lease is the abandoned case: {found:?}"
        );
        assert_eq!(found[0].capture_path, corpse);
        assert_eq!(found[0].record.as_ref().unwrap().phase_index, 5);
    }

    /// The record names a stage directory that may or may not still be there,
    /// and the same for its sidecar. Reporting a path that is gone sends an
    /// operator to delete nothing and makes the size a lie.
    #[test]
    fn only_staging_that_still_exists_is_named_and_sized() {
        let root = tempfile::tempdir().unwrap();
        let capture = root.path().join(".kin-git-capture-partial");
        std::fs::create_dir(&capture).unwrap();
        std::fs::write(capture.join("capture.lease"), b"").unwrap();
        std::fs::write(capture.join("blob"), vec![0_u8; 4096]).unwrap();

        let stage = root
            .path()
            .join(".kin.init-11111111-1111-4111-8111-111111111111");
        let mut written = record();
        written.stage_path = Some(stage.display().to_string());
        std::fs::write(
            capture.join(ATTEMPT_RECORD_NAME),
            serde_json::to_vec(&written).unwrap(),
        )
        .unwrap();

        // The stage never survived the kill.
        let gone = &abandoned_init_attempts(root.path()).unwrap()[0];
        assert!(gone.stage_path.is_none(), "an absent stage is not named");
        assert_eq!(
            gone.stage_bytes, 0,
            "a stage that is not on disk holds nothing"
        );
        assert!(gone.owner_path.is_none(), "no stage means no sidecar");
        assert_eq!(gone.paths().len(), 1);
        assert!(gone.reclaimable_bytes() >= 4096);

        // The stage survived, its sidecar did not.
        std::fs::create_dir(&stage).unwrap();
        std::fs::write(stage.join("body"), vec![0_u8; 2048]).unwrap();
        let bare = &abandoned_init_attempts(root.path()).unwrap()[0];
        assert_eq!(bare.stage_path.as_deref(), Some(stage.as_path()));
        assert!(
            bare.stage_bytes >= 2048,
            "the stage's own disk must be counted, got {}",
            bare.stage_bytes
        );
        assert!(bare.owner_path.is_none(), "an absent sidecar is not named");
        assert_eq!(bare.paths().len(), 2);

        // Both survived, which is the shape the stranger found on disk.
        let owner = owner_sidecar_path(&stage);
        std::fs::write(&owner, b"{}").unwrap();
        let whole = &abandoned_init_attempts(root.path()).unwrap()[0];
        assert_eq!(whole.owner_path.as_deref(), Some(owner.as_path()));
        assert_eq!(whole.paths().len(), 3);
    }

    /// A record too large, or one that is not a regular file at all, is refused
    /// rather than read. Both are the shape of something Kin did not write.
    #[test]
    fn a_record_that_is_not_one_is_refused_by_shape_before_it_is_parsed() {
        let root = tempfile::tempdir().unwrap();

        let huge = root.path().join(".kin-git-capture-huge");
        std::fs::create_dir(&huge).unwrap();
        std::fs::write(
            huge.join(ATTEMPT_RECORD_NAME),
            vec![b' '; (MAX_RECORD_BYTES + 1) as usize],
        )
        .unwrap();
        let (parsed, why) = read_attempt_record(&huge);
        assert!(parsed.is_none());
        assert!(
            why.is_some_and(|why| why.contains("past the")),
            "an oversized record is refused by its size"
        );

        let directory = root.path().join(".kin-git-capture-directory");
        std::fs::create_dir_all(directory.join(ATTEMPT_RECORD_NAME)).unwrap();
        let (parsed, why) = read_attempt_record(&directory);
        assert!(parsed.is_none());
        assert!(
            why.is_some_and(|why| why.contains("not a regular file")),
            "a directory wearing the record's name is not a record"
        );
    }

    /// The restart notice belongs to a conversion of the repository being
    /// converted now. A sibling's corpse is worth naming and is not this run's
    /// to restart.
    #[test]
    fn an_attempt_is_matched_to_the_repository_it_was_converting() {
        let ours = attempt(Some(record()));
        assert!(ours.converted(Path::new("/work/requests")));
        assert!(!ours.converted(Path::new("/work/express")));
        assert!(
            !attempt(None).converted(Path::new("/work/requests")),
            "an attempt with no record cannot claim a repository"
        );
    }

    /// Two states the reclaim report has to tell apart: everything came back,
    /// and something was left in place. Reporting the first when the second
    /// happened is the silent orphan defect returning under a friendlier line.
    #[test]
    fn the_reclaim_report_counts_what_is_actually_gone() {
        let root = tempfile::tempdir().unwrap();
        let freed_path = root.path().join(".kin-git-capture-freed");
        let held_path = root.path().join(".kin-git-capture-held");
        std::fs::create_dir(&held_path).unwrap();

        let freed = AbandonedInit {
            capture_path: freed_path,
            capture_bytes: 1024,
            record: None,
            record_unreadable: None,
            stage_path: None,
            stage_bytes: 0,
            owner_path: None,
        };
        let held = AbandonedInit {
            capture_path: held_path.clone(),
            capture_bytes: 2048,
            record: None,
            record_unreadable: None,
            stage_path: None,
            stage_bytes: 0,
            owner_path: None,
        };

        assert!(
            reclaim_lines(&[]).is_empty(),
            "nothing to reclaim earns no line at all"
        );

        let all_gone = reclaim_lines(std::slice::from_ref(&freed)).join("\n");
        assert!(all_gone.contains("reclaimed 1.0 KB"), "{all_gone}");
        assert!(
            !all_gone.contains("still on disk"),
            "a clean reclaim must not claim something was left: {all_gone}"
        );

        let none_gone = reclaim_lines(std::slice::from_ref(&held)).join("\n");
        assert!(
            !none_gone.contains("reclaimed"),
            "nothing was freed, so nothing may be reported as reclaimed: {none_gone}"
        );
        assert!(
            none_gone.contains("2.0 KB is still on disk")
                && none_gone.contains(&held_path.display().to_string()),
            "what stayed must be named with its size: {none_gone}"
        );

        let mixed = reclaim_lines(&[freed, held]).join("\n");
        assert!(
            mixed.contains("reclaimed 1.0 KB") && mixed.contains("2.0 KB is still on disk"),
            "a partial reclaim must report both halves: {mixed}"
        );

        report_reclaimed(&[]);
        assert!(
            held_path.exists(),
            "reporting must never delete what it reports"
        );
    }

    /// The doctor row has three shapes and each is a different fact: nothing to
    /// report, staging that can say where it stopped, and staging that cannot.
    #[test]
    fn the_doctor_row_says_only_what_the_records_support() {
        assert!(
            doctor_row(&[]).is_none(),
            "a clean disk gets no attention row"
        );

        let (detail, fix) = doctor_row(&[attempt(Some(record()))]).expect("a row");
        assert!(
            detail.contains("phase 13 of 17, commit bootstrap transaction"),
            "{detail}"
        );
        assert!(detail.contains("420.0 MB"), "{detail}");
        assert!(fix.contains("kin init"), "{fix}");
        assert!(fix.contains("/work/.kin.init-22ef96e2.owner"), "{fix}");

        let (detail, _) = doctor_row(&[attempt(None)]).expect("a row");
        assert!(
            detail.contains("older Kin staged it"),
            "staging with no record says so rather than inventing a phase: {detail}"
        );
        assert!(
            !detail.contains("stopped in phase"),
            "an absent record must never render as a phase number: {detail}"
        );

        let mut unopened = record();
        unopened.phase_index = 0;
        unopened.phase_label = String::new();
        let (detail, _) = doctor_row(&[attempt(Some(unopened))]).expect("a row");
        assert!(
            detail.contains("phase 1 of 17, before the first phase opened"),
            "a kill before any phase opened has its own wording: {detail}"
        );
    }

    /// An attempt killed before the ladder opened a phase must not render as
    /// "phase 0", and must not render as a phase it never reached.
    #[test]
    fn a_kill_before_the_first_phase_is_worded_as_one() {
        let mut unopened = record();
        unopened.phase_index = 0;
        unopened.phase_label = String::new();
        let rendered =
            post_mortem_lines(&attempt(Some(unopened)), None, Path::new("/work/requests"))
                .join("\n");
        assert!(
            rendered.contains("phase 1 of 17, before the first phase opened"),
            "{rendered}"
        );
        assert!(!rendered.contains("phase 0"), "{rendered}");
    }

    #[test]
    fn byte_and_second_rendering_reads_the_way_a_person_says_it() {
        assert_eq!(human_bytes(0), "0 bytes");
        assert_eq!(human_bytes(512), "512 bytes");
        assert_eq!(human_bytes(2048), "2.0 KB");
        assert_eq!(human_bytes(210 * 1024 * 1024), "210.0 MB");
        assert_eq!(human_bytes(12 * 1024 * 1024 * 1024), "12.0 GB");
        assert_eq!(human_seconds(0), "0 s");
        assert_eq!(human_seconds(89), "89 s");
        assert_eq!(human_seconds(90), "1 min 30 s");
        assert_eq!(human_seconds(707), "11 min 47 s");
    }

    /// `kin init .` in `/root/shallow` opened with "a previous kin init of
    /// /root/repo did not finish". The cleanup is right and worth announcing.
    /// The header just never said the two paths were different repositories,
    /// and a reader with one repository in mind reads it as the one they are
    /// standing in.
    #[test]
    fn the_post_mortem_names_the_repository_it_is_about_and_the_one_being_initialized() {
        let elsewhere =
            post_mortem_lines(&attempt(Some(record())), None, Path::new("/work/shallow"))
                .join("\n");
        assert!(
            elsewhere.contains("a previous kin init of /work/requests did not finish"),
            "the corpse is still named: {elsewhere}"
        );
        assert!(
            elsewhere.contains(
                "a different repository from the /work/shallow this run is \
                                initializing"
            ),
            "and so is the repository this run is converting: {elsewhere}"
        );

        let ours = post_mortem_lines(&attempt(Some(record())), None, Path::new("/work/requests"))
            .join("\n");
        assert!(
            ours.contains("a previous kin init of /work/requests did not finish"),
            "the same-repository case still opens the same way: {ours}"
        );
        assert!(
            !ours.contains("a different repository"),
            "and does not print one path twice in one sentence: {ours}"
        );

        // A capture with no readable record cannot name a source, so the
        // clause is what carries the current repository there. This arm asks
        // only that it is named; whether a difference is claimed is asked by
        // `staging_without_a_record_claims_no_difference_it_cannot_see`, so
        // one mutation cannot be caught twice and read as two defences.
        let orphan = AbandonedInit {
            record: None,
            ..attempt(None)
        };
        let orphan_lines = post_mortem_lines(&orphan, None, Path::new("/work/shallow")).join("\n");
        assert!(
            orphan_lines.contains("this run is initializing /work/shallow"),
            "an unreadable record still says which repository this run is about: {orphan_lines}"
        );
    }
}
