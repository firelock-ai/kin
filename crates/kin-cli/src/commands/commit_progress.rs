// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! What `kin commit` shows while the daemon is committing, and what it says
//! when the daemon dies underneath it.
//!
//! A comment-only commit on a converted repository costs two to three minutes,
//! and for all of it the CLI printed nothing at all. The daemon was naming every
//! phase it entered the whole time, into `.kin/daemon.log`, so the information
//! existed and simply never reached the person waiting: silence and a hang were
//! indistinguishable, which is how a commit that had been running for 172
//! seconds was read as working right up to the moment it failed.
//!
//! The phases arrive by reading the log the daemon already writes rather than by
//! asking the daemon for them. That matters for the case this exists to cover: a
//! daemon deep in a synchronous commit has no runtime worker free to answer a
//! progress request, so a polling endpoint would go quiet exactly when the
//! caller most needs to see something. The file keeps growing regardless.

use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

/// One phase line lifted out of the daemon log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhaseLine {
    pub phase: String,
    /// Milliseconds the phase has run, when the line reported them.
    pub elapsed_ms: Option<u64>,
}

impl PhaseLine {
    /// How the phase reads on the caller's terminal.
    pub fn render(&self) -> String {
        match self.elapsed_ms {
            Some(ms) if ms >= 1000 => format!("{} ({:.1}s)", self.phase, ms as f64 / 1000.0),
            Some(ms) => format!("{} ({ms}ms)", self.phase),
            None => format!("{}...", self.phase),
        }
    }
}

/// Drop ANSI escape sequences from a log line.
///
/// The daemon's `tracing` formatter colors field names, so the bytes between a
/// name and its value are not what a naive match expects: a byte-level search
/// for `phase=` fails on a line that visibly contains it. Stripping first is
/// what makes the parse below able to fire at all.
pub fn strip_ansi(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\u{1b}' {
            out.push(ch);
            continue;
        }
        if chars.peek() == Some(&'[') {
            chars.next();
            for escape in chars.by_ref() {
                if escape.is_ascii_alphabetic() {
                    break;
                }
            }
        }
    }
    out
}

/// Messages whose lines carry a commit phase worth showing.
const PHASE_MESSAGES: [&str; 3] = [
    "slow commit phase",
    "commit phase in progress",
    "commit phase",
];

/// Lift a commit phase out of one daemon-log line, if it holds one.
pub fn parse_phase_line(raw: &str) -> Option<PhaseLine> {
    let line = strip_ansi(raw);
    if !PHASE_MESSAGES.iter().any(|message| line.contains(message)) {
        return None;
    }
    let phase = field_value(&line, "phase")?;
    let elapsed_ms = field_value(&line, "elapsed_ms").and_then(|value| value.parse().ok());
    Some(PhaseLine { phase, elapsed_ms })
}

/// Read `name=value` or `name="value"` out of an already-stripped log line.
fn field_value(line: &str, name: &str) -> Option<String> {
    let needle = format!("{name}=");
    let mut from = 0usize;
    while let Some(offset) = line[from..].find(&needle) {
        let start = from + offset;
        // Reject a suffix match such as `phase_elapsed_ms=` matching `ms=`: the
        // character before the name must not itself be part of a longer name.
        let boundary_ok = start == 0
            || !line[..start]
                .chars()
                .next_back()
                .is_some_and(|ch| ch.is_alphanumeric() || ch == '_');
        let rest = &line[start + needle.len()..];
        if boundary_ok {
            return Some(match rest.strip_prefix('"') {
                Some(quoted) => quoted.split('"').next()?.to_string(),
                None => rest
                    .split(|ch: char| ch.is_whitespace())
                    .next()?
                    .to_string(),
            });
        }
        from = start + needle.len();
    }
    None
}

/// A cursor over the daemon log that yields phases as the daemon reaches them.
///
/// Opened at the log's current length so a commit never replays the phases of
/// the one before it.
pub struct PhaseTail {
    path: PathBuf,
    offset: u64,
    pending: String,
    last_rendered: Option<String>,
}

impl PhaseTail {
    /// Start tailing `<kin_root>/daemon.log` from wherever it currently ends.
    pub fn open(kin_root: &Path) -> Self {
        let path = kin_root.join("daemon.log");
        let offset = std::fs::metadata(&path).map(|meta| meta.len()).unwrap_or(0);
        Self {
            path,
            offset,
            pending: String::new(),
            last_rendered: None,
        }
    }

    /// Every phase written since the last call, deduplicated so a beat that
    /// repeats an unchanged phase does not repeat a line on the terminal.
    pub fn poll(&mut self) -> Vec<String> {
        let Ok(mut file) = std::fs::File::open(&self.path) else {
            return Vec::new();
        };
        if file.seek(SeekFrom::Start(self.offset)).is_err() {
            return Vec::new();
        }
        let mut fresh = String::new();
        let Ok(read) = file.read_to_string(&mut fresh) else {
            return Vec::new();
        };
        self.offset += read as u64;
        self.pending.push_str(&fresh);

        let mut rendered = Vec::new();
        while let Some(newline) = self.pending.find('\n') {
            let line: String = self.pending.drain(..=newline).collect();
            let Some(phase) = parse_phase_line(&line) else {
                continue;
            };
            let text = phase.render();
            if self.last_rendered.as_deref() == Some(text.as_str()) {
                continue;
            }
            self.last_rendered = Some(text.clone());
            rendered.push(text);
        }
        rendered
    }
}

/// Explain a commit that failed at the transport, when the daemon is why.
///
/// The failure this covers reads, verbatim, as `error sending request ... /
/// connection closed before message completed`, which describes a socket and
/// says nothing about a daemon that was SIGKILLed with the caller's transaction
/// in flight. The killer leaves a note in the repository it emptied, so the
/// answer is on disk; this is the CLI reading it back.
pub fn daemon_death_explanation(kin_root: &Path) -> Option<String> {
    let note = kin_daemon_spawn::read_daemon_death_note(kin_root)?;
    Some(format!(
        "the daemon serving this repository was terminated while the request was in flight: {}. \
         Its log is {}; the change was not recorded.",
        note.summary(),
        kin_root.join("daemon.log").display()
    ))
}

/// How close to the ceiling a resident set has to get before a lost daemon is
/// reported as having most likely run out of memory.
///
/// The measured case cleared a 12288 MiB ceiling by five megabytes, so a bar
/// anywhere near the top would have called it. The bar sits well below that
/// because the cost of being wrong is asymmetric: a daemon that died at 92% of
/// its ceiling for some other reason is told memory was the likely cause and
/// loses a little time, while one that really was killed at 92% and is told
/// nothing sends its user back to reading a socket error.
const NEAR_CEILING_FRACTION: f64 = 0.90;

fn human_bytes(bytes: u64) -> String {
    const GIB: u64 = 1024 * 1024 * 1024;
    const MIB: u64 = 1024 * 1024;
    if bytes >= GIB {
        format!("{:.1} GiB", bytes as f64 / GIB as f64)
    } else {
        format!("{} MiB", bytes / MIB)
    }
}

/// What the daemon's own abandoned marker says about how the commit ended.
///
/// The failure this exists for reaches the caller as `connection closed before
/// message completed`, which describes a socket. The daemon had been
/// OOM-killed: `memory.events` recorded two kills, the successful retry of the
/// same one-file commit peaked at 12283 MiB against a 12288 MiB ceiling, and
/// nothing in the reported error named memory, the phase, or even a process
/// that had stopped. A person reading it concludes the tool is flaky.
///
/// [`daemon_death_explanation`] already covers the killer that writes a note.
/// The kernel writes none, so everything here is reconstructed from two things
/// that survive a SIGKILL: the transaction marker the daemon published on its
/// own beat, and this host's memory accounting read after the fact.
///
/// Memory is attributed in two grades and they are labelled differently on
/// purpose, the same way [`super::embed`] grades an embed that lost its daemon.
/// A cgroup that recorded a kill is the kernel's own statement and is reported
/// as observed. A resident set that had climbed to within
/// [`NEAR_CEILING_FRACTION`] of the ceiling is a strong prior and nothing more,
/// so it is reported as likely. With neither, the phase and the process death
/// are still reported and memory is not mentioned at all: a daemon that died
/// for another reason must not be handed a diagnosis nobody measured.
pub fn daemon_loss_explanation(
    abandoned: Option<&kin_daemon_spawn::OpenTransaction>,
    daemon_alive: bool,
    now_unix: u64,
    evidence: &crate::capability::MemoryEvidence,
) -> Option<String> {
    // No marker is no evidence. The daemon may never have opened a transaction
    // at all, and inventing a phase for it would be worse than the socket error
    // this replaces.
    let open = abandoned?;
    let beat_age = open.beat_age_secs(now_unix);
    let doing = match &open.phase {
        Some(phase) => format!(
            "{} in phase {} for {}s",
            open.operation, phase, open.elapsed_secs
        ),
        None => format!("{} for {}s", open.operation, open.elapsed_secs),
    };
    let state = if daemon_alive {
        format!(
            "the daemon serving this repository (pid {}) is still running but stopped beating \
             {}s ago, with {} open",
            open.pid, beat_age, doing
        )
    } else {
        format!(
            "the daemon serving this repository (pid {}) is gone; it was {}, and its last beat \
             {}s before it stopped",
            open.pid, doing, beat_age
        )
    };
    let mut sentence = match observed_rss(open) {
        Some(rss) => format!(
            "{state} reported a resident set of {}",
            render_rss(open, rss)
        ),
        None => format!("{state} published no memory reading"),
    };
    sentence.push('.');
    if let Some(memory) = memory_attribution(open, evidence) {
        sentence.push(' ');
        sentence.push_str(&memory);
    }
    Some(sentence)
}

/// The resident set to reason about: the high-water mark when the beat saw one,
/// otherwise the last sample.
///
/// The peak is the better answer to "how close did this get to the ceiling",
/// and it is a floor under the true peak rather than the true peak itself: the
/// beat samples every five seconds and a climb can outrun it.
fn observed_rss(open: &kin_daemon_spawn::OpenTransaction) -> Option<u64> {
    open.peak_rss_bytes.max(open.rss_bytes)
}

fn render_rss(open: &kin_daemon_spawn::OpenTransaction, observed: u64) -> String {
    match (open.rss_bytes, open.peak_rss_bytes) {
        (Some(last), Some(peak)) if peak > last => format!(
            "{} (at least {} at its highest sampled beat)",
            human_bytes(last),
            human_bytes(peak)
        ),
        _ => human_bytes(observed),
    }
}

/// The memory sentence, when this host can support one.
fn memory_attribution(
    open: &kin_daemon_spawn::OpenTransaction,
    evidence: &crate::capability::MemoryEvidence,
) -> Option<String> {
    let observed_kills = evidence.cgroup_oom_kills.filter(|count| *count > 0);
    let near_ceiling = observed_rss(open)
        .is_some_and(|rss| rss as f64 >= evidence.limit_bytes as f64 * NEAR_CEILING_FRACTION);
    let cause = match (observed_kills, near_ceiling) {
        (Some(count), _) => format!(
            "This machine's kernel recorded {count} out-of-memory kill(s) against the {} \
             available here, so the commit ran out of memory.",
            human_bytes(evidence.limit_bytes)
        ),
        (None, true) => format!(
            "That is within {}% of the {} available here, so it most likely ran out of memory.",
            (100.0 - NEAR_CEILING_FRACTION * 100.0).round(),
            human_bytes(evidence.limit_bytes)
        ),
        (None, false) => return None,
    };
    Some(format!("{cause} {COMMIT_MEMORY_REMEDY}"))
}

/// What a caller can do about a commit that ran out of memory.
///
/// Stated once and shared with the `kin doctor` check that reports the same
/// headroom before a commit is attempted, so the two surfaces cannot drift into
/// describing the same cost differently.
pub const COMMIT_MEMORY_REMEDY: &str =
    "A commit prepares the whole repository successor in memory, so its peak follows the size of \
     the store rather than the size of the edit. Re-run it with more memory available; \
     `kin doctor` reports this headroom before a commit is attempted.";

/// The words both the commit line and `kin commit --help` are built from.
///
/// A macro rather than a plain const because `concat!` takes literals, and the
/// help paragraph has to fold this sentence in at compile time. Two `&str`
/// consts cannot be joined in const position, and a help surface that restates
/// the sentence by hand is a surface that drifts.
macro_rules! authority_not_git_note {
    () => {
        "Recorded in Kin authority, not in git. `git status` stays dirty until you run `kin \
         eject` or push this branch to a Kin remote."
    };
}

/// The line a `kin commit` prints after recording a change.
///
/// `kin commit` is not a git commit, and until now nothing said so: the working
/// tree it just committed from stays dirty forever, `git log` never moves, and
/// in a brownfield repository whose CI, hooks and reviewers all read git that
/// reads as a commit that silently did nothing.
pub const AUTHORITY_NOT_GIT_NOTE: &str = authority_not_git_note!();

/// The long help `kin commit --help` prints, ending in the line above.
///
/// The commit-time line was the only surface carrying the fact, and a commit is
/// too late for it: the npm0549 stranger read `kin commit --help`, formed the
/// write-through assumption there, and only met the correction after running a
/// commit they had already reasoned about (FIR-2627). Help is where the
/// assumption forms, so help carries the same sentence, spliced from the same
/// macro so the two cannot say different things.
pub const COMMIT_LONG_ABOUT: &str = concat!(
    "Create an exact semantic and artifact commit.\n\n",
    "The commit lands in Kin's own authority, not in Git. Nothing is written to `.git`, so ",
    "`git status` still lists every file this commit recorded and `git log` does not move. ",
    "That is the design rather than a gap: Kin holds the change, and `kin log`, `kin diff` and ",
    "`kin review` read it. Hand it back to Git when you want it there, with `kin eject` for the ",
    "working tree or a push to a Kin remote. Until then, tools that read Git, including CI, ",
    "hooks and reviewers, see an unchanged repository with a dirty tree.\n\n",
    authority_not_git_note!(),
);

#[cfg(test)]
mod tests {
    use super::*;

    /// The CLI reference carries the same sentence the binary prints.
    ///
    /// `docs/cli-reference.md` is written by hand from the clap definitions,
    /// and its own header says nothing fails the build when the two drift. For
    /// one sentence that is not good enough: FIR-2627 exists because a fact
    /// lived on exactly one surface, and a doc page that quotes it and then
    /// stops matching would rebuild the same defect on a page nobody re-reads.
    ///
    /// Falsify by editing either the constant or the quoted line in the page:
    /// the two stop matching and this fails.
    #[test]
    fn the_cli_reference_quotes_the_commit_authority_line_verbatim() {
        let page =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/cli-reference.md");
        let text = std::fs::read_to_string(&page)
            .unwrap_or_else(|error| panic!("{} must be readable: {error}", page.display()));

        // Positive control first: a page that failed to read, or one whose
        // commit section was renamed, would otherwise be indistinguishable
        // from a page that dropped the sentence.
        assert!(
            text.contains("### `kin commit`"),
            "the commit section must exist, or this test asserts about nothing"
        );

        let flat_page = text.split_whitespace().collect::<Vec<_>>().join(" ");
        let flat_note = AUTHORITY_NOT_GIT_NOTE
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        assert!(
            flat_page.contains(&flat_note),
            "docs/cli-reference.md must quote the commit-time authority line verbatim"
        );

        // Falsification: a phrase never written must be absent, so a
        // `contains` that matches anything cannot be what passed above.
        assert!(
            !flat_page.contains("Recorded in git authority"),
            "the check must be able to fail"
        );
    }

    const GIB: u64 = 1024 * 1024 * 1024;

    fn evidence(limit_bytes: u64, oom_kills: Option<u64>) -> crate::capability::MemoryEvidence {
        crate::capability::MemoryEvidence {
            limit_bytes,
            cgroup_oom_kills: oom_kills,
        }
    }

    /// A marker shaped like the one the OOM-killed daemon left behind.
    ///
    /// Written through `kin_daemon_spawn` and read back through it rather than
    /// constructed inline, so the round trip a real diagnosis depends on is the
    /// thing under test. A field the daemon writes and the CLI cannot read
    /// makes every sentence below silently lose its evidence, and an inline
    /// struct would never notice.
    fn abandoned_marker(
        rss_bytes: Option<u64>,
        peak_rss_bytes: Option<u64>,
    ) -> Option<Box<kin_daemon_spawn::OpenTransaction>> {
        let dir = tempfile::tempdir().unwrap();
        kin_daemon_spawn::write_open_transaction(
            dir.path(),
            &kin_daemon_spawn::OpenTransaction {
                pid: 412,
                operation: "commit".to_string(),
                phase: Some("reconcile_workspace_and_commit_authority".to_string()),
                elapsed_secs: 178,
                phase_elapsed_secs: 26,
                beat_unix: 1_000,
                rss_bytes,
                peak_rss_bytes,
            },
        );
        kin_daemon_spawn::read_open_transaction(dir.path()).map(Box::new)
    }

    /// The reported failure, and the sentence that replaces it.
    ///
    /// A stranger adding 17 lines of docstring to one file was told
    /// `connection closed before message completed` and lost 207 seconds to a
    /// message that names HTTP. The kernel had killed the daemon: `oom_kill 2`
    /// in the cgroup, and the successful retry of the same commit peaked at
    /// 12283 MiB against a 12288 MiB ceiling. Nothing in the reported error
    /// named memory, the phase, or a process that had stopped.
    ///
    /// Falsify by returning `None` from `memory_attribution` for the observed
    /// grade: the phase still reports and the memory assertions fail, which is
    /// exactly the half of the defect that got the tool called flaky.
    #[test]
    fn a_daemon_the_kernel_killed_is_reported_in_memory_terms_and_names_its_phase() {
        let marker = abandoned_marker(Some(11 * GIB), Some(11 * GIB + GIB / 2));
        let explained = daemon_loss_explanation(
            marker.as_deref(),
            false,
            1_006,
            &evidence(12 * GIB, Some(2)),
        )
        .expect("a dead daemon holding a marker must be explained");

        assert!(
            explained.contains("reconcile_workspace_and_commit_authority"),
            "the phase the commit died in must be named: {explained}"
        );
        assert!(
            explained.contains("pid 412") && explained.contains("is gone"),
            "the process death must be stated, not implied: {explained}"
        );
        assert!(
            explained.contains("out-of-memory kill"),
            "the kernel's own accounting must be quoted: {explained}"
        );
        assert!(
            explained.contains("11.0 GiB") && explained.contains("11.5 GiB"),
            "the last reading and the high-water mark must both appear: {explained}"
        );
        assert!(
            explained.contains("12.0 GiB"),
            "the ceiling it ran against must be named: {explained}"
        );
        assert!(
            explained.contains("`kin doctor`"),
            "the reader must be told where the headroom is reported before a commit: {explained}"
        );
    }

    /// A resident set at the ceiling with no kernel accounting is reported as
    /// likely, never as observed. The two are different claims and a reader
    /// acts on them differently.
    #[test]
    fn a_resident_set_at_the_ceiling_without_kernel_accounting_is_only_likely() {
        let marker = abandoned_marker(Some(11 * GIB + GIB / 2), None);
        let explained =
            daemon_loss_explanation(marker.as_deref(), false, 1_006, &evidence(12 * GIB, None))
                .expect("a dead daemon holding a marker must be explained");
        assert!(
            explained.contains("most likely ran out of memory"),
            "an unaccounted death at the ceiling is a prior, not a kernel statement: {explained}"
        );
        assert!(
            !explained.contains("out-of-memory kill"),
            "nothing may quote accounting this host never produced: {explained}"
        );
    }

    /// A daemon that died with room to spare keeps its own cause.
    ///
    /// Telling a user their commit ran out of memory when it did not is the
    /// same defect as telling them nothing, pointed the other way: both send
    /// them to fix something that is not broken.
    #[test]
    fn a_death_with_headroom_reports_the_phase_and_claims_nothing_about_memory() {
        let marker = abandoned_marker(Some(2 * GIB), Some(2 * GIB));
        let explained = daemon_loss_explanation(
            marker.as_deref(),
            false,
            1_006,
            &evidence(64 * GIB, Some(0)),
        )
        .expect("a dead daemon holding a marker must still be explained");
        assert!(
            explained.contains("reconcile_workspace_and_commit_authority"),
            "the phase is worth reporting whatever killed it: {explained}"
        );
        assert!(
            !explained.contains("ran out of memory"),
            "no measurement supports a memory diagnosis here: {explained}"
        );
    }

    /// No marker is no evidence, and the caller keeps the message it had.
    #[test]
    fn a_lost_reply_with_no_marker_at_all_invents_no_diagnosis() {
        assert!(
            daemon_loss_explanation(None, false, 1_006, &evidence(GIB, Some(9))).is_none(),
            "a kill count alone says nothing about a commit that published no transaction"
        );
    }

    /// A daemon that is still running but stopped beating is wedged, not dead,
    /// and is described as what it is.
    #[test]
    fn a_live_daemon_whose_beat_went_quiet_is_reported_as_wedged_rather_than_gone() {
        let marker = abandoned_marker(Some(3 * GIB), Some(3 * GIB));
        let explained =
            daemon_loss_explanation(marker.as_deref(), true, 1_400, &evidence(64 * GIB, None))
                .expect("a marker with a live pid still explains itself");
        assert!(
            explained.contains("still running but stopped beating 400s ago"),
            "a wedged daemon must not be reported as a dead one: {explained}"
        );
    }

    /// A daemon that could not sample its own memory says so, and is never
    /// reported as having used nothing.
    #[test]
    fn an_unsampled_resident_set_reads_as_absent_and_never_as_zero() {
        let marker = abandoned_marker(None, None);
        let explained =
            daemon_loss_explanation(marker.as_deref(), false, 1_006, &evidence(12 * GIB, None))
                .expect("a dead daemon holding a marker must be explained");
        assert!(
            explained.contains("published no memory reading"),
            "an unsampled reading must be stated as absent: {explained}"
        );
        assert!(
            !explained.contains("0 MiB") && !explained.contains("ran out of memory"),
            "an absent sample must never become a measurement: {explained}"
        );
    }

    #[test]
    fn a_phase_survives_the_ansi_escapes_the_daemon_writes_between_name_and_value() {
        // The exact shape a colored `tracing` line takes: the field name is
        // wrapped in escapes, so `phase="` is not a substring of the raw bytes.
        let raw = "2026-08-17T11:41:56.123Z  INFO kin_daemon::mcp_commit: slow commit phase \
                   \u{1b}[3mphase\u{1b}[0m\u{1b}[2m=\u{1b}[0m\"publish_workspace_admission\" \
                   \u{1b}[3melapsed_ms\u{1b}[0m\u{1b}[2m=\u{1b}[0m85776";
        assert!(
            !raw.contains("phase=\""),
            "the fixture must actually carry the escapes this parse exists for"
        );
        let parsed = parse_phase_line(raw).expect("a phase line must survive its own coloring");
        assert_eq!(parsed.phase, "publish_workspace_admission");
        assert_eq!(parsed.elapsed_ms, Some(85776));
        assert_eq!(parsed.render(), "publish_workspace_admission (85.8s)");
    }

    #[test]
    fn a_line_that_is_not_a_commit_phase_yields_nothing() {
        assert!(parse_phase_line("INFO kin_daemon: daemon is up and ready").is_none());
        assert!(
            parse_phase_line(
                "INFO kin_db::storage::history_replay: validating repository history, 6730 \
                 changes phase=\"git_projection_replay\""
            )
            .is_none(),
            "only the daemon's own commit-phase messages are shown, so an unrelated `phase=` \
             field cannot masquerade as commit progress"
        );
    }

    #[test]
    fn an_in_progress_beat_renders_without_a_completion_time() {
        let parsed = parse_phase_line(
            "INFO kin_daemon::commit_liveness: commit phase in progress \
             phase=\"git_projection_replay\" elapsed_ms=20000",
        )
        .expect("an in-progress beat is a phase line");
        assert_eq!(parsed.render(), "git_projection_replay (20.0s)");
    }

    #[test]
    fn the_tail_starts_at_the_end_so_a_commit_never_replays_the_last_one() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("daemon.log");
        std::fs::write(
            &log,
            "INFO kin_daemon::mcp_commit: slow commit phase phase=\"older_commit\" \
             elapsed_ms=1000\n",
        )
        .unwrap();

        let mut tail = PhaseTail::open(dir.path());
        assert!(tail.poll().is_empty(), "history is not this commit's news");

        append(
            &log,
            "INFO kin_daemon::mcp_commit: slow commit phase phase=\"plan_transaction\" \
             elapsed_ms=27960\n",
        );
        assert_eq!(tail.poll(), vec!["plan_transaction (28.0s)".to_string()]);
    }

    #[test]
    fn a_repeated_beat_on_one_phase_does_not_repeat_a_line() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("daemon.log");
        std::fs::write(&log, "").unwrap();
        let mut tail = PhaseTail::open(dir.path());

        let beat = "INFO kin_daemon::commit_liveness: commit phase in progress \
                    phase=\"publish_workspace_admission\" elapsed_ms=5000\n";
        append(&log, beat);
        assert_eq!(
            tail.poll(),
            vec!["publish_workspace_admission (5.0s)".to_string()]
        );
        append(&log, beat);
        assert!(tail.poll().is_empty());

        append(
            &log,
            "INFO kin_daemon::commit_liveness: commit phase in progress \
             phase=\"publish_workspace_admission\" elapsed_ms=10000\n",
        );
        assert_eq!(
            tail.poll(),
            vec!["publish_workspace_admission (10.0s)".to_string()],
            "a phase that is still running must keep reporting that it is"
        );
    }

    #[test]
    fn a_partial_line_is_held_until_it_is_whole() {
        let dir = tempfile::tempdir().unwrap();
        let log = dir.path().join("daemon.log");
        std::fs::write(&log, "").unwrap();
        let mut tail = PhaseTail::open(dir.path());

        append(
            &log,
            "INFO kin_daemon::mcp_commit: slow commit phase phase=\"pl",
        );
        assert!(
            tail.poll().is_empty(),
            "half a phase name must never be printed as a phase"
        );
        append(&log, "an_transaction\" elapsed_ms=27960\n");
        assert_eq!(tail.poll(), vec!["plan_transaction (28.0s)".to_string()]);
    }

    #[test]
    fn a_transport_failure_reports_the_daemon_death_behind_it() {
        let dir = tempfile::tempdir().unwrap();
        assert!(
            daemon_death_explanation(dir.path()).is_none(),
            "no note means no claim about why anything died"
        );

        kin_daemon_spawn::write_daemon_death_note(
            dir.path(),
            &kin_daemon_spawn::DaemonDeathNote {
                pid: 387,
                killed_by: "kin-supervisor-reaper".to_string(),
                reason: "reaping misbehaving repo daemon: OrphanedUnreachableStalled".to_string(),
                in_flight: Some("commit in phase publish_workspace_admission for 86s".to_string()),
                at: "2026-08-17T11:43:00Z".to_string(),
            },
        );
        let explanation =
            daemon_death_explanation(dir.path()).expect("a note explains the failure");
        assert!(
            explanation.contains("kin-supervisor-reaper"),
            "{explanation}"
        );
        assert!(explanation.contains("daemon.log"), "{explanation}");
        assert!(
            explanation.contains("the change was not recorded"),
            "{explanation}"
        );
    }

    fn append(path: &Path, text: &str) {
        use std::io::Write as _;
        let mut file = std::fs::OpenOptions::new().append(true).open(path).unwrap();
        file.write_all(text.as_bytes()).unwrap();
    }
}
