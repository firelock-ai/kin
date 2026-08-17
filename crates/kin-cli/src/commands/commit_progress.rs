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

/// The line a `kin commit` prints after recording a change.
///
/// `kin commit` is not a git commit, and until now nothing said so: the working
/// tree it just committed from stays dirty forever, `git log` never moves, and
/// in a brownfield repository whose CI, hooks and reviewers all read git that
/// reads as a commit that silently did nothing.
pub const AUTHORITY_NOT_GIT_NOTE: &str = "Recorded in Kin authority, not in git — `git status` \
                                          stays dirty until you run `kin eject` or push this \
                                          branch to a Kin remote.";

#[cfg(test)]
mod tests {
    use super::*;

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
