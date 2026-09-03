// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! What the CLI says when a command ran out of open file descriptors.
//!
//! Kin raises its own open-file soft limit at startup
//! ([`kin_core::file_limit`]), so on almost every machine this never fires. It
//! exists for the machine where the raise could not help: a hard limit already
//! at the soft limit, which no unprivileged process can lift.
//!
//! What the user saw before this existed was the raw kernel refusal, wrapped in
//! whichever storage call happened to be holding it:
//!
//! ```text
//! graph error: storage error: failed to clone retained repository directory
//! /path/.kin.init-.../kindb/...: Too many open files (os error 24)
//! ```
//!
//! That names a descriptor and a UUID, and neither is the problem or the fix.
//! The limit is the problem, its value is the missing fact, and `ulimit` is the
//! fix, so those are what this prints.
//!
//! Detection reads the error two ways because the error arrives two ways. A
//! failure that is still an `io::Error` somewhere in its chain is matched on its
//! `errno`, which is exact. A failure that came up through the storage layer is
//! not: that layer renders the cause into its message string and returns a typed
//! error carrying text, so by the time it reaches here the only evidence left is
//! the sentence. Matching the sentence is weaker than matching a code, and it is
//! what the shape allows without a change in another repository.

use kin_core::file_limit::{OpenFileLimit, TARGET_OPEN_FILES};

/// The `errno` values that mean "no more descriptors": this process's limit,
/// and the whole machine's.
#[cfg(unix)]
const DESCRIPTOR_EXHAUSTION_CODES: &[i32] = &[libc::EMFILE, libc::ENFILE];

/// Nothing to match structurally off Unix, where this module's advice does not
/// apply either. The rendered form below still answers.
#[cfg(not(unix))]
const DESCRIPTOR_EXHAUSTION_CODES: &[i32] = &[];

/// The sentence the storage layer leaves behind once it has flattened the
/// `io::Error` that caused it into text.
const DESCRIPTOR_EXHAUSTION_TEXT: &str = "Too many open files";

/// The guidance to print after this error, or `None` when it was not descriptor
/// exhaustion.
pub fn remedy(error: &anyhow::Error) -> Option<String> {
    is_descriptor_exhaustion(error).then(|| remedy_text(kin_core::file_limit::open_file_limit()))
}

/// Whether this error, anywhere in its chain, is the kernel refusing to open
/// another file.
fn is_descriptor_exhaustion(error: &anyhow::Error) -> bool {
    let structural = error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .and_then(std::io::Error::raw_os_error)
            .is_some_and(|code| DESCRIPTOR_EXHAUSTION_CODES.contains(&code))
    });
    structural || rendered_names_descriptor_exhaustion(&format!("{error:?}"))
}

/// Whether a rendered error chain names descriptor exhaustion in words.
///
/// Split out so the text rule is testable against a real rendered message
/// rather than only against an error this test could construct.
fn rendered_names_descriptor_exhaustion(rendered: &str) -> bool {
    rendered.contains(DESCRIPTOR_EXHAUSTION_TEXT)
}

/// The guidance itself: what ran out, what the limit is now, and the one
/// command that changes it.
fn remedy_text(limit: Option<OpenFileLimit>) -> String {
    let mut text = String::from("kin: ran out of open file descriptors.\n");
    if let Some(limit) = limit {
        let hard = match limit.hard {
            Some(hard) => hard.to_string(),
            None => "unlimited".to_string(),
        };
        text.push_str(&format!(
            "  open files: soft limit {}, hard limit {hard}.\n",
            limit.soft
        ));
        if limit.hard == Some(limit.soft) {
            text.push_str(
                "  Kin raises the soft limit at startup and cannot go past the hard limit.\n",
            );
        }
    }
    text.push_str(&format!(
        "  Raise it for this shell with `ulimit -n {TARGET_OPEN_FILES}`, then run the command again.\n"
    ));
    #[cfg(target_os = "macos")]
    text.push_str(&format!(
        "  Raise it for the machine with `sudo launchctl limit maxfiles {TARGET_OPEN_FILES} unlimited`.\n"
    ));
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact message the failing admission produced on a stock macOS
    /// limit, copied from a run of kin 0.6.3 at `ulimit -Sn 256`. This is the
    /// input the textual rule exists for: no `io::Error` survives in it.
    const MEASURED_ADMISSION_FAILURE: &str = "admit exact reachable Git repository authority\n\n\
Caused by:\n    graph error: storage error: failed to clone retained repository directory \
/tmp/repos/.kin.init-0b94609a/kindb/d14ae4e8: Too many open files (os error 24)";

    #[test]
    fn the_measured_admission_failure_is_recognized() {
        assert!(rendered_names_descriptor_exhaustion(
            MEASURED_ADMISSION_FAILURE
        ));
    }

    #[test]
    fn an_unrelated_failure_is_not_recognized() {
        assert!(!rendered_names_descriptor_exhaustion(
            "storage error: failed to clone retained repository directory /tmp/x: \
Permission denied (os error 13)"
        ));
        assert!(!rendered_names_descriptor_exhaustion("the disk is full"));
    }

    /// Unix only: the structural rule matches an `errno`, and `EMFILE` means
    /// something else on a platform that does not define it this way.
    #[cfg(unix)]
    #[test]
    fn an_io_error_carrying_the_errno_is_recognized_through_its_context() {
        use anyhow::Context as _;

        let error = Err::<(), _>(std::io::Error::from_raw_os_error(libc::EMFILE))
            .context("copy Git objects")
            .expect_err("build a wrapped descriptor-exhaustion error");
        assert!(is_descriptor_exhaustion(&error));
        assert!(remedy(&error).is_some());
    }

    #[test]
    fn an_unrelated_error_gets_no_remedy() {
        let error = anyhow::anyhow!("refused: the workspace has uncommitted changes");
        assert!(!is_descriptor_exhaustion(&error));
        assert!(remedy(&error).is_none());
    }

    /// The remedy has to carry the three facts the raw kernel message did not:
    /// what ran out, the number in force, and the command that changes it.
    #[test]
    fn the_remedy_names_the_limit_its_value_and_the_command() {
        let text = remedy_text(Some(OpenFileLimit {
            soft: 256,
            hard: Some(256),
        }));
        assert!(text.contains("open file"), "{text}");
        assert!(text.contains("256"), "{text}");
        assert!(text.contains("ulimit -n 10240"), "{text}");
        assert!(
            text.contains("cannot go past the hard limit"),
            "a limit pinned at its ceiling did not say so: {text}"
        );
    }

    /// A machine that still has headroom must not be told Kin gave up on a
    /// ceiling it never hit.
    #[test]
    fn a_limit_below_its_ceiling_does_not_blame_the_hard_limit() {
        let text = remedy_text(Some(OpenFileLimit {
            soft: 256,
            hard: None,
        }));
        assert!(text.contains("unlimited"), "{text}");
        assert!(!text.contains("cannot go past the hard limit"), "{text}");
    }

    /// A platform that cannot report its limit still gets the remedy, without
    /// a line that would have to invent a number.
    #[test]
    fn an_unreadable_limit_still_yields_the_command() {
        let text = remedy_text(None);
        assert!(text.contains("ulimit -n 10240"), "{text}");
        assert!(!text.contains("soft limit"), "{text}");
    }
}
