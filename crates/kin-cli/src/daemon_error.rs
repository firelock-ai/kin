// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The body a daemon returns when it refuses a non-idempotent command.
//!
//! A transport cannot tell a refusal from a half-done write. It sees a status
//! and some bytes, and it cannot know whether a proxy answered, or whether the
//! daemon acted and then failed to report. That is why every non-2xx from a
//! non-idempotent command is treated as indeterminate, and why the caller is
//! told the daemon may already have committed.
//!
//! For an ordinary refusal that is alarming and false. `kin resolve --continue`
//! with conflicts outstanding is a decision the daemon reached and acted on in
//! no way, and it was reported as a possible write.
//!
//! The daemon is the only party that knows. So it says so, in this body, and
//! the transport believes it only where believing it is safe. The field is
//! absent by default and absence means indeterminate, which is today's
//! behaviour: a proxy can strip a field, which is safe, and nothing can add one.

use serde::{Deserialize, Serialize};

/// The JSON schema this body is validated against.
pub const DAEMON_ERROR_SCHEMA: &str = "kin://contracts/daemon-error";

/// One refusal, as the daemon describes it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DaemonErrorBody {
    /// The refusal in the daemon's own words, rendered to the caller verbatim.
    pub message: String,
    /// True only when the daemon raised this refusal before its first authority
    /// write, so nothing was published and a caller may act on that.
    ///
    /// Defaulted, so a daemon that predates this field parses as `false`, which
    /// is the safe answer and today's behaviour.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub refused_before_write: bool,
}

impl DaemonErrorBody {
    /// A refusal raised before anything was written.
    pub fn before_write(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            refused_before_write: true,
        }
    }

    /// A refusal that says nothing about what was written.
    pub fn unknown(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            refused_before_write: false,
        }
    }

    /// Read a refusal out of a response body, or `None` when it is not one.
    ///
    /// `None` covers an older daemon's plain-text body, a proxy's HTML, and a
    /// truncated read, and every one of them means the caller learns nothing
    /// and keeps the indeterminate answer. Unknown fields are refused so a
    /// body shaped like something else cannot be read as this.
    pub fn parse(body: &str) -> Option<Self> {
        serde_json::from_str::<Self>(body).ok()
    }

    /// The body as the daemon puts it on the wire.
    pub fn to_wire(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| self.message.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_absent_marker_reads_as_unknown_rather_than_before_write() {
        let parsed = DaemonErrorBody::parse(r#"{"message":"refused"}"#)
            .expect("a body with only a message is still a refusal body");
        assert!(
            !parsed.refused_before_write,
            "an older daemon says nothing, and nothing must not read as a promise"
        );
    }

    #[test]
    fn a_plain_text_body_is_not_a_refusal_body() {
        assert_eq!(
            DaemonErrorBody::parse("repository projection conflict: tracked path differs"),
            None,
            "today's plain-text refusals must not parse into a marker"
        );
    }

    #[test]
    fn the_marker_survives_a_round_trip_and_is_omitted_when_false() {
        let before = DaemonErrorBody::before_write("nothing was committed");
        let wire = before.to_wire();
        assert!(wire.contains("refused_before_write"));
        assert_eq!(DaemonErrorBody::parse(&wire), Some(before));

        // Omitted rather than written as false, so a body carrying the field at
        // all is a body some daemon meant to set it in.
        let unknown = DaemonErrorBody::unknown("nothing was committed");
        assert!(!unknown.to_wire().contains("refused_before_write"));
        assert_eq!(DaemonErrorBody::parse(&unknown.to_wire()), Some(unknown));
    }
}
