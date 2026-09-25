// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Client-side outcome of a cross-repo spine query.
//!
//! Every spine client (the CLI `kin xref`/impact path, the MCP handlers, and
//! any future consumer) talks to the daemon's `/spine/*` endpoints over HTTP.
//! Those calls have three meaningfully different outcomes that must NOT be
//! collapsed into a single "empty" result:
//!
//! 1. **Not configured** — no daemon endpoint in this context (e.g. a
//!    standalone, local-only MCP server with no `KIN_DAEMON_URL`). Cross-repo
//!    federation simply does not apply here, so a quiet absence of cross-repo
//!    data is correct and must stay non-noisy.
//! 2. **Unavailable** — a daemon endpoint IS configured but the query failed:
//!    the request errored, returned a non-success status (e.g. `503` when the
//!    spine is disabled), or returned a malformed body. This is a real gap and
//!    must be surfaced, never reported as "no cross-repo references".
//! 3. **Found** — a healthy spine answered. The payload may be legitimately
//!    empty (genuinely no cross-repo edges), which is an explicit, trustworthy
//!    empty result distinct from case 2.
//!
//! Collapsing (2) into (3) is the silent-degradation bug this type removes: it
//! is the cross-repo analogue of the graph-first rule "fail loud or report the
//! gap; do not hide it behind a fallback".

/// The outcome of a client spine query carrying a parsed body `T` on success.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpineQuery<T> {
    /// No spine endpoint is configured in this context — local-only; quiet.
    NotConfigured,
    /// A spine endpoint is configured but the query failed (transport error,
    /// non-success status, or malformed response). Carries a human reason.
    Unavailable(String),
    /// A healthy spine answered. `T` may be empty (an explicit empty result).
    Found(T),
}

/// Body-agnostic classification of a spine HTTP probe, separated from response
/// parsing so the local-only / unavailable / healthy distinction is identical
/// across clients and unit-testable without a live daemon.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpineProbe {
    /// No endpoint configured (`configured == false`).
    NotConfigured,
    /// Configured but the probe did not yield a success status.
    Unavailable(String),
    /// Configured and the endpoint returned a success (2xx) status.
    Healthy,
}

/// Classify a spine probe from whether an endpoint is configured and the HTTP
/// status it returned (`None` = the request never produced a response, e.g. a
/// transport error). Pure: no I/O, no environment, no body type — the single
/// place the three-state distinction is decided.
pub fn classify_spine_probe(configured: bool, status: Option<u16>) -> SpineProbe {
    if !configured {
        return SpineProbe::NotConfigured;
    }
    match status {
        Some(code) if (200..300).contains(&code) => SpineProbe::Healthy,
        Some(code) => SpineProbe::Unavailable(format!("spine returned HTTP {code}")),
        None => SpineProbe::Unavailable("spine request failed (no response)".to_string()),
    }
}

/// The daemon's own spine as one read found it, for a handler that consults it
/// in-process rather than over `/spine/*`.
///
/// The daemon builds its spine on first use, and a pass that finds a writer
/// holding graph authority steps aside rather than publish a capture its root
/// does not back. The read that asked then has no spine to consult, and neither
/// does a read on a daemon whose spine is switched off. The two are opposite
/// facts. A spine that is off means cross-repo authority does not apply to this
/// install. A deferred one means it applies and has not been established yet,
/// so an answer read in that window lacks whatever other repositories would
/// have added to it. One `None` for both is how such an answer came to report
/// `not_configured` and certify.
#[derive(Clone, Copy)]
pub enum DaemonSpine<'a> {
    /// A spine built and proved for this read.
    Ready(&'a dyn crate::SpineBackend),
    /// No spine, because its initialization stepped aside while graph authority
    /// was changing. Carries the reason the daemon recorded. A later read
    /// retries the initialization.
    Deferred(&'a str),
    /// No spine, because it refused this repository's graph for a standing
    /// reason a drained writer does not change. Carries the reason the daemon
    /// recorded, which opens with [`SPINE_CANDIDATE_REPRESENTATION_GAP`].
    Refused(&'a str),
    /// No spine and none pending: the spine is switched off.
    Absent,
}

/// The code a daemon opens its recorded reason with when the spine refuses a
/// graph that holds an inferred member, whose candidate authority the spine
/// format cannot carry. The refusal stands for as long as the graph holds the
/// member.
pub const SPINE_CANDIDATE_REPRESENTATION_GAP: &str = "spine_candidate_representation_gap";

impl<'a> DaemonSpine<'a> {
    /// Classify one read's spine from what its read-authority acquisition
    /// returned and the reason the daemon recorded for having none.
    ///
    /// A spine in hand wins. A reason an earlier pass recorded says nothing
    /// about a read that got a spine. A reason that opens with
    /// [`SPINE_CANDIDATE_REPRESENTATION_GAP`] is a refusal, and any other is a
    /// deferral.
    pub fn from_read(
        backend: Option<&'a dyn crate::SpineBackend>,
        reason: Option<&'a str>,
    ) -> Self {
        match (backend, reason) {
            (Some(backend), _) => Self::Ready(backend),
            (None, Some(reason)) if reason.starts_with(SPINE_CANDIDATE_REPRESENTATION_GAP) => {
                Self::Refused(reason)
            }
            (None, Some(reason)) => Self::Deferred(reason),
            (None, None) => Self::Absent,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_spine_in_hand_wins_over_a_recorded_deferral() {
        // An earlier pass's deferral must not demote a read that got a spine,
        // and only a read with neither a spine nor a deferral is absent.
        let backend = crate::InMemorySpineBackend::new();
        assert!(matches!(
            DaemonSpine::from_read(Some(&backend), Some("an earlier pass stepped aside")),
            DaemonSpine::Ready(_)
        ));
        assert!(matches!(
            DaemonSpine::from_read(None, Some("a writer held graph authority")),
            DaemonSpine::Deferred("a writer held graph authority")
        ));
        assert!(matches!(
            DaemonSpine::from_read(None, None),
            DaemonSpine::Absent
        ));
    }

    #[test]
    fn a_standing_refusal_is_told_apart_from_a_deferral() {
        let refusal = "spine_candidate_representation_gap: repo r contains inferred member m";
        assert!(matches!(
            DaemonSpine::from_read(None, Some(refusal)),
            DaemonSpine::Refused(reason) if reason == refusal
        ));
        // A spine in hand still wins over a refusal an earlier pass recorded.
        let backend = crate::InMemorySpineBackend::new();
        assert!(matches!(
            DaemonSpine::from_read(Some(&backend), Some(refusal)),
            DaemonSpine::Ready(_)
        ));
    }

    #[test]
    fn unconfigured_is_quiet_regardless_of_status() {
        // State 1: no endpoint configured -> NotConfigured even if a status is
        // somehow present. Local-only stays quiet.
        assert_eq!(classify_spine_probe(false, None), SpineProbe::NotConfigured);
        assert_eq!(
            classify_spine_probe(false, Some(200)),
            SpineProbe::NotConfigured
        );
    }

    #[test]
    fn configured_non_success_is_unavailable_not_empty() {
        // State 2: configured but 503 (spine disabled) / 5xx / transport error
        // -> Unavailable, never silently treated as "no references".
        assert!(matches!(
            classify_spine_probe(true, Some(503)),
            SpineProbe::Unavailable(_)
        ));
        assert!(matches!(
            classify_spine_probe(true, Some(500)),
            SpineProbe::Unavailable(_)
        ));
        // No response at all (transport failure) is also Unavailable, not empty.
        assert!(matches!(
            classify_spine_probe(true, None),
            SpineProbe::Unavailable(_)
        ));
    }

    #[test]
    fn configured_success_is_healthy() {
        // State 3: a healthy spine answered (2xx). Whether the body is empty is
        // then an explicit, trustworthy empty result decided by the caller.
        assert_eq!(classify_spine_probe(true, Some(200)), SpineProbe::Healthy);
        assert_eq!(classify_spine_probe(true, Some(204)), SpineProbe::Healthy);
    }

    #[test]
    fn unavailable_reason_names_the_status() {
        // The surfaced reason must identify the failure so it is actionable and
        // distinguishable from a genuine empty result.
        match classify_spine_probe(true, Some(503)) {
            SpineProbe::Unavailable(reason) => assert!(reason.contains("503"), "reason: {reason}"),
            other => panic!("expected Unavailable, got {other:?}"),
        }
    }
}
