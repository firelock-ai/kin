// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Interposition canary: detect when the VFS shim was silently stripped.
//!
//! kin-vfs serves graph-backed files by interposing libc calls via
//! `DYLD_INSERT_LIBRARIES` (macOS) / `LD_PRELOAD` (Linux). That interposition can
//! be stripped without warning: macOS drops `DYLD_INSERT_LIBRARIES` for
//! SIP-protected, hardened-runtime, or signed binaries, and Linux drops
//! `LD_PRELOAD` across a setuid/re-exec boundary. When it is stripped the shim
//! never loads, the constructor never runs, none of the hooks exist in the
//! process, and **every** syscall hits raw disk. The tool then reads filesystem
//! bytes as if they were graph truth — a trust-contract violation with no error.
//!
//! The fix is a launch-time handshake. Whoever sets up interposition mints a
//! one-time **canary token** and injects it into the child via [`CANARY_ENV`].
//! On successful load the shim announces that token back to the daemon, which
//! records it as confirmed. The launcher then asks for the [`InterposeStatus`]:
//!
//! - token expected AND confirmed       → [`InterposeStatus::Active`] (graph-native)
//! - token expected but NEVER confirmed → [`InterposeStatus::Stripped`] (FAIL LOUD)
//! - no valid token expected            → [`InterposeStatus::NotRequired`]
//!
//! This module is the pure, side-effect-free core of that mechanism. It owns no
//! sockets and touches no filesystem, so it is unit-testable without the shim's
//! own libc overrides interfering (a tempdir test inside the shim would hit the
//! shim's hooked `open`/`access` and fail with EACCES).

use std::collections::HashSet;

use parking_lot::Mutex;

/// Environment variable carrying the launch-time canary token, injected by the
/// launcher into a child it starts under interposition. Its presence means
/// "interposition is required for this process; the shim must confirm it."
pub const CANARY_ENV: &str = "KIN_VFS_CANARY";

/// Environment variable the shim sets **in its own process** once it has loaded
/// and activated. An in-process self-check can read it to confirm the shim is
/// live; its absence (when [`CANARY_ENV`] was set) means the shim was stripped.
pub const INTERPOSE_ACTIVE_ENV: &str = "KIN_VFS_INTERPOSE_ACTIVE";

/// Maximum accepted canary-token length. Tokens are launcher-minted nonces;
/// this is a sanity bound, not a security boundary.
const MAX_TOKEN_LEN: usize = 128;

/// Outcome of comparing what interposition was expected against what was
/// confirmed. `Active`/`NotRequired` are graph-native-safe; `Stripped` is the
/// fail-loud case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterposeStatus {
    /// Interposition was expected and the shim confirmed it loaded. The process
    /// is graph-native.
    Active,
    /// Interposition was expected but never confirmed — the shim was stripped
    /// (SIP / hardened / signed binary / re-exec). The process is reading raw
    /// disk and must FAIL LOUD instead of being trusted as graph truth.
    Stripped,
    /// No valid canary token was expected, so interposition was not required of
    /// this process. Nothing to fail about.
    NotRequired,
}

impl InterposeStatus {
    /// True when the process can be trusted as graph-native (or interposition
    /// was simply not required).
    pub fn is_graph_native(self) -> bool {
        matches!(self, InterposeStatus::Active | InterposeStatus::NotRequired)
    }

    /// True only for the stripped-interposition fail-loud case.
    pub fn is_stripped(self) -> bool {
        matches!(self, InterposeStatus::Stripped)
    }
}

/// Whether `token` is a well-formed canary token: non-empty after trimming,
/// within [`MAX_TOKEN_LEN`], and restricted to URL-safe nonce characters. An
/// empty or malformed token must NOT count as "expected" — otherwise a stray
/// blank `KIN_VFS_CANARY=` would be flagged `Stripped` forever (a false alarm).
pub fn is_valid_token(token: &str) -> bool {
    let t = token.trim();
    !t.is_empty()
        && t.len() <= MAX_TOKEN_LEN
        && t.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Trim and validate a raw token source, yielding the canonical token only when
/// it is well-formed. `None`/blank/malformed all collapse to `None` ("no token
/// expected"), so the trim is applied identically on both the announce and
/// verdict sides — a token never mismatches itself across whitespace.
pub fn normalize_token(raw: Option<&str>) -> Option<String> {
    let t = raw?.trim();
    if is_valid_token(t) {
        Some(t.to_string())
    } else {
        None
    }
}

/// The pure verdict: given the token interposition was expected to confirm and
/// whether the daemon observed that confirmation, classify the process.
///
/// A malformed/blank expected token is treated as "not expected"
/// ([`InterposeStatus::NotRequired`]) so a misconfigured environment can never
/// manufacture a false `Stripped`.
pub fn interpose_verdict(expected_token: Option<&str>, confirmed: bool) -> InterposeStatus {
    match normalize_token(expected_token) {
        Some(_) if confirmed => InterposeStatus::Active,
        Some(_) => InterposeStatus::Stripped,
        None => InterposeStatus::NotRequired,
    }
}

/// Build the loud diagnostic for a stripped-interposition process. Names the
/// offending process and spells out that it is reading raw disk, so the failure
/// is observable instead of silently serving filesystem bytes as graph truth.
pub fn stripped_error_message(process: &str) -> String {
    format!(
        "kin-vfs: interposition STRIPPED for `{process}` — the VFS shim did not load \
         (DYLD_INSERT_LIBRARIES / LD_PRELOAD dropped by SIP, a hardened or signed \
         binary, or a re-exec). This process is NOT graph-native: it is reading raw \
         disk and bypassing graph truth. Re-run it through the FUSE/NFS projection or \
         an unrestricted binary, or set KIN_VFS_DISABLE=1 to explicitly acknowledge \
         raw-disk mode."
    )
}

/// Daemon-side ledger of interposition canaries.
///
/// The launcher records the token it injected with [`expect`](Self::expect); the
/// shim's announce handshake records [`confirm`](Self::confirm). A token that was
/// expected but never confirmed identifies a process whose interposition was
/// stripped. All operations are pure in-memory set arithmetic behind a mutex —
/// no sockets, no filesystem — so the detection logic is testable in isolation.
#[derive(Default)]
pub struct CanaryRegistry {
    inner: Mutex<RegistryInner>,
}

#[derive(Default)]
struct RegistryInner {
    expected: HashSet<String>,
    confirmed: HashSet<String>,
}

impl CanaryRegistry {
    /// Create an empty registry.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record that the launcher expects `token` to be confirmed (it injected
    /// `KIN_VFS_CANARY=token` into a child launched under interposition).
    /// Returns `false` (and records nothing) if the token is malformed.
    pub fn expect(&self, token: &str) -> bool {
        match normalize_token(Some(token)) {
            Some(t) => {
                self.inner.lock().expected.insert(t);
                true
            }
            None => false,
        }
    }

    /// Record a shim announcement: interposition is confirmed for `token`.
    /// Returns `false` (and records nothing) if the token is malformed.
    pub fn confirm(&self, token: &str) -> bool {
        match normalize_token(Some(token)) {
            Some(t) => {
                self.inner.lock().confirmed.insert(t);
                true
            }
            None => false,
        }
    }

    /// Whether `token` has been confirmed by a shim announcement.
    pub fn is_confirmed(&self, token: &str) -> bool {
        match normalize_token(Some(token)) {
            Some(t) => self.inner.lock().confirmed.contains(&t),
            None => false,
        }
    }

    /// Classify a token the launcher expected: [`InterposeStatus::Active`] if it
    /// was confirmed, [`InterposeStatus::Stripped`] if not, or
    /// [`InterposeStatus::NotRequired`] when `expected_token` is absent/malformed.
    pub fn verdict(&self, expected_token: Option<&str>) -> InterposeStatus {
        let confirmed = match normalize_token(expected_token) {
            Some(t) => self.inner.lock().confirmed.contains(&t),
            None => false,
        };
        interpose_verdict(expected_token, confirmed)
    }

    /// Tokens that were expected but never confirmed — i.e. the processes whose
    /// interposition was stripped. The launcher fails these loud.
    pub fn stripped_tokens(&self) -> Vec<String> {
        let guard = self.inner.lock();
        guard
            .expected
            .difference(&guard.confirmed)
            .cloned()
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_validation_rejects_blank_and_malformed() {
        assert!(is_valid_token("abc123"));
        assert!(is_valid_token("kin-canary_42"));
        assert!(!is_valid_token(""));
        assert!(!is_valid_token("   "));
        // Spaces / control / punctuation outside the nonce charset are rejected.
        assert!(!is_valid_token("has space"));
        assert!(!is_valid_token("semi;colon"));
        // Over-length is rejected.
        assert!(!is_valid_token(&"a".repeat(MAX_TOKEN_LEN + 1)));
        assert!(is_valid_token(&"a".repeat(MAX_TOKEN_LEN)));
    }

    #[test]
    fn normalize_trims_and_filters() {
        assert_eq!(normalize_token(Some("  tok-1 ")).as_deref(), Some("tok-1"));
        assert_eq!(normalize_token(Some("")), None);
        assert_eq!(normalize_token(Some("   ")), None);
        assert_eq!(normalize_token(None), None);
        assert_eq!(normalize_token(Some("bad token")), None);
    }

    #[test]
    fn verdict_matrix() {
        // Expected + confirmed -> Active (graph-native).
        assert_eq!(interpose_verdict(Some("t"), true), InterposeStatus::Active);
        // Expected + NOT confirmed -> Stripped (fail loud).
        assert_eq!(
            interpose_verdict(Some("t"), false),
            InterposeStatus::Stripped
        );
        // No token expected -> NotRequired regardless of confirmation.
        assert_eq!(interpose_verdict(None, false), InterposeStatus::NotRequired);
        assert_eq!(interpose_verdict(None, true), InterposeStatus::NotRequired);
        // A blank/malformed expected token must never become a false Stripped.
        assert_eq!(
            interpose_verdict(Some("   "), false),
            InterposeStatus::NotRequired
        );
        assert_eq!(
            interpose_verdict(Some("bad token"), false),
            InterposeStatus::NotRequired
        );
    }

    #[test]
    fn status_classifiers() {
        assert!(InterposeStatus::Active.is_graph_native());
        assert!(InterposeStatus::NotRequired.is_graph_native());
        assert!(!InterposeStatus::Stripped.is_graph_native());
        assert!(InterposeStatus::Stripped.is_stripped());
        assert!(!InterposeStatus::Active.is_stripped());
    }

    #[test]
    fn registry_confirm_makes_token_active() {
        let reg = CanaryRegistry::new();
        reg.expect("tok-active");
        // Before the announce, an expected-but-unconfirmed token is Stripped.
        assert_eq!(reg.verdict(Some("tok-active")), InterposeStatus::Stripped);
        assert!(!reg.is_confirmed("tok-active"));

        // The shim announces -> token becomes Active.
        assert!(reg.confirm("tok-active"));
        assert!(reg.is_confirmed("tok-active"));
        assert_eq!(reg.verdict(Some("tok-active")), InterposeStatus::Active);
    }

    #[test]
    fn registry_whitespace_insensitive_match() {
        let reg = CanaryRegistry::new();
        // Confirm with surrounding whitespace; verdict queried with the bare
        // token must still see it (both sides normalize identically).
        reg.confirm("  spaced-tok ");
        assert_eq!(reg.verdict(Some("spaced-tok")), InterposeStatus::Active);
    }

    #[test]
    fn registry_stripped_tokens_lists_only_unconfirmed() {
        let reg = CanaryRegistry::new();
        reg.expect("confirmed-one");
        reg.expect("stripped-one");
        reg.expect("stripped-two");
        reg.confirm("confirmed-one");
        // A confirm with no matching expect is fine and does not appear stripped.
        reg.confirm("unexpected-extra");

        let mut stripped = reg.stripped_tokens();
        stripped.sort();
        assert_eq!(stripped, vec!["stripped-one", "stripped-two"]);
    }

    #[test]
    fn registry_rejects_malformed_tokens() {
        let reg = CanaryRegistry::new();
        assert!(!reg.expect(""));
        assert!(!reg.confirm("bad token"));
        assert!(reg.stripped_tokens().is_empty());
        // Malformed verdict query collapses to NotRequired, never Stripped.
        assert_eq!(reg.verdict(Some("")), InterposeStatus::NotRequired);
    }

    #[test]
    fn stripped_message_is_loud_and_names_process() {
        let msg = stripped_error_message("ripgrep");
        assert!(msg.contains("ripgrep"));
        assert!(msg.contains("STRIPPED"));
        assert!(msg.contains("raw disk"));
        assert!(msg.contains("NOT graph-native"));
    }
}
