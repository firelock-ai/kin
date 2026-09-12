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
//! Loading is necessary but not sufficient. Interposition covers a fixed roster
//! of libc symbols, and a workspace file reached through a surface outside that
//! roster is served from raw disk by a process whose shim loaded perfectly. A
//! verdict built only from the load handshake reports [`InterposeStatus::Active`]
//! for that run, which is a guard that cannot fail: it answers "did the shim
//! load" while claiming to answer "were these reads graph-native".
//!
//! So the shim also reports the bypasses it can observe. When a hook resolves a
//! workspace-owned path that the real filesystem is about to answer, it records
//! the surface against the launch token, and the verdict becomes
//! [`InterposeStatus::Bypassed`] — red, and named by surface, whatever the load
//! handshake said. The roster of observable surfaces is a roster: a class the
//! shim never sees cannot be reported, so the surfaces it does see must be.
//!
//! This module is the pure, side-effect-free core of that mechanism. It owns no
//! sockets and touches no filesystem, so it is unit-testable without the shim's
//! own libc overrides interfering (a tempdir test inside the shim would hit the
//! shim's hooked `open`/`access` and fail with EACCES).

use std::collections::{BTreeSet, HashMap, HashSet};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

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

/// Maximum accepted length of a reported bypass surface name.
const MAX_SURFACE_LEN: usize = 64;

/// Maximum distinct surfaces retained per token. The verdict only needs to know
/// *that* a class bypassed, so a bound keeps one looping process from growing
/// the daemon's ledger without limit. Reaching it cannot hide a bypass: the
/// token is already red by the first entry.
const MAX_SURFACES_PER_TOKEN: usize = 16;

/// Outcome of comparing what interposition was expected against what was
/// confirmed and observed. `Active`/`NotRequired` are graph-native-safe;
/// `Stripped` and `Bypassed` are the fail-loud cases.
///
/// Wire type: variants are appended, never reordered, so an older peer keeps
/// decoding the variants it already knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InterposeStatus {
    /// Interposition was expected, the shim confirmed it loaded, and no bypass
    /// was observed. The process is graph-native.
    Active,
    /// Interposition was expected but never confirmed — the shim was stripped
    /// (SIP / hardened / signed binary / re-exec). The process is reading raw
    /// disk and must FAIL LOUD instead of being trusted as graph truth.
    Stripped,
    /// No valid canary token was expected, so interposition was not required of
    /// this process. Nothing to fail about.
    NotRequired,
    /// The shim loaded, but at least one workspace-owned path was answered by
    /// the real filesystem through a surface interposition does not cover. Some
    /// of this run's reads were raw disk, so it is not graph-native.
    Bypassed,
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

    /// True only when a workspace path was observed being served from raw disk.
    pub fn is_bypassed(self) -> bool {
        matches!(self, InterposeStatus::Bypassed)
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

/// Trim and validate a reported bypass surface name (`fopen`, `freopen`, …).
///
/// Surfaces are shim-minted identifiers, not user text. Restricting them to a
/// short ASCII identifier charset keeps a malformed report out of the ledger
/// and out of the operator-facing message built from it.
pub fn normalize_surface(raw: &str) -> Option<String> {
    let surface = raw.trim();
    let well_formed = !surface.is_empty()
        && surface.len() <= MAX_SURFACE_LEN
        && surface
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    well_formed.then(|| surface.to_string())
}

/// The pure verdict: given the token interposition was expected to confirm and
/// whether the daemon observed that confirmation, classify the process.
///
/// A malformed/blank expected token is treated as "not expected"
/// ([`InterposeStatus::NotRequired`]) so a misconfigured environment can never
/// manufacture a false `Stripped`.
pub fn interpose_verdict(expected_token: Option<&str>, confirmed: bool) -> InterposeStatus {
    interpose_verdict_with_bypass(expected_token, confirmed, false)
}

/// The full verdict, including whether any bypass was observed for the token.
///
/// `Stripped` outranks `Bypassed`: a shim that never loaded served *every* read
/// from raw disk, which is the larger claim, and it explains the missing
/// confirmation rather than leaving it unaccounted for. A confirmed load with
/// an observed bypass is `Bypassed`, never `Active` — the load handshake alone
/// must not be able to certify a run whose reads went to disk.
pub fn interpose_verdict_with_bypass(
    expected_token: Option<&str>,
    confirmed: bool,
    bypassed: bool,
) -> InterposeStatus {
    match normalize_token(expected_token) {
        Some(_) if !confirmed => InterposeStatus::Stripped,
        Some(_) if bypassed => InterposeStatus::Bypassed,
        Some(_) => InterposeStatus::Active,
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

/// Build the loud diagnostic for a run that reached workspace files through a
/// surface interposition does not cover. Names the process and the surfaces, so
/// the operator learns which reads were raw disk instead of being told the run
/// was graph-native.
pub fn bypassed_error_message(process: &str, surfaces: &[String]) -> String {
    let named = if surfaces.is_empty() {
        "an uninterposed surface".to_string()
    } else {
        surfaces.join(", ")
    };
    format!(
        "kin-vfs: interposition BYPASSED for `{process}` — the VFS shim loaded, but \
         workspace files were read through {named}, which interposition does not \
         cover. Those reads returned raw disk bytes, not graph truth, so this run is \
         NOT graph-native. Re-run it through the FUSE/NFS projection, use a tool that \
         reads through the interposed syscalls, or set KIN_VFS_DISABLE=1 to explicitly \
         acknowledge raw-disk mode."
    )
}

/// Daemon-side ledger of interposition canaries.
///
/// The launcher records the token it injected with [`expect`](Self::expect); the
/// shim's announce handshake records [`confirm`](Self::confirm), and each
/// observed raw-disk answer for a workspace path records a
/// [`bypass`](Self::record_bypass). A token that was expected but never
/// confirmed identifies a process whose interposition was stripped; a confirmed
/// token carrying bypasses identifies one whose shim loaded and was routed
/// around anyway. All operations are pure in-memory set arithmetic behind a
/// mutex — no sockets, no filesystem — so the detection logic is testable in
/// isolation.
#[derive(Default)]
pub struct CanaryRegistry {
    inner: Mutex<RegistryInner>,
}

#[derive(Default)]
struct RegistryInner {
    expected: HashSet<String>,
    confirmed: HashSet<String>,
    /// Token → the surfaces observed serving a workspace path from raw disk.
    /// Ordered so the operator-facing message is stable across runs.
    bypassed: HashMap<String, BTreeSet<String>>,
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

    /// Record that `surface` served a workspace-owned path from raw disk in the
    /// process holding `token`. Returns `false` (and records nothing) if either
    /// value is malformed, so a garbled report cannot turn a clean run red.
    ///
    /// A bypass is recorded even when no launcher expected the token: the
    /// process still read disk bytes for a graph-owned path, and a later
    /// verdict query for that token must see it.
    pub fn record_bypass(&self, token: &str, surface: &str) -> bool {
        let (Some(token), Some(surface)) =
            (normalize_token(Some(token)), normalize_surface(surface))
        else {
            return false;
        };
        let mut guard = self.inner.lock();
        let surfaces = guard.bypassed.entry(token).or_default();
        if surfaces.len() >= MAX_SURFACES_PER_TOKEN && !surfaces.contains(&surface) {
            // Already red, and the roster is bounded. Drop the extra name
            // rather than the verdict.
            return true;
        }
        surfaces.insert(surface);
        true
    }

    /// The surfaces recorded as having served raw disk for `token`, in stable
    /// order. Empty when the token is malformed or nothing bypassed.
    pub fn bypassed_surfaces(&self, token: &str) -> Vec<String> {
        match normalize_token(Some(token)) {
            Some(t) => self
                .inner
                .lock()
                .bypassed
                .get(&t)
                .map(|surfaces| surfaces.iter().cloned().collect())
                .unwrap_or_default(),
            None => Vec::new(),
        }
    }

    /// Classify a token the launcher expected: [`InterposeStatus::Stripped`] if
    /// it was never confirmed, [`InterposeStatus::Bypassed`] if it was confirmed
    /// but a surface served raw disk, [`InterposeStatus::Active`] if confirmed
    /// and clean, or [`InterposeStatus::NotRequired`] when `expected_token` is
    /// absent/malformed.
    pub fn verdict(&self, expected_token: Option<&str>) -> InterposeStatus {
        let (confirmed, bypassed) = match normalize_token(expected_token) {
            Some(t) => {
                let guard = self.inner.lock();
                (
                    guard.confirmed.contains(&t),
                    guard.bypassed.contains_key(&t),
                )
            }
            None => (false, false),
        };
        interpose_verdict_with_bypass(expected_token, confirmed, bypassed)
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

        // A bypassed run is not graph-native and is not the stripped case.
        assert!(!InterposeStatus::Bypassed.is_graph_native());
        assert!(!InterposeStatus::Bypassed.is_stripped());
        assert!(InterposeStatus::Bypassed.is_bypassed());
        assert!(!InterposeStatus::Active.is_bypassed());
    }

    #[test]
    fn a_confirmed_load_does_not_certify_a_bypassed_run() {
        // The load handshake alone cannot answer "were these reads graph-native".
        assert_eq!(
            interpose_verdict_with_bypass(Some("t"), true, false),
            InterposeStatus::Active
        );
        assert_eq!(
            interpose_verdict_with_bypass(Some("t"), true, true),
            InterposeStatus::Bypassed
        );
        // Stripped outranks bypassed: nothing loaded, so every read was disk.
        assert_eq!(
            interpose_verdict_with_bypass(Some("t"), false, true),
            InterposeStatus::Stripped
        );
        // No token expected stays NotRequired even with a stray bypass report.
        assert_eq!(
            interpose_verdict_with_bypass(None, true, true),
            InterposeStatus::NotRequired
        );
    }

    #[test]
    fn surface_validation_rejects_blank_and_malformed() {
        assert_eq!(normalize_surface(" fopen ").as_deref(), Some("fopen"));
        assert_eq!(normalize_surface("freopen").as_deref(), Some("freopen"));
        assert_eq!(normalize_surface(""), None);
        assert_eq!(normalize_surface("   "), None);
        assert_eq!(normalize_surface("has space"), None);
        assert_eq!(normalize_surface("path/traversal"), None);
        assert_eq!(normalize_surface(&"a".repeat(MAX_SURFACE_LEN + 1)), None);
    }

    #[test]
    fn registry_bypass_turns_a_confirmed_token_red() {
        let reg = CanaryRegistry::new();
        reg.expect("tok-bypass");
        reg.confirm("tok-bypass");
        assert_eq!(reg.verdict(Some("tok-bypass")), InterposeStatus::Active);

        assert!(reg.record_bypass("tok-bypass", "fopen"));
        assert_eq!(reg.verdict(Some("tok-bypass")), InterposeStatus::Bypassed);
        assert_eq!(reg.bypassed_surfaces("tok-bypass"), vec!["fopen"]);

        // Surfaces accumulate, deduplicate, and report in stable order.
        reg.record_bypass("tok-bypass", "freopen");
        reg.record_bypass("tok-bypass", "fopen");
        assert_eq!(
            reg.bypassed_surfaces("tok-bypass"),
            vec!["fopen", "freopen"]
        );

        // A malformed report changes nothing; an untouched token stays clean.
        assert!(!reg.record_bypass("tok-bypass", "bad surface"));
        assert!(!reg.record_bypass("", "fopen"));
        reg.expect("tok-clean");
        reg.confirm("tok-clean");
        assert_eq!(reg.verdict(Some("tok-clean")), InterposeStatus::Active);
        assert!(reg.bypassed_surfaces("tok-clean").is_empty());
    }

    #[test]
    fn registry_bypass_roster_is_bounded_without_losing_the_verdict() {
        let reg = CanaryRegistry::new();
        reg.expect("tok-many");
        reg.confirm("tok-many");
        for index in 0..(MAX_SURFACES_PER_TOKEN * 2) {
            assert!(reg.record_bypass("tok-many", &format!("surface-{index}")));
        }
        assert_eq!(
            reg.bypassed_surfaces("tok-many").len(),
            MAX_SURFACES_PER_TOKEN
        );
        assert_eq!(reg.verdict(Some("tok-many")), InterposeStatus::Bypassed);
    }

    #[test]
    fn bypassed_message_is_loud_and_names_the_surfaces() {
        let msg = bypassed_error_message("awk", &["fopen".to_string()]);
        assert!(msg.contains("awk"));
        assert!(msg.contains("BYPASSED"));
        assert!(msg.contains("fopen"));
        assert!(msg.contains("raw disk"));
        assert!(msg.contains("NOT graph-native"));

        // Even with no surface named, the message must not read as reassuring.
        let unnamed = bypassed_error_message("awk", &[]);
        assert!(unnamed.contains("BYPASSED"));
        assert!(unnamed.contains("uninterposed surface"));
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
