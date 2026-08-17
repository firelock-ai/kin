// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Shared list of behavior-relevant environment variables that a long-lived
//! repo daemon captures at process start, plus the pure comparison used to
//! detect when a CLI invocation's environment has diverged from the daemon's.
//!
//! A repo worker daemon is a per-user singleton: the first `kin` command spawns
//! it, and it inherits *that* command's environment. Every later command talks
//! to the already-running daemon over HTTP and does not re-export its own
//! environment into the worker. So a behavior knob like `KIN_EMBED_HYBRID` —
//! read deep in the embedding / inference substrate the worker hosts — is fixed
//! at the value the daemon captured when it started. A later
//! `KIN_EMBED_HYBRID=balanced kin embed` against that daemon is silently
//! ignored, and the operator gets the old lever with no signal.
//!
//! Request-scoped propagation of these knobs is a larger change that crosses the
//! daemon boundary into substrate that reads them at its own process start.
//! Until that lands, the mismatch must at least be loud: the daemon reports the
//! value it holds for each listed variable via its health payload, and the CLI
//! compares its own environment against that report and warns (or, under
//! `KIN_STRICT_BEHAVIOR_ENV`, errors) on any divergence.
//!
//! Both sides read [`BEHAVIOR_ENV_VARS`], so the daemon's report and the CLI's
//! comparison can never drift apart. [`compare`] is pure over its two inputs and
//! therefore fully unit-testable.

use std::collections::BTreeMap;

/// Behavior-relevant variables whose effect is decided in the daemon worker
/// process (or the embedding / inference substrate it hosts), not per request.
///
/// This is intentionally *not* limited to the `KIN_*` prefix: `EMBED_MAX_SEQ_LEN`
/// is consumed by the inference substrate under its own name. Membership here is
/// about "does the value get baked into the worker at start" — not about naming.
pub const BEHAVIOR_ENV_VARS: &[&str] = &[
    "KIN_RESOURCE_PROFILE",
    "KIN_EMBED_HYBRID",
    "KIN_EMBED_HYBRID_CPU_MAX_SEQ_LEN",
    "KIN_EMBED_HYBRID_GPU_TPUT_RATIO",
    "KIN_INFER_CPU_BACKEND",
    "KIN_INFER_OCCUPANCY_DISPATCH",
    "KIN_EMBED_CACHE",
    "KIN_EMBED_CACHE_DIR",
    "KIN_EMBED_BACKEND",
    "KIN_DAEMON_DISABLE_FILESYSTEM_RECONCILE",
    "KIN_DAEMON_LOCATE_ONLY",
    "KIN_DAEMON_AUTO_EMBED",
    "KIN_COCHANGE_MAX_FAN_OUT",
    "EMBED_MAX_SEQ_LEN",
];

/// A snapshot of the behavior-env surface: variable name → `Some(value)` when
/// the variable is set (including to an empty string) or `None` when unset in
/// that process. Serializes as a plain JSON object of `string | null` values.
pub type BehaviorEnv = BTreeMap<String, Option<String>>;

/// Capture the behavior-env surface using an arbitrary `lookup` (typically
/// `|name| std::env::var(name).ok()`). Pure in the lookup, so it is
/// deterministic and testable; [`snapshot_from_process`] wires it to the live
/// process environment.
pub fn snapshot_with<F>(mut lookup: F) -> BehaviorEnv
where
    F: FnMut(&str) -> Option<String>,
{
    BEHAVIOR_ENV_VARS
        .iter()
        .map(|name| ((*name).to_string(), lookup(name)))
        .collect()
}

/// Capture the behavior-env surface from the live process environment. Called by
/// the daemon to build its health report and by the CLI to build the snapshot it
/// compares against that report.
pub fn snapshot_from_process() -> BehaviorEnv {
    snapshot_with(|name| std::env::var(name).ok())
}

/// A single behavior-env divergence between the invoking CLI and the running
/// daemon for one variable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Divergence {
    /// Variable name.
    pub var: String,
    /// Raw value in the invoking CLI's environment (`None` = unset).
    pub cli: Option<String>,
    /// Raw value the daemon captured at start (`None` = unset).
    pub daemon: Option<String>,
}

impl Divergence {
    /// One line: `VAR: cli=<value> daemon=<value>`, where an unset side renders
    /// as `(unset)` and a present value is quoted.
    pub fn describe(&self) -> String {
        format!(
            "{}: cli={} daemon={}",
            self.var,
            show(&self.cli),
            show(&self.daemon),
        )
    }
}

/// Render an optional raw value for a human: quoted string, or `(unset)`.
fn show(value: &Option<String>) -> String {
    match value {
        Some(v) => format!("{v:?}"),
        None => "(unset)".to_string(),
    }
}

/// The comparison-effective form of a raw value: trimmed, with empty-after-trim
/// treated as unset. This mirrors how Kin's read sites treat an empty value as
/// "unset", so an empty string on one side and a genuinely-unset variable on the
/// other do not read as a spurious divergence.
fn effective(value: &Option<String>) -> Option<&str> {
    value.as_deref().map(str::trim).filter(|s| !s.is_empty())
}

/// Compare a CLI snapshot against a daemon-reported snapshot and return one
/// [`Divergence`] per behavior-relevant variable whose values differ. Pure: only
/// the two maps are consulted.
///
/// Only variables the daemon actually reported are compared. A daemon that
/// predates this surface (or a given variable) simply omits it from its report,
/// and an omitted variable yields no divergence — we never invent a mismatch for
/// a value we cannot observe. Comparison is on the trimmed raw value (see
/// [`effective`]); the returned [`Divergence`] carries the untrimmed originals so
/// the operator sees exactly what each side holds. Results are in
/// [`BEHAVIOR_ENV_VARS`] order.
pub fn compare(cli: &BehaviorEnv, daemon: &BehaviorEnv) -> Vec<Divergence> {
    let mut out = Vec::new();
    for &var in BEHAVIOR_ENV_VARS {
        let Some(daemon_val) = daemon.get(var) else {
            continue;
        };
        let cli_val = cli.get(var).cloned().flatten();
        if effective(&cli_val) != effective(daemon_val) {
            out.push(Divergence {
                var: var.to_string(),
                cli: cli_val,
                daemon: daemon_val.clone(),
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &[(&str, Option<&str>)]) -> BehaviorEnv {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.map(str::to_string)))
            .collect()
    }

    #[test]
    fn snapshot_covers_every_listed_var() {
        let snap = snapshot_with(|name| Some(format!("val-{name}")));
        assert_eq!(snap.len(), BEHAVIOR_ENV_VARS.len());
        for name in BEHAVIOR_ENV_VARS {
            assert_eq!(snap.get(*name), Some(&Some(format!("val-{name}"))));
        }
    }

    #[test]
    fn snapshot_records_unset_as_none() {
        let snap = snapshot_with(|_| None);
        assert_eq!(snap.len(), BEHAVIOR_ENV_VARS.len());
        assert!(snap.values().all(|v| v.is_none()));
    }

    #[test]
    fn the_background_embedding_opt_out_is_reported() {
        // An operator who sets this and still watches the accelerator run has
        // no way to tell a rejected opt-out from an ignored one. The daemon
        // fixed the value when it started; a command that reaches an existing
        // daemon cannot change it, so the mismatch has to be reportable.
        assert!(
            BEHAVIOR_ENV_VARS.contains(&"KIN_DAEMON_AUTO_EMBED"),
            "daemon health must report the background-embedding opt-out it is running under"
        );
    }

    #[test]
    fn resume_identity_knobs_are_reported() {
        for name in [
            "KIN_DAEMON_DISABLE_FILESYSTEM_RECONCILE",
            "KIN_DAEMON_LOCATE_ONLY",
            "KIN_COCHANGE_MAX_FAN_OUT",
        ] {
            assert!(
                BEHAVIOR_ENV_VARS.contains(&name),
                "daemon health must report resume-identity knob {name}"
            );
        }
    }

    #[test]
    fn identical_env_has_no_divergence() {
        let cli = env(&[("KIN_EMBED_HYBRID", Some("balanced"))]);
        let daemon = env(&[("KIN_EMBED_HYBRID", Some("balanced"))]);
        assert!(compare(&cli, &daemon).is_empty());
    }

    #[test]
    fn override_ignored_by_daemon_is_flagged() {
        // The motivating case: the operator sets a lever on this command, but the
        // long-lived daemon started without it and never sees the override.
        let cli = env(&[("KIN_EMBED_HYBRID", Some("balanced"))]);
        let daemon = env(&[("KIN_EMBED_HYBRID", None)]);
        let diffs = compare(&cli, &daemon);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].var, "KIN_EMBED_HYBRID");
        assert_eq!(diffs[0].cli.as_deref(), Some("balanced"));
        assert_eq!(diffs[0].daemon, None);
    }

    #[test]
    fn daemon_only_value_is_flagged() {
        // The reverse: the daemon carries a lever this command did not set, so
        // the command silently runs under it.
        let cli = env(&[("KIN_RESOURCE_PROFILE", None)]);
        let daemon = env(&[("KIN_RESOURCE_PROFILE", Some("throughput"))]);
        let diffs = compare(&cli, &daemon);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].var, "KIN_RESOURCE_PROFILE");
        assert_eq!(diffs[0].cli, None);
        assert_eq!(diffs[0].daemon.as_deref(), Some("throughput"));
    }

    #[test]
    fn differing_values_are_flagged() {
        let cli = env(&[("EMBED_MAX_SEQ_LEN", Some("256"))]);
        let daemon = env(&[("EMBED_MAX_SEQ_LEN", Some("512"))]);
        let diffs = compare(&cli, &daemon);
        assert_eq!(diffs.len(), 1);
        assert_eq!(diffs[0].var, "EMBED_MAX_SEQ_LEN");
    }

    #[test]
    fn empty_and_unset_do_not_diverge() {
        // Empty-after-trim is treated as unset on both sides, matching read-site
        // semantics, so this is not a spurious divergence.
        let cli = env(&[("KIN_EMBED_CACHE_DIR", Some("   "))]);
        let daemon = env(&[("KIN_EMBED_CACHE_DIR", None)]);
        assert!(compare(&cli, &daemon).is_empty());
    }

    #[test]
    fn surrounding_whitespace_is_ignored() {
        let cli = env(&[("KIN_EMBED_BACKEND", Some("metal"))]);
        let daemon = env(&[("KIN_EMBED_BACKEND", Some(" metal "))]);
        assert!(compare(&cli, &daemon).is_empty());
    }

    #[test]
    fn daemon_without_surface_yields_no_divergence() {
        // An older daemon reports no behavior_env at all; the CLI must not invent
        // divergences it cannot observe.
        let cli = snapshot_with(|_| Some("set".to_string()));
        let daemon: BehaviorEnv = BTreeMap::new();
        assert!(compare(&cli, &daemon).is_empty());
    }

    #[test]
    fn unlisted_daemon_key_is_ignored() {
        // Only the shared list is compared; stray keys in a report are inert.
        let cli = env(&[("KIN_EMBED_HYBRID", Some("balanced"))]);
        let mut daemon = env(&[("KIN_EMBED_HYBRID", Some("balanced"))]);
        daemon.insert("KIN_SOMETHING_ELSE".to_string(), Some("x".to_string()));
        assert!(compare(&cli, &daemon).is_empty());
    }

    #[test]
    fn multiple_divergences_sorted_by_list_order() {
        let cli = env(&[
            ("EMBED_MAX_SEQ_LEN", Some("256")),
            ("KIN_RESOURCE_PROFILE", Some("throughput")),
        ]);
        let daemon = env(&[
            ("EMBED_MAX_SEQ_LEN", Some("512")),
            ("KIN_RESOURCE_PROFILE", None),
        ]);
        let diffs = compare(&cli, &daemon);
        assert_eq!(diffs.len(), 2);
        // KIN_RESOURCE_PROFILE precedes EMBED_MAX_SEQ_LEN in BEHAVIOR_ENV_VARS.
        assert_eq!(diffs[0].var, "KIN_RESOURCE_PROFILE");
        assert_eq!(diffs[1].var, "EMBED_MAX_SEQ_LEN");
    }

    #[test]
    fn describe_renders_unset_and_quoted_values() {
        let d = Divergence {
            var: "KIN_EMBED_HYBRID".to_string(),
            cli: Some("balanced".to_string()),
            daemon: None,
        };
        assert_eq!(
            d.describe(),
            "KIN_EMBED_HYBRID: cli=\"balanced\" daemon=(unset)"
        );
    }
}
