// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The resource profile a kin binary selects for itself.
//!
//! `KIN_RESOURCE_PROFILE` is the one switch every inference-side budget keys
//! off: kin-infer resolves the GPU kernel plan, the Metal submission depth and
//! the embedding budgets from it, and kin-db's batch budget reads the same name.
//! kin-infer's fallback for an unset selector is `proof` — the deliberately
//! conservative, everything-off, bit-identical configuration a citable benchmark
//! wants. That is the right fallback for a library whose caller never chose.
//!
//! A shipped binary did choose. Left unset, `kin` and `kin-daemon` ran the proof
//! configuration in front of users: an empty GPU kernel plan and the smallest
//! budgets in the file, for no reason anyone had decided. This module makes the
//! choice explicit, once, at process start.
//!
//! Three properties this deliberately holds to:
//!
//! - **An explicit value always wins.** The default is applied only when the
//!   variable is absent, so `KIN_RESOURCE_PROFILE=proof` still pins the
//!   bit-identical configuration and the benchmark harness (which pins both
//!   arms explicitly) is untouched.
//! - **Empty is not absent.** An empty value is left exactly as written so the
//!   startup env audit still reports it, rather than being silently repaired
//!   into a valid one.
//! - **The CLI and the daemon apply the SAME default.** The daemon captures its
//!   environment at startup, and `kin embed` and `kin resources inspect` compare
//!   their own against it; a CLI selecting one profile while the daemon runs
//!   another would warn on both and refuse under `KIN_STRICT_BEHAVIOR_ENV`. They
//!   agree by construction because both call [`apply_product_default`].
//!
//! [`product_selected`] records whether the value came from here or from the
//! operator. That distinction matters wherever the profile NAME carries a second
//! meaning: `kin embed` reads `interactive` as "small machine, bound the pass",
//! which is a statement about the host an operator makes, not something the
//! product should start asserting on every machine.

use std::sync::atomic::{AtomicBool, Ordering};

/// The canonical selector name.
pub const RESOURCE_PROFILE_ENV: &str = "KIN_RESOURCE_PROFILE";

/// Records the value [`apply_product_default`] wrote, so a child process can
/// tell an inherited product default from an operator's choice.
///
/// Provenance does not survive a spawn on its own. A kin binary that selects the
/// default writes it into its own environment, because that is where kin-infer
/// and kin-db read it, and every process it spawns then inherits a set variable
/// that looks exactly like an export the operator typed. The daemon is spawned
/// by the CLI, so on a host where nobody set anything the daemon saw a present
/// value, left the atomic false, and `kin resources inspect` reported the ship
/// default as an operator override.
///
/// The marker carries the VALUE rather than a bare flag. A caller that overrides
/// the profile for a child (a benchmark harness pinning `proof`) passes the new
/// value without touching the marker, so the two disagree and the child
/// correctly reads its profile as chosen for it. Trusting a bare flag would
/// report that override as kin's own default.
pub const RESOURCE_PROFILE_PRODUCT_DEFAULT_ENV: &str = "KIN_RESOURCE_PROFILE_PRODUCT_DEFAULT";

/// The profile a kin binary selects when the operator has not chosen one.
///
/// `interactive` carries the two Metal kernel levers that preserve embedding
/// values (the double-buffered GEMM and the pooled readback) and a bounded
/// submission depth, while keeping proof's embedding budgets, serial persist
/// order and single-lane host parallelism. `throughput` additionally scales the
/// batch budgets and engages the CPU twin; it stays opt-in because it is also
/// the profile that overlaps a batch's persist with the next batch's compute,
/// which changes the order vectors are written in.
pub const PRODUCT_DEFAULT_PROFILE: &str = "interactive";

/// Set by [`apply_product_default`] when it actually wrote the default.
static PRODUCT_SELECTED: AtomicBool = AtomicBool::new(false);

/// The profile to write given the current raw value of the selector, or `None`
/// to leave the environment exactly as it is.
///
/// Pure, so the precedence rule is testable without touching the process
/// environment: a present value of any shape (including an empty or invalid
/// one) is the operator's, and only an absent variable is unchosen.
pub fn product_default_for(current: Option<&str>) -> Option<&'static str> {
    match current {
        None => Some(PRODUCT_DEFAULT_PROFILE),
        Some(_) => None,
    }
}

/// Select the product default profile for this process when the operator has
/// not set one. Call once, as early in `main` as possible.
///
/// Two ordering requirements, both satisfied by calling this first:
/// mutating the environment must happen before any thread that could read it
/// exists, and before the first reader resolves and caches its answer (the GPU
/// kernel plan and the submission depth are each resolved once per process).
pub fn apply_product_default() {
    let current = std::env::var(RESOURCE_PROFILE_ENV).ok();
    if let Some(profile) = product_default_for(current.as_deref()) {
        std::env::set_var(RESOURCE_PROFILE_ENV, profile);
        std::env::set_var(RESOURCE_PROFILE_PRODUCT_DEFAULT_ENV, profile);
        PRODUCT_SELECTED.store(true, Ordering::Relaxed);
        return;
    }
    PRODUCT_SELECTED.store(
        inherited_product_default(current.as_deref(), |key| std::env::var(key).ok()),
        Ordering::Relaxed,
    );
}

/// Whether a value already present in the environment is one a kin parent
/// selected rather than one the operator chose.
///
/// Pure over its lookup so both sides are testable without touching the process
/// environment. True only when the marker names the value actually in effect:
/// a marker naming something else is a stale inheritance from a parent whose
/// value was overridden on the way down, and it is not evidence about this one.
pub fn inherited_product_default<F>(current: Option<&str>, lookup: F) -> bool
where
    F: Fn(&str) -> Option<String>,
{
    match current {
        None => false,
        Some(current) => {
            lookup(RESOURCE_PROFILE_PRODUCT_DEFAULT_ENV).is_some_and(|marked| marked == current)
        }
    }
}

/// Whether the active profile was selected by [`apply_product_default`] rather
/// than by the operator. False in any process that never applied the default,
/// which is the honest answer for a library caller or a test.
pub fn product_selected() -> bool {
    PRODUCT_SELECTED.load(Ordering::Relaxed)
}

/// Reset the product-selected mark. Test-only: the flag is process-global and
/// tests covering both sides of the distinction share one process.
#[doc(hidden)]
pub fn reset_product_selected_for_tests() {
    PRODUCT_SELECTED.store(false, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `KIN_*` name this code sets must be in the central registry, or every
    /// kin invocation warns that it is probably a typo.
    ///
    /// Nothing connects a `set_var` to the registry at compile time, and the
    /// registry's own doc-drift test only compares the registry against the
    /// generated doc, so an unregistered name is invisible to every local gate.
    /// It surfaces only when a real binary runs: the audit warning went to the
    /// output of `kin ... --json`, and the install proof failed parsing it with
    /// "Unexpected non-whitespace character after JSON at position 4". This test
    /// is the connection that was missing.
    #[test]
    fn the_provenance_marker_is_a_registered_environment_variable() {
        for name in [RESOURCE_PROFILE_ENV, RESOURCE_PROFILE_PRODUCT_DEFAULT_ENV] {
            assert!(
                kin_core::env_registry::is_known(name),
                "{name} is set by this module but is not in the env registry, so every kin \
                 invocation will warn that it is probably a typo and corrupt any JSON output"
            );
        }
    }

    #[test]
    fn an_inherited_marker_naming_the_active_value_is_kins_own_default() {
        // The shape a spawned daemon sees: the CLI wrote both, and the child
        // inherited both.
        assert!(inherited_product_default(Some("interactive"), |key| {
            (key == RESOURCE_PROFILE_PRODUCT_DEFAULT_ENV).then(|| "interactive".to_string())
        }));
    }

    #[test]
    fn a_marker_naming_a_different_value_is_not_evidence_about_this_one() {
        // A harness pinning `proof` for a child passes the value without
        // touching the marker. Reading a bare flag here would report the
        // harness's explicit pin as kin's ship default.
        assert!(!inherited_product_default(Some("proof"), |key| {
            (key == RESOURCE_PROFILE_PRODUCT_DEFAULT_ENV).then(|| "interactive".to_string())
        }));
    }

    #[test]
    fn a_present_value_with_no_marker_is_the_operators() {
        assert!(!inherited_product_default(Some("interactive"), |_| None));
    }

    #[test]
    fn an_absent_selector_is_never_inherited() {
        // Nothing is in effect yet, so there is nothing a marker could describe.
        assert!(!inherited_product_default(None, |_| Some(
            "interactive".to_string()
        )));
    }

    #[test]
    fn absent_selector_takes_the_product_default() {
        assert_eq!(product_default_for(None), Some(PRODUCT_DEFAULT_PROFILE));
        assert_eq!(product_default_for(None), Some("interactive"));
    }

    #[test]
    fn an_explicit_value_always_wins() {
        for chosen in [
            "proof",
            "interactive",
            "throughput",
            "ci",
            "PROOF",
            " proof ",
        ] {
            assert_eq!(
                product_default_for(Some(chosen)),
                None,
                "{chosen:?} is the operator's choice and must survive"
            );
        }
    }

    /// An empty or unrecognized value is left alone rather than repaired: the
    /// startup env audit reports it, and repairing it here would hide the
    /// operator's mistake behind a working process.
    #[test]
    fn empty_and_invalid_values_are_left_for_the_audit() {
        assert_eq!(product_default_for(Some("")), None);
        assert_eq!(product_default_for(Some("   ")), None);
        assert_eq!(product_default_for(Some("bogus")), None);
    }

    /// The env-writing wrapper itself, through the workspace's one sanctioned
    /// mutation guard so the write is restored and serialized against every
    /// other env-mutating test in this binary. The pure rule above is the
    /// precedence contract; this asserts the wrapper honors it and records the
    /// origin, which is what `kin resources inspect` and the embed budget read.
    #[test]
    fn apply_writes_only_when_the_selector_is_absent() {
        {
            let _domain = kin_core::test_env::EnvVarGuard::unset(RESOURCE_PROFILE_ENV);
            reset_product_selected_for_tests();
            apply_product_default();
            assert_eq!(
                std::env::var(RESOURCE_PROFILE_ENV).ok().as_deref(),
                Some(PRODUCT_DEFAULT_PROFILE)
            );
            assert!(product_selected());
        }
        {
            let _domain = kin_core::test_env::EnvVarGuard::set(RESOURCE_PROFILE_ENV, "proof");
            reset_product_selected_for_tests();
            apply_product_default();
            assert_eq!(
                std::env::var(RESOURCE_PROFILE_ENV).ok().as_deref(),
                Some("proof"),
                "an operator's choice must survive the product default"
            );
            assert!(!product_selected());
        }
        reset_product_selected_for_tests();
    }

    #[test]
    fn the_default_is_a_profile_the_registry_accepts() {
        let spec = kin_core::env_registry::spec(RESOURCE_PROFILE_ENV)
            .expect("the selector is a registered env var");
        assert!(
            kin_core::env_registry::validate_value(&spec, PRODUCT_DEFAULT_PROFILE).is_ok(),
            "the product default must pass the startup env audit it runs before"
        );
        // The registry documents what a kin binary actually does, so its
        // documented default and the value applied here cannot drift apart.
        assert_eq!(spec.default, PRODUCT_DEFAULT_PROFILE);
    }
}
