//! Bearer tokens a daemon surface accepts, and the signal that says whether a
//! rotation overlap window can close.
//!
//! # Why an overlap window exists at all
//!
//! One Kubernetes Secret, `kin-daemon-auth-token`, is injected into three
//! containers in the hosted deployment: `kin-registry`, `kin-daemon` and
//! `kinlab-control-plane` (kin-infra `compute/workloads.ts`, three
//! `secretKeyRef` sites). Two of those run a daemon surface that ENFORCES the
//! token; one is a client that SENDS it.
//!
//! Three containers cannot have their environment replaced at the same instant.
//! During any rollout there is a window where a sender holds one value and an
//! enforcer holds another, and with a single accepted token every request
//! crossing that window is a 401. That is not a small window either: the
//! control-plane readiness probe budget alone is `periodSeconds: 15` with
//! `failureThreshold: 30`.
//!
//! So the enforcing side accepts two values during a rotation: the token it
//! primarily expects, and the superseded one it still honours. The rotation
//! becomes three ordered steps that each survive on their own, rather than one
//! step that has to be atomic and cannot be:
//!
//! 1. Give every enforcer the new token as `..._PREVIOUS` alongside the old
//!    primary, or the old one as `..._PREVIOUS` alongside a new primary. Either
//!    ordering works because both values are accepted; what matters is that the
//!    set contains both before any sender moves.
//! 2. Roll the senders onto the new value.
//! 3. Remove the superseded value once nothing is using it.
//!
//! # Why step 3 needs a measurement rather than a guess
//!
//! "Nothing is using it" is not observable from outside, so this module counts
//! it. Every request that authenticates on the superseded token increments a
//! counter and stamps a timestamp. An operator closes the window when that
//! counter has stopped moving, not when a timer expires.
//!
//! Without the counter the retention decision is a guess, and the two ways of
//! guessing wrong are not symmetric: dropping the old token too early is an
//! outage, and keeping it forever means a rotation never actually retires the
//! credential it was run to retire.
//!
//! # Retention and rollback
//!
//! A rollback restores a previous Deployment revision, and that revision's
//! containers carry the token they were built with. So the superseded token has
//! to stay accepted for at least as long as a rollback to the previous revision
//! is a thing anyone would do. Retiring it sooner turns the rollback itself
//! into the outage the rollback was meant to end.
//!
//! This module supplies the mechanism and the reading. How long to hold the
//! window open is a policy an operator sets, and the counter is what makes that
//! policy checkable instead of aspirational.

use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;

use sha2::{Digest, Sha256};

/// Which of the accepted tokens a request presented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenVerdict {
    /// Enforcement is off for this surface: no primary token is configured.
    NotEnforced,
    /// The token this surface primarily expects.
    Primary,
    /// The superseded token, still accepted while the rotation window is open.
    Previous,
    /// Neither accepted token.
    Rejected,
}

impl TokenVerdict {
    /// Whether the request may proceed.
    pub fn is_accepted(self) -> bool {
        matches!(self, Self::NotEnforced | Self::Primary | Self::Previous)
    }
}

/// How a token set was rejected at construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RotationConfigError {
    /// A superseded token is configured with no primary.
    ///
    /// Refused rather than promoted, because silently treating the superseded
    /// value as the sole authority is the opposite of what its name says and
    /// would leave a rotation looking complete while the retired credential is
    /// the only one that works.
    PreviousWithoutPrimary {
        previous_env: String,
        primary_env: String,
    },
    /// The two configured tokens are the same value.
    ///
    /// Refused because it reads as an open overlap window and is not one: the
    /// previous-token counter can never move, so the reading an operator closes
    /// the window on would be a permanent zero whether or not anything is still
    /// presenting the old value.
    PreviousEqualsPrimary {
        previous_env: String,
        primary_env: String,
    },
}

impl std::fmt::Display for RotationConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PreviousWithoutPrimary {
                previous_env,
                primary_env,
            } => write!(
                f,
                "{previous_env} is set but {primary_env} is not. The superseded token is never \
                 promoted to sole authority: set {primary_env} to the token this surface should \
                 primarily expect, or unset {previous_env}."
            ),
            Self::PreviousEqualsPrimary {
                previous_env,
                primary_env,
            } => write!(
                f,
                "{previous_env} and {primary_env} carry the same value, which is not a rotation \
                 overlap: the superseded-token counter can never move, so it cannot tell you \
                 whether the window is safe to close. Set {previous_env} to the token being \
                 retired, or unset it."
            ),
        }
    }
}

impl std::error::Error for RotationConfigError {}

/// A fixed-width digest of a token.
///
/// Comparing digests rather than the tokens themselves means the comparison is
/// over 32 bytes whatever the tokens' lengths, so the check leaks neither the
/// expected token's length nor how many leading bytes a guess got right. It is
/// not a secrecy measure for the token, which the process already holds in
/// full; it is about what a caller can learn by timing requests.
#[derive(Clone, Copy, PartialEq, Eq)]
struct TokenDigest([u8; 32]);

impl TokenDigest {
    fn of(token: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(token.as_bytes());
        let digest = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&digest);
        Self(out)
    }

    /// Constant-time equality over the two digests.
    ///
    /// Written as an or-accumulation over every byte rather than a short-circuit
    /// compare, so the number of bytes examined does not depend on where the
    /// first difference is. `PartialEq` on the array is not used here on
    /// purpose: it is free to return early.
    fn ct_eq(&self, other: &Self) -> bool {
        let mut difference: u8 = 0;
        for index in 0..32 {
            difference |= self.0[index] ^ other.0[index];
        }
        difference == 0
    }
}

/// Counters that say whether a rotation overlap window is still carrying
/// traffic.
///
/// Shared rather than owned so the surface exposing the reading and the guard
/// recording it are looking at the same numbers. Cloning a `RotationTokens`
/// clones the handle, not the counts, which is what the axum middleware layer
/// needs: it clones the state per request.
#[derive(Debug, Default)]
struct RotationCounters {
    previous_accepted: AtomicU64,
    /// Unix seconds of the most recent accept on the superseded token, or 0 if
    /// it has never been used. Zero is distinguishable from a real timestamp
    /// because this daemon cannot be serving in 1970.
    previous_last_accepted_unix: AtomicI64,
}

/// The bearer tokens one daemon surface accepts.
#[derive(Clone)]
pub struct RotationTokens {
    primary: Option<TokenDigest>,
    previous: Option<TokenDigest>,
    counters: Arc<RotationCounters>,
}

impl std::fmt::Debug for RotationTokens {
    /// Reports presence, never material.
    ///
    /// A token set reaching a log line or a panic message through a derived
    /// `Debug` is the same class of defect as printing a prefix of a secret, so
    /// the derive is deliberately not used.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RotationTokens")
            .field("primary_configured", &self.primary.is_some())
            .field("previous_configured", &self.previous.is_some())
            .field("previous_accepted", &self.previous_accepted_count())
            .finish()
    }
}

impl RotationTokens {
    /// A surface with no enforcement.
    pub fn disabled() -> Self {
        Self {
            primary: None,
            previous: None,
            counters: Arc::new(RotationCounters::default()),
        }
    }

    /// Build a token set, refusing the two configurations that cannot mean what
    /// they appear to.
    ///
    /// `primary_env` and `previous_env` name the variables the values came from
    /// and appear in a refusal, so an operator reading it knows which of the
    /// two to change. Neither token value is ever put in the message.
    pub fn new(
        primary: Option<String>,
        previous: Option<String>,
        primary_env: &str,
        previous_env: &str,
    ) -> Result<Self, RotationConfigError> {
        let primary = normalize(primary);
        let previous = normalize(previous);

        match (&primary, &previous) {
            (None, Some(_)) => {
                return Err(RotationConfigError::PreviousWithoutPrimary {
                    previous_env: previous_env.to_string(),
                    primary_env: primary_env.to_string(),
                })
            }
            (Some(current), Some(retired)) if current == retired => {
                return Err(RotationConfigError::PreviousEqualsPrimary {
                    previous_env: previous_env.to_string(),
                    primary_env: primary_env.to_string(),
                })
            }
            _ => {}
        }

        Ok(Self {
            primary: primary.as_deref().map(TokenDigest::of),
            previous: previous.as_deref().map(TokenDigest::of),
            counters: Arc::new(RotationCounters::default()),
        })
    }

    /// Whether this surface enforces a token at all.
    pub fn is_enforced(&self) -> bool {
        self.primary.is_some()
    }

    /// Whether a rotation overlap window is open.
    pub fn overlap_open(&self) -> bool {
        self.previous.is_some()
    }

    /// How many requests have been accepted on the superseded token.
    ///
    /// This is the reading step 3 of a rotation waits on. A window whose count
    /// is still climbing has traffic on the retired credential, and closing it
    /// would 401 that traffic.
    pub fn previous_accepted_count(&self) -> u64 {
        self.counters.previous_accepted.load(Ordering::Relaxed)
    }

    /// Unix seconds of the most recent accept on the superseded token, or `None`
    /// if it has never been presented.
    pub fn previous_last_accepted_unix(&self) -> Option<i64> {
        let stamp = self
            .counters
            .previous_last_accepted_unix
            .load(Ordering::Relaxed);
        (stamp != 0).then_some(stamp)
    }

    /// Classify a presented token, recording a superseded-token accept.
    ///
    /// Both configured tokens are compared on every enforced call, rather than
    /// returning as soon as the primary matches. A short-circuit here would make
    /// the work depend on which token was presented, which is the timing
    /// signal the digest comparison exists to remove.
    pub fn classify(&self, provided: Option<&str>) -> TokenVerdict {
        let Some(primary) = self.primary.as_ref() else {
            return TokenVerdict::NotEnforced;
        };
        let Some(provided) = provided else {
            return TokenVerdict::Rejected;
        };
        let presented = TokenDigest::of(provided);

        let matches_primary = presented.ct_eq(primary);
        let matches_previous = self
            .previous
            .as_ref()
            .map(|retired| presented.ct_eq(retired))
            .unwrap_or(false);

        if matches_primary {
            return TokenVerdict::Primary;
        }
        if matches_previous {
            self.record_previous_accept();
            return TokenVerdict::Previous;
        }
        TokenVerdict::Rejected
    }

    fn record_previous_accept(&self) {
        self.counters
            .previous_accepted
            .fetch_add(1, Ordering::Relaxed);
        self.counters
            .previous_last_accepted_unix
            .store(chrono::Utc::now().timestamp(), Ordering::Relaxed);
    }
}

fn normalize(token: Option<String>) -> Option<String> {
    token
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRIMARY_ENV: &str = "KIN_DAEMON_AUTH_TOKEN";
    const PREVIOUS_ENV: &str = "KIN_DAEMON_AUTH_TOKEN_PREVIOUS";

    /// A token value that cannot occur in the refusal's own prose.
    ///
    /// The first version of these tests used "same" and failed, because the
    /// message says "carry the same value" for reasons that have nothing to do
    /// with interpolation. A leak assertion whose fixture is an ordinary word
    /// grades the wording rather than the code, so the fixture is a string no
    /// sentence would contain.
    const TOKEN_SENTINEL: &str = "qzqz-token-material-qzqz";

    fn tokens(primary: Option<&str>, previous: Option<&str>) -> RotationTokens {
        RotationTokens::new(
            primary.map(str::to_string),
            previous.map(str::to_string),
            PRIMARY_ENV,
            PREVIOUS_ENV,
        )
        .expect("valid token configuration")
    }

    #[test]
    fn an_unconfigured_surface_does_not_enforce() {
        let set = tokens(None, None);
        assert!(!set.is_enforced());
        assert_eq!(set.classify(None), TokenVerdict::NotEnforced);
        assert_eq!(set.classify(Some("anything")), TokenVerdict::NotEnforced);
        assert!(set.classify(Some("anything")).is_accepted());
    }

    #[test]
    fn a_primary_only_surface_accepts_exactly_that_token() {
        let set = tokens(Some("current"), None);
        assert!(set.is_enforced());
        assert!(!set.overlap_open());
        assert_eq!(set.classify(Some("current")), TokenVerdict::Primary);
        assert_eq!(set.classify(Some("retired")), TokenVerdict::Rejected);
        assert_eq!(set.classify(None), TokenVerdict::Rejected);
        // The counter must stay at zero: with no window open there is nothing
        // for a superseded accept to mean.
        assert_eq!(set.previous_accepted_count(), 0);
        assert_eq!(set.previous_last_accepted_unix(), None);
    }

    #[test]
    fn an_open_window_accepts_both_and_says_which() {
        let set = tokens(Some("current"), Some("retired"));
        assert!(set.overlap_open());
        assert_eq!(set.classify(Some("current")), TokenVerdict::Primary);
        assert_eq!(set.classify(Some("retired")), TokenVerdict::Previous);
        assert_eq!(set.classify(Some("neither")), TokenVerdict::Rejected);
    }

    #[test]
    fn only_a_superseded_accept_moves_the_counter() {
        let set = tokens(Some("current"), Some("retired"));
        assert_eq!(set.previous_accepted_count(), 0);

        // The primary must not move it. A counter that also counted primary
        // traffic would never reach the zero an operator closes the window on.
        for _ in 0..5 {
            assert_eq!(set.classify(Some("current")), TokenVerdict::Primary);
        }
        assert_eq!(set.previous_accepted_count(), 0);
        assert_eq!(set.previous_last_accepted_unix(), None);

        // A rejection must not move it either.
        assert_eq!(set.classify(Some("neither")), TokenVerdict::Rejected);
        assert_eq!(set.classify(None), TokenVerdict::Rejected);
        assert_eq!(set.previous_accepted_count(), 0);

        assert_eq!(set.classify(Some("retired")), TokenVerdict::Previous);
        assert_eq!(set.previous_accepted_count(), 1);
        assert_eq!(set.classify(Some("retired")), TokenVerdict::Previous);
        assert_eq!(set.previous_accepted_count(), 2);

        let stamp = set
            .previous_last_accepted_unix()
            .expect("a stamp after a superseded accept");
        // Not asserting an exact instant, only that it is a real timestamp
        // rather than the zero sentinel: this daemon cannot be serving in 1970.
        assert!(
            stamp > 1_600_000_000,
            "stamp {stamp} is not a plausible unix time"
        );
    }

    #[test]
    fn the_counter_is_shared_across_clones() {
        // The axum middleware layer clones the state per request, so a counter
        // that lived in the clone would read zero forever no matter how much
        // traffic the retired token carried.
        let set = tokens(Some("current"), Some("retired"));
        let clone = set.clone();
        assert_eq!(clone.classify(Some("retired")), TokenVerdict::Previous);
        assert_eq!(set.previous_accepted_count(), 1);
        assert_eq!(clone.previous_accepted_count(), 1);
    }

    #[test]
    fn whitespace_only_configuration_is_absent_not_present() {
        // Kubernetes mounts an absent optional secret key as an empty string,
        // so treating empty as configured would open a window against a token
        // nobody holds and refuse the equals-primary case for two blanks.
        let set = tokens(Some("current"), Some("   "));
        assert!(!set.overlap_open());
        assert_eq!(set.classify(Some("   ")), TokenVerdict::Rejected);

        let none = tokens(Some("  \t "), None);
        assert!(!none.is_enforced());
    }

    #[test]
    fn a_presented_token_is_trimmed_by_the_caller_not_here() {
        // The guards strip "Bearer " and trim before calling in, and this
        // asserts classify does not trim again: a token whose real value has
        // surrounding space would otherwise authenticate under two spellings.
        let set = tokens(Some("current"), None);
        assert_eq!(set.classify(Some(" current ")), TokenVerdict::Rejected);
    }

    #[test]
    fn a_superseded_token_with_no_primary_is_refused() {
        let error = RotationTokens::new(
            None,
            Some(TOKEN_SENTINEL.to_string()),
            PRIMARY_ENV,
            PREVIOUS_ENV,
        )
        .expect_err("a superseded token with no primary must be refused");
        assert_eq!(
            error,
            RotationConfigError::PreviousWithoutPrimary {
                previous_env: PREVIOUS_ENV.to_string(),
                primary_env: PRIMARY_ENV.to_string(),
            }
        );
        // The message names both variables and neither value.
        let rendered = error.to_string();
        assert!(rendered.contains(PRIMARY_ENV), "{rendered}");
        assert!(rendered.contains(PREVIOUS_ENV), "{rendered}");
        assert!(
            !rendered.contains(TOKEN_SENTINEL),
            "the refusal must not carry the token: {rendered}"
        );
        // Control: the assertion must be able to fire. Without this, a
        // `contains` that never matched would read as a clean pass here and on
        // a message that really did interpolate the token.
        assert!(format!("leaked {TOKEN_SENTINEL}").contains(TOKEN_SENTINEL));
    }

    #[test]
    fn two_identical_tokens_are_refused_as_a_false_window() {
        let error = RotationTokens::new(
            Some(TOKEN_SENTINEL.to_string()),
            Some(TOKEN_SENTINEL.to_string()),
            PRIMARY_ENV,
            PREVIOUS_ENV,
        )
        .expect_err("an identical pair must be refused");
        assert_eq!(
            error,
            RotationConfigError::PreviousEqualsPrimary {
                previous_env: PREVIOUS_ENV.to_string(),
                primary_env: PRIMARY_ENV.to_string(),
            }
        );
        let rendered = error.to_string();
        assert!(rendered.contains(PRIMARY_ENV), "{rendered}");
        assert!(rendered.contains(PREVIOUS_ENV), "{rendered}");
        assert!(
            !rendered.contains(TOKEN_SENTINEL),
            "the refusal must not carry the token: {rendered}"
        );
        assert!(format!("leaked {TOKEN_SENTINEL}").contains(TOKEN_SENTINEL));
    }

    #[test]
    fn trimming_makes_two_spellings_of_one_token_an_identical_pair() {
        // The equality check runs after normalization, so " same " and "same"
        // are the same configuration and must be refused as one. Checking
        // before trimming would admit a window that can never move its counter,
        // which is the exact state the refusal exists to prevent.
        RotationTokens::new(
            Some(TOKEN_SENTINEL.to_string()),
            Some(format!("  {TOKEN_SENTINEL}  ")),
            PRIMARY_ENV,
            PREVIOUS_ENV,
        )
        .expect_err("a pair identical after trimming must be refused");
    }

    #[test]
    fn debug_reports_presence_and_never_material() {
        let set = tokens(Some("super-secret-primary"), Some("super-secret-retired"));
        let rendered = format!("{set:?}");
        assert!(rendered.contains("primary_configured: true"), "{rendered}");
        assert!(rendered.contains("previous_configured: true"), "{rendered}");
        assert!(
            !rendered.contains("super-secret"),
            "Debug leaked token material: {rendered}"
        );
    }

    #[test]
    fn digest_equality_is_reflexive_and_discriminating() {
        // The instrument the whole guard rests on. Without this, a ct_eq that
        // always returned true would make every classify test above pass on the
        // primary arm and only the Rejected arms would catch it.
        let one = TokenDigest::of("alpha");
        let two = TokenDigest::of("beta");
        assert!(one.ct_eq(&one));
        assert!(!one.ct_eq(&two));
        // A one-character difference must still be caught, including at the
        // very end of a long token, which is where a length-only compare fails.
        let long = "x".repeat(512);
        let long_a = TokenDigest::of(&format!("{long}a"));
        let long_b = TokenDigest::of(&format!("{long}b"));
        assert!(!long_a.ct_eq(&long_b));
    }

    #[test]
    fn tokens_of_different_lengths_compare_over_the_same_width() {
        // Digest comparison is why this holds: the compare is 32 bytes whatever
        // the tokens' lengths, so neither the expected length nor a matching
        // prefix is observable from how long the check takes.
        let short = TokenDigest::of("a");
        let long = TokenDigest::of(&"a".repeat(4096));
        assert!(!short.ct_eq(&long));
        assert_eq!(short.0.len(), long.0.len());
    }
}
