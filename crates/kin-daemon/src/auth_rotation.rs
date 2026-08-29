//! Bearer tokens a daemon surface accepts, and the two bounds that close a
//! rotation overlap window whether or not anyone is watching.
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
//! # The counter says when it is safe to close. The bounds say when it must.
//!
//! "Nothing is using the old token" is not observable from outside, so this
//! module counts it. Every request that authenticates on the superseded token
//! increments a counter and stamps a timestamp, and an operator can close the
//! window early once that counter has stopped moving.
//!
//! That reading is necessary and it is not sufficient. On its own it makes the
//! end of a credential's life a thing a human remembers rather than a thing the
//! system does, so a window nobody revisits stays open forever with no alarm and
//! nothing that degrades. So the window also carries two bounds it enforces
//! itself, and the superseded token is accepted only while BOTH hold:
//!
//! * a maximum age, measured from the instant the window opened, and
//! * a maximum number of superseded-token accepts.
//!
//! Whichever bound is reached first closes the window, and the refusal names
//! which one it was. Neither bound can be configured away: a zero, a negative
//! or an unparseable value is refused at startup rather than read as
//! "unbounded", because an unbounded setting would restore exactly the state
//! these bounds exist to end. An operator who needs longer sets a longer bound,
//! which is a deliberate and auditable act rather than an omission.
//!
//! # Why the window is durable
//!
//! Both bounds are worthless if a restart resets them, and a restart is not an
//! exceptional event here: a rollout is precisely what a rotation window exists
//! to survive. An in-memory count is zeroed by the restart that opens the
//! window, which turns the reading an operator closes on into a fresh zero that
//! looks like "nothing is using the old token" and is not.
//!
//! So the window's start instant and its accept count live in a small JSON
//! record beside the surface's other durable state, written the way
//! `state::write_persisted_mcp_transactions_checked` writes its own: serialize,
//! write a temporary file, fsync it, rename it into place, fsync the directory.
//! A process that starts with a superseded token configured RESUMES the record
//! it finds rather than opening a new window, so the age keeps running and the
//! count keeps climbing across a restart. A process that starts with no
//! superseded token configured removes the record, so closing a window clears
//! its state and the next rotation opens a fresh one.
//!
//! The record carries no token material, not even a digest: a start instant and
//! a count are all the two bounds need, so there is nothing in the file that
//! could verify a guess at either token.
//!
//! # What durability here does and does not reach
//!
//! The record survives any restart that preserves the surface's state
//! directory, which is every local daemon and every container restart inside a
//! live pod. It does NOT survive a pod REPLACEMENT in the hosted `kin-daemon`
//! Deployment, whose workspace volume is an `emptyDir` (kin-infra
//! `compute/workloads.ts`), so a replaced pod starts with an empty state
//! directory and opens a fresh window. That is a property of the volume, not of
//! this module, and giving the deployment a persistent volume would close it.
//!
//! Until it is closed, `/auth/rotation` is what keeps the gap legible rather
//! than silent: it reports `window_opened_unix`, so a count of zero on a window
//! that opened ninety seconds ago is visibly not the same claim as a count of
//! zero on one that opened yesterday. The count is also per-replica, so a
//! reading from one pod says nothing about the others.
//!
//! # Retention and rollback
//!
//! A rollback restores a previous Deployment revision, and that revision's
//! containers carry the token they were built with. So the superseded token has
//! to stay accepted for at least as long as a rollback to the previous revision
//! is a thing anyone would do, which is what the default age bound is sized
//! for. Retiring it sooner turns the rollback itself into the outage the
//! rollback was meant to end, and that is the cost of setting the bound too
//! low: the two ways of getting it wrong are not symmetric, and closing early
//! is the expensive one.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::Arc;

use sha2::{Digest, Sha256};

/// Which of the accepted tokens a request presented.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenVerdict {
    /// Enforcement is off for this surface: no primary token is configured.
    NotEnforced,
    /// The token this surface primarily expects.
    Primary,
    /// The superseded token, accepted because the rotation window is open and
    /// inside both of its bounds.
    Previous,
    /// The superseded token, refused because the rotation window has closed.
    ///
    /// Distinct from `Rejected` so the surface can log WHICH bound closed the
    /// window. It is not distinct to the caller: both map to the same 401 with
    /// the same body, because telling an unauthenticated caller that the value
    /// it presented used to be a valid credential here is information it should
    /// not get from a refusal.
    WindowClosed(WindowClosure),
    /// Neither accepted token.
    Rejected,
}

impl TokenVerdict {
    /// Whether the request may proceed.
    pub fn is_accepted(self) -> bool {
        matches!(self, Self::NotEnforced | Self::Primary | Self::Previous)
    }
}

/// Which bound closed a rotation overlap window.
///
/// Each variant carries the bound it breached and the variable that sets it, so
/// the refusal names the knob an operator would turn rather than making them
/// work out which of the two fired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowClosure {
    /// The window has been open longer than its configured maximum age.
    Expired {
        max_age_secs: u64,
        age_secs: u64,
        env: &'static str,
    },
    /// The window has accepted its configured maximum number of superseded
    /// requests.
    AcceptsExhausted { max_accepts: u64, env: &'static str },
}

impl WindowClosure {
    /// A stable one-word reason, for `/auth/rotation` and for log fields.
    pub fn reason(self) -> &'static str {
        match self {
            Self::Expired { .. } => "expired",
            Self::AcceptsExhausted { .. } => "accepts_exhausted",
        }
    }

    /// The operator-facing sentence naming which bound closed the window.
    ///
    /// The two are deliberately different sentences rather than one sentence
    /// with a substituted noun: a message that varies only in a field cannot
    /// tell a reader, or a test, which branch produced it.
    pub fn message(self) -> String {
        match self {
            Self::Expired {
                max_age_secs,
                age_secs,
                env,
            } => format!(
                "the rotation overlap window opened {age_secs} seconds ago and its maximum age is \
                 {max_age_secs} seconds, so the superseded token is no longer accepted. Finish the \
                 rotation, or raise {env} and restart if the window still needs to be open."
            ),
            Self::AcceptsExhausted { max_accepts, env } => format!(
                "the rotation overlap window has already accepted its maximum of {max_accepts} \
                 requests on the superseded token, so it is no longer accepted. Finish the \
                 rotation, or raise {env} and restart if the window still needs to be open."
            ),
        }
    }
}

/// How a token set or its bounds were rejected at construction.
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
    /// A bound variable is set to something that is not a positive whole
    /// number.
    ///
    /// Refused rather than defaulted, and refused rather than read as
    /// "unbounded", because both of those turn a fat-fingered bound into a
    /// window with no enforced end, which is the state the bounds exist to
    /// prevent.
    UnusableBound {
        env: String,
        requirement: &'static str,
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
            Self::UnusableBound { env, requirement } => write!(
                f,
                "{env} must be {requirement}. It bounds how long a rotation overlap window stays \
                 open, so it is refused rather than defaulted or read as unbounded. Set it to a \
                 usable value or unset it to take the default."
            ),
        }
    }
}

impl std::error::Error for RotationConfigError {}

/// The two bounds a rotation overlap window closes on, and the variables that
/// set them.
///
/// Both are ceilings rather than targets. The counter on `/auth/rotation` is
/// still what says a window can close EARLY; these say when it closes anyway.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RotationBounds {
    max_age_secs: u64,
    max_accepts: u64,
    max_age_env: &'static str,
    max_accepts_env: &'static str,
}

impl RotationBounds {
    /// Maximum age of a rotation overlap window, in seconds, when unset.
    ///
    /// One day. A rollout and any rollback anyone would actually perform are
    /// over long before this, and a window still open the next day was almost
    /// certainly forgotten rather than held open on purpose.
    pub const DEFAULT_MAX_AGE_SECS: u64 = 86_400;

    /// Maximum number of superseded-token accepts when unset.
    ///
    /// A ceiling, not an estimate of a rollout's traffic. The senders crossing
    /// a hosted rotation window are three containers rather than a user
    /// population, so this sits far above what a rotation should need and far
    /// below indefinite. A surface that legitimately serves more raises it.
    pub const DEFAULT_MAX_ACCEPTS: u64 = 10_000;

    const AGE_REQUIREMENT: &'static str = "a whole number of seconds greater than zero";
    const ACCEPTS_REQUIREMENT: &'static str = "a whole number of requests greater than zero";

    /// Read both bounds from the environment, refusing an unusable value.
    ///
    /// An unset or empty variable takes the default; anything else must parse
    /// as a positive whole number.
    pub fn from_env(
        max_age_env: &'static str,
        max_accepts_env: &'static str,
    ) -> Result<Self, RotationConfigError> {
        Ok(Self {
            max_age_secs: positive_bound_from_env(
                max_age_env,
                Self::DEFAULT_MAX_AGE_SECS,
                Self::AGE_REQUIREMENT,
            )?,
            max_accepts: positive_bound_from_env(
                max_accepts_env,
                Self::DEFAULT_MAX_ACCEPTS,
                Self::ACCEPTS_REQUIREMENT,
            )?,
            max_age_env,
            max_accepts_env,
        })
    }

    /// The default bounds, for a surface that opens no window.
    ///
    /// Infallible on purpose. A primary-only surface has no window for a bound
    /// to close, so reading the environment there would let a fat-fingered
    /// bound refuse a path that was never going to use it.
    pub fn defaults(max_age_env: &'static str, max_accepts_env: &'static str) -> Self {
        Self {
            max_age_secs: Self::DEFAULT_MAX_AGE_SECS,
            max_accepts: Self::DEFAULT_MAX_ACCEPTS,
            max_age_env,
            max_accepts_env,
        }
    }

    /// Bounds built directly, for tests and for callers that do not read the
    /// environment.
    pub fn new(
        max_age_secs: u64,
        max_accepts: u64,
        max_age_env: &'static str,
        max_accepts_env: &'static str,
    ) -> Result<Self, RotationConfigError> {
        if max_age_secs == 0 {
            return Err(RotationConfigError::UnusableBound {
                env: max_age_env.to_string(),
                requirement: Self::AGE_REQUIREMENT,
            });
        }
        if max_accepts == 0 {
            return Err(RotationConfigError::UnusableBound {
                env: max_accepts_env.to_string(),
                requirement: Self::ACCEPTS_REQUIREMENT,
            });
        }
        Ok(Self {
            max_age_secs,
            max_accepts,
            max_age_env,
            max_accepts_env,
        })
    }

    pub fn max_age_secs(&self) -> u64 {
        self.max_age_secs
    }

    pub fn max_accepts(&self) -> u64 {
        self.max_accepts
    }
}

/// Parse one bound, refusing anything that is not a positive whole number.
///
/// The refusal names the variable and the requirement and never the value it
/// found. An operator can paste anything into a variable, up to and including
/// the token they meant to put in the one above it, so a bound parser that
/// echoed its input would be a token-material leak waiting for a typo.
fn positive_bound_from_env(
    env: &str,
    default: u64,
    requirement: &'static str,
) -> Result<u64, RotationConfigError> {
    let Ok(raw) = std::env::var(env) else {
        return Ok(default);
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Ok(default);
    }
    match trimmed.parse::<u64>() {
        Ok(value) if value > 0 => Ok(value),
        _ => Err(RotationConfigError::UnusableBound {
            env: env.to_string(),
            requirement,
        }),
    }
}

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

/// The durable half of a rotation overlap window.
///
/// Two numbers and no token material: a start instant and a count are all the
/// two bounds need, so there is nothing here that could verify a guess at
/// either token, and nothing that a backup of the state directory would carry
/// beyond the fact that a rotation happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct WindowRecord {
    /// Unix seconds at which this window was first opened, by this process or
    /// by one that has since restarted.
    opened_unix: i64,
    /// Accepts on the superseded token across every process that has served
    /// this window.
    previous_accepted: u64,
}

/// One open rotation overlap window: where its durable record lives, when it
/// opened, and what closes it.
#[derive(Debug)]
struct RotationWindow {
    record_path: PathBuf,
    opened_unix: i64,
    bounds: RotationBounds,
}

/// Live readings for a rotation overlap window.
///
/// Shared rather than owned so the surface exposing the reading and the guard
/// recording it are looking at the same numbers. Cloning a `RotationTokens`
/// clones the handle, not the counts, which is what the axum middleware layer
/// needs: it clones the state per request.
#[derive(Debug, Default)]
struct RotationCounters {
    /// Accepts on the superseded token, seeded from the durable record at
    /// startup so it counts the window rather than the process.
    previous_accepted: AtomicU64,
    /// Unix seconds of the most recent accept on the superseded token, or 0 if
    /// this process has not seen one. Zero is distinguishable from a real
    /// timestamp because this daemon cannot be serving in 1970.
    previous_last_accepted_unix: AtomicI64,
    /// Superseded-token requests this process has refused because a bound had
    /// closed the window. In memory on purpose: it is the alarm that says
    /// closing the window broke something, and it is about this process rather
    /// than about the window.
    previous_refused_since_start: AtomicU64,
    /// Set once if a durable write fails, so the status route can say the count
    /// has stopped surviving a restart instead of implying it still does.
    persist_failed: AtomicBool,
}

/// The bearer tokens one daemon surface accepts.
#[derive(Clone)]
pub struct RotationTokens {
    primary: Option<TokenDigest>,
    previous: Option<TokenDigest>,
    window: Option<Arc<RotationWindow>>,
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
            .field("window_opened_unix", &self.window_opened_unix())
            .finish()
    }
}

impl RotationTokens {
    /// A surface with no enforcement and no window.
    pub fn disabled() -> Self {
        Self {
            primary: None,
            previous: None,
            window: None,
            counters: Arc::new(RotationCounters::default()),
        }
    }

    /// Build a token set, refusing the configurations that cannot mean what they
    /// appear to, and open or resume the rotation window.
    ///
    /// `primary_env` and `previous_env` name the variables the values came from
    /// and appear in a refusal, so an operator reading it knows which of the
    /// two to change. Neither token value is ever put in the message.
    ///
    /// `record_path` is where the durable window record lives. It is passed in
    /// rather than derived here because the two surfaces keep their state in
    /// different directories, and a shared default would let a future change to
    /// either directory silently join their windows into one.
    pub fn new(
        primary: Option<String>,
        previous: Option<String>,
        primary_env: &str,
        previous_env: &str,
        record_path: PathBuf,
        bounds: RotationBounds,
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

        let counters = Arc::new(RotationCounters::default());
        let window = if previous.is_some() {
            let record = open_or_resume_window(&record_path);
            counters
                .previous_accepted
                .store(record.previous_accepted, Ordering::Relaxed);
            Some(Arc::new(RotationWindow {
                record_path,
                opened_unix: record.opened_unix,
                bounds,
            }))
        } else {
            // Closing a window clears its state, so the next rotation opens a
            // fresh one rather than inheriting a spent age and count. Every way
            // of unsetting the superseded token in the hosted deployment goes
            // through a restart, which is why this is the right place for it.
            discard_window_record(&record_path);
            None
        };

        Ok(Self {
            primary: primary.as_deref().map(TokenDigest::of),
            previous: previous.as_deref().map(TokenDigest::of),
            window,
            counters,
        })
    }

    /// Whether this surface enforces a token at all.
    pub fn is_enforced(&self) -> bool {
        self.primary.is_some()
    }

    /// Whether a superseded token is configured.
    ///
    /// This says the operator has opened a window, not that the window is still
    /// accepting: a window whose bounds have closed still reports `true` here
    /// until the superseded token is unset. `window_closure()` is the live
    /// state.
    pub fn overlap_open(&self) -> bool {
        self.previous.is_some()
    }

    /// How many requests have been accepted on the superseded token, across
    /// every process that has served this window.
    ///
    /// This is the reading step 3 of a rotation waits on. A window whose count
    /// is still climbing has traffic on the retired credential, and closing it
    /// would 401 that traffic. Read it beside `window_opened_unix`: a zero on a
    /// window that opened a minute ago is not the same claim as a zero on one
    /// that opened yesterday.
    pub fn previous_accepted_count(&self) -> u64 {
        self.counters.previous_accepted.load(Ordering::Relaxed)
    }

    /// Unix seconds of the most recent accept on the superseded token, or `None`
    /// if this process has not seen one.
    pub fn previous_last_accepted_unix(&self) -> Option<i64> {
        let stamp = self
            .counters
            .previous_last_accepted_unix
            .load(Ordering::Relaxed);
        (stamp != 0).then_some(stamp)
    }

    /// Unix seconds at which the open window opened, or `None` when no window
    /// is open.
    pub fn window_opened_unix(&self) -> Option<i64> {
        self.window.as_ref().map(|window| window.opened_unix)
    }

    /// Unix seconds at which the open window's age bound closes it, or `None`
    /// when no window is open.
    pub fn window_expires_unix(&self) -> Option<i64> {
        self.window.as_ref().map(|window| {
            window
                .opened_unix
                .saturating_add(window.bounds.max_age_secs as i64)
        })
    }

    /// The open window's bounds, or `None` when no window is open.
    pub fn window_bounds(&self) -> Option<RotationBounds> {
        self.window.as_ref().map(|window| window.bounds)
    }

    /// Which bound has closed the open window, if either has.
    ///
    /// `None` means the window is still accepting, or that no window is open at
    /// all; `overlap_open()` separates those two.
    pub fn window_closure(&self) -> Option<WindowClosure> {
        let window = self.window.as_ref()?;
        window
            .age_closure(chrono::Utc::now().timestamp())
            .or_else(|| window.accepts_closure(self.previous_accepted_count()))
    }

    /// Superseded-token requests this process has refused because a bound had
    /// closed the window.
    ///
    /// Per-process rather than durable, because it is an alarm about now: a
    /// number climbing here says the window closed while something was still
    /// presenting the retired token, which is the case that needs a human.
    pub fn previous_refused_since_start(&self) -> u64 {
        self.counters
            .previous_refused_since_start
            .load(Ordering::Relaxed)
    }

    /// Whether the window's durable record is still being written.
    ///
    /// `false` means the count in memory is no longer surviving a restart, so
    /// the bounds have quietly become per-process again. Reported rather than
    /// fatal: refusing traffic because a disk write failed would be the outage
    /// the window exists to prevent.
    pub fn window_state_durable(&self) -> bool {
        !self.counters.persist_failed.load(Ordering::Relaxed)
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
            return match self.admit_previous() {
                Ok(()) => TokenVerdict::Previous,
                Err(closure) => {
                    self.counters
                        .previous_refused_since_start
                        .fetch_add(1, Ordering::Relaxed);
                    TokenVerdict::WindowClosed(closure)
                }
            };
        }
        TokenVerdict::Rejected
    }

    /// Take one accept against the window's two bounds, or say which bound
    /// refused it.
    ///
    /// The age is checked first, so a window that has breached both is reported
    /// as expired: the age bound is the one about the credential's life, and
    /// the accept cap is the ceiling underneath it.
    fn admit_previous(&self) -> Result<(), WindowClosure> {
        // A superseded token with no window cannot be reached through `new`,
        // which builds one whenever a superseded token is configured. Refusing
        // rather than admitting keeps the unreachable case fail-closed.
        let Some(window) = self.window.as_ref() else {
            return Err(WindowClosure::Expired {
                max_age_secs: 0,
                age_secs: 0,
                env: "unknown",
            });
        };

        if let Some(closure) = window.age_closure(chrono::Utc::now().timestamp()) {
            return Err(closure);
        }

        // Claim a slot under the cap before serving it. A load-then-increment
        // would let concurrent requests both see the last slot and both take
        // it, so the cap would be a ceiling the window could step over by
        // exactly as many requests as happen to race.
        let mut observed = self.counters.previous_accepted.load(Ordering::Acquire);
        let taken = loop {
            if let Some(closure) = window.accepts_closure(observed) {
                return Err(closure);
            }
            match self.counters.previous_accepted.compare_exchange_weak(
                observed,
                observed + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break observed + 1,
                Err(current) => observed = current,
            }
        };

        self.persist(window, taken);
        self.counters
            .previous_last_accepted_unix
            .store(chrono::Utc::now().timestamp(), Ordering::Relaxed);
        Ok(())
    }

    /// Write the new count through to the durable record.
    ///
    /// A failure warns once and sets the flag `window_state_durable()` reports.
    /// It does not refuse the request: the count under-reporting after a restart
    /// is a legible problem, and 401ing a sender that holds a valid superseded
    /// token because a disk write failed is the outage this whole module exists
    /// to avoid.
    fn persist(&self, window: &RotationWindow, previous_accepted: u64) {
        let record = WindowRecord {
            opened_unix: window.opened_unix,
            previous_accepted,
        };
        if let Err(error) = write_window_record(&window.record_path, &record) {
            if !self.counters.persist_failed.swap(true, Ordering::Relaxed) {
                tracing::warn!(
                    path = %window.record_path.display(),
                    error = %error,
                    "the rotation window record could not be written; its accept count and its \
                     bounds will not survive a restart of this process"
                );
            }
        }
    }
}

impl RotationWindow {
    /// The age bound, evaluated against a caller-supplied now.
    ///
    /// A clock that has moved backwards past the recorded start yields a
    /// negative age, which is treated as expired rather than as a fresh window:
    /// a window whose start instant this process cannot make sense of is not
    /// one it should keep honouring.
    fn age_closure(&self, now_unix: i64) -> Option<WindowClosure> {
        let age = now_unix.checked_sub(self.opened_unix)?;
        if age < 0 {
            return Some(WindowClosure::Expired {
                max_age_secs: self.bounds.max_age_secs,
                age_secs: 0,
                env: self.bounds.max_age_env,
            });
        }
        let age = age as u64;
        (age >= self.bounds.max_age_secs).then_some(WindowClosure::Expired {
            max_age_secs: self.bounds.max_age_secs,
            age_secs: age,
            env: self.bounds.max_age_env,
        })
    }

    /// The accept-count bound, evaluated against a count already taken.
    fn accepts_closure(&self, already_accepted: u64) -> Option<WindowClosure> {
        (already_accepted >= self.bounds.max_accepts).then_some(WindowClosure::AcceptsExhausted {
            max_accepts: self.bounds.max_accepts,
            env: self.bounds.max_accepts_env,
        })
    }
}

/// Resume the window the record describes, or open a new one now.
///
/// An unreadable or nonsense record opens a new window rather than refusing to
/// serve: a corrupt state file is not a reason to take the surface down, and a
/// fresh window is the conservative reading of an unreadable one, since it
/// re-arms both bounds rather than assuming a budget that was already spent.
/// A record claiming a start instant in 1970 is nonsense for the same reason
/// the zero timestamp sentinel is safe: this daemon cannot be serving then.
fn open_or_resume_window(record_path: &Path) -> WindowRecord {
    if let Some(existing) = read_window_record(record_path) {
        return existing;
    }
    let opened = WindowRecord {
        opened_unix: chrono::Utc::now().timestamp(),
        previous_accepted: 0,
    };
    if let Err(error) = write_window_record(record_path, &opened) {
        tracing::warn!(
            path = %record_path.display(),
            error = %error,
            "the rotation window record could not be created; the window's age and accept bounds \
             will not survive a restart of this process"
        );
    }
    opened
}

fn read_window_record(record_path: &Path) -> Option<WindowRecord> {
    let bytes = std::fs::read(record_path).ok()?;
    let record: WindowRecord = serde_json::from_slice(&bytes).ok()?;
    (record.opened_unix > 0).then_some(record)
}

fn discard_window_record(record_path: &Path) {
    match std::fs::remove_file(record_path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => tracing::warn!(
            path = %record_path.display(),
            error = %error,
            "a closed rotation window's record could not be removed; the next rotation will \
             resume this one's age and accept count instead of opening a fresh window"
        ),
    }
}

/// Write the record the way `state::write_persisted_mcp_transactions_checked`
/// writes its own: temporary file, fsync, rename, fsync the directory.
///
/// The file is not given restrictive permissions because it holds no secret: a
/// start instant and a count. It sits beside files that do hold secrets, and
/// making it look like one of them would misreport what it is.
fn write_window_record(record_path: &Path, record: &WindowRecord) -> std::io::Result<()> {
    use std::io::Write as _;

    if let Some(parent) = record_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec(record).map_err(std::io::Error::other)?;
    let tmp = record_path.with_extension("json.tmp");
    let write_result = (|| -> std::io::Result<()> {
        let mut file = std::fs::File::create(&tmp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        std::fs::rename(&tmp, record_path)?;
        if let Some(parent) = record_path.parent() {
            crate::state::sync_directory_metadata(parent)?;
        }
        Ok(())
    })();
    if write_result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    write_result
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
    const MAX_AGE_ENV: &str = "KIN_DAEMON_AUTH_ROTATION_WINDOW_SECS";
    const MAX_ACCEPTS_ENV: &str = "KIN_DAEMON_AUTH_ROTATION_MAX_ACCEPTS";

    /// A token value that cannot occur in the refusal's own prose.
    ///
    /// The first version of these tests used "same" and failed, because the
    /// message says "carry the same value" for reasons that have nothing to do
    /// with interpolation. A leak assertion whose fixture is an ordinary word
    /// grades the wording rather than the code, so the fixture is a string no
    /// sentence would contain.
    const TOKEN_SENTINEL: &str = "qzqz-token-material-qzqz";

    fn record_path(dir: &Path) -> PathBuf {
        dir.join("auth-rotation-window.json")
    }

    fn bounds(max_age_secs: u64, max_accepts: u64) -> RotationBounds {
        RotationBounds::new(max_age_secs, max_accepts, MAX_AGE_ENV, MAX_ACCEPTS_ENV)
            .expect("positive bounds are usable")
    }

    fn tokens_bounded(
        dir: &Path,
        primary: Option<&str>,
        previous: Option<&str>,
        bounds: RotationBounds,
    ) -> RotationTokens {
        RotationTokens::new(
            primary.map(str::to_string),
            previous.map(str::to_string),
            PRIMARY_ENV,
            PREVIOUS_ENV,
            record_path(dir),
            bounds,
        )
        .expect("valid token configuration")
    }

    /// Bounds wide enough that neither can close the window inside a test, so a
    /// test about something else never accidentally grades a bound.
    fn tokens(dir: &Path, primary: Option<&str>, previous: Option<&str>) -> RotationTokens {
        tokens_bounded(dir, primary, previous, bounds(3_600, 1_000))
    }

    fn expect_previous_closure(set: &RotationTokens, token: &str) -> WindowClosure {
        match set.classify(Some(token)) {
            TokenVerdict::WindowClosed(closure) => closure,
            other => panic!("expected a closed rotation window, got {other:?}"),
        }
    }

    #[test]
    fn an_unconfigured_surface_does_not_enforce() {
        let dir = tempfile::tempdir().expect("tempdir");
        let set = tokens(dir.path(), None, None);
        assert!(!set.is_enforced());
        assert_eq!(set.classify(None), TokenVerdict::NotEnforced);
        assert_eq!(set.classify(Some("anything")), TokenVerdict::NotEnforced);
        assert!(set.classify(Some("anything")).is_accepted());
        assert_eq!(set.window_opened_unix(), None);
    }

    #[test]
    fn a_primary_only_surface_accepts_exactly_that_token() {
        let dir = tempfile::tempdir().expect("tempdir");
        let set = tokens(dir.path(), Some("current"), None);
        assert!(set.is_enforced());
        assert!(!set.overlap_open());
        assert_eq!(set.classify(Some("current")), TokenVerdict::Primary);
        assert_eq!(set.classify(Some("retired")), TokenVerdict::Rejected);
        assert_eq!(set.classify(None), TokenVerdict::Rejected);
        // The counter must stay at zero: with no window open there is nothing
        // for a superseded accept to mean.
        assert_eq!(set.previous_accepted_count(), 0);
        assert_eq!(set.previous_last_accepted_unix(), None);
        // And no window exists to bound, so nothing reports one.
        assert_eq!(set.window_opened_unix(), None);
        assert_eq!(set.window_closure(), None);
    }

    #[test]
    fn an_open_window_accepts_both_and_says_which() {
        let dir = tempfile::tempdir().expect("tempdir");
        let set = tokens(dir.path(), Some("current"), Some("retired"));
        assert!(set.overlap_open());
        assert_eq!(set.classify(Some("current")), TokenVerdict::Primary);
        assert_eq!(set.classify(Some("retired")), TokenVerdict::Previous);
        assert_eq!(set.classify(Some("neither")), TokenVerdict::Rejected);
        // An open window inside both bounds reports no closure.
        assert_eq!(set.window_closure(), None);
    }

    #[test]
    fn only_a_superseded_accept_moves_the_counter() {
        let dir = tempfile::tempdir().expect("tempdir");
        let set = tokens(dir.path(), Some("current"), Some("retired"));
        assert_eq!(set.previous_accepted_count(), 0);

        // The primary must not move it. A counter that also counted primary
        // traffic would never reach the zero an operator closes the window on,
        // and would spend the accept cap on traffic the window is not about.
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
        let dir = tempfile::tempdir().expect("tempdir");
        let set = tokens(dir.path(), Some("current"), Some("retired"));
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
        let dir = tempfile::tempdir().expect("tempdir");
        let set = tokens(dir.path(), Some("current"), Some("   "));
        assert!(!set.overlap_open());
        assert_eq!(set.classify(Some("   ")), TokenVerdict::Rejected);
        // No window is opened for a blank, so no record is written either.
        assert!(!record_path(dir.path()).exists());

        let other = tempfile::tempdir().expect("tempdir");
        let none = tokens(other.path(), Some("  \t "), None);
        assert!(!none.is_enforced());
    }

    #[test]
    fn a_presented_token_is_trimmed_by_the_caller_not_here() {
        // The guards strip "Bearer " and trim before calling in, and this
        // asserts classify does not trim again: a token whose real value has
        // surrounding space would otherwise authenticate under two spellings.
        let dir = tempfile::tempdir().expect("tempdir");
        let set = tokens(dir.path(), Some("current"), None);
        assert_eq!(set.classify(Some(" current ")), TokenVerdict::Rejected);
    }

    #[test]
    fn a_superseded_token_with_no_primary_is_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let error = RotationTokens::new(
            None,
            Some(TOKEN_SENTINEL.to_string()),
            PRIMARY_ENV,
            PREVIOUS_ENV,
            record_path(dir.path()),
            bounds(3_600, 1_000),
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
        let dir = tempfile::tempdir().expect("tempdir");
        let error = RotationTokens::new(
            Some(TOKEN_SENTINEL.to_string()),
            Some(TOKEN_SENTINEL.to_string()),
            PRIMARY_ENV,
            PREVIOUS_ENV,
            record_path(dir.path()),
            bounds(3_600, 1_000),
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
        let dir = tempfile::tempdir().expect("tempdir");
        RotationTokens::new(
            Some(TOKEN_SENTINEL.to_string()),
            Some(format!("  {TOKEN_SENTINEL}  ")),
            PRIMARY_ENV,
            PREVIOUS_ENV,
            record_path(dir.path()),
            bounds(3_600, 1_000),
        )
        .expect_err("a pair identical after trimming must be refused");
    }

    #[test]
    fn debug_reports_presence_and_never_material() {
        let dir = tempfile::tempdir().expect("tempdir");
        let set = tokens(
            dir.path(),
            Some("super-secret-primary"),
            Some("super-secret-retired"),
        );
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

    // ---- The two bounds ------------------------------------------------

    #[test]
    fn the_age_bound_closes_a_window_that_has_been_open_too_long() {
        // The window's start instant comes from the durable record, so an old
        // record is how a long-open window is reached without waiting for one.
        // This is the same path a restart takes, which is why it is written
        // through `write_window_record` rather than by hand.
        let dir = tempfile::tempdir().expect("tempdir");
        let opened = chrono::Utc::now().timestamp() - 10_000;
        write_window_record(
            &record_path(dir.path()),
            &WindowRecord {
                opened_unix: opened,
                previous_accepted: 0,
            },
        )
        .expect("seed the window record");

        let set = tokens_bounded(
            dir.path(),
            Some("current"),
            Some("retired"),
            bounds(5, 1_000),
        );
        assert_eq!(set.window_opened_unix(), Some(opened));

        // The primary is untouched by the age bound: an expired window must
        // never take the surface down, only end the superseded token's life.
        assert_eq!(set.classify(Some("current")), TokenVerdict::Primary);

        let closure = expect_previous_closure(&set, "retired");
        let WindowClosure::Expired {
            max_age_secs,
            age_secs,
            env,
        } = closure
        else {
            panic!("expected the age bound to close the window, got {closure:?}");
        };
        assert_eq!(max_age_secs, 5);
        assert_eq!(env, MAX_AGE_ENV);
        assert!(
            (10_000..=10_010).contains(&age_secs),
            "age {age_secs} is not the seeded window's age"
        );
        // A refused request must not be counted as an accept, or the reading an
        // operator closes on would climb after the window had already closed.
        assert_eq!(set.previous_accepted_count(), 0);
        assert_eq!(set.previous_refused_since_start(), 1);
        assert!(!closure.message().is_empty());
    }

    #[test]
    fn the_accept_bound_closes_a_window_that_has_carried_its_cap() {
        let dir = tempfile::tempdir().expect("tempdir");
        let set = tokens_bounded(
            dir.path(),
            Some("current"),
            Some("retired"),
            bounds(3_600, 2),
        );

        assert_eq!(set.classify(Some("retired")), TokenVerdict::Previous);
        assert_eq!(set.classify(Some("retired")), TokenVerdict::Previous);
        assert_eq!(set.previous_accepted_count(), 2);

        let closure = expect_previous_closure(&set, "retired");
        let WindowClosure::AcceptsExhausted { max_accepts, env } = closure else {
            panic!("expected the accept bound to close the window, got {closure:?}");
        };
        assert_eq!(max_accepts, 2);
        assert_eq!(env, MAX_ACCEPTS_ENV);
        // The cap is a ceiling, not a soft target: the refused request must not
        // push the count past the cap it was refused by.
        assert_eq!(set.previous_accepted_count(), 2);
        assert_eq!(set.previous_refused_since_start(), 1);
        // And the primary keeps working after the window closes.
        assert_eq!(set.classify(Some("current")), TokenVerdict::Primary);
    }

    #[test]
    fn a_restart_resumes_the_window_rather_than_reopening_it() {
        // The defect this exists for: the counter and the clock both used to
        // live only in the process, so the restart that a rotation window is
        // opened to survive reset both. A second process against the same state
        // directory must continue the first one's window, not start a new one.
        let dir = tempfile::tempdir().expect("tempdir");
        let bounds = bounds(3_600, 2);

        let first = tokens_bounded(dir.path(), Some("current"), Some("retired"), bounds);
        assert_eq!(first.classify(Some("retired")), TokenVerdict::Previous);
        assert_eq!(first.classify(Some("retired")), TokenVerdict::Previous);
        assert_eq!(first.previous_accepted_count(), 2);
        let opened = first.window_opened_unix().expect("an open window");
        drop(first);

        let second = tokens_bounded(dir.path(), Some("current"), Some("retired"), bounds);
        // The clock resumed: the second process's window opened when the first
        // one's did, so the age bound keeps running across the restart.
        assert_eq!(second.window_opened_unix(), Some(opened));
        // The count resumed: a fresh zero here is the reading that tells an
        // operator nothing is using the retired token when something is.
        assert_eq!(second.previous_accepted_count(), 2);
        // And the resumed count is load-bearing rather than decorative: the cap
        // it carries past closes the window in the new process immediately.
        let closure = expect_previous_closure(&second, "retired");
        assert!(
            matches!(closure, WindowClosure::AcceptsExhausted { .. }),
            "the resumed count must close the window, got {closure:?}"
        );
    }

    #[test]
    fn the_two_bounds_refuse_with_different_messages() {
        // Two branches that report the same field are indistinguishable to a
        // field-level assertion, so each arm asserts its whole sentence. Both
        // closures are produced by real windows rather than built by hand, so a
        // guard that sent every refusal down one branch fails here rather than
        // passing on a message it still formats correctly.
        let expired_dir = tempfile::tempdir().expect("tempdir");
        let opened = chrono::Utc::now().timestamp() - 600;
        write_window_record(
            &record_path(expired_dir.path()),
            &WindowRecord {
                opened_unix: opened,
                previous_accepted: 0,
            },
        )
        .expect("seed the window record");
        let expired = tokens_bounded(
            expired_dir.path(),
            Some("current"),
            Some("retired"),
            bounds(60, 1_000),
        );
        let expired_closure = expect_previous_closure(&expired, "retired");
        let WindowClosure::Expired { age_secs, .. } = expired_closure else {
            panic!("expected the age bound, got {expired_closure:?}");
        };
        assert!(
            (600..=610).contains(&age_secs),
            "age {age_secs} is not the seeded window's age"
        );
        assert_eq!(expired_closure.reason(), "expired");
        assert_eq!(
            expired_closure.message(),
            format!(
                "the rotation overlap window opened {age_secs} seconds ago and its maximum age is \
                 60 seconds, so the superseded token is no longer accepted. Finish the rotation, \
                 or raise KIN_DAEMON_AUTH_ROTATION_WINDOW_SECS and restart if the window still \
                 needs to be open."
            )
        );

        let exhausted_dir = tempfile::tempdir().expect("tempdir");
        let exhausted = tokens_bounded(
            exhausted_dir.path(),
            Some("current"),
            Some("retired"),
            bounds(3_600, 1),
        );
        assert_eq!(exhausted.classify(Some("retired")), TokenVerdict::Previous);
        let exhausted_closure = expect_previous_closure(&exhausted, "retired");
        assert_eq!(exhausted_closure.reason(), "accepts_exhausted");
        assert_eq!(
            exhausted_closure.message(),
            "the rotation overlap window has already accepted its maximum of 1 requests on the \
             superseded token, so it is no longer accepted. Finish the rotation, or raise \
             KIN_DAEMON_AUTH_ROTATION_MAX_ACCEPTS and restart if the window still needs to be \
             open."
        );

        // The join: the two arms must not be able to collapse onto one another.
        assert_ne!(expired_closure.message(), exhausted_closure.message());
        assert_ne!(expired_closure.reason(), exhausted_closure.reason());
    }

    #[test]
    fn a_closed_window_is_still_a_configured_overlap() {
        // `overlap_open` answers "did an operator set the superseded token",
        // and `window_closure` answers "is it still being accepted". Collapsing
        // the two would make a closed window look like a finished rotation on
        // the status route, and the operator would never learn that traffic is
        // now being refused.
        let dir = tempfile::tempdir().expect("tempdir");
        let set = tokens_bounded(
            dir.path(),
            Some("current"),
            Some("retired"),
            bounds(3_600, 1),
        );
        assert_eq!(set.classify(Some("retired")), TokenVerdict::Previous);
        assert!(set.overlap_open());
        assert!(set.window_closure().is_some());
        assert_eq!(
            set.window_closure().map(WindowClosure::reason),
            Some("accepts_exhausted")
        );
    }

    #[test]
    fn closing_the_window_discards_its_record() {
        // Removing the superseded token must clear the window's state, or the
        // next rotation would resume a spent age and count and close on its
        // first request.
        let dir = tempfile::tempdir().expect("tempdir");
        let open = tokens(dir.path(), Some("current"), Some("retired"));
        assert_eq!(open.classify(Some("retired")), TokenVerdict::Previous);
        assert!(record_path(dir.path()).exists());
        drop(open);

        let closed = tokens(dir.path(), Some("current"), None);
        assert!(!closed.overlap_open());
        assert!(
            !record_path(dir.path()).exists(),
            "closing the window must remove its record"
        );

        // A later rotation therefore opens a fresh window rather than resuming.
        let reopened = tokens(dir.path(), Some("current"), Some("retired-again"));
        assert_eq!(reopened.previous_accepted_count(), 0);
    }

    #[test]
    fn a_zero_bound_is_refused_rather_than_read_as_unbounded() {
        // The whole point of the bounds is that no configuration leaves the
        // window without an end. A zero read as "unbounded" would put back
        // exactly the state they were added to remove.
        let age = RotationBounds::new(0, 10, MAX_AGE_ENV, MAX_ACCEPTS_ENV)
            .expect_err("a zero age bound must be refused");
        assert_eq!(
            age,
            RotationConfigError::UnusableBound {
                env: MAX_AGE_ENV.to_string(),
                requirement: "a whole number of seconds greater than zero",
            }
        );
        assert!(age.to_string().contains(MAX_AGE_ENV), "{age}");

        let accepts = RotationBounds::new(10, 0, MAX_AGE_ENV, MAX_ACCEPTS_ENV)
            .expect_err("a zero accept bound must be refused");
        assert_eq!(
            accepts,
            RotationConfigError::UnusableBound {
                env: MAX_ACCEPTS_ENV.to_string(),
                requirement: "a whole number of requests greater than zero",
            }
        );
        assert!(accepts.to_string().contains(MAX_ACCEPTS_ENV), "{accepts}");
        // The two refusals name different variables, so an operator is not sent
        // to the wrong knob.
        assert_ne!(age.to_string(), accepts.to_string());
    }

    #[test]
    fn bounds_are_read_from_the_environment_and_an_unusable_value_is_refused() {
        // `KIN_*` reads are process-global, so this holds the shared lock every
        // env-mutating test in this binary takes.
        let _guard = crate::test_env_lock();
        const AGE: &str = "KIN_DAEMON_AUTH_ROTATION_WINDOW_SECS";
        const ACCEPTS: &str = "KIN_DAEMON_AUTH_ROTATION_MAX_ACCEPTS";

        std::env::remove_var(AGE);
        std::env::remove_var(ACCEPTS);
        let defaulted = RotationBounds::from_env(AGE, ACCEPTS).expect("unset takes the defaults");
        assert_eq!(
            defaulted.max_age_secs(),
            RotationBounds::DEFAULT_MAX_AGE_SECS
        );
        assert_eq!(defaulted.max_accepts(), RotationBounds::DEFAULT_MAX_ACCEPTS);

        std::env::set_var(AGE, "120");
        std::env::set_var(ACCEPTS, "7");
        let set = RotationBounds::from_env(AGE, ACCEPTS).expect("positive values are usable");
        assert_eq!(set.max_age_secs(), 120);
        assert_eq!(set.max_accepts(), 7);

        // Zero is refused rather than read as unbounded, and so is a value that
        // is not a number at all. Both would otherwise silently default.
        std::env::set_var(AGE, "0");
        let zero = RotationBounds::from_env(AGE, ACCEPTS).expect_err("zero must be refused");
        assert_eq!(
            zero,
            RotationConfigError::UnusableBound {
                env: AGE.to_string(),
                requirement: "a whole number of seconds greater than zero",
            }
        );

        std::env::set_var(AGE, "forever");
        let unparseable = RotationBounds::from_env(AGE, ACCEPTS)
            .expect_err("a value that is not a number must be refused");
        assert!(matches!(
            unparseable,
            RotationConfigError::UnusableBound { .. }
        ));
        // The refusal must not echo what it found. An operator can paste
        // anything into a bound variable, including the token meant for the
        // one above it.
        std::env::set_var(AGE, TOKEN_SENTINEL);
        let pasted = RotationBounds::from_env(AGE, ACCEPTS)
            .expect_err("a pasted token must be refused as a bound")
            .to_string();
        assert!(
            !pasted.contains(TOKEN_SENTINEL),
            "the bound refusal must not carry what it read: {pasted}"
        );
        assert!(pasted.contains(AGE), "{pasted}");
        // Control: the assertion above must be able to fire.
        assert!(format!("leaked {TOKEN_SENTINEL}").contains(TOKEN_SENTINEL));

        std::env::remove_var(AGE);
        std::env::remove_var(ACCEPTS);
    }

    #[test]
    fn an_unreadable_record_opens_a_fresh_window_rather_than_refusing_to_serve() {
        // A corrupt state file is not a reason to take the surface down, and a
        // fresh window is the conservative reading of one: it re-arms both
        // bounds rather than assuming a budget that was already spent.
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(record_path(dir.path()), b"{not json").expect("write a corrupt record");
        let set = tokens(dir.path(), Some("current"), Some("retired"));
        let opened = set.window_opened_unix().expect("a fresh window");
        assert!(
            (chrono::Utc::now().timestamp() - opened).abs() < 60,
            "a corrupt record must open a window now, not at {opened}"
        );
        assert_eq!(set.previous_accepted_count(), 0);
        assert_eq!(set.classify(Some("retired")), TokenVerdict::Previous);
    }
}
