// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Idle-window floors held by attached clients for as long as their session
//! lasts.
//!
//! A daemon's own idle window is fixed by whichever process spawned it, and on
//! a developer machine that is usually an ordinary CLI command with the short
//! CLI window. An MCP session that attaches afterwards needs the daemon to
//! outlive the pauses between an agent's tool calls, so it states a floor. A
//! floor is a lease rather than a permanent change: it lasts while the session
//! renews it, it ends when the session releases it, and a session that dies
//! without releasing it loses it one floor after its last renewal. The daemon
//! then returns to its own idle policy instead of keeping the attached
//! client's window for the rest of its life.
//!
//! The effective window is the larger of the daemon's own window and every
//! live floor. A daemon that never idles out keeps never idling out, and a
//! floor can never shorten a window another client relies on.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// The most leases one daemon holds at once.
///
/// A floor is a statement of need, not a way to pin a daemon's memory for
/// good. Each lease's floor is clamped by its caller to the same ceiling a
/// permanent raise gets, and this count bounds what a misbehaving client can
/// make the table hold.
pub const MAX_IDLE_FLOOR_LEASES: usize = 256;

/// Longest lease id accepted, in bytes.
pub const MAX_IDLE_FLOOR_LEASE_ID_BYTES: usize = 128;

#[derive(Debug, Clone)]
struct Lease {
    floor: Duration,
    expires_at: Instant,
    client: String,
}

/// What holding or renewing a lease did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseHeld {
    /// The floor this lease now holds, after clamping.
    pub floor: Duration,
    /// How long the lease lasts without another renewal.
    pub expires_in: Duration,
    /// Whether this call created the lease rather than renewing it.
    pub created: bool,
}

/// Why a lease was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeaseRefusal {
    /// The id was empty, too long, or not printable ASCII.
    InvalidId,
    /// A floor of zero asks for nothing, and "never idle out" is not a floor.
    ZeroFloor,
    /// The table already holds [`MAX_IDLE_FLOOR_LEASES`] live leases.
    TooManyLeases,
}

impl LeaseRefusal {
    pub fn message(&self) -> String {
        match self {
            Self::InvalidId => format!(
                "lease must be 1 to {MAX_IDLE_FLOOR_LEASE_ID_BYTES} printable ASCII characters"
            ),
            Self::ZeroFloor => {
                "at_least_secs must be positive; a floor of forever is not a floor".to_string()
            }
            Self::TooManyLeases => format!(
                "this daemon already holds {MAX_IDLE_FLOOR_LEASES} idle-floor leases; release one \
                 or wait for one to expire"
            ),
        }
    }
}

/// The idle-floor leases one daemon holds.
#[derive(Debug, Default)]
pub struct IdleFloorLeases {
    leases: Mutex<HashMap<String, Lease>>,
}

impl IdleFloorLeases {
    /// Hold or renew `id` with `floor`, clamped to `max_floor`, as of `now`.
    ///
    /// A renewal replaces the floor rather than keeping the larger of the two,
    /// so a session that lowers what it needs is taken at its word. The lease
    /// lasts one floor from `now`: a session that goes quiet for longer than
    /// its own floor has stopped needing the daemon under any reading.
    pub fn hold(
        &self,
        id: &str,
        floor: Duration,
        max_floor: Duration,
        client: &str,
        now: Instant,
    ) -> Result<LeaseHeld, LeaseRefusal> {
        if !valid_lease_id(id) {
            return Err(LeaseRefusal::InvalidId);
        }
        if floor.is_zero() {
            return Err(LeaseRefusal::ZeroFloor);
        }
        let floor = floor.min(max_floor);
        let mut leases = self.table();
        leases.retain(|_, lease| lease.expires_at > now);
        let created = !leases.contains_key(id);
        if created && leases.len() >= MAX_IDLE_FLOOR_LEASES {
            return Err(LeaseRefusal::TooManyLeases);
        }
        leases.insert(
            id.to_string(),
            Lease {
                floor,
                expires_at: now + floor,
                client: client.chars().take(64).collect(),
            },
        );
        Ok(LeaseHeld {
            floor,
            expires_in: floor,
            created,
        })
    }

    /// Release `id`. Returns the client that held it, or `None` when no live
    /// lease had that id.
    pub fn release(&self, id: &str, now: Instant) -> Option<String> {
        let mut leases = self.table();
        leases.retain(|_, lease| lease.expires_at > now);
        leases.remove(id).map(|lease| lease.client)
    }

    /// The largest floor any live lease holds as of `now`.
    pub fn floor(&self, now: Instant) -> Option<Duration> {
        self.table()
            .values()
            .filter(|lease| lease.expires_at > now)
            .map(|lease| lease.floor)
            .max()
    }

    /// How many leases are live as of `now`.
    pub fn live(&self, now: Instant) -> usize {
        self.table()
            .values()
            .filter(|lease| lease.expires_at > now)
            .count()
    }

    /// The table, recovered from a poisoned lock. Every write to it is a
    /// single insert, remove or retain, so a panic elsewhere cannot leave it
    /// half-written, and refusing every later lease over it would put the
    /// attached sessions back at the mercy of the daemon's short window.
    fn table(&self) -> std::sync::MutexGuard<'_, HashMap<String, Lease>> {
        self.leases
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// The window the idle monitor decides against: the daemon's own window,
/// raised to the largest live floor.
///
/// `None` means the daemon never idles out, and no floor changes that.
pub fn effective_idle_window(own: Option<Duration>, floor: Option<Duration>) -> Option<Duration> {
    let own = own?;
    Some(floor.map_or(own, |floor| own.max(floor)))
}

fn valid_lease_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_IDLE_FLOOR_LEASE_ID_BYTES
        && id.bytes().all(|byte| byte.is_ascii_graphic())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAX: Duration = Duration::from_secs(86_400);

    fn secs(value: u64) -> Duration {
        Duration::from_secs(value)
    }

    #[test]
    fn a_held_floor_raises_a_short_window_and_leaves_a_long_one_alone() {
        let leases = IdleFloorLeases::default();
        let now = Instant::now();
        leases
            .hold("mcp-a", secs(1800), MAX, "kin mcp", now)
            .unwrap();
        let floor = leases.floor(now);
        assert_eq!(floor, Some(secs(1800)));
        assert_eq!(
            effective_idle_window(Some(secs(60)), floor),
            Some(secs(1800))
        );
        assert_eq!(
            effective_idle_window(Some(secs(3600)), floor),
            Some(secs(3600)),
            "a floor must never shorten the daemon's own window"
        );
        assert_eq!(
            effective_idle_window(None, floor),
            None,
            "a daemon that never idles out keeps never idling out"
        );
    }

    #[test]
    fn a_released_floor_returns_the_daemon_to_its_own_window() {
        let leases = IdleFloorLeases::default();
        let now = Instant::now();
        leases
            .hold("mcp-a", secs(1800), MAX, "kin mcp", now)
            .unwrap();
        assert_eq!(leases.release("mcp-a", now).as_deref(), Some("kin mcp"));
        assert_eq!(leases.floor(now), None);
        assert_eq!(
            effective_idle_window(Some(secs(60)), leases.floor(now)),
            Some(secs(60))
        );
        assert_eq!(
            leases.release("mcp-a", now),
            None,
            "a second release has nothing to release"
        );
    }

    #[test]
    fn an_unrenewed_floor_expires_one_floor_after_its_last_renewal() {
        let leases = IdleFloorLeases::default();
        let start = Instant::now();
        leases
            .hold("mcp-a", secs(100), MAX, "kin mcp", start)
            .unwrap();
        // Renewed at 60 s, so it now lasts until 160 s, not 100 s.
        let renewed = leases
            .hold("mcp-a", secs(100), MAX, "kin mcp", start + secs(60))
            .unwrap();
        assert!(!renewed.created, "a second hold renews the same lease");
        assert_eq!(leases.floor(start + secs(159)), Some(secs(100)));
        assert_eq!(
            leases.floor(start + secs(160)),
            None,
            "a session that stopped renewing must not hold the daemon forever"
        );
        assert_eq!(leases.live(start + secs(160)), 0);
    }

    #[test]
    fn the_largest_live_floor_wins_and_each_session_releases_only_its_own() {
        let leases = IdleFloorLeases::default();
        let now = Instant::now();
        leases.hold("a", secs(600), MAX, "kin mcp", now).unwrap();
        leases.hold("b", secs(1800), MAX, "kin mcp", now).unwrap();
        assert_eq!(leases.floor(now), Some(secs(1800)));
        leases.release("b", now);
        assert_eq!(
            leases.floor(now),
            Some(secs(600)),
            "releasing one session must leave another session's floor in force"
        );
    }

    #[test]
    fn a_floor_is_clamped_and_a_zero_or_malformed_request_is_refused() {
        let leases = IdleFloorLeases::default();
        let now = Instant::now();
        let held = leases
            .hold("a", Duration::MAX, MAX, "kin mcp", now)
            .unwrap();
        assert_eq!(held.floor, MAX);
        assert_eq!(
            leases.hold("b", Duration::ZERO, MAX, "kin mcp", now),
            Err(LeaseRefusal::ZeroFloor)
        );
        for id in [
            "",
            "has space",
            &"x".repeat(MAX_IDLE_FLOOR_LEASE_ID_BYTES + 1),
        ] {
            assert_eq!(
                leases.hold(id, secs(10), MAX, "kin mcp", now),
                Err(LeaseRefusal::InvalidId),
                "{id:?} must be refused"
            );
        }
    }

    #[test]
    fn the_table_is_bounded_but_expired_leases_make_room() {
        let leases = IdleFloorLeases::default();
        let now = Instant::now();
        for index in 0..MAX_IDLE_FLOOR_LEASES {
            leases
                .hold(&format!("lease-{index}"), secs(10), MAX, "kin mcp", now)
                .unwrap();
        }
        assert_eq!(
            leases.hold("one-more", secs(10), MAX, "kin mcp", now),
            Err(LeaseRefusal::TooManyLeases)
        );
        assert!(
            leases
                .hold("lease-0", secs(10), MAX, "kin mcp", now)
                .is_ok(),
            "renewing a lease already held never counts against the bound"
        );
        assert!(
            leases
                .hold("one-more", secs(10), MAX, "kin mcp", now + secs(11))
                .is_ok(),
            "expired leases must not keep the table full"
        );
    }
}
