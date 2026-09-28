// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The idle floor an MCP session holds on the repo daemon it forwards to.
//!
//! A repo daemon's idle window is chosen by whichever process spawned it. An
//! ordinary CLI command such as `kin init` or `kin daemon sweep` spawns one
//! with the short CLI window, and an MCP session that attaches to it afterwards
//! goes quiet between an agent's tool calls for longer than that window. The
//! daemon then exits under an active session, and the next call finds nothing
//! listening.
//!
//! So a session states what it needs, as a lease on the daemon it forwards to:
//!
//! - held as soon as the session binds a daemon, however it bound it (the
//!   launcher's startup bind, a workspace-roots bind, an on-demand
//!   re-resolution, or a revival that found or started a daemon);
//! - renewed while calls continue, so it cannot lapse under an active session;
//! - moved when the session's daemon changes, and released on the one it left;
//! - released when the session ends, so the daemon returns to its own idle
//!   policy instead of keeping the session's window for the rest of its life.
//!
//! A session that dies without releasing its lease loses it one floor after
//! its last renewal, on the daemon side. A daemon that predates leases takes
//! the same request as a one-time raise of its window, which is what it did
//! before this existed.
//!
//! The floor is only taken by a process that is an MCP session. Nothing here
//! runs until [`enable`] is called, which the stdio server and the `kin mcp`
//! launcher do; a process that merely links this crate never sends a lease.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::time::Instant;

/// How often a session renews its floor while calls continue.
///
/// The daemon keeps a lease for one floor after its last renewal, so renewing
/// once a minute keeps an active session's lease within a minute of the full
/// floor, at the cost of one loopback request a minute at most.
pub const RENEW_INTERVAL: Duration = Duration::from_secs(60);

/// How long one lease request may take. A lease is bookkeeping around a call,
/// never a reason to stall it.
const REQUEST_BUDGET: Duration = Duration::from_secs(2);

/// The name the daemon logs for this client.
const CLIENT_NAME: &str = "kin mcp";

static ENABLED: AtomicBool = AtomicBool::new(false);

static SESSION: tokio::sync::Mutex<Option<SessionFloor>> = tokio::sync::Mutex::const_new(None);

/// Mark this process as an MCP session that holds an idle floor on the daemon
/// it forwards to. Idempotent.
pub fn enable() {
    ENABLED.store(true, Ordering::Release);
}

fn enabled() -> bool {
    ENABLED.load(Ordering::Acquire)
}

/// The floor this session asks for, in seconds.
///
/// The window an MCP-started daemon runs with, because a session that attached
/// to a daemon somebody else started needs exactly what a session that started
/// its own gets. An operator's own positive `KIN_DAEMON_IDLE_TIMEOUT_SECS` is
/// what they said a daemon should wait, so it is taken instead. Zero ("never
/// idle out") cannot be asked of a daemon somebody else started, so it, like a
/// value that does not parse, falls back to the session default rather than
/// to no floor at all.
pub fn floor_secs(operator_window: Option<&str>) -> u64 {
    operator_window
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|secs| *secs > 0)
        .unwrap_or_else(|| {
            kin_daemon_spawn::MCP_IDLE_TIMEOUT_SECS
                .parse()
                .unwrap_or(1800)
        })
}

/// Hold this session's floor on `base` now, unless it is already held there
/// and was renewed within [`RENEW_INTERVAL`].
///
/// For a launcher that has just bound a daemon: holding at bind time rather
/// than at the first forwarded call covers a session that binds and then asks
/// nothing for longer than the daemon's own window.
pub async fn hold(base: &str) {
    if !enabled() {
        return;
    }
    let mut session = SESSION.lock().await;
    session
        .get_or_insert_with(SessionFloor::for_this_process)
        .keep(base, Instant::now(), &HttpTransport)
        .await;
}

/// Keep this session's floor on `base`, the daemon a call is about to reach.
///
/// Called on every forwarded request, so it never waits: when a lease request
/// is already in flight for this session, the call goes ahead without one,
/// because the request in flight is the renewal.
pub(crate) async fn keep(base: &str) {
    if !enabled() {
        return;
    }
    let Ok(mut session) = SESSION.try_lock() else {
        return;
    };
    session
        .get_or_insert_with(SessionFloor::for_this_process)
        .keep(base, Instant::now(), &HttpTransport)
        .await;
}

/// Release this session's floor, wherever it is held. Called when the session
/// ends, so the daemon returns to its own idle policy.
pub async fn release() {
    if !enabled() {
        return;
    }
    let mut session = SESSION.lock().await;
    if let Some(floor) = session.as_mut() {
        floor.release(&HttpTransport).await;
    }
}

/// What a daemon said to a lease request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HoldAnswer {
    /// The window now in force, when the daemon reported one.
    pub effective_secs: Option<u64>,
    /// Whether the daemon took the request as a lease. A daemon that predates
    /// leases takes it as a one-time raise instead and says nothing about one.
    pub leased: bool,
}

/// How a lease reaches a daemon. A seam so the renewal policy is testable
/// without a daemon, a clock or a socket.
pub(crate) trait FloorTransport: Sync {
    async fn hold(&self, base: &str, lease: &str, floor_secs: u64) -> Result<HoldAnswer, String>;
    async fn release(&self, base: &str, lease: &str) -> Result<(), String>;
}

/// The production transport: the daemon's `/idle-timeout` routes, with the
/// same bearer token every other forwarded request carries.
struct HttpTransport;

impl HttpTransport {
    fn client() -> Result<reqwest::Client, String> {
        reqwest::Client::builder()
            .connect_timeout(Duration::from_millis(500))
            .timeout(REQUEST_BUDGET)
            .pool_max_idle_per_host(0)
            .build()
            .map_err(|error| format!("could not build an HTTP client: {error}"))
    }
}

impl FloorTransport for HttpTransport {
    async fn hold(&self, base: &str, lease: &str, floor_secs: u64) -> Result<HoldAnswer, String> {
        let request = Self::client()?
            .post(format!("{}/idle-timeout", base.trim_end_matches('/')))
            .json(&serde_json::json!({
                "at_least_secs": floor_secs,
                "client": CLIENT_NAME,
                "lease": lease,
            }));
        let response = crate::daemon_delegate::with_auth(request)
            .send()
            .await
            .map_err(|error| error.to_string())?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(format!("HTTP {status}: {}", body.trim()));
        }
        let body = response
            .json::<serde_json::Value>()
            .await
            .unwrap_or_default();
        Ok(HoldAnswer {
            effective_secs: body.get("effective_secs").and_then(|value| value.as_u64()),
            leased: body.get("lease").is_some_and(|lease| lease.is_object()),
        })
    }

    async fn release(&self, base: &str, lease: &str) -> Result<(), String> {
        let request = Self::client()?
            .post(format!(
                "{}/idle-timeout/release",
                base.trim_end_matches('/')
            ))
            .json(&serde_json::json!({ "lease": lease }));
        let response = crate::daemon_delegate::with_auth(request)
            .send()
            .await
            .map_err(|error| error.to_string())?;
        if response.status().is_success() {
            Ok(())
        } else {
            Err(format!("HTTP {}", response.status()))
        }
    }
}

/// One session's lease and where it stands.
#[derive(Debug)]
pub(crate) struct SessionFloor {
    lease: String,
    floor_secs: u64,
    /// The daemon the lease is held on, when a daemon accepted it.
    held_on: Option<String>,
    /// The daemon last asked, and when, whether or not it accepted. Keyed to
    /// the daemon so a failure on one never delays the lease on the next.
    last_attempt: Option<(String, Instant)>,
    /// The daemon a failed lease was last reported for, so a daemon that
    /// cannot take one is named once rather than once a minute.
    failure_reported_for: Option<String>,
}

impl SessionFloor {
    fn for_this_process() -> Self {
        Self::new(
            format!("kin-mcp-{}", uuid::Uuid::new_v4()),
            floor_secs(
                std::env::var("KIN_DAEMON_IDLE_TIMEOUT_SECS")
                    .ok()
                    .as_deref(),
            ),
        )
    }

    pub(crate) fn new(lease: String, floor_secs: u64) -> Self {
        Self {
            lease,
            floor_secs,
            held_on: None,
            last_attempt: None,
            failure_reported_for: None,
        }
    }

    /// Hold or renew the lease on `base` when it is due, moving it off the
    /// daemon it was held on when `base` is a different one.
    pub(crate) async fn keep(&mut self, base: &str, now: Instant, transport: &impl FloorTransport) {
        let base = base.trim_end_matches('/');
        let due = match &self.last_attempt {
            Some((asked, at)) if asked == base => now.duration_since(*at) >= RENEW_INTERVAL,
            _ => true,
        };
        if !due {
            return;
        }
        if let Some(previous) = self.held_on.take_if(|held| held.as_str() != base) {
            // The session moved to another daemon: a workspace re-bind or a
            // revival. The one it left gets its own policy back now rather
            // than one floor from now, and a daemon that is already gone
            // answers nothing, which is the same outcome.
            if let Err(error) = transport.release(&previous, &self.lease).await {
                tracing::debug!(
                    url = %previous,
                    %error,
                    "kin-mcp: could not release the idle floor on the daemon this session left"
                );
            }
        }
        self.last_attempt = Some((base.to_string(), now));
        match transport.hold(base, &self.lease, self.floor_secs).await {
            Ok(answer) => {
                let first = self.held_on.as_deref() != Some(base);
                self.held_on = Some(base.to_string());
                self.failure_reported_for = None;
                match answer.effective_secs {
                    Some(effective) if effective != 0 && effective < self.floor_secs => {
                        tracing::warn!(
                            url = %base,
                            floor_secs = self.floor_secs,
                            effective_secs = effective,
                            "kin-mcp: the repo daemon accepted this session's idle floor but \
                             reports a shorter window; it may exit between tool calls"
                        );
                    }
                    _ if first && answer.leased => tracing::info!(
                        url = %base,
                        floor_secs = self.floor_secs,
                        "kin-mcp: holding an idle floor on the repo daemon for this session"
                    ),
                    _ if first => tracing::info!(
                        url = %base,
                        floor_secs = self.floor_secs,
                        "kin-mcp: the repo daemon predates idle-floor leases and raised its \
                         window for good instead"
                    ),
                    _ => tracing::debug!(url = %base, "kin-mcp: renewed this session's idle floor"),
                }
            }
            Err(error) if self.failure_reported_for.as_deref() == Some(base) => tracing::debug!(
                url = %base,
                %error,
                "kin-mcp: the repo daemon still does not take this session's idle floor"
            ),
            Err(error) => {
                self.failure_reported_for = Some(base.to_string());
                tracing::warn!(
                    url = %base,
                    floor_secs = self.floor_secs,
                    %error,
                    "kin-mcp: could not hold an idle floor on the repo daemon; it may exit on its \
                     own idle window between tool calls, and the next call then restarts it"
                );
            }
        }
    }

    /// Release the lease wherever it is held.
    pub(crate) async fn release(&mut self, transport: &impl FloorTransport) {
        let Some(held) = self.held_on.take() else {
            return;
        };
        self.last_attempt = None;
        match transport.release(&held, &self.lease).await {
            Ok(()) => tracing::info!(
                url = %held,
                "kin-mcp: released this session's idle floor; the daemon is back on its own idle \
                 policy"
            ),
            Err(error) => tracing::debug!(
                url = %held,
                %error,
                "kin-mcp: could not release this session's idle floor; it expires on its own"
            ),
        }
    }

    #[cfg(test)]
    pub(crate) fn held_on(&self) -> Option<&str> {
        self.held_on.as_deref()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Recorder {
        calls: Mutex<Vec<String>>,
        refuse_hold: bool,
        legacy: bool,
    }

    impl Recorder {
        fn calls(&self) -> Vec<String> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl FloorTransport for Recorder {
        async fn hold(
            &self,
            base: &str,
            lease: &str,
            floor_secs: u64,
        ) -> Result<HoldAnswer, String> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("hold {base} {lease} {floor_secs}"));
            if self.refuse_hold {
                return Err("connection refused".to_string());
            }
            Ok(HoldAnswer {
                effective_secs: Some(floor_secs),
                leased: !self.legacy,
            })
        }

        async fn release(&self, base: &str, lease: &str) -> Result<(), String> {
            self.calls
                .lock()
                .unwrap()
                .push(format!("release {base} {lease}"));
            Ok(())
        }
    }

    const A: &str = "http://127.0.0.1:4101";
    const B: &str = "http://127.0.0.1:4102";

    #[tokio::test(start_paused = true)]
    async fn the_first_call_holds_the_floor_and_later_calls_renew_it_only_when_due() {
        let transport = Recorder::default();
        let mut floor = SessionFloor::new("lease-1".to_string(), 1800);
        let start = Instant::now();

        floor.keep(A, start, &transport).await;
        assert_eq!(transport.calls(), vec![format!("hold {A} lease-1 1800")]);
        assert_eq!(floor.held_on(), Some(A));

        // Calls inside the renewal interval cost nothing.
        floor
            .keep(A, start + Duration::from_secs(10), &transport)
            .await;
        floor
            .keep(A, start + Duration::from_secs(59), &transport)
            .await;
        assert_eq!(transport.calls().len(), 1);

        // A call past the interval renews, so an active session's lease never
        // lapses however long the session runs.
        floor
            .keep(A, start + Duration::from_secs(75), &transport)
            .await;
        floor
            .keep(A, start + Duration::from_secs(150), &transport)
            .await;
        assert_eq!(
            transport.calls(),
            vec![
                format!("hold {A} lease-1 1800"),
                format!("hold {A} lease-1 1800"),
                format!("hold {A} lease-1 1800"),
            ]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_new_daemon_gets_the_floor_at_once_and_the_old_one_is_released() {
        let transport = Recorder::default();
        let mut floor = SessionFloor::new("lease-1".to_string(), 1800);
        let start = Instant::now();
        floor.keep(A, start, &transport).await;
        // A revival or a re-bind lands on another daemon a second later: it
        // must not wait out the renewal interval with no floor at all.
        floor
            .keep(B, start + Duration::from_secs(1), &transport)
            .await;
        assert_eq!(
            transport.calls(),
            vec![
                format!("hold {A} lease-1 1800"),
                format!("release {A} lease-1"),
                format!("hold {B} lease-1 1800"),
            ]
        );
        assert_eq!(floor.held_on(), Some(B));
    }

    #[tokio::test(start_paused = true)]
    async fn ending_the_session_releases_the_floor_once() {
        let transport = Recorder::default();
        let mut floor = SessionFloor::new("lease-1".to_string(), 1800);
        floor.keep(A, Instant::now(), &transport).await;
        floor.release(&transport).await;
        floor.release(&transport).await;
        assert_eq!(
            transport.calls(),
            vec![
                format!("hold {A} lease-1 1800"),
                format!("release {A} lease-1"),
            ]
        );
        assert_eq!(floor.held_on(), None);
    }

    #[tokio::test(start_paused = true)]
    async fn a_refused_floor_is_retried_after_the_interval_not_on_every_call() {
        let transport = Recorder {
            refuse_hold: true,
            ..Recorder::default()
        };
        let mut floor = SessionFloor::new("lease-1".to_string(), 1800);
        let start = Instant::now();
        floor.keep(A, start, &transport).await;
        floor
            .keep(A, start + Duration::from_secs(5), &transport)
            .await;
        assert_eq!(
            transport.calls().len(),
            1,
            "a refusal must not cost every call a request"
        );
        assert_eq!(floor.held_on(), None);
        floor
            .keep(A, start + Duration::from_secs(61), &transport)
            .await;
        assert_eq!(transport.calls().len(), 2);
        // Nothing is held, so ending the session sends nothing.
        floor.release(&transport).await;
        assert_eq!(transport.calls().len(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn a_daemon_that_predates_leases_is_still_asked_and_still_counts_as_held() {
        let transport = Recorder {
            legacy: true,
            ..Recorder::default()
        };
        let mut floor = SessionFloor::new("lease-1".to_string(), 1800);
        floor.keep(A, Instant::now(), &transport).await;
        assert_eq!(floor.held_on(), Some(A));
    }

    #[test]
    fn the_floor_is_the_mcp_window_unless_the_operator_named_a_positive_one() {
        assert_eq!(floor_secs(None), 1800);
        assert_eq!(floor_secs(Some("7200")), 7200);
        assert_eq!(floor_secs(Some(" 900 ")), 900);
        assert_eq!(
            floor_secs(Some("0")),
            1800,
            "never idling out cannot be asked of a daemon somebody else started"
        );
        assert_eq!(floor_secs(Some("soon")), 1800);
    }

    #[tokio::test]
    async fn a_process_that_is_not_an_mcp_session_sends_nothing() {
        // `enable` is process-wide and nothing in this crate's tests calls it,
        // so the public entry points must be inert here. A test binary that
        // forwards through a stub daemon must never see a lease request it did
        // not ask for.
        assert!(!enabled());
        hold("http://127.0.0.1:9").await;
        keep("http://127.0.0.1:9").await;
        release().await;
        assert!(SESSION.lock().await.is_none());
    }
}
