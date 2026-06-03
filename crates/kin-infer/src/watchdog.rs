// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Embed self-clean watchdog: orphan self-exit + throughput/wall guard.
//!
//! A long-running GPU embed can outlive the thing that started it (a dropped
//! ssh/agent connection reparents the process to init) or wedge into a busy-spin
//! that pegs the GPU while making almost no real progress. Neither is caught by
//! the in-flight backpressure warn in `metal_backend` (warn-only, full-drain
//! only) — so a stray run can pin the device indefinitely.
//!
//! This module is the durable, in-library self-clean for both classes:
//!
//! - **A. Parent-death watchdog.** Polls `getppid()`; if the process has been
//!   reparented to init (`ppid == 1`) it was orphaned — release the GPU and exit.
//!   macOS has no `PR_SET_PDEATHSIG`, so polling is the portable signal.
//! - **B. Throughput / wall guard.** Trips when wall-time exceeds a hard cap, or
//!   when throughput stays below a floor for a sustained window. Liveness is the
//!   *persisted-batch* delta the caller reports via [`EmbedWatchdog::bump`] — NOT
//!   GPU% or per-forward ticks, which a busy-spin keeps alive while persisting
//!   nothing (`GPU% != liveness`).
//! - **C. Production-driver promotion.** The same guard the scale test used, now
//!   a reusable type the daemon embed loop wraps around its batch loop, with an
//!   optional on-trip hook to flush completed batches before aborting.
//!
//! On trip the watchdog runs the optional release/persist hook, logs loudly, and
//! `std::process::abort()`s — a process exit is the one release that always frees
//! the Metal command queue even when a worker thread is wedged inside the driver.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

/// Why the watchdog tripped, for the on-trip hook and the abort log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TripReason {
    /// The process was reparented to init (`getppid() == 1`) — orphaned.
    Orphaned,
    /// Total wall-time exceeded the hard cap.
    WallCapExceeded,
    /// Throughput stayed below the floor for the sustained window.
    ThroughputFloor,
}

impl TripReason {
    fn as_str(self) -> &'static str {
        match self {
            TripReason::Orphaned => "orphaned (parent died; reparented to init)",
            TripReason::WallCapExceeded => "wall-time cap exceeded",
            TripReason::ThroughputFloor => "throughput below floor for the sustained window",
        }
    }
}

/// Watchdog configuration. All fields have env-overridable defaults via
/// [`EmbedConfig::from_env`]; construct directly for explicit control (tests).
#[derive(Clone, Copy, Debug)]
pub struct EmbedConfig {
    /// Master switch. When false [`EmbedWatchdog::spawn`] is a no-op guard.
    pub enabled: bool,
    /// Poll cadence for all three checks.
    pub poll: Duration,
    /// Enable the `getppid() == 1` orphan check.
    pub orphan_check: bool,
    /// Hard wall-time ceiling for the whole guarded region. `None` disables it.
    pub wall_cap: Option<Duration>,
    /// Minimum persisted units/sec required once `floor_grace` has elapsed. The
    /// guard trips if throughput stays below this for `floor_window`. `None`
    /// disables the throughput floor.
    pub throughput_floor: Option<f64>,
    /// How long below the floor before tripping (sustained-low window).
    pub floor_window: Duration,
    /// Grace period after start before the floor is evaluated at all (warm-up,
    /// first-batch model load, cold caches).
    pub floor_grace: Duration,
}

impl EmbedConfig {
    /// Production defaults: orphan check on, 6h wall cap, no throughput floor
    /// (the caller opts into a floor only when it knows its expected rate). Poll
    /// every 500ms — cheap, and fast enough to release a wedged GPU promptly.
    pub fn production() -> Self {
        Self {
            enabled: true,
            poll: Duration::from_millis(500),
            orphan_check: true,
            wall_cap: Some(Duration::from_secs(6 * 3600)),
            throughput_floor: None,
            floor_window: Duration::from_secs(120),
            floor_grace: Duration::from_secs(60),
        }
    }

    /// A disabled config — [`EmbedWatchdog::spawn`] returns an inert guard.
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            ..Self::production()
        }
    }

    /// Production defaults overlaid with env overrides:
    /// - `KIN_EMBED_WATCHDOG=0` disables the whole watchdog.
    /// - `KIN_EMBED_ORPHAN_CHECK=0` disables only the orphan self-exit.
    /// - `KIN_EMBED_MAX_SECS=<n>` sets the wall cap (`0` disables it).
    /// - `KIN_EMBED_MIN_RATE=<f>` sets the persisted-units/sec floor (`0`/absent
    ///   disables it).
    /// - `KIN_EMBED_FLOOR_WINDOW_SECS` / `KIN_EMBED_FLOOR_GRACE_SECS` tune the
    ///   floor's sustained window and warm-up grace.
    pub fn from_env() -> Self {
        let mut cfg = Self::production();
        if env_flag_off("KIN_EMBED_WATCHDOG") {
            cfg.enabled = false;
        }
        if env_flag_off("KIN_EMBED_ORPHAN_CHECK") {
            cfg.orphan_check = false;
        }
        if let Some(secs) = env_u64("KIN_EMBED_MAX_SECS") {
            cfg.wall_cap = (secs > 0).then(|| Duration::from_secs(secs));
        }
        if let Some(rate) = env_f64("KIN_EMBED_MIN_RATE") {
            cfg.throughput_floor = (rate > 0.0).then_some(rate);
        }
        if let Some(secs) = env_u64("KIN_EMBED_FLOOR_WINDOW_SECS") {
            cfg.floor_window = Duration::from_secs(secs.max(1));
        }
        if let Some(secs) = env_u64("KIN_EMBED_FLOOR_GRACE_SECS") {
            cfg.floor_grace = Duration::from_secs(secs);
        }
        cfg
    }
}

/// Shared, lock-free liveness signal: the count of persisted units (entities or
/// batches — the caller's choice, the floor is in the same unit) and a done flag
/// that stops the poller. Cloning shares the same counters.
#[derive(Clone, Default)]
struct Progress {
    persisted: Arc<AtomicU64>,
    done: Arc<AtomicBool>,
}

/// RAII handle to a running watchdog. Drop signals the poller to exit and joins
/// it, so a normal end-of-loop scope-exit shuts the watchdog down cleanly; only
/// a genuine trip aborts the process. Hold it for the lifetime of the embed loop.
pub struct EmbedWatchdog {
    progress: Progress,
    handle: Option<JoinHandle<()>>,
}

impl EmbedWatchdog {
    /// Spawn a watchdog over the embed region. The optional `on_trip` hook runs
    /// once on the poller thread just before the abort — use it to release the
    /// Metal queue and flush completed batches (incremental persist). The hook
    /// must be panic-safe and reasonably quick; the process aborts right after.
    ///
    /// A disabled config returns an inert guard (no thread, no overhead) so
    /// callers can wrap every embed loop unconditionally.
    pub fn spawn<F>(cfg: EmbedConfig, on_trip: Option<F>) -> Self
    where
        F: FnOnce(TripReason) + Send + 'static,
    {
        let progress = Progress::default();
        if !cfg.enabled {
            return Self {
                progress,
                handle: None,
            };
        }

        let watch = progress.clone();
        let mut on_trip = on_trip;
        let handle = std::thread::Builder::new()
            .name("kin-infer-embed-watchdog".into())
            .spawn(move || {
                let start = Instant::now();
                let mut last_persisted = watch.persisted.load(Ordering::Relaxed);
                // The throughput-floor timer starts after the grace period; it
                // resets whenever persisted progress advances, so only a SUSTAINED
                // low-progress stretch (busy-spin or wedge) trips the floor.
                let mut below_floor_since: Option<Instant> = None;

                loop {
                    std::thread::sleep(cfg.poll);
                    if watch.done.load(Ordering::Relaxed) {
                        return;
                    }

                    let reason = Self::check(
                        &cfg,
                        start,
                        &watch,
                        &mut last_persisted,
                        &mut below_floor_since,
                    );
                    if let Some(reason) = reason {
                        tracing::error!(
                            reason = reason.as_str(),
                            elapsed_s = start.elapsed().as_secs_f64(),
                            persisted = watch.persisted.load(Ordering::Relaxed),
                            "kin_infer.embed_watchdog: TRIPPED — releasing the GPU and aborting"
                        );
                        eprintln!(
                            "\n!!! kin-infer embed watchdog TRIPPED: {} \
                             (elapsed {:.1}s, persisted {}). Releasing the GPU and aborting.",
                            reason.as_str(),
                            start.elapsed().as_secs_f64(),
                            watch.persisted.load(Ordering::Relaxed),
                        );
                        if let Some(hook) = on_trip.take() {
                            hook(reason);
                        }
                        // A process exit is the one release that always frees the
                        // Metal command queue, even with a worker wedged in the
                        // driver. The non-zero exit makes the trip observable.
                        std::process::abort();
                    }
                }
            })
            .expect("spawn embed watchdog thread");

        Self {
            progress,
            handle: Some(handle),
        }
    }

    /// Evaluate all three checks. Returns the trip reason, or `None` to keep
    /// running. Split out for unit-testing the decision logic without a thread.
    fn check(
        cfg: &EmbedConfig,
        start: Instant,
        watch: &Progress,
        last_persisted: &mut u64,
        below_floor_since: &mut Option<Instant>,
    ) -> Option<TripReason> {
        // A: orphan self-exit — parent reparented to init.
        if cfg.orphan_check && parent_is_init() {
            return Some(TripReason::Orphaned);
        }

        let elapsed = start.elapsed();

        // B (wall cap): hard ceiling on the whole guarded region.
        if let Some(cap) = cfg.wall_cap {
            if elapsed > cap {
                return Some(TripReason::WallCapExceeded);
            }
        }

        // B (throughput floor): persisted-delta liveness, evaluated only after
        // the warm-up grace. Resets the low-progress timer on real progress.
        if let Some(floor) = cfg.throughput_floor {
            let persisted = watch.persisted.load(Ordering::Relaxed);
            let advanced = persisted > *last_persisted;
            *last_persisted = persisted;

            if elapsed < cfg.floor_grace {
                *below_floor_since = None;
            } else {
                let rate = persisted as f64 / elapsed.as_secs_f64().max(1e-9);
                if advanced || rate >= floor {
                    // Either fresh progress this tick, or the running rate is at
                    // or above the floor — healthy, clear the low-progress timer.
                    *below_floor_since = None;
                } else {
                    let since = below_floor_since.get_or_insert_with(Instant::now);
                    if since.elapsed() >= cfg.floor_window {
                        return Some(TripReason::ThroughputFloor);
                    }
                }
            }
        }

        None
    }

    /// Report `n` newly-persisted units (entities or batches — same unit as the
    /// throughput floor). Call after each batch is actually persisted, not after
    /// each forward: persisted progress is the liveness signal a busy-spin cannot
    /// fake. Cheap relaxed atomic add.
    #[inline]
    pub fn bump(&self, n: u64) {
        self.progress.persisted.fetch_add(n, Ordering::Relaxed);
    }

    /// A cloneable handle to the persisted-progress counter, for bumping from a
    /// worker thread that runs the embed loop while the [`EmbedWatchdog`] is held
    /// on another thread. Move a clone into the worker and call
    /// [`ProgressHandle::bump`] after each persisted batch.
    pub fn progress_handle(&self) -> ProgressHandle {
        ProgressHandle {
            persisted: Arc::clone(&self.progress.persisted),
        }
    }
}

/// A thread-portable handle to the watchdog's persisted-progress counter.
#[derive(Clone)]
pub struct ProgressHandle {
    persisted: Arc<AtomicU64>,
}

impl ProgressHandle {
    /// Report `n` newly-persisted units. Same unit and semantics as
    /// [`EmbedWatchdog::bump`]; cheap relaxed atomic add.
    #[inline]
    pub fn bump(&self, n: u64) {
        self.persisted.fetch_add(n, Ordering::Relaxed);
    }
}

impl Drop for EmbedWatchdog {
    fn drop(&mut self) {
        // Signal the poller to exit and join it, so a clean end-of-loop never
        // leaves the watchdog thread running.
        self.progress.done.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

/// Whether this process has been reparented to init — the portable orphan
/// signal on platforms without `PR_SET_PDEATHSIG`. Always false off-unix.
#[cfg(unix)]
fn parent_is_init() -> bool {
    // SAFETY: getppid is always safe; it takes no args and cannot fail.
    unsafe { libc::getppid() == 1 }
}

#[cfg(not(unix))]
fn parent_is_init() -> bool {
    false
}

fn env_flag_off(key: &str) -> bool {
    matches!(
        std::env::var(key).ok().as_deref(),
        Some("0") | Some("false") | Some("no") | Some("off")
    )
}

fn env_u64(key: &str) -> Option<u64> {
    std::env::var(key).ok().and_then(|s| s.trim().parse().ok())
}

fn env_f64(key: &str) -> Option<f64> {
    std::env::var(key).ok().and_then(|s| s.trim().parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_cfg() -> EmbedConfig {
        EmbedConfig {
            enabled: true,
            poll: Duration::from_millis(10),
            orphan_check: false, // off so the test's live parent doesn't matter
            wall_cap: None,
            throughput_floor: None,
            floor_window: Duration::from_secs(1),
            floor_grace: Duration::from_secs(0),
        }
    }

    #[test]
    fn disabled_guard_is_inert() {
        let wd = EmbedWatchdog::spawn(EmbedConfig::disabled(), None::<fn(TripReason)>);
        wd.bump(10);
        // No thread spawned; drop is a no-op join of None.
        assert!(wd.handle.is_none());
    }

    #[test]
    fn wall_cap_trips() {
        let cfg = EmbedConfig {
            wall_cap: Some(Duration::from_millis(0)),
            ..base_cfg()
        };
        let watch = Progress::default();
        let start = Instant::now() - Duration::from_secs(1);
        let mut last = 0u64;
        let mut below = None;
        let reason = EmbedWatchdog::check(&cfg, start, &watch, &mut last, &mut below);
        assert_eq!(reason, Some(TripReason::WallCapExceeded));
    }

    #[test]
    fn throughput_floor_trips_only_when_sustained_low() {
        let cfg = EmbedConfig {
            throughput_floor: Some(100.0), // need >=100 persisted/sec
            floor_window: Duration::from_millis(0), // trip as soon as below
            floor_grace: Duration::from_secs(0),
            ..base_cfg()
        };
        let watch = Progress::default();
        // 2 seconds elapsed, 0 persisted -> rate 0 < 100, and window=0 -> trip.
        let start = Instant::now() - Duration::from_secs(2);
        let mut last = 0u64;
        let mut below = None;
        // First tick records below_floor_since; with window 0 it trips this tick.
        let reason = EmbedWatchdog::check(&cfg, start, &watch, &mut last, &mut below);
        assert_eq!(reason, Some(TripReason::ThroughputFloor));
    }

    #[test]
    fn healthy_progress_does_not_trip() {
        let cfg = EmbedConfig {
            throughput_floor: Some(1.0),
            floor_window: Duration::from_millis(0),
            floor_grace: Duration::from_secs(0),
            wall_cap: Some(Duration::from_secs(3600)),
            ..base_cfg()
        };
        let watch = Progress::default();
        watch.persisted.store(1_000, Ordering::Relaxed); // plenty persisted
        let start = Instant::now() - Duration::from_secs(1); // rate ~1000/s >= 1
        let mut last = 0u64;
        let mut below = None;
        let reason = EmbedWatchdog::check(&cfg, start, &watch, &mut last, &mut below);
        assert_eq!(reason, None);
    }

    #[test]
    fn grace_period_suppresses_floor() {
        let cfg = EmbedConfig {
            throughput_floor: Some(100.0),
            floor_window: Duration::from_millis(0),
            floor_grace: Duration::from_secs(60), // long grace
            ..base_cfg()
        };
        let watch = Progress::default();
        // Only 1s elapsed (< 60s grace) with 0 persisted -> floor not evaluated.
        let start = Instant::now() - Duration::from_secs(1);
        let mut last = 0u64;
        let mut below = None;
        let reason = EmbedWatchdog::check(&cfg, start, &watch, &mut last, &mut below);
        assert_eq!(reason, None);
    }

    #[test]
    fn bump_and_clean_drop() {
        let wd = EmbedWatchdog::spawn(base_cfg(), None::<fn(TripReason)>);
        wd.bump(5);
        wd.bump(7);
        assert_eq!(wd.progress.persisted.load(Ordering::Relaxed), 12);
        // Clean drop joins the poller without aborting.
        drop(wd);
    }
}
