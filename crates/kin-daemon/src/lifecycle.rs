// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Daemon lifecycle: if it's there, use it. If it's not, start it.
//!
//! The daemon writes `.kin/daemon.pid` and `.kin/daemon.port` on startup.
//! The CLI reads those files to connect. If the daemon isn't running, the
//! CLI spawns it and waits for the port to open.

use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use fs2::FileExt;
use tracing::info;

// ── Daemon Singleton Lock ───────────────────────────────────────────────

/// An exclusive, per-repo daemon lock.
///
/// Held for the daemon's entire lifetime to guarantee at most one daemon
/// process per repo. The lock is an OS-level advisory `flock(2)` on
/// `.kin/daemon.lock`. Because the kernel ties the lock to the open file
/// description, it is released automatically when this handle is dropped *or*
/// when the last process holding that description exits. A forked child can
/// inherit the description and keep it locked after the stamped daemon dies;
/// that case is detected and reported, but not automatically unlinked.
///
/// Current builds never unlink this pathname automatically. The separate
/// lifecycle coordination lock serializes all current acquisition and endpoint
/// publication paths, but it cannot exclude a compatible older writer that
/// does not participate. Recovery therefore fails closed rather than replacing
/// an inode that a legacy process could have acquired after a userspace check.
#[derive(Debug)]
pub struct DaemonLock {
    file: std::fs::File,
    canonical_kin_root: PathBuf,
}

impl DaemonLock {
    /// Canonical `.kin` root whose singleton this capability protects.
    ///
    /// Carrying the repository identity with the file handle prevents a caller
    /// from replaying authority acquired for repo A while starting state opened
    /// from repo B.
    pub fn canonical_kin_root(&self) -> &Path {
        &self.canonical_kin_root
    }
}

impl Drop for DaemonLock {
    /// Clear the owner stamp before releasing the lock.
    ///
    /// This is what makes the stamp mean something precise: a non-empty
    /// `daemon.lock` body says a process took the lock and did *not* release it
    /// cleanly. A clean exit runs this drop; a `SIGKILL` cannot, which is
    /// exactly the case reclaim needs to identify. Without the clear, every
    /// ordinary shutdown would leave a dead-owner record and the next startup
    /// would "reclaim" locks that were never stale.
    fn drop(&mut self) {
        let _ = self.file.set_len(0);
        let _ = self.file.flush();
    }
}

/// Stamp the acquiring process's PID into the lock file body.
///
/// The flock lives on the open file description, so the file's *contents* are
/// free real estate. Recording the owner there gives every other process a
/// piece of evidence about who holds the repo that does not depend on
/// `daemon.pid` surviving: `daemon.pid` is written by the daemon and can be
/// removed by any other participant, while this stamp is written under the
/// lock by the only process that could have taken it.
fn stamp_lock_owner(file: &mut std::fs::File) {
    let stamp = current_owner_stamp();
    if file.set_len(0).is_err() {
        return;
    }
    if file.seek(SeekFrom::Start(0)).is_err() {
        return;
    }
    if write!(file, "{stamp}").is_err() {
        return;
    }
    let _ = file.flush();
}

/// Marker introducing an owner stamp that carries process identity rather than
/// a bare PID.
const OWNER_STAMP_V2: &str = "kin-daemon-owner-v2";

/// Render this process's owner stamp.
///
/// A PID alone cannot identify a process incarnation: PIDs are reused, so a
/// stamp naming a dead daemon's PID starts describing whatever unrelated
/// process the kernel handed that number to next, and every reader then reports
/// a live daemon owning a repo it has never heard of. Binding the boot and the
/// process creation instant makes the record false for an impostor.
///
/// Falls back to the bare-PID form when identity cannot be read at all, which
/// is the same evidence the previous format carried and never less.
fn current_owner_stamp() -> String {
    match kin_cli::daemon_client::current_process_identity() {
        Ok(identity) => match serde_json::to_string(&identity) {
            Ok(encoded) => format!("{OWNER_STAMP_V2} {encoded}"),
            Err(_) => std::process::id().to_string(),
        },
        Err(_) => std::process::id().to_string(),
    }
}

/// What a lock file's owner stamp records.
#[derive(Debug, Clone, PartialEq, Eq)]
struct LockOwnerStamp {
    pid: u32,
    /// Present only for stamps written by a daemon that could read its own
    /// identity. Absent for the legacy bare-PID form, where a recycled PID
    /// remains indistinguishable from the original owner.
    identity: Option<kin_cli::daemon_client::ProcessIdentity>,
}

/// Parse either stamp form.
///
/// The legacy bare-PID form is still accepted: a mixed-version repo can have a
/// stamp written by an older daemon, and refusing to read it would discard the
/// only owner evidence that survives endpoint-file deletion.
fn parse_lock_owner_stamp(body: &str) -> Option<LockOwnerStamp> {
    let body = body.trim();
    if let Some(encoded) = body.strip_prefix(OWNER_STAMP_V2) {
        let identity: kin_cli::daemon_client::ProcessIdentity =
            serde_json::from_str(encoded.trim()).ok()?;
        return Some(LockOwnerStamp {
            pid: identity.pid(),
            identity: Some(identity),
        });
    }
    Some(LockOwnerStamp {
        pid: body.parse::<u32>().ok()?,
        identity: None,
    })
}

fn read_lock_owner_stamp(kin_root: &Path) -> Option<LockOwnerStamp> {
    parse_lock_owner_stamp(&std::fs::read_to_string(kin_root.join("daemon.lock")).ok()?)
}

/// Owner PID recorded inside `.kin/daemon.lock` by whichever process last
/// acquired the lock, if present and parseable.
///
/// Unlike [`recorded_daemon_pid`], this record cannot be erased by a client
/// clearing endpoint files, so it stays available exactly when `daemon.pid` is
/// missing.
pub fn lock_owner_pid(kin_root: &Path) -> Option<u32> {
    read_lock_owner_stamp(kin_root).map(|stamp| stamp.pid)
}

/// Who currently owns this repo's daemon lock, as far as on-disk evidence can
/// say, and whether that process is still alive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SingletonLockHolder {
    pub pid: u32,
    pub alive: bool,
    /// Whether `alive` was decided against the recorded process incarnation
    /// rather than the PID alone.
    ///
    /// False means the stamp predates identity-bound ownership, so `alive`
    /// cannot rule out a PID that has been reused since the daemon exited.
    pub identity_verified: bool,
}

/// Resolve the recorded owner of the repo daemon lock from real process
/// evidence: the lock file's own owner stamp first (it survives endpoint-file
/// deletion), then `daemon.pid`. Returns `None` only when neither record
/// exists.
///
/// When the stamp carries a process identity, liveness means *that* incarnation
/// is still running. A PID the kernel has since handed to something else reads
/// as dead, which is the honest answer: the daemon that took the lock is gone,
/// and reporting the impostor as a running daemon sent operators to stop a
/// process that had nothing to do with Kin.
pub fn singleton_lock_holder(kin_root: &Path) -> Option<SingletonLockHolder> {
    if let Some(stamp) = read_lock_owner_stamp(kin_root) {
        if let Some(identity) = stamp.identity {
            return Some(SingletonLockHolder {
                pid: stamp.pid,
                // An identity that cannot be read at all (permission denied on
                // another user's process) is indeterminate, not dead: fail
                // closed and treat the owner as live.
                alive: kin_cli::daemon_client::process_identity_is_current(&identity)
                    .unwrap_or(true),
                identity_verified: true,
            });
        }
        return Some(SingletonLockHolder {
            pid: stamp.pid,
            alive: is_process_alive(stamp.pid),
            identity_verified: false,
        });
    }
    let pid = recorded_daemon_pid(kin_root)?;
    Some(SingletonLockHolder {
        pid,
        alive: is_process_alive(pid),
        identity_verified: false,
    })
}

/// Try to acquire the exclusive daemon lock for a repo.
///
/// `kin_root` is the `.kin` directory (the same root that holds `daemon.pid`
/// and `daemon.port`).
///
/// Returns:
/// - `Ok(Some(lock))` — this process is now the sole daemon. Keep `lock` alive
///   for the daemon's whole lifetime; dropping it releases the lock.
/// - `Ok(None)` — another live daemon already holds the lock. The caller must
///   not start a second daemon and should exit cleanly.
/// - `Err(_)` — an unexpected IO error opening the lock file.
pub fn acquire_singleton_lock(kin_root: &Path) -> std::io::Result<Option<DaemonLock>> {
    without_blocking_runtime_worker(|| acquire_singleton_lock_inner(kin_root))
}

fn acquire_singleton_lock_inner(kin_root: &Path) -> std::io::Result<Option<DaemonLock>> {
    acquire_singleton_lock_inner_until(kin_root, Instant::now() + SINGLETON_LOCK_RETRY_BUDGET)
}

fn acquire_singleton_lock_inner_until(
    kin_root: &Path,
    deadline: Instant,
) -> std::io::Result<Option<DaemonLock>> {
    acquire_singleton_lock_inner_until_with_coordination_hook(kin_root, deadline, || {})
}

fn acquire_singleton_lock_inner_until_with_coordination_hook<F>(
    kin_root: &Path,
    deadline: Instant,
    on_coordination_contention: F,
) -> std::io::Result<Option<DaemonLock>>
where
    F: FnMut(),
{
    let canonical_kin_root = kin_root.canonicalize()?;
    let _coordination = acquire_singleton_coordination_guard_until_with_hook(
        &canonical_kin_root,
        deadline,
        on_coordination_contention,
    )?;
    let path = canonical_kin_root.join("daemon.lock");
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&path)?;
    match file.try_lock_exclusive() {
        Ok(()) => {
            // Record ownership while holding the lock, so a contender that
            // fails to acquire can always name the process it lost to.
            stamp_lock_owner(&mut file);
            Ok(Some(DaemonLock {
                file,
                canonical_kin_root,
            }))
        }
        // fs2 reports contention with the platform's "would block" error
        // (EWOULDBLOCK on Unix). Treat that — and only that — as "already
        // held"; surface every other IO error to the caller.
        Err(err) if err.kind() == fs2::lock_contended_error().kind() => Ok(None),
        Err(err) => Err(err),
    }
}

/// Serialize current daemon acquisition, evidence reads, and endpoint changes.
///
/// `daemon.lock` itself cannot provide this coordination while a leaked child
/// fd keeps that inode locked after its stamped owner dies. This second,
/// never-unlinked inode is held only for short authority sections. A bounded
/// acquire fails closed if an inherited coordination fd ever leaks.
fn acquire_singleton_coordination_guard(kin_root: &Path) -> std::io::Result<std::fs::File> {
    acquire_singleton_coordination_guard_until(
        kin_root,
        Instant::now() + SINGLETON_LOCK_RETRY_BUDGET,
    )
}

fn acquire_singleton_coordination_guard_until(
    kin_root: &Path,
    deadline: Instant,
) -> std::io::Result<std::fs::File> {
    acquire_singleton_coordination_guard_until_with_hook(kin_root, deadline, || {})
}

fn acquire_singleton_coordination_guard_until_with_hook<F>(
    kin_root: &Path,
    deadline: Instant,
    mut on_contention: F,
) -> std::io::Result<std::fs::File>
where
    F: FnMut(),
{
    let path = kin_root.join("daemon.lifecycle");
    let file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(path)?;
    loop {
        match file.try_lock_exclusive() {
            Ok(()) => return Ok(file),
            Err(err) if err.kind() == fs2::lock_contended_error().kind() => {
                on_contention();
                let now = Instant::now();
                if now >= deadline {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::WouldBlock,
                        "timed out waiting for daemon lifecycle coordination lock",
                    ));
                }
                std::thread::sleep(
                    SINGLETON_LOCK_RETRY_INTERVAL.min(deadline.saturating_duration_since(now)),
                );
            }
            Err(err) => return Err(err),
        }
    }
}

/// Acquire the singleton lock, retrying for a bounded window while the lock is
/// contended.
///
/// The handoff window between an exiting daemon and its successor is real but
/// short: the kernel releases the flock as the old process dies, and a starter
/// that gives up on the first `EWOULDBLOCK` turns that microsecond race into a
/// user-visible refusal. Retry briefly, then stop — an unbounded retry would
/// turn a genuine second daemon into a spinner instead of a loud error.
///
/// Returns `Ok(None)` when the lock is still held at the end of the window; the
/// caller must then report the holder rather than start a second daemon.
pub fn acquire_singleton_lock_within(
    kin_root: &Path,
    budget: Duration,
) -> std::io::Result<Option<DaemonLock>> {
    without_blocking_runtime_worker(|| {
        let deadline = Instant::now() + budget;
        loop {
            match acquire_singleton_lock_inner_until(kin_root, deadline) {
                Ok(Some(lock)) => return Ok(Some(lock)),
                Ok(None) => {}
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        && Instant::now() >= deadline =>
                {
                    return Ok(None);
                }
                Err(error) => return Err(error),
            }
            let now = Instant::now();
            if now >= deadline {
                return Ok(None);
            }
            std::thread::sleep(
                SINGLETON_LOCK_RETRY_INTERVAL.min(deadline.saturating_duration_since(now)),
            );
        }
    })
}

/// Run a blocking step without holding a tokio worker thread hostage.
///
/// Daemon lifecycle has two of these: waiting out a contended singleton lock,
/// and warming sibling repository graphs for the spine. Both are synchronous
/// and both are reached from async contexts, and blocking the worker inline is
/// what let a warm-up starve the daemon's own liveness routes — a client
/// polling `/readiness` saw nothing, concluded the daemon was dead, and
/// clobbered a live daemon's endpoint files. `block_in_place` hands this
/// worker's remaining tasks to another thread first, so `/health` and
/// `/readiness` keep being served throughout.
///
/// Outside a multi-thread runtime (a `current_thread` runtime, or no runtime at
/// all, as in unit tests) there is no worker to hand off and `block_in_place`
/// would panic, so the work runs directly.
pub(crate) fn without_blocking_runtime_worker<T>(work: impl FnOnce() -> T) -> T {
    match tokio::runtime::Handle::try_current() {
        Ok(handle) if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread => {
            tokio::task::block_in_place(work)
        }
        _ => work(),
    }
}

/// How long a contended starter keeps retrying the singleton lock before it
/// reports the holder. Long enough to cover an exiting daemon's teardown,
/// short enough that a genuine second daemon fails fast and loudly.
pub const SINGLETON_LOCK_RETRY_BUDGET: Duration = Duration::from_secs(5);

const SINGLETON_LOCK_RETRY_INTERVAL: Duration = Duration::from_millis(100);

// ── Stale-Lock Reclaim ────────────────────────────────────────────────────

/// Recorded owner PID for this repo, from `.kin/daemon.pid`, if present and
/// parseable.
fn recorded_daemon_pid(kin_root: &Path) -> Option<u32> {
    std::fs::read_to_string(kin_root.join("daemon.pid"))
        .ok()
        .and_then(|content| content.trim().parse::<u32>().ok())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LockOwnerEvidence {
    lock_owner: Option<u32>,
    endpoint_owner: Option<u32>,
}

impl LockOwnerEvidence {
    fn read(kin_root: &Path) -> Self {
        Self {
            lock_owner: lock_owner_pid(kin_root),
            endpoint_owner: recorded_daemon_pid(kin_root),
        }
    }

    fn owners(self) -> impl Iterator<Item = u32> {
        [self.lock_owner, self.endpoint_owner].into_iter().flatten()
    }

    fn live_owner(self) -> Option<u32> {
        self.owners().find(|pid| is_process_alive(*pid))
    }

    fn first_owner(self) -> Option<u32> {
        self.owners().next()
    }
}

/// What a reclaim attempt concluded, and why.
///
/// Every variant is reported: a reclaim that declines must say which evidence
/// made it decline, because the alternative — returning an empty list — reads
/// to the caller exactly like "nothing was wrong here".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StaleLockReclaim {
    /// Legacy/historical outcome retained for source compatibility. Current
    /// mixed-version-safe recovery does not produce it automatically.
    Cleared(Vec<PathBuf>),
    /// A recorded owner is alive, so the locks are deliberately preserved.
    OwnerAlive(u32),
    /// Neither the lock file's owner stamp nor `daemon.pid` names an owner, so
    /// liveness cannot be established and reclaiming would be a guess.
    OwnerUnknown,
    /// Ownership evidence changed after the dead-owner check. The new state is
    /// preserved rather than unlinking an inode whose authority is no longer
    /// the one that was evaluated.
    OwnerChanged {
        previous_lock_owner: Option<u32>,
        previous_endpoint_owner: Option<u32>,
        current_lock_owner: Option<u32>,
        current_endpoint_owner: Option<u32>,
    },
    /// Safe acquisition/retirement coordination is unavailable. This includes
    /// both a contended lifecycle inode and the mixed-version boundary where
    /// compatible older writers do not participate in that protocol.
    CoordinationUnavailable(String),
}

impl StaleLockReclaim {
    /// Lock files actually removed; empty for every non-clearing outcome.
    pub fn cleared(&self) -> &[PathBuf] {
        match self {
            Self::Cleared(paths) => paths,
            _ => &[],
        }
    }
}

/// Reclaim stale lock files left behind when a daemon died while a forked child
/// still held an inherited `flock(2)` fd.
///
/// All of Kin's repo locks are advisory flocks, so the kernel releases them when
/// the owning process dies — *except* when a child inherited the open fd before
/// the parent died (or wedged) without `exec`-ing it away. The kernel keeps the
/// advisory lock alive on the open file description until every inheriting fd
/// closes, so a fresh acquire then spuriously fails with `EWOULDBLOCK`
/// (os error 35) even though no live daemon owns the repo.
///
/// SAFETY: reclaim ONLY when a recorded owner PID is present **and dead**.
///
/// - A *live* owner means a real daemon holds the lock; unlinking would let a
///   second daemon lock a fresh inode and run concurrently — the very
///   singleton-multiplicity hazard `daemon.lock` exists to prevent.
/// - No recorded owner at all means liveness is unknowable from disk, so the
///   locks stay and the gap is reported instead of silently swallowed.
///
/// Ownership is read from two independent records: the owner stamp written into
/// `daemon.lock` under the lock itself, and `daemon.pid`. The stamp is what
/// keeps this path working when `daemon.pid` is absent — a client that cleared
/// endpoint files used to erase the only evidence, turning reclaim into a
/// permanent no-op while the repo stayed wedged. If either record names a live
/// process, nothing is touched.
///
/// Automatic unlink is intentionally unsupported while non-participating older
/// writers remain compatible. A dead owner is reported precisely, but every
/// lock is preserved; the operator can stop the leaked holder or allow it to
/// exit, after which the ordinary bounded acquire succeeds on the same inode.
pub fn reclaim_stale_locks(kin_root: &Path) -> StaleLockReclaim {
    reclaim_stale_locks_within(kin_root, SINGLETON_LOCK_RETRY_BUDGET)
}

/// Resolve stale-lock evidence within the caller's remaining acquisition
/// budget. Coordination timeout is reported fail-closed.
pub fn reclaim_stale_locks_within(kin_root: &Path, budget: Duration) -> StaleLockReclaim {
    let deadline = Instant::now() + budget;
    without_blocking_runtime_worker(|| {
        reclaim_stale_locks_with_hooks_until(kin_root, deadline, || {}, || {})
    })
}

#[cfg(test)]
fn reclaim_stale_locks_with_hook<F>(kin_root: &Path, before_revalidation: F) -> StaleLockReclaim
where
    F: FnOnce(),
{
    reclaim_stale_locks_with_hooks_until(
        kin_root,
        Instant::now() + SINGLETON_LOCK_RETRY_BUDGET,
        before_revalidation,
        || {},
    )
}

#[cfg(test)]
fn reclaim_stale_locks_with_hooks<F, G>(
    kin_root: &Path,
    before_revalidation: F,
    after_revalidation: G,
) -> StaleLockReclaim
where
    F: FnOnce(),
    G: FnOnce(),
{
    reclaim_stale_locks_with_hooks_until(
        kin_root,
        Instant::now() + SINGLETON_LOCK_RETRY_BUDGET,
        before_revalidation,
        after_revalidation,
    )
}

fn reclaim_stale_locks_with_hooks_until<F, G>(
    kin_root: &Path,
    deadline: Instant,
    before_revalidation: F,
    after_revalidation: G,
) -> StaleLockReclaim
where
    F: FnOnce(),
    G: FnOnce(),
{
    let _coordination = match acquire_singleton_coordination_guard_until(kin_root, deadline) {
        Ok(coordination) => coordination,
        Err(error) => {
            tracing::warn!(
                repo = %kin_root.display(),
                error = %error,
                "refusing stale-lock reclaim without lifecycle coordination"
            );
            return StaleLockReclaim::CoordinationUnavailable(error.to_string());
        }
    };

    let previous = LockOwnerEvidence::read(kin_root);
    if let Some(alive) = previous.live_owner() {
        return StaleLockReclaim::OwnerAlive(alive);
    }
    let Some(dead_owner) = previous.first_owner() else {
        tracing::warn!(
            repo = %kin_root.display(),
            "repo lock is contended but no owner is recorded in daemon.lock or daemon.pid; \
             refusing to reclaim a lock whose holder cannot be identified"
        );
        return StaleLockReclaim::OwnerUnknown;
    };

    before_revalidation();

    // The coordination inode excludes every current acquisition path. Re-read
    // anyway so PID reuse or a current endpoint publisher is reported
    // accurately. It cannot exclude an older/non-participating writer, which
    // is why the verified dead-owner case below still refuses automatic unlink.
    let current = LockOwnerEvidence::read(kin_root);
    if let Some(alive) = current.live_owner() {
        return StaleLockReclaim::OwnerAlive(alive);
    }
    if current != previous {
        tracing::warn!(
            repo = %kin_root.display(),
            previous_lock_owner = ?previous.lock_owner,
            previous_endpoint_owner = ?previous.endpoint_owner,
            current_lock_owner = ?current.lock_owner,
            current_endpoint_owner = ?current.endpoint_owner,
            "daemon lock ownership changed during stale-lock reclaim; preserving all locks"
        );
        return StaleLockReclaim::OwnerChanged {
            previous_lock_owner: previous.lock_owner,
            previous_endpoint_owner: previous.endpoint_owner,
            current_lock_owner: current.lock_owner,
            current_endpoint_owner: current.endpoint_owner,
        };
    }

    after_revalidation();

    tracing::warn!(
        repo = %kin_root.display(),
        owner_pid = dead_owner,
        "recorded daemon owner is dead, but automatic singleton retirement is disabled at the \
         mixed-version compatibility boundary; preserving every lock"
    );
    StaleLockReclaim::CoordinationUnavailable(format!(
        "recorded owner pid {dead_owner} is dead, but automatic singleton retirement is \
         unsupported while compatible older daemons may acquire without daemon.lifecycle"
    ))
}

// ── Daemon State Files ──────────────────────────────────────────────────

/// Name of the sidecar that attributes a published endpoint to one process
/// incarnation.
const ENDPOINT_OWNER_FILE: &str = "daemon.owner";

/// Schema tag carried by [`ENDPOINT_OWNER_FILE`].
const ENDPOINT_OWNER_SCHEMA: &str = "kin.daemon.endpoint-owner.v1";

/// Who published the endpoint currently on disk.
///
/// `daemon.pid` holds a bare PID because every version of every Kin surface
/// reads it that way, and a PID alone cannot survive reuse: after the recorded
/// daemon exits, that number starts naming whatever the kernel handed it to
/// next, and a reader comparing PIDs either preserves a dead endpoint forever
/// or deletes a live one. This sidecar records the same process incarnation the
/// singleton lock stamps, so ownership can be *proved* rather than inferred
/// from a number.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct EndpointOwnerRecord {
    schema: String,
    identity: kin_cli::daemon_client::ProcessIdentity,
    port: u16,
}

impl EndpointOwnerRecord {
    fn current(port: u16) -> Option<Self> {
        Some(Self {
            schema: ENDPOINT_OWNER_SCHEMA.to_string(),
            identity: kin_cli::daemon_client::current_process_identity().ok()?,
            port,
        })
    }
}

/// What the on-disk endpoint says about its owner.
///
/// The distinction that matters is between an endpoint this process may
/// destroy and one it may not. Only [`EndpointOwnership::CurrentProcess`]
/// authorizes removal; every other variant means the files belong to somebody
/// else, or to nobody this build can identify, and must be left alone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointOwnership {
    /// No endpoint is published: `daemon.pid` is absent.
    Absent,
    /// The endpoint names this exact process incarnation.
    CurrentProcess,
    /// The endpoint names a different owner. `live` is decided against the
    /// recorded incarnation when an owner record exists, and against the bare
    /// PID otherwise; an indeterminate probe reads as live, because an
    /// uninspectable owner is not a dead one.
    OtherProcess { pid: u32, live: bool },
    /// An endpoint exists but names nobody: `daemon.pid` is unparseable and
    /// there is no owner record to fall back on.
    Unattributed,
}

impl EndpointOwnership {
    /// Whether the calling process may delete these endpoint files.
    pub fn authorizes_removal(self) -> bool {
        matches!(self, Self::CurrentProcess)
    }
}

fn read_endpoint_owner_record(kin_root: &Path) -> Option<EndpointOwnerRecord> {
    let raw = std::fs::read_to_string(kin_root.join(ENDPOINT_OWNER_FILE)).ok()?;
    let record: EndpointOwnerRecord = serde_json::from_str(&raw).ok()?;
    (record.schema == ENDPOINT_OWNER_SCHEMA).then_some(record)
}

/// Classify the published endpoint's owner.
///
/// `daemon.pid` is what makes an endpoint *published*: a stray owner record
/// with no PID file beside it attributes nothing, and the next publication
/// overwrites it.
pub fn endpoint_ownership(kin_root: &Path) -> EndpointOwnership {
    if !kin_root.join("daemon.pid").exists() {
        return EndpointOwnership::Absent;
    }
    if let Some(record) = read_endpoint_owner_record(kin_root) {
        return match kin_cli::daemon_client::process_identity_is_current(&record.identity) {
            Ok(true) if record.identity.pid() == std::process::id() => {
                EndpointOwnership::CurrentProcess
            }
            Ok(is_current) => EndpointOwnership::OtherProcess {
                pid: record.identity.pid(),
                live: is_current,
            },
            // An identity that cannot be read at all (another user's process)
            // is indeterminate, not dead.
            Err(_) => EndpointOwnership::OtherProcess {
                pid: record.identity.pid(),
                live: true,
            },
        };
    }
    match recorded_daemon_pid(kin_root) {
        Some(pid) if pid == std::process::id() => EndpointOwnership::CurrentProcess,
        Some(pid) => EndpointOwnership::OtherProcess {
            pid,
            live: is_process_alive(pid),
        },
        None => EndpointOwnership::Unattributed,
    }
}

fn write_atomic_endpoint_component(
    kin_root: &Path,
    name: &str,
    value: impl AsRef<[u8]>,
) -> std::io::Result<()> {
    let tmp = kin_root.join(format!("{name}.tmp"));
    let dst = kin_root.join(name);
    std::fs::write(&tmp, value)?;
    std::fs::rename(tmp, dst)
}

/// Remove every component of an endpoint the caller has already proved it may
/// destroy — its own, or one whose recorded owner is verifiably gone.
///
/// Order matters on a crash: `daemon.pid` goes first because it is what makes
/// an endpoint published, so an interrupted retirement leaves no record any
/// reader will act on.
fn remove_endpoint_components(kin_root: &Path) {
    let _ = std::fs::remove_file(kin_root.join("daemon.pid"));
    let _ = std::fs::remove_file(kin_root.join("daemon.port"));
    let _ = std::fs::remove_file(kin_root.join(ENDPOINT_OWNER_FILE));
}

/// Publish the daemon's complete endpoint while holding lifecycle authority.
///
/// Current endpoint retirement takes the same never-unlinked lock, so a
/// successor publication cannot land between a predecessor comparison and
/// deletion. Every temporary file is prepared before any visible component
/// changes, and a failed publication rolls back only the components this call
/// actually installed — an endpoint belonging to a process that is still
/// running is never in that set.
pub fn publish_daemon_endpoint(kin_root: &Path, port: u16) -> std::io::Result<()> {
    let _authority = acquire_singleton_coordination_guard(kin_root)?;
    publish_daemon_endpoint_under_authority(kin_root, port)
}

fn publish_daemon_endpoint_under_authority(kin_root: &Path, port: u16) -> std::io::Result<()> {
    // Port 0 means "the OS will pick one", never "connect here". Publishing it
    // strands every reader on an endpoint nothing can dial, and the daemon that
    // published it keeps refusing successors because it still owns the repo.
    if port == 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "refusing to publish an unbound daemon port",
        ));
    }
    // A starter that lost the singleton must never reach this, but publication
    // overwrites files by design, so the guarantee is asserted here rather than
    // assumed from the call graph.
    if let EndpointOwnership::OtherProcess { pid, live: true } = endpoint_ownership(kin_root) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!("daemon endpoint for {} is owned by live pid {pid}", kin_root.display()),
        ));
    }

    let owner = EndpointOwnerRecord::current(port)
        .and_then(|record| serde_json::to_string(&record).ok());
    let pid = std::process::id().to_string();
    let port = port.to_string();

    let mut installed: Vec<&str> = Vec::new();
    let result: std::io::Result<()> = (|| {
        if let Some(owner) = &owner {
            std::fs::write(kin_root.join("daemon.owner.tmp"), owner.as_bytes())?;
        }
        std::fs::write(kin_root.join("daemon.pid.tmp"), pid.as_bytes())?;
        std::fs::write(kin_root.join("daemon.port.tmp"), port.as_bytes())?;
        // Attribution lands before the endpoint it attributes, so the instant
        // `daemon.pid` names this process the proof that it does is already
        // readable.
        if owner.is_some() {
            std::fs::rename(
                kin_root.join("daemon.owner.tmp"),
                kin_root.join(ENDPOINT_OWNER_FILE),
            )?;
            installed.push(ENDPOINT_OWNER_FILE);
        }
        std::fs::rename(kin_root.join("daemon.pid.tmp"), kin_root.join("daemon.pid"))?;
        installed.push("daemon.pid");
        std::fs::rename(
            kin_root.join("daemon.port.tmp"),
            kin_root.join("daemon.port"),
        )?;
        installed.push("daemon.port");
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(kin_root.join("daemon.owner.tmp"));
        let _ = std::fs::remove_file(kin_root.join("daemon.pid.tmp"));
        let _ = std::fs::remove_file(kin_root.join("daemon.port.tmp"));
        for name in installed {
            let _ = std::fs::remove_file(kin_root.join(name));
        }
    }
    result
}

/// Write PID file atomically (write tmp + rename).
///
/// Retained for API compatibility and tests. Production startup publishes the
/// PID and bound port together with [`publish_daemon_endpoint`].
pub fn write_pid_file(kin_root: &Path) {
    if let Ok(_authority) = acquire_singleton_coordination_guard(kin_root) {
        // A partial publication carries no port, so it cannot write an owner
        // record. Drop any predecessor's record rather than let it attribute
        // this PID to the wrong incarnation.
        let _ = std::fs::remove_file(kin_root.join(ENDPOINT_OWNER_FILE));
        let _ =
            write_atomic_endpoint_component(kin_root, "daemon.pid", std::process::id().to_string());
    }
}

/// Write the port file so the CLI knows where to connect.
///
/// Written atomically (temp + rename) so a CLI polling the port file during the
/// daemon→CLI port handshake never parses a torn or partial value.
pub fn write_port_file(kin_root: &Path, port: u16) {
    if let Ok(_authority) = acquire_singleton_coordination_guard(kin_root) {
        let _ = write_atomic_endpoint_component(kin_root, "daemon.port", port.to_string());
    }
}

/// Read port from `.kin/daemon.port`.
///
/// Zero is not a port anything can connect to: it is the bind-time request for
/// an OS-assigned port, and a record carrying it names no endpoint. Treated as
/// unpublished, exactly as the shared spawn contract treats it.
pub fn read_port_file(kin_root: &Path) -> Option<u16> {
    std::fs::read_to_string(kin_root.join("daemon.port"))
        .ok()
        .and_then(|s| s.trim().parse::<u16>().ok())
        .filter(|port| *port != 0)
}

/// Remove PID file, but only if it's ours (prevents removing a successor's).
pub fn remove_pid_file(kin_root: &Path) {
    let Ok(_authority) = acquire_singleton_coordination_guard(kin_root) else {
        return;
    };
    if endpoint_ownership(kin_root).authorizes_removal() {
        let _ = std::fs::remove_file(kin_root.join("daemon.pid"));
        let _ = std::fs::remove_file(kin_root.join(ENDPOINT_OWNER_FILE));
    }
}

/// Remove daemon endpoint files, but only when this process can prove it
/// published them.
///
/// Proof is the recorded process incarnation, not the PID: an endpoint whose
/// number happens to match a recycled PID belongs to a daemon that already
/// exited, and one whose number differs may belong to a successor that
/// republished while this process was draining.
pub fn remove_daemon_files_if_current_process(kin_root: &Path) {
    let Ok(_authority) = acquire_singleton_coordination_guard(kin_root) else {
        tracing::warn!(
            repo = %kin_root.display(),
            "preserving daemon endpoint because lifecycle authority is unavailable"
        );
        return;
    };
    let ownership = endpoint_ownership(kin_root);
    if !ownership.authorizes_removal() {
        if !matches!(ownership, EndpointOwnership::Absent) {
            tracing::warn!(
                repo = %kin_root.display(),
                ?ownership,
                "preserving daemon endpoint published by another process"
            );
        }
        return;
    }
    remove_endpoint_components(kin_root);
}

/// Is the process with this PID alive?
fn is_process_alive(pid: u32) -> bool {
    kin_cli::daemon_client::is_process_alive(pid)
}

/// Is the daemon running for this repo? Checks PID file + port reachable.
///
/// A dead owner's endpoint is cleared, but only against proof: the recorded
/// incarnation is re-read under lifecycle authority and must still be the same
/// dead owner the first read saw. A live owner — including one this process
/// cannot inspect — keeps its files.
pub fn daemon_is_up(kin_root: &Path) -> Option<u16> {
    match endpoint_ownership(kin_root) {
        EndpointOwnership::Absent | EndpointOwnership::Unattributed => return None,
        EndpointOwnership::CurrentProcess | EndpointOwnership::OtherProcess { live: true, .. } => {}
        stale @ EndpointOwnership::OtherProcess { live: false, .. } => {
            // Stale — clean up only while publication is excluded and the
            // endpoint still names the same dead owner the verdict was formed
            // about.
            let _authority = acquire_singleton_coordination_guard(kin_root).ok()?;
            if endpoint_ownership(kin_root) == stale {
                remove_endpoint_components(kin_root);
            }
            return None;
        }
    }
    let port = read_port_file(kin_root)?;
    if is_port_open(port) {
        Some(port)
    } else {
        None // PID alive but port not open — daemon still starting or wedged
    }
}

// ── Port Checking ───────────────────────────────────────────────────────

fn is_port_open(port: u16) -> bool {
    let addr: std::net::SocketAddr = ([127, 0, 0, 1], port).into();
    std::net::TcpStream::connect_timeout(&addr, Duration::from_millis(200)).is_ok()
}

fn find_free_port() -> Option<u16> {
    std::net::TcpListener::bind("127.0.0.1:0")
        .ok()
        .and_then(|l| l.local_addr().ok())
        .map(|a| a.port())
}

// ── Daemon Binary Discovery ─────────────────────────────────────────────

fn find_daemon_binary() -> Option<PathBuf> {
    if let Ok(explicit) = std::env::var("KIN_DAEMON_BIN") {
        let path = PathBuf::from(explicit);
        if path.exists() {
            return Some(path);
        }
    }
    // Next to the running kin binary.
    if let Ok(exe) = std::env::current_exe() {
        let sibling = exe.with_file_name("kin-daemon");
        if sibling.exists() {
            return Some(sibling);
        }
        if exe
            .parent()
            .and_then(|path| path.file_name())
            .is_some_and(|name| name == "deps")
        {
            if let Some(target_dir) = exe.parent().and_then(|path| path.parent()) {
                let target_sibling = target_dir.join("kin-daemon");
                if target_sibling.exists() {
                    return Some(target_sibling);
                }
            }
        }
    }
    which::which("kin-daemon").ok()
}

fn default_idle_timeout_secs() -> &'static str {
    if cfg!(test) {
        "1"
    } else {
        "60"
    }
}

/// Default idle timeout for MCP-initiated daemon autostarts (30 minutes).
///
/// Interactive MCP agent loops routinely pause longer than the 60-second CLI
/// default between tool calls, so MCP-path spawns use this larger window.  An
/// explicit `KIN_DAEMON_IDLE_TIMEOUT_SECS` env var always overrides both.
///
/// Defined once in the shared spawn contract that both daemon-start paths build
/// their command through, rather than repeated per crate.
pub const MCP_IDLE_TIMEOUT_SECS: &str = kin_daemon_spawn::MCP_IDLE_TIMEOUT_SECS;

/// Pure resolution of the idle-timeout value to inject into a spawned daemon.
///
/// Returns `None` when the user has already set `KIN_DAEMON_IDLE_TIMEOUT_SECS`
/// (their value wins; we let the env var propagate naturally to the child).
/// Returns `Some(value)` when we should explicitly set the env var: either
/// the caller-supplied override or the compiled default when no override is
/// given.
///
/// All accepted values are compile-time string literals (`&'static str`), so
/// the caller-override parameter is restricted to that lifetime.
///
/// Factored out of the spawn path so the env-assembly logic is unit-testable
/// without actually starting a daemon process.
pub(crate) fn resolve_idle_timeout_env(
    user_env_is_set: bool,
    caller_override: Option<&'static str>,
) -> Option<&'static str> {
    if user_env_is_set {
        return None;
    }
    Some(caller_override.unwrap_or(default_idle_timeout_secs()))
}

// ── The One Function ────────────────────────────────────────────────────

/// Ensure the daemon is running for this repo. Returns its base URL.
///
/// 1. If it's already up → return its URL. (~1ms)
/// 2. If not → start it, wait for the port to open, return URL. (~2-3s)
/// 3. If start fails → return Err.
///
/// No timeouts, no escape hatches, no lock file dances. Simple.
pub async fn ensure_daemon_running(kin_root: &Path) -> Result<String, AutoStartError> {
    ensure_daemon_running_with_idle_timeout(kin_root, None).await
}

/// Like [`ensure_daemon_running`] but lets the caller inject a specific idle
/// timeout into the spawned daemon process.
///
/// Pass `Some(MCP_IDLE_TIMEOUT_SECS)` on the MCP-initiated path (30 min) so
/// interactive agent sessions don't expire the daemon mid-session.  Pass
/// `None` to use the compiled default (60 s).  An explicit
/// `KIN_DAEMON_IDLE_TIMEOUT_SECS` env var always takes precedence over both.
pub async fn ensure_daemon_running_with_idle_timeout(
    kin_root: &Path,
    idle_timeout_override: Option<&'static str>,
) -> Result<String, AutoStartError> {
    // ── If it's there, use it ───────────────────────────────────────────
    if let Some(port) = daemon_is_up(kin_root) {
        return Ok(format!("http://127.0.0.1:{}", port));
    }

    // ── If it's not, start it ───────────────────────────────────────────
    let daemon_bin = find_daemon_binary().ok_or(AutoStartError::BinaryNotFound)?;
    let working_dir = kin_root
        .parent()
        .ok_or_else(|| AutoStartError::InvalidLayout(".kin has no parent".into()))?;
    let port = find_free_port().unwrap_or(4219);

    info!(binary = %daemon_bin.display(), repo = %working_dir.display(), port, "starting daemon");

    let mut cmd = std::process::Command::new(&daemon_bin);
    cmd.args([
        "--repo",
        &working_dir.display().to_string(),
        "--port",
        &port.to_string(),
    ]);
    cmd.stdout(Stdio::null());
    cmd.stderr(Stdio::null());
    if let Some(timeout) = resolve_idle_timeout_env(
        std::env::var_os("KIN_DAEMON_IDLE_TIMEOUT_SECS").is_some(),
        idle_timeout_override,
    ) {
        cmd.env("KIN_DAEMON_IDLE_TIMEOUT_SECS", timeout);
    }

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
    }

    cmd.spawn()
        .map_err(|e| AutoStartError::SpawnFailed(e.to_string()))?;

    // Wait for the port to open. The daemon loads the snapshot and binds —
    // typically 2-3s. We check every 100ms, give up after 10s.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while std::time::Instant::now() < deadline {
        if is_port_open(port) {
            info!(port, "daemon is up");
            return Ok(format!("http://127.0.0.1:{}", port));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    Err(AutoStartError::StartupTimeout)
}

// ── macOS Launch Agent (start on boot) ───────────────────────────────────

/// Register a launchd Launch Agent so the daemon starts on login.
///
/// Called by `kin init` after initializing a repo. Creates a per-repo
/// plist in ~/Library/LaunchAgents/ and loads it immediately.
///
/// Each repo gets its own agent with a unique label:
///   ai.firelock.kin-daemon.<repo_id>
#[cfg(target_os = "macos")]
pub fn register_launch_agent(kin_root: &Path) -> Result<(), String> {
    let working_dir = kin_root.parent().ok_or("no parent")?;
    let repo_id = working_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("default");

    let daemon_bin =
        find_daemon_binary().ok_or_else(|| "kin-daemon binary not found".to_string())?;

    let port = read_port_file(kin_root).unwrap_or_else(|| find_free_port().unwrap_or(4219));

    let label = format!("ai.firelock.kin-daemon.{}", repo_id);
    let plist = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{bin}</string>
        <string>--repo</string>
        <string>{repo}</string>
        <string>--port</string>
        <string>{port}</string>
    </array>
    <key>KeepAlive</key>
    <true/>
    <key>RunAtLoad</key>
    <true/>
    <key>ProcessType</key>
    <string>Background</string>
    <key>StandardOutPath</key>
    <string>/tmp/kin-daemon-{id}.stdout.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/kin-daemon-{id}.stderr.log</string>
</dict>
</plist>"#,
        label = label,
        bin = daemon_bin.display(),
        repo = working_dir.display(),
        port = port,
        id = repo_id,
    );

    let home = std::env::var("HOME").map_err(|_| "HOME not set")?;
    let launch_agents = PathBuf::from(&home).join("Library/LaunchAgents");
    std::fs::create_dir_all(&launch_agents).map_err(|e| format!("create LaunchAgents dir: {e}"))?;

    let plist_path = launch_agents.join(format!("{label}.plist"));

    // Unload old version if it exists (idempotent).
    if plist_path.exists() {
        let _ = std::process::Command::new("launchctl")
            .arg("unload")
            .arg(&plist_path)
            .output();
    }

    std::fs::write(&plist_path, &plist).map_err(|e| format!("write plist: {e}"))?;

    let output = std::process::Command::new("launchctl")
        .arg("load")
        .arg(&plist_path)
        .output()
        .map_err(|e| format!("launchctl load: {e}"))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("launchctl load failed: {stderr}"));
    }

    info!(label = %label, "registered macOS Launch Agent");
    Ok(())
}

/// Unregister the Launch Agent for a repo.
///
/// Called by `kin eject` before removing `.kin/`.
#[cfg(target_os = "macos")]
pub fn unregister_launch_agent(kin_root: &Path) {
    let working_dir = match kin_root.parent() {
        Some(p) => p,
        None => return,
    };
    let repo_id = working_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("default");

    let label = format!("ai.firelock.kin-daemon.{}", repo_id);
    if let Ok(home) = std::env::var("HOME") {
        let home = PathBuf::from(home);
        let plist_path = home
            .join("Library/LaunchAgents")
            .join(format!("{label}.plist"));
        if plist_path.exists() {
            let _ = std::process::Command::new("launchctl")
                .arg("unload")
                .arg(&plist_path)
                .output();
            let _ = std::fs::remove_file(&plist_path);
            info!(label = %label, "unregistered macOS Launch Agent");
        }
    }
}

/// No-op on non-macOS platforms.
#[cfg(not(target_os = "macos"))]
pub fn register_launch_agent(_kin_root: &Path) -> Result<(), String> {
    Ok(()) // Linux: TODO systemd user unit
}

/// No-op on non-macOS platforms.
#[cfg(not(target_os = "macos"))]
pub fn unregister_launch_agent(_kin_root: &Path) {}

// ── Errors ──────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum AutoStartError {
    #[error("kin-daemon binary not found (not in PATH or next to kin binary)")]
    BinaryNotFound,
    #[error("failed to spawn kin-daemon: {0}")]
    SpawnFailed(String),
    #[error("daemon failed to start within 10s")]
    StartupTimeout,
    #[error("invalid .kin layout: {0}")]
    InvalidLayout(String),
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Port-file handshake ────────────────────────────────────────────────
    //
    // The daemon publishes its real bound port here for the CLI handshake, so
    // read_port_file must recover exactly what write_port_file wrote, overwrite
    // must replace cleanly, and the atomic temp artifact must never linger for a
    // polling reader to trip over.

    #[test]
    fn port_file_round_trips_atomically() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let root = dir.path();

        assert_eq!(
            read_port_file(root),
            None,
            "no port file before first write"
        );

        write_port_file(root, 51234);
        assert_eq!(read_port_file(root), Some(51234));

        // Overwrite (temp + rename) must replace the previous value cleanly.
        write_port_file(root, 6001);
        assert_eq!(read_port_file(root), Some(6001));

        // The atomic-write temp file must not be left behind.
        assert!(
            !root.join("daemon.port.tmp").exists(),
            "atomic write must not leave a .tmp artifact"
        );
    }

    #[test]
    fn complete_endpoint_publication_writes_pid_and_bound_port_together() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        publish_daemon_endpoint(root, 51234).expect("publish endpoint");

        assert_eq!(recorded_daemon_pid(root), Some(std::process::id()));
        assert_eq!(read_port_file(root), Some(51234));
        assert!(!root.join("daemon.pid.tmp").exists());
        assert!(!root.join("daemon.port.tmp").exists());
    }

    // ── Idle-timeout env resolution ────────────────────────────────────────
    //
    // These lock the scoped-timeout contract: user env wins over everything,
    // callers can inject an override (MCP 1800s), and None falls back to the
    // compiled default.

    #[test]
    fn resolve_idle_timeout_uses_default_when_nothing_set() {
        // No user env, no caller override → fall through to default_idle_timeout_secs().
        // In test builds default_idle_timeout_secs() returns "1"; we just assert
        // the value matches whatever that function returns, not a hard-coded number.
        let result = resolve_idle_timeout_env(false, None);
        assert_eq!(result, Some(default_idle_timeout_secs()));
    }

    #[test]
    fn resolve_idle_timeout_caller_override_propagates() {
        // MCP-path caller passes Some("1800") → that value reaches the daemon.
        assert_eq!(resolve_idle_timeout_env(false, Some("1800")), Some("1800"));
        assert_eq!(resolve_idle_timeout_env(false, Some("300")), Some("300"));
    }

    #[test]
    fn resolve_idle_timeout_user_env_always_wins() {
        // When the user has set KIN_DAEMON_IDLE_TIMEOUT_SECS we must not inject
        // anything, regardless of the caller override.
        assert_eq!(resolve_idle_timeout_env(true, None), None);
        assert_eq!(resolve_idle_timeout_env(true, Some("1800")), None);
        assert_eq!(resolve_idle_timeout_env(true, Some("9999")), None);
    }

    #[test]
    fn mcp_idle_timeout_constant_is_1800() {
        // Regression guard: the MCP path must inject 1800s (30 min), not the
        // 60-second CLI default.
        assert_eq!(MCP_IDLE_TIMEOUT_SECS, "1800");
    }

    #[test]
    fn stale_pid_cleaned_up() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("daemon.pid"), "999999999").unwrap();
        std::fs::write(dir.path().join("daemon.port"), "4219").unwrap();
        assert!(daemon_is_up(dir.path()).is_none());
        assert!(!dir.path().join("daemon.pid").exists());
        assert!(!dir.path().join("daemon.port").exists());
    }

    #[test]
    fn missing_files_means_not_up() {
        let dir = tempfile::tempdir().unwrap();
        assert!(daemon_is_up(dir.path()).is_none());
    }

    #[test]
    fn write_and_remove_pid() {
        let dir = tempfile::tempdir().unwrap();
        write_pid_file(dir.path());
        assert!(dir.path().join("daemon.pid").exists());
        remove_pid_file(dir.path());
        assert!(!dir.path().join("daemon.pid").exists());
    }

    #[test]
    fn second_daemon_refuses_when_lock_held() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        // First daemon acquires the per-repo singleton lock.
        let first = acquire_singleton_lock(root).expect("lock IO should succeed");
        assert!(first.is_some(), "first daemon should acquire the lock");

        // A second daemon on the SAME repo must be refused while the first
        // holds the lock — this is the multiplicity bug fix. flock(2) treats
        // each open() independently, so a fresh acquire in-process conflicts
        // exactly as a separate daemon process would.
        let second = acquire_singleton_lock(root).expect("lock IO should succeed");
        assert!(
            second.is_none(),
            "second daemon must refuse to start while the first holds the lock"
        );

        // Releasing the first lock (process exit / drop) lets a successor take
        // over — the lock never goes stale. A *concurrent* test that fork+execs
        // while this lock fd is open transiently inherits it (flock is keyed to
        // the open file description and survives until every inheriting fd
        // closes; the child's fd closes on exec via CLOEXEC). That window can
        // briefly keep the lock held after `drop(first)`, so retry the reacquire
        // rather than asserting success on the first attempt.
        drop(first);
        let third = retry_acquire_lock(root);
        assert!(
            third.is_some(),
            "a new daemon should acquire the lock once the previous one exits"
        );
    }

    /// Acquire the singleton lock, briefly retrying while a concurrent test's
    /// inherited fd still holds it. Bounded so a genuinely-stuck lock still fails
    /// the test instead of hanging.
    fn retry_acquire_lock(root: &Path) -> Option<DaemonLock> {
        for _ in 0..100 {
            match acquire_singleton_lock(root).expect("lock IO should succeed") {
                Some(lock) => return Some(lock),
                None => std::thread::sleep(Duration::from_millis(20)),
            }
        }
        None
    }

    #[test]
    fn reclaim_fails_closed_when_owner_pid_is_dead() {
        // A SIGKILLed daemon whose forked child leaked the flock fd leaves a
        // dead-owner PID and lingering lock files. Because compatible legacy
        // starters do not take daemon.lifecycle, automatic pathname
        // replacement cannot prove exclusion and must preserve every lock.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("kindb")).unwrap();
        std::fs::write(root.join("daemon.pid"), "999999999").unwrap();
        std::fs::write(root.join("daemon.lock"), b"").unwrap();
        std::fs::write(root.join("kindb").join("graph.lock"), b"").unwrap();

        let reclaim = reclaim_stale_locks(root);
        assert!(
            matches!(
                &reclaim,
                StaleLockReclaim::CoordinationUnavailable(reason)
                    if reason.contains("compatible older daemons")
                        && reason.contains("999999999")
            ),
            "dead-owner retirement must disclose the mixed-version boundary: {reclaim:?}"
        );
        assert!(reclaim.cleared().is_empty());
        assert!(root.join("daemon.lock").exists());
        assert!(root.join("kindb").join("graph.lock").exists());
    }

    #[test]
    fn reclaim_preserves_locks_when_owner_is_live() {
        // A LIVE owner (this test process) means a real daemon holds the lock;
        // reclaiming would let a second daemon lock a fresh inode and run
        // concurrently — the singleton-multiplicity hazard. Must be a no-op.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("kindb")).unwrap();
        std::fs::write(root.join("daemon.pid"), std::process::id().to_string()).unwrap();
        std::fs::write(root.join("daemon.lock"), b"").unwrap();
        std::fs::write(root.join("kindb").join("graph.lock"), b"").unwrap();

        assert_eq!(
            reclaim_stale_locks(root),
            StaleLockReclaim::OwnerAlive(std::process::id()),
            "live-owner locks must be preserved"
        );
        assert!(root.join("daemon.lock").exists());
        assert!(root.join("kindb").join("graph.lock").exists());
    }

    #[test]
    fn legacy_acquirer_after_final_read_cannot_be_unlinked() {
        use std::cell::RefCell;

        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("daemon.lock"), "999999999").unwrap();
        let legacy_lock = RefCell::new(None);

        let reclaim = reclaim_stale_locks_with_hooks(
            root,
            || {},
            || {
                // This hook is after the final owner read. It models an older
                // daemon that does not take daemon.lifecycle: acquire and stamp
                // the existing singleton inode at the exact former unlink
                // window.
                let mut file = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(root.join("daemon.lock"))
                    .unwrap();
                file.try_lock_exclusive()
                    .expect("legacy successor acquires the old inode");
                file.set_len(0).unwrap();
                file.seek(SeekFrom::Start(0)).unwrap();
                write!(file, "{}", std::process::id()).unwrap();
                file.flush().unwrap();
                legacy_lock.replace(Some(file));
            },
        );

        assert!(
            matches!(
                &reclaim,
                StaleLockReclaim::CoordinationUnavailable(reason)
                    if reason.contains("compatible older daemons")
                        && reason.contains("999999999")
            ),
            "the legacy-acquirer seam must fail closed: {reclaim:?}"
        );
        assert!(root.join("daemon.lock").exists());
        assert_eq!(
            lock_owner_pid(root),
            Some(std::process::id()),
            "the legacy successor's stamp must survive the former unlink window"
        );
        assert!(
            acquire_singleton_lock_within(root, Duration::ZERO)
                .expect("current acquire IO")
                .is_none(),
            "current acquisition must observe the legacy holder on the preserved inode"
        );
        drop(legacy_lock.into_inner());
    }

    #[test]
    fn reclaim_revalidates_owner_evidence_before_reporting_retirement_boundary() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("daemon.lock"), "999999999").unwrap();

        let reclaim = reclaim_stale_locks_with_hook(root, || {
            // Simulate an older/non-participating successor that does not take
            // daemon.lifecycle. The final evidence read must still catch it.
            std::fs::write(root.join("daemon.lock"), std::process::id().to_string()).unwrap();
        });

        assert_eq!(
            reclaim,
            StaleLockReclaim::OwnerAlive(std::process::id()),
            "a newly live owner must cancel stale-owner recovery"
        );
        assert!(
            root.join("daemon.lock").exists(),
            "revalidation must preserve the successor's inode"
        );
        assert_eq!(lock_owner_pid(root), Some(std::process::id()));
    }

    #[test]
    fn reclaim_is_noop_without_any_recorded_owner() {
        // Neither record names an owner, so liveness cannot be established and
        // reclaiming would be a guess. Refusing to start is always safe;
        // reclaiming a live lock is not. The outcome is reported as
        // OwnerUnknown rather than an empty list, so the caller can say why.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("kindb")).unwrap();
        std::fs::write(root.join("daemon.lock"), b"").unwrap();
        std::fs::write(root.join("kindb").join("graph.lock"), b"").unwrap();

        assert_eq!(reclaim_stale_locks(root), StaleLockReclaim::OwnerUnknown);
        assert!(root.join("daemon.lock").exists());
        assert!(root.join("kindb").join("graph.lock").exists());
    }

    // ── Reclaim must work without daemon.pid ──────────────────────────────
    //
    // The deadlock chain ended here: a client cleared a live daemon's endpoint
    // files, so when that daemon later died by SIGKILL there was no daemon.pid
    // left, reclaim had no owner to evaluate, and every subsequent start lost
    // the leaked flock forever. The lock file's own owner stamp is the evidence
    // that survives, because only the process holding the lock can write it.

    #[test]
    fn singleton_lock_stamps_its_owner_pid() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        let lock = acquire_singleton_lock(root)
            .expect("lock IO should succeed")
            .expect("first acquire should win");
        assert_eq!(
            lock_owner_pid(root),
            Some(std::process::id()),
            "the acquiring process must record itself in the lock file"
        );
        drop(lock);
    }

    #[test]
    fn releasing_the_lock_clears_the_owner_stamp() {
        // A clean release must leave no dead-owner record: otherwise every
        // ordinary restart would look like a crashed predecessor and "reclaim"
        // locks that were never stale.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        let lock = acquire_singleton_lock(root)
            .expect("lock IO should succeed")
            .expect("first acquire should win");
        drop(lock);

        assert_eq!(
            lock_owner_pid(root),
            None,
            "a cleanly released lock must not name an owner"
        );
        assert_eq!(reclaim_stale_locks(root), StaleLockReclaim::OwnerUnknown);
        assert!(
            root.join("daemon.lock").exists(),
            "a clean release must not make the next startup reclaim anything"
        );
    }

    #[test]
    fn reclaim_uses_the_lock_owner_stamp_when_daemon_pid_is_missing() {
        // The exact deadlock state: a dead owner recorded only in the lock
        // file, because daemon.pid was removed by someone else. Before the
        // stamp existed this returned "nothing to do" and the repo stayed
        // wedged until the leaked fd closed.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("kindb")).unwrap();
        std::fs::write(root.join("daemon.lock"), "999999999").unwrap();
        std::fs::write(root.join("kindb").join("graph.lock"), b"").unwrap();
        assert!(
            !root.join("daemon.pid").exists(),
            "this is the missing-pid case"
        );

        let reclaim = reclaim_stale_locks(root);
        assert!(
            matches!(
                &reclaim,
                StaleLockReclaim::CoordinationUnavailable(reason)
                    if reason.contains("compatible older daemons")
                        && reason.contains("999999999")
            ),
            "dead stamp-only ownership must fail closed: {reclaim:?}"
        );
        assert!(root.join("daemon.lock").exists());
        assert!(root.join("kindb").join("graph.lock").exists());
    }

    #[test]
    fn reclaim_refuses_when_the_lock_stamp_names_a_live_owner() {
        // Same missing-pid shape, live owner. Reclaiming here would let a
        // second daemon lock a fresh inode and run concurrently.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("kindb")).unwrap();
        std::fs::write(root.join("daemon.lock"), std::process::id().to_string()).unwrap();
        std::fs::write(root.join("kindb").join("graph.lock"), b"").unwrap();

        assert_eq!(
            reclaim_stale_locks(root),
            StaleLockReclaim::OwnerAlive(std::process::id())
        );
        assert!(root.join("daemon.lock").exists());
        assert!(root.join("kindb").join("graph.lock").exists());
    }

    #[test]
    fn reclaim_refuses_when_only_the_pid_file_names_a_live_owner() {
        // Evidence is a union, not a preference: a live owner in either record
        // must veto the reclaim.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("kindb")).unwrap();
        std::fs::write(root.join("daemon.lock"), "999999999").unwrap();
        std::fs::write(root.join("daemon.pid"), std::process::id().to_string()).unwrap();

        assert_eq!(
            reclaim_stale_locks(root),
            StaleLockReclaim::OwnerAlive(std::process::id())
        );
        assert!(root.join("daemon.lock").exists());
    }

    #[test]
    fn lock_holder_is_named_from_the_stamp_without_a_pid_file() {
        // What the contention error needs: identify the holder so the refusal
        // can name a process instead of saying "another daemon owns this repo".
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("daemon.lock"), std::process::id().to_string()).unwrap();

        let holder = singleton_lock_holder(root).expect("stamp identifies the holder");
        assert_eq!(holder.pid, std::process::id());
        assert!(holder.alive);

        std::fs::write(root.join("daemon.lock"), "999999999").unwrap();
        let dead = singleton_lock_holder(root).expect("stamp identifies the holder");
        assert_eq!(dead.pid, 999999999);
        assert!(!dead.alive);
        assert!(
            !dead.identity_verified,
            "a bare-PID stamp cannot rule out PID reuse and must not claim it did"
        );
    }

    #[test]
    fn a_recycled_pid_cannot_impersonate_the_daemon_that_took_the_lock() {
        // The stamp names a process incarnation, and this process is not it.
        // A bare PID here would report a live daemon owning the repo, because
        // the PID resolves to something alive: this very test.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        let impostor = current_owner_stamp();
        assert!(
            impostor.starts_with(OWNER_STAMP_V2),
            "this platform must stamp identity, not a bare pid: {impostor}"
        );
        // Rewrite the birth token so the record names a different incarnation
        // of the same live PID — exactly the shape PID reuse produces.
        let forged = impostor.replace("start-time:", "start-time:9");
        let forged = forged.replace("start-ticks:", "start-ticks:9");
        let forged = forged.replace("created-100ns:", "created-100ns:9");
        assert_ne!(forged, impostor, "the birth token must have been altered");
        std::fs::write(root.join("daemon.lock"), &forged).unwrap();

        let holder = singleton_lock_holder(root).expect("stamp identifies the holder");
        assert_eq!(holder.pid, std::process::id());
        assert!(holder.identity_verified);
        assert!(
            !holder.alive,
            "a live PID whose recorded incarnation is gone is not the daemon that took the lock"
        );
    }

    #[test]
    fn an_identity_stamp_recognizes_its_own_writer() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("daemon.lock"), current_owner_stamp()).unwrap();

        let holder = singleton_lock_holder(root).expect("stamp identifies the holder");
        assert_eq!(holder.pid, std::process::id());
        assert!(holder.alive, "the writing process is still running");
        assert!(holder.identity_verified);
    }

    #[test]
    fn a_legacy_bare_pid_stamp_is_still_read() {
        // A repo whose lock was stamped by an older daemon must not lose its
        // only owner evidence to a format it does not recognize.
        assert_eq!(
            parse_lock_owner_stamp("4242"),
            Some(LockOwnerStamp {
                pid: 4242,
                identity: None
            })
        );
        assert_eq!(parse_lock_owner_stamp(""), None);
        assert_eq!(parse_lock_owner_stamp("not-a-pid"), None);
    }

    #[test]
    fn bounded_retry_gives_up_instead_of_spinning_forever() {
        // The loser retries to cover an exiting daemon's teardown, then stops.
        // An unbounded retry would replace a loud error with a hang.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let held = acquire_singleton_lock(root)
            .expect("lock IO should succeed")
            .expect("first acquire should win");

        let started = std::time::Instant::now();
        let budget = Duration::from_millis(300);
        let contended =
            acquire_singleton_lock_within(root, budget).expect("lock IO should succeed");

        assert!(contended.is_none(), "a held lock must not be handed out");
        assert!(
            started.elapsed() >= budget,
            "the retry must actually cover its budget"
        );
        assert!(
            started.elapsed() < budget * 20,
            "the retry must be bounded, not a spin"
        );
        drop(held);
    }

    #[test]
    fn bounded_retry_deadline_includes_lifecycle_coordination() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let lifecycle = acquire_singleton_coordination_guard(root)
            .expect("test must hold lifecycle coordination");

        let started = Instant::now();
        let budget = Duration::from_millis(150);
        let contended =
            acquire_singleton_lock_within(root, budget).expect("bounded acquire result");

        assert!(contended.is_none());
        assert!(
            started.elapsed() >= budget,
            "the caller budget must be honored rather than skipped"
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "the inner lifecycle wait must not substitute its five-second budget"
        );
        drop(lifecycle);
    }

    #[test]
    fn bounded_retry_wins_once_the_holder_releases() {
        // The handoff case the retry exists for.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().to_path_buf();
        let held = acquire_singleton_lock(&root)
            .expect("lock IO should succeed")
            .expect("first acquire should win");

        let releaser = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(150));
            drop(held);
        });

        let acquired = acquire_singleton_lock_within(&root, Duration::from_secs(10))
            .expect("lock IO should succeed");
        assert!(
            acquired.is_some(),
            "the successor must take the lock once the holder releases"
        );
        releaser.join().expect("releaser thread");
    }

    #[test]
    fn singleton_lock_file_lives_in_kin_root() {
        let dir = tempfile::tempdir().unwrap();
        let lock = acquire_singleton_lock(dir.path()).expect("lock IO should succeed");
        assert!(lock.is_some());
        assert!(
            dir.path().join("daemon.lock").exists(),
            "lock file should be created under the .kin root"
        );
    }

    #[test]
    fn remove_pid_wont_delete_others() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("daemon.pid"), "1").unwrap();
        remove_pid_file(dir.path()); // PID 1 != ours
        assert!(dir.path().join("daemon.pid").exists());
    }

    #[test]
    fn remove_daemon_files_only_removes_owned_endpoint() {
        let dir = tempfile::tempdir().unwrap();
        write_pid_file(dir.path());
        write_port_file(dir.path(), 4219);

        remove_daemon_files_if_current_process(dir.path());
        assert!(!dir.path().join("daemon.pid").exists());
        assert!(!dir.path().join("daemon.port").exists());
    }

    #[test]
    fn remove_daemon_files_preserves_successor_endpoint() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("daemon.pid"), "1").unwrap();
        write_port_file(dir.path(), 4219);

        remove_daemon_files_if_current_process(dir.path());
        assert!(dir.path().join("daemon.pid").exists());
        assert!(dir.path().join("daemon.port").exists());
    }
}
