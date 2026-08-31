// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Daemon lifecycle: if it's there, use it. If it's not, start it.
//!
//! The daemon writes `.kin/daemon.pid` and `.kin/daemon.port` on startup.
//! The CLI reads those files to connect. If the daemon isn't running, the
//! CLI spawns it and waits for the port to open.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[cfg(target_os = "macos")]
use std::fs::{File, OpenOptions};
#[cfg(target_os = "macos")]
use std::io::{Read as _, Seek, SeekFrom, Write};
#[cfg(target_os = "macos")]
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
#[cfg(target_os = "macos")]
use std::process::{Child, Command, ExitStatus, Output, Stdio};

use fs2::FileExt;
#[cfg(target_os = "macos")]
use sha2::{Digest as _, Sha256};
#[cfg(target_os = "macos")]
use tracing::info;

pub use kin_cli::daemon_client::AutoStartError;

// ── Daemon Singleton Lock ───────────────────────────────────────────────

/// Compatibility name for the shared per-repository runtime capability.
pub type DaemonLock = kin_cli::daemon_client::RepositoryRuntimeAuthority;

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
#[cfg(test)]
fn current_owner_stamp() -> String {
    kin_cli::daemon_client::current_repository_runtime_owner_stamp()
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
    kin_cli::daemon_client::acquire_repository_runtime_authority(kin_root)
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
    kin_cli::daemon_client::acquire_repository_runtime_authority_within(kin_root, budget)
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
pub const SINGLETON_LOCK_RETRY_BUDGET: Duration =
    kin_daemon_spawn::REPOSITORY_RUNTIME_AUTHORITY_RETRY_BUDGET;

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

/// The record written into [`ENDPOINT_OWNER_FILE`].
///
/// Declared once, beside the process identity it carries, and shared with the
/// CLI start path that reads it: the daemon publishes attribution and the CLI
/// decides from it whether an endpoint may be replaced, and two declarations of
/// one schema are two things to keep in step.
use kin_cli::daemon_client::EndpointOwnerRecord;

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

use kin_cli::daemon_client::read_endpoint_owner_record;

/// Classify the published endpoint's owner.
///
/// `daemon.pid` is what makes an endpoint *published*: a stray owner record
/// with no PID file beside it attributes nothing, and the next publication
/// overwrites it.
pub fn endpoint_ownership(kin_root: &Path) -> EndpointOwnership {
    endpoint_ownership_with_probe(
        kin_root,
        kin_cli::daemon_client::process_identity_is_current,
    )
}

/// The probe is injectable for the same reason publication's is: the
/// indeterminate arm is a decision, not an accident, and a decision that cannot
/// be exercised in a test is one a later change can silently invert.
fn endpoint_ownership_with_probe(
    kin_root: &Path,
    probe: impl FnOnce(&kin_cli::daemon_client::ProcessIdentity) -> std::io::Result<bool>,
) -> EndpointOwnership {
    if !kin_root.join("daemon.pid").exists() {
        return EndpointOwnership::Absent;
    }
    if let Some(record) = read_endpoint_owner_record(kin_root) {
        // Answer the "is it mine" case from this process's own identity rather
        // than from a probe of a foreign PID. Retirement used to be
        // `read(daemon.pid) == process::id()`, which cannot fail; routing the
        // self case through a fallible probe would let a transient error
        // refuse a daemon permission to retire its own endpoint and strand it.
        if record.identity().pid() == std::process::id() {
            return match kin_cli::daemon_client::current_process_identity() {
                Ok(current) if current == *record.identity() => EndpointOwnership::CurrentProcess,
                // Our PID, a different incarnation: the publisher is gone and
                // the kernel handed us its number.
                Ok(_) => EndpointOwnership::OtherProcess {
                    pid: record.identity().pid(),
                    live: false,
                },
                Err(_) => EndpointOwnership::OtherProcess {
                    pid: record.identity().pid(),
                    live: true,
                },
            };
        }
        return match probe(record.identity()) {
            Ok(is_current) => EndpointOwnership::OtherProcess {
                pid: record.identity().pid(),
                live: is_current,
            },
            // An identity that cannot be read at all (another user's process)
            // is indeterminate. `live` governs removal, and refusing to delete
            // what cannot be inspected is the safe direction, so it reads as
            // live here. Publication asks a different question and must not
            // reuse this answer: see [`proven_live_other_endpoint_owner`].
            Err(_) => EndpointOwnership::OtherProcess {
                pid: record.identity().pid(),
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

/// The PID of a *different* incarnation that the endpoint record **proves** is
/// still running, if there is one.
///
/// This answers the question that governs yielding, not the one that governs
/// deleting, and the two fail in opposite directions.
///
/// Refusing to delete what cannot be inspected is safe: the worst case is a
/// stale file. Refusing to *publish* over what cannot be inspected is not,
/// because the caller already holds the repository singleton, so no legitimate
/// owner can exist and the refusal is fatal at startup. An indeterminate probe
/// there wedges the repo permanently: a SIGKILLed daemon leaves the record
/// behind, the kernel later hands its PID to a process owned by another user,
/// every probe of that PID returns `PermissionDenied` rather than an answer,
/// and nothing in the system clears the record. The daemon exits 1 forever and
/// the error names an unrelated process the operator has no reason to touch.
///
/// So "not proven" is the answer for an unreadable probe here, which is also
/// what the name and the legacy-record rule already say: a claim that cannot be
/// verified must not keep a repo's rightful owner from advertising itself.
pub(crate) fn proven_live_other_endpoint_owner(kin_root: &Path) -> Option<u32> {
    proven_live_other_endpoint_owner_with_probe(
        kin_root,
        kin_cli::daemon_client::process_identity_is_current,
    )
}

fn proven_live_other_endpoint_owner_with_probe(
    kin_root: &Path,
    probe: impl FnOnce(&kin_cli::daemon_client::ProcessIdentity) -> std::io::Result<bool>,
) -> Option<u32> {
    if !kin_root.join("daemon.pid").exists() {
        return None;
    }
    let record = read_endpoint_owner_record(kin_root)?;
    if record.identity().pid() == std::process::id() {
        return None;
    }
    probe(record.identity())
        .unwrap_or(false)
        .then(|| record.identity().pid())
}

/// Publish an endpoint attributed to a process other than this one, so tests
/// can build the state a real successor would leave behind without running a
/// second daemon.
#[cfg(all(test, unix))]
pub(crate) fn publish_foreign_endpoint_for_test(
    kin_root: &Path,
    identity: kin_cli::daemon_client::ProcessIdentity,
    port: u16,
) {
    let pid = identity.pid();
    let record = EndpointOwnerRecord::for_identity(identity);
    std::fs::write(kin_root.join("daemon.pid"), pid.to_string()).unwrap();
    std::fs::write(kin_root.join("daemon.port"), port.to_string()).unwrap();
    std::fs::write(
        kin_root.join(ENDPOINT_OWNER_FILE),
        serde_json::to_string(&record).unwrap(),
    )
    .unwrap();
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
    // The serving record retires with the endpoint, and only here. Its whole
    // meaning is that a copy left behind by a process that is gone marks a
    // daemon which never reached this line, so retiring it anywhere a killed
    // daemon could also reach would erase the evidence it exists to keep.
    kin_daemon_spawn::retire_serving_daemon(kin_root);
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
    // Waiting out the coordination lock is a synchronous sleep reached from
    // async contexts, and holding a worker hostage here is what once starved
    // the liveness routes a client was polling before it clobbered the very
    // endpoint being published.
    without_blocking_runtime_worker(|| {
        let _authority = acquire_singleton_coordination_guard(kin_root)?;
        publish_daemon_endpoint_under_authority(kin_root, port)
    })
}

/// Publish under an injectable ownership probe, so a test can drive the
/// indeterminate case that the host's own permissions decide otherwise.
#[cfg(all(test, unix))]
fn publish_daemon_endpoint_with_probe(
    kin_root: &Path,
    port: u16,
    probe: impl FnOnce(&kin_cli::daemon_client::ProcessIdentity) -> std::io::Result<bool>,
) -> std::io::Result<()> {
    without_blocking_runtime_worker(|| {
        let _authority = acquire_singleton_coordination_guard(kin_root)?;
        publish_daemon_endpoint_under_authority_with_probe(kin_root, port, probe)
    })
}

fn publish_daemon_endpoint_under_authority(kin_root: &Path, port: u16) -> std::io::Result<()> {
    publish_daemon_endpoint_under_authority_with_probe(
        kin_root,
        port,
        kin_cli::daemon_client::process_identity_is_current,
    )
}

fn publish_daemon_endpoint_under_authority_with_probe(
    kin_root: &Path,
    port: u16,
    probe: impl FnOnce(&kin_cli::daemon_client::ProcessIdentity) -> std::io::Result<bool>,
) -> std::io::Result<()> {
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
    if let Some(pid) = proven_live_other_endpoint_owner_with_probe(kin_root, probe) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!(
                "daemon endpoint for {} is owned by live pid {pid}",
                kin_root.display()
            ),
        ));
    }

    let owner =
        EndpointOwnerRecord::current().and_then(|record| serde_json::to_string(&record).ok());
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
    if port == 0 {
        // Never a reachable endpoint: it is the bind-time request for an
        // OS-assigned port, and recording it advertises an address nothing can
        // dial while the daemon that wrote it keeps owning the repo.
        return;
    }
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
    without_blocking_runtime_worker(|| {
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
    })
}

/// Retire an endpoint whose recorded owner this caller has proved is dead.
///
/// A daemon killed from outside never retires its own endpoint: retirement runs
/// after the shutdown select returns, and a SIGKILLed process never gets there.
/// The record then keeps naming a dead pid as the live owner of the repository,
/// which is what left `kin doctor` reporting a STALE daemon with its endpoint
/// record still on disk after a supervisor reap.
///
/// Returns whether anything was removed. Removal requires the record to still
/// name `owner_pid` and that pid to be gone; a record naming a live process, a
/// successor that republished, or nobody identifiable is left alone. That keeps
/// this in the same direction the rest of this module runs in — proof authorizes
/// destruction, absence of proof never does.
pub fn retire_endpoint_of_dead_owner(kin_root: &Path, owner_pid: u32) -> bool {
    without_blocking_runtime_worker(|| {
        let Ok(_authority) = acquire_singleton_coordination_guard(kin_root) else {
            tracing::warn!(
                repo = %kin_root.display(),
                "preserving daemon endpoint because lifecycle authority is unavailable"
            );
            return false;
        };
        match endpoint_ownership(kin_root) {
            EndpointOwnership::OtherProcess { pid, live: false } if pid == owner_pid => {
                remove_endpoint_components(kin_root);
                true
            }
            _ => false,
        }
    })
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
            without_blocking_runtime_worker(|| {
                let Ok(_authority) = acquire_singleton_coordination_guard(kin_root) else {
                    return;
                };
                if endpoint_ownership(kin_root) == stale {
                    remove_endpoint_components(kin_root);
                }
            });
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

// ── Daemon Binary Discovery ─────────────────────────────────────────────

#[cfg(target_os = "macos")]
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

#[cfg(target_os = "macos")]
fn resolve_launch_agent_daemon_binary(
    selected: &Path,
    resolution_cwd: &Path,
) -> Result<PathBuf, String> {
    let candidate = if selected.is_absolute() {
        selected.to_path_buf()
    } else {
        resolution_cwd.join(selected)
    };
    let canonical = candidate.canonicalize().map_err(|error| {
        format!(
            "canonicalize selected kin-daemon binary {}: {error}",
            candidate.display()
        )
    })?;
    let metadata = canonical.metadata().map_err(|error| {
        format!(
            "inspect selected kin-daemon binary {}: {error}",
            canonical.display()
        )
    })?;
    if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
        return Err(format!(
            "selected kin-daemon binary {} is not a regular executable file",
            canonical.display()
        ));
    }
    Ok(canonical)
}

#[cfg(target_os = "macos")]
fn validate_launch_agent_daemon_binary(path: &Path) -> Result<(), String> {
    let mut command = Command::new(path);
    command.arg("--compat-json");
    let label = format!("{} --compat-json", path.display());
    let output = output_macos_command_with_deadline(
        command,
        &label,
        LAUNCHCTL_DEADLINE,
        LAUNCHCTL_CAPTURE_LIMIT,
    )
    .map_err(|error| format!("validate LaunchAgent kin-daemon binary: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "selected kin-daemon binary {} failed compatibility probe with status {} \
             (stdout-bytes={}, stderr-bytes={})",
            path.display(),
            output.status,
            output.stdout.len(),
            output.stderr.len()
        ));
    }
    kin_cli::daemon_client::validate_daemon_compat_json(&output.stdout).map_err(|error| {
        format!(
            "selected kin-daemon binary {} is incompatible with this Kin build: {error}",
            path.display()
        )
    })
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

// Starting a repo daemon is not this crate's surface. `kin-cli` owns the one
// startup, readiness, supervisor, and failure-cleanup contract, and
// `kin-daemon-spawn` owns the decisions both start paths share. This module
// used to re-export a third entry point on top of them, which for a published
// crate is an invitation to start a daemon through a path nothing in tree
// exercises. Call `kin_cli::daemon_client::ensure_daemon_running` instead.

// ── macOS Launch Agent (start on boot) ───────────────────────────────────

#[cfg(target_os = "macos")]
const LAUNCHCTL_DEADLINE: Duration = Duration::from_secs(10);
#[cfg(target_os = "macos")]
const LAUNCHCTL_CLEANUP_GRACE: Duration = Duration::from_secs(5);
#[cfg(target_os = "macos")]
const LAUNCHCTL_POLL_INTERVAL: Duration = Duration::from_millis(10);
#[cfg(target_os = "macos")]
const LAUNCHCTL_CAPTURE_LIMIT: u64 = 64 * 1024;
#[cfg(all(test, target_os = "macos"))]
static RETAINED_LAUNCHCTL_DIRECT_REAP_COMPLETED_PID: std::sync::atomic::AtomicU32 =
    std::sync::atomic::AtomicU32::new(0);

/// A regular-file output capture that removes its private backing file on
/// every return path.
///
/// Pipes are deliberately unsuitable here: `launchctl` (or a subprocess it
/// starts) can pass a pipe write end to a descendant, causing `Command::output`
/// to wait forever after the direct child exits. A regular file makes direct
/// child completion independently observable, while the polling loop below
/// caps both disk growth and readback.
#[cfg(target_os = "macos")]
struct LaunchctlCapture {
    path: PathBuf,
    file: File,
}

#[cfg(target_os = "macos")]
impl LaunchctlCapture {
    fn create(stream: &str) -> std::io::Result<Self> {
        use std::os::unix::fs::OpenOptionsExt as _;

        for _ in 0..16 {
            let path = std::env::temp_dir().join(format!(
                "kin-launchctl-{}-{stream}-{}.capture",
                std::process::id(),
                uuid::Uuid::new_v4()
            ));
            match OpenOptions::new()
                .create_new(true)
                .read(true)
                .write(true)
                .mode(0o600)
                .open(&path)
            {
                Ok(file) => return Ok(Self { path, file }),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error),
            }
        }
        Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "could not allocate a unique launchctl capture file",
        ))
    }

    fn len(&self) -> std::io::Result<u64> {
        Ok(self.file.metadata()?.len())
    }

    fn read_bounded(&self, limit: u64) -> std::io::Result<Vec<u8>> {
        let mut file = self.file.try_clone()?;
        file.seek(SeekFrom::Start(0))?;
        let mut bytes = Vec::with_capacity(usize::try_from(limit.min(16 * 1024)).unwrap_or(0));
        file.take(limit.saturating_add(1)).read_to_end(&mut bytes)?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > limit {
            bytes.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
        }
        Ok(bytes)
    }
}

#[cfg(target_os = "macos")]
impl Drop for LaunchctlCapture {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Stable ownership for the complete `launchctl` process group.
///
/// The shared watcher owns a separate inert sentinel in the target group. Its
/// stdin is an ownership pipe: ordinary cleanup closes it, and parent death
/// closes it in the kernel. The watcher remains outside the target group so it
/// can establish a stop barrier, kill every member, and prove the pinned group
/// empty even if Rust cleanup never runs.
#[cfg(target_os = "macos")]
struct LaunchctlContainment {
    guardian: Option<kin_daemon_spawn::ProcessGroupGuardian>,
}

/// Resolve the guardian entrypoint for a real Kin product process.
///
/// Product binaries dispatch the private guardian mode before normal argument
/// parsing. Keeping this branch on `product` is load-bearing: `exact_test`
/// appends libtest-only arguments and is reserved for the unit-test binary
/// below.
#[cfg(all(target_os = "macos", not(test)))]
fn launchctl_guardian_launcher() -> std::io::Result<kin_daemon_spawn::ProcessGroupGuardianLauncher>
{
    let executable = std::env::current_exe()
        .map_err(|error| lifecycle_io(error, "resolve launchctl guardian executable"))?;
    Ok(kin_daemon_spawn::ProcessGroupGuardianLauncher::product(
        executable,
    ))
}

/// Route a re-executed Rust unit-test binary to one exact guardian worker.
#[cfg(all(target_os = "macos", test))]
fn launchctl_guardian_launcher() -> std::io::Result<kin_daemon_spawn::ProcessGroupGuardianLauncher>
{
    let executable = std::env::current_exe()
        .map_err(|error| lifecycle_io(error, "resolve launchctl guardian test executable"))?;
    Ok(kin_daemon_spawn::ProcessGroupGuardianLauncher::exact_test(
        executable,
        "kin_process_group_guardian_worker",
    ))
}

#[cfg(target_os = "macos")]
impl LaunchctlContainment {
    fn spawn(command: Command, deadline: Instant) -> std::io::Result<(Child, Self)> {
        let readiness = LaunchctlCapture::create("guardian-ready")?;
        let launcher = launchctl_guardian_launcher()?;
        let mut guardian = launcher
            .spawn_with(&readiness.path, deadline, |guardian_environment| {
                // Preserve the launchctl caller's authority boundary. The
                // shared launcher installs its private dispatch values only
                // after this scrub returns.
                kin_daemon_spawn::scrub_daemon_guardian_environment(guardian_environment);
            })
            .map_err(|error| lifecycle_io(error, "spawn launchctl parent-death guardian"))?;

        match guardian.spawn(command) {
            Ok(child) => Ok((
                child,
                Self {
                    guardian: Some(guardian),
                },
            )),
            Err(error) => {
                let mut containment = Self {
                    guardian: Some(guardian),
                };
                let cleanup = containment.terminate_and_reap("unlaunched launchctl");
                Err(lifecycle_io(
                    error,
                    format!(
                        "spawn launchctl inside stable containment; cleanup={}",
                        render_lifecycle_result(&cleanup)
                    ),
                ))
            }
        }
    }

    fn terminate(&mut self) -> std::io::Result<()> {
        if let Some(guardian) = self.guardian.as_mut() {
            guardian.request_cleanup();
        }
        Ok(())
    }

    fn take_guardian(&mut self) -> Option<kin_daemon_spawn::ProcessGroupGuardian> {
        self.guardian.take()
    }

    fn confirm_empty_until(&mut self, deadline: Instant, label: &str) -> std::io::Result<()> {
        let Some(guardian) = self.guardian.as_mut() else {
            return Ok(());
        };
        match guardian.reap_until(deadline) {
            Ok(_) => {
                self.guardian.take();
                Ok(())
            }
            Err(error) => Err(lifecycle_io(
                error,
                format!("prove {label} process-group containment empty"),
            )),
        }
    }

    fn reap_guardian_until(&mut self, deadline: Instant, label: &str) -> std::io::Result<()> {
        self.confirm_empty_until(deadline, label)
    }

    fn terminate_and_reap(&mut self, label: &str) -> std::io::Result<()> {
        let terminate = self.terminate();
        let empty = self.confirm_empty_until(Instant::now() + LAUNCHCTL_CLEANUP_GRACE, label);
        let reap = if empty.is_ok() {
            self.reap_guardian_until(Instant::now() + LAUNCHCTL_CLEANUP_GRACE, label)
        } else {
            Err(std::io::Error::other(
                "guardian reap skipped because live containment was not disproven",
            ))
        };
        combine_lifecycle_cleanup(terminate, Ok(()), empty, reap)
    }
}

#[cfg(target_os = "macos")]
impl Drop for LaunchctlContainment {
    fn drop(&mut self) {
        let _ = self.terminate();
        let _ = self.confirm_empty_until(
            Instant::now() + LAUNCHCTL_CLEANUP_GRACE,
            "launchctl command",
        );
    }
}

#[cfg(target_os = "macos")]
fn poll_launchctl_child_until(
    child: &mut Child,
    deadline: Instant,
    label: &str,
) -> std::io::Result<Option<ExitStatus>> {
    loop {
        if let Some(status) = child
            .try_wait()
            .map_err(|error| lifecycle_io(error, format!("poll {label} during cleanup")))?
        {
            return Ok(Some(status));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        std::thread::sleep(LAUNCHCTL_POLL_INTERVAL);
    }
}

/// Unwind-safe ownership of both the direct process and its complete tree.
///
/// `std::process::Child` does not wait in Drop. Keeping the child beside the
/// containment capability ensures a panic between spawn and an explicit
/// return path still terminates and reaps the direct child before releasing
/// the stable guardian.
#[cfg(target_os = "macos")]
struct RunningLaunchctlCommand {
    child: Option<Child>,
    containment: LaunchctlContainment,
    #[cfg(test)]
    force_direct_reap_retention: bool,
}

#[cfg(target_os = "macos")]
impl RunningLaunchctlCommand {
    fn child_mut(&mut self) -> &mut Child {
        self.child
            .as_mut()
            .expect("launchctl direct-child handle remains owned")
    }

    fn cleanup(&mut self, label: &str) -> std::io::Result<()> {
        if self.child.is_none() && self.containment.guardian.is_none() {
            return Ok(());
        }

        let terminate = self.containment.terminate();
        let direct_kill = match self.child.as_mut() {
            Some(child) => match child.kill() {
                Ok(()) => Ok(()),
                Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => Ok(()),
                Err(error) => Err(lifecycle_io(error, format!("kill direct {label} process"))),
            },
            None => Ok(()),
        };
        #[cfg(test)]
        let force_direct_reap_retention = std::mem::take(&mut self.force_direct_reap_retention);
        #[cfg(not(test))]
        let force_direct_reap_retention = false;
        let (direct_reaped, direct_reap) = match self.child.as_mut() {
            Some(_) if force_direct_reap_retention => (
                false,
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!("direct {label} process was not reaped by the forced test path"),
                )),
            ),
            Some(child) => match poll_launchctl_child_until(
                child,
                Instant::now() + LAUNCHCTL_CLEANUP_GRACE,
                label,
            ) {
                Ok(Some(_)) => (true, direct_kill),
                Ok(None) => (
                    false,
                    Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        format!("direct {label} process was not reaped"),
                    )),
                ),
                Err(error) => (false, Err(error)),
            },
            None => (true, Ok(())),
        };

        if !direct_reaped {
            let retention = retain_failed_launchctl_command(self, label);
            return Err(std::io::Error::other(format!(
                "containment terminate={}; direct reap={}; containment proof deferred until exact \
                 direct status is retained; retention={}",
                render_lifecycle_result(&terminate),
                render_lifecycle_result(&direct_reap),
                render_lifecycle_result(&retention)
            )));
        }
        self.child.take();

        let empty = self
            .containment
            .confirm_empty_until(Instant::now() + LAUNCHCTL_CLEANUP_GRACE, label);
        let guardian_reap = if empty.is_ok() {
            self.containment
                .reap_guardian_until(Instant::now() + LAUNCHCTL_CLEANUP_GRACE, label)
        } else {
            Err(std::io::Error::other(
                "guardian reap skipped because live containment was not disproven",
            ))
        };
        combine_lifecycle_cleanup(terminate, direct_reap, empty, guardian_reap)
    }
}

#[cfg(target_os = "macos")]
struct RetainedLaunchctlCleanup {
    child: Child,
    guardian: kin_daemon_spawn::ProcessGroupGuardian,
}

#[cfg(target_os = "macos")]
impl RetainedLaunchctlCleanup {
    fn run(mut self) {
        #[cfg(test)]
        let child_id = self.child.id();
        self.guardian.request_cleanup();
        let _ = self.child.kill();
        loop {
            match self.child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) | Err(_) => {
                    let _ = self.child.kill();
                    std::thread::sleep(LAUNCHCTL_POLL_INTERVAL);
                }
            }
        }
        #[cfg(test)]
        RETAINED_LAUNCHCTL_DIRECT_REAP_COMPLETED_PID
            .store(child_id, std::sync::atomic::Ordering::SeqCst);
        // The exact direct status is now reaped. Only now may guardian
        // finalization consume the sentinel and release the numeric PGID pin.
        let _ = self
            .guardian
            .reap_until(Instant::now() + LAUNCHCTL_CLEANUP_GRACE);
    }
}

#[cfg(target_os = "macos")]
fn retain_failed_launchctl_command(
    running: &mut RunningLaunchctlCommand,
    label: &str,
) -> std::io::Result<()> {
    let Some(child) = running.child.take() else {
        if let Some(mut guardian) = running.containment.take_guardian() {
            guardian.request_cleanup();
            std::mem::forget(guardian);
        }
        return Err(std::io::Error::other(format!(
            "{label} lost its exact direct-child handle; guardian intentionally retained"
        )));
    };
    let Some(guardian) = running.containment.take_guardian() else {
        std::mem::forget(child);
        return Err(std::io::Error::other(format!(
            "{label} lost its guardian; exact direct-child handle intentionally retained"
        )));
    };

    let retained = std::mem::ManuallyDrop::new(RetainedLaunchctlCleanup { child, guardian });
    std::thread::Builder::new()
        .name("kin-retained-launchctl-cleanup".to_string())
        .spawn(move || {
            let retained = std::mem::ManuallyDrop::into_inner(retained);
            retained.run();
        })
        .map(|_| ())
        .map_err(|error| {
            std::io::Error::new(
                error.kind(),
                format!(
                    "spawn retained launchctl cleanup owner for {label}: {error}; exact guardian \
                     and direct-child handles intentionally retained"
                ),
            )
        })
}

#[cfg(target_os = "macos")]
impl Drop for RunningLaunchctlCommand {
    fn drop(&mut self) {
        let _ = self.cleanup("launchctl command unwind guard");
    }
}

#[cfg(target_os = "macos")]
fn combine_lifecycle_cleanup(
    terminate: std::io::Result<()>,
    direct_reap: std::io::Result<()>,
    empty: std::io::Result<()>,
    guardian_reap: std::io::Result<()>,
) -> std::io::Result<()> {
    if terminate.is_ok() && direct_reap.is_ok() && empty.is_ok() && guardian_reap.is_ok() {
        return Ok(());
    }
    Err(std::io::Error::other(format!(
        "containment terminate={}; direct reap={}; containment empty={}; guardian reap={}",
        render_lifecycle_result(&terminate),
        render_lifecycle_result(&direct_reap),
        render_lifecycle_result(&empty),
        render_lifecycle_result(&guardian_reap)
    )))
}

#[cfg(target_os = "macos")]
fn render_lifecycle_result(result: &std::io::Result<()>) -> String {
    result
        .as_ref()
        .map(|_| "ok".to_string())
        .unwrap_or_else(|error| error.to_string())
}

#[cfg(target_os = "macos")]
fn lifecycle_io(error: std::io::Error, context: impl std::fmt::Display) -> std::io::Error {
    std::io::Error::new(error.kind(), format!("{context}: {error}"))
}

#[cfg(target_os = "macos")]
fn cap_command_capture_files(command: &mut Command, capture_limit: u64) -> std::io::Result<()> {
    use std::os::unix::process::CommandExt as _;

    // Permit exactly one sentinel byte beyond the public limit. That byte
    // makes an overflow mechanically distinguishable from output whose length
    // is exactly the accepted maximum, while RLIMIT_FSIZE prevents a child
    // from filling disk between metadata polls.
    let kernel_limit: libc::rlim_t = capture_limit
        .checked_add(1)
        .ok_or_else(|| std::io::Error::other("launchctl capture limit overflow"))?;
    unsafe {
        command.pre_exec(move || {
            let limits = libc::rlimit {
                rlim_cur: kernel_limit,
                rlim_max: kernel_limit,
            };
            if libc::setrlimit(libc::RLIMIT_FSIZE, &limits) == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn output_macos_command_with_deadline(
    mut command: Command,
    label: &str,
    timeout: Duration,
    capture_limit: u64,
) -> std::io::Result<Output> {
    let stdout = LaunchctlCapture::create("stdout")?;
    let stderr = LaunchctlCapture::create("stderr")?;
    command
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout.file.try_clone()?))
        .stderr(Stdio::from(stderr.file.try_clone()?));
    kin_daemon_spawn::scrub_daemon_process_authority(&mut command);
    cap_command_capture_files(&mut command, capture_limit)?;

    let deadline = Instant::now() + timeout;
    let (child, containment) = LaunchctlContainment::spawn(command, deadline)?;
    let mut running = RunningLaunchctlCommand {
        child: Some(child),
        containment,
        #[cfg(test)]
        force_direct_reap_retention: false,
    };
    loop {
        let stdout_len = stdout.len();
        let stderr_len = stderr.len();
        match (stdout_len, stderr_len) {
            (Ok(stdout_len), Ok(stderr_len))
                if stdout_len > capture_limit || stderr_len > capture_limit =>
            {
                let cleanup = running.cleanup(label);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "{label} exceeded the {capture_limit}-byte per-stream capture limit \
                         (stdout={stdout_len}, stderr={stderr_len}); cleanup={}",
                        render_lifecycle_result(&cleanup)
                    ),
                ));
            }
            (Ok(_), Ok(_)) => {}
            (Err(error), _) | (_, Err(error)) => {
                let cleanup = running.cleanup(label);
                return Err(lifecycle_io(
                    error,
                    format!(
                        "inspect {label} capture size; cleanup={}",
                        render_lifecycle_result(&cleanup)
                    ),
                ));
            }
        }

        match running.child_mut().try_wait() {
            Ok(Some(status)) => {
                let descendant_cleanup = running.containment.terminate_and_reap(label);
                if let Err(error) = descendant_cleanup {
                    return Err(lifecycle_io(
                        error,
                        format!("clean {label} descendants after direct exit"),
                    ));
                }
                let stdout_len = stdout.len()?;
                let stderr_len = stderr.len()?;
                if stdout_len > capture_limit || stderr_len > capture_limit {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "{label} exceeded the {capture_limit}-byte per-stream capture limit \
                             (stdout={stdout_len}, stderr={stderr_len})"
                        ),
                    ));
                }
                return Ok(Output {
                    status,
                    stdout: stdout.read_bounded(capture_limit)?,
                    stderr: stderr.read_bounded(capture_limit)?,
                });
            }
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(LAUNCHCTL_POLL_INTERVAL);
            }
            Ok(None) => {
                let cleanup = running.cleanup(label);
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    format!(
                        "{label} timed out after {timeout:?}; cleanup={}",
                        render_lifecycle_result(&cleanup)
                    ),
                ));
            }
            Err(error) => {
                let cleanup = running.cleanup(label);
                return Err(lifecycle_io(
                    error,
                    format!(
                        "poll {label}; cleanup={}",
                        render_lifecycle_result(&cleanup)
                    ),
                ));
            }
        }
    }
}

#[cfg(target_os = "macos")]
#[derive(Debug, PartialEq, Eq)]
enum LaunchctlActionError {
    NotLoaded(String),
    Failed(String),
}

#[cfg(target_os = "macos")]
impl std::fmt::Display for LaunchctlActionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotLoaded(detail) | Self::Failed(detail) => formatter.write_str(detail),
        }
    }
}

#[cfg(target_os = "macos")]
fn launchctl_action(action: &str, plist_path: &Path) -> Result<(), LaunchctlActionError> {
    let mut command = Command::new("/bin/launchctl");
    command.arg(action).arg(plist_path);
    let label = format!("launchctl {action}");
    let output = output_macos_command_with_deadline(
        command,
        &label,
        LAUNCHCTL_DEADLINE,
        LAUNCHCTL_CAPTURE_LIMIT,
    )
    .map_err(|error| LaunchctlActionError::Failed(format!("{label}: {error}")))?;
    require_launchctl_success(action, &label, output)
}

#[cfg(target_os = "macos")]
fn require_launchctl_success(
    action: &str,
    label: &str,
    output: Output,
) -> Result<(), LaunchctlActionError> {
    if output.status.success() {
        return Ok(());
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let detail = format!(
        "{label} failed with status {}: stdout={} stderr={}",
        output.status,
        stdout.trim(),
        stderr.trim()
    );
    if action == "unload" && launchctl_reports_not_loaded(&stdout, &stderr) {
        Err(LaunchctlActionError::NotLoaded(detail))
    } else {
        Err(LaunchctlActionError::Failed(detail))
    }
}

#[cfg(target_os = "macos")]
fn launchctl_reports_not_loaded(stdout: &str, stderr: &str) -> bool {
    let report = format!("{stdout}\n{stderr}").to_ascii_lowercase();
    ["could not find specified service", "service is not loaded"]
        .iter()
        .any(|marker| report.contains(marker))
}

#[cfg(target_os = "macos")]
fn unload_then_remove_launch_agent(
    plist_path: &Path,
    unload: impl FnOnce() -> Result<(), LaunchctlActionError>,
) -> Result<(), String> {
    match unload() {
        Ok(()) | Err(LaunchctlActionError::NotLoaded(_)) => {}
        Err(error @ LaunchctlActionError::Failed(_)) => return Err(error.to_string()),
    }
    std::fs::remove_file(plist_path)
        .map_err(|error| format!("remove launch agent {}: {error}", plist_path.display()))
}

#[cfg(target_os = "macos")]
fn launch_agent_label(working_dir: &Path) -> Result<String, String> {
    let canonical = working_dir.canonicalize().map_err(|error| {
        format!(
            "canonicalize repository root {} for LaunchAgent identity: {error}",
            working_dir.display()
        )
    })?;
    let canonical_text = launch_agent_path_text(&canonical, "repository root")?;
    let digest = hex::encode(Sha256::digest(canonical_text.as_bytes()));
    let raw_suffix = canonical
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or("repo");
    let mut suffix = String::with_capacity(raw_suffix.len().min(32));
    let mut previous_dash = false;
    for character in raw_suffix.chars() {
        if suffix.len() >= 32 {
            break;
        }
        let normalized = if character.is_ascii_alphanumeric() {
            character.to_ascii_lowercase()
        } else {
            '-'
        };
        if normalized == '-' {
            if suffix.is_empty() || previous_dash {
                continue;
            }
            previous_dash = true;
        } else {
            previous_dash = false;
        }
        suffix.push(normalized);
    }
    while suffix.ends_with('-') {
        suffix.pop();
    }
    if suffix.is_empty() {
        suffix.push_str("repo");
    }
    Ok(format!(
        "ai.firelock.kin-daemon.{}.{}",
        &digest[..32],
        suffix
    ))
}

#[cfg(target_os = "macos")]
fn launch_agent_path_text<'a>(path: &'a Path, label: &str) -> Result<&'a str, String> {
    path.to_str().ok_or_else(|| {
        format!(
            "{label} cannot be represented as UTF-8 for LaunchAgent registration: {}",
            path.display()
        )
    })
}

#[cfg(target_os = "macos")]
fn plist_xml_text(value: &str) -> Result<String, String> {
    let mut escaped = String::with_capacity(value.len());
    for character in value.chars() {
        if !matches!(
            character,
            '\u{9}' | '\u{A}' | '\u{D}'
                | '\u{20}'..='\u{D7FF}'
                | '\u{E000}'..='\u{FFFD}'
                | '\u{10000}'..='\u{10FFFF}'
        ) {
            return Err(format!(
                "LaunchAgent plist value contains XML 1.0-illegal character U+{:04X}",
                u32::from(character)
            ));
        }
        match character {
            '\t' => escaped.push_str("&#x9;"),
            '\n' => escaped.push_str("&#xA;"),
            '\r' => escaped.push_str("&#xD;"),
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            _ => escaped.push(character),
        }
    }
    Ok(escaped)
}

#[cfg(target_os = "macos")]
#[derive(Debug, PartialEq, Eq)]
enum LegacyLaunchAgentDisposition {
    Absent,
    Removed,
    PreservedUnrelated,
}

#[cfg(target_os = "macos")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LegacyLaunchAgentInspection {
    Absent,
    Matching,
    PreservedUnrelated,
}

#[cfg(target_os = "macos")]
#[derive(Debug, PartialEq, Eq)]
enum LegacyMigrationCommitError {
    PriorAuthorityActive(String),
    ReplacementRequired(String),
}

#[cfg(target_os = "macos")]
impl std::fmt::Display for LegacyMigrationCommitError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PriorAuthorityActive(detail) | Self::ReplacementRequired(detail) => {
                formatter.write_str(detail)
            }
        }
    }
}

#[cfg(target_os = "macos")]
fn legacy_launch_agent_label(working_dir: &Path) -> String {
    // This intentionally reproduces the pre-digest identity exactly so an
    // upgrade can find it. Do not sanitize or canonicalize the basename here.
    let repo_id = working_dir
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("default");
    format!("ai.firelock.kin-daemon.{repo_id}")
}

#[cfg(target_os = "macos")]
fn read_plist_program_arguments(plist_path: &Path) -> Result<Vec<String>, String> {
    let mut command = Command::new("/usr/bin/plutil");
    command
        .arg("-extract")
        .arg("ProgramArguments")
        .arg("json")
        .arg("-o")
        .arg("-")
        .arg(plist_path);
    let output = output_macos_command_with_deadline(
        command,
        "plutil extract ProgramArguments",
        LAUNCHCTL_DEADLINE,
        LAUNCHCTL_CAPTURE_LIMIT,
    )
    .map_err(|error| {
        format!(
            "inspect legacy LaunchAgent {} ProgramArguments: {error}",
            plist_path.display()
        )
    })?;
    if !output.status.success() {
        return Err(format!(
            "inspect legacy LaunchAgent {} ProgramArguments: plutil exited with {} \
             (stdout-bytes={}, stderr-bytes={})",
            plist_path.display(),
            output.status,
            output.stdout.len(),
            output.stderr.len()
        ));
    }
    serde_json::from_slice(&output.stdout).map_err(|error| {
        format!(
            "decode legacy LaunchAgent {} ProgramArguments: {error}",
            plist_path.display()
        )
    })
}

#[cfg(target_os = "macos")]
fn legacy_program_arguments_target_repository(
    arguments: &[String],
    canonical_target: &Path,
) -> Result<bool, String> {
    let repo_positions = arguments
        .iter()
        .enumerate()
        .filter_map(|(index, argument)| (argument == "--repo").then_some(index))
        .collect::<Vec<_>>();
    let [repo_index] = repo_positions.as_slice() else {
        return Err(format!(
            "legacy LaunchAgent must contain exactly one --repo argument, found {}",
            repo_positions.len()
        ));
    };
    let repo_index = *repo_index;
    let repo_argument = arguments
        .get(repo_index + 1)
        .ok_or_else(|| "legacy LaunchAgent --repo argument has no value".to_string())?;
    let recorded_path = Path::new(repo_argument);
    if !recorded_path.is_absolute() {
        return Err(format!(
            "legacy LaunchAgent --repo argument must be absolute, found {}",
            recorded_path.display()
        ));
    }
    let recorded = recorded_path.canonicalize().map_err(|error| {
        format!(
            "canonicalize legacy LaunchAgent repository {}: {error}",
            recorded_path.display()
        )
    })?;
    Ok(recorded == canonical_target)
}

#[cfg(target_os = "macos")]
fn inspect_legacy_launch_agent(
    plist_path: &Path,
    canonical_target: &Path,
    read_program_arguments: impl FnOnce(&Path) -> Result<Vec<String>, String>,
) -> Result<LegacyLaunchAgentInspection, String> {
    if !plist_path.exists() {
        return Ok(LegacyLaunchAgentInspection::Absent);
    }
    let arguments = read_program_arguments(plist_path)?;
    if !legacy_program_arguments_target_repository(&arguments, canonical_target)? {
        return Ok(LegacyLaunchAgentInspection::PreservedUnrelated);
    }
    Ok(LegacyLaunchAgentInspection::Matching)
}

#[cfg(target_os = "macos")]
fn remove_legacy_launch_agent_if_matching(
    plist_path: &Path,
    canonical_target: &Path,
    read_program_arguments: impl FnOnce(&Path) -> Result<Vec<String>, String>,
    unload: impl FnOnce() -> Result<(), LaunchctlActionError>,
) -> Result<LegacyLaunchAgentDisposition, String> {
    match inspect_legacy_launch_agent(plist_path, canonical_target, read_program_arguments)? {
        LegacyLaunchAgentInspection::Absent => {
            return Ok(LegacyLaunchAgentDisposition::Absent);
        }
        LegacyLaunchAgentInspection::PreservedUnrelated => {
            return Ok(LegacyLaunchAgentDisposition::PreservedUnrelated);
        }
        LegacyLaunchAgentInspection::Matching => {}
    }
    unload_then_remove_launch_agent(plist_path, unload)?;
    Ok(LegacyLaunchAgentDisposition::Removed)
}

#[cfg(target_os = "macos")]
fn reconcile_legacy_launch_agent(
    launch_agents: &Path,
    working_dir: &Path,
    canonical_target: &Path,
) -> Result<(String, LegacyLaunchAgentDisposition), String> {
    let label = legacy_launch_agent_label(working_dir);
    let plist_path = launch_agents.join(format!("{label}.plist"));
    let disposition = remove_legacy_launch_agent_if_matching(
        &plist_path,
        canonical_target,
        read_plist_program_arguments,
        || launchctl_action("unload", &plist_path),
    )?;
    Ok((label, disposition))
}

#[cfg(target_os = "macos")]
fn commit_legacy_launch_agent_migration(
    preflight: LegacyLaunchAgentInspection,
    plist_path: &Path,
    canonical_target: &Path,
    read_program_arguments: impl FnOnce(&Path) -> Result<Vec<String>, String>,
    unload: impl FnOnce() -> Result<(), LaunchctlActionError>,
    remove: impl FnOnce() -> Result<(), String>,
    restore_job: impl FnOnce() -> Result<(), LaunchctlActionError>,
) -> Result<LegacyLaunchAgentDisposition, LegacyMigrationCommitError> {
    // Re-read the visible legacy authority after replacement activation. This
    // closes ordinary absent/matching/unrelated changes between preflight and
    // commit. It deliberately does not claim protection against a malicious
    // same-user writer racing the subsequent launchctl/filesystem operations;
    // ambiguous evidence is preserved and reported instead of guessed.
    match inspect_legacy_launch_agent(plist_path, canonical_target, read_program_arguments) {
        Ok(LegacyLaunchAgentInspection::Absent) => {
            return Ok(LegacyLaunchAgentDisposition::Absent);
        }
        Ok(LegacyLaunchAgentInspection::PreservedUnrelated) => {
            return Ok(LegacyLaunchAgentDisposition::PreservedUnrelated);
        }
        Ok(LegacyLaunchAgentInspection::Matching) => {}
        Err(error) => {
            let detail =
                format!("legacy LaunchAgent could not be revalidated after preflight: {error}");
            return if preflight == LegacyLaunchAgentInspection::Matching {
                Err(LegacyMigrationCommitError::PriorAuthorityActive(detail))
            } else {
                Err(LegacyMigrationCommitError::ReplacementRequired(format!(
                    "{detail}; the unverifiable exact object was preserved and the loaded \
                     replacement remains active"
                )))
            };
        }
    }

    let legacy_was_loaded = match unload() {
        Ok(()) => true,
        Err(LaunchctlActionError::NotLoaded(_)) => false,
        Err(error @ LaunchctlActionError::Failed(_)) => {
            return Err(LegacyMigrationCommitError::PriorAuthorityActive(
                error.to_string(),
            ));
        }
    };

    if let Err(remove_error) = remove() {
        if !legacy_was_loaded {
            return Err(LegacyMigrationCommitError::ReplacementRequired(format!(
                "{remove_error}; the legacy job was already unloaded, so the loaded replacement \
                 remains active"
            )));
        }
        return match restore_job() {
            Ok(()) => Err(LegacyMigrationCommitError::PriorAuthorityActive(format!(
                "{remove_error}; restored the legacy job before replacement rollback"
            ))),
            Err(restore_error) => Err(LegacyMigrationCommitError::ReplacementRequired(format!(
                "{remove_error}; could not restore the legacy job ({restore_error}), so the \
                 loaded replacement remains active"
            ))),
        };
    }

    Ok(LegacyLaunchAgentDisposition::Removed)
}

#[cfg(target_os = "macos")]
#[derive(Debug)]
struct LoadedDigestLaunchAgent {
    plist_path: PathBuf,
    prior_plist: Option<Vec<u8>>,
    prior_was_loaded: bool,
}

#[cfg(target_os = "macos")]
impl LoadedDigestLaunchAgent {
    fn install(plist_path: &Path, plist: &[u8]) -> Result<Self, String> {
        Self::install_with_actions(
            plist_path,
            plist,
            |path| launchctl_action("unload", path),
            |path| launchctl_action("load", path),
            |path| unload_then_remove_launch_agent(path, || launchctl_action("unload", path)),
            |path| launchctl_action("load", path),
        )
    }

    fn install_with_actions(
        plist_path: &Path,
        plist: &[u8],
        unload_prior: impl FnOnce(&Path) -> Result<(), LaunchctlActionError>,
        load_replacement: impl FnOnce(&Path) -> Result<(), LaunchctlActionError>,
        cleanup_failed_replacement: impl FnOnce(&Path) -> Result<(), String>,
        restore_prior_job: impl FnOnce(&Path) -> Result<(), LaunchctlActionError>,
    ) -> Result<Self, String> {
        let stage_path = write_launch_agent_stage(plist_path, plist)?;
        let prior_plist = match read_bounded_launch_agent_plist(plist_path) {
            Ok(contents) => contents,
            Err(error) => {
                let _ = std::fs::remove_file(&stage_path);
                return Err(error);
            }
        };
        let prior_was_loaded = if prior_plist.is_some() {
            match unload_prior(plist_path) {
                Ok(()) => true,
                Err(LaunchctlActionError::NotLoaded(_)) => false,
                Err(error @ LaunchctlActionError::Failed(_)) => {
                    let _ = std::fs::remove_file(&stage_path);
                    return Err(error.to_string());
                }
            }
        } else {
            false
        };

        if let Err(load_error) = load_replacement(&stage_path) {
            let cleanup = cleanup_failed_replacement(&stage_path);
            let restore = if prior_was_loaded {
                restore_prior_job(plist_path).map_err(|error| error.to_string())
            } else {
                Ok(())
            };
            return Err(format!(
                "{load_error}; failed replacement cleanup={cleanup:?}; prior restore={restore:?}"
            ));
        }

        if let Err(publish_error) = std::fs::rename(&stage_path, plist_path) {
            let cleanup = cleanup_failed_replacement(&stage_path);
            let restore = if prior_was_loaded {
                restore_prior_job(plist_path).map_err(|error| error.to_string())
            } else {
                Ok(())
            };
            return Err(format!(
                "publish digest LaunchAgent {}: {publish_error}; failed replacement \
                 cleanup={cleanup:?}; prior restore={restore:?}",
                plist_path.display()
            ));
        }

        Ok(Self {
            plist_path: plist_path.to_path_buf(),
            prior_plist,
            prior_was_loaded,
        })
    }

    fn rollback(self) -> Result<(), String> {
        self.rollback_with_actions(
            |path| launchctl_action("unload", path),
            |path| launchctl_action("load", path),
        )
    }

    fn rollback_with_actions(
        self,
        unload_replacement: impl FnOnce(&Path) -> Result<(), LaunchctlActionError>,
        restore_prior_job: impl FnOnce(&Path) -> Result<(), LaunchctlActionError>,
    ) -> Result<(), String> {
        match unload_replacement(&self.plist_path) {
            Ok(()) | Err(LaunchctlActionError::NotLoaded(_)) => {}
            Err(error @ LaunchctlActionError::Failed(_)) => return Err(error.to_string()),
        }

        match self.prior_plist {
            Some(prior) => {
                let stage = write_launch_agent_stage(&self.plist_path, &prior)?;
                std::fs::rename(&stage, &self.plist_path).map_err(|error| {
                    format!(
                        "restore prior digest LaunchAgent {}: {error}; staged prior retained at {}",
                        self.plist_path.display(),
                        stage.display()
                    )
                })?;
                if self.prior_was_loaded {
                    restore_prior_job(&self.plist_path).map_err(|error| error.to_string())?;
                }
            }
            None => {
                std::fs::remove_file(&self.plist_path).map_err(|error| {
                    format!(
                        "remove rolled-back digest LaunchAgent {}: {error}",
                        self.plist_path.display()
                    )
                })?;
            }
        }
        Ok(())
    }
}

#[cfg(target_os = "macos")]
fn read_bounded_launch_agent_plist(plist_path: &Path) -> Result<Option<Vec<u8>>, String> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(plist_path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(format!(
                "open existing digest LaunchAgent {}: {error}",
                plist_path.display()
            ));
        }
    };
    let metadata = file.metadata().map_err(|error| {
        format!(
            "inspect existing digest LaunchAgent {}: {error}",
            plist_path.display()
        )
    })?;
    if !metadata.is_file() || metadata.uid() != unsafe { libc::geteuid() } || metadata.nlink() != 1
    {
        return Err(format!(
            "existing digest LaunchAgent {} is not a singly-linked regular file owned by this user",
            plist_path.display()
        ));
    }
    let mut contents = Vec::new();
    file.take(LAUNCHCTL_CAPTURE_LIMIT + 1)
        .read_to_end(&mut contents)
        .map_err(|error| {
            format!(
                "read existing digest LaunchAgent {}: {error}",
                plist_path.display()
            )
        })?;
    if contents.len() as u64 > LAUNCHCTL_CAPTURE_LIMIT {
        return Err(format!(
            "existing digest LaunchAgent {} exceeds the {}-byte retention limit",
            plist_path.display(),
            LAUNCHCTL_CAPTURE_LIMIT
        ));
    }
    Ok(Some(contents))
}

#[cfg(target_os = "macos")]
fn write_launch_agent_stage(plist_path: &Path, contents: &[u8]) -> Result<PathBuf, String> {
    let parent = plist_path
        .parent()
        .ok_or_else(|| format!("LaunchAgent {} has no parent", plist_path.display()))?;
    let file_name = plist_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("kin-daemon.plist");
    let stage_path = parent.join(format!(".{file_name}.{}.tmp", uuid::Uuid::new_v4()));
    let mut stage = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&stage_path)
        .map_err(|error| {
            format!(
                "create staged digest LaunchAgent {}: {error}",
                stage_path.display()
            )
        })?;
    if let Err(error) = stage.write_all(contents).and_then(|_| stage.sync_all()) {
        let _ = std::fs::remove_file(&stage_path);
        return Err(format!(
            "write staged digest LaunchAgent {}: {error}",
            stage_path.display()
        ));
    }
    Ok(stage_path)
}

#[cfg(target_os = "macos")]
fn install_replacement_after_legacy_preflight<Replacement>(
    preflight: impl FnOnce() -> Result<LegacyLaunchAgentInspection, String>,
    install_replacement: impl FnOnce() -> Result<Replacement, String>,
    commit_legacy: impl FnOnce(
        LegacyLaunchAgentInspection,
    ) -> Result<LegacyLaunchAgentDisposition, LegacyMigrationCommitError>,
    rollback_replacement: impl FnOnce(Replacement) -> Result<(), String>,
) -> Result<LegacyLaunchAgentDisposition, String> {
    let inspection = preflight()?;
    let replacement = install_replacement()?;
    match commit_legacy(inspection) {
        Ok(disposition) => Ok(disposition),
        Err(LegacyMigrationCommitError::ReplacementRequired(error)) => Err(error),
        Err(LegacyMigrationCommitError::PriorAuthorityActive(error)) => {
            match rollback_replacement(replacement) {
                Ok(()) => Err(format!(
                    "{error}; rolled back the digest-addressed replacement"
                )),
                Err(rollback_error) => Err(format!(
                    "{error}; replacement rollback also failed: {rollback_error}"
                )),
            }
        }
    }
}

/// Render the LaunchAgent plist for one repository.
///
/// Pure in its inputs so the argument vector launchd will run is assertable
/// without installing anything, which is the only way the port rule above stays
/// pinned: it is a property of the plist, not of a code path a test can reach.
#[cfg(target_os = "macos")]
fn render_launch_agent_plist(
    label: &str,
    daemon_path: &str,
    repo_path: &str,
) -> Result<String, String> {
    let escaped_label = plist_xml_text(label)?;
    let escaped_bin = plist_xml_text(daemon_path)?;
    let escaped_repo = plist_xml_text(repo_path)?;
    let escaped_stdout = plist_xml_text(&format!("/tmp/{label}.stdout.log"))?;
    let escaped_stderr = plist_xml_text(&format!("/tmp/{label}.stderr.log"))?;
    Ok(format!(
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
    <string>{stdout}</string>
    <key>StandardErrorPath</key>
    <string>{stderr}</string>
</dict>
</plist>"#,
        label = escaped_label,
        bin = escaped_bin,
        repo = escaped_repo,
        port = kin_daemon_spawn::DAEMON_PORT_ARGUMENT,
        stdout = escaped_stdout,
        stderr = escaped_stderr,
    ))
}

/// Internal implementation for a future Kin-owned launchd opt-in surface.
///
/// This stays crate-private because its containment re-executes the current
/// Kin product binary, which must dispatch the private guardian mode before
/// argument parsing. Exposing it to arbitrary downstream executables would
/// create an invalid implicit host contract. The current CLI does not call it
/// during `kin init`.
///
/// Each repo gets its own agent with a canonical-root digest label:
///   ai.firelock.kin-daemon.<digest>.<readable-suffix>
#[cfg(target_os = "macos")]
#[allow(dead_code)]
pub(crate) fn register_launch_agent(kin_root: &Path) -> Result<(), String> {
    let working_dir = kin_root.parent().ok_or("no parent")?;
    let canonical_working_dir = working_dir.canonicalize().map_err(|error| {
        format!(
            "canonicalize repository root {} for LaunchAgent registration: {error}",
            working_dir.display()
        )
    })?;
    let repo_path = launch_agent_path_text(&canonical_working_dir, "repository root")?;

    let binary_resolution_cwd = std::env::current_dir()
        .map_err(|error| format!("resolve current directory for kin-daemon selection: {error}"))?;
    let selected_daemon =
        find_daemon_binary().ok_or_else(|| "kin-daemon binary not found".to_string())?;
    let daemon_bin = resolve_launch_agent_daemon_binary(&selected_daemon, &binary_resolution_cwd)?;
    validate_launch_agent_daemon_binary(&daemon_bin)?;
    let daemon_path = launch_agent_path_text(&daemon_bin, "kin-daemon path")?;

    // The daemon owns port selection, here as on every other start path. This
    // used to bake a number into the plist: the port a daemon happened to be
    // serving, or one probed with a listener and released, or 4219 when neither
    // was available. Every one of those is a port some other process may hold
    // by the time launchd runs the agent, and `KeepAlive` then restarts a
    // daemon that keeps dying on the same bind conflict. Passing zero makes the
    // daemon bind an ephemeral port and publish it, which is what the port file
    // exists for and what every reader already consults.
    let label = launch_agent_label(&canonical_working_dir)?;
    let plist = render_launch_agent_plist(&label, daemon_path, repo_path)?;

    let home = std::env::var("HOME").map_err(|_| "HOME not set")?;
    let launch_agents = PathBuf::from(&home).join("Library/LaunchAgents");
    std::fs::create_dir_all(&launch_agents).map_err(|e| format!("create LaunchAgents dir: {e}"))?;

    let plist_path = launch_agents.join(format!("{label}.plist"));
    let legacy_label = legacy_launch_agent_label(working_dir);
    let legacy_plist_path = launch_agents.join(format!("{legacy_label}.plist"));
    let legacy_disposition = install_replacement_after_legacy_preflight(
        || {
            inspect_legacy_launch_agent(
                &legacy_plist_path,
                &canonical_working_dir,
                read_plist_program_arguments,
            )
        },
        || LoadedDigestLaunchAgent::install(&plist_path, plist.as_bytes()),
        |preflight| {
            commit_legacy_launch_agent_migration(
                preflight,
                &legacy_plist_path,
                &canonical_working_dir,
                read_plist_program_arguments,
                || launchctl_action("unload", &legacy_plist_path),
                || {
                    std::fs::remove_file(&legacy_plist_path).map_err(|error| {
                        format!(
                            "remove launch agent {}: {error}",
                            legacy_plist_path.display()
                        )
                    })
                },
                || launchctl_action("load", &legacy_plist_path),
            )
        },
        LoadedDigestLaunchAgent::rollback,
    )?;
    match legacy_disposition {
        LegacyLaunchAgentDisposition::Removed => {
            info!(
                label = %legacy_label,
                replacement = %label,
                "removed matching legacy macOS LaunchAgent after loading replacement"
            );
        }
        LegacyLaunchAgentDisposition::PreservedUnrelated => {
            info!(
                label = %legacy_label,
                replacement = %label,
                "preserved same-basename legacy macOS LaunchAgent owned by another repository"
            );
        }
        LegacyLaunchAgentDisposition::Absent => {}
    }

    info!(label = %label, "registered macOS Launch Agent");
    Ok(())
}

/// Internal cleanup for the Kin-owned LaunchAgent implementation.
///
/// It remains crate-private for the same guardian-host reason as
/// [`register_launch_agent`]. The current CLI does not call it during
/// `kin eject`.
#[cfg(target_os = "macos")]
#[allow(dead_code)]
pub(crate) fn unregister_launch_agent(kin_root: &Path) {
    let working_dir = match kin_root.parent() {
        Some(p) => p,
        None => return,
    };
    let label = match launch_agent_label(working_dir) {
        Ok(label) => label,
        Err(error) => {
            tracing::warn!(%error, "could not derive macOS LaunchAgent identity");
            return;
        }
    };
    if let Ok(home) = std::env::var("HOME") {
        let home = PathBuf::from(home);
        let launch_agents = home.join("Library/LaunchAgents");
        let plist_path = launch_agents.join(format!("{label}.plist"));
        if plist_path.exists() {
            match unload_then_remove_launch_agent(&plist_path, || {
                launchctl_action("unload", &plist_path)
            }) {
                Ok(()) => info!(label = %label, "unregistered macOS Launch Agent"),
                Err(error) => {
                    tracing::warn!(
                        label = %label,
                        plist = %plist_path.display(),
                        %error,
                        "could not unregister macOS Launch Agent; preserving plist"
                    );
                }
            }
        }
        let canonical_working_dir = match working_dir.canonicalize() {
            Ok(path) => path,
            Err(error) => {
                tracing::warn!(
                    repository = %working_dir.display(),
                    %error,
                    "could not canonicalize repository for legacy macOS LaunchAgent removal"
                );
                return;
            }
        };
        match reconcile_legacy_launch_agent(&launch_agents, working_dir, &canonical_working_dir) {
            Ok((legacy_label, LegacyLaunchAgentDisposition::Removed)) => {
                info!(
                    label = %legacy_label,
                    "unregistered matching legacy macOS LaunchAgent"
                );
            }
            Ok((legacy_label, LegacyLaunchAgentDisposition::PreservedUnrelated)) => {
                info!(
                    label = %legacy_label,
                    "preserved same-basename legacy macOS LaunchAgent owned by another repository"
                );
            }
            Ok((_, LegacyLaunchAgentDisposition::Absent)) => {}
            Err(error) => {
                tracing::warn!(
                    repository = %canonical_working_dir.display(),
                    %error,
                    "could not safely remove legacy macOS LaunchAgent; preserving plist"
                );
            }
        }
    }
}

/// No-op on non-macOS platforms.
#[cfg(not(target_os = "macos"))]
#[allow(dead_code)]
pub(crate) fn register_launch_agent(_kin_root: &Path) -> Result<(), String> {
    Ok(()) // Linux: TODO systemd user unit
}

/// No-op on non-macOS platforms.
#[cfg(not(target_os = "macos"))]
#[allow(dead_code)]
pub(crate) fn unregister_launch_agent(_kin_root: &Path) {}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(target_os = "macos"))]
    use std::io::{Seek as _, SeekFrom, Write as _};

    #[cfg(target_os = "macos")]
    const LIFECYCLE_WORKER_MODE: &str = "KINTEST_LIFECYCLE_WORKER_MODE";
    #[cfg(target_os = "macos")]
    const LIFECYCLE_DESCENDANT_MARKER: &str = "KINTEST_LIFECYCLE_DESCENDANT_MARKER";

    #[cfg(target_os = "macos")]
    fn lifecycle_worker_command(mode: &str) -> Command {
        let mut command = Command::new(std::env::current_exe().expect("current test executable"));
        command
            .args([
                "--exact",
                "lifecycle::tests::macos_bounded_command_worker",
                "--nocapture",
            ])
            .env(LIFECYCLE_WORKER_MODE, mode);
        command
    }

    #[cfg(target_os = "macos")]
    fn publish_worker_pid_atomically(path: &Path) {
        let mut staged_name = path.as_os_str().to_os_string();
        staged_name.push(".staged");
        let staged = PathBuf::from(staged_name);
        std::fs::write(&staged, std::process::id().to_string()).expect("write staged worker pid");
        std::fs::rename(staged, path).expect("publish worker pid");
    }

    #[cfg(target_os = "macos")]
    fn wait_for_worker_pid(path: &Path) -> u32 {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(pid) = std::fs::read_to_string(path)
                .ok()
                .and_then(|contents| contents.trim().parse::<u32>().ok())
                .filter(|pid| *pid != 0)
            {
                return pid;
            }
            assert!(
                Instant::now() < deadline,
                "worker never published a parseable pid"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    #[cfg(target_os = "macos")]
    fn process_is_live(pid: u32) -> bool {
        let system = sysinfo::System::new_all();
        system
            .process(sysinfo::Pid::from_u32(pid))
            .is_some_and(|process| {
                !matches!(
                    process.status(),
                    sysinfo::ProcessStatus::Dead | sysinfo::ProcessStatus::Zombie
                )
            })
    }

    #[cfg(target_os = "macos")]
    fn wait_for_process_exit(pid: u32) {
        let deadline = Instant::now() + Duration::from_secs(5);
        while process_is_live(pid) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            !process_is_live(pid),
            "contained worker descendant {pid} survived helper return"
        );
    }

    /// Subprocess-only fixture for the bounded macOS command helper.
    ///
    /// With no mode this is a normal no-op unit test. Focused parent tests
    /// reinvoke this exact test with a mode so no real launchctl service is
    /// touched.
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_bounded_command_worker() {
        use std::io::{Read as _, Write as _};

        let Ok(mode) = std::env::var(LIFECYCLE_WORKER_MODE) else {
            return;
        };
        match mode.as_str() {
            "stdio" => {
                let mut stdin = String::new();
                std::io::stdin()
                    .read_to_string(&mut stdin)
                    .expect("read closed stdin");
                assert!(stdin.is_empty(), "bounded command stdin was not closed");
                println!("bounded stdout");
                eprintln!("bounded stderr");
            }
            "flood" => {
                std::io::stdout()
                    .write_all(&vec![b'x'; 128 * 1024])
                    .expect("write capture-limit fixture");
            }
            "descendant" => {
                let marker = PathBuf::from(
                    std::env::var_os(LIFECYCLE_DESCENDANT_MARKER).expect("descendant marker path"),
                );
                publish_worker_pid_atomically(&marker);
                std::thread::sleep(Duration::from_secs(60));
            }
            "spawn-descendant" | "spawn-descendant-and-wait" => {
                let marker = PathBuf::from(
                    std::env::var_os(LIFECYCLE_DESCENDANT_MARKER).expect("descendant marker path"),
                );
                let mut descendant = lifecycle_worker_command("descendant");
                descendant
                    .env(LIFECYCLE_DESCENDANT_MARKER, &marker)
                    .stdin(Stdio::null());
                let descendant = descendant.spawn().expect("spawn contained descendant");
                let _descendant_pid = wait_for_worker_pid(&marker);
                drop(descendant);
                if mode == "spawn-descendant-and-wait" {
                    std::thread::sleep(Duration::from_secs(60));
                }
            }
            "nonzero" => std::process::exit(23),
            "not-loaded" => {
                eprintln!("Unload failed: 3: Could not find specified service");
                std::process::exit(3);
            }
            other => panic!("unknown lifecycle worker mode {other}"),
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_bounded_command_closes_stdin_and_captures_output() {
        let command = lifecycle_worker_command("stdio");
        let output = output_macos_command_with_deadline(
            command,
            "lifecycle stdio fixture",
            Duration::from_secs(5),
            4096,
        )
        .expect("bounded command output");

        assert!(output.status.success());
        assert!(String::from_utf8_lossy(&output.stdout).contains("bounded stdout"));
        assert!(String::from_utf8_lossy(&output.stderr).contains("bounded stderr"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_bounded_command_enforces_capture_limit() {
        let command = lifecycle_worker_command("flood");
        let error = output_macos_command_with_deadline(
            command,
            "lifecycle capture fixture",
            Duration::from_secs(5),
            1024,
        )
        .expect_err("oversized capture must fail");

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert!(error.to_string().contains("1024-byte per-stream"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_bounded_command_deadline_reaps_the_complete_process_tree() {
        let root = tempfile::tempdir().expect("tempdir");
        let marker = root.path().join("descendant.pid");
        let mut command = lifecycle_worker_command("spawn-descendant-and-wait");
        command.env(LIFECYCLE_DESCENDANT_MARKER, &marker);

        let started = Instant::now();
        let error = output_macos_command_with_deadline(
            command,
            "lifecycle deadline fixture",
            Duration::from_secs(2),
            4096,
        )
        .expect_err("hung command must reach its deadline");
        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(
            started.elapsed() < Duration::from_secs(8),
            "deadline helper exceeded its bounded cleanup window"
        );

        let descendant = wait_for_worker_pid(&marker);
        wait_for_process_exit(descendant);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_bounded_command_cleans_inherited_descendant_after_direct_exit() {
        let root = tempfile::tempdir().expect("tempdir");
        let marker = root.path().join("descendant.pid");
        let mut command = lifecycle_worker_command("spawn-descendant");
        command.env(LIFECYCLE_DESCENDANT_MARKER, &marker);

        let output = output_macos_command_with_deadline(
            command,
            "lifecycle inherited-output fixture",
            Duration::from_secs(5),
            4096,
        )
        .expect("direct process should finish without inherited-output hang");
        assert!(output.status.success());

        let descendant = wait_for_worker_pid(&marker);
        wait_for_process_exit(descendant);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_bounded_command_unwind_guard_reaps_direct_child_and_descendant() {
        let root = tempfile::tempdir().expect("tempdir");
        let marker = root.path().join("descendant.pid");
        let mut command = lifecycle_worker_command("spawn-descendant-and-wait");
        command
            .env(LIFECYCLE_DESCENDANT_MARKER, &marker)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        kin_daemon_spawn::scrub_daemon_process_authority(&mut command);
        cap_command_capture_files(&mut command, 4096).expect("install capture file limit");

        let mut direct_pid = 0;
        let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let (child, containment) =
                LaunchctlContainment::spawn(command, Instant::now() + Duration::from_secs(5))
                    .expect("spawn unwind-guard fixture");
            direct_pid = child.id();
            let _running = RunningLaunchctlCommand {
                child: Some(child),
                containment,
                force_direct_reap_retention: false,
            };
            let _descendant_pid = wait_for_worker_pid(&marker);
            panic!("exercise bounded-command unwind guard");
        }));
        assert!(unwind.is_err(), "fixture must unwind through the guard");

        let descendant = wait_for_worker_pid(&marker);
        wait_for_process_exit(direct_pid);
        wait_for_process_exit(descendant);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_failed_direct_reap_retains_exact_child_and_guardian_until_reaped() {
        let root = tempfile::tempdir().expect("tempdir");
        let marker = root.path().join("descendant.pid");
        let mut command = lifecycle_worker_command("spawn-descendant-and-wait");
        command
            .env(LIFECYCLE_DESCENDANT_MARKER, &marker)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        kin_daemon_spawn::scrub_daemon_process_authority(&mut command);
        cap_command_capture_files(&mut command, 4096).expect("install capture file limit");

        let (child, containment) =
            LaunchctlContainment::spawn(command, Instant::now() + Duration::from_secs(5))
                .expect("spawn retained-cleanup fixture");
        let direct_pid = child.id();
        let descendant = wait_for_worker_pid(&marker);
        let mut running = RunningLaunchctlCommand {
            child: Some(child),
            containment,
            force_direct_reap_retention: true,
        };

        RETAINED_LAUNCHCTL_DIRECT_REAP_COMPLETED_PID.store(0, std::sync::atomic::Ordering::SeqCst);
        let error = running
            .cleanup("forced retained launchctl cleanup")
            .expect_err("forced foreground reap miss must report retained cleanup");
        assert!(
            error.to_string().contains("retention=ok"),
            "cleanup must report a durable retained owner: {error}"
        );
        assert!(
            running.child.is_none() && running.containment.guardian.is_none(),
            "exact child and guardian must move together into retained ownership"
        );

        let reaped_deadline = Instant::now() + Duration::from_secs(5);
        while RETAINED_LAUNCHCTL_DIRECT_REAP_COMPLETED_PID.load(std::sync::atomic::Ordering::SeqCst)
            != direct_pid
            && Instant::now() < reaped_deadline
        {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(
            RETAINED_LAUNCHCTL_DIRECT_REAP_COMPLETED_PID.load(std::sync::atomic::Ordering::SeqCst)
                == direct_pid,
            "retained owner never collected the exact direct-child status"
        );
        wait_for_process_exit(direct_pid);
        wait_for_process_exit(descendant);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn launchctl_nonzero_status_prevents_plist_deletion() {
        let root = tempfile::tempdir().expect("tempdir");
        let plist_path = root.path().join("agent.plist");
        std::fs::write(&plist_path, "fixture").expect("write plist fixture");
        let command = lifecycle_worker_command("nonzero");
        let output = output_macos_command_with_deadline(
            command,
            "launchctl status fixture",
            Duration::from_secs(5),
            4096,
        )
        .expect("capture nonzero launchctl fixture");
        let status_error = require_launchctl_success("unload", "launchctl unload", output)
            .expect_err("nonzero launchctl status must fail");
        assert!(matches!(status_error, LaunchctlActionError::Failed(_)));

        let error = unload_then_remove_launch_agent(&plist_path, || Err(status_error))
            .expect_err("unload failure must prevent plist deletion");
        assert!(error.contains("status"));
        assert!(
            plist_path.exists(),
            "plist must remain when launchctl unload fails"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn launchctl_not_loaded_status_allows_stale_plist_repair() {
        let root = tempfile::tempdir().expect("tempdir");
        let plist_path = root.path().join("agent.plist");
        std::fs::write(&plist_path, "fixture").expect("write plist fixture");
        let command = lifecycle_worker_command("not-loaded");
        let output = output_macos_command_with_deadline(
            command,
            "launchctl not-loaded fixture",
            Duration::from_secs(5),
            4096,
        )
        .expect("capture not-loaded launchctl fixture");
        let status_error = require_launchctl_success("unload", "launchctl unload", output)
            .expect_err("not-loaded launchctl status remains a typed outcome");
        assert!(matches!(status_error, LaunchctlActionError::NotLoaded(_)));

        unload_then_remove_launch_agent(&plist_path, || Err(status_error))
            .expect("an already-unloaded plist is repairable");
        assert!(!plist_path.exists());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn launch_agent_identity_uses_canonical_root_not_basename() {
        let root = tempfile::tempdir().expect("tempdir");
        let first = root.path().join("clients").join("app");
        let second = root.path().join("internal").join("app");
        std::fs::create_dir_all(&first).expect("first repo root");
        std::fs::create_dir_all(&second).expect("second repo root");

        let first_label = launch_agent_label(&first).expect("first launch label");
        let second_label = launch_agent_label(&second).expect("second launch label");
        assert_ne!(first_label, second_label);
        assert!(first_label.ends_with(".app"));
        assert!(second_label.ends_with(".app"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn relative_explicit_daemon_binary_is_canonical_and_must_be_executable() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = tempfile::tempdir().expect("tempdir");
        let relative = Path::new("target/debug/kin-daemon");
        let binary = root.path().join(relative);
        std::fs::create_dir_all(binary.parent().unwrap()).expect("binary parent");
        std::fs::write(&binary, b"#!/bin/sh\nprintf 'not-compatible-json'\n")
            .expect("binary fixture");
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o700))
            .expect("executable permissions");

        let resolved = resolve_launch_agent_daemon_binary(relative, root.path())
            .expect("resolve relative explicit daemon");
        assert!(resolved.is_absolute());
        assert_eq!(resolved, binary.canonicalize().unwrap());
        let compat_error = validate_launch_agent_daemon_binary(&resolved)
            .expect_err("invalid compat payload must reject activation");
        assert!(compat_error.contains("incompatible"), "{compat_error}");

        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o600))
            .expect("non-executable permissions");
        let error = resolve_launch_agent_daemon_binary(relative, root.path())
            .expect_err("non-executable daemon must fail closed");
        assert!(error.contains("regular executable"), "{error}");

        let directory = root.path().join("daemon-directory");
        std::fs::create_dir(&directory).expect("directory fixture");
        let error = resolve_launch_agent_daemon_binary(&directory, root.path())
            .expect_err("directory daemon selection must fail closed");
        assert!(error.contains("regular executable"), "{error}");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn legacy_upgrade_removes_only_a_matching_repository_agent() {
        let root = tempfile::tempdir().expect("tempdir");
        let repository = root.path().join("clients").join("app");
        let launch_agents = root.path().join("LaunchAgents");
        std::fs::create_dir_all(&repository).expect("repository");
        std::fs::create_dir_all(&launch_agents).expect("LaunchAgents");
        let canonical = repository.canonicalize().expect("canonical repository");
        let legacy_label = legacy_launch_agent_label(&repository);
        let legacy_plist = launch_agents.join(format!("{legacy_label}.plist"));
        std::fs::write(&legacy_plist, "legacy fixture").expect("legacy plist");
        let unloaded = std::cell::Cell::new(false);

        let disposition = remove_legacy_launch_agent_if_matching(
            &legacy_plist,
            &canonical,
            |_| {
                Ok(vec![
                    "/usr/local/bin/kin-daemon".to_string(),
                    "--repo".to_string(),
                    repository.to_string_lossy().into_owned(),
                    "--port".to_string(),
                    "4219".to_string(),
                ])
            },
            || {
                unloaded.set(true);
                Ok(())
            },
        )
        .expect("migrate matching legacy agent");

        assert_eq!(disposition, LegacyLaunchAgentDisposition::Removed);
        assert!(unloaded.get(), "matching legacy job must be unloaded");
        assert!(
            !legacy_plist.exists(),
            "matching legacy plist must be removed"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn legacy_preflight_failure_cannot_activate_replacement() {
        let replacement_loaded = std::cell::Cell::new(false);
        let commit_ran = std::cell::Cell::new(false);

        let error = install_replacement_after_legacy_preflight(
            || Err("relative legacy --repo is unverifiable".to_string()),
            || {
                replacement_loaded.set(true);
                Ok(())
            },
            |_| {
                commit_ran.set(true);
                Ok(LegacyLaunchAgentDisposition::Removed)
            },
            |_: ()| panic!("nothing was installed, so rollback must not run"),
        )
        .expect_err("preflight error must stop before digest activation");

        assert!(error.contains("unverifiable"));
        assert!(!replacement_loaded.get());
        assert!(!commit_ran.get());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn replacement_load_failure_cannot_start_legacy_cleanup() {
        let commit_ran = std::cell::Cell::new(false);

        let error = install_replacement_after_legacy_preflight(
            || Ok(LegacyLaunchAgentInspection::Matching),
            || Err("replacement load failed".to_string()),
            |_| {
                commit_ran.set(true);
                Ok(LegacyLaunchAgentDisposition::Removed)
            },
            |_: ()| panic!("a failed install never reached replacement rollback authority"),
        )
        .expect_err("replacement load failure must stop legacy cleanup");

        assert!(error.contains("replacement load failed"));
        assert!(
            !commit_ran.get(),
            "legacy cleanup must not begin before replacement activation succeeds"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn failed_digest_load_removes_stage_and_restores_prior_job() {
        let root = tempfile::tempdir().expect("tempdir");
        let plist_path = root.path().join("digest.plist");
        std::fs::write(&plist_path, b"prior plist").expect("prior plist");
        let prior_loaded = std::cell::Cell::new(true);
        let cleanup_ran = std::cell::Cell::new(false);

        let error = LoadedDigestLaunchAgent::install_with_actions(
            &plist_path,
            b"replacement plist",
            |_| {
                prior_loaded.set(false);
                Ok(())
            },
            |stage| {
                assert_eq!(
                    stage.extension().and_then(|value| value.to_str()),
                    Some("tmp")
                );
                Err(LaunchctlActionError::Failed(
                    "replacement load failed".to_string(),
                ))
            },
            |stage| {
                cleanup_ran.set(true);
                std::fs::remove_file(stage).map_err(|error| error.to_string())
            },
            |prior| {
                assert_eq!(std::fs::read(prior).expect("prior bytes"), b"prior plist");
                prior_loaded.set(true);
                Ok(())
            },
        )
        .expect_err("failed replacement load must roll back staged state");

        assert!(error.contains("replacement load failed"));
        assert!(cleanup_ran.get());
        assert!(prior_loaded.get());
        assert_eq!(std::fs::read(&plist_path).unwrap(), b"prior plist");
        assert_eq!(
            std::fs::read_dir(root.path())
                .expect("temporary directory")
                .filter_map(Result::ok)
                .filter(|entry| entry.path().extension().is_some_and(|value| value == "tmp"))
                .count(),
            0,
            "a failed load must not leave a future-login plist artifact"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn oversized_prior_digest_plist_fails_before_launchctl_or_allocation_growth() {
        let root = tempfile::tempdir().expect("tempdir");
        let plist_path = root.path().join("digest.plist");
        std::fs::write(
            &plist_path,
            vec![b'x'; LAUNCHCTL_CAPTURE_LIMIT as usize + 1],
        )
        .expect("oversized prior plist");

        let error = LoadedDigestLaunchAgent::install_with_actions(
            &plist_path,
            b"replacement plist",
            |_| panic!("oversized prior must fail before unload"),
            |_| panic!("oversized prior must fail before replacement load"),
            |_| panic!("oversized prior must fail before loaded-stage cleanup"),
            |_| panic!("oversized prior must fail before prior-job restore"),
        )
        .expect_err("oversized prior plist must fail closed");

        assert!(error.contains("retention limit"), "{error}");
        assert_eq!(
            std::fs::metadata(&plist_path).unwrap().len(),
            LAUNCHCTL_CAPTURE_LIMIT + 1
        );
        assert_eq!(
            std::fs::read_dir(root.path())
                .expect("temporary directory")
                .filter_map(Result::ok)
                .filter(|entry| entry.path().extension().is_some_and(|value| value == "tmp"))
                .count(),
            0,
            "failed bounded retention must remove the unpublished stage"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn prior_digest_reader_rejects_symlink_and_fifo_without_blocking() {
        use std::os::unix::ffi::OsStrExt as _;

        let root = tempfile::tempdir().expect("tempdir");
        let target = root.path().join("target.plist");
        let symlink = root.path().join("symlink.plist");
        std::fs::write(&target, b"target").expect("target plist");
        std::os::unix::fs::symlink(&target, &symlink).expect("symlink plist");
        let symlink_error =
            read_bounded_launch_agent_plist(&symlink).expect_err("symlink must fail closed");
        assert!(symlink_error.contains("open existing"), "{symlink_error}");

        let fifo = root.path().join("fifo.plist");
        let fifo_c = std::ffi::CString::new(fifo.as_os_str().as_bytes()).expect("FIFO path");
        assert_eq!(unsafe { libc::mkfifo(fifo_c.as_ptr(), 0o600) }, 0);
        let started = Instant::now();
        let fifo_error = read_bounded_launch_agent_plist(&fifo).expect_err("FIFO must fail closed");
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "nonblocking FIFO rejection exceeded its wall-clock bound"
        );
        assert!(fifo_error.contains("regular file"), "{fifo_error}");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn digest_rollback_restores_prior_bytes_and_loaded_state() {
        let root = tempfile::tempdir().expect("tempdir");
        let plist_path = root.path().join("digest.plist");
        std::fs::write(&plist_path, b"prior plist").expect("prior plist");
        let prior_loaded = std::cell::Cell::new(true);
        let replacement_loaded = std::cell::Cell::new(false);

        let replacement = LoadedDigestLaunchAgent::install_with_actions(
            &plist_path,
            b"replacement plist",
            |_| {
                prior_loaded.set(false);
                Ok(())
            },
            |_| {
                replacement_loaded.set(true);
                Ok(())
            },
            |_| panic!("successful load must not invoke failed-stage cleanup"),
            |_| panic!("successful load must not immediately restore prior job"),
        )
        .expect("install replacement");
        assert_eq!(std::fs::read(&plist_path).unwrap(), b"replacement plist");

        replacement
            .rollback_with_actions(
                |_| {
                    replacement_loaded.set(false);
                    Ok(())
                },
                |_| {
                    prior_loaded.set(true);
                    Ok(())
                },
            )
            .expect("rollback digest replacement");

        assert!(!replacement_loaded.get());
        assert!(prior_loaded.get());
        assert_eq!(std::fs::read(&plist_path).unwrap(), b"prior plist");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn legacy_unload_failure_rolls_back_loaded_replacement() {
        let root = tempfile::tempdir().expect("tempdir");
        let repository = root.path().join("app");
        std::fs::create_dir_all(&repository).expect("repository");
        let canonical = repository.canonicalize().expect("canonical repository");
        let legacy_plist = root.path().join("legacy.plist");
        std::fs::write(&legacy_plist, "legacy fixture").expect("legacy plist");
        let replacement_loaded = std::cell::Cell::new(false);

        let error = install_replacement_after_legacy_preflight(
            || Ok(LegacyLaunchAgentInspection::Matching),
            || {
                replacement_loaded.set(true);
                Ok(())
            },
            |preflight| {
                commit_legacy_launch_agent_migration(
                    preflight,
                    &legacy_plist,
                    &canonical,
                    |_| {
                        Ok(vec![
                            "kin-daemon".to_string(),
                            "--repo".to_string(),
                            repository.to_string_lossy().into_owned(),
                        ])
                    },
                    || {
                        Err(LaunchctlActionError::Failed(
                            "legacy unload failed".to_string(),
                        ))
                    },
                    || panic!("failed unload must preserve the legacy plist"),
                    || panic!("failed unload must not require legacy restoration"),
                )
            },
            |_| {
                replacement_loaded.set(false);
                Ok(())
            },
        )
        .expect_err("legacy unload failure must abort migration");

        assert!(error.contains("legacy unload failed"));
        assert!(error.contains("rolled back"));
        assert!(!replacement_loaded.get());
        assert!(
            legacy_plist.exists(),
            "failed legacy unload must preserve the prior plist"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn post_unload_remove_failure_keeps_replacement_when_legacy_restore_fails() {
        let root = tempfile::tempdir().expect("tempdir");
        let repository = root.path().join("app");
        std::fs::create_dir_all(&repository).expect("repository");
        let canonical = repository.canonicalize().expect("canonical repository");
        let legacy_plist = root.path().join("legacy.plist");
        std::fs::write(&legacy_plist, "legacy fixture").expect("legacy plist");
        let replacement_loaded = std::cell::Cell::new(false);
        let legacy_loaded = std::cell::Cell::new(true);
        let rollback_ran = std::cell::Cell::new(false);

        let error = install_replacement_after_legacy_preflight(
            || Ok(LegacyLaunchAgentInspection::Matching),
            || {
                replacement_loaded.set(true);
                Ok(())
            },
            |preflight| {
                commit_legacy_launch_agent_migration(
                    preflight,
                    &legacy_plist,
                    &canonical,
                    |_| {
                        Ok(vec![
                            "kin-daemon".to_string(),
                            "--repo".to_string(),
                            repository.to_string_lossy().into_owned(),
                        ])
                    },
                    || {
                        legacy_loaded.set(false);
                        Ok(())
                    },
                    || Err("legacy plist removal failed".to_string()),
                    || {
                        Err(LaunchctlActionError::Failed(
                            "legacy restore failed".to_string(),
                        ))
                    },
                )
            },
            |_| {
                rollback_ran.set(true);
                replacement_loaded.set(false);
                Ok(())
            },
        )
        .expect_err("failed legacy restore must leave replacement as authority");

        assert!(error.contains("replacement remains active"));
        assert!(replacement_loaded.get());
        assert!(!legacy_loaded.get());
        assert!(!rollback_ran.get());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn absent_to_matching_legacy_race_is_revalidated_and_cleaned() {
        let root = tempfile::tempdir().expect("tempdir");
        let repository = root.path().join("app");
        std::fs::create_dir_all(&repository).expect("repository");
        let canonical = repository.canonicalize().expect("canonical repository");
        let legacy_plist = root.path().join("legacy.plist");
        let legacy_loaded = std::cell::Cell::new(false);

        let disposition = install_replacement_after_legacy_preflight(
            || Ok(LegacyLaunchAgentInspection::Absent),
            || {
                std::fs::write(&legacy_plist, "raced legacy fixture").expect("legacy plist");
                legacy_loaded.set(true);
                Ok(())
            },
            |preflight| {
                commit_legacy_launch_agent_migration(
                    preflight,
                    &legacy_plist,
                    &canonical,
                    |_| {
                        Ok(vec![
                            "kin-daemon".to_string(),
                            "--repo".to_string(),
                            repository.to_string_lossy().into_owned(),
                        ])
                    },
                    || {
                        legacy_loaded.set(false);
                        Ok(())
                    },
                    || std::fs::remove_file(&legacy_plist).map_err(|error| error.to_string()),
                    || panic!("successful removal does not restore legacy"),
                )
            },
            |_: ()| panic!("successful post-load cleanup must not roll back replacement"),
        )
        .expect("current matching ownership should authorize guarded cleanup");

        assert_eq!(disposition, LegacyLaunchAgentDisposition::Removed);
        assert!(!legacy_loaded.get());
        assert!(!legacy_plist.exists());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn matching_to_unrelated_legacy_change_is_preserved_without_mutation() {
        let root = tempfile::tempdir().expect("tempdir");
        let target = root.path().join("target").join("app");
        let unrelated = root.path().join("unrelated").join("app");
        std::fs::create_dir_all(&target).expect("target repository");
        std::fs::create_dir_all(&unrelated).expect("unrelated repository");
        let canonical = target.canonicalize().expect("canonical target");
        let legacy_plist = root.path().join("legacy.plist");
        std::fs::write(&legacy_plist, "unrelated fixture").expect("legacy plist");
        let replacement_loaded = std::cell::Cell::new(false);

        let disposition = install_replacement_after_legacy_preflight(
            || Ok(LegacyLaunchAgentInspection::Matching),
            || {
                replacement_loaded.set(true);
                Ok(())
            },
            |preflight| {
                commit_legacy_launch_agent_migration(
                    preflight,
                    &legacy_plist,
                    &canonical,
                    |_| {
                        Ok(vec![
                            "kin-daemon".to_string(),
                            "--repo".to_string(),
                            unrelated.to_string_lossy().into_owned(),
                        ])
                    },
                    || panic!("unrelated legacy job must never be unloaded"),
                    || panic!("unrelated legacy plist must never be removed"),
                    || panic!("unrelated legacy job must never need restoration"),
                )
            },
            |_: ()| panic!("unrelated legacy authority must not roll back target replacement"),
        )
        .expect("current unrelated ownership must be preserved");

        assert_eq!(
            disposition,
            LegacyLaunchAgentDisposition::PreservedUnrelated
        );
        assert!(replacement_loaded.get());
        assert!(legacy_plist.exists());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn legacy_unregister_removes_a_matching_already_unloaded_agent() {
        let root = tempfile::tempdir().expect("tempdir");
        let repository = root.path().join("app");
        std::fs::create_dir_all(&repository).expect("repository");
        let canonical = repository.canonicalize().expect("canonical repository");
        let legacy_plist = root.path().join("legacy.plist");
        std::fs::write(&legacy_plist, "legacy fixture").expect("legacy plist");

        let disposition = remove_legacy_launch_agent_if_matching(
            &legacy_plist,
            &canonical,
            |_| {
                Ok(vec![
                    "kin-daemon".to_string(),
                    "--repo".to_string(),
                    repository.to_string_lossy().into_owned(),
                ])
            },
            || {
                Err(LaunchctlActionError::NotLoaded(
                    "service is not loaded".to_string(),
                ))
            },
        )
        .expect("remove matching unloaded legacy agent");

        assert_eq!(disposition, LegacyLaunchAgentDisposition::Removed);
        assert!(
            !legacy_plist.exists(),
            "matching stale plist must be removed"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn legacy_same_basename_collision_preserves_the_unrelated_agent() {
        let root = tempfile::tempdir().expect("tempdir");
        let first = root.path().join("clients").join("app");
        let second = root.path().join("internal").join("app");
        std::fs::create_dir_all(&first).expect("first repository");
        std::fs::create_dir_all(&second).expect("second repository");
        assert_eq!(
            legacy_launch_agent_label(&first),
            legacy_launch_agent_label(&second)
        );
        let second_canonical = second.canonicalize().expect("second canonical repository");
        let legacy_plist = root.path().join("same-basename.plist");
        std::fs::write(&legacy_plist, "legacy fixture").expect("legacy plist");

        let disposition = remove_legacy_launch_agent_if_matching(
            &legacy_plist,
            &second_canonical,
            |_| {
                Ok(vec![
                    "kin-daemon".to_string(),
                    "--repo".to_string(),
                    first.to_string_lossy().into_owned(),
                ])
            },
            || panic!("an unrelated legacy agent must never be unloaded"),
        )
        .expect("classify unrelated legacy agent");

        assert_eq!(
            disposition,
            LegacyLaunchAgentDisposition::PreservedUnrelated
        );
        assert!(
            legacy_plist.exists(),
            "unrelated same-basename legacy plist must remain"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn malformed_legacy_program_arguments_fail_closed() {
        let root = tempfile::tempdir().expect("tempdir");
        let repository = root.path().join("app");
        std::fs::create_dir_all(&repository).expect("repository");
        let canonical = repository.canonicalize().expect("canonical repository");
        let legacy_plist = root.path().join("malformed.plist");
        std::fs::write(&legacy_plist, "legacy fixture").expect("legacy plist");

        let error = remove_legacy_launch_agent_if_matching(
            &legacy_plist,
            &canonical,
            |_| Ok(vec!["kin-daemon".to_string()]),
            || panic!("an unverifiable legacy agent must never be unloaded"),
        )
        .expect_err("missing --repo must fail closed");

        assert!(error.contains("exactly one --repo"), "{error}");
        assert!(legacy_plist.exists(), "unverifiable plist must remain");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn relative_legacy_repository_argument_fails_closed() {
        let root = tempfile::tempdir().expect("tempdir");
        let repository = root.path().join("app");
        std::fs::create_dir_all(&repository).expect("repository");
        let canonical = repository.canonicalize().expect("canonical repository");
        let legacy_plist = root.path().join("relative.plist");
        std::fs::write(&legacy_plist, "legacy fixture").expect("legacy plist");

        let error = remove_legacy_launch_agent_if_matching(
            &legacy_plist,
            &canonical,
            |_| {
                Ok(vec![
                    "kin-daemon".to_string(),
                    "--repo".to_string(),
                    ".".to_string(),
                ])
            },
            || panic!("a relative legacy authority must never be unloaded"),
        )
        .expect_err("relative --repo must not inherit the registering process CWD");

        assert!(error.contains("must be absolute"), "{error}");
        assert!(
            legacy_plist.exists(),
            "unverifiable relative legacy plist must remain"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn a_launch_agent_lets_the_daemon_choose_its_own_port() {
        // The plist used to carry a number: the port a daemon happened to be
        // serving, one probed with a listener and immediately released, or 4219.
        // launchd runs this argument vector at boot, long after any of those
        // facts was true, and `KeepAlive` turns a bind conflict into a restart
        // loop. Zero is the same request every other start path makes.
        let plist = render_launch_agent_plist(
            "ai.firelock.kin-daemon.digest.repo",
            "/usr/local/bin/kin-daemon",
            "/repos/app",
        )
        .expect("render the launch agent plist");

        let dir = tempfile::tempdir().expect("tempdir");
        let plist_path = dir.path().join("agent.plist");
        std::fs::write(&plist_path, &plist).expect("write plist");
        let arguments =
            read_plist_program_arguments(&plist_path).expect("extract ProgramArguments");

        assert_eq!(
            arguments,
            vec![
                "/usr/local/bin/kin-daemon",
                "--repo",
                "/repos/app",
                "--port",
                kin_daemon_spawn::DAEMON_PORT_ARGUMENT,
            ],
            "launchd must ask the daemon to bind and report a port, not name one"
        );
        assert!(
            !plist.contains("4219"),
            "no hardcoded fallback port may survive in the plist: {plist}"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn plutil_reads_legacy_program_arguments_for_guarded_migration() {
        let root = tempfile::tempdir().expect("tempdir");
        let repository = root.path().join("app\ttab\nline\rreturn");
        std::fs::create_dir_all(&repository).expect("repository");
        let repository_text = plist_xml_text(
            repository
                .to_str()
                .expect("temporary repository path must be UTF-8"),
        )
        .expect("encode repository path");
        let plist_path = root.path().join("legacy.plist");
        let plist = format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>ai.firelock.kin-daemon.app</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/kin-daemon</string>
        <string>--repo</string>
        <string>{repository_text}</string>
        <string>--port</string>
        <string>4219</string>
    </array>
</dict>
</plist>"#
        );
        std::fs::write(&plist_path, plist).expect("legacy plist");

        let arguments =
            read_plist_program_arguments(&plist_path).expect("extract ProgramArguments");
        assert_eq!(
            arguments,
            vec![
                "/usr/local/bin/kin-daemon",
                "--repo",
                repository.to_str().expect("UTF-8 repository"),
                "--port",
                "4219",
            ]
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn plist_text_escapes_every_xml_metacharacter() {
        assert_eq!(
            plist_xml_text("a&b<c>d\"e'f").expect("escape valid XML text"),
            "a&amp;b&lt;c&gt;d&quot;e&apos;f"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn plist_text_encodes_xml_whitespace_controls_for_exact_round_trip() {
        assert_eq!(
            plist_xml_text("tab\tline\nreturn\rend").expect("encode XML 1.0 whitespace controls"),
            "tab&#x9;line&#xA;return&#xD;end"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn plist_text_rejects_xml_1_0_illegal_control_characters() {
        let error = plist_xml_text("repo\u{1}name")
            .expect_err("XML 1.0-illegal control character must fail closed");
        assert!(error.contains("U+0001"), "{error}");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn launch_agent_identity_rejects_non_utf8_repository_paths() {
        use std::os::unix::ffi::OsStringExt as _;

        let invalid = PathBuf::from(std::ffi::OsString::from_vec(vec![
            b'r', b'e', b'p', b'o', 0xff,
        ]));
        let error = launch_agent_path_text(&invalid, "repository root")
            .expect_err("non-UTF-8 root must fail closed");
        assert!(error.contains("cannot be represented as UTF-8"), "{error}");
    }

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

    #[test]
    fn mcp_idle_timeout_constant_is_1800() {
        // Regression guard: the MCP path must inject 1800s (30 min), not the
        // 60-second CLI default.
        assert_eq!(MCP_IDLE_TIMEOUT_SECS, "1800");
    }

    #[test]
    fn delegated_startup_error_contract_is_shared_by_type() {
        fn accepts_public_error(error: kin_cli::daemon_client::AutoStartError) -> AutoStartError {
            error
        }

        assert!(matches!(
            accepts_public_error(AutoStartError::BinaryNotFound),
            AutoStartError::BinaryNotFound
        ));
        assert!(matches!(
            accepts_public_error(AutoStartError::InvalidLayout("no parent".to_string())),
            AutoStartError::InvalidLayout(detail) if detail == "no parent"
        ));
        assert!(matches!(
            accepts_public_error(AutoStartError::StartupTimeout(
                "connection refused".to_string()
            )),
            AutoStartError::StartupTimeout(detail) if detail == "connection refused"
        ));
        assert!(matches!(
            accepts_public_error(AutoStartError::SpawnFailed(
                "permission denied".to_string()
            )),
            AutoStartError::SpawnFailed(detail) if detail == "permission denied"
        ));
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

    // ── Endpoint ownership ────────────────────────────────────────────────
    //
    // The failure these close: a daemon that lost the singleton lock deleted
    // the incumbent's endpoint files on its way out, and the incumbent — which
    // keyed its own liveness on those files existing — shut itself down. Every
    // destructive endpoint decision now needs proof of ownership, and the proof
    // is a process incarnation rather than a reusable PID.

    /// Rewrite a serialized identity's birth token so it names a different
    /// incarnation of the same live PID: exactly the shape PID reuse produces.
    fn forge_other_incarnation(encoded: &str) -> String {
        let forged = encoded
            .replace("start-time:", "start-time:9")
            .replace("start-ticks:", "start-ticks:9")
            .replace("created-100ns:", "created-100ns:9");
        assert_ne!(forged, encoded, "the birth token must have been altered");
        forged
    }

    #[test]
    fn publication_attributes_the_endpoint_to_its_publisher() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        publish_daemon_endpoint(root, 51234).expect("publish endpoint");

        assert_eq!(endpoint_ownership(root), EndpointOwnership::CurrentProcess);
        assert!(
            root.join(ENDPOINT_OWNER_FILE).exists(),
            "publication must record who published"
        );
        let record = read_endpoint_owner_record(root).expect("owner record parses");
        assert_eq!(record.identity().pid(), std::process::id());
    }

    #[test]
    fn a_recycled_pid_cannot_claim_a_published_endpoint() {
        // The endpoint names this live PID, but a different incarnation of it.
        // A bare-PID comparison would authorize this process to delete files it
        // never published.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        publish_daemon_endpoint(root, 51234).expect("publish endpoint");

        let record = std::fs::read_to_string(root.join(ENDPOINT_OWNER_FILE)).unwrap();
        std::fs::write(
            root.join(ENDPOINT_OWNER_FILE),
            forge_other_incarnation(&record),
        )
        .unwrap();

        assert_eq!(
            endpoint_ownership(root),
            EndpointOwnership::OtherProcess {
                pid: std::process::id(),
                live: false,
            },
            "an incarnation that is gone does not own this endpoint, whatever its PID resolves to"
        );

        remove_daemon_files_if_current_process(root);
        assert!(
            root.join("daemon.pid").exists() && root.join("daemon.port").exists(),
            "an endpoint this process cannot prove it published must survive"
        );
    }

    #[test]
    fn retirement_clears_the_owner_record_with_the_endpoint() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        publish_daemon_endpoint(root, 51234).expect("publish endpoint");

        remove_daemon_files_if_current_process(root);

        assert!(!root.join("daemon.pid").exists());
        assert!(!root.join("daemon.port").exists());
        assert!(
            !root.join(ENDPOINT_OWNER_FILE).exists(),
            "a retired endpoint must leave no attribution behind for the next reader"
        );
        assert_eq!(endpoint_ownership(root), EndpointOwnership::Absent);
    }

    #[test]
    fn a_legacy_endpoint_without_an_owner_record_is_still_attributed() {
        // A repo whose endpoint was published by an older daemon has no
        // sidecar. Refusing to read the bare PID would make every such endpoint
        // permanently unremovable, including by the daemon that owns it.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        std::fs::write(root.join("daemon.pid"), std::process::id().to_string()).unwrap();
        assert_eq!(endpoint_ownership(root), EndpointOwnership::CurrentProcess);

        std::fs::write(root.join("daemon.pid"), "1").unwrap();
        assert_eq!(
            endpoint_ownership(root),
            EndpointOwnership::OtherProcess { pid: 1, live: true }
        );

        std::fs::write(root.join("daemon.pid"), "not-a-pid").unwrap();
        assert_eq!(endpoint_ownership(root), EndpointOwnership::Unattributed);
    }

    /// A pid the OS has finished with, obtained by starting a process and
    /// waiting on it rather than by picking a number and hoping.
    fn a_pid_that_is_gone() -> u32 {
        let mut child = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg("exit 0")
            .spawn()
            .expect("spawn a process to outlive");
        let pid = child.id();
        child.wait().expect("wait for it to exit");
        pid
    }

    /// A daemon SIGKILLed by the supervisor's reaper retires nothing of its own:
    /// endpoint retirement runs after the shutdown select returns and a killed
    /// process never gets there. `kin doctor` then read STALE with the record
    /// still on disk, which is a reading that does not match reality — the
    /// endpoint names a live owner that is dead. The killer knows it is dead, so
    /// the killer clears it.
    #[test]
    fn the_endpoint_of_a_daemon_proved_dead_is_retired_by_whoever_killed_it() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let dead = a_pid_that_is_gone();

        std::fs::write(root.join("daemon.pid"), dead.to_string()).unwrap();
        std::fs::write(root.join("daemon.port"), "39603").unwrap();
        assert_eq!(
            endpoint_ownership(root),
            EndpointOwnership::OtherProcess {
                pid: dead,
                live: false
            }
        );

        assert!(retire_endpoint_of_dead_owner(root, dead));
        assert_eq!(
            endpoint_ownership(root),
            EndpointOwnership::Absent,
            "doctor must read the same absence the killer created"
        );
        assert!(!root.join("daemon.port").exists());
    }

    /// The retirement is proof-gated in both directions it can be wrong: a
    /// record naming a live daemon, and a record naming a successor rather than
    /// the pid that was killed. Either would strand a working repository.
    #[test]
    fn retiring_a_dead_owners_endpoint_refuses_a_live_owner_or_a_successor() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        // pid 1 is always alive.
        std::fs::write(root.join("daemon.pid"), "1").unwrap();
        std::fs::write(root.join("daemon.port"), "39603").unwrap();
        assert!(
            !retire_endpoint_of_dead_owner(root, 1),
            "a live owner's endpoint is never destroyed"
        );
        assert!(root.join("daemon.pid").exists());

        // A successor republished under a different pid: the killed daemon's
        // number no longer owns this endpoint and clearing it would strand the
        // daemon that does.
        let dead = a_pid_that_is_gone();
        assert!(
            !retire_endpoint_of_dead_owner(root, dead),
            "an endpoint naming somebody else is left where it is"
        );
        assert!(root.join("daemon.pid").exists());
    }

    #[test]
    fn a_stray_owner_record_alone_publishes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        publish_daemon_endpoint(root, 51234).expect("publish endpoint");
        std::fs::remove_file(root.join("daemon.pid")).unwrap();

        assert_eq!(
            endpoint_ownership(root),
            EndpointOwnership::Absent,
            "daemon.pid is what makes an endpoint published; attribution alone is not one"
        );
    }

    #[test]
    fn publication_refuses_an_unbound_port() {
        // `--port 0` means "the OS will pick one". Publishing it strands every
        // reader on an endpoint nothing can dial while the publisher keeps
        // owning the repo and refusing successors.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();

        let error = publish_daemon_endpoint(root, 0).expect_err("zero is not an endpoint");
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
        assert_eq!(endpoint_ownership(root), EndpointOwnership::Absent);
        assert!(!root.join("daemon.port").exists());
    }

    #[test]
    fn a_zero_port_record_reads_as_unpublished() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("daemon.port"), "0").unwrap();
        assert_eq!(read_port_file(dir.path()), None);
        assert!(daemon_is_up(dir.path()).is_none());
    }

    #[cfg(unix)]
    #[test]
    fn publication_refuses_to_replace_a_proven_live_owners_endpoint() {
        // A real other process, so the record names an incarnation that really
        // is running rather than a PID that might mean anything.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let mut incumbent = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn a stand-in incumbent");
        let identity = kin_cli::daemon_client::process_identity(incumbent.id())
            .expect("read the incumbent's identity")
            .expect("the incumbent is running");

        std::fs::write(root.join("daemon.pid"), incumbent.id().to_string()).unwrap();
        std::fs::write(root.join("daemon.port"), "51234").unwrap();
        std::fs::write(
            root.join(ENDPOINT_OWNER_FILE),
            serde_json::to_string(&EndpointOwnerRecord::for_identity(identity)).unwrap(),
        )
        .unwrap();

        let error =
            publish_daemon_endpoint(root, 4219).expect_err("a live owner's endpoint is not ours");
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(
            std::fs::read_to_string(root.join("daemon.pid")).unwrap(),
            incumbent.id().to_string()
        );
        assert_eq!(
            std::fs::read_to_string(root.join("daemon.port")).unwrap(),
            "51234"
        );

        let _ = incumbent.kill();
        let _ = incumbent.wait();
    }

    #[cfg(unix)]
    #[test]
    fn an_unreadable_owner_probe_is_not_proof_of_a_live_owner() {
        // The wedge this closes. A daemon is SIGKILLed, so its endpoint and
        // owner record survive. The kernel later hands its PID to a process
        // owned by another user, where every identity probe returns
        // PermissionDenied rather than an answer. Treating that as proof of a
        // live owner refused publication, and publication refusal is fatal at
        // startup, so the repo's daemon could never start again: no sweep
        // clears the record either, because they all preserve what they cannot
        // inspect. Only a human deleting the file recovered it.
        //
        // Both the record's owner and the probe are supplied by the test. An
        // earlier version seeded the record from pid 1 and fell back to this
        // process's own identity when that could not be read, which made the
        // outcome depend on whether the host lets you inspect pid 1: on macOS
        // it passed through the owner-is-self shortcut without touching the
        // indeterminate path at all, and on Linux pid 1 was readable, so
        // publication saw a genuinely live owner and correctly refused.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let mut foreign = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn a stand-in foreign owner");
        let identity = kin_cli::daemon_client::process_identity(foreign.id())
            .expect("read the foreign owner's identity")
            .expect("the foreign owner is running");
        publish_foreign_endpoint_for_test(root, identity, 51234);

        let unreadable = |_: &kin_cli::daemon_client::ProcessIdentity| {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "cannot read birth identity for a foreign process",
            ))
        };
        assert_eq!(
            proven_live_other_endpoint_owner_with_probe(root, unreadable),
            None,
            "an unreadable probe is not proof, so it must not block publication"
        );

        publish_daemon_endpoint_with_probe(root, 4219, unreadable)
            .expect("the rightful owner must still be able to advertise itself");
        assert_eq!(endpoint_ownership(root), EndpointOwnership::CurrentProcess);
        assert_eq!(read_port_file(root), Some(4219));

        let _ = foreign.kill();
        let _ = foreign.wait();
    }

    #[cfg(unix)]
    #[test]
    fn an_unreadable_owner_probe_still_protects_the_endpoint_from_removal() {
        // The other half of the split: failing closed is right for deleting.
        // The same indeterminate probe that must not block publication must
        // still stop this process from retiring an endpoint it cannot prove is
        // dead.
        //
        // This drives a real owner record for a real foreign process and
        // injects the unreadable probe, so the indeterminate arm is actually
        // executed. An earlier version wrote a bare `daemon.pid` and reached
        // the legacy branch instead, testing something else entirely under this
        // name.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let mut foreign = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn a stand-in foreign owner");
        let identity = kin_cli::daemon_client::process_identity(foreign.id())
            .expect("read the foreign owner's identity")
            .expect("the foreign owner is running");
        publish_foreign_endpoint_for_test(root, identity, 51234);

        let unreadable = |_: &kin_cli::daemon_client::ProcessIdentity| {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "cannot read birth identity for a foreign process",
            ))
        };
        let ownership = endpoint_ownership_with_probe(root, unreadable);

        assert_eq!(
            ownership,
            EndpointOwnership::OtherProcess {
                pid: foreign.id(),
                live: true,
            },
            "an owner that cannot be inspected must read as live for the removal decision"
        );
        assert!(
            !ownership.authorizes_removal(),
            "never delete an endpoint whose owner cannot be inspected"
        );

        // And end to end, through the real probe: the endpoint survives.
        remove_daemon_files_if_current_process(root);
        assert!(
            root.join("daemon.pid").exists() && root.join("daemon.port").exists(),
            "an endpoint owned by another live process must survive retirement"
        );

        let _ = foreign.kill();
        let _ = foreign.wait();
    }

    #[test]
    fn a_legacy_endpoint_naming_a_live_pid_is_not_removed() {
        // The legacy branch the test above used to reach by accident, kept
        // deliberately and named for what it is: no owner record, a bare PID
        // that resolves to something alive, so removal is refused.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("daemon.pid"), "1").unwrap();
        std::fs::write(root.join("daemon.port"), "51234").unwrap();

        assert_eq!(
            endpoint_ownership(root),
            EndpointOwnership::OtherProcess { pid: 1, live: true }
        );
        remove_daemon_files_if_current_process(root);
        assert!(root.join("daemon.pid").exists() && root.join("daemon.port").exists());
    }

    #[test]
    fn a_daemon_can_always_retire_its_own_endpoint() {
        // Retirement used to be `read(daemon.pid) == process::id()`, which
        // cannot fail. Identity must not make it fallible: a daemon that
        // cannot retire its own endpoint leaves a stale one behind, which
        // other surfaces assert never happens.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        publish_daemon_endpoint(root, 4219).expect("publish");

        assert_eq!(endpoint_ownership(root), EndpointOwnership::CurrentProcess);
        remove_daemon_files_if_current_process(root);
        assert_eq!(endpoint_ownership(root), EndpointOwnership::Absent);
        assert!(!root.join(ENDPOINT_OWNER_FILE).exists());
    }

    #[test]
    fn publication_replaces_a_legacy_endpoint_whose_pid_proves_nothing() {
        // PID 1 is alive and is not this process, but a bare-PID record cannot
        // prove that number still names the daemon that wrote it. The publisher
        // holds the repository singleton, so refusing here would leave the
        // repo's rightful owner permanently unable to advertise itself.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("daemon.pid"), "1").unwrap();
        std::fs::write(root.join("daemon.port"), "51234").unwrap();

        publish_daemon_endpoint(root, 4219)
            .expect("an unprovable claim must not block publication");

        assert_eq!(endpoint_ownership(root), EndpointOwnership::CurrentProcess);
        assert_eq!(read_port_file(root), Some(4219));
    }

    #[test]
    fn a_failed_publication_rolls_back_only_what_it_installed() {
        // Force the port rename to fail by parking a non-empty directory on the
        // destination. The rollback must remove the components this call
        // installed and nothing else.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir(root.join("daemon.port")).unwrap();
        std::fs::write(root.join("daemon.port").join("occupant"), b"x").unwrap();

        publish_daemon_endpoint(root, 51234).expect_err("renaming onto a directory must fail");

        assert!(
            !root.join("daemon.pid").exists(),
            "the pid this call installed must be rolled back"
        );
        assert!(
            !root.join(ENDPOINT_OWNER_FILE).exists(),
            "the attribution this call installed must be rolled back"
        );
        assert!(
            root.join("daemon.port").join("occupant").exists(),
            "a path this call never installed must be left exactly as found"
        );
        assert!(!root.join("daemon.pid.tmp").exists());
        assert!(!root.join("daemon.port.tmp").exists());
        assert!(!root.join("daemon.owner.tmp").exists());
    }

    #[test]
    fn a_live_owners_endpoint_survives_the_liveness_probe() {
        // The probe answers "is it serving", and the answer for an unreachable
        // port is no — but that is not a licence to delete a live daemon's
        // endpoint.
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::write(root.join("daemon.pid"), "1").unwrap();
        std::fs::write(root.join("daemon.port"), "1").unwrap();

        assert!(daemon_is_up(root).is_none());
        assert!(root.join("daemon.pid").exists());
        assert!(root.join("daemon.port").exists());
    }
}
