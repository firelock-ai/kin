// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The isolated Git capture directory one `kin init` owns.
//!
//! Publishing `.kin` is atomic: every refusal before the publication rename
//! leaves it absent, and the staged layout beside it carries a locked owner
//! record that the next init's orphan recovery reaps. The Git capture directory
//! had neither. It is created before any of that, holds the entire object
//! closure of the source repository while init derives semantics from it, and
//! was removed only by the ordinary drop of a temporary-directory handle. A
//! process that dies without unwinding skips that drop, so an interrupted init
//! stranded the whole closure beside the repository, untracked and unnamed.
//!
//! Three things cover it here. A lease file inside the directory is held for as
//! long as the init runs, so a later reader that can take it exclusively has
//! proof no live init owns that directory; the kernel releases it however the
//! holder dies, including under `SIGKILL`. Every init reaps such directories
//! before creating its own. And while an init runs, a terminating signal is
//! caught long enough to remove what this process staged before the signal is
//! delivered again for real.
//!
//! The directory stays a sibling of the repository rather than moving under the
//! system temporary directory. It holds every byte of the source object
//! closure, tens of gigabytes on a large history, and the system temporary
//! directory is memory-backed on common Linux hosts. Relocating there would
//! trade debris that is now cleaned for an out-of-space failure on the repos
//! that need admission most.

use std::fs::OpenOptions;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use fs2::FileExt as _;
use tracing::{debug, warn};

use crate::error::{KinError, Result};

/// Name prefix of the per-init Git capture directory.
pub const GIT_CAPTURE_PREFIX: &str = ".kin-git-capture-";

/// Lease file inside one capture directory.
///
/// Inside rather than beside it, because unlike the staged repository layout
/// this directory is never renamed into place, so nothing it contains can reach
/// published authority.
const CAPTURE_LEASE_NAME: &str = "capture.lease";

/// Name the lease is created and locked under before it is published.
///
/// A lease is proof only while it is held, so the name a reader tests must
/// never exist unheld. Creating the file and locking it are two calls, and a
/// reap landing between them takes the lock the claim is about to take, reads a
/// live directory as abandoned, and deletes the capture out from under an init
/// that carries on believing it owns one. Locking under this name and renaming
/// it into place closes that window rather than narrowing it: the rename is
/// atomic, the lock follows the inode through it, and `CAPTURE_LEASE_NAME`
/// therefore never exists unheld.
///
/// The reap deliberately does not know this name. A directory carrying no
/// published lease is retained and disclosed whatever else is inside it, which
/// is what makes a claim in flight safe from a concurrent reap.
const CAPTURE_LEASE_PENDING_NAME: &str = "capture.lease.pending";

/// One init's isolated Git capture directory.
///
/// Dropping this removes the directory. Holding it holds the lease that tells
/// every other init the directory is still in use.
pub(crate) struct GitCaptureStaging {
    path: PathBuf,
    /// Held open and exclusively locked for the life of the capture. Closed
    /// before the directory is removed, because Windows cannot delete a file
    /// something still has open.
    lease: Option<std::fs::File>,
}

impl GitCaptureStaging {
    /// Reap abandoned capture directories, then claim a fresh one.
    ///
    /// The order here is the whole guarantee. Signal cleanup is installed
    /// before anything exists to clean, and the path is registered before it is
    /// created, so there is no instant where a capture directory is on disk and
    /// a terminating signal would leave it there. Registering a path that is
    /// never created costs nothing: removing it finds nothing.
    pub(crate) fn claim(parent: &Path) -> Result<Self> {
        install_signal_cleanup();
        reap_abandoned_git_captures(parent)?;
        let path = parent.join(format!("{GIT_CAPTURE_PREFIX}{}", uuid::Uuid::new_v4()));
        register_staging_path(&path);
        let mut staging = Self { path, lease: None };
        create_private_directory(&staging.path)?;
        staging.lease = Some(hold_capture_lease(&staging.path)?);
        Ok(staging)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for GitCaptureStaging {
    fn drop(&mut self) {
        drop(self.lease.take());
        unregister_staging_path(&self.path);
        remove_staging_tree(&self.path);
    }
}

/// Take this init's lease on one capture directory, held on return.
///
/// The lease is created and locked under [`CAPTURE_LEASE_PENDING_NAME`] and
/// only then renamed to the name every reader tests, so no reader can ever
/// observe [`CAPTURE_LEASE_NAME`] unheld. See that constant for why the order
/// is the guarantee.
fn hold_capture_lease(directory: &Path) -> Result<std::fs::File> {
    let pending_path = directory.join(CAPTURE_LEASE_PENDING_NAME);
    let mut options = OpenOptions::new();
    options.read(true).write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let lease = options
        .open(&pending_path)
        .map_err(|error| KinError::io(&pending_path, error))?;
    lease
        .try_lock_exclusive()
        .map_err(|error| KinError::io(&pending_path, error))?;
    let lease_path = directory.join(CAPTURE_LEASE_NAME);
    std::fs::rename(&pending_path, &lease_path)
        .map_err(|error| KinError::io(&lease_path, error))?;
    Ok(lease)
}

/// Create one directory readable only by its owner.
fn create_private_directory(path: &Path) -> Result<()> {
    #[cfg(unix)]
    let builder = {
        use std::os::unix::fs::DirBuilderExt;

        let mut builder = std::fs::DirBuilder::new();
        builder.mode(0o700);
        builder
    };
    #[cfg(not(unix))]
    let builder = std::fs::DirBuilder::new();
    builder
        .create(path)
        .map_err(|error| KinError::io(path, error))
}

/// Remove one staging tree, tolerating a writer that is still filling it.
///
/// On the signal path the init thread keeps running until the re-raise lands,
/// so it can create an entry inside a directory this walk has already passed.
/// A bounded retry closes that, and anything still left carries its lease for
/// the next init to reap.
fn remove_staging_tree(path: &Path) {
    for attempt in 0..STAGING_REMOVAL_ATTEMPTS {
        match std::fs::remove_dir_all(path) {
            Ok(()) => return,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
            Err(error) if attempt + 1 == STAGING_REMOVAL_ATTEMPTS => {
                debug!(
                    path = %path.display(),
                    %error,
                    "could not remove a Git capture directory; the next kin init reaps it"
                );
            }
            Err(_) => {}
        }
    }
}

/// How many times removal retries against a writer still filling the tree.
const STAGING_REMOVAL_ATTEMPTS: usize = 8;

/// Remove every capture directory beside `parent` that no live init owns.
///
/// A directory whose lease can be taken exclusively is abandoned: the only
/// holder is gone. A directory whose lease is contended belongs to a concurrent
/// init, which is ordinary when sibling repositories under one parent are
/// admitted at the same time. A directory carrying no readable lease is
/// disclosed rather than removed, because an older Kin wrote it and this call
/// cannot prove nothing is using it, and because a claim that has created its
/// directory but not yet published its lease looks exactly the same from here.
///
/// Answers how many were removed.
pub(crate) fn reap_abandoned_git_captures(parent: &Path) -> Result<usize> {
    let entries = match std::fs::read_dir(parent) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(KinError::io(parent, error)),
    };
    let mut entries = entries
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(|error| KinError::io(parent, error))?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    let mut reaped = 0;
    for entry in entries {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.starts_with(GIT_CAPTURE_PREFIX) {
            continue;
        }
        let candidate = entry.path();
        let metadata = match std::fs::symlink_metadata(&candidate) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(KinError::io(&candidate, error)),
        };
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            warn!(
                path = %candidate.display(),
                "retaining a Git capture path that is not a directory Kin created"
            );
            continue;
        }
        match capture_lease_is_abandoned(&candidate) {
            Ok(true) => {}
            Ok(false) => continue,
            Err(reason) => {
                warn!(
                    path = %candidate.display(),
                    reason = %reason,
                    "a previous kin init left this Git capture directory behind; it is safe to \
                     delete once no kin init is running"
                );
                continue;
            }
        }
        match std::fs::remove_dir_all(&candidate) {
            Ok(()) => {
                reaped += 1;
                warn!(
                    path = %candidate.display(),
                    "removed a Git capture directory an interrupted kin init left behind"
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(KinError::io(&candidate, error)),
        }
    }
    Ok(reaped)
}

/// Whether one capture directory's lease proves it is abandoned.
///
/// `Ok(false)` means a live init holds it. `Err` carries why the question could
/// not be answered, which the caller discloses rather than acting on.
///
/// Shared with the post-mortem reader in [`crate::init_attempt`] on purpose. A
/// reader that decided liveness its own way could report a sibling conversion
/// running right now as a corpse, and reaping and reporting must agree about
/// what abandoned means or the two surfaces contradict each other.
pub(crate) fn capture_lease_is_abandoned(directory: &Path) -> std::result::Result<bool, String> {
    let lease_path = directory.join(CAPTURE_LEASE_NAME);
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.custom_flags(libc::O_NOFOLLOW);
    }
    let lease = options
        .open(&lease_path)
        .map_err(|error| format!("its lease {} is unreadable: {error}", CAPTURE_LEASE_NAME))?;
    match lease.try_lock_exclusive() {
        Ok(()) => Ok(true),
        Err(error) if is_lease_contention(&error) => Ok(false),
        Err(error) => Err(format!("its lease could not be tested: {error}")),
    }
}

/// Whether a lock attempt was refused because someone else holds the lock.
///
/// Unix `flock` reports contention as `EWOULDBLOCK`, which std maps to
/// `WouldBlock`; Windows `LockFileEx` reports `ERROR_LOCK_VIOLATION`, which std
/// leaves uncategorized. Testing the kind alone would recognize contention on
/// one platform and nothing on the other, turning a live directory into one
/// this call deletes.
fn is_lease_contention(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::WouldBlock
        || (error.raw_os_error().is_some()
            && error.raw_os_error() == fs2::lock_contended_error().raw_os_error())
}

/// Staging paths this process created and has not yet removed.
fn staging_paths() -> &'static Mutex<Vec<PathBuf>> {
    static PATHS: OnceLock<Mutex<Vec<PathBuf>>> = OnceLock::new();
    PATHS.get_or_init(|| Mutex::new(Vec::new()))
}

fn register_staging_path(path: &Path) {
    if let Ok(mut paths) = staging_paths().lock() {
        paths.push(path.to_path_buf());
    }
}

fn unregister_staging_path(path: &Path) {
    if let Ok(mut paths) = staging_paths().lock() {
        paths.retain(|registered| registered != path);
    }
}

/// Remove every staging path this process still owns.
///
/// Called from an ordinary thread, never from a signal handler, so it is free
/// to allocate and walk directories. Only the signal path needs it: an init
/// that returns removes its own directory by dropping it.
#[cfg(unix)]
fn remove_registered_staging() {
    let Ok(mut paths) = staging_paths().lock() else {
        return;
    };
    for path in paths.drain(..) {
        remove_staging_tree(&path);
    }
}

#[cfg(not(unix))]
fn install_signal_cleanup() {}

/// Catch a terminating signal long enough to remove what this init staged.
///
/// The handler itself only writes one byte to a pipe, which is async-signal-safe;
/// a dedicated thread does the removal in ordinary context and then delivers the
/// signal again with its default disposition, so the process still dies of what
/// killed it and with the status that says so. Removing a directory tree from
/// the handler would be shorter and could deadlock against an interrupted
/// allocation, turning stranded bytes into a hang.
///
/// A signal something else already handles is left alone. Init is a library
/// call as well as a command, and displacing a caller's own handler to clean up
/// after ourselves would be a worse trade than leaving the directory for the
/// next init's reap.
#[cfg(unix)]
fn install_signal_cleanup() {
    use std::sync::atomic::{AtomicI32, Ordering};

    /// Write end of the self-pipe. Read by the handler, so it is an atomic
    /// rather than anything that needs a lock.
    static NOTIFY_FD: AtomicI32 = AtomicI32::new(-1);
    static INSTALLED: OnceLock<()> = OnceLock::new();

    const CAUGHT: [libc::c_int; 3] = [libc::SIGINT, libc::SIGTERM, libc::SIGHUP];

    extern "C" fn poke(signal: libc::c_int) {
        let fd = NOTIFY_FD.load(Ordering::Relaxed);
        if fd < 0 {
            return;
        }
        let byte = signal as u8;
        // The only call in this handler, and async-signal-safe. A short write
        // or a full pipe both mean a poke is already in flight.
        unsafe {
            libc::write(fd, std::ptr::from_ref(&byte).cast(), 1);
        }
    }

    INSTALLED.get_or_init(|| {
        let mut fds = [0 as libc::c_int; 2];
        if unsafe { libc::pipe(fds.as_mut_ptr()) } != 0 {
            debug!(
                error = %std::io::Error::last_os_error(),
                "no staging cleanup on termination: pipe unavailable"
            );
            return;
        }
        for fd in fds {
            unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
        }
        let read_fd = fds[0];
        NOTIFY_FD.store(fds[1], Ordering::SeqCst);

        let mut caught = Vec::new();
        for signal in CAUGHT {
            let mut previous: libc::sigaction = unsafe { std::mem::zeroed() };
            if unsafe { libc::sigaction(signal, std::ptr::null(), &mut previous) } != 0 {
                continue;
            }
            if previous.sa_sigaction != libc::SIG_DFL {
                continue;
            }
            let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
            action.sa_sigaction = poke as *const () as usize;
            action.sa_flags = libc::SA_RESTART;
            unsafe { libc::sigemptyset(&mut action.sa_mask) };
            if unsafe { libc::sigaction(signal, &action, std::ptr::null_mut()) } == 0 {
                caught.push(signal);
            }
        }
        if caught.is_empty() {
            return;
        }

        let spawned = std::thread::Builder::new()
            .name("kin-init-staging-cleanup".to_string())
            .spawn(move || {
                let mut byte = 0u8;
                let signal = loop {
                    let read =
                        unsafe { libc::read(read_fd, std::ptr::from_mut(&mut byte).cast(), 1) };
                    if read == 1 {
                        break libc::c_int::from(byte);
                    }
                    if read < 0
                        && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted
                    {
                        continue;
                    }
                    // The pipe cannot deliver, so nothing will ever ask this
                    // thread to clean up.
                    return;
                };
                remove_registered_staging();
                let mut default: libc::sigaction = unsafe { std::mem::zeroed() };
                default.sa_sigaction = libc::SIG_DFL;
                unsafe {
                    libc::sigemptyset(&mut default.sa_mask);
                    libc::sigaction(signal, &default, std::ptr::null_mut());
                    libc::raise(signal);
                }
            });
        if spawned.is_err() {
            // Without the thread the handler would swallow the signal instead
            // of cleaning up, which is strictly worse than not catching it.
            for signal in caught {
                let mut default: libc::sigaction = unsafe { std::mem::zeroed() };
                default.sa_sigaction = libc::SIG_DFL;
                unsafe {
                    libc::sigemptyset(&mut default.sa_mask);
                    libc::sigaction(signal, &default, std::ptr::null_mut());
                }
            }
            NOTIFY_FD.store(-1, Ordering::SeqCst);
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capture_dir(parent: &Path, suffix: &str) -> PathBuf {
        let path = parent.join(format!("{GIT_CAPTURE_PREFIX}{suffix}"));
        std::fs::create_dir(&path).expect("capture directory");
        path
    }

    fn write_lease(directory: &Path) {
        std::fs::write(directory.join(CAPTURE_LEASE_NAME), b"").expect("lease");
    }

    #[test]
    fn a_claimed_capture_directory_is_removed_when_it_drops() {
        let parent = tempfile::tempdir().expect("tempdir");
        let staged = GitCaptureStaging::claim(parent.path()).expect("claim capture staging");
        let path = staged.path().to_path_buf();
        assert!(path.is_dir());
        assert!(path.join(CAPTURE_LEASE_NAME).is_file());
        assert!(
            !path.join(CAPTURE_LEASE_PENDING_NAME).exists(),
            "the lease is published by rename, so its pending name must be gone"
        );
        drop(staged);
        assert!(!path.exists(), "{} survived its owner", path.display());
    }

    /// The interrupted-init case: a directory whose lease nobody holds.
    #[test]
    fn an_abandoned_capture_directory_is_reaped_by_the_next_claim() {
        let parent = tempfile::tempdir().expect("tempdir");
        let abandoned = capture_dir(parent.path(), "abandoned");
        write_lease(&abandoned);
        std::fs::create_dir(abandoned.join("objects")).expect("captured objects");
        std::fs::write(abandoned.join("objects/body"), b"837 MiB in miniature").expect("body");

        assert_eq!(reap_abandoned_git_captures(parent.path()).expect("reap"), 1);
        assert!(!abandoned.exists());
    }

    /// A directory a live init owns is never reaped out from under it.
    #[test]
    fn a_live_capture_directory_survives_a_concurrent_reap() {
        let parent = tempfile::tempdir().expect("tempdir");
        let live = GitCaptureStaging::claim(parent.path()).expect("claim capture staging");
        let path = live.path().to_path_buf();

        assert_eq!(reap_abandoned_git_captures(parent.path()).expect("reap"), 0);
        assert!(path.is_dir(), "a leased capture directory must survive");
        drop(live);
    }

    /// A directory an older Kin left carries no lease, so it is named instead of
    /// deleted: nothing here can prove it is unused.
    #[test]
    fn a_capture_directory_without_a_lease_is_retained_and_disclosed() {
        let parent = tempfile::tempdir().expect("tempdir");
        let legacy = capture_dir(parent.path(), "legacy");
        std::fs::write(legacy.join("stray"), b"body").expect("stray body");

        assert_eq!(reap_abandoned_git_captures(parent.path()).expect("reap"), 0);
        assert!(legacy.is_dir(), "an unproven directory must be retained");
    }

    /// Claiming reaps before it stages, so one interrupted run does not compound.
    #[test]
    fn claiming_reaps_before_it_stages() {
        let parent = tempfile::tempdir().expect("tempdir");
        let abandoned = capture_dir(parent.path(), "abandoned");
        write_lease(&abandoned);

        let staged = GitCaptureStaging::claim(parent.path()).expect("claim capture staging");
        assert!(!abandoned.exists());
        assert!(staged.path().is_dir());
    }

    /// A terminating signal removes the capture directory before the process
    /// dies, and the process still dies of the signal that killed it.
    ///
    /// The child holds a claimed staging directory and nothing else, so the
    /// parent can prove the signal path ran rather than that the child never
    /// got far enough to stage anything: the signal is sent only after the
    /// child's lease has been observed on disk.
    #[cfg(unix)]
    #[test]
    fn a_terminating_signal_removes_the_capture_directory() {
        let root = tempfile::tempdir().expect("tempdir");
        let parent = root.path().join("parent");
        std::fs::create_dir(&parent).expect("staging parent");

        let mut child = std::process::Command::new(
            std::env::current_exe().expect("resolve staging signal test executable"),
        )
        .arg("init_staging::tests::staging_signal_subprocess")
        .arg("--nocapture")
        .arg("--test-threads=1")
        .env("KIN_INIT_STAGING_SIGNAL_TEST_PARENT", &parent)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn staging signal subprocess");

        let staged = wait_for_leased_capture_directory(&parent, &mut child);

        assert_eq!(
            unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) },
            0,
            "deliver SIGTERM to the staging subprocess"
        );
        let status = child.wait().expect("await staging subprocess");

        use std::os::unix::process::ExitStatusExt;
        assert_eq!(
            status.signal(),
            Some(libc::SIGTERM),
            "the process must still die of the signal it was sent: {status:?}"
        );
        assert!(
            !staged.exists(),
            "{} survived a terminating signal",
            staged.display()
        );
    }

    /// Poll for the child's leased capture directory, failing loudly rather
    /// than letting a child that never staged anything pass the test above.
    ///
    /// The lease is the condition, not the directory. [`GitCaptureStaging::claim`]
    /// creates the directory and only then opens and locks the lease inside it,
    /// so a parent that returns on the directory alone observes a claim still in
    /// flight and reads a lease the child has not written yet. That window is
    /// wall clock rather than an event, which the child wins on an idle machine
    /// and loses on a loaded one.
    #[cfg(unix)]
    fn wait_for_leased_capture_directory(
        parent: &Path,
        child: &mut std::process::Child,
    ) -> PathBuf {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            if let Ok(entries) = std::fs::read_dir(parent) {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    if name
                        .to_str()
                        .is_some_and(|name| name.starts_with(GIT_CAPTURE_PREFIX))
                        && entry.path().is_dir()
                        && entry.path().join(CAPTURE_LEASE_NAME).is_file()
                    {
                        return entry.path();
                    }
                }
            }
            if let Some(status) = child.try_wait().expect("poll staging subprocess") {
                panic!("staging subprocess exited before it staged anything: {status:?}");
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                panic!("staging subprocess never leased a capture directory");
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        }
    }

    /// Child half of [`a_terminating_signal_removes_the_capture_directory`].
    #[cfg(unix)]
    #[test]
    fn staging_signal_subprocess() {
        let Some(parent) = std::env::var_os("KIN_INIT_STAGING_SIGNAL_TEST_PARENT") else {
            return;
        };
        let staged = GitCaptureStaging::claim(Path::new(&parent)).expect("claim capture staging");
        // Held, not dropped: only the signal path may remove this directory.
        std::mem::forget(staged);
        loop {
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }

    /// A reap never removes a capture directory whose claim is still in flight.
    ///
    /// Two inits admitting sibling repositories under one parent share this
    /// directory, which the module treats as ordinary, so one init's reap runs
    /// while another init's claim is partway through. A claim becomes visible
    /// to that reap the instant its directory exists, and stays reapable until
    /// its lease is held, so the reaper hammers here for the whole of many
    /// claims rather than sampling one.
    #[test]
    fn a_claim_in_flight_survives_a_concurrent_reap() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let parent = tempfile::tempdir().expect("tempdir");
        let root = parent.path().to_path_buf();
        let stop = Arc::new(AtomicBool::new(false));
        let reaper = {
            let root = root.clone();
            let stop = Arc::clone(&stop);
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let _ = reap_abandoned_git_captures(&root);
                }
            })
        };

        // The reaper is stopped before anything is asserted: a panic here would
        // otherwise leave it spinning on a core for the rest of the run. Both
        // ways a claim can lose are recorded, because an unpublished lease
        // fails in two directions: the reap takes the lock the claim was about
        // to take, or it removes the directory the claim already believes it
        // owns.
        let mut lost = None;
        for attempt in 0..CONCURRENT_REAP_ATTEMPTS {
            match GitCaptureStaging::claim(&root) {
                Err(error) => {
                    lost = Some(format!("attempt {attempt} could not claim at all: {error}"));
                    break;
                }
                Ok(staged) => {
                    let held =
                        staged.path().is_dir() && staged.path().join(CAPTURE_LEASE_NAME).is_file();
                    drop(staged);
                    if !held {
                        lost = Some(format!("attempt {attempt} lost the directory it claimed"));
                        break;
                    }
                }
            }
        }
        stop.store(true, Ordering::Relaxed);
        reaper.join().expect("reaper thread");

        if let Some(detail) = lost {
            panic!("a concurrent reap defeated a claim still in flight: {detail}");
        }
    }

    /// How many claims the concurrent reap above races.
    const CONCURRENT_REAP_ATTEMPTS: usize = 200;

    /// A path wearing the prefix that is not a directory is left alone.
    #[test]
    fn a_capture_prefixed_file_is_never_removed() {
        let parent = tempfile::tempdir().expect("tempdir");
        let decoy = parent.path().join(format!("{GIT_CAPTURE_PREFIX}file"));
        std::fs::write(&decoy, b"not a capture").expect("decoy");

        assert_eq!(reap_abandoned_git_captures(parent.path()).expect("reap"), 0);
        assert!(decoy.is_file());
    }
}
