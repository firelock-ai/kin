// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Attribution of a daemon that holds its repository but has not published an
//! endpoint yet.
//!
//! A daemon takes the repository's runtime authority, the identity-stamped
//! `daemon.lock`, before it opens any state, and publishes `daemon.pid` only
//! once that state is open. Opening a large store, or re-qualifying it first,
//! can take tens of seconds, and a stop that looked only at `daemon.pid`
//! reported that window as "nothing running" while the daemon kept going.
//!
//! The same authority is also taken by one-shot offline maintenance such as
//! `kin upgrade`, so a held lock and a live stamped process never name a
//! daemon on their own. A daemon therefore records its own incarnation and
//! executing image, captured by itself, beside the lock it holds. Only a held
//! lock whose stamp, record and live process all agree names a starting
//! daemon. Anything else holding the lock is busy, never stopped. The advisory
//! startup progress record is not consulted here at all.

use super::*;
use std::io;

/// The record a starting daemon writes beside the lock it holds.
pub const STARTING_OWNER_FILE_NAME: &str = "daemon-starting-owner.json";

const STARTING_OWNER_SCHEMA: &str = "kin.daemon.starting-owner.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StartingOwnerRecord {
    schema: String,
    kin_root: PathBuf,
    owner: EndpointOwnerRecord,
}

/// Who holds a repository's runtime authority, as far as stopping it goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartingDaemonOwner {
    /// Nobody holds the runtime authority.
    Absent,
    /// A daemon holds it: the lock's stamp, the daemon's own record and the
    /// live process incarnation agree, and the record carries the executing
    /// image the daemon captured for itself.
    Starting(EndpointOwnerRecord),
    /// Something holds it that cannot be attributed to a daemon, such as an
    /// offline maintenance command. It must never be signalled.
    Busy { reason: String, pid: Option<u32> },
}

/// Lifecycle coordination held across one signal to a starting daemon, after
/// its ownership was re-proved. Drop it before waiting for the exit.
#[derive(Debug)]
pub struct StartingDaemonSignalGuard {
    _lifecycle: File,
    owner: EndpointOwnerRecord,
}

/// This daemon's record, removed on a normal exit when it is still this
/// daemon's. A daemon that is killed leaves it behind, and a reader ignores
/// it once the lock is released or stamped by someone else.
#[derive(Debug)]
pub struct StartingDaemonOwnerPublication {
    root: PathBuf,
    record: StartingOwnerRecord,
}

impl Drop for StartingDaemonOwnerPublication {
    fn drop(&mut self) {
        let Ok(_coordination) = lifecycle_until(
            &self.root,
            Instant::now() + LIFECYCLE_AUTHORITY_RETRY_BUDGET,
        ) else {
            return;
        };
        let path = self.root.join(STARTING_OWNER_FILE_NAME);
        if read_record(&path).ok().as_ref() == Some(&self.record) {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn refusal(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, message.into())
}

fn lifecycle_until(root: &Path, deadline: Instant) -> io::Result<File> {
    let file = open_startup_regular_file(&root.join("daemon.lifecycle"), true, false, true)?;
    loop {
        match file.try_lock_exclusive() {
            Ok(()) => return Ok(file),
            Err(error) if error.kind() == fs2::lock_contended_error().kind() => {
                process_executable::check_deadline(deadline)?;
                std::thread::sleep(
                    LIFECYCLE_AUTHORITY_RETRY_INTERVAL
                        .min(deadline.saturating_duration_since(Instant::now())),
                );
            }
            Err(error) => return Err(error),
        }
    }
}

fn read_record(path: &Path) -> io::Result<StartingOwnerRecord> {
    let raw = read_regular_file_nofollow(path)
        .ok_or_else(|| refusal("the runtime holder published no daemon startup record"))?;
    serde_json::from_str(&raw)
        .map_err(|_| refusal("the runtime holder's daemon startup record is malformed"))
}

/// Whether another open description holds the lock. An unheld lock is taken
/// on this handle and released when the handle closes.
fn singleton_is_held(file: &File) -> io::Result<bool> {
    match file.try_lock_exclusive() {
        Ok(()) => Ok(false),
        Err(error) if error.kind() == fs2::lock_contended_error().kind() => Ok(true),
        Err(error) => Err(error),
    }
}

/// The process incarnation the lock is stamped with. A stamp this build
/// cannot read still yields its PID for the report when it has one.
fn owner_stamp(file: &mut File, observed_pid: &mut Option<u32>) -> io::Result<ProcessIdentity> {
    file.rewind()?;
    let mut text = String::new();
    file.take(16 * 1024).read_to_string(&mut text)?;
    let text = text.trim();
    let Some(encoded) = text.strip_prefix(REPOSITORY_RUNTIME_OWNER_STAMP_V2) else {
        *observed_pid = text.parse::<u32>().ok();
        return Err(refusal(
            "the runtime holder's lock carries no process-incarnation stamp",
        ));
    };
    let identity: ProcessIdentity = serde_json::from_str(encoded.trim())
        .map_err(|_| refusal("the runtime holder's process-incarnation stamp is unreadable"))?;
    *observed_pid = Some(identity.pid());
    Ok(identity)
}

fn same_singleton_path(root: &Path, file: &File) -> io::Result<()> {
    let current = open_startup_regular_file(&root.join("daemon.lock"), false, false, false)?;
    if startup_file_identity(file)? != startup_file_identity(&current)? {
        return Err(refusal(
            "the repository runtime lock was replaced during the check",
        ));
    }
    Ok(())
}

/// Whether an endpoint published by a different, possibly live, incarnation is
/// on disk. A dead predecessor's leftover endpoint is not one, and neither is
/// the endpoint the attributed daemon itself publishes while being stopped.
#[cfg(unix)]
fn live_foreign_endpoint(root: &Path, identity: &ProcessIdentity) -> bool {
    let (published, _) = repo_daemon_recorded_endpoint(root);
    let Some(published) = published else {
        return false;
    };
    match read_endpoint_owner_record(root) {
        // An unreadable incarnation may be live, so it counts as live.
        Some(owner) if owner.identity() != identity => {
            process_identity_is_current(owner.identity()).unwrap_or(true)
        }
        _ => published != identity.pid() && is_process_alive(published),
    }
}

/// This daemon's own incarnation and executing image, captured before it
/// takes the runtime authority so the unattributed window after the lock is
/// as short as a file write.
pub fn capture_starting_daemon_owner() -> Option<EndpointOwnerRecord> {
    let budget =
        process_executable::observation_budget(std::process::id(), DAEMON_BINARY_PROBE_TIMEOUT);
    EndpointOwnerRecord::current_with_deadline(Instant::now() + budget)
}

/// Record `owner`, this process, as the daemon holding `kin_root`'s runtime
/// authority. Refused unless this process holds that authority and its stamp
/// names this incarnation.
pub fn publish_starting_daemon_owner(
    kin_root: &Path,
    owner: EndpointOwnerRecord,
) -> io::Result<StartingDaemonOwnerPublication> {
    let root = kin_root.canonicalize()?;
    if current_process_identity()? != *owner.identity() {
        return Err(refusal(
            "a daemon startup record may only name the process writing it",
        ));
    }
    let _coordination = lifecycle_until(
        &root,
        Instant::now() + kin_daemon_spawn::REPOSITORY_RUNTIME_AUTHORITY_RETRY_BUDGET,
    )?;
    let mut singleton = open_startup_regular_file(&root.join("daemon.lock"), false, false, false)?;
    if !singleton_is_held(&singleton)?
        || owner_stamp(&mut singleton, &mut None)? != *owner.identity()
    {
        return Err(refusal(
            "a daemon startup record needs the runtime authority this process holds",
        ));
    }
    same_singleton_path(&root, &singleton)?;
    let record = StartingOwnerRecord {
        schema: STARTING_OWNER_SCHEMA.to_owned(),
        kin_root: root.clone(),
        owner,
    };
    // Created exclusively under an unpredictable name and renamed over the
    // record, so a link planted at the record's name is replaced, not followed.
    let mut staged = tempfile::Builder::new()
        .prefix(".daemon-starting-owner-")
        .tempfile_in(&root)?;
    serde_json::to_writer(&mut staged, &record)?;
    staged.flush()?;
    staged.persist(root.join(STARTING_OWNER_FILE_NAME))?;
    Ok(StartingDaemonOwnerPublication { root, record })
}

fn inspect(
    kin_root: &Path,
    expected: Option<&EndpointOwnerRecord>,
    deadline: Instant,
    observed_pid: &mut Option<u32>,
) -> io::Result<Option<StartingDaemonSignalGuard>> {
    let root = kin_root.canonicalize()?;
    // A repository no runtime has ever held has no lock to ask, and a stop
    // must not create coordination files in it.
    if matches!(
        std::fs::symlink_metadata(root.join("daemon.lock")),
        Err(ref error) if error.kind() == io::ErrorKind::NotFound
    ) {
        return Ok(None);
    }
    // Held for the whole check, so neither a runtime acquisition nor an
    // endpoint publication lands between the reads below.
    let lifecycle = lifecycle_until(&root, deadline)?;
    let mut singleton =
        match open_startup_regular_file(&root.join("daemon.lock"), false, false, false) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
    if !singleton_is_held(&singleton)? {
        // Whatever the unlocked stamp still says, nobody holds the repository.
        return Ok(None);
    }
    let identity = owner_stamp(&mut singleton, observed_pid)?;
    let record = read_record(&root.join(STARTING_OWNER_FILE_NAME))?;
    if record.schema != STARTING_OWNER_SCHEMA || record.owner.schema != ENDPOINT_OWNER_SCHEMA {
        return Err(refusal(
            "the runtime holder's daemon startup record has an unsupported schema",
        ));
    }
    if record.kin_root != root {
        return Err(refusal(
            "the daemon startup record belongs to a different repository",
        ));
    }
    if record.owner.identity != identity {
        return Err(refusal(
            "the runtime holder is not the daemon its startup record names",
        ));
    }
    if expected.is_some_and(|expected| *expected != record.owner) {
        return Err(refusal(
            "the repository runtime changed owner after it was attributed",
        ));
    }
    if !process_identity_is_current(&identity)? {
        return Err(refusal(
            "the runtime holder's recorded process incarnation is no longer running",
        ));
    }
    // Signals re-observe the live image and compare it with this evidence, so
    // here it only has to exist and be usable.
    #[cfg(unix)]
    record.owner.executable_identity()?;
    #[cfg(not(unix))]
    {
        let _ = (lifecycle, singleton);
        return Err(refusal(
            "stopping a daemon before it publishes an endpoint is unsupported on this platform",
        ));
    }
    #[cfg(unix)]
    {
        if live_foreign_endpoint(&root, &identity) {
            return Err(refusal(
                "a different daemon's endpoint is published for this repository",
            ));
        }
        same_singleton_path(&root, &singleton)?;
        if !singleton_is_held(&singleton)? {
            return Ok(None);
        }
        if owner_stamp(&mut singleton, observed_pid)? != identity {
            return Err(refusal(
                "the repository runtime changed owner during the check",
            ));
        }
        process_executable::check_deadline(deadline)?;
        Ok(Some(StartingDaemonSignalGuard {
            _lifecycle: lifecycle,
            owner: record.owner,
        }))
    }
}

/// Who holds `kin_root`'s runtime authority, from the lock itself and the
/// holder's own daemon record, never from advisory progress or a bare PID.
pub fn starting_daemon_owner(kin_root: &Path) -> StartingDaemonOwner {
    let mut pid = None;
    match inspect(
        kin_root,
        None,
        Instant::now() + kin_daemon_spawn::REPOSITORY_RUNTIME_AUTHORITY_RETRY_BUDGET,
        &mut pid,
    ) {
        Ok(None) => StartingDaemonOwner::Absent,
        Ok(Some(guard)) => StartingDaemonOwner::Starting(guard.owner.clone()),
        Err(error) => StartingDaemonOwner::Busy {
            reason: error.to_string(),
            pid,
        },
    }
}

/// Re-prove, immediately before a signal, that `expected` still holds
/// `kin_root`, and keep lifecycle coordination until the guard drops. The
/// caller still sends through its incarnation- and image-checked target.
pub fn revalidate_starting_daemon_owner(
    kin_root: &Path,
    expected: &EndpointOwnerRecord,
    deadline: Instant,
) -> io::Result<StartingDaemonSignalGuard> {
    inspect(kin_root, Some(expected), deadline, &mut None)?.ok_or_else(|| {
        refusal("the daemon that was starting no longer holds the repository runtime")
    })
}

/// Stamp `kin_root`'s held runtime lock with `owner` and record it exactly as
/// a daemon starting there does, for a stand-in process a test started. The
/// caller must already hold the lock.
#[cfg(test)]
pub(crate) fn stand_in_as_starting_daemon_for_test(kin_root: &Path, owner: &EndpointOwnerRecord) {
    let root = kin_root.canonicalize().unwrap();
    std::fs::write(
        root.join("daemon.lock"),
        format!(
            "{REPOSITORY_RUNTIME_OWNER_STAMP_V2} {}",
            serde_json::to_string(owner.identity()).unwrap()
        ),
    )
    .unwrap();
    std::fs::write(
        root.join(STARTING_OWNER_FILE_NAME),
        serde_json::to_string(&StartingOwnerRecord {
            schema: STARTING_OWNER_SCHEMA.to_owned(),
            kin_root: root.clone(),
            owner: owner.clone(),
        })
        .unwrap(),
    )
    .unwrap();
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    fn held(root: &Path) -> RepositoryRuntimeAuthority {
        acquire_repository_runtime_authority(root)
            .unwrap()
            .expect("take the repository runtime authority")
    }

    fn stamp(root: &Path, identity: &ProcessIdentity) {
        std::fs::write(
            root.join("daemon.lock"),
            format!(
                "{REPOSITORY_RUNTIME_OWNER_STAMP_V2} {}",
                serde_json::to_string(identity).unwrap()
            ),
        )
        .unwrap();
    }

    fn write_record(root: &Path, kin_root: &Path, owner: &EndpointOwnerRecord) {
        std::fs::write(
            root.join(STARTING_OWNER_FILE_NAME),
            serde_json::to_string(&StartingOwnerRecord {
                schema: STARTING_OWNER_SCHEMA.to_owned(),
                kin_root: kin_root.canonicalize().unwrap(),
                owner: owner.clone(),
            })
            .unwrap(),
        )
        .unwrap();
    }

    fn own_owner() -> EndpointOwnerRecord {
        let owner = capture_starting_daemon_owner().expect("capture this process");
        owner
            .executable_identity()
            .expect("this process has an image");
        owner
    }

    fn parent_identity() -> ProcessIdentity {
        process_identity(std::os::unix::process::parent_id())
            .unwrap()
            .expect("the parent is alive")
    }

    fn publish_endpoint(root: &Path, identity: &ProcessIdentity) {
        std::fs::write(root.join("daemon.pid"), identity.pid().to_string()).unwrap();
        std::fs::write(root.join("daemon.port"), "4219").unwrap();
        std::fs::write(
            root.join("daemon.owner"),
            serde_json::to_string(&EndpointOwnerRecord::for_identity(identity.clone())).unwrap(),
        )
        .unwrap();
    }

    fn busy(root: &Path) -> String {
        match starting_daemon_owner(root) {
            StartingDaemonOwner::Busy { reason, .. } => reason,
            other => panic!("expected a busy runtime, got {other:?}"),
        }
    }

    /// The daemon's own publication, under the authority it holds, is what a
    /// stop attributes, and it survives the endpoint that daemon publishes
    /// later. A publication without the authority is refused.
    #[test]
    fn a_held_published_startup_owner_is_attributed_and_survives_its_endpoint() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        assert!(publish_starting_daemon_owner(root, own_owner()).is_err());
        assert_eq!(starting_daemon_owner(root), StartingDaemonOwner::Absent);

        let _authority = held(root);
        let owner = own_owner();
        let publication = publish_starting_daemon_owner(root, owner.clone()).unwrap();
        assert_eq!(
            starting_daemon_owner(root),
            StartingDaemonOwner::Starting(owner.clone())
        );
        // The same incarnation publishing its endpoint mid-stop keeps it
        // attributable, and a dead predecessor's leftover endpoint does not
        // hide it.
        publish_endpoint(root, owner.identity());
        drop(
            revalidate_starting_daemon_owner(root, &owner, Instant::now() + Duration::from_secs(5))
                .unwrap(),
        );
        let mut gone = owner.identity().clone();
        gone.birth_token = format!("{}-earlier", gone.birth_token);
        publish_endpoint(root, &gone);
        assert_eq!(
            starting_daemon_owner(root),
            StartingDaemonOwner::Starting(owner.clone())
        );

        drop(publication);
        assert!(!root.join(STARTING_OWNER_FILE_NAME).exists());
    }

    /// A lock nobody holds names nobody, whatever its stale stamp and record
    /// say, including a live unrelated process.
    #[test]
    fn a_stale_unlocked_stamp_naming_a_live_process_is_absent() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        drop(held(root));
        let parent = parent_identity();
        stamp(root, &parent);
        write_record(
            root,
            root,
            &EndpointOwnerRecord {
                executable: own_owner().executable,
                ..EndpointOwnerRecord::for_identity(parent)
            },
        );
        assert_eq!(starting_daemon_owner(root), StartingDaemonOwner::Absent);
    }

    /// A maintenance command holds the same lock with a live stamp and writes
    /// no daemon record. It is busy, never a daemon, and a record some killed
    /// daemon left behind does not change that.
    #[test]
    fn a_live_maintenance_holder_is_busy_even_beside_a_stale_daemon_record() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let _maintenance = held(root);
        busy(root);
        let StartingDaemonOwner::Busy { pid, .. } = starting_daemon_owner(root) else {
            unreachable!()
        };
        assert_eq!(pid, Some(std::process::id()));

        let mut killed = current_process_identity().unwrap();
        killed.birth_token = format!("{}-earlier", killed.birth_token);
        write_record(
            root,
            root,
            &EndpointOwnerRecord {
                executable: own_owner().executable,
                ..EndpointOwnerRecord::for_identity(killed)
            },
        );
        busy(root);
    }

    /// Every record that does not prove the live holder is a daemon of this
    /// repository with usable image evidence is refused: a reused incarnation,
    /// a foreign repository, missing or unusable image evidence, a changed
    /// owner, and a live foreign endpoint.
    #[test]
    fn unproven_startup_owners_are_busy_and_never_attributed() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let other = tempfile::tempdir().unwrap();
        let _authority = held(root);
        let owner = own_owner();

        // A reused incarnation: the lock and record agree on this PID with an
        // earlier birth.
        let mut reused = owner.identity().clone();
        reused.birth_token = format!("{}-earlier", reused.birth_token);
        let reused_owner = EndpointOwnerRecord {
            executable: owner.executable.clone(),
            ..EndpointOwnerRecord::for_identity(reused.clone())
        };
        stamp(root, &reused);
        write_record(root, root, &reused_owner);
        assert!(busy(root).contains("no longer running"));
        stamp(root, owner.identity());

        write_record(root, other.path(), &owner);
        assert!(busy(root).contains("different repository"));

        write_record(
            root,
            root,
            &EndpointOwnerRecord::for_identity(owner.identity().clone()),
        );
        assert!(busy(root).contains("no executable identity"));
        write_record(
            root,
            root,
            &EndpointOwnerRecord {
                executable: Some(serde_json::json!({"algorithm": "unknown"})),
                ..owner.clone()
            },
        );
        busy(root);

        write_record(root, root, &owner);
        assert_eq!(
            starting_daemon_owner(root),
            StartingDaemonOwner::Starting(owner.clone())
        );
        let changed = EndpointOwnerRecord {
            executable: None,
            ..owner.clone()
        };
        assert!(revalidate_starting_daemon_owner(
            root,
            &changed,
            Instant::now() + Duration::from_secs(5)
        )
        .is_err());

        publish_endpoint(root, &parent_identity());
        assert!(busy(root).contains("different daemon's endpoint"));
        assert!(revalidate_starting_daemon_owner(
            root,
            &owner,
            Instant::now() + Duration::from_secs(5)
        )
        .is_err());
    }

    /// A link at the record's name is refused, never followed.
    #[test]
    fn a_link_at_the_startup_record_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();
        let _authority = held(root);
        let owner = own_owner();
        let target = tmp.path().join("elsewhere.json");
        write_record(root, root, &owner);
        std::fs::rename(root.join(STARTING_OWNER_FILE_NAME), &target).unwrap();
        std::os::unix::fs::symlink(&target, root.join(STARTING_OWNER_FILE_NAME)).unwrap();
        busy(root);
    }
}
