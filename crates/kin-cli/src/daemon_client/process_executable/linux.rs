// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use super::{check_deadline, ExecutableIdentity};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Read};
use std::os::unix::fs::MetadataExt;
use std::time::Instant;

pub(super) fn observe(pid: u32, deadline: Instant) -> io::Result<ExecutableIdentity> {
    check_deadline(deadline)?;
    // Open the kernel's executing-image reference, never the pathname rendered
    // by read_link: that name can now refer to an upgrade or be marked deleted.
    let reference = format!("/proc/{pid}/exe");
    let image = File::open(&reference)?;
    observe_opened_image(image, deadline, || File::open(&reference))
}

fn observe_opened_image<F>(
    mut image: File,
    deadline: Instant,
    reopen_current_image: F,
) -> io::Result<ExecutableIdentity>
where
    F: FnOnce() -> io::Result<File>,
{
    check_deadline(deadline)?;
    let before = image.metadata()?;
    if !before.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the executing-image reference is not a regular file",
        ));
    }
    let mut digest = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        check_deadline(deadline)?;
        let count = image.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    let after = image.metadata()?;
    check_deadline(deadline)?;
    if before.len() != after.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "executing-image length changed during observation",
        ));
    }
    let sha256 = hex::encode(digest.finalize());
    // An exec can leave the opened image valid while /proc/PID/exe now names a
    // different one. Re-open the kernel reference after hashing to reject that
    // transition. This is still a point-in-time check, not an exec lock.
    check_deadline(deadline)?;
    let current = reopen_current_image()?;
    check_deadline(deadline)?;
    let current_metadata = current.metadata()?;
    check_deadline(deadline)?;
    if current_metadata.dev() != before.dev() || current_metadata.ino() != before.ino() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "the process changed its executing image during observation",
        ));
    }
    Ok(ExecutableIdentity::LinuxProcExeSha256V1 {
        device: before.dev(),
        inode: before.ino(),
        sha256,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::process::{Child, Command, Stdio};
    use std::time::Duration;

    struct OwnedImageChild(Child);

    impl Drop for OwnedImageChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn image_fixture(contents: &[u8]) -> tempfile::NamedTempFile {
        let file = tempfile::NamedTempFile::new().unwrap();
        std::fs::write(file.path(), contents).unwrap();
        file
    }

    #[test]
    fn rejects_a_changed_current_image_while_the_opened_image_remains_valid() {
        // Identical bytes ensure the current inode, rather than just the
        // digest of the old still-readable descriptor, decides this case.
        let original = image_fixture(b"abc");
        let replacement = image_fixture(b"abc");
        let opened = File::open(original.path()).unwrap();
        let old_metadata = opened.metadata().unwrap();
        let next_metadata = replacement.as_file().metadata().unwrap();
        assert_ne!(
            (old_metadata.dev(), old_metadata.ino()),
            (next_metadata.dev(), next_metadata.ino())
        );
        let reopened = Cell::new(false);
        let error = observe_opened_image(opened, Instant::now() + Duration::from_secs(5), || {
            reopened.set(true);
            File::open(replacement.path())
        })
        .unwrap_err();
        assert!(reopened.get());
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(std::fs::read(original.path()).unwrap(), b"abc");
    }

    #[test]
    fn retains_authority_for_an_opened_image_after_its_install_path_is_replaced() {
        let directory = tempfile::tempdir().unwrap();
        let install_path = directory.path().join("worker");
        std::fs::write(&install_path, b"abc").unwrap();
        let opened = File::open(&install_path).unwrap();
        let still_executing = opened.try_clone().unwrap();
        let metadata = opened.metadata().unwrap();
        std::fs::remove_file(&install_path).unwrap();
        std::fs::write(&install_path, b"later installed image").unwrap();

        // Model the kernel reference retaining the executing inode despite a
        // changed installation path. Neither observation opens that path.
        let observed =
            observe_opened_image(opened, Instant::now() + Duration::from_secs(5), || {
                Ok(still_executing)
            })
            .unwrap();
        assert_eq!(
            observed,
            ExecutableIdentity::LinuxProcExeSha256V1 {
                device: metadata.dev(),
                inode: metadata.ino(),
                sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
                    .to_owned(),
            }
        );
    }

    #[test]
    fn refuses_when_the_current_image_cannot_be_reopened() {
        let original = image_fixture(b"abc");
        let error = observe_opened_image(
            File::open(original.path()).unwrap(),
            Instant::now() + Duration::from_secs(5),
            || Err(io::Error::from_raw_os_error(libc::EACCES)),
        )
        .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EACCES));
    }

    #[test]
    fn an_expired_budget_never_reopens_the_image() {
        let original = image_fixture(b"abc");
        let reopened = Cell::new(false);
        let error =
            observe_opened_image(File::open(original.path()).unwrap(), Instant::now(), || {
                reopened.set(true);
                File::open(original.path())
            })
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(!reopened.get());
    }

    #[test]
    fn an_unreadable_opened_image_never_reopens_the_current_image() {
        // A write-only regular descriptor has valid metadata but cannot supply
        // hash bytes; the read error must never become executable authority.
        let original = image_fixture(b"abc");
        let opened = std::fs::OpenOptions::new()
            .write(true)
            .open(original.path())
            .unwrap();
        let reopened = Cell::new(false);
        let error = observe_opened_image(opened, Instant::now() + Duration::from_secs(5), || {
            reopened.set(true);
            File::open(original.path())
        })
        .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EBADF));
        assert!(!reopened.get());
    }

    #[test]
    fn observes_a_small_kernel_image_consistently() {
        // This grades the kernel image reference, not SHA-256 throughput over
        // the growing, unoptimized test executable. A native cat waits on our
        // pipe without a shell or a timer; the guard reaps it even on panic.
        let expected = std::fs::metadata("/bin/cat").unwrap();
        let mut child = OwnedImageChild(
            Command::new("/bin/cat")
                .stdin(Stdio::piped())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn the owned native image fixture"),
        );
        let pid = child.0.id();
        // spawn returns once the child is inside execve, but the kernel wakes
        // the parent before it swaps the child's memory map, so for a moment
        // /proc/<pid>/exe can still name this test executable. Wait for the
        // exec to land rather than reading that window as a wrong image.
        let exec_deadline = Instant::now() + Duration::from_secs(5);
        let metadata = loop {
            let metadata = std::fs::metadata(format!("/proc/{pid}/exe")).unwrap();
            if (metadata.dev(), metadata.ino()) == (expected.dev(), expected.ino())
                || Instant::now() >= exec_deadline
            {
                break metadata;
            }
            std::thread::sleep(Duration::from_millis(1));
        };
        assert_eq!(
            (metadata.dev(), metadata.ino()),
            (expected.dev(), expected.ino()),
            "the child must execute the native fixture image"
        );
        let executable_bytes = metadata.len();
        let deadline = Instant::now() + Duration::from_secs(5);
        let first_started = Instant::now();
        let first = observe(pid, deadline);
        let first_elapsed = first_started.elapsed();
        eprintln!(
            "linux executable observation: executable_bytes={executable_bytes}, first_elapsed_us={}, first={first:?}",
            first_elapsed.as_micros()
        );
        let first = first.expect("observe the owned native image");
        let second_started = Instant::now();
        let second = observe(pid, deadline);
        let second_elapsed = second_started.elapsed();
        eprintln!(
            "linux executable observation: executable_bytes={executable_bytes}, second_elapsed_us={}, second={second:?}",
            second_elapsed.as_micros()
        );
        let second = second.expect("observe the same native image again");
        assert_eq!(first, second);
        first.validate().unwrap();
        assert!(matches!(
            first,
            ExecutableIdentity::LinuxProcExeSha256V1 { device, inode, .. }
                if device == expected.dev() && inode == expected.ino()
        ));
        drop(child.0.stdin.take());
        assert!(child.0.wait().unwrap().success());
    }
}
