// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Cross-process advisory locks for registry storage transactions.
//!
//! Tokio locks only coordinate handlers inside one daemon. Registry roots can
//! also be mounted by multiple daemon processes during rollout or recovery, so
//! every read/modify/write authority boundary needs a lock whose identity is
//! the shared storage path itself.

use fs2::FileExt;
use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Condvar, Mutex, OnceLock, Weak};

#[derive(Default)]
struct GateState {
    readers: usize,
    writer: bool,
    waiting_writers: usize,
}

#[derive(Default)]
struct ProcessGate {
    state: Mutex<GateState>,
    changed: Condvar,
}

struct ProcessGuard {
    gate: Arc<ProcessGate>,
    exclusive: bool,
}

impl ProcessGuard {
    fn acquire(key: crate::atomic_file::AuthorityKey, exclusive: bool) -> io::Result<Self> {
        static GATES: OnceLock<
            Mutex<HashMap<crate::atomic_file::AuthorityKey, Weak<ProcessGate>>>,
        > = OnceLock::new();

        let gate = {
            let mut gates = GATES
                .get_or_init(|| Mutex::new(HashMap::new()))
                .lock()
                .map_err(|_| io::Error::other("registry process-lock map is poisoned"))?;
            gates.retain(|_, gate| gate.strong_count() > 0);
            match gates.get(&key).and_then(Weak::upgrade) {
                Some(gate) => gate,
                None => {
                    let gate = Arc::new(ProcessGate::default());
                    gates.insert(key, Arc::downgrade(&gate));
                    gate
                }
            }
        };

        let mut state = gate
            .state
            .lock()
            .map_err(|_| io::Error::other("registry process lock is poisoned"))?;
        if exclusive {
            state.waiting_writers += 1;
            while state.writer || state.readers > 0 {
                state = gate
                    .changed
                    .wait(state)
                    .map_err(|_| io::Error::other("registry process lock is poisoned"))?;
            }
            state.waiting_writers -= 1;
            state.writer = true;
        } else {
            // Give a queued writer priority so a continuous stream of public reads cannot
            // starve package publication forever.
            while state.writer || state.waiting_writers > 0 {
                state = gate
                    .changed
                    .wait(state)
                    .map_err(|_| io::Error::other("registry process lock is poisoned"))?;
            }
            state.readers += 1;
        }
        drop(state);
        Ok(Self { gate, exclusive })
    }
}

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        let mut state = self
            .gate
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.exclusive {
            state.writer = false;
        } else {
            state.readers = state.readers.saturating_sub(1);
        }
        self.gate.changed.notify_all();
    }
}

pub(crate) struct StorageLock {
    file: crate::atomic_file::AnchoredLockFile,
    _process_guard: ProcessGuard,
}

impl StorageLock {
    #[cfg(test)]
    pub(crate) fn exclusive(path: &Path) -> io::Result<Self> {
        Self::acquire(path, true)
    }

    pub(crate) fn shared_at(
        root: &crate::atomic_file::AuthorityRoot,
        relative: &Path,
    ) -> io::Result<Self> {
        Self::acquire_file(root.open_lock_file(relative)?, false)
    }

    pub(crate) fn exclusive_at(
        root: &crate::atomic_file::AuthorityRoot,
        relative: &Path,
    ) -> io::Result<Self> {
        Self::acquire_file(root.open_lock_file(relative)?, true)
    }

    pub(crate) async fn exclusive_at_async(
        root: crate::atomic_file::AuthorityRoot,
        relative: PathBuf,
    ) -> io::Result<Self> {
        tokio::task::spawn_blocking(move || Self::exclusive_at(&root, &relative))
            .await
            .map_err(|error| io::Error::other(format!("registry lock task failed: {error}")))?
    }

    #[cfg(test)]
    fn acquire(path: &Path, exclusive: bool) -> io::Result<Self> {
        Self::acquire_file(crate::atomic_file::open_lock_file(path)?, exclusive)
    }

    fn acquire_file(
        file: crate::atomic_file::AnchoredLockFile,
        exclusive: bool,
    ) -> io::Result<Self> {
        let process_guard = ProcessGuard::acquire(file.authority_key(), exclusive)?;
        if exclusive {
            FileExt::lock_exclusive(&file.file)?;
        } else {
            FileExt::lock_shared(&file.file)?;
        }
        file.verify_named()?;
        Ok(Self {
            file,
            _process_guard: process_guard,
        })
    }
}

impl Drop for StorageLock {
    fn drop(&mut self) {
        let _ = FileExt::unlock(&self.file.file);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Duration;

    #[test]
    fn same_process_exclusive_locks_are_serialized_by_authority_identity() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().canonicalize().unwrap().join("registry.lock");
        let first = StorageLock::exclusive(&path).unwrap();
        let (attempted_tx, attempted_rx) = mpsc::channel();
        let (acquired_tx, acquired_rx) = mpsc::channel();
        let contender_path = path.clone();
        let contender = std::thread::spawn(move || {
            attempted_tx.send(()).unwrap();
            let _lock = StorageLock::exclusive(&contender_path).unwrap();
            acquired_tx.send(()).unwrap();
        });

        attempted_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert!(matches!(
            acquired_rx.recv_timeout(Duration::from_millis(50)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        drop(first);
        acquired_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        contender.join().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_parent_aliases_share_one_process_gate() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let root_path = root.path().canonicalize().unwrap();
        let real = root_path.join("real");
        let alias = root_path.join("alias");
        std::fs::create_dir(&real).unwrap();
        symlink(&real, &alias).unwrap();

        // Registry storage rejects symlink traversal instead of assigning a second lock
        // identity to the same underlying authority.
        let error = StorageLock::exclusive(&alias.join("registry.lock"))
            .err()
            .expect("symlinked registry parent must be rejected");
        assert!(matches!(
            error.raw_os_error(),
            Some(code) if code == libc::ELOOP || code == libc::ENOTDIR
        ));
    }
}
