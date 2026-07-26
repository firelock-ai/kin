// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::path::{Path, PathBuf};
use std::sync::mpsc;

use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tracing::{debug, error, info};

use crate::error::{IndexError, Result};

/// Events emitted by the file watcher.
#[derive(Debug, Clone)]
pub enum FileEvent {
    /// A source file was created or modified.
    Changed(PathBuf),
    /// A source file was removed.
    Removed(PathBuf),
}

/// File watcher that monitors a directory for source file changes.
pub struct FileWatcher {
    _watcher: RecommendedWatcher,
    receiver: mpsc::Receiver<FileEvent>,
}

impl FileWatcher {
    /// Start watching every tracked source entry under a repository root.
    ///
    /// Parser support is enrichment, not admission. The watcher must therefore
    /// report Compose/config files, lockfiles, unsupported languages, binaries,
    /// and symlinks just as reliably as parser-backed source files.
    pub fn new(root: &Path) -> Result<Self> {
        let (tx, rx) = mpsc::channel();
        let root = root.to_path_buf();
        let event_root = root.clone();

        let mut watcher =
            notify::recommended_watcher(move |res: std::result::Result<Event, notify::Error>| {
                match res {
                    Ok(event) => {
                        let events = classify_event(&event, &event_root);
                        for fe in events {
                            if tx.send(fe).is_err() {
                                return;
                            }
                        }
                    }
                    Err(e) => {
                        error!(error = %e, "file watcher error");
                    }
                }
            })
            .map_err(|e| IndexError::Watcher(e.to_string()))?;

        watcher
            .watch(&root, RecursiveMode::Recursive)
            .map_err(|e| IndexError::Watcher(e.to_string()))?;

        info!(root = %root.display(), "started file watcher");

        Ok(Self {
            _watcher: watcher,
            receiver: rx,
        })
    }

    /// Receive the next file event (blocking).
    pub fn recv(&self) -> Option<FileEvent> {
        self.receiver.recv().ok()
    }

    /// Try to receive a file event without blocking.
    pub fn try_recv(&self) -> Option<FileEvent> {
        self.receiver.try_recv().ok()
    }

    /// Drain all pending events.
    pub fn drain(&self) -> Vec<FileEvent> {
        let mut events = Vec::new();
        while let Some(event) = self.try_recv() {
            events.push(event);
        }
        events
    }
}

fn classify_event(event: &Event, root: &Path) -> Vec<FileEvent> {
    let mut file_events = Vec::new();

    let relevant_paths: Vec<&PathBuf> = event
        .paths
        .iter()
        .filter(|p| {
            let Ok(rel_path) = p.strip_prefix(root) else {
                return false;
            };
            if !crate::should_index_repo_relative_path(rel_path) {
                return false;
            }
            // A removed path no longer has metadata to inspect. Notify emits
            // file-level removal paths for recursive watches, so retain it and
            // let exact-tree reconciliation decide whether it was tracked.
            matches!(event.kind, EventKind::Remove(_))
                || std::fs::symlink_metadata(p)
                    .map(|metadata| metadata.is_file() || metadata.file_type().is_symlink())
                    .unwrap_or(false)
        })
        .collect();

    if relevant_paths.is_empty() {
        return file_events;
    }

    match event.kind {
        EventKind::Create(_) | EventKind::Modify(_) => {
            for path in relevant_paths {
                debug!(path = %path.display(), "file changed");
                file_events.push(FileEvent::Changed(path.clone()));
            }
        }
        EventKind::Remove(_) => {
            for path in relevant_paths {
                debug!(path = %path.display(), "file removed");
                file_events.push(FileEvent::Removed(path.clone()));
            }
        }
        _ => {}
    }

    file_events
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_detects_unsupported_and_extensionless_files() {
        let root = tempfile::tempdir().unwrap();
        let readme = root.path().join("README");
        let compose = root.path().join("compose.yml");
        let lockfile = root.path().join("package-lock.json");
        std::fs::write(&readme, "hello").unwrap();
        std::fs::write(&compose, "services: {}").unwrap();
        std::fs::write(&lockfile, "{}").unwrap();
        let event = Event {
            kind: EventKind::Modify(notify::event::ModifyKind::Data(
                notify::event::DataChange::Content,
            )),
            paths: vec![readme, compose, lockfile],
            attrs: Default::default(),
        };
        let result = classify_event(&event, root.path());
        assert_eq!(result.len(), 3);
        assert!(result
            .iter()
            .all(|event| matches!(event, FileEvent::Changed(_))));
    }

    #[test]
    fn classify_detects_source_file_change() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("main.rs");
        std::fs::write(&path, "fn main() {}").unwrap();
        let event = Event {
            kind: EventKind::Modify(notify::event::ModifyKind::Data(
                notify::event::DataChange::Content,
            )),
            paths: vec![path],
            attrs: Default::default(),
        };
        let result = classify_event(&event, root.path());
        assert_eq!(result.len(), 1);
        assert!(matches!(result[0], FileEvent::Changed(_)));
    }

    #[test]
    fn classify_detects_file_removal() {
        let event = Event {
            kind: EventKind::Remove(notify::event::RemoveKind::File),
            paths: vec![PathBuf::from("/tmp/old.py")],
            attrs: Default::default(),
        };
        let result = classify_event(&event, Path::new("/tmp"));
        assert_eq!(result.len(), 1);
        assert!(matches!(result[0], FileEvent::Removed(_)));
    }

    #[test]
    fn classify_includes_generated_directory_paths() {
        let root = tempfile::tempdir().unwrap();
        let generated = root.path().join("out/generated.rs");
        std::fs::create_dir_all(generated.parent().unwrap()).unwrap();
        std::fs::write(&generated, "pub const GENERATED: bool = true;").unwrap();
        let event = Event {
            kind: EventKind::Modify(notify::event::ModifyKind::Data(
                notify::event::DataChange::Content,
            )),
            paths: vec![generated],
            attrs: Default::default(),
        };
        let result = classify_event(&event, root.path());
        assert_eq!(result.len(), 1);
        assert!(matches!(result[0], FileEvent::Changed(_)));
    }
}
