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
    /// Start watching a directory for changes to files with the given extensions.
    pub fn new(root: &Path, extensions: Vec<String>) -> Result<Self> {
        let (tx, rx) = mpsc::channel();
        let exts = extensions.clone();
        let root = root.to_path_buf();
        let event_root = root.clone();

        let mut watcher =
            notify::recommended_watcher(move |res: std::result::Result<Event, notify::Error>| {
                match res {
                    Ok(event) => {
                        let events = classify_event(&event, &exts, &event_root);
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

fn classify_event(event: &Event, extensions: &[String], root: &Path) -> Vec<FileEvent> {
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
            p.extension()
                .and_then(|e| e.to_str())
                .map(|ext| extensions.iter().any(|e| e == ext))
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

/// Collect all supported file extensions from the adapter registry.
pub fn supported_extensions() -> Vec<String> {
    let registry = kin_parser::AdapterRegistry::new();
    let mut exts = Vec::new();
    for lang in registry.supported_languages() {
        if let Some(adapter) = registry.get_by_language(lang) {
            for ext in adapter.file_extensions() {
                exts.push(ext.to_string());
            }
        }
    }
    exts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn supported_extensions_includes_common_types() {
        let exts = supported_extensions();
        assert!(exts.contains(&"ts".to_string()));
        assert!(exts.contains(&"js".to_string()));
        assert!(exts.contains(&"py".to_string()));
        assert!(exts.contains(&"go".to_string()));
        assert!(exts.contains(&"java".to_string()));
        assert!(exts.contains(&"rs".to_string()));
    }

    #[test]
    fn classify_ignores_non_matching_extensions() {
        let event = Event {
            kind: EventKind::Modify(notify::event::ModifyKind::Data(
                notify::event::DataChange::Content,
            )),
            paths: vec![PathBuf::from("/tmp/readme.txt")],
            attrs: Default::default(),
        };
        let extensions = vec!["rs".to_string(), "ts".to_string()];
        let result = classify_event(&event, &extensions, Path::new("/tmp"));
        assert!(result.is_empty());
    }

    #[test]
    fn classify_detects_source_file_change() {
        let event = Event {
            kind: EventKind::Modify(notify::event::ModifyKind::Data(
                notify::event::DataChange::Content,
            )),
            paths: vec![PathBuf::from("/tmp/main.rs")],
            attrs: Default::default(),
        };
        let extensions = vec!["rs".to_string()];
        let result = classify_event(&event, &extensions, Path::new("/tmp"));
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
        let extensions = vec!["py".to_string()];
        let result = classify_event(&event, &extensions, Path::new("/tmp"));
        assert_eq!(result.len(), 1);
        assert!(matches!(result[0], FileEvent::Removed(_)));
    }

    #[test]
    fn classify_ignores_skipped_dir_paths() {
        let event = Event {
            kind: EventKind::Modify(notify::event::ModifyKind::Data(
                notify::event::DataChange::Content,
            )),
            paths: vec![PathBuf::from("/tmp/out/generated.rs")],
            attrs: Default::default(),
        };
        let extensions = vec!["rs".to_string()];
        let result = classify_event(&event, &extensions, Path::new("/tmp"));
        assert!(result.is_empty());
    }
}
