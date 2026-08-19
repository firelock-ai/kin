// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::path::{Path, PathBuf};
use std::sync::{mpsc, Arc, Mutex, PoisonError};

use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tracing::{debug, error, info, warn};

use crate::error::{IndexError, Result};

/// Events emitted by the file watcher.
#[derive(Debug, Clone)]
pub enum FileEvent {
    /// A source file was created or modified.
    Changed(PathBuf),
    /// A source file was removed.
    Removed(PathBuf),
}

/// Host events a watcher declined to place inside the repository it watches.
///
/// Reported rather than merely counted, because nothing downstream ever sees
/// these paths. An event dropped here never reaches the reconciliation loop, so
/// the loop cannot notice its own blindness and every surface that asks the
/// loop how it is doing gets a healthy answer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EventsOutsideRoot {
    /// How many host events this watcher could not place.
    pub count: u64,
    /// The most recently dropped path, so a report names one.
    pub last_path: Option<PathBuf>,
}

/// Every form of the repository root a host event may legitimately arrive under.
///
/// The backends do not agree on which form they report, and none of them is
/// wrong. macOS FSEvents resolves every symbolic link above the watched
/// directory before it reports anything, so a watch registered on
/// `/var/repo` is told about `/private/var/repo/main.rs`. Linux inotify
/// instead echoes the path it was handed, so the same watch registered through
/// a symlink keeps reporting the symlinked form. On Windows canonicalization
/// adds a `\\?\` verbatim prefix that no event carries at all.
///
/// So neither form alone can be the root: binding the resolved one breaks the
/// backends that echo, and binding the given one breaks the backends that
/// resolve. Both are held, and a path that matches neither lexically is
/// resolved once and asked again.
struct RepositoryRoots {
    bound: PathBuf,
    canonical: Option<PathBuf>,
}

impl RepositoryRoots {
    fn bind(root: &Path) -> Self {
        let bound = root.to_path_buf();
        let canonical = root
            .canonicalize()
            .ok()
            .filter(|resolved| *resolved != bound);
        Self { bound, canonical }
    }

    /// Place one host path inside this repository, or report that it is not
    /// inside it at all.
    fn relative(&self, path: &Path) -> Option<PathBuf> {
        if let Some(relative) = self.strip(path) {
            return Some(relative);
        }
        // Disagreeing lexically is the ordinary case rather than a miss, so the
        // path is resolved the way admission resolves it and asked again. The
        // leaf is preserved: a removal names a path that no longer exists, and
        // an event about a symbolic link is about the link and not its target.
        let resolved = crate::canonicalize_host_parent_preserving_leaf(path).ok()?;
        self.strip(&resolved)
    }

    fn strip(&self, path: &Path) -> Option<PathBuf> {
        if let Ok(relative) = path.strip_prefix(&self.bound) {
            return Some(relative.to_path_buf());
        }
        self.canonical
            .as_deref()
            .and_then(|canonical| path.strip_prefix(canonical).ok())
            .map(Path::to_path_buf)
    }

    /// The resolved root, or the bound one when it could not be resolved.
    fn resolved(&self) -> &Path {
        self.canonical.as_deref().unwrap_or(&self.bound)
    }
}

/// Record one host event that named a path outside the bound repository.
///
/// Loud once and counted always. The first is warned because a repository whose
/// events all land outside it admits nothing ambiently and used to say so
/// nowhere; the rest are counted because a genuinely foreign path can churn,
/// and a warning per event would bury the one that explains the daemon.
fn record_outside_root(
    outside_root: &Mutex<EventsOutsideRoot>,
    roots: &RepositoryRoots,
    path: &Path,
) {
    let mut recorded = outside_root.lock().unwrap_or_else(PoisonError::into_inner);
    recorded.count = recorded.count.saturating_add(1);
    recorded.last_path = Some(path.to_path_buf());
    if recorded.count == 1 {
        warn!(
            path = %path.display(),
            bound_root = %roots.bound.display(),
            resolved_root = %roots.resolved().display(),
            "a host event names a path this watcher cannot place inside the repository it \
             watches; it was dropped, so nothing that path changed will be admitted from the \
             act of writing it"
        );
    } else {
        debug!(
            count = recorded.count,
            path = %path.display(),
            "another host event fell outside the bound repository root"
        );
    }
}

/// File watcher that monitors a directory for source file changes.
pub struct FileWatcher {
    _watcher: RecommendedWatcher,
    receiver: mpsc::Receiver<FileEvent>,
    outside_root: Arc<Mutex<EventsOutsideRoot>>,
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
        // Resolved once here rather than per event. The root does not move
        // under a running daemon, and resolving it on every notification would
        // put a filesystem call on the path a churning working copy walks
        // thousands of times.
        let event_roots = RepositoryRoots::bind(&root);
        let outside_root = Arc::new(Mutex::new(EventsOutsideRoot::default()));
        let event_outside_root = Arc::clone(&outside_root);

        let mut watcher =
            notify::recommended_watcher(move |res: std::result::Result<Event, notify::Error>| {
                match res {
                    Ok(event) => {
                        let events = classify_event(&event, &event_roots, &event_outside_root);
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

        // Registered on the root as it was given. The backend resolves it or
        // does not, and either way both forms are already held.
        watcher
            .watch(&root, RecursiveMode::Recursive)
            .map_err(|e| IndexError::Watcher(e.to_string()))?;

        info!(root = %root.display(), "started file watcher");

        Ok(Self {
            _watcher: watcher,
            receiver: rx,
            outside_root,
        })
    }

    /// Host events this watcher could not place inside the repository it
    /// watches, so a caller can disclose its own blind spot.
    pub fn events_outside_root(&self) -> EventsOutsideRoot {
        self.outside_root
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
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

fn classify_event(
    event: &Event,
    roots: &RepositoryRoots,
    outside_root: &Mutex<EventsOutsideRoot>,
) -> Vec<FileEvent> {
    let mut file_events = Vec::new();

    let relevant_paths: Vec<&PathBuf> = event
        .paths
        .iter()
        .filter(|p| {
            let Some(rel_path) = roots.relative(p) else {
                record_outside_root(outside_root, roots, p);
                return false;
            };
            if !crate::should_index_repo_relative_path(&rel_path) {
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

    /// Classify one event against a root, discarding the outside-root record.
    fn classify(event: &Event, root: &Path) -> Vec<FileEvent> {
        classify_against(event, root).0
    }

    /// Classify one event against a root and keep what it declined to place.
    fn classify_against(event: &Event, root: &Path) -> (Vec<FileEvent>, EventsOutsideRoot) {
        let roots = RepositoryRoots::bind(root);
        let outside_root = Mutex::new(EventsOutsideRoot::default());
        let events = classify_event(event, &roots, &outside_root);
        let recorded = outside_root.into_inner().unwrap();
        (events, recorded)
    }

    fn content_change(paths: Vec<PathBuf>) -> Event {
        Event {
            kind: EventKind::Modify(notify::event::ModifyKind::Data(
                notify::event::DataChange::Content,
            )),
            paths,
            attrs: Default::default(),
        }
    }

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
        let result = classify(&event, root.path());
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
        let result = classify(&event, root.path());
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
        let result = classify(&event, Path::new("/tmp"));
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
        let result = classify(&event, root.path());
        assert_eq!(result.len(), 1);
        assert!(matches!(result[0], FileEvent::Changed(_)));
    }

    /// FIR-2442. A watcher bound through a symlinked root must still place the
    /// events its backend reports, whichever form the backend chose.
    ///
    /// This is the shape macOS produces on every run: FSEvents resolves the
    /// watched path before reporting, so a daemon bound to `/var/repo` is told
    /// about `/private/var/repo/main.rs`. The lexical comparison this replaced
    /// dropped every one of those, silently.
    #[cfg(unix)]
    #[test]
    fn classify_places_an_event_the_backend_reported_under_the_resolved_root() {
        let base = tempfile::tempdir().unwrap();
        let real = base.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = base.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let written = link.join("main.rs");
        std::fs::write(&written, "fn main() {}").unwrap();

        let reported = real.canonicalize().unwrap().join("main.rs");
        assert_ne!(
            reported, written,
            "the fixture must exercise two different spellings of one file"
        );

        let (result, outside) = classify_against(&content_change(vec![reported]), &link);

        assert_eq!(result.len(), 1, "the resolved form names a repository file");
        assert!(matches!(result[0], FileEvent::Changed(_)));
        assert_eq!(outside, EventsOutsideRoot::default());
    }

    /// The mirror case, which is what Linux inotify and Windows canonicalization
    /// produce: the root is held resolved and the event arrives unresolved.
    #[cfg(unix)]
    #[test]
    fn classify_places_an_event_reported_under_a_symlinked_spelling_of_the_root() {
        let base = tempfile::tempdir().unwrap();
        let real = base.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = base.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let written = link.join("main.rs");
        std::fs::write(&written, "fn main() {}").unwrap();

        let resolved_root = real.canonicalize().unwrap();
        let (result, outside) = classify_against(&content_change(vec![written]), &resolved_root);

        assert_eq!(result.len(), 1, "the symlinked form names the same file");
        assert!(matches!(result[0], FileEvent::Changed(_)));
        assert_eq!(outside, EventsOutsideRoot::default());
    }

    /// FIR-2442. A path that really is outside the repository is still dropped,
    /// but it is counted and named rather than discarded in silence.
    #[test]
    fn classify_reports_an_event_that_falls_outside_the_bound_root() {
        let base = tempfile::tempdir().unwrap();
        let root = base.path().join("repo");
        let foreign = base.path().join("elsewhere");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&foreign).unwrap();
        let outside_path = foreign.join("stranger.rs");
        std::fs::write(&outside_path, "pub fn stranger() {}").unwrap();

        let (result, outside) =
            classify_against(&content_change(vec![outside_path.clone()]), &root);

        assert!(result.is_empty(), "a foreign path is not admitted");
        assert_eq!(outside.count, 1, "the drop is counted");
        assert_eq!(
            outside.last_path,
            Some(outside_path),
            "the drop names the path it dropped"
        );
    }

    /// FIR-2442, end to end through a real backend. A repository reached through
    /// a symlink must report the writes made through it.
    #[cfg(unix)]
    #[test]
    fn a_watcher_bound_through_a_symlinked_root_reports_writes_through_it() {
        let base = tempfile::tempdir().unwrap();
        let real = base.path().join("real");
        std::fs::create_dir(&real).unwrap();
        let link = base.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let watcher = FileWatcher::new(&link).unwrap();
        // The backend registers its watch asynchronously, so a write racing
        // registration would prove nothing either way.
        std::thread::sleep(std::time::Duration::from_millis(500));
        std::fs::write(link.join("added.rs"), "pub fn added() {}").unwrap();

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        let mut seen = Vec::new();
        while std::time::Instant::now() < deadline && seen.is_empty() {
            if let Some(event) = watcher.try_recv() {
                seen.push(event);
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }

        assert!(
            !seen.is_empty(),
            "a write through the symlinked root {} produced no event in 30s; the watcher \
             placed {} event(s) outside the root it is bound to (most recent {:?})",
            link.display(),
            watcher.events_outside_root().count,
            watcher.events_outside_root().last_path,
        );
        assert_eq!(
            watcher.events_outside_root().count,
            0,
            "no event from inside the repository may be dropped as foreign"
        );
    }
}
