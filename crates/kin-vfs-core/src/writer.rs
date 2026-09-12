// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Write admission for projection surfaces.
//!
//! A projection surface (NFS mount, FUSE mount) serves graph-owned truth. A
//! write arriving at that surface is not truth yet, and the surface must not
//! pretend it is. [`ContentWriter`] is the seam that turns an accepted write
//! into a Kin change: the surface stages the bytes, and an admission folds
//! every staged path into graph truth as one transaction.
//!
//! Two rules shape the trait.
//!
//! **Staging is explicit, never a fallback.** [`ContentWriter::staged`] answers
//! only for paths this surface itself wrote. A path the graph does not know and
//! this surface never wrote is absent, and stays absent: [`WriteThroughProvider`]
//! never reaches past the graph to repair a miss. That is the whole difference
//! between an admission boundary and raw file-search authority.
//!
//! **An unadmitted write is reported, never hidden.** [`WriteHealth`] is what a
//! status probe reads, and a failed admission leaves its paths staged with the
//! graph's own refusal attached rather than dropping them.

use std::sync::Arc;
use std::time::Duration;

use crate::path::{VfsName, VfsPath};
use crate::provider::ContentProvider;
use crate::stat::{DirEntry, VirtualStat};
use crate::{VfsError, VfsResult};

/// One admission: every staged write folded into graph truth as one change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Admission {
    /// The change the graph published.
    pub change_id: String,
    /// The branch it published on.
    pub branch: String,
    /// How many files the change carried.
    pub file_count: usize,
    /// The paths this surface had staged when the admission ran.
    pub paths: Vec<VfsPath>,
}

/// What a projection surface reports about its own write path.
///
/// A status probe reads this and nothing else. `Settled` is the only variant
/// that means every write the surface accepted is graph truth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteHealth {
    /// Nothing is staged. Every accepted write reached the graph.
    Settled {
        /// The most recent admission, when this surface has made one.
        last: Option<Admission>,
    },
    /// Writes are staged and an admission is still owed.
    Pending {
        /// The paths waiting to be admitted.
        paths: Vec<VfsPath>,
    },
    /// An admission was attempted and refused. The paths are still staged.
    Degraded {
        /// The paths still waiting.
        paths: Vec<VfsPath>,
        /// Exactly what the admission failed with.
        reason: String,
    },
}

impl WriteHealth {
    /// One lowercase word for a status line: `settled`, `pending`, `degraded`.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Settled { .. } => "settled",
            Self::Pending { .. } => "pending",
            Self::Degraded { .. } => "degraded",
        }
    }

    /// The paths this surface still owes the graph.
    pub fn unadmitted(&self) -> &[VfsPath] {
        match self {
            Self::Settled { .. } => &[],
            Self::Pending { paths } | Self::Degraded { paths, .. } => paths,
        }
    }
}

/// How a staged path differs from what the graph holds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Staged {
    /// This surface holds bytes for the path that the graph has not admitted.
    /// Covers both a new file and an edit to a file the graph already knows.
    Present(VirtualStat),
    /// This surface removed the path. The graph may still list it.
    Removed,
}

/// A surface that can admit writes back into graph-owned truth.
///
/// Implementors own the staging medium and the admission transaction. The
/// surface (NFS, FUSE) owns only when to call [`Self::admit`].
pub trait ContentWriter: Send + Sync {
    /// Replace `data.len()` bytes at `offset` in `path`, extending if needed.
    fn write_at(&self, path: &VfsPath, offset: u64, data: &[u8]) -> VfsResult<VirtualStat>;

    /// Create an empty regular file. With `exclusive`, an existing path is an
    /// error rather than a truncation.
    fn create_file(&self, path: &VfsPath, exclusive: bool) -> VfsResult<VirtualStat>;

    /// Set the length of `path`, truncating or zero-extending.
    fn set_len(&self, path: &VfsPath, size: u64) -> VfsResult<VirtualStat>;

    /// Create a directory.
    fn create_dir(&self, path: &VfsPath) -> VfsResult<VirtualStat>;

    /// Remove a file or an empty directory.
    fn remove(&self, path: &VfsPath) -> VfsResult<()>;

    /// Rename `from` to `to`.
    fn rename(&self, from: &VfsPath, to: &VfsPath) -> VfsResult<()>;

    /// The staged disposition of `path`, or `None` when the graph is
    /// authoritative for it.
    ///
    /// This is the only question [`WriteThroughProvider`] asks before falling
    /// through to the graph, so an implementation that answers `Some` for a
    /// path it did not write turns the staging medium into answer authority.
    fn staged(&self, path: &VfsPath) -> Option<Staged>;

    /// Staged changes to `dir`'s listing: entries this surface added, and names
    /// it removed.
    fn staged_children(&self, dir: &VfsPath) -> (Vec<DirEntry>, Vec<VfsName>);

    /// Read a byte range from a staged path.
    fn read_staged(&self, path: &VfsPath, offset: u64, len: u64) -> VfsResult<Vec<u8>>;

    /// Read a staged symlink's exact target bytes.
    fn read_staged_link(&self, path: &VfsPath) -> VfsResult<Vec<u8>>;

    /// Fold every staged write into graph truth as one change.
    ///
    /// `Ok(None)` means nothing was staged, which is a no-op rather than a
    /// failure: an admission with nothing to carry must not reach the authority
    /// path, because a change that records nothing is refused there anyway.
    ///
    /// Blocking. Callers on an async runtime must move it off the worker.
    fn admit(&self) -> VfsResult<Option<Admission>>;

    /// Whether staged writes have been quiescent for at least `debounce` and an
    /// admission is owed. False when nothing is staged.
    fn admission_due(&self, debounce: Duration) -> bool;

    /// What a status probe should report.
    fn health(&self) -> WriteHealth;
}

/// A [`ContentProvider`] that serves graph truth, overlaid with the writes a
/// [`ContentWriter`] has staged but not yet admitted.
///
/// Read-your-writes for the surface's own writes; graph truth for everything
/// else. A path neither the graph nor the staging area holds stays absent, and
/// a graph error stays a graph error: the overlay is consulted by explicit
/// staged-set membership, never as repair for a miss.
pub struct WriteThroughProvider<P> {
    graph: P,
    writer: Arc<dyn ContentWriter>,
}

impl<P> WriteThroughProvider<P> {
    /// Overlay `writer`'s staged writes on `graph`.
    pub fn new(graph: P, writer: Arc<dyn ContentWriter>) -> Self {
        Self { graph, writer }
    }

    /// The underlying graph provider.
    pub fn graph(&self) -> &P {
        &self.graph
    }

    /// The write side. The surface shares this handle, so what it admits and
    /// what this provider overlays are the same staged set by construction.
    pub fn writer(&self) -> &Arc<dyn ContentWriter> {
        &self.writer
    }
}

impl<P> ContentProvider for WriteThroughProvider<P>
where
    P: ContentProvider,
{
    fn read_file(&self, path: &VfsPath) -> VfsResult<Vec<u8>> {
        match self.writer.staged(path) {
            Some(Staged::Present(stat)) => self.writer.read_staged(path, 0, stat.size),
            Some(Staged::Removed) => Err(VfsError::NotFound {
                path: path.to_string(),
            }),
            None => self.graph.read_file(path),
        }
    }

    fn read_range(&self, path: &VfsPath, offset: u64, len: u64) -> VfsResult<Vec<u8>> {
        match self.writer.staged(path) {
            Some(Staged::Present(_)) => self.writer.read_staged(path, offset, len),
            Some(Staged::Removed) => Err(VfsError::NotFound {
                path: path.to_string(),
            }),
            None => self.graph.read_range(path, offset, len),
        }
    }

    fn stat(&self, path: &VfsPath) -> VfsResult<VirtualStat> {
        match self.writer.staged(path) {
            Some(Staged::Present(stat)) => Ok(stat),
            Some(Staged::Removed) => Err(VfsError::NotFound {
                path: path.to_string(),
            }),
            None => self.graph.stat(path),
        }
    }

    fn read_dir(&self, path: &VfsPath) -> VfsResult<Vec<DirEntry>> {
        let (added, removed) = self.writer.staged_children(path);
        // A directory the graph has never seen exists only in the staging area.
        // Its absence from the graph is not an error to report when this
        // surface created it, and is exactly an error to report otherwise.
        let mut entries = match self.graph.read_dir(path) {
            Ok(entries) => entries,
            Err(error) => {
                let created_here = matches!(self.writer.staged(path), Some(Staged::Present(_)));
                if created_here && matches!(error, VfsError::NotFound { .. }) {
                    Vec::new()
                } else {
                    return Err(error);
                }
            }
        };
        entries.retain(|entry| !removed.contains(&entry.name));
        for entry in added {
            if !entries.iter().any(|existing| existing.name == entry.name) {
                entries.push(entry);
            }
        }
        Ok(entries)
    }

    fn exists(&self, path: &VfsPath) -> VfsResult<bool> {
        match self.writer.staged(path) {
            Some(Staged::Present(_)) => Ok(true),
            Some(Staged::Removed) => Ok(false),
            None => self.graph.exists(path),
        }
    }

    fn read_link(&self, path: &VfsPath) -> VfsResult<Vec<u8>> {
        match self.writer.staged(path) {
            Some(Staged::Present(_)) => self.writer.read_staged_link(path),
            Some(Staged::Removed) => Err(VfsError::NotFound {
                path: path.to_string(),
            }),
            None => self.graph.read_link(path),
        }
    }

    fn version(&self) -> u64 {
        self.graph.version()
    }

    fn begin_lookup_endpoint(&self) {
        self.graph.begin_lookup_endpoint();
    }

    fn finish_lookup_endpoint(&self) -> Option<String> {
        self.graph.finish_lookup_endpoint()
    }
}

/// A [`ContentWriter`] that stages nothing and refuses every mutation.
///
/// Lets a read-only surface use one provider type with the writable one: the
/// overlay is then a compile-time constant rather than a second code path, so a
/// read-only mount and a writable mount cannot drift in how they read.
pub struct NoWrites;

impl NoWrites {
    fn refuse(path: &VfsPath) -> VfsError {
        VfsError::PermissionDenied {
            path: path.to_string(),
        }
    }
}

impl ContentWriter for NoWrites {
    fn write_at(&self, path: &VfsPath, _offset: u64, _data: &[u8]) -> VfsResult<VirtualStat> {
        Err(Self::refuse(path))
    }

    fn create_file(&self, path: &VfsPath, _exclusive: bool) -> VfsResult<VirtualStat> {
        Err(Self::refuse(path))
    }

    fn set_len(&self, path: &VfsPath, _size: u64) -> VfsResult<VirtualStat> {
        Err(Self::refuse(path))
    }

    fn create_dir(&self, path: &VfsPath) -> VfsResult<VirtualStat> {
        Err(Self::refuse(path))
    }

    fn remove(&self, path: &VfsPath) -> VfsResult<()> {
        Err(Self::refuse(path))
    }

    fn rename(&self, from: &VfsPath, _to: &VfsPath) -> VfsResult<()> {
        Err(Self::refuse(from))
    }

    fn staged(&self, _path: &VfsPath) -> Option<Staged> {
        None
    }

    fn staged_children(&self, _dir: &VfsPath) -> (Vec<DirEntry>, Vec<VfsName>) {
        (Vec::new(), Vec::new())
    }

    fn read_staged(&self, path: &VfsPath, _offset: u64, _len: u64) -> VfsResult<Vec<u8>> {
        Err(VfsError::NotFound {
            path: path.to_string(),
        })
    }

    fn read_staged_link(&self, path: &VfsPath) -> VfsResult<Vec<u8>> {
        Err(VfsError::NotFound {
            path: path.to_string(),
        })
    }

    fn admit(&self) -> VfsResult<Option<Admission>> {
        Ok(None)
    }

    fn admission_due(&self, _debounce: Duration) -> bool {
        false
    }

    fn health(&self) -> WriteHealth {
        WriteHealth::Settled { last: None }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stat::FileType;
    use parking_lot::Mutex;
    use std::collections::HashMap;

    fn path(text: &str) -> VfsPath {
        VfsPath::from_utf8(text).unwrap()
    }

    fn name(text: &str) -> VfsName {
        VfsName::from_utf8(text).unwrap()
    }

    fn file_stat(size: u64) -> VirtualStat {
        VirtualStat {
            size,
            is_file: true,
            is_dir: false,
            is_symlink: false,
            mode: 0o644,
            mtime: 0,
            ctime: 0,
            nlink: 1,
            content_hash: None,
        }
    }

    /// A graph that holds two files and counts every read it is asked for, so a
    /// test can prove the overlay did *not* reach it as well as that it did.
    #[derive(Default)]
    struct FakeGraph {
        files: HashMap<VfsPath, Vec<u8>>,
        dirs: HashMap<VfsPath, Vec<DirEntry>>,
        reads: Mutex<Vec<VfsPath>>,
    }

    impl FakeGraph {
        fn with_main() -> Self {
            let mut graph = Self::default();
            graph
                .files
                .insert(path("src/main.rs"), b"graph bytes".to_vec());
            graph.files.insert(path("README.md"), b"readme".to_vec());
            graph.dirs.insert(
                path("src"),
                vec![DirEntry {
                    name: name("main.rs"),
                    file_type: FileType::File,
                }],
            );
            graph
        }
    }

    impl ContentProvider for FakeGraph {
        fn read_file(&self, path: &VfsPath) -> VfsResult<Vec<u8>> {
            self.reads.lock().push(path.clone());
            self.files
                .get(path)
                .cloned()
                .ok_or_else(|| VfsError::NotFound {
                    path: path.to_string(),
                })
        }

        fn read_range(&self, path: &VfsPath, offset: u64, len: u64) -> VfsResult<Vec<u8>> {
            let bytes = self.read_file(path)?;
            let start = (offset as usize).min(bytes.len());
            let end = ((offset + len) as usize).min(bytes.len());
            Ok(bytes[start..end].to_vec())
        }

        fn stat(&self, path: &VfsPath) -> VfsResult<VirtualStat> {
            self.reads.lock().push(path.clone());
            if self.dirs.contains_key(path) {
                return Ok(VirtualStat::directory(0));
            }
            self.files
                .get(path)
                .map(|bytes| file_stat(bytes.len() as u64))
                .ok_or_else(|| VfsError::NotFound {
                    path: path.to_string(),
                })
        }

        fn read_dir(&self, path: &VfsPath) -> VfsResult<Vec<DirEntry>> {
            self.dirs
                .get(path)
                .cloned()
                .ok_or_else(|| VfsError::NotFound {
                    path: path.to_string(),
                })
        }

        fn exists(&self, path: &VfsPath) -> VfsResult<bool> {
            Ok(self.files.contains_key(path) || self.dirs.contains_key(path))
        }

        fn read_link(&self, path: &VfsPath) -> VfsResult<Vec<u8>> {
            Err(VfsError::NotFound {
                path: path.to_string(),
            })
        }
    }

    /// A writer whose staged set is set by the test, and which records every
    /// staged read so a test can prove the overlay never asked.
    #[derive(Default)]
    struct FakeWriter {
        staged: HashMap<VfsPath, Staged>,
        bytes: HashMap<VfsPath, Vec<u8>>,
        staged_reads: Mutex<Vec<VfsPath>>,
    }

    impl FakeWriter {
        fn present(mut self, at: &str, bytes: &[u8]) -> Self {
            self.staged
                .insert(path(at), Staged::Present(file_stat(bytes.len() as u64)));
            self.bytes.insert(path(at), bytes.to_vec());
            self
        }

        fn present_dir(mut self, at: &str) -> Self {
            let mut stat = file_stat(0);
            stat.is_file = false;
            stat.is_dir = true;
            self.staged.insert(path(at), Staged::Present(stat));
            self
        }

        fn removed(mut self, at: &str) -> Self {
            self.staged.insert(path(at), Staged::Removed);
            self
        }
    }

    impl ContentWriter for FakeWriter {
        fn write_at(&self, _p: &VfsPath, _o: u64, _d: &[u8]) -> VfsResult<VirtualStat> {
            unimplemented!("the overlay under test never mutates")
        }
        fn create_file(&self, _p: &VfsPath, _e: bool) -> VfsResult<VirtualStat> {
            unimplemented!()
        }
        fn set_len(&self, _p: &VfsPath, _s: u64) -> VfsResult<VirtualStat> {
            unimplemented!()
        }
        fn create_dir(&self, _p: &VfsPath) -> VfsResult<VirtualStat> {
            unimplemented!()
        }
        fn remove(&self, _p: &VfsPath) -> VfsResult<()> {
            unimplemented!()
        }
        fn rename(&self, _f: &VfsPath, _t: &VfsPath) -> VfsResult<()> {
            unimplemented!()
        }

        fn staged(&self, path: &VfsPath) -> Option<Staged> {
            self.staged.get(path).cloned()
        }

        fn staged_children(&self, dir: &VfsPath) -> (Vec<DirEntry>, Vec<VfsName>) {
            let mut added = Vec::new();
            let mut removed = Vec::new();
            for (path, staged) in &self.staged {
                let Some(remainder) = dir.strip_dir_prefix(path) else {
                    continue;
                };
                if remainder.contains(&b'/') {
                    continue;
                }
                let child = VfsName::from_bytes(remainder.to_vec()).unwrap();
                match staged {
                    Staged::Present(stat) => added.push(DirEntry {
                        name: child,
                        file_type: if stat.is_dir {
                            FileType::Directory
                        } else {
                            FileType::File
                        },
                    }),
                    Staged::Removed => removed.push(child),
                }
            }
            (added, removed)
        }

        fn read_staged(&self, path: &VfsPath, offset: u64, len: u64) -> VfsResult<Vec<u8>> {
            self.staged_reads.lock().push(path.clone());
            let bytes = self.bytes.get(path).cloned().ok_or(VfsError::NotFound {
                path: path.to_string(),
            })?;
            let start = (offset as usize).min(bytes.len());
            let end = ((offset + len) as usize).min(bytes.len());
            Ok(bytes[start..end].to_vec())
        }

        fn read_staged_link(&self, path: &VfsPath) -> VfsResult<Vec<u8>> {
            Err(VfsError::NotFound {
                path: path.to_string(),
            })
        }

        fn admit(&self) -> VfsResult<Option<Admission>> {
            Ok(None)
        }
        fn admission_due(&self, _d: Duration) -> bool {
            false
        }
        fn health(&self) -> WriteHealth {
            WriteHealth::Settled { last: None }
        }
    }

    fn overlay(writer: FakeWriter) -> WriteThroughProvider<FakeGraph> {
        WriteThroughProvider::new(FakeGraph::with_main(), Arc::new(writer))
    }

    #[test]
    fn a_staged_edit_is_read_back_instead_of_the_graph_copy() {
        let provider = overlay(FakeWriter::default().present("src/main.rs", b"my edit"));
        assert_eq!(
            provider.read_file(&path("src/main.rs")).unwrap(),
            b"my edit".to_vec()
        );
        assert_eq!(provider.stat(&path("src/main.rs")).unwrap().size, 7);
    }

    #[test]
    fn a_staged_removal_is_absent_even_though_the_graph_still_holds_it() {
        let provider = overlay(FakeWriter::default().removed("README.md"));
        assert!(matches!(
            provider.read_file(&path("README.md")),
            Err(VfsError::NotFound { .. })
        ));
        assert!(!provider.exists(&path("README.md")).unwrap());
    }

    /// The guard that keeps this an admission boundary rather than file-search
    /// authority: a path nothing staged is never looked for in the staging
    /// medium, so a graph miss stays a graph miss.
    ///
    /// The assertion is that the staging medium was **not consulted**, not that
    /// the answer was `NotFound`. A fallback would answer `NotFound` here too,
    /// since the fake writer holds no bytes for this path either, so an
    /// assertion on the error alone passes with the guard removed and proves
    /// nothing. Only the call record can tell the two apart.
    #[test]
    fn an_unstaged_path_is_never_read_from_the_staging_medium() {
        let writer = Arc::new(FakeWriter::default().present("src/main.rs", b"my edit"));
        let provider = WriteThroughProvider::new(
            FakeGraph::with_main(),
            writer.clone() as Arc<dyn ContentWriter>,
        );

        let missing = path("does/not/exist.rs");
        assert!(matches!(
            provider.read_file(&missing),
            Err(VfsError::NotFound { .. })
        ));
        assert!(
            provider.graph().reads.lock().contains(&missing),
            "the graph must be asked"
        );
        assert!(
            writer.staged_reads.lock().is_empty(),
            "the staging medium was consulted for an unstaged path: {:?}",
            writer.staged_reads.lock()
        );
    }

    /// The same guard on the range, stat, and link paths, which a fallback
    /// added to one method at a time would otherwise slip through.
    #[test]
    fn an_unstaged_path_is_not_consulted_on_any_read_shape() {
        let writer = Arc::new(FakeWriter::default().present("src/main.rs", b"my edit"));
        let provider = WriteThroughProvider::new(
            FakeGraph::with_main(),
            writer.clone() as Arc<dyn ContentWriter>,
        );

        let missing = path("does/not/exist.rs");
        let _ = provider.read_range(&missing, 0, 8);
        let _ = provider.stat(&missing);
        let _ = provider.read_link(&missing);
        let _ = provider.exists(&missing);
        assert!(
            writer.staged_reads.lock().is_empty(),
            "the staging medium was consulted: {:?}",
            writer.staged_reads.lock()
        );
    }

    #[test]
    fn a_graph_file_with_nothing_staged_reads_from_the_graph() {
        let provider = overlay(FakeWriter::default().present("other.rs", b"x"));
        assert_eq!(
            provider.read_file(&path("README.md")).unwrap(),
            b"readme".to_vec()
        );
    }

    #[test]
    fn a_listing_adds_staged_children_and_drops_staged_removals() {
        let writer = FakeWriter::default()
            .present("src/new.rs", b"n")
            .removed("src/main.rs");
        let provider = overlay(writer);
        let names: Vec<String> = provider
            .read_dir(&path("src"))
            .unwrap()
            .into_iter()
            .map(|entry| entry.name.to_string())
            .collect();
        assert_eq!(names, vec!["new.rs".to_string()]);
    }

    #[test]
    fn a_directory_the_surface_created_lists_its_staged_children() {
        let writer = FakeWriter::default()
            .present_dir("fresh")
            .present("fresh/a.rs", b"a");
        let provider = overlay(writer);
        let names: Vec<String> = provider
            .read_dir(&path("fresh"))
            .unwrap()
            .into_iter()
            .map(|entry| entry.name.to_string())
            .collect();
        assert_eq!(names, vec!["a.rs".to_string()]);
    }

    #[test]
    fn a_directory_neither_side_holds_is_still_absent() {
        let provider = overlay(FakeWriter::default());
        assert!(matches!(
            provider.read_dir(&path("nowhere")),
            Err(VfsError::NotFound { .. })
        ));
    }

    #[test]
    fn a_deeper_descendant_is_not_a_direct_child() {
        let writer = FakeWriter::default().present("src/deep/nested.rs", b"d");
        let provider = overlay(writer);
        let names: Vec<String> = provider
            .read_dir(&path("src"))
            .unwrap()
            .into_iter()
            .map(|entry| entry.name.to_string())
            .collect();
        assert_eq!(names, vec!["main.rs".to_string()]);
    }

    #[test]
    fn no_writes_refuses_every_mutation_and_stages_nothing() {
        let writer = NoWrites;
        assert!(writer.write_at(&path("a"), 0, b"x").is_err());
        assert!(writer.create_file(&path("a"), false).is_err());
        assert!(writer.set_len(&path("a"), 0).is_err());
        assert!(writer.create_dir(&path("a")).is_err());
        assert!(writer.remove(&path("a")).is_err());
        assert!(writer.rename(&path("a"), &path("b")).is_err());
        assert!(writer.staged(&path("a")).is_none());
        assert_eq!(writer.admit().unwrap(), None);
        assert!(!writer.admission_due(Duration::from_millis(1)));
        assert_eq!(writer.health().label(), "settled");
    }

    #[test]
    fn health_labels_and_unadmitted_paths_agree() {
        assert_eq!(WriteHealth::Settled { last: None }.label(), "settled");
        assert!(WriteHealth::Settled { last: None }.unadmitted().is_empty());
        let pending = WriteHealth::Pending {
            paths: vec![path("a.rs")],
        };
        assert_eq!(pending.label(), "pending");
        assert_eq!(pending.unadmitted(), &[path("a.rs")]);
        let degraded = WriteHealth::Degraded {
            paths: vec![path("a.rs")],
            reason: "refused".into(),
        };
        assert_eq!(degraded.label(), "degraded");
        assert_eq!(degraded.unadmitted(), &[path("a.rs")]);
    }
}
