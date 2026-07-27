// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use crate::cache::{CachedEntry, VfsCache};
use crate::error::VfsError;
use crate::path::VfsPath;
use crate::provider::ContentProvider;
use crate::stat::{DirEntry, VirtualStat};
use crate::VfsResult;

/// A virtual file tree that maps absolute host paths to content via a
/// ContentProvider. Maintains an LRU cache for hot files.
///
/// Host paths are byte-exact (`&[u8]`): on Unix they come from `OsStr`/`CStr`
/// bytes and may not be UTF-8. The workspace root is stored as exact bytes and
/// containment is checked byte-wise with a separator guard.
pub struct VirtualFileTree<P: ContentProvider> {
    provider: P,
    cache: VfsCache,
    workspace_root: Vec<u8>,
}

impl<P: ContentProvider> VirtualFileTree<P> {
    pub fn new(provider: P, workspace_root: impl Into<Vec<u8>>, cache_capacity: usize) -> Self {
        let mut workspace_root = workspace_root.into();
        while workspace_root.len() > 1 && workspace_root.last() == Some(&b'/') {
            workspace_root.pop();
        }
        Self {
            provider,
            cache: VfsCache::new(cache_capacity),
            workspace_root,
        }
    }

    /// Check if an absolute host path falls within this workspace.
    pub fn is_workspace_path(&self, path: &[u8]) -> bool {
        self.relative_path(path).is_some()
    }

    /// Convert an absolute host path to a validated workspace-relative path.
    fn relative_path(&self, path: &[u8]) -> Option<VfsPath> {
        if !path.starts_with(&self.workspace_root) {
            return None;
        }
        let rest = &path[self.workspace_root.len()..];
        if rest.is_empty() {
            return Some(VfsPath::root());
        }
        if rest[0] != b'/' {
            return None;
        }
        let mut rest = &rest[1..];
        while rest.last() == Some(&b'/') {
            rest = &rest[..rest.len() - 1];
        }
        VfsPath::from_bytes(rest.to_vec()).ok()
    }

    fn require_relative(&self, abs_path: &[u8]) -> VfsResult<VfsPath> {
        self.relative_path(abs_path)
            .ok_or_else(|| VfsError::NotFound {
                path: String::from_utf8_lossy(abs_path).into_owned(),
            })
    }

    /// Get metadata for an absolute host path.
    pub fn stat(&self, abs_path: &[u8]) -> VfsResult<VirtualStat> {
        let rel = self.require_relative(abs_path)?;
        let provider_version = self.provider.version();

        // Cache entries are valid only for the exact provider snapshot that
        // produced them. The provider's monotonic version is graph authority;
        // filesystem metadata never participates in freshness.
        if let Some(entry) = self.cache.get(&rel, provider_version) {
            return match entry {
                CachedEntry::Stat(s) | CachedEntry::Content { stat: s, .. } => Ok(s),
            };
        }

        let stat = self.provider.stat(&rel)?;
        self.cache
            .put(rel, provider_version, CachedEntry::Stat(stat.clone()));
        Ok(stat)
    }

    /// Read file content for an absolute host path.
    pub fn read(&self, abs_path: &[u8]) -> VfsResult<Vec<u8>> {
        let rel = self.require_relative(abs_path)?;
        let provider_version = self.provider.version();

        // Check cache for content
        if let Some(CachedEntry::Content { data, .. }) = self.cache.get(&rel, provider_version) {
            return Ok(data);
        }

        let data = self.provider.read_file(&rel)?;
        let stat = self.provider.stat(&rel)?;
        self.cache.put(
            rel,
            provider_version,
            CachedEntry::Content {
                stat,
                data: data.clone(),
            },
        );
        Ok(data)
    }

    /// Read a byte range for an absolute host path.
    pub fn read_range(&self, abs_path: &[u8], offset: u64, len: u64) -> VfsResult<Vec<u8>> {
        let rel = self.require_relative(abs_path)?;
        let provider_version = self.provider.version();

        // If we have the full content cached, slice it
        if let Some(CachedEntry::Content { data, .. }) = self.cache.get(&rel, provider_version) {
            let start = offset as usize;
            let end = (offset + len) as usize;
            if start >= data.len() {
                return Ok(Vec::new());
            }
            let end = end.min(data.len());
            return Ok(data[start..end].to_vec());
        }

        self.provider.read_range(&rel, offset, len)
    }

    /// List directory entries for an absolute host path.
    pub fn list_dir(&self, abs_path: &[u8]) -> VfsResult<Vec<DirEntry>> {
        let rel = self.require_relative(abs_path)?;
        self.provider.read_dir(&rel)
    }

    /// Read a symbolic link target as its exact graph-owned bytes.
    pub fn read_link(&self, abs_path: &[u8]) -> VfsResult<Vec<u8>> {
        let rel = self.require_relative(abs_path)?;
        self.provider.read_link(&rel)
    }

    /// Check if an absolute host path exists in the virtual tree.
    pub fn exists(&self, abs_path: &[u8]) -> VfsResult<bool> {
        let rel = match self.relative_path(abs_path) {
            Some(r) => r,
            None => return Ok(false),
        };
        self.provider.exists(&rel)
    }

    /// Invalidate cached entries for specific workspace-relative paths.
    pub fn invalidate(&self, paths: &[VfsPath]) {
        self.cache.invalidate(paths);
    }

    /// Invalidate all cached entries.
    pub fn invalidate_all(&self) {
        self.cache.invalidate_all();
    }

    /// Get the workspace root bytes.
    pub fn workspace_root(&self) -> &[u8] {
        &self.workspace_root
    }

    /// Access the underlying provider.
    pub fn provider(&self) -> &P {
        &self.provider
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::path::VfsName;
    use crate::stat::FileType;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::RwLock;

    /// In-memory provider for testing, keyed by byte-exact paths.
    struct MemoryProvider {
        files: HashMap<VfsPath, Vec<u8>>,
    }

    impl MemoryProvider {
        fn new(files: Vec<(&[u8], &[u8])>) -> Self {
            Self {
                files: files
                    .into_iter()
                    .map(|(k, v)| (VfsPath::from_bytes(k.to_vec()).unwrap(), v.to_vec()))
                    .collect(),
            }
        }

        fn directories(&self) -> std::collections::HashSet<VfsPath> {
            let mut dirs = std::collections::HashSet::new();
            dirs.insert(VfsPath::root());
            for path in self.files.keys() {
                let mut current = path.parent();
                while let Some(dir) = current {
                    current = dir.parent();
                    dirs.insert(dir);
                }
            }
            dirs
        }
    }

    impl ContentProvider for MemoryProvider {
        fn read_file(&self, path: &VfsPath) -> VfsResult<Vec<u8>> {
            self.files
                .get(path)
                .cloned()
                .ok_or_else(|| VfsError::NotFound {
                    path: path.to_string(),
                })
        }

        fn read_range(&self, path: &VfsPath, offset: u64, len: u64) -> VfsResult<Vec<u8>> {
            let data = self.read_file(path)?;
            let start = offset as usize;
            let end = (offset + len) as usize;
            if start >= data.len() {
                return Ok(Vec::new());
            }
            Ok(data[start..end.min(data.len())].to_vec())
        }

        fn stat(&self, path: &VfsPath) -> VfsResult<VirtualStat> {
            if let Some(data) = self.files.get(path) {
                Ok(VirtualStat::regular_file(
                    data.len() as u64,
                    [0u8; 32],
                    false,
                    0,
                ))
            } else if self.directories().contains(path) {
                Ok(VirtualStat::directory(0))
            } else {
                Err(VfsError::NotFound {
                    path: path.to_string(),
                })
            }
        }

        fn read_dir(&self, path: &VfsPath) -> VfsResult<Vec<DirEntry>> {
            let mut entries = std::collections::HashSet::new();
            for file_path in self.files.keys() {
                let rest = if path.is_root() {
                    file_path.as_bytes()
                } else if let Some(rest) = path.strip_dir_prefix(file_path) {
                    rest
                } else {
                    continue;
                };
                let (name, is_dir) = match rest.iter().position(|byte| *byte == b'/') {
                    Some(position) => (&rest[..position], true),
                    None => (rest, false),
                };
                let file_type = if is_dir {
                    FileType::Directory
                } else {
                    FileType::File
                };
                entries.insert((VfsName::from_bytes(name.to_vec()).unwrap(), file_type));
            }

            Ok(entries
                .into_iter()
                .map(|(name, file_type)| DirEntry { name, file_type })
                .collect())
        }

        fn exists(&self, path: &VfsPath) -> VfsResult<bool> {
            Ok(self.files.contains_key(path) || self.directories().contains(path))
        }

        fn read_link(&self, path: &VfsPath) -> VfsResult<Vec<u8>> {
            Err(VfsError::NotFound {
                path: path.to_string(),
            })
        }
    }

    struct VersionedMemoryProvider {
        files: RwLock<HashMap<VfsPath, Vec<u8>>>,
        version: AtomicU64,
    }

    impl VersionedMemoryProvider {
        fn new(path: &[u8], data: &[u8]) -> Self {
            Self {
                files: RwLock::new(HashMap::from([(
                    VfsPath::from_bytes(path.to_vec()).unwrap(),
                    data.to_vec(),
                )])),
                version: AtomicU64::new(1),
            }
        }

        fn replace(&self, path: &[u8], data: &[u8]) {
            self.files
                .write()
                .unwrap()
                .insert(VfsPath::from_bytes(path.to_vec()).unwrap(), data.to_vec());
            self.version.fetch_add(1, Ordering::SeqCst);
        }
    }

    impl ContentProvider for VersionedMemoryProvider {
        fn read_file(&self, path: &VfsPath) -> VfsResult<Vec<u8>> {
            self.files
                .read()
                .unwrap()
                .get(path)
                .cloned()
                .ok_or_else(|| VfsError::NotFound {
                    path: path.to_string(),
                })
        }

        fn read_range(&self, path: &VfsPath, offset: u64, len: u64) -> VfsResult<Vec<u8>> {
            let data = self.read_file(path)?;
            let start = usize::try_from(offset).unwrap_or(usize::MAX);
            if start >= data.len() {
                return Ok(Vec::new());
            }
            let end = usize::try_from(offset.saturating_add(len))
                .unwrap_or(usize::MAX)
                .min(data.len());
            Ok(data[start..end].to_vec())
        }

        fn stat(&self, path: &VfsPath) -> VfsResult<VirtualStat> {
            if path.is_root() {
                return Ok(VirtualStat::directory(self.version()));
            }
            let data = self
                .files
                .read()
                .unwrap()
                .get(path)
                .cloned()
                .ok_or_else(|| VfsError::NotFound {
                    path: path.to_string(),
                })?;
            Ok(VirtualStat::regular_file(
                data.len() as u64,
                [0; 32],
                false,
                self.version(),
            ))
        }

        fn read_dir(&self, path: &VfsPath) -> VfsResult<Vec<DirEntry>> {
            if !path.is_root() {
                return Err(VfsError::NotDirectory {
                    path: path.to_string(),
                });
            }
            let mut entries: Vec<_> = self
                .files
                .read()
                .unwrap()
                .keys()
                .map(|path| DirEntry {
                    name: VfsName::from_bytes(path.file_name().unwrap().to_vec()).unwrap(),
                    file_type: FileType::File,
                })
                .collect();
            entries.sort_by(|left, right| left.name.as_bytes().cmp(right.name.as_bytes()));
            Ok(entries)
        }

        fn exists(&self, path: &VfsPath) -> VfsResult<bool> {
            Ok(path.is_root() || self.files.read().unwrap().contains_key(path))
        }

        fn read_link(&self, path: &VfsPath) -> VfsResult<Vec<u8>> {
            Err(VfsError::InvalidInput {
                path: path.to_string(),
            })
        }

        fn version(&self) -> u64 {
            self.version.load(Ordering::SeqCst)
        }
    }

    #[test]
    fn read_file_from_memory_provider() {
        let provider = MemoryProvider::new(vec![
            (b"src/main.rs", b"fn main() {}"),
            (b"Cargo.toml", b"[package]\nname = \"test\""),
        ]);
        let tree = VirtualFileTree::new(provider, b"/workspace".to_vec(), 100);

        let content = tree.read(b"/workspace/src/main.rs").unwrap();
        assert_eq!(content, b"fn main() {}");
    }

    #[test]
    fn stat_file_returns_correct_metadata() {
        let provider = MemoryProvider::new(vec![(b"file.txt", b"hello world")]);
        let tree = VirtualFileTree::new(provider, b"/ws".to_vec(), 100);

        let stat = tree.stat(b"/ws/file.txt").unwrap();
        assert!(stat.is_file);
        assert!(!stat.is_dir);
        assert_eq!(stat.size, 11);
    }

    #[test]
    fn stat_directory_works() {
        let provider = MemoryProvider::new(vec![(b"src/lib.rs", b"// lib")]);
        let tree = VirtualFileTree::new(provider, b"/ws".to_vec(), 100);

        let stat = tree.stat(b"/ws/src").unwrap();
        assert!(stat.is_dir);
        assert!(!stat.is_file);
    }

    #[test]
    fn non_workspace_path_returns_not_found() {
        let provider = MemoryProvider::new(vec![(b"file.txt", b"data")]);
        let tree = VirtualFileTree::new(provider, b"/ws".to_vec(), 100);

        assert!(tree.stat(b"/other/file.txt").is_err());
        // Prefix sibling must not be treated as inside the workspace.
        assert!(tree.stat(b"/wsx/file.txt").is_err());
    }

    #[test]
    fn non_utf8_host_paths_resolve_exactly() {
        let provider = MemoryProvider::new(vec![(b"logs/x-\xff.log".as_slice(), b"raw")]);
        let tree = VirtualFileTree::new(provider, b"/ws".to_vec(), 100);

        assert_eq!(tree.read(b"/ws/logs/x-\xff.log").unwrap(), b"raw");
        assert!(tree.exists(b"/ws/logs/x-\xff.log").unwrap());
        // A different byte in the same position is a different identity.
        assert!(tree.read(b"/ws/logs/x-\xfe.log").is_err());
    }

    #[test]
    fn cache_serves_repeated_reads() {
        let provider = MemoryProvider::new(vec![(b"file.txt", b"cached")]);
        let tree = VirtualFileTree::new(provider, b"/ws".to_vec(), 100);

        let first = tree.read(b"/ws/file.txt").unwrap();
        let second = tree.read(b"/ws/file.txt").unwrap();
        assert_eq!(first, second);
        assert_eq!(first, b"cached");
    }

    #[test]
    fn cache_entries_are_scoped_to_the_exact_provider_version() {
        let provider = VersionedMemoryProvider::new(b"compose.yaml", b"v1");
        let tree = VirtualFileTree::new(provider, b"/ws".to_vec(), 100);

        assert_eq!(tree.read(b"/ws/compose.yaml").unwrap(), b"v1");
        assert_eq!(tree.stat(b"/ws/compose.yaml").unwrap().size, 2);

        tree.provider()
            .replace(b"compose.yaml", b"version-two-exact-bytes");
        tree.provider().replace(b"raw-\xff.bin", b"\x00\xff");

        assert_eq!(
            tree.read(b"/ws/compose.yaml").unwrap(),
            b"version-two-exact-bytes",
            "a stale content entry must not cross the provider-version boundary"
        );
        assert_eq!(
            tree.stat(b"/ws/compose.yaml").unwrap().size,
            b"version-two-exact-bytes".len() as u64,
            "a stale stat entry must not cross the provider-version boundary"
        );
        assert_eq!(
            tree.list_dir(b"/ws")
                .unwrap()
                .into_iter()
                .map(|entry| entry.name.into_bytes())
                .collect::<Vec<_>>(),
            vec![b"compose.yaml".to_vec(), b"raw-\xff.bin".to_vec()]
        );
    }

    #[test]
    fn invalidation_clears_cache() {
        let provider = MemoryProvider::new(vec![(b"file.txt", b"v1")]);
        let tree = VirtualFileTree::new(provider, b"/ws".to_vec(), 100);

        let _ = tree.read(b"/ws/file.txt").unwrap();
        tree.invalidate(&[VfsPath::from_utf8("file.txt").unwrap()]);
        // Next read goes to provider again (cache miss)
        let content = tree.read(b"/ws/file.txt").unwrap();
        assert_eq!(content, b"v1");
    }

    #[test]
    fn read_range_from_cached_content() {
        let provider = MemoryProvider::new(vec![(b"file.txt", b"hello world")]);
        let tree = VirtualFileTree::new(provider, b"/ws".to_vec(), 100);

        // Prime cache
        let _ = tree.read(b"/ws/file.txt").unwrap();

        // Read range from cache
        let range = tree.read_range(b"/ws/file.txt", 6, 5).unwrap();
        assert_eq!(range, b"world");
    }

    #[test]
    fn list_directory_entries() {
        let provider = MemoryProvider::new(vec![
            (b"src/main.rs", b"fn main() {}"),
            (b"src/lib.rs", b"// lib"),
            (b"Cargo.toml", b"[package]"),
        ]);
        let tree = VirtualFileTree::new(provider, b"/ws".to_vec(), 100);

        let mut entries = tree.list_dir(b"/ws/src").unwrap();
        entries.sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name.as_bytes(), b"lib.rs");
        assert_eq!(entries[1].name.as_bytes(), b"main.rs");
    }

    #[test]
    fn exists_checks() {
        let provider = MemoryProvider::new(vec![(b"src/main.rs", b"fn main() {}")]);
        let tree = VirtualFileTree::new(provider, b"/ws".to_vec(), 100);

        assert!(tree.exists(b"/ws/src/main.rs").unwrap());
        assert!(tree.exists(b"/ws/src").unwrap());
        assert!(!tree.exists(b"/ws/nope.rs").unwrap());
        assert!(!tree.exists(b"/other/path").unwrap());
    }
}
