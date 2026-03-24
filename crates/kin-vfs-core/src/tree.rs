// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::path::{Path, PathBuf};

use crate::cache::{CachedEntry, VfsCache};
use crate::error::VfsError;
use crate::provider::ContentProvider;
use crate::stat::{DirEntry, VirtualStat};
use crate::VfsResult;

/// A virtual file tree that maps paths to content via a ContentProvider.
/// Maintains an LRU cache for hot files.
pub struct VirtualFileTree<P: ContentProvider> {
    provider: P,
    cache: VfsCache,
    workspace_root: PathBuf,
}

impl<P: ContentProvider> VirtualFileTree<P> {
    pub fn new(provider: P, workspace_root: PathBuf, cache_capacity: usize) -> Self {
        Self {
            provider,
            cache: VfsCache::new(cache_capacity),
            workspace_root,
        }
    }

    /// Check if an absolute path falls within this workspace.
    pub fn is_workspace_path(&self, path: &str) -> bool {
        Path::new(path).starts_with(&self.workspace_root)
    }

    /// Convert an absolute path to a workspace-relative path.
    fn relative_path<'a>(&self, path: &'a str) -> Option<&'a str> {
        Path::new(path)
            .strip_prefix(&self.workspace_root)
            .ok()
            .and_then(|p| p.to_str())
    }

    /// Get metadata for an absolute path.
    pub fn stat(&self, abs_path: &str) -> VfsResult<VirtualStat> {
        let rel = self.relative_path(abs_path).ok_or_else(|| VfsError::NotFound {
            path: abs_path.to_string(),
        })?;

        // Check cache first
        if let Some(entry) = self.cache.get(rel) {
            return match entry {
                CachedEntry::Stat(s) | CachedEntry::Content { stat: s, .. } => Ok(s),
            };
        }

        let stat = self.provider.stat(rel)?;
        self.cache
            .put(rel.to_string(), CachedEntry::Stat(stat.clone()));
        Ok(stat)
    }

    /// Read file content for an absolute path.
    pub fn read(&self, abs_path: &str) -> VfsResult<Vec<u8>> {
        let rel = self.relative_path(abs_path).ok_or_else(|| VfsError::NotFound {
            path: abs_path.to_string(),
        })?;

        // Check cache for content
        if let Some(CachedEntry::Content { data, .. }) = self.cache.get(rel) {
            return Ok(data);
        }

        let data = self.provider.read_file(rel)?;
        let stat = self.provider.stat(rel)?;
        self.cache.put(
            rel.to_string(),
            CachedEntry::Content {
                stat,
                data: data.clone(),
            },
        );
        Ok(data)
    }

    /// Read a byte range for an absolute path.
    pub fn read_range(&self, abs_path: &str, offset: u64, len: u64) -> VfsResult<Vec<u8>> {
        let rel = self.relative_path(abs_path).ok_or_else(|| VfsError::NotFound {
            path: abs_path.to_string(),
        })?;

        // If we have the full content cached, slice it
        if let Some(CachedEntry::Content { data, .. }) = self.cache.get(rel) {
            let start = offset as usize;
            let end = (offset + len) as usize;
            if start >= data.len() {
                return Ok(Vec::new());
            }
            let end = end.min(data.len());
            return Ok(data[start..end].to_vec());
        }

        self.provider.read_range(rel, offset, len)
    }

    /// List directory entries for an absolute path.
    pub fn list_dir(&self, abs_path: &str) -> VfsResult<Vec<DirEntry>> {
        let rel = self.relative_path(abs_path).ok_or_else(|| VfsError::NotFound {
            path: abs_path.to_string(),
        })?;
        self.provider.read_dir(rel)
    }

    /// Check if an absolute path exists in the virtual tree.
    pub fn exists(&self, abs_path: &str) -> VfsResult<bool> {
        let rel = match self.relative_path(abs_path) {
            Some(r) => r,
            None => return Ok(false),
        };
        self.provider.exists(rel)
    }

    /// Invalidate cached entries for specific paths.
    pub fn invalidate(&self, paths: &[String]) {
        self.cache.invalidate(paths);
    }

    /// Invalidate all cached entries.
    pub fn invalidate_all(&self) {
        self.cache.invalidate_all();
    }

    /// Get the workspace root path.
    pub fn workspace_root(&self) -> &Path {
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
    use crate::stat::FileType;
    use std::collections::HashMap;

    /// In-memory provider for testing.
    struct MemoryProvider {
        files: HashMap<String, Vec<u8>>,
    }

    impl MemoryProvider {
        fn new(files: Vec<(&str, &[u8])>) -> Self {
            Self {
                files: files
                    .into_iter()
                    .map(|(k, v)| (k.to_string(), v.to_vec()))
                    .collect(),
            }
        }

        fn directories(&self) -> std::collections::HashSet<String> {
            let mut dirs = std::collections::HashSet::new();
            dirs.insert(String::new()); // root
            for path in self.files.keys() {
                let mut current = String::new();
                for component in Path::new(path).parent().into_iter().flat_map(|p| p.components()) {
                    if !current.is_empty() {
                        current.push('/');
                    }
                    current.push_str(&component.as_os_str().to_string_lossy());
                    dirs.insert(current.clone());
                }
            }
            dirs
        }
    }

    impl ContentProvider for MemoryProvider {
        fn read_file(&self, path: &str) -> VfsResult<Vec<u8>> {
            self.files
                .get(path)
                .cloned()
                .ok_or_else(|| VfsError::NotFound {
                    path: path.to_string(),
                })
        }

        fn read_range(&self, path: &str, offset: u64, len: u64) -> VfsResult<Vec<u8>> {
            let data = self.read_file(path)?;
            let start = offset as usize;
            let end = (offset + len) as usize;
            if start >= data.len() {
                return Ok(Vec::new());
            }
            Ok(data[start..end.min(data.len())].to_vec())
        }

        fn stat(&self, path: &str) -> VfsResult<VirtualStat> {
            if let Some(data) = self.files.get(path) {
                Ok(VirtualStat::file(data.len() as u64, [0u8; 32], 0))
            } else if self.directories().contains(path) {
                Ok(VirtualStat::directory(0))
            } else {
                Err(VfsError::NotFound {
                    path: path.to_string(),
                })
            }
        }

        fn read_dir(&self, path: &str) -> VfsResult<Vec<DirEntry>> {
            let prefix = if path.is_empty() {
                String::new()
            } else {
                format!("{}/", path)
            };

            let mut entries = std::collections::HashSet::new();
            for file_path in self.files.keys() {
                if let Some(rest) = file_path.strip_prefix(&prefix) {
                    let name = rest.split('/').next().unwrap_or(rest);
                    let full = format!("{}{}", prefix, name);
                    let ft = if self.files.contains_key(&full) {
                        FileType::File
                    } else {
                        FileType::Directory
                    };
                    entries.insert((name.to_string(), ft));
                } else if prefix.is_empty() {
                    let name = file_path.split('/').next().unwrap_or(file_path);
                    let ft = if self.files.contains_key(name) {
                        FileType::File
                    } else {
                        FileType::Directory
                    };
                    entries.insert((name.to_string(), ft));
                }
            }

            Ok(entries
                .into_iter()
                .map(|(name, file_type)| DirEntry { name, file_type })
                .collect())
        }

        fn exists(&self, path: &str) -> VfsResult<bool> {
            Ok(self.files.contains_key(path) || self.directories().contains(path))
        }
    }

    #[test]
    fn read_file_from_memory_provider() {
        let provider = MemoryProvider::new(vec![
            ("src/main.rs", b"fn main() {}"),
            ("Cargo.toml", b"[package]\nname = \"test\""),
        ]);
        let tree = VirtualFileTree::new(provider, PathBuf::from("/workspace"), 100);

        let content = tree.read("/workspace/src/main.rs").unwrap();
        assert_eq!(content, b"fn main() {}");
    }

    #[test]
    fn stat_file_returns_correct_metadata() {
        let provider = MemoryProvider::new(vec![("file.txt", b"hello world")]);
        let tree = VirtualFileTree::new(provider, PathBuf::from("/ws"), 100);

        let stat = tree.stat("/ws/file.txt").unwrap();
        assert!(stat.is_file);
        assert!(!stat.is_dir);
        assert_eq!(stat.size, 11);
    }

    #[test]
    fn stat_directory_works() {
        let provider = MemoryProvider::new(vec![("src/lib.rs", b"// lib")]);
        let tree = VirtualFileTree::new(provider, PathBuf::from("/ws"), 100);

        let stat = tree.stat("/ws/src").unwrap();
        assert!(stat.is_dir);
        assert!(!stat.is_file);
    }

    #[test]
    fn non_workspace_path_returns_not_found() {
        let provider = MemoryProvider::new(vec![("file.txt", b"data")]);
        let tree = VirtualFileTree::new(provider, PathBuf::from("/ws"), 100);

        assert!(tree.stat("/other/file.txt").is_err());
    }

    #[test]
    fn cache_serves_repeated_reads() {
        let provider = MemoryProvider::new(vec![("file.txt", b"cached")]);
        let tree = VirtualFileTree::new(provider, PathBuf::from("/ws"), 100);

        let first = tree.read("/ws/file.txt").unwrap();
        let second = tree.read("/ws/file.txt").unwrap();
        assert_eq!(first, second);
        assert_eq!(first, b"cached");
    }

    #[test]
    fn invalidation_clears_cache() {
        let provider = MemoryProvider::new(vec![("file.txt", b"v1")]);
        let tree = VirtualFileTree::new(provider, PathBuf::from("/ws"), 100);

        let _ = tree.read("/ws/file.txt").unwrap();
        tree.invalidate(&["file.txt".to_string()]);
        // Next read goes to provider again (cache miss)
        let content = tree.read("/ws/file.txt").unwrap();
        assert_eq!(content, b"v1");
    }

    #[test]
    fn read_range_from_cached_content() {
        let provider = MemoryProvider::new(vec![("file.txt", b"hello world")]);
        let tree = VirtualFileTree::new(provider, PathBuf::from("/ws"), 100);

        // Prime cache
        let _ = tree.read("/ws/file.txt").unwrap();

        // Read range from cache
        let range = tree.read_range("/ws/file.txt", 6, 5).unwrap();
        assert_eq!(range, b"world");
    }

    #[test]
    fn list_directory_entries() {
        let provider = MemoryProvider::new(vec![
            ("src/main.rs", b"fn main() {}"),
            ("src/lib.rs", b"// lib"),
            ("Cargo.toml", b"[package]"),
        ]);
        let tree = VirtualFileTree::new(provider, PathBuf::from("/ws"), 100);

        let mut entries = tree.list_dir("/ws/src").unwrap();
        entries.sort_by(|a, b| a.name.cmp(&b.name));
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "lib.rs");
        assert_eq!(entries[1].name, "main.rs");
    }

    #[test]
    fn exists_checks() {
        let provider = MemoryProvider::new(vec![("src/main.rs", b"fn main() {}")]);
        let tree = VirtualFileTree::new(provider, PathBuf::from("/ws"), 100);

        assert!(tree.exists("/ws/src/main.rs").unwrap());
        assert!(tree.exists("/ws/src").unwrap());
        assert!(!tree.exists("/ws/nope.rs").unwrap());
        assert!(!tree.exists("/other/path").unwrap());
    }
}
