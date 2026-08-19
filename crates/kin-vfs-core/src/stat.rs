// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use serde::{Deserialize, Serialize};

use crate::path::VfsName;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VirtualStat {
    pub size: u64,
    pub is_file: bool,
    pub is_dir: bool,
    pub is_symlink: bool,
    /// Unix permissions represented by this graph-owned tree entry.
    pub mode: u32,
    /// Graph-derived modification clock.
    ///
    /// Leaf artifacts carry the projection's epoch-second timestamp.
    /// Directories carry the monotonic repository-authority generation for the
    /// exact descendant membership represented by this stat. That logical
    /// value is deliberately not reconstructed from descendant timestamps:
    /// removing or renaming the newest child must never move directory
    /// metadata backward.
    pub mtime: u64,
    /// Creation/change clock, using the same representation as [`Self::mtime`].
    pub ctime: u64,
    /// Number of hard links.
    pub nlink: u64,
    /// SHA-256 content hash for files, None for directories.
    pub content_hash: Option<[u8; 32]>,
}

impl VirtualStat {
    pub fn regular_file(size: u64, content_hash: [u8; 32], executable: bool, mtime: u64) -> Self {
        Self {
            size,
            is_file: true,
            is_dir: false,
            is_symlink: false,
            mode: if executable { 0o755 } else { 0o644 },
            mtime,
            ctime: mtime,
            nlink: 1,
            content_hash: Some(content_hash),
        }
    }

    pub fn symlink(size: u64, content_hash: [u8; 32], mtime: u64) -> Self {
        Self {
            size,
            is_file: false,
            is_dir: false,
            is_symlink: true,
            mode: 0o777,
            mtime,
            ctime: mtime,
            nlink: 1,
            content_hash: Some(content_hash),
        }
    }

    pub fn directory(mtime: u64) -> Self {
        Self {
            size: 0,
            is_file: false,
            is_dir: true,
            is_symlink: false,
            mode: 0o755,
            mtime,
            ctime: mtime,
            nlink: 2,
            content_hash: None,
        }
    }
}

/// One directory entry with its byte-exact name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirEntry {
    pub name: VfsName,
    pub file_type: FileType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FileType {
    File,
    Directory,
    Symlink,
    /// A nested-repository boundary (Git submodule pointer). Carried
    /// explicitly in listings; per-path operations fail with
    /// [`crate::VfsError::UnsupportedRepositoryBoundary`] unless a child
    /// projection exists.
    Gitlink,
}

#[cfg(test)]
mod tests {
    use super::VirtualStat;

    #[test]
    fn regular_file_mode_preserves_executable_bit() {
        assert_eq!(VirtualStat::regular_file(1, [1; 32], false, 0).mode, 0o644);
        assert_eq!(VirtualStat::regular_file(1, [1; 32], true, 0).mode, 0o755);
    }

    #[test]
    fn symlink_is_not_reported_as_regular_file() {
        let stat = VirtualStat::symlink(7, [2; 32], 0);
        assert!(!stat.is_file);
        assert!(stat.is_symlink);
        assert_eq!(stat.mode, 0o777);
    }
}
