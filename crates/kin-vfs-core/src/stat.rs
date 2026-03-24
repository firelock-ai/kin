// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VirtualStat {
    pub size: u64,
    pub is_file: bool,
    pub is_dir: bool,
    pub is_symlink: bool,
    /// Unix permissions (0o644 for files, 0o755 for dirs).
    pub mode: u32,
    /// Last modification time (epoch seconds, from graph change timestamp).
    pub mtime: u64,
    /// Creation time (epoch seconds).
    pub ctime: u64,
    /// Number of hard links.
    pub nlink: u64,
    /// SHA-256 content hash for files, None for directories.
    pub content_hash: Option<[u8; 32]>,
}

impl VirtualStat {
    pub fn file(size: u64, content_hash: [u8; 32], mtime: u64) -> Self {
        Self {
            size,
            is_file: true,
            is_dir: false,
            is_symlink: false,
            mode: 0o644,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DirEntry {
    pub name: String,
    pub file_type: FileType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum FileType {
    File,
    Directory,
    Symlink,
}
