// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Wire protocol types for VFS shim ↔ daemon communication.
//!
//! This is the single source of truth. Both `kin-vfs-daemon` and `kin-vfs-shim`
//! re-export these types rather than defining their own copies.

use crate::{DirEntry, VirtualStat};
use serde::{Deserialize, Serialize};

/// Protocol version. Bump when making breaking wire-format changes.
pub const VFS_PROTOCOL_VERSION: u32 = 1;

/// Request from VFS shim to daemon.
#[derive(Debug, Serialize, Deserialize)]
pub enum VfsRequest {
    /// Get metadata for a path.
    Stat { path: String },

    /// List directory contents.
    ReadDir { path: String },

    /// Read file content (full or range).
    Read { path: String, offset: u64, len: u64 },

    /// Read symbolic link target.
    ReadLink { path: String },

    /// Check if path is accessible.
    Access { path: String, mode: u32 },

    /// Keepalive ping.
    Ping,

    /// Register for push invalidation events.
    Subscribe,

    /// Interposition canary handshake. Sent once by the shim when it loads and
    /// activates with a `KIN_VFS_CANARY` launch token, so the daemon can record
    /// that this process is genuinely graph-native. A process whose
    /// `DYLD_INSERT_LIBRARIES` / `LD_PRELOAD` was stripped never loads the shim
    /// and therefore never sends this — letting a launcher fail it loud instead
    /// of trusting raw-disk reads as graph truth.
    Announce { pid: u32, token: String },
}

/// Response from daemon to VFS shim.
#[derive(Debug, Serialize, Deserialize)]
pub enum VfsResponse {
    /// Metadata.
    Stat(VirtualStat),

    /// Directory listing.
    DirEntries(Vec<DirEntry>),

    /// File content (or range).
    Content { data: Vec<u8>, total_size: u64 },

    /// Symlink target.
    LinkTarget(String),

    /// Access check result.
    Accessible(bool),

    /// Pong.
    Pong,

    /// Error.
    Error { code: ErrorCode, message: String },

    /// Push invalidation from daemon to shim.
    Invalidate { paths: Vec<String> },

    /// Acknowledge an interposition canary [`VfsRequest::Announce`].
    Announced,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ErrorCode {
    NotFound,
    PermissionDenied,
    IsDirectory,
    NotDirectory,
    IoError,
    Internal,
}
