// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Wire protocol types for VFS shim ↔ daemon communication.
//!
//! This is the single source of truth. Both `kin-vfs-daemon` and `kin-vfs-shim`
//! re-export these types rather than defining their own copies.
//!
//! Path identity on this protocol is byte-exact: every request path is a
//! validated [`VfsPath`], every directory-entry name a validated
//! [`crate::path::VfsName`], and invalidation pushes carry canonical path
//! bytes. Malformed paths (absolute, `.`/`..`, NUL, empty components) are
//! rejected at decode time.

use crate::canary::InterposeStatus;
use crate::path::VfsPath;
use crate::{DirEntry, VirtualStat};
use serde::{Deserialize, Serialize};

/// Protocol version. Bump when making breaking wire-format changes.
///
/// v3: byte-exact path authority — request paths and directory-entry names
/// are raw validated bytes (no `String` path identity), invalidations carry
/// canonical path bytes, and `ErrorCode::UnsupportedBoundary` reports gitlink
/// repository boundaries.
pub const VFS_PROTOCOL_VERSION: u32 = 3;

/// Request from VFS shim to daemon.
#[derive(Debug, Serialize, Deserialize)]
pub enum VfsRequest {
    /// Get metadata for a repo-relative graph path (root is the empty path).
    Stat { path: VfsPath },

    /// List directory contents for a repo-relative graph path.
    ReadDir { path: VfsPath },

    /// Read file content (full or range) by repo-relative graph path.
    Read {
        path: VfsPath,
        offset: u64,
        len: u64,
    },

    /// Read symbolic link target by repo-relative graph path.
    ReadLink { path: VfsPath },

    /// Check if a repo-relative graph path is accessible.
    Access { path: VfsPath, mode: u32 },

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

    /// A launcher registers, before it starts a child under interposition, that
    /// it expects `token` to be announced. Recorded in the daemon's canary
    /// registry so a never-confirmed token reads back as stripped.
    CanaryExpect { token: String },

    /// A launcher queries the interposition verdict for a token it previously
    /// expected (after the child has run). The daemon answers with
    /// [`VfsResponse::CanaryStatus`].
    CanaryVerdict { token: String },

    /// The shim reports that a workspace-owned path was answered by the real
    /// filesystem through `surface`, a libc entry point interposition does not
    /// route through the graph. Loading is not enough to make a run
    /// graph-native, so this is what keeps the verdict falsifiable: a run whose
    /// shim loaded perfectly still reads back as
    /// [`InterposeStatus::Bypassed`] once a surface is reported.
    ///
    /// Appended last: this enum is the shim/daemon wire format, and a new
    /// variant in the middle would renumber the ones a peer already decodes.
    CanaryBypass { token: String, surface: String },

    /// A launcher asks which surfaces were reported for a token, so its
    /// diagnostic can name them instead of telling the operator only that
    /// something bypassed. Answered with [`VfsResponse::CanaryBypasses`].
    CanaryBypassSurfaces { token: String },
}

/// Response from daemon to VFS shim.
#[derive(Debug, Serialize, Deserialize)]
pub enum VfsResponse {
    /// Metadata.
    Stat(VirtualStat),

    /// Directory listing with byte-exact entry names.
    DirEntries(Vec<DirEntry>),

    /// File content (or range).
    Content { data: Vec<u8>, total_size: u64 },

    /// Symlink target (exact stored bytes).
    LinkTarget(Vec<u8>),

    /// Access check result.
    Accessible(bool),

    /// Pong.
    Pong,

    /// Error.
    Error { code: ErrorCode, message: String },

    /// Push invalidation from daemon to shim, carrying canonical path bytes.
    /// An empty list means "everything may have changed".
    Invalidate { paths: Vec<VfsPath> },

    /// Acknowledge an interposition canary [`VfsRequest::Announce`] or
    /// [`VfsRequest::CanaryExpect`].
    Announced,

    /// Interposition verdict for a [`VfsRequest::CanaryVerdict`] query.
    CanaryStatus(InterposeStatus),

    /// Surfaces reported as having served a workspace path from raw disk, in
    /// stable order. Appended last, for the same wire-compatibility reason as
    /// [`VfsRequest::CanaryBypass`].
    CanaryBypasses(Vec<String>),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ErrorCode {
    NotFound,
    PermissionDenied,
    IsDirectory,
    NotDirectory,
    InvalidInput,
    /// The path names a nested-repository (gitlink) boundary with no child
    /// projection; its contents cannot be served without fabricating state.
    UnsupportedBoundary,
    IoError,
    Internal,
}
