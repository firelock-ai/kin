// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! kin-vfs-core: Virtual filesystem primitives.
//!
//! Provides the `ContentProvider` trait and `VirtualFileTree` for mapping
//! byte-exact file paths to content served by any backend (blob store, HTTP,
//! in-memory). Path identity is [`VfsPath`]/[`VfsName`] — validated raw bytes,
//! never `String` — so any name a Unix filesystem allows is preserved exactly.
//! This crate is standalone-valuable — usable by any project, not just Kin.

pub mod cache;
pub mod canary;
pub mod error;
pub mod path;
pub mod pathmap;
pub mod protocol;
pub mod provider;
pub mod stat;
pub mod tree;

pub use canary::{CanaryRegistry, InterposeStatus};
pub use error::{VfsError, VfsResult};
pub use path::{VfsName, VfsPath, VfsPathError};
pub use provider::{AsyncContentProvider, ContentProvider};
pub use stat::{DirEntry, FileType, VirtualStat};
pub use tree::VirtualFileTree;
