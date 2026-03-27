// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! kin-vfs-core: Virtual filesystem primitives.
//!
//! Provides the `ContentProvider` trait and `VirtualFileTree` for mapping
//! file paths to content served by any backend (blob store, HTTP, in-memory).
//! This crate is standalone-valuable — usable by any project, not just Kin.

pub mod cache;
pub mod error;
pub mod protocol;
pub mod provider;
pub mod stat;
pub mod tree;

pub use error::{VfsError, VfsResult};
pub use provider::ContentProvider;
pub use stat::{DirEntry, FileType, VirtualStat};
pub use tree::VirtualFileTree;
