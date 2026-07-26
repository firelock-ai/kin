// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Canonical repository admission primitives.
//!
//! The implementation lives at the durable `kin-db` authority boundary.
//! Indexing callers may preview the same matcher, but they cannot publish an
//! admission verdict or substitute local filesystem state for database-owned
//! policy and CAS bytes.

pub use kin_db::admission::*;
