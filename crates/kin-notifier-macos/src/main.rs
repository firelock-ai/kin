// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Kin's macOS notification identity.
//!
//! This binary exists only to be the executable inside `KinNotifier.app`, whose
//! bundle supplies the sender name, icon, and Notification Center grouping that
//! a bare CLI cannot have. See [`macos`] for the implementation.
//!
//! It is built on every platform so the workspace stays uniform, but does
//! nothing outside macOS: the exit code matches "no bundle identity", which is
//! what tells `kin-notify` to use a different backend.

use std::process::ExitCode;

#[cfg(target_os = "macos")]
mod macos;

#[cfg(target_os = "macos")]
fn main() -> ExitCode {
    macos::run()
}

#[cfg(not(target_os = "macos"))]
fn main() -> ExitCode {
    eprintln!("KinNotifier: macOS only; this platform has no bundle identity to post under");
    ExitCode::from(3)
}
