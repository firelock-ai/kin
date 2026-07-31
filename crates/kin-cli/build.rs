// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Give the Windows `kin` binaries a main thread that can parse their own
//! command tree.
//!
//! Windows reserves 1 MiB for a binary's main thread where Unix reserves 8, and
//! it is fixed at link time rather than raised at runtime. Building the command
//! tree recurses over every subcommand, and this crate's own tests already run
//! that recursion on a dedicated 16 MiB thread because the 2 MiB a test thread
//! gets is not enough. So an unoptimized Windows build overflows before `main`
//! reaches any command at all, including `--version`, and an optimized one
//! survives only on smaller frames, one command-tree growth away from the same
//! cliff.
//!
//! Reserved address space is not committed memory, so matching the 16 MiB the
//! tests already use costs nothing at runtime and removes the cliff from both
//! profiles.
//!
//! This has to be a link argument emitted here rather than `rustflags` in
//! `.cargo/config.toml`: a `RUSTFLAGS` value in the environment replaces the
//! config key outright, and CI sets `RUSTFLAGS` for every job.

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("msvc") {
        println!("cargo::rustc-link-arg-bins=/STACK:16777216");
    }
}
