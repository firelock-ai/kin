// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::path::{Path, PathBuf};
use std::process::Command;

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let root = git(&manifest_dir, &["rev-parse", "--show-toplevel"])
        .map(PathBuf::from)
        .unwrap_or_else(|| manifest_dir.clone());

    if let Some(head) = git(&root, &["rev-parse", "--git-path", "HEAD"]) {
        println!("cargo:rerun-if-changed={head}");
    }
    if let Some(reference) = git(&root, &["symbolic-ref", "-q", "HEAD"]) {
        if let Some(path) = git(&root, &["rev-parse", "--git-path", &reference]) {
            println!("cargo:rerun-if-changed={path}");
        }
    }

    let sha = git(&root, &["rev-parse", "--short=12", "HEAD"]).unwrap_or_else(|| "unknown".into());
    let branch = git(&root, &["branch", "--show-current"])
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "detached".into());
    let dirty = git(&root, &["status", "--porcelain"])
        .map(|value| !value.is_empty())
        .unwrap_or(false);
    let built_at = Command::new("date")
        .args(["-u", "+%Y-%m-%dT%H:%M:%SZ"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown".into());
    let sha_display = if dirty && sha != "unknown" {
        format!("{sha}-dirty")
    } else {
        sha.clone()
    };
    let package_version = std::env::var("CARGO_PKG_VERSION").unwrap_or_else(|_| "0.0.0".into());
    let version = format!("{package_version} ({sha_display} {branch} {built_at})");

    println!("cargo:rustc-env=KIN_BUILD_GIT_SHA={sha}");
    println!("cargo:rustc-env=KIN_BUILD_DIRTY={dirty}");
    println!("cargo:rustc-env=KIN_BUILD_BRANCH={branch}");
    println!("cargo:rustc-env=KIN_BUILD_TIME={built_at}");
    println!("cargo:rustc-env=KIN_BUILD_VERSION={version}");
}

fn git(cwd: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let value = String::from_utf8_lossy(&output.stdout).trim().to_string();
    (!value.is_empty()).then_some(value)
}
