// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The Rust toolchain rust-analyzer reads the standard library from.
//!
//! rust-analyzer resolves calls into `std`, `core` and `alloc` from the
//! `rust-src` component of the toolchain the repository pins in
//! `rust-toolchain.toml` (or `rust-toolchain`), and without a pin from the
//! toolchain rustup selects by default. rustup is read from its files, never
//! run, and never asked to install anything. When that toolchain lacks
//! `rust-src`, Kin fetches the component's archive from static.rust-lang.org,
//! checked against the sha256 the release's channel manifest publishes, and
//! unpacks it as data; rustup's installer scripts in it are never run.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use sha2::Digest;

use super::super::fetch::{download_verified, Fetcher};
use super::super::{python::store as shared, unpack};
use crate::adapters::contract::hex;

/// Where Rust releases are published.
pub const DIST: &str = "https://static.rust-lang.org/dist";

/// The largest `rust-src` archive fetched.
const MAX_ARCHIVE_BYTES: u64 = 256 * 1024 * 1024;

/// The channel `rust-toolchain.toml` or `rust-toolchain` at the root pins,
/// and the file that pins it.
pub fn pinned_channel(root: &Path) -> Option<(String, String)> {
    for file in ["rust-toolchain.toml", "rust-toolchain"] {
        let Ok(text) = std::fs::read_to_string(root.join(file)) else {
            continue;
        };
        let channel = match toml::from_str::<toml::Table>(&text) {
            Ok(table) => table
                .get("toolchain")
                .and_then(|toolchain| toolchain.get("channel"))
                .and_then(toml::Value::as_str)
                .map(str::to_string),
            Err(_) if file == "rust-toolchain" => Some(text.trim().to_string()),
            Err(_) => None,
        };
        if let Some(channel) = channel.filter(|channel| !channel.is_empty()) {
            return Some((channel, file.to_string()));
        }
    }
    None
}

/// The host's target triple, as rustup names toolchain directories.
pub fn host_triple() -> Option<&'static str> {
    Some(match (std::env::consts::ARCH, std::env::consts::OS) {
        ("aarch64", "macos") => "aarch64-apple-darwin",
        ("x86_64", "macos") => "x86_64-apple-darwin",
        ("x86_64", "linux") => "x86_64-unknown-linux-gnu",
        ("aarch64", "linux") => "aarch64-unknown-linux-gnu",
        ("x86_64", "windows") => "x86_64-pc-windows-msvc",
        ("aarch64", "windows") => "aarch64-pc-windows-msvc",
        _ => return None,
    })
}

/// rustup's home: `RUSTUP_HOME`, else `~/.rustup`, when it exists.
pub fn rustup_home(vars: &HashMap<String, String>, home: Option<&Path>) -> Option<PathBuf> {
    vars.get("RUSTUP_HOME")
        .filter(|dir| !dir.is_empty())
        .map(PathBuf::from)
        .or_else(|| home.map(|home| home.join(".rustup")))
        .filter(|dir| dir.join("toolchains").is_dir())
}

/// A channel without the host triple a toolchain directory name carries.
pub fn channel_name(toolchain: &str, triple: &str) -> String {
    toolchain
        .strip_suffix(&format!("-{triple}"))
        .unwrap_or(toolchain)
        .to_string()
}

/// The installed toolchain directory for `channel`, when rustup has one that
/// can run Cargo: a toolchain directory without `cargo` and `rustc` (a
/// minimal install, or one interrupted) cannot load a workspace.
pub fn installed(rustup: &Path, channel: &str, triple: &str) -> Option<PathBuf> {
    let channel = channel_name(channel, triple);
    let executable = |dir: &Path, name: &str| {
        dir.join("bin").join(name).is_file()
            || dir.join("bin").join(format!("{name}.exe")).is_file()
    };
    [format!("{channel}-{triple}"), channel]
        .into_iter()
        .map(|name| rustup.join("toolchains").join(name))
        .find(|dir| {
            dir.join("lib/rustlib").is_dir() && executable(dir, "cargo") && executable(dir, "rustc")
        })
}

/// The toolchain rustup selects when nothing pins one.
pub fn default_toolchain(rustup: &Path) -> Option<String> {
    let text = std::fs::read_to_string(rustup.join("settings.toml")).ok()?;
    let table: toml::Table = toml::from_str(&text).ok()?;
    table.get("default_toolchain")?.as_str().map(str::to_string)
}

/// The standard library source of an installed toolchain, when it has the
/// `rust-src` component.
pub fn library_of(toolchain: &Path) -> Option<PathBuf> {
    let library = toolchain.join("lib/rustlib/src/rust/library");
    library.join("core/src/lib.rs").is_file().then_some(library)
}

/// A release's `rust-src` component, as its channel manifest publishes it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RustSrc {
    /// The release, `1.91.0 (2025-10-30)` style, naming the store directory.
    pub release: String,
    pub url: String,
    pub sha256: String,
}

impl RustSrc {
    /// A directory name for this release.
    pub fn key(&self) -> String {
        self.release
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '.' || c == '-' {
                    c
                } else {
                    '_'
                }
            })
            .collect()
    }
}

/// Read the `rust-src` entry of a channel manifest.
pub fn rust_src_in_manifest(text: &str) -> Result<RustSrc, String> {
    let table: toml::Table =
        toml::from_str(text).map_err(|error| format!("the channel manifest: {error}"))?;
    let date = table
        .get("date")
        .and_then(toml::Value::as_str)
        .unwrap_or("undated");
    let version = table
        .get("pkg")
        .and_then(|pkg| pkg.get("rustc"))
        .and_then(|rustc| rustc.get("version"))
        .and_then(toml::Value::as_str)
        .and_then(|version| version.split_whitespace().next())
        .unwrap_or("unknown");
    let target = table
        .get("pkg")
        .and_then(|pkg| pkg.get("rust-src"))
        .and_then(|src| src.get("target"))
        .and_then(|target| target.get("*"))
        .ok_or("the channel manifest publishes no rust-src")?;
    let field = |key: &str| {
        target
            .get(key)
            .and_then(toml::Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| format!("the channel manifest's rust-src has no {key}"))
    };
    Ok(RustSrc {
        release: format!("{version}-{date}"),
        url: field("url")?,
        sha256: field("hash")?.to_ascii_lowercase(),
    })
}

/// The channel manifest URL for a channel rustup would accept.
pub fn manifest_url(channel: &str) -> String {
    // `nightly-2024-01-01`, `beta-2024-01-01`: a dated channel.
    for base in ["nightly", "beta", "stable"] {
        if let Some(date) = channel.strip_prefix(&format!("{base}-")) {
            if date.len() == 10 && date.as_bytes()[4] == b'-' {
                return format!("{DIST}/{date}/channel-rust-{base}.toml");
            }
        }
    }
    format!("{DIST}/channel-rust-{channel}.toml")
}

/// Where Kin keeps an unpacked `rust-src`.
pub fn store_dir(store: &Path, src: &RustSrc) -> PathBuf {
    store.join("rust-src").join(src.key())
}

/// The library directory of a `rust-src` in Kin's store, when it is there.
pub fn stored_library(store: &Path, src: &RustSrc) -> Option<PathBuf> {
    let library = store_dir(store, src).join("rust/library");
    library.join("core/src/lib.rs").is_file().then_some(library)
}

/// Fetch the channel manifest of `channel`, checked against the sha256
/// published beside it.
pub fn fetch_manifest(fetcher: &dyn Fetcher, channel: &str) -> Result<RustSrc, String> {
    let url = manifest_url(channel);
    let (_, manifest) = fetcher
        .document(&url, "application/toml")
        .map_err(|error| error.to_string())?;
    let (_, published) = fetcher
        .document(&format!("{url}.sha256"), "text/plain")
        .map_err(|error| error.to_string())?;
    let published = String::from_utf8_lossy(&published)
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    let actual = hex(&sha2::Sha256::digest(&manifest));
    if published != actual {
        return Err(format!(
            "{url} hashes to sha256 {actual}, and {url}.sha256 publishes {published}"
        ));
    }
    rust_src_in_manifest(&String::from_utf8_lossy(&manifest))
}

/// Put `src` in Kin's store, checked against its published sha256. Returns
/// the library directory and the bytes downloaded.
pub fn ensure(
    fetcher: &dyn Fetcher,
    store: &Path,
    src: &RustSrc,
) -> Result<(PathBuf, u64), String> {
    if let Some(library) = stored_library(store, src) {
        return Ok((library, 0));
    }
    let unique = shared::unique_suffix();
    let archive = store
        .join("downloads")
        .join(format!("rust-src-{}.{unique}.tar.gz", src.key()));
    let downloaded = download_verified(fetcher, &src.url, &archive, &src.sha256, MAX_ARCHIVE_BYTES)
        .map_err(|error| error.to_string())?;
    let destination = store_dir(store, src);
    let staging = destination.with_file_name(format!(".{}.{unique}.tmp", src.key()));
    let outcome = (|| -> Result<(), String> {
        unpack::untar_gz(&archive, &staging, unpack::TarLayout::DATA)?;
        // `rust-src-<version>/rust-src/lib/rustlib/src/rust/`, beside the
        // installer's own files, which are never run.
        let top = std::fs::read_dir(&staging)
            .map_err(|error| error.to_string())?
            .filter_map(Result::ok)
            .map(|entry| entry.path().join("rust-src/lib/rustlib/src/rust"))
            .find(|dir| dir.join("library/core/src/lib.rs").is_file())
            .ok_or("the archive holds no rust-src/lib/rustlib/src/rust/library")?;
        let kept = staging.join("kept");
        std::fs::create_dir_all(&kept).map_err(|error| error.to_string())?;
        std::fs::rename(&top, kept.join("rust")).map_err(|error| error.to_string())?;
        shared::publish_dir(&kept, &destination)
    })();
    let _ = std::fs::remove_file(&archive);
    let _ = std::fs::remove_dir_all(&staging);
    outcome?;
    let library =
        stored_library(store, src).ok_or_else(|| format!("{} unpacked no library", src.url))?;
    Ok((library, downloaded.bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::repo_scan::Fixture;
    use crate::analysis_env::fetch::testing::FixedFetcher;
    use crate::analysis_env::unpack::testing::write_tar_gz;

    #[test]
    fn the_pin_is_read_from_either_file() {
        let repo = Fixture::new("rust-pin");
        assert!(pinned_channel(&repo.root).is_none());
        repo.write("rust-toolchain", "1.78.0\n");
        assert_eq!(
            pinned_channel(&repo.root),
            Some(("1.78.0".to_string(), "rust-toolchain".to_string()))
        );
        repo.write(
            "rust-toolchain.toml",
            "[toolchain]\nchannel = \"nightly-2024-01-01\"\ncomponents = [\"rust-src\"]\n",
        );
        assert_eq!(pinned_channel(&repo.root).unwrap().0, "nightly-2024-01-01");
    }

    #[test]
    fn manifest_urls_name_dated_and_numbered_channels() {
        assert_eq!(
            manifest_url("1.91.0"),
            "https://static.rust-lang.org/dist/channel-rust-1.91.0.toml"
        );
        assert_eq!(
            manifest_url("nightly-2024-01-01"),
            "https://static.rust-lang.org/dist/2024-01-01/channel-rust-nightly.toml"
        );
        assert_eq!(
            manifest_url("stable"),
            "https://static.rust-lang.org/dist/channel-rust-stable.toml"
        );
    }

    #[test]
    fn installed_toolchains_are_found_by_channel() {
        let rustup = Fixture::new("rustup-home");
        rustup.write("toolchains/1.91.0-aarch64-apple-darwin/lib/rustlib/x", "");
        rustup.write(
            "toolchains/stable-aarch64-apple-darwin/lib/rustlib/src/rust/library/core/src/lib.rs",
            "",
        );
        for toolchain in ["1.91.0", "stable", "1.85"] {
            for tool in ["cargo", "rustc"] {
                if toolchain != "1.85" || tool == "cargo" {
                    rustup.write(
                        &format!("toolchains/{toolchain}-aarch64-apple-darwin/bin/{tool}"),
                        "",
                    );
                }
            }
        }
        rustup.write("toolchains/1.85-aarch64-apple-darwin/lib/rustlib/x", "");
        rustup.write(
            "settings.toml",
            "default_toolchain = \"stable-aarch64-apple-darwin\"\n",
        );
        let triple = "aarch64-apple-darwin";
        let pinned = installed(&rustup.root, "1.91.0", triple).unwrap();
        assert!(library_of(&pinned).is_none(), "no rust-src component");
        let default = default_toolchain(&rustup.root).unwrap();
        let stable = installed(&rustup.root, &default, triple).unwrap();
        assert!(library_of(&stable).is_some());
        assert!(installed(&rustup.root, "1.78.0", triple).is_none());
        assert!(
            installed(&rustup.root, "1.85", triple).is_none(),
            "a toolchain without rustc cannot run Cargo"
        );
    }

    /// The manifest must match its published sha256; the component's archive
    /// must match the manifest; only the library is kept.
    #[test]
    fn rust_src_is_fetched_against_the_published_digests() {
        let store = Fixture::new("rust-src-store");
        let archive = store.root.join("src.tar.gz");
        write_tar_gz(
            &archive,
            &[
                ("rust-src-1.91.0/install.sh", b"#!/bin/sh\nexit 1\n"),
                (
                    "rust-src-1.91.0/rust-src/lib/rustlib/src/rust/library/core/src/lib.rs",
                    b"pub mod option;\n",
                ),
            ],
        );
        let bytes = std::fs::read(&archive).unwrap();
        let sha = hex(&sha2::Sha256::digest(&bytes));
        let manifest = format!(
            "date = \"2025-10-30\"\n[pkg.rustc]\nversion = \"1.91.0 (abc 2025-10-30)\"\n\
             [pkg.rust-src.target.\"*\"]\nurl = \"https://dist.example/rust-src.tar.gz\"\nhash = \"{sha}\"\n"
        );
        let mut fetcher = FixedFetcher::default();
        let url = manifest_url("1.91.0");
        fetcher.documents.insert(
            url.clone(),
            (
                "application/toml".to_string(),
                manifest.clone().into_bytes(),
            ),
        );
        fetcher.documents.insert(
            format!("{url}.sha256"),
            (
                "text/plain".to_string(),
                format!(
                    "{}  channel-rust-1.91.0.toml\n",
                    hex(&sha2::Sha256::digest(manifest.as_bytes()))
                )
                .into_bytes(),
            ),
        );
        fetcher
            .files
            .insert("https://dist.example/rust-src.tar.gz".to_string(), bytes);
        let src = fetch_manifest(&fetcher, "1.91.0").unwrap();
        assert_eq!(src.release, "1.91.0-2025-10-30");
        let (library, downloaded) = ensure(&fetcher, &store.root, &src).unwrap();
        assert!(downloaded > 0);
        assert!(library.join("core/src/lib.rs").is_file());
        assert!(!store_dir(&store.root, &src).join("install.sh").exists());

        fetcher.documents.insert(
            format!("{url}.sha256"),
            (
                "text/plain".to_string(),
                b"00  channel-rust-1.91.0.toml\n".to_vec(),
            ),
        );
        assert!(fetch_manifest(&fetcher, "1.91.0").is_err());
    }
}
