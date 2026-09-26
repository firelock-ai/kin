// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The Go toolchain gopls loads packages with.
//!
//! gopls runs the `go` command to load every package, and the `go` command
//! refuses a module whose `go` line names a newer Go than itself. So the
//! toolchain is chosen from `go.mod`: the installed Go when it is at least the
//! `go` line, and otherwise the version the `toolchain` line names (or the
//! `go` line itself), fetched from go.dev and checked against the sha256
//! go.dev publishes for that file. The installed Go is read from its `VERSION`
//! file, never run.

use std::path::{Path, PathBuf};

use super::super::fetch::{download_verified, Fetcher};
use super::super::python::store as shared;
use super::super::unpack;

/// go.dev's list of every release and its files, with their digests.
pub const RELEASES_URL: &str = "https://go.dev/dl/?mode=json&include=all";

/// Where release files are downloaded from.
pub const DOWNLOAD_BASE: &str = "https://dl.google.com/go";

/// The largest Go distribution archive fetched.
const MAX_ARCHIVE_BYTES: u64 = 512 * 1024 * 1024;

/// A Go version, compared the way the `go` command compares them: `1.21`
/// (a language version) sorts before `1.21rc1`, which sorts before `1.21.0`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct GoVersion {
    major: u32,
    minor: u32,
    /// 0 for a bare language version, 1 for a prerelease, 2 for a release.
    kind: u8,
    /// The prerelease kind (0 beta, 1 rc) and number, or the patch number.
    pre: (u8, u32),
    patch: u32,
}

impl GoVersion {
    /// Parse `1.22`, `1.22.4`, `1.22rc1`, `go1.22.4`.
    pub fn parse(text: &str) -> Option<Self> {
        let text = text.trim().trim_start_matches("go");
        let mut parts = text.splitn(3, '.');
        let major: u32 = parts.next()?.parse().ok()?;
        let minor_text = parts.next().unwrap_or("0");
        let digits: String = minor_text
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        let minor: u32 = digits.parse().ok()?;
        let suffix = &minor_text[digits.len()..];
        let patch_text = parts.next();
        if !suffix.is_empty() {
            let (kind, number) = if let Some(n) = suffix.strip_prefix("rc") {
                (1, n)
            } else if let Some(n) = suffix.strip_prefix("beta") {
                (0, n)
            } else {
                return None;
            };
            return Some(Self {
                major,
                minor,
                kind: 1,
                pre: (kind, number.parse().ok()?),
                patch: 0,
            });
        }
        match patch_text {
            None => Some(Self {
                major,
                minor,
                kind: 0,
                pre: (0, 0),
                patch: 0,
            }),
            Some(patch) => Some(Self {
                major,
                minor,
                kind: 2,
                pre: (0, 0),
                patch: patch.parse().ok()?,
            }),
        }
    }

    /// The release name go.dev files a distribution under, `go1.22.4`. A
    /// bare language version from Go 1.21 on names its `.0` release; before
    /// 1.21 the first release was named without a patch.
    pub fn release_name(&self) -> String {
        match self.kind {
            2 => format!("go{}.{}.{}", self.major, self.minor, self.patch),
            1 => format!(
                "go{}.{}{}{}",
                self.major,
                self.minor,
                if self.pre.0 == 1 { "rc" } else { "beta" },
                self.pre.1
            ),
            _ if self.major == 1 && self.minor < 21 => format!("go{}.{}", self.major, self.minor),
            _ => format!("go{}.{}.0", self.major, self.minor),
        }
    }
}

impl std::fmt::Display for GoVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.release_name().trim_start_matches("go"))
    }
}

/// The value of the first `<directive> <value>` line of a `go.mod`.
pub fn directive(text: &str, name: &str) -> Option<String> {
    text.lines().find_map(|line| {
        let rest = line.trim().strip_prefix(name)?;
        rest.starts_with(char::is_whitespace)
            .then(|| rest.split("//").next().unwrap_or("").trim().to_string())
            .filter(|value| !value.is_empty())
    })
}

/// What the repository asks of the toolchain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Requirement {
    /// The newest `go` line among the workspace's modules: the oldest Go
    /// that can load them.
    pub minimum: GoVersion,
    /// The `toolchain` line, when one names a newer release.
    pub preferred: Option<GoVersion>,
    /// The files that said so, for the report.
    pub pinned_by: String,
}

impl Requirement {
    /// The release Kin fetches when the installed Go is too old.
    pub fn release(&self) -> GoVersion {
        self.preferred
            .clone()
            .filter(|preferred| *preferred >= self.minimum)
            .unwrap_or_else(|| self.minimum.clone())
    }
}

/// The requirement of the modules at `mod_files` and, when there is one, the
/// root `go.work`, whose `go` line binds every module it uses.
pub fn requirement(mod_files: &[PathBuf], go_work: Option<&Path>) -> Option<Requirement> {
    let mut minimum: Option<(GoVersion, String)> = None;
    let mut preferred: Option<GoVersion> = None;
    for file in go_work
        .into_iter()
        .chain(mod_files.iter().map(PathBuf::as_path))
    {
        let Ok(text) = std::fs::read_to_string(file) else {
            continue;
        };
        if let Some(version) = directive(&text, "go").and_then(|v| GoVersion::parse(&v)) {
            if minimum
                .as_ref()
                .is_none_or(|(current, _)| version > *current)
            {
                minimum = Some((version, file.display().to_string()));
            }
        }
        if let Some(version) = directive(&text, "toolchain").and_then(|v| GoVersion::parse(&v)) {
            if preferred.as_ref().is_none_or(|current| version > *current) {
                preferred = Some(version);
            }
        }
    }
    let (minimum, file) = minimum?;
    let pinned_by = match &preferred {
        Some(preferred) => format!("go {minimum} and toolchain go{preferred} in {file}"),
        None => format!("go {minimum} in {file}"),
    };
    Some(Requirement {
        minimum,
        preferred,
        pinned_by,
    })
}

/// A Go installation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledGo {
    /// Its root, which holds `bin/go` and `VERSION`.
    pub root: PathBuf,
    pub version: GoVersion,
}

impl InstalledGo {
    pub fn bin(&self) -> PathBuf {
        self.root.join("bin")
    }
}

/// The Go installation at `root`, from its `VERSION` file.
pub fn installation_at(root: &Path) -> Option<InstalledGo> {
    let text = std::fs::read_to_string(root.join("VERSION")).ok()?;
    let version = GoVersion::parse(text.lines().next()?)?;
    root.join("bin/go").is_file().then(|| InstalledGo {
        root: root.to_path_buf(),
        version,
    })
}

/// The Go installation behind a `go` executable, following links (a
/// Homebrew `bin/go` links into `libexec`).
pub fn installation_of(go: &Path) -> Option<InstalledGo> {
    let real = std::fs::canonicalize(go).ok()?;
    installation_at(real.parent()?.parent()?)
}

/// The go.dev platform names of this host.
pub fn host_platform() -> Option<(&'static str, &'static str)> {
    let os = match std::env::consts::OS {
        "macos" => "darwin",
        "linux" => "linux",
        "windows" => "windows",
        "freebsd" => "freebsd",
        _ => return None,
    };
    let arch = match std::env::consts::ARCH {
        "aarch64" => "arm64",
        "x86_64" => "amd64",
        "x86" => "386",
        _ => return None,
    };
    Some((os, arch))
}

/// Where Kin keeps the Go distribution of `release`.
pub fn toolchain_dir(store: &Path, release: &GoVersion) -> PathBuf {
    store.join("toolchains").join(release.release_name())
}

/// The Go distribution of `release` in Kin's store, when it is there.
pub fn stored(store: &Path, release: &GoVersion) -> Option<InstalledGo> {
    installation_at(&toolchain_dir(store, release).join("go"))
}

/// One file of a release, as go.dev lists it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReleaseFile {
    pub filename: String,
    pub sha256: String,
    pub size: u64,
}

/// The archive of `release` for `os`/`arch` in go.dev's release list.
pub fn find_archive(
    list: &serde_json::Value,
    release: &str,
    os: &str,
    arch: &str,
) -> Option<ReleaseFile> {
    list.as_array()?
        .iter()
        .filter(|entry| entry.get("version").and_then(|v| v.as_str()) == Some(release))
        .flat_map(|entry| {
            entry
                .get("files")
                .and_then(|f| f.as_array())
                .into_iter()
                .flatten()
        })
        .find(|file| {
            file.get("os").and_then(|v| v.as_str()) == Some(os)
                && file.get("arch").and_then(|v| v.as_str()) == Some(arch)
                && file.get("kind").and_then(|v| v.as_str()) == Some("archive")
                && file
                    .get("filename")
                    .and_then(|v| v.as_str())
                    .is_some_and(|name| name.ends_with(".tar.gz"))
        })
        .and_then(|file| {
            Some(ReleaseFile {
                filename: file.get("filename")?.as_str()?.to_string(),
                sha256: file.get("sha256")?.as_str()?.to_ascii_lowercase(),
                size: file.get("size").and_then(|v| v.as_u64()).unwrap_or(0),
            })
        })
}

/// Put the Go distribution of `release` in Kin's store, checked against the
/// digest go.dev lists for it. Returns it and the bytes downloaded.
pub fn ensure(
    fetcher: &dyn Fetcher,
    store: &Path,
    release: &GoVersion,
) -> Result<(InstalledGo, u64), String> {
    if let Some(installed) = stored(store, release) {
        return Ok((installed, 0));
    }
    let (os, arch) = host_platform().ok_or_else(|| {
        format!(
            "go.dev publishes no Go for {} {}",
            std::env::consts::OS,
            std::env::consts::ARCH
        )
    })?;
    let (_, list) = fetcher
        .document(RELEASES_URL, "application/json")
        .map_err(|error| error.to_string())?;
    let list: serde_json::Value = serde_json::from_slice(&list)
        .map_err(|error| format!("go.dev's release list is not JSON: {error}"))?;
    let name = release.release_name();
    let file = find_archive(&list, &name, os, arch)
        .ok_or_else(|| format!("go.dev lists no {name} archive for {os}-{arch}"))?;
    let unique = shared::unique_suffix();
    let archive = store
        .join("downloads")
        .join(format!("{}.{unique}.part", file.filename));
    let downloaded = download_verified(
        fetcher,
        &format!("{DOWNLOAD_BASE}/{}", file.filename),
        &archive,
        &file.sha256,
        MAX_ARCHIVE_BYTES,
    )
    .map_err(|error| error.to_string())?;
    let destination = toolchain_dir(store, release);
    let staging = destination.with_file_name(format!(".{name}.{unique}.tmp"));
    let unpacked = unpack::untar_gz(&archive, &staging, unpack::TarLayout::TOOLCHAIN);
    let _ = std::fs::remove_file(&archive);
    if let Err(reason) = unpacked {
        let _ = std::fs::remove_dir_all(&staging);
        return Err(format!("{}: {reason}", file.filename));
    }
    shared::publish_dir(&staging, &destination)?;
    let installed =
        stored(store, release).ok_or_else(|| format!("{} holds no go/bin/go", file.filename))?;
    Ok((installed, downloaded.bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::repo_scan::Fixture;

    #[test]
    fn versions_order_the_way_the_go_command_orders_them() {
        let v = |text| GoVersion::parse(text).unwrap();
        assert!(v("1.21") < v("1.21rc1"));
        assert!(v("1.21rc1") < v("1.21rc2"));
        assert!(v("1.21beta1") < v("1.21rc1"));
        assert!(v("1.21rc2") < v("1.21.0"));
        assert!(v("1.21.0") < v("1.21.1"));
        assert!(v("1.9.7") < v("1.21"));
        assert!(v("go1.25.7") >= v("1.25.0"));
        assert_eq!(v("1.22").release_name(), "go1.22.0");
        assert_eq!(v("1.19").release_name(), "go1.19");
        assert_eq!(v("go1.22.4").release_name(), "go1.22.4");
        assert_eq!(v("1.23rc1").release_name(), "go1.23rc1");
        assert!(GoVersion::parse("banana").is_none());
    }

    /// The newest `go` line binds; a `toolchain` line names the release to
    /// fetch, unless it is older than the `go` line.
    #[test]
    fn the_requirement_comes_from_every_module() {
        let repo = Fixture::new("go-requirement");
        let a = repo.write("go.mod", "module a\n\ngo 1.21\n\ntoolchain go1.22.4\n");
        let b = repo.write("b/go.mod", "module b\n\ngo 1.23.1 // newest\n");
        let requirement = requirement(&[a.clone(), b], None).unwrap();
        assert_eq!(requirement.minimum.to_string(), "1.23.1");
        assert_eq!(requirement.release().release_name(), "go1.23.1");
        let requirement = super::requirement(&[a], None).unwrap();
        assert_eq!(requirement.release().release_name(), "go1.22.4");
        assert!(requirement.pinned_by.contains("toolchain go1.22.4"));
    }

    #[test]
    fn an_installation_is_read_from_its_version_file() {
        let root = Fixture::new("go-installed");
        root.write("libexec/VERSION", "go1.25.7\ntime 2026-02-03T20:02:30Z\n");
        root.write("libexec/bin/go", "");
        let installed = installation_at(&root.root.join("libexec")).unwrap();
        assert_eq!(installed.version, GoVersion::parse("1.25.7").unwrap());
        assert!(installation_at(&root.root).is_none());
    }

    #[test]
    fn the_archive_is_found_in_the_release_list() {
        let list = serde_json::json!([{
            "version": "go1.22.4",
            "files": [
                {"filename": "go1.22.4.src.tar.gz", "os": "", "arch": "", "kind": "source", "sha256": "aa"},
                {"filename": "go1.22.4.darwin-arm64.pkg", "os": "darwin", "arch": "arm64", "kind": "installer", "sha256": "bb"},
                {"filename": "go1.22.4.darwin-arm64.tar.gz", "os": "darwin", "arch": "arm64", "kind": "archive", "sha256": "CC", "size": 7},
            ],
        }]);
        let file = find_archive(&list, "go1.22.4", "darwin", "arm64").unwrap();
        assert_eq!(file.filename, "go1.22.4.darwin-arm64.tar.gz");
        assert_eq!(file.sha256, "cc");
        assert!(find_archive(&list, "go1.22.5", "darwin", "arm64").is_none());
    }
}
