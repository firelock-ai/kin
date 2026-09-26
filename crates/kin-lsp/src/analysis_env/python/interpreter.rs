// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The CPython an analysis environment is analysed as.
//!
//! pyright takes the Python version only from a configuration file or from
//! an interpreter it runs; its language-server settings carry no version.
//! Writing a configuration file into the repository is writing into it, so
//! the version comes from an interpreter: a standalone CPython build of the
//! version the repository pins, downloaded like any other artifact and
//! verified against a digest recorded here. pyright runs it only to read
//! `sys.version_info` and `sys.path`, with `-I`, and the environment it runs
//! in has a site-packages holding nothing that executes at startup, so no
//! dependency code runs.
//!
//! The builds are python-build-standalone's, the portable CPython builds uv
//! and other tools install. One release is pinned for every host, as Kin pins
//! its language-server releases.
//!
//! ## Re-measuring the pins
//!
//! Change [`RELEASE`], then read each asset's digest and size from the
//! release API and replace the table:
//!
//! ```text
//! curl -sSL https://api.github.com/repos/astral-sh/python-build-standalone/releases/tags/<release> \
//!   | jq -r '.assets[] | select(.name | test("^cpython-3\\.1[0-4]\\.[0-9]+\\+[0-9]+-(aarch64|x86_64)-(apple-darwin|unknown-linux-gnu)-install_only\\.tar\\.gz$")) | [.name, .digest, .size] | @tsv'
//! ```

use std::path::{Path, PathBuf};

use super::super::fetch::{download_verified, Fetcher};
use super::super::unpack;

/// The python-build-standalone release every pinned build comes from.
pub const RELEASE: &str = "20260924";

/// Where the release's assets are downloaded from.
pub const BASE_URL: &str = "https://github.com/astral-sh/python-build-standalone/releases/download";

/// One pinned CPython build.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PinnedPython {
    /// The minor version of Python 3.
    pub minor: u32,
    /// The full version the build is.
    pub version: &'static str,
    /// The Rust target triple it runs on.
    pub target: &'static str,
    /// The sha256 of the `install_only` archive, lowercase hex.
    pub sha256: &'static str,
    /// Its size in bytes.
    pub size: u64,
}

impl PinnedPython {
    /// The archive's file name.
    pub fn asset(&self) -> String {
        format!(
            "cpython-{}+{RELEASE}-{}-install_only.tar.gz",
            self.version, self.target
        )
    }

    /// The URL it is downloaded from.
    pub fn url(&self) -> String {
        format!("{BASE_URL}/{RELEASE}/{}", self.asset().replace('+', "%2B"))
    }

    /// The directory it unpacks to in the store.
    pub fn store_name(&self) -> String {
        format!("cpython-{}+{RELEASE}-{}", self.version, self.target)
    }

    /// The interpreter inside the unpacked build.
    pub fn interpreter_in(&self, dir: &Path) -> PathBuf {
        dir.join("python/bin")
            .join(format!("python3.{}", self.minor))
    }
}

/// Every pinned build: Python 3.10 to 3.14 for the four hosts Kin ships for.
pub const PINNED: &[PinnedPython] = &[
    PinnedPython {
        minor: 10,
        version: "3.10.21",
        target: "aarch64-apple-darwin",
        sha256: "640f6eef16f3c85aaf6430e4ab258e6ca75fe7dc0fc29b10d26ed6ca792ebe4e",
        size: 25_832_478,
    },
    PinnedPython {
        minor: 10,
        version: "3.10.21",
        target: "aarch64-unknown-linux-gnu",
        sha256: "caafe6f9e2a904874c20a8a942414e05e01d46937311d02ef55614365ba34e19",
        size: 43_926_859,
    },
    PinnedPython {
        minor: 10,
        version: "3.10.21",
        target: "x86_64-apple-darwin",
        sha256: "d89ffc797a7b7a145e6dd21340205f5644573024a2c2c7c05991d4c23d029382",
        size: 25_536_408,
    },
    PinnedPython {
        minor: 10,
        version: "3.10.21",
        target: "x86_64-unknown-linux-gnu",
        sha256: "7e80168bf45472a17da889caa06519024e8589d51656b73cfa6f38cb2236a233",
        size: 43_782_696,
    },
    PinnedPython {
        minor: 11,
        version: "3.11.16",
        target: "aarch64-apple-darwin",
        sha256: "d718e3c5c6f4b225ed25f88bf65e4c5d314e0dea0d716ea50bc9d038630c502b",
        size: 27_088_178,
    },
    PinnedPython {
        minor: 11,
        version: "3.11.16",
        target: "aarch64-unknown-linux-gnu",
        sha256: "96f6f6af710762a34507ba222435a8d58d0b2a97c48cb84c0a0c73cdff199bb0",
        size: 48_940_326,
    },
    PinnedPython {
        minor: 11,
        version: "3.11.16",
        target: "x86_64-apple-darwin",
        sha256: "a93ee2dd8f2dbddbd85a0c9f1739f98d6ead305cbf445918a2fe28deb77f2d4b",
        size: 26_985_019,
    },
    PinnedPython {
        minor: 11,
        version: "3.11.16",
        target: "x86_64-unknown-linux-gnu",
        sha256: "49a52eb189878431a36efd137e7cd08f6429e59dc049b9cfb030bf706eb33fd4",
        size: 48_915_795,
    },
    PinnedPython {
        minor: 12,
        version: "3.12.14",
        target: "aarch64-apple-darwin",
        sha256: "9763f43db2481a6af36af82ec40302aab7a73632f880129d07a6e81aec846277",
        size: 25_153_879,
    },
    PinnedPython {
        minor: 12,
        version: "3.12.14",
        target: "aarch64-unknown-linux-gnu",
        sha256: "c0574c9c9fec561eb192ad510e4e79aaad039929b3531b3bb873e2f630fb14a9",
        size: 52_312_565,
    },
    PinnedPython {
        minor: 12,
        version: "3.12.14",
        target: "x86_64-apple-darwin",
        sha256: "0d6a4a299908123f00bc844df737603f047ff9eba14fda6cad83f3cf3cb3a2af",
        size: 24_837_706,
    },
    PinnedPython {
        minor: 12,
        version: "3.12.14",
        target: "x86_64-unknown-linux-gnu",
        sha256: "5eae8cf79dd47fc2496a4fccc892936be831ce7a84d984b2299dfb1cdb592682",
        size: 66_890_910,
    },
    PinnedPython {
        minor: 13,
        version: "3.13.15",
        target: "aarch64-apple-darwin",
        sha256: "a18e1d1b6067d39cf7b2b605fdb78ad6b8a3aed221c44ef934d399dccf355453",
        size: 25_332_842,
    },
    PinnedPython {
        minor: 13,
        version: "3.13.15",
        target: "aarch64-unknown-linux-gnu",
        sha256: "c8dd48f5e5be632b518a79076189419cb8591559959ec137e4d30f5ce143c04d",
        size: 57_563_810,
    },
    PinnedPython {
        minor: 13,
        version: "3.13.15",
        target: "x86_64-apple-darwin",
        sha256: "f445e867ad221c006af745bc0e8d2c168149e14fe194abef1d7ac0da9a4c9de1",
        size: 25_049_185,
    },
    PinnedPython {
        minor: 13,
        version: "3.13.15",
        target: "x86_64-unknown-linux-gnu",
        sha256: "c20e1ff8600a0241849588b36948942eaccdc80da34df69674f3784a687197de",
        size: 75_134_396,
    },
    PinnedPython {
        minor: 14,
        version: "3.14.7",
        target: "aarch64-apple-darwin",
        sha256: "d3da099bb2bdd57e2f5ff8496cb9827f7d92eee332b09f8dc93706dabfc51a96",
        size: 26_781_712,
    },
    PinnedPython {
        minor: 14,
        version: "3.14.7",
        target: "aarch64-unknown-linux-gnu",
        sha256: "0dec153b4932cfa7094d4b6772022a503c7842a6c07978576695f8b5a8785055",
        size: 57_551_202,
    },
    PinnedPython {
        minor: 14,
        version: "3.14.7",
        target: "x86_64-apple-darwin",
        sha256: "11ff6db91dadbf8544d437e617586ee5184382ce95e4a44b7a64864db48cfe87",
        size: 26_929_188,
    },
    PinnedPython {
        minor: 14,
        version: "3.14.7",
        target: "x86_64-unknown-linux-gnu",
        sha256: "5539eaf1de20bd9b5f43ea11c3c1f84cbac74fe927ac050318a9210c022618cb",
        size: 74_964_439,
    },
];

/// The pinned build for a minor version on a target, or the nearest pinned
/// minor when that one is not pinned, with the substitution named.
pub fn pinned_for(minor: u32, target: &str) -> Option<(&'static PinnedPython, Option<String>)> {
    let on_target: Vec<&PinnedPython> = PINNED.iter().filter(|p| p.target == target).collect();
    if let Some(exact) = on_target.iter().find(|p| p.minor == minor) {
        return Some((exact, None));
    }
    let nearest = on_target
        .iter()
        .min_by_key(|p| (p.minor.abs_diff(minor), std::cmp::Reverse(p.minor)))?;
    Some((
        nearest,
        Some(format!(
            "Kin pins no CPython 3.{minor} build, so the environment is analysed as {}",
            nearest.version
        )),
    ))
}

/// The newest pinned minor version that `accepts`, for a repository that
/// states a supported range but pins no version.
pub fn newest_accepted(
    target: &str,
    accepts: &dyn Fn(&str) -> bool,
) -> Option<&'static PinnedPython> {
    PINNED
        .iter()
        .filter(|p| p.target == target && accepts(p.version))
        .max_by_key(|p| p.minor)
}

/// The interpreter of a build already in the store, without the network.
pub fn installed(store: &Path, pinned: &PinnedPython) -> Option<PathBuf> {
    let interpreter = pinned.interpreter_in(&store.join("interpreters").join(pinned.store_name()));
    is_executable(&interpreter).then_some(interpreter)
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .is_ok_and(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

/// The interpreter of a pinned build, downloading, verifying and unpacking
/// it into the store first when it is not there. Returns the interpreter and
/// the bytes downloaded, zero when the store already held it.
pub fn ensure(
    fetcher: &dyn Fetcher,
    store: &Path,
    pinned: &PinnedPython,
) -> Result<(PathBuf, u64), String> {
    if let Some(interpreter) = installed(store, pinned) {
        return Ok((interpreter, 0));
    }
    let interpreters = store.join("interpreters");
    let unique = super::store::unique_suffix();
    let archive = store
        .join("downloads")
        .join(format!("{}.{unique}.part", pinned.store_name()));
    let downloaded = download_verified(
        fetcher,
        &pinned.url(),
        &archive,
        pinned.sha256,
        pinned.size + 1,
    )
    .map_err(|error| error.to_string())?;
    let staging = interpreters.join(format!(".{}.{unique}.tmp", pinned.store_name()));
    let unpacked = unpack::untar_gz(&archive, &staging, unpack::TarLayout::TOOLCHAIN);
    let _ = std::fs::remove_file(&archive);
    if let Err(error) = unpacked {
        let _ = std::fs::remove_dir_all(&staging);
        return Err(format!("{}: {error}", pinned.asset()));
    }
    let destination = interpreters.join(pinned.store_name());
    if destination.exists() {
        // A build unpacked without its executables by an earlier Kin.
        let retired = interpreters.join(format!(".{}.{unique}.old", pinned.store_name()));
        let _ = std::fs::rename(&destination, &retired);
        let _ = std::fs::remove_dir_all(&retired);
    }
    super::store::publish_dir(&staging, &destination)?;
    installed(store, pinned)
        .map(|interpreter| (interpreter, downloaded.bytes))
        .ok_or_else(|| {
            format!(
                "{} holds no python3.{} binary",
                pinned.asset(),
                pinned.minor
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_host_has_every_pinned_minor() {
        for target in [
            "aarch64-apple-darwin",
            "x86_64-apple-darwin",
            "aarch64-unknown-linux-gnu",
            "x86_64-unknown-linux-gnu",
        ] {
            for minor in 10..=14 {
                let (pinned, substitution) = pinned_for(minor, target).unwrap();
                assert_eq!(pinned.minor, minor);
                assert!(substitution.is_none());
                assert_eq!(pinned.sha256.len(), 64);
            }
        }
    }

    #[test]
    fn an_unpinned_minor_takes_the_nearest_and_says_so() {
        let (pinned, substitution) = pinned_for(9, "aarch64-apple-darwin").unwrap();
        assert_eq!(pinned.minor, 10);
        assert!(substitution.unwrap().contains("3.9"));
        let (pinned, _) = pinned_for(15, "aarch64-apple-darwin").unwrap();
        assert_eq!(pinned.minor, 14);
        assert!(pinned_for(12, "riscv64-unknown-linux-gnu").is_none());
    }

    #[test]
    fn the_url_escapes_the_plus_in_the_asset_name() {
        let (pinned, _) = pinned_for(11, "aarch64-apple-darwin").unwrap();
        assert_eq!(
            pinned.url(),
            "https://github.com/astral-sh/python-build-standalone/releases/download/20260924/cpython-3.11.16%2B20260924-aarch64-apple-darwin-install_only.tar.gz"
        );
    }
}
