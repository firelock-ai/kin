// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Installing a language server from its project's own release binaries, for a
//! host that carries none of the toolchains the package route needs.
//!
//! The gap this closes is the one a cold walkthrough measured on 2026-08-28. A
//! stranger followed the documented install, initialized a Rust repository, and
//! got `rust: imports 0/1085 (0%)` with "no language server found". The product
//! named its own repair, `kin doctor --fix --install-language-servers`, and the
//! repair exited 1 with "'rustup' is not installed on this host; install
//! 'rustup', then run 'rustup component add rust-analyzer'". Every step of that
//! is honest and the outcome is still that a developer who is not a Rust
//! developer cannot get reference edges for a Rust repository by following the
//! product's own instructions. Kin asked them to install a toolchain to read
//! somebody else's code.
//!
//! So Kin fetches the binary itself when the toolchain is absent. Three
//! properties make that safe enough to do on a user's machine without asking
//! them to trust a URL:
//!
//! * The release is PINNED. One tag, named here, for every host. An install
//!   that resolved "latest" would put a different binary on two machines
//!   initialized a week apart and give their graphs different edges with
//!   nothing recording why.
//! * Every asset carries its own sha256, recorded in this source file and
//!   verified against the bytes before anything is written to a durable path. A
//!   digest that does not match refuses loudly and installs nothing;
//!   [`InstallFailure::ChecksumMismatch`] is a separate outcome from a network
//!   error for that reason, because the two need different words and only one
//!   of them means the bytes were wrong.
//! * The rustup route stays PREFERRED. A host that has rustup gets the
//!   component that tracks its own toolchain, and Kin's pinned copy is a
//!   fallback for a host that has neither. The tool directory is appended to
//!   `PATH` rather than prepended for the same reason
//!   (`kin_core::tool_prefix`).
//!
//! ## Re-measuring the pins
//!
//! The digests below were measured by downloading each asset and hashing it.
//! To move the pin, change [`RUST_ANALYZER_RELEASE`]'s tag and re-run:
//!
//! ```text
//! tag=<new tag>
//! for a in rust-analyzer-x86_64-unknown-linux-gnu.gz \
//!          rust-analyzer-aarch64-unknown-linux-gnu.gz \
//!          rust-analyzer-aarch64-apple-darwin.gz \
//!          rust-analyzer-x86_64-apple-darwin.gz; do
//!   curl -fsSL -o "$a" \
//!     "https://github.com/rust-lang/rust-analyzer/releases/download/$tag/$a"
//! done
//! shasum -a 256 *.gz
//! ```
//!
//! The recorded `size` is the second reading: it is the release API's own
//! `assets[].size` for the same file, so a download truncated by a proxy is
//! named as a truncation rather than as a digest that happens not to match.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

/// One release asset, for one host, with the digest Kin verifies it against.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ReleaseAsset {
    /// The Rust target triple this asset serves, as `cfg!` reports the host.
    pub(crate) target: &'static str,
    /// The file name inside the release.
    pub(crate) name: &'static str,
    /// The sha256 of the asset as published, lowercase hex.
    pub(crate) sha256: &'static str,
    /// The published size in bytes, from the release API.
    pub(crate) size: u64,
}

/// How an asset is packed, and therefore how it is unpacked.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AssetFormat {
    /// A single gzip-compressed executable.
    Gzip,
}

/// A project's pinned release, and the assets Kin will install from it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PinnedRelease {
    /// The binary that lands on disk, which is also the name discovery matches.
    pub(crate) binary: &'static str,
    /// The upstream project, for the disclosure line.
    pub(crate) project: &'static str,
    /// The release tag every asset here comes from.
    pub(crate) tag: &'static str,
    /// Where the release lives, without the tag or the file name.
    pub(crate) base_url: &'static str,
    pub(crate) format: AssetFormat,
    pub(crate) assets: &'static [ReleaseAsset],
}

impl PinnedRelease {
    /// The asset for a host target, or `None` when this release does not build
    /// one.
    pub(crate) fn asset_for(&self, target: &str) -> Option<&'static ReleaseAsset> {
        self.assets.iter().find(|asset| asset.target == target)
    }

    /// The full URL an asset is fetched from, honouring the test base override.
    pub(crate) fn asset_url(&self, asset: &ReleaseAsset, base: &str) -> String {
        format!("{}/{}/{}", base.trim_end_matches('/'), self.tag, asset.name)
    }
}

/// rust-analyzer's own release binaries.
///
/// Four hosts: the two Linux and the two macOS targets Kin ships for. Windows
/// carries `.zip` assets in the same release and is deliberately not pinned
/// here, because Kin has never exercised that unpack path and an unproven
/// install route is worse than a refusal that names the rustup command.
///
/// The Linux assets are the `-gnu` builds. A musl host is not covered and does
/// not need a special case here: the readiness probe already reports a server
/// that installed and would not start, which is the honest answer for a binary
/// this host's loader refuses.
pub(crate) const RUST_ANALYZER_RELEASE: PinnedRelease = PinnedRelease {
    binary: "rust-analyzer",
    project: "rust-lang/rust-analyzer",
    tag: "2026-08-24",
    base_url: "https://github.com/rust-lang/rust-analyzer/releases/download",
    format: AssetFormat::Gzip,
    assets: &[
        ReleaseAsset {
            target: "x86_64-unknown-linux-gnu",
            name: "rust-analyzer-x86_64-unknown-linux-gnu.gz",
            sha256: "c4d409690b98d84ce98174829362a59214825d72304fe2504f4b906a116b51fe",
            size: 14_865_773,
        },
        ReleaseAsset {
            target: "aarch64-unknown-linux-gnu",
            name: "rust-analyzer-aarch64-unknown-linux-gnu.gz",
            sha256: "3463f9115c725fc5dfb002431833ec83d1f1f9c4c35b76ad5f47b92c58a521f1",
            size: 14_317_193,
        },
        ReleaseAsset {
            target: "aarch64-apple-darwin",
            name: "rust-analyzer-aarch64-apple-darwin.gz",
            sha256: "5f4557c2ea4d62f80f1ffeea2646d0d56fab7172a0db11f3065c4d246b763989",
            size: 13_875_126,
        },
        ReleaseAsset {
            target: "x86_64-apple-darwin",
            name: "rust-analyzer-x86_64-apple-darwin.gz",
            sha256: "822cc4369562fc2ed26d1cf3953ef93927d8fdda4302d82e2eec407e2734eefd",
            size: 14_591_602,
        },
    ],
};

/// The target triple for the host this build runs on, as the pin table spells
/// it.
///
/// A runtime match over `cfg!` rather than a `#[cfg]` block, so every arm is
/// compiled and type-checked on every host including the one this fleet builds
/// on.
pub(crate) fn host_target() -> Option<&'static str> {
    match (std::env::consts::OS, std::env::consts::ARCH) {
        ("linux", "x86_64") => Some("x86_64-unknown-linux-gnu"),
        ("linux", "aarch64") => Some("aarch64-unknown-linux-gnu"),
        ("macos", "aarch64") => Some("aarch64-apple-darwin"),
        ("macos", "x86_64") => Some("x86_64-apple-darwin"),
        _ => None,
    }
}

/// Where release assets are fetched from.
///
/// The override exists so an acceptance check can drive the whole route,
/// download included, against bytes it controls rather than against the
/// internet. It is honoured on its own; the DIGEST override beside it is not,
/// and that asymmetry is deliberate: pointing the fetch somewhere else is a
/// test setup step, while relaxing the digest is the guard itself and must be
/// impossible to do by accident against the real release.
pub(crate) const ASSET_BASE_ENV: &str = "KIN_LANGUAGE_SERVER_ASSET_BASE";

/// The digest an overridden base URL is verified against.
///
/// Ignored unless [`ASSET_BASE_ENV`] is also set, so this can never weaken the
/// check against the pinned release. A fixture has different bytes and
/// therefore a different digest, and stating it here is what keeps the
/// acceptance check exercising a real verification rather than a disabled one.
pub(crate) const ASSET_SHA256_ENV: &str = "KIN_LANGUAGE_SERVER_ASSET_SHA256";

/// Where this run fetches from, and what digest it demands, read from the
/// process environment.
///
/// The one place these two variables are read. Everything below takes the
/// answer as an argument, so a test states the whole environment it asserts
/// against rather than mutating a table every other test shares.
pub(crate) fn resolve_source_from_env(
    release: &PinnedRelease,
    asset: &ReleaseAsset,
) -> (String, String) {
    resolve_source(release, asset, |key| std::env::var(key).ok())
}

/// Where this run fetches from, and what digest it demands, resolved from an
/// arbitrary lookup.
///
/// Pure in the lookup, so the precedence rule is testable without touching the
/// process environment.
pub(crate) fn resolve_source<F>(
    release: &PinnedRelease,
    asset: &ReleaseAsset,
    lookup: F,
) -> (String, String)
where
    F: Fn(&str) -> Option<String>,
{
    let base = lookup(ASSET_BASE_ENV).filter(|value| !value.trim().is_empty());
    match base {
        None => (release.base_url.to_string(), asset.sha256.to_string()),
        Some(base) => {
            let digest = lookup(ASSET_SHA256_ENV)
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| asset.sha256.to_string());
            (base, digest)
        }
    }
}

/// Why a release install could not happen, in the operator's terms.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InstallFailure {
    /// No asset is pinned for this host.
    UnsupportedHost { target: String },
    /// The bytes never arrived.
    Download { url: String, reason: String },
    /// The bytes arrived and are not the pinned ones.
    ChecksumMismatch {
        url: String,
        expected: String,
        actual: String,
        bytes: u64,
    },
    /// The bytes arrived, verified, and could not be unpacked or written.
    Install {
        destination: PathBuf,
        reason: String,
    },
}

impl InstallFailure {
    /// One line naming what happened, for a report row.
    pub(crate) fn reason(&self) -> String {
        match self {
            Self::UnsupportedHost { target } => format!(
                "Kin pins no {} release binary for this host ({target})",
                RUST_ANALYZER_RELEASE.binary
            ),
            Self::Download { url, reason } => {
                format!("could not download {url}: {reason}")
            }
            Self::ChecksumMismatch {
                url,
                expected,
                actual,
                bytes,
            } => format!(
                "the {bytes} bytes served by {url} hash to sha256 {actual}, and Kin pins \
                 {expected}. Nothing was installed."
            ),
            Self::Install {
                destination,
                reason,
            } => format!("could not install into {}: {reason}", destination.display()),
        }
    }
}

/// What one release install did, in enough detail for the operator to check it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReleaseInstall {
    pub(crate) binary: &'static str,
    pub(crate) project: &'static str,
    pub(crate) tag: &'static str,
    pub(crate) url: String,
    pub(crate) sha256: String,
    pub(crate) destination: PathBuf,
}

impl ReleaseInstall {
    /// The disclosure a run prints: what landed, from where, and the digest
    /// that was verified before it landed.
    pub(crate) fn evidence_lines(&self) -> Vec<String> {
        vec![
            format!(
                "{} {} from the {} release {}",
                self.binary, self.tag, self.project, self.tag
            ),
            format!("source:   {}", self.url),
            format!("sha256:   {} (verified before install)", self.sha256),
            format!("installed to: {}", self.destination.display()),
        ]
    }
}

/// How many bytes a release asset may be before Kin stops reading.
///
/// A ceiling rather than a trust: an overridden base URL is a test fixture and
/// a real one is a fifteen-megabyte binary, so a body that keeps arriving is a
/// misrouted download rather than a language server.
const MAX_ASSET_BYTES: u64 = 256 * 1024 * 1024;

/// Fetch, verify and install the pinned server for this host.
///
/// The order is the guarantee. Bytes are hashed as they arrive into a temporary
/// file, the digest is compared before anything is unpacked, and only a
/// verified archive is expanded and renamed into place. A mismatch removes the
/// temporary file and returns [`InstallFailure::ChecksumMismatch`]; nothing
/// reaches [`kin_core::tool_prefix::managed_tool_bin_dir`] on that path.
pub(crate) fn install_pinned_release(
    release: &PinnedRelease,
    target: Option<&'static str>,
    bin_dir: &Path,
    base: &str,
    expected: &str,
) -> Result<ReleaseInstall, InstallFailure> {
    let target = target.ok_or_else(|| InstallFailure::UnsupportedHost {
        target: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
    })?;
    let asset = release
        .asset_for(target)
        .ok_or_else(|| InstallFailure::UnsupportedHost {
            target: target.to_string(),
        })?;
    let url = release.asset_url(asset, base);

    std::fs::create_dir_all(bin_dir).map_err(|error| InstallFailure::Install {
        destination: bin_dir.to_path_buf(),
        reason: error.to_string(),
    })?;

    let (archive, digest, bytes) = download_to_temp(&url, bin_dir)?;
    if digest != expected.to_lowercase() {
        let _ = std::fs::remove_file(&archive);
        return Err(InstallFailure::ChecksumMismatch {
            url,
            expected: expected.to_lowercase(),
            actual: digest,
            bytes,
        });
    }

    let destination = bin_dir.join(release.binary);
    expand_into_place(release.format, &archive, &destination).map_err(|reason| {
        InstallFailure::Install {
            destination: destination.clone(),
            reason,
        }
    })?;
    let _ = std::fs::remove_file(&archive);

    Ok(ReleaseInstall {
        binary: release.binary,
        project: release.project,
        tag: release.tag,
        url,
        sha256: digest,
        destination,
    })
}

/// Stream `url` into a temporary file beside the destination, hashing as it
/// goes.
///
/// Written beside the destination rather than into the system temp directory so
/// the rename that follows is on one filesystem, which is what makes it atomic:
/// a crash mid-write leaves a partial temporary file and never a partial
/// `rust-analyzer` that discovery would find and start.
fn download_to_temp(url: &str, bin_dir: &Path) -> Result<(PathBuf, String, u64), InstallFailure> {
    let client = reqwest::blocking::Client::builder()
        .user_agent(concat!("kin/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|error| InstallFailure::Download {
            url: url.to_string(),
            reason: error.to_string(),
        })?;
    let response = client
        .get(url)
        .send()
        .map_err(|error| InstallFailure::Download {
            url: url.to_string(),
            reason: error.to_string(),
        })?;
    if !response.status().is_success() {
        return Err(InstallFailure::Download {
            url: url.to_string(),
            reason: format!("the server answered {}", response.status()),
        });
    }

    let temp = bin_dir.join(format!(".kin-download-{}", std::process::id()));
    let mut file = std::fs::File::create(&temp).map_err(|error| InstallFailure::Download {
        url: url.to_string(),
        reason: format!("could not open {}: {error}", temp.display()),
    })?;
    let mut hasher = Sha256::new();
    let mut total: u64 = 0;
    let mut reader = response;
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let read = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) => {
                let _ = std::fs::remove_file(&temp);
                return Err(InstallFailure::Download {
                    url: url.to_string(),
                    reason: error.to_string(),
                });
            }
        };
        total += read as u64;
        if total > MAX_ASSET_BYTES {
            let _ = std::fs::remove_file(&temp);
            return Err(InstallFailure::Download {
                url: url.to_string(),
                reason: format!("the response passed {MAX_ASSET_BYTES} bytes and was abandoned"),
            });
        }
        hasher.update(&buffer[..read]);
        if let Err(error) = file.write_all(&buffer[..read]) {
            let _ = std::fs::remove_file(&temp);
            return Err(InstallFailure::Download {
                url: url.to_string(),
                reason: error.to_string(),
            });
        }
    }
    if let Err(error) = file.flush() {
        let _ = std::fs::remove_file(&temp);
        return Err(InstallFailure::Download {
            url: url.to_string(),
            reason: error.to_string(),
        });
    }
    drop(file);

    Ok((temp, hex::encode(hasher.finalize()), total))
}

/// Unpack a verified archive and put the binary in place, executable.
fn expand_into_place(
    format: AssetFormat,
    archive: &Path,
    destination: &Path,
) -> Result<(), String> {
    let staged = destination.with_extension("kin-staged");
    {
        let source = std::fs::File::open(archive).map_err(|error| error.to_string())?;
        let mut out = std::fs::File::create(&staged).map_err(|error| error.to_string())?;
        match format {
            AssetFormat::Gzip => {
                let mut decoder = flate2::read::GzDecoder::new(source);
                std::io::copy(&mut decoder, &mut out).map_err(|error| error.to_string())?;
            }
        }
        out.flush().map_err(|error| error.to_string())?;
    }
    set_executable(&staged)?;
    std::fs::rename(&staged, destination).map_err(|error| {
        let _ = std::fs::remove_file(&staged);
        error.to_string()
    })
}

/// Make a staged file executable, before it takes the name discovery matches.
///
/// Done on the staged path rather than after the rename so the binary is never
/// visible under its real name without the bit: `which` accepts a file only
/// when it is executable, and a window where it is not is a window where
/// discovery walks past a server that is there.
#[cfg(unix)]
fn set_executable(path: &Path) -> Result<(), String> {
    use std::os::unix::fs::PermissionsExt;
    let mut permissions = std::fs::metadata(path)
        .map_err(|error| error.to_string())?
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(path, permissions).map_err(|error| error.to_string())
}

#[cfg(not(unix))]
fn set_executable(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every pinned asset states a full sha256 and a real size.
    ///
    /// The failing case is a pin moved by hand where one digest was pasted
    /// short or one size left at zero. Both read as ordinary table rows and
    /// only fail at install time, on the one host that asset serves, which is
    /// the host nobody is on when the pin moves.
    #[test]
    fn every_pinned_asset_carries_a_full_digest_and_a_size() {
        assert!(
            !RUST_ANALYZER_RELEASE.assets.is_empty(),
            "a release with no assets can install nothing"
        );
        for asset in RUST_ANALYZER_RELEASE.assets {
            assert_eq!(
                asset.sha256.len(),
                64,
                "{}: sha256 must be 64 hex characters, got {:?}",
                asset.name,
                asset.sha256
            );
            assert!(
                asset
                    .sha256
                    .chars()
                    .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
                "{}: sha256 must be lowercase hex, got {:?}",
                asset.name,
                asset.sha256
            );
            assert!(
                asset.size > 1_000_000,
                "{}: a language server smaller than a megabyte is not the published asset",
                asset.name
            );
            assert!(
                asset.name.contains(asset.target),
                "{}: the asset name must carry the target it serves, {}",
                asset.name,
                asset.target
            );
        }
    }

    /// Two hosts must never share one digest.
    ///
    /// A copy-paste while moving the pin puts one host's binary on another's,
    /// and the install succeeds: the digest matches the bytes that were served,
    /// because they are the bytes that were asked for. Only the loader
    /// disagrees, later, on somebody else's machine.
    #[test]
    fn no_two_hosts_share_a_digest_or_a_name() {
        for (index, asset) in RUST_ANALYZER_RELEASE.assets.iter().enumerate() {
            for other in &RUST_ANALYZER_RELEASE.assets[index + 1..] {
                assert_ne!(
                    asset.sha256, other.sha256,
                    "{} and {} carry the same digest",
                    asset.name, other.name
                );
                assert_ne!(
                    asset.target, other.target,
                    "two assets both claim to serve {}",
                    asset.target
                );
            }
        }
    }

    /// The four hosts Kin ships binaries for are the four hosts pinned.
    #[test]
    fn the_pinned_hosts_are_the_hosts_kin_ships_for() {
        let mut targets: Vec<&str> = RUST_ANALYZER_RELEASE
            .assets
            .iter()
            .map(|asset| asset.target)
            .collect();
        targets.sort_unstable();
        assert_eq!(
            targets,
            vec![
                "aarch64-apple-darwin",
                "aarch64-unknown-linux-gnu",
                "x86_64-apple-darwin",
                "x86_64-unknown-linux-gnu",
            ]
        );
    }

    /// The host this test runs on resolves to a pinned asset.
    ///
    /// Not a tautology over the table: it asserts the OS and ARCH strings this
    /// build reports are the ones [`host_target`] matches on, which is the join
    /// a hand-written match arm gets wrong.
    #[test]
    fn this_host_resolves_to_an_asset() {
        let target = host_target().expect("this fleet builds on a pinned host");
        assert!(
            RUST_ANALYZER_RELEASE.asset_for(target).is_some(),
            "{target} resolves to no pinned asset"
        );
    }

    /// A digest override is ignored unless the base URL is overridden too.
    ///
    /// This is the whole safety of the test lever. Without the pairing rule,
    /// one environment variable would relax verification against the real
    /// release, which is the guard removing itself.
    #[test]
    fn a_digest_override_alone_cannot_relax_the_pin() {
        let asset = RUST_ANALYZER_RELEASE.assets[0];
        let (base, digest) = resolve_source(&RUST_ANALYZER_RELEASE, &asset, |key| {
            if key == ASSET_SHA256_ENV {
                Some("0".repeat(64))
            } else {
                None
            }
        });
        assert_eq!(base, RUST_ANALYZER_RELEASE.base_url);
        assert_eq!(
            digest, asset.sha256,
            "a digest override with no base override must leave the pin standing"
        );
    }

    /// With both set, the fixture's own base and digest are used.
    #[test]
    fn an_overridden_base_takes_its_own_digest() {
        let asset = RUST_ANALYZER_RELEASE.assets[0];
        let fixture_digest = "a".repeat(64);
        let (base, digest) = resolve_source(&RUST_ANALYZER_RELEASE, &asset, |key| match key {
            ASSET_BASE_ENV => Some("http://127.0.0.1:9/x".to_string()),
            ASSET_SHA256_ENV => Some(fixture_digest.clone()),
            _ => None,
        });
        assert_eq!(base, "http://127.0.0.1:9/x");
        assert_eq!(digest, fixture_digest);
    }

    /// An overridden base with no digest still demands the pinned one.
    #[test]
    fn an_overridden_base_without_a_digest_keeps_the_pin() {
        let asset = RUST_ANALYZER_RELEASE.assets[0];
        let (_, digest) = resolve_source(&RUST_ANALYZER_RELEASE, &asset, |key| {
            (key == ASSET_BASE_ENV).then(|| "http://127.0.0.1:9/x".to_string())
        });
        assert_eq!(digest, asset.sha256);
    }

    /// The URL is the base, the tag and the asset name, in that order.
    #[test]
    fn the_asset_url_names_the_tag_and_the_file() {
        let asset = RUST_ANALYZER_RELEASE.assets[0];
        assert_eq!(
            RUST_ANALYZER_RELEASE.asset_url(&asset, "https://example.invalid/releases/download/"),
            format!(
                "https://example.invalid/releases/download/{}/{}",
                RUST_ANALYZER_RELEASE.tag, asset.name
            ),
            "a trailing slash on the base must not double in the URL"
        );
    }

    /// A mismatch reason names both digests and the bytes it read.
    ///
    /// A refusal that says only "checksum mismatch" sends an operator to a
    /// search engine. Naming what was served, what was demanded, and how many
    /// bytes arrived separates a corrupted download from a proxy that served an
    /// HTML error page under a 200.
    #[test]
    fn a_mismatch_names_both_digests_and_refuses_out_loud() {
        let failure = InstallFailure::ChecksumMismatch {
            url: "https://example.invalid/a.gz".to_string(),
            expected: "b".repeat(64),
            actual: "c".repeat(64),
            bytes: 1234,
        };
        let reason = failure.reason();
        assert!(reason.contains(&"b".repeat(64)), "{reason}");
        assert!(reason.contains(&"c".repeat(64)), "{reason}");
        assert!(reason.contains("1234"), "{reason}");
        assert!(
            reason.contains("Nothing was installed"),
            "a mismatch must say what it did NOT do: {reason}"
        );
    }

    // ---- the standalone route, end to end --------------------------------
    //
    // A local HTTP server, a gzip of a fixture "binary", and the real
    // download-verify-unpack-install path. What is NOT exercised here is which
    // URL production reads, and that is deliberate: `resolve_source` is tested
    // above for the precedence rule, and the acceptance check drives the shipped
    // binary against a fixture server through the environment. Everything
    // between the response body and the executable on disk is the same code on
    // both paths.

    /// A one-request HTTP server that serves `body` and then stops.
    ///
    /// Returns the base URL. Hand-rolled rather than pulled in as a dependency
    /// because the whole protocol surface used here is a status line, a length
    /// and a body.
    fn serve_once(body: Vec<u8>) -> (String, std::thread::JoinHandle<()>) {
        use std::io::BufRead;
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind a loopback port");
        let port = listener.local_addr().expect("read the bound port").port();
        let handle = std::thread::spawn(move || {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            // Drain the request head so the client is not writing into a socket
            // nobody reads, which on some platforms surfaces as a broken pipe
            // rather than as the response.
            {
                let mut reader =
                    std::io::BufReader::new(stream.try_clone().expect("clone the accepted stream"));
                let mut line = String::new();
                while reader.read_line(&mut line).unwrap_or(0) > 0 {
                    if line == "\r\n" || line == "\n" {
                        break;
                    }
                    line.clear();
                }
            }
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes());
            let _ = stream.write_all(&body);
            let _ = stream.flush();
        });
        (format!("http://127.0.0.1:{port}"), handle)
    }

    /// A gzip of `payload`, as the release serves its binaries.
    fn gzipped(payload: &[u8]) -> Vec<u8> {
        use flate2::write::GzEncoder;
        use flate2::Compression;
        let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
        encoder.write_all(payload).expect("gzip the fixture");
        encoder.finish().expect("finish the gzip stream")
    }

    fn sha256_of(bytes: &[u8]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        hex::encode(hasher.finalize())
    }

    /// A release whose one asset serves whatever host the test runs on.
    fn fixture_release(target: &'static str) -> PinnedRelease {
        // Leaked so the asset can carry the `'static` lifetime the real table
        // has. One small allocation per test run, in a test binary.
        let assets: &'static [ReleaseAsset] = Box::leak(Box::new([ReleaseAsset {
            target,
            name: "rust-analyzer-fixture.gz",
            // Never consulted: every call below passes the expected digest in.
            sha256: "0000000000000000000000000000000000000000000000000000000000000000",
            size: 1,
        }]));
        PinnedRelease {
            binary: "rust-analyzer",
            project: "rust-lang/rust-analyzer",
            tag: "fixture-tag",
            base_url: "http://127.0.0.1:1/never-used",
            format: AssetFormat::Gzip,
            assets,
        }
    }

    /// The whole standalone route: fetch, verify, unpack, install, and be found
    /// by the same `which` lookup enrichment discovery performs.
    ///
    /// The discovery half is the one that would otherwise be assumed. A binary
    /// on disk with the right name is not a discovered server: `which` accepts
    /// a file only when it is executable and only when its directory is on the
    /// path being searched, and both of those are decisions this code makes.
    ///
    /// Falsified by removing the `set_executable` call in `expand_into_place`:
    /// the install still reports success and `which_in` returns nothing, so the
    /// discovery assertion is the one that fires.
    #[test]
    fn the_standalone_route_installs_a_binary_discovery_can_find() {
        let target = host_target().expect("this fleet builds on a pinned host");
        let release = fixture_release(target);
        let payload = b"#!/bin/sh\necho rust-analyzer 1.2.3\n";
        let archive = gzipped(payload);
        let digest = sha256_of(&archive);
        let (base, server) = serve_once(archive.clone());

        let home = tempfile::tempdir().expect("a scratch tool root");
        let bin_dir = home.path().join("tools").join("bin");

        let install = install_pinned_release(&release, Some(target), &bin_dir, &base, &digest)
            .expect("a served archive whose digest matches must install");
        server.join().expect("the fixture server thread must end");

        assert_eq!(install.destination, bin_dir.join("rust-analyzer"));
        assert_eq!(install.sha256, digest);
        assert!(
            install.url.starts_with(&base) && install.url.ends_with("rust-analyzer-fixture.gz"),
            "the evidence must name the URL the bytes came from: {}",
            install.url
        );

        // Unpacked, not merely copied.
        let written = std::fs::read(&install.destination).expect("read the installed binary");
        assert_eq!(
            written, payload,
            "the installed file must be the decompressed payload, not the archive"
        );

        // The archive is not left behind under a name a later run would trip on.
        let leftovers: Vec<String> = std::fs::read_dir(&bin_dir)
            .expect("list the tool bin dir")
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .filter(|name| name != "rust-analyzer")
            .collect();
        assert!(
            leftovers.is_empty(),
            "the download and staging files must be cleaned up, found {leftovers:?}"
        );

        // Registered where discovery looks: the same crate, the same lookup,
        // over the PATH `kin_core::tool_prefix` composes.
        let path = kin_core::tool_prefix::path_with_managed_tools(
            Some(&std::ffi::OsString::from("/nonexistent-for-this-test")),
            std::slice::from_ref(&bin_dir),
        )
        .expect("the tool dir must be added to a PATH that lacks it");
        let found = which::which_in("rust-analyzer", Some(&path), home.path())
            .expect("discovery must find the installed server on that PATH");
        assert_eq!(
            found.canonicalize().expect("canonicalize what which found"),
            install
                .destination
                .canonicalize()
                .expect("canonicalize the install destination"),
            "discovery must resolve to the binary this install wrote"
        );
    }

    /// Bytes that are not the pinned ones are refused, and nothing is written.
    ///
    /// The arm that proves verification runs at all. The happy-path test above
    /// passes with verification deleted, because there the digest matches by
    /// construction; only this one goes red.
    ///
    /// Falsified by deleting the `if digest != expected` block in
    /// `install_pinned_release`: this test then reports `Ok`, and the
    /// assertion that fires is the `expected a checksum refusal` panic on the
    /// `match`, followed on a repeat run by the destination-does-not-exist
    /// assertion.
    #[test]
    fn bytes_that_do_not_match_the_pin_are_refused_and_nothing_is_installed() {
        let target = host_target().expect("this fleet builds on a pinned host");
        let release = fixture_release(target);
        let archive = gzipped(b"a language server nobody pinned");
        let served_digest = sha256_of(&archive);
        // Stated independently of the bytes, which is the whole point: a digest
        // computed from what was served could never disagree with it.
        let pinned_digest = "f".repeat(64);
        assert_ne!(served_digest, pinned_digest);
        let (base, server) = serve_once(archive.clone());

        let home = tempfile::tempdir().expect("a scratch tool root");
        let bin_dir = home.path().join("tools").join("bin");

        let failure =
            install_pinned_release(&release, Some(target), &bin_dir, &base, &pinned_digest)
                .expect_err("bytes that do not match the pin must not install");
        server.join().expect("the fixture server thread must end");

        match &failure {
            InstallFailure::ChecksumMismatch {
                expected,
                actual,
                bytes,
                ..
            } => {
                assert_eq!(expected, &pinned_digest);
                assert_eq!(actual, &served_digest);
                assert_eq!(*bytes, archive.len() as u64);
            }
            other => panic!("expected a checksum refusal, got {other:?}"),
        }

        assert!(
            !bin_dir.join("rust-analyzer").exists(),
            "a refused download must leave no binary behind"
        );
        let leftovers: Vec<String> = std::fs::read_dir(&bin_dir)
            .expect("list the tool bin dir")
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().to_string())
            .collect();
        assert!(
            leftovers.is_empty(),
            "a refused download must leave no temporary file either, found {leftovers:?}"
        );
    }

    /// A server that answers with an error status is a download failure, not a
    /// digest failure.
    ///
    /// The control for the arm above. A classifier that reported every unhappy
    /// path as a checksum mismatch would pass that test while telling every
    /// operator behind a proxy that their bytes were tampered with.
    #[test]
    fn a_refused_request_is_a_download_failure_rather_than_a_mismatch() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind a loopback port");
        let port = listener.local_addr().expect("read the bound port").port();
        let server = std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let _ = stream.write_all(
                    b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                );
            }
        });

        let target = host_target().expect("this fleet builds on a pinned host");
        let release = fixture_release(target);
        let home = tempfile::tempdir().expect("a scratch tool root");
        let bin_dir = home.path().join("tools").join("bin");
        let failure = install_pinned_release(
            &release,
            Some(target),
            &bin_dir,
            &format!("http://127.0.0.1:{port}"),
            &"e".repeat(64),
        )
        .expect_err("a 404 must not install");
        server.join().expect("the fixture server thread must end");

        match &failure {
            InstallFailure::Download { reason, .. } => {
                assert!(reason.contains("404"), "{reason}");
            }
            other => panic!("a 404 must read as a download failure, got {other:?}"),
        }
    }

    /// A host with no pinned asset is refused before any request is made.
    #[test]
    fn a_host_with_no_pinned_asset_is_refused_by_name() {
        let release = fixture_release("x86_64-unknown-linux-gnu");
        let home = tempfile::tempdir().expect("a scratch tool root");
        let failure = install_pinned_release(
            &release,
            Some("powerpc64-unknown-linux-gnu"),
            &home.path().join("bin"),
            "http://127.0.0.1:1/never-used",
            &"e".repeat(64),
        )
        .expect_err("an unpinned host must be refused");
        match &failure {
            InstallFailure::UnsupportedHost { target } => {
                assert_eq!(target, "powerpc64-unknown-linux-gnu");
            }
            other => panic!("expected an unsupported-host refusal, got {other:?}"),
        }
    }

    /// The evidence lines carry the source and the digest, not just a tick.
    #[test]
    fn the_evidence_names_the_source_and_the_digest() {
        let install = ReleaseInstall {
            binary: "rust-analyzer",
            project: "rust-lang/rust-analyzer",
            tag: "2026-08-24",
            url: "https://example.invalid/rust-analyzer.gz".to_string(),
            sha256: "d".repeat(64),
            destination: PathBuf::from("/home/u/.kin/tools/bin/rust-analyzer"),
        };
        let lines = install.evidence_lines().join("\n");
        assert!(
            lines.contains("https://example.invalid/rust-analyzer.gz"),
            "{lines}"
        );
        assert!(lines.contains(&"d".repeat(64)), "{lines}");
        assert!(
            lines.contains("/home/u/.kin/tools/bin/rust-analyzer"),
            "{lines}"
        );
        assert!(lines.contains("2026-08-24"), "{lines}");
    }
}
