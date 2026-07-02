// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::path::PathBuf;

const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const GITHUB_RELEASES_LATEST_URL: &str =
    "https://api.github.com/repos/firelock-ai/kin/releases/latest";
const GITHUB_RELEASES_LIST_URL: &str =
    "https://api.github.com/repos/firelock-ai/kin/releases?per_page=30";

/// Expected release asset names for integrity verification.
const CHECKSUMS_ASSET: &str = "checksums-sha256.txt";
const SIGNATURE_ASSET: &str = "checksums-sha256.txt.sig";

/// Firelock release-signing public key (ed25519, hex-encoded).
///
/// Set via `KIN_RELEASE_PUBLIC_KEY` env var at compile time. CI release builds
/// inject the real key; local dev builds get `None` and must use `--skip-verify`.
///
/// To rotate: generate a new keypair with `kin keygen --release`, update the CI
/// secret, and re-sign all active release assets with the new key.
const RELEASE_PUBLIC_KEY_HEX: Option<&str> = option_env!("KIN_RELEASE_PUBLIC_KEY");

#[derive(serde::Deserialize)]
struct GithubRelease {
    tag_name: String,
    /// GitHub marks any tag containing `-` (e.g. `-alpha`/`-beta`/`-rc`) as a
    /// pre-release. Used to select builds for the alpha channel.
    #[serde(default)]
    prerelease: bool,
    assets: Vec<GithubAsset>,
}

/// Release channel selected for `kin update`.
#[derive(
    Clone,
    Copy,
    Debug,
    Default,
    PartialEq,
    Eq,
    serde::Serialize,
    serde::Deserialize,
    clap::ValueEnum,
)]
#[serde(rename_all = "lowercase")]
pub enum Channel {
    /// Stable releases only. The default.
    #[default]
    Stable,
    /// Latest pre-release (alpha/beta/rc) build. Unstable — not for production.
    Alpha,
}

fn channel_name(channel: Channel) -> &'static str {
    match channel {
        Channel::Stable => "stable",
        Channel::Alpha => "alpha",
    }
}

/// Persisted update preferences, stored at `~/.kin/update.toml`.
#[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
struct UpdateConfig {
    #[serde(default)]
    channel: Channel,
}

impl UpdateConfig {
    fn path() -> Result<PathBuf> {
        Ok(kin_home_dir()?.join("update.toml"))
    }

    /// Load stored preferences, falling back to defaults on any missing file or
    /// parse error (the preference is advisory, never a hard failure).
    fn load() -> Self {
        Self::path()
            .ok()
            .and_then(|p| std::fs::read_to_string(p).ok())
            .and_then(|s| toml::from_str(&s).ok())
            .unwrap_or_default()
    }

    fn save(&self) -> Result<()> {
        let path = Self::path()?;
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).context("failed to create ~/.kin")?;
        }
        let contents = toml::to_string_pretty(self).context("failed to serialize update config")?;
        std::fs::write(&path, contents)
            .with_context(|| format!("failed to write {}", path.display()))?;
        Ok(())
    }
}

/// Resolve the effective channel: an explicit `--channel` flag wins and is saved
/// as the new default; otherwise the stored default is used; otherwise `stable`.
fn resolve_channel(flag: Option<Channel>) -> Channel {
    let stored = UpdateConfig::load().channel;
    if let Some(requested) = flag {
        if requested != stored {
            // Persisting is best-effort: a write failure must not block the update.
            match (UpdateConfig { channel: requested }).save() {
                Ok(()) => println!("Saved default update channel: {}", channel_name(requested)),
                Err(e) => eprintln!("Note: could not persist update channel preference: {e}"),
            }
        }
    }
    effective_channel(flag, stored)
}

/// Pure channel-precedence rule (flag over stored default), split out for tests.
fn effective_channel(flag: Option<Channel>, stored: Channel) -> Channel {
    flag.unwrap_or(stored)
}

#[derive(serde::Deserialize)]
struct GithubAsset {
    name: String,
    browser_download_url: String,
}

pub async fn run(skip_verify: bool, channel_flag: Option<Channel>) -> Result<()> {
    println!("Current version: v{CURRENT_VERSION}");

    let channel = resolve_channel(channel_flag);
    match channel {
        Channel::Stable => println!("Update channel: stable"),
        Channel::Alpha => {
            println!("Update channel: alpha (pre-release)");
            eprintln!(
                "WARNING: alpha builds are pre-releases. They are unstable, may change \
                 or break without notice, and are not recommended for production use. \
                 Switch back with `kin update --channel stable`."
            );
        }
    }
    println!("Checking for updates...");

    let client = reqwest::Client::builder().user_agent("kin-cli").build()?;

    let release = resolve_release(&client, channel).await?;

    let latest = release.tag_name.trim_start_matches('v');

    if !is_newer(latest, CURRENT_VERSION) {
        println!("Already up to date (v{CURRENT_VERSION}).");
        return Ok(());
    }

    println!("New version available: v{latest}");

    let (os, arch) = detect_platform()?;
    let archive_suffix = format!("kin-{os}-{arch}");

    let asset = release
        .assets
        .iter()
        .find(|a| a.name.contains(&archive_suffix))
        .with_context(|| {
            format!(
                "no release asset found for platform {os}-{arch} (looked for '{archive_suffix}' in {} assets)",
                release.assets.len()
            )
        })?;

    println!("Downloading {}...", asset.name);

    let archive_bytes = client
        .get(&asset.browser_download_url)
        .send()
        .await
        .context("failed to download release archive")?
        .error_for_status()
        .context("download returned an error")?
        .bytes()
        .await
        .context("failed to read archive bytes")?;

    // --- Integrity verification ---
    if skip_verify {
        eprintln!(
            "WARNING: --skip-verify is set. Skipping signature and checksum \
             verification. This binary has NOT been authenticated."
        );
    } else {
        verify_archive(&client, &release, &asset.name, &archive_bytes).await?;
    }

    let kin_home = kin_home_dir()?;
    let bin_dir = kin_home.join("bin");
    let lib_dir = kin_home.join("lib");

    std::fs::create_dir_all(&bin_dir).context("failed to create ~/.kin/bin")?;
    std::fs::create_dir_all(&lib_dir).context("failed to create ~/.kin/lib")?;

    // Atomic binary replacement: rm then write (avoids dyld deadlock on macOS
    // when overwriting a mapped binary inode — see CLAUDE.md debugging guide).
    remove_existing_binaries(&bin_dir);

    extract_archive(&archive_bytes, &asset.name, &bin_dir, &lib_dir)?;

    println!("Updated to v{latest} successfully.");
    Ok(())
}

/// Fetch the release to install for the requested channel.
///
/// Stable uses the GitHub `releases/latest` endpoint (which never returns a
/// pre-release). Alpha lists releases and picks the newest pre-release.
async fn resolve_release(client: &reqwest::Client, channel: Channel) -> Result<GithubRelease> {
    match channel {
        Channel::Stable => {
            let release: GithubRelease = client
                .get(GITHUB_RELEASES_LATEST_URL)
                .send()
                .await
                .context("failed to reach GitHub releases API")?
                .error_for_status()
                .context("GitHub API returned an error")?
                .json()
                .await
                .context("failed to parse release JSON")?;
            Ok(release)
        }
        Channel::Alpha => {
            let releases: Vec<GithubRelease> = client
                .get(GITHUB_RELEASES_LIST_URL)
                .send()
                .await
                .context("failed to reach GitHub releases API")?
                .error_for_status()
                .context("GitHub API returned an error")?
                .json()
                .await
                .context("failed to parse releases JSON")?;
            select_alpha(releases).context(
                "no pre-release build is available on the alpha channel yet. \
                 See https://github.com/firelock-ai/kin/releases",
            )
        }
    }
}

/// Select the newest pre-release from a list of releases (highest version wins).
fn select_alpha(releases: Vec<GithubRelease>) -> Option<GithubRelease> {
    releases
        .into_iter()
        .filter(|r| r.prerelease || r.tag_name.contains('-'))
        .max_by(|a, b| {
            compare_versions(
                a.tag_name.trim_start_matches('v'),
                b.tag_name.trim_start_matches('v'),
            )
        })
}

/// Download the checksums file and its ed25519 signature from the release,
/// verify the signature, then verify the archive's SHA-256 matches.
async fn verify_archive(
    client: &reqwest::Client,
    release: &GithubRelease,
    archive_name: &str,
    archive_bytes: &[u8],
) -> Result<()> {
    use ed25519_dalek::{Signature, VerifyingKey};

    println!("Verifying release signature...");

    // 1. Find the checksums + signature assets.
    let checksums_asset = release
        .assets
        .iter()
        .find(|a| a.name == CHECKSUMS_ASSET)
        .with_context(|| {
            format!(
                "release is missing '{CHECKSUMS_ASSET}' — cannot verify integrity. \
                 Use --skip-verify to bypass (NOT recommended)."
            )
        })?;

    let sig_asset = release
        .assets
        .iter()
        .find(|a| a.name == SIGNATURE_ASSET)
        .with_context(|| {
            format!(
                "release is missing '{SIGNATURE_ASSET}' — cannot verify integrity. \
                 Use --skip-verify to bypass (NOT recommended)."
            )
        })?;

    // 2. Download both.
    let checksums_bytes = client
        .get(&checksums_asset.browser_download_url)
        .send()
        .await
        .context("failed to download checksums file")?
        .error_for_status()?
        .bytes()
        .await
        .context("failed to read checksums bytes")?;

    let sig_bytes = client
        .get(&sig_asset.browser_download_url)
        .send()
        .await
        .context("failed to download signature file")?
        .error_for_status()?
        .bytes()
        .await
        .context("failed to read signature bytes")?;

    // 3. Verify ed25519 signature of checksums file.
    let pub_key_hex = RELEASE_PUBLIC_KEY_HEX.with_context(|| {
        "this binary was built without a release signing key \
         (KIN_RELEASE_PUBLIC_KEY not set at compile time). \
         Use --skip-verify for development builds."
    })?;
    let pub_key_bytes =
        hex::decode(pub_key_hex).context("invalid release public key (hex decode failed)")?;
    let pub_key_array: [u8; 32] = pub_key_bytes.try_into().map_err(|v: Vec<u8>| {
        anyhow::anyhow!("release public key is {} bytes, expected 32", v.len())
    })?;
    let verifying_key = VerifyingKey::from_bytes(&pub_key_array)
        .context("invalid release public key (not on curve)")?;

    // Signature file contains raw 64-byte ed25519 signature.
    let sig_array: [u8; 64] = sig_bytes.as_ref().try_into().map_err(|_| {
        anyhow::anyhow!(
            "signature file is {} bytes, expected 64-byte ed25519 signature",
            sig_bytes.len()
        )
    })?;
    let signature = Signature::from_bytes(&sig_array);

    verifying_key
        .verify_strict(&checksums_bytes, &signature)
        .map_err(|_| {
            anyhow::anyhow!(
                "SIGNATURE VERIFICATION FAILED.\n\
             The checksums file was NOT signed by Firelock's release key.\n\
             This could indicate a compromised release. Aborting update.\n\
             If you believe this is an error, check https://github.com/firelock-ai/kin/releases"
            )
        })?;

    println!("  Signature valid (ed25519, Firelock release key).");

    // 4. Compute SHA-256 of the downloaded archive.
    let mut hasher = Sha256::new();
    hasher.update(archive_bytes);
    let archive_hash = hex::encode(hasher.finalize());

    // 5. Find the expected hash in the checksums file.
    let checksums_text =
        std::str::from_utf8(&checksums_bytes).context("checksums file is not valid UTF-8")?;

    let expected_hash = parse_checksum(checksums_text, archive_name).with_context(|| {
        format!(
            "archive '{archive_name}' not found in signed checksums file. \
                 Available entries:\n{checksums_text}"
        )
    })?;

    // 6. Compare.
    if archive_hash != expected_hash {
        anyhow::bail!(
            "SHA-256 MISMATCH.\n\
             Expected: {expected_hash}\n\
             Got:      {archive_hash}\n\
             The downloaded archive does not match the signed checksum.\n\
             This could indicate a corrupted download or tampered release. Aborting."
        );
    }

    println!("  SHA-256 checksum verified ({}).", &archive_hash[..16]);
    Ok(())
}

/// Parse a `sha256sum`-style checksums file and return the hash for `filename`.
///
/// Format: `<hex-hash>  <filename>` (two spaces, matching coreutils sha256sum output).
fn parse_checksum(checksums_text: &str, filename: &str) -> Option<String> {
    for line in checksums_text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // Support both "hash  filename" (two spaces) and "hash filename" (one space).
        if let Some((hash, name)) = line.split_once(char::is_whitespace) {
            let name = name.trim();
            if name == filename {
                return Some(hash.to_lowercase());
            }
        }
    }
    None
}

/// Remove existing kin binaries before writing new ones.
/// This avoids the dyld deadlock described in the debugging guide:
/// `cp` over a mapped inode can wedge the dynamic linker on macOS.
fn remove_existing_binaries(bin_dir: &std::path::Path) {
    for name in &["kin", "kin-daemon", "kin-mcp"] {
        let path = bin_dir.join(name);
        if path.exists() {
            let _ = std::fs::remove_file(&path);
        }
    }
}

/// Compare two semver-style version strings. Returns true if `latest` > `current`.
///
/// Understands pre-release suffixes (e.g. `0.2.7-alpha.1`) per semver precedence:
/// a pre-release ranks below its released version, and pre-release identifiers are
/// compared numerically when numeric, otherwise lexically. This keeps the alpha
/// channel from ever offering a downgrade from a newer stable build.
fn is_newer(latest: &str, current: &str) -> bool {
    compare_versions(latest, current) == Ordering::Greater
}

fn compare_versions(a: &str, b: &str) -> Ordering {
    let (a_core, a_pre) = split_version(a);
    let (b_core, b_pre) = split_version(b);
    match compare_numeric(&a_core, &b_core) {
        Ordering::Equal => compare_prerelease(a_pre.as_deref(), b_pre.as_deref()),
        ord => ord,
    }
}

/// Split `1.2.3-alpha.4` into `([1, 2, 3], Some(["alpha", "4"]))`.
fn split_version(v: &str) -> (Vec<u64>, Option<Vec<String>>) {
    let v = v.trim_start_matches('v');
    let (core, pre) = match v.split_once('-') {
        Some((core, pre)) => (core, Some(pre)),
        None => (v, None),
    };
    let core_nums = core
        .split('.')
        .map(|s| s.parse::<u64>().unwrap_or(0))
        .collect();
    let pre_ids = pre.map(|p| p.split('.').map(str::to_string).collect());
    (core_nums, pre_ids)
}

fn compare_numeric(a: &[u64], b: &[u64]) -> Ordering {
    for i in 0..a.len().max(b.len()) {
        let x = a.get(i).copied().unwrap_or(0);
        let y = b.get(i).copied().unwrap_or(0);
        match x.cmp(&y) {
            Ordering::Equal => continue,
            ord => return ord,
        }
    }
    Ordering::Equal
}

fn compare_prerelease(a: Option<&[String]>, b: Option<&[String]>) -> Ordering {
    match (a, b) {
        (None, None) => Ordering::Equal,
        // A released version outranks any pre-release of the same core.
        (None, Some(_)) => Ordering::Greater,
        (Some(_), None) => Ordering::Less,
        (Some(a), Some(b)) => {
            for i in 0..a.len().max(b.len()) {
                match (a.get(i), b.get(i)) {
                    (Some(x), Some(y)) => match compare_prerelease_id(x, y) {
                        Ordering::Equal => continue,
                        ord => return ord,
                    },
                    // More identifiers wins when the shared prefix is equal.
                    (Some(_), None) => return Ordering::Greater,
                    (None, Some(_)) => return Ordering::Less,
                    (None, None) => break,
                }
            }
            Ordering::Equal
        }
    }
}

fn compare_prerelease_id(a: &str, b: &str) -> Ordering {
    match (a.parse::<u64>(), b.parse::<u64>()) {
        (Ok(x), Ok(y)) => x.cmp(&y),
        // Numeric identifiers always rank lower than alphanumeric ones.
        (Ok(_), Err(_)) => Ordering::Less,
        (Err(_), Ok(_)) => Ordering::Greater,
        (Err(_), Err(_)) => a.cmp(b),
    }
}

fn detect_platform() -> Result<(&'static str, &'static str)> {
    let os = if cfg!(target_os = "macos") {
        "darwin"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else {
        anyhow::bail!("unsupported OS");
    };

    let arch = if cfg!(target_arch = "x86_64") {
        "amd64"
    } else if cfg!(target_arch = "aarch64") {
        "arm64"
    } else {
        anyhow::bail!("unsupported architecture");
    };

    Ok((os, arch))
}

fn kin_home_dir() -> Result<PathBuf> {
    let base = directories::BaseDirs::new().context("could not determine home directory")?;
    Ok(base.home_dir().join(".kin"))
}

fn extract_archive(
    bytes: &[u8],
    name: &str,
    bin_dir: &std::path::Path,
    lib_dir: &std::path::Path,
) -> Result<()> {
    if name.ends_with(".tar.gz") || name.ends_with(".tgz") {
        extract_tar_gz(bytes, bin_dir, lib_dir)
    } else if name.ends_with(".zip") {
        extract_zip(bytes, bin_dir, lib_dir)
    } else {
        anyhow::bail!("unknown archive format: {name}");
    }
}

fn extract_tar_gz(
    bytes: &[u8],
    bin_dir: &std::path::Path,
    lib_dir: &std::path::Path,
) -> Result<()> {
    use std::io::Read;
    let decoder = flate2::read::GzDecoder::new(bytes);
    let mut archive = tar::Archive::new(decoder);

    for entry in archive.entries().context("failed to read tar entries")? {
        let mut entry = entry.context("corrupt tar entry")?;
        let path = entry.path().context("invalid entry path")?.into_owned();
        let Some(file_name) = path.file_name() else {
            continue;
        };
        let file_name_str = file_name.to_string_lossy();

        // Determine destination based on file type
        let dest = if is_binary(&file_name_str) {
            bin_dir.join(file_name)
        } else if is_lib(&file_name_str) {
            lib_dir.join(file_name)
        } else {
            continue;
        };

        let mut buf = Vec::new();
        entry.read_to_end(&mut buf)?;
        std::fs::write(&dest, &buf)
            .with_context(|| format!("failed to write {}", dest.display()))?;

        // Mark binaries executable on Unix
        #[cfg(unix)]
        if is_binary(&file_name_str) {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755))?;
        }
    }
    Ok(())
}

fn extract_zip(bytes: &[u8], bin_dir: &std::path::Path, lib_dir: &std::path::Path) -> Result<()> {
    use std::io::Read;
    let cursor = std::io::Cursor::new(bytes);
    let mut archive = zip::ZipArchive::new(cursor).context("failed to open zip archive")?;

    for i in 0..archive.len() {
        let mut file = archive.by_index(i).context("corrupt zip entry")?;
        let Some(file_name) = file
            .enclosed_name()
            .and_then(|p| p.file_name().map(|f| f.to_owned()))
        else {
            continue;
        };
        let file_name_str = file_name.to_string_lossy();

        let dest = if is_binary(&file_name_str) {
            bin_dir.join(&file_name)
        } else if is_lib(&file_name_str) {
            lib_dir.join(&file_name)
        } else {
            continue;
        };

        let mut buf = Vec::new();
        file.read_to_end(&mut buf)?;
        std::fs::write(&dest, &buf)
            .with_context(|| format!("failed to write {}", dest.display()))?;

        #[cfg(unix)]
        if is_binary(&file_name_str) {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755))?;
        }
    }
    Ok(())
}

fn is_binary(name: &str) -> bool {
    let base = name.strip_suffix(".exe").unwrap_or(name);
    matches!(base, "kin" | "kin-daemon" | "kin-mcp")
}

fn is_lib(name: &str) -> bool {
    name.ends_with(".so") || name.ends_with(".dylib") || name.ends_with(".dll")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_comparison() {
        assert!(is_newer("0.2.0", "0.1.0"));
        assert!(is_newer("1.0.0", "0.9.9"));
        assert!(!is_newer("0.1.0", "0.1.0"));
        assert!(!is_newer("0.1.0", "0.2.0"));
    }

    #[test]
    fn version_comparison_understands_prereleases() {
        // A pre-release of a higher core beats a lower stable release.
        assert!(is_newer("0.2.7-alpha.1", "0.2.6"));
        // A newer alpha beats an older alpha of the same core.
        assert!(is_newer("0.2.7-alpha.2", "0.2.7-alpha.1"));
        // A stable release outranks its own pre-release.
        assert!(is_newer("0.2.7", "0.2.7-alpha.9"));
        // A pre-release never outranks its released version (no downgrade).
        assert!(!is_newer("0.2.7-alpha.1", "0.2.7"));
        // Equal pre-releases are not newer.
        assert!(!is_newer("0.2.7-alpha.1", "0.2.7-alpha.1"));
        // Alphanumeric identifiers rank above numeric; 'beta' > 'alpha' lexically.
        assert!(is_newer("0.2.7-beta", "0.2.7-alpha.1"));
        // Leading 'v' is tolerated on either side.
        assert!(is_newer("v0.2.7", "v0.2.6"));
    }

    #[test]
    fn effective_channel_precedence() {
        // An explicit flag wins over the stored default.
        assert_eq!(
            effective_channel(Some(Channel::Alpha), Channel::Stable),
            Channel::Alpha
        );
        assert_eq!(
            effective_channel(Some(Channel::Stable), Channel::Alpha),
            Channel::Stable
        );
        // No flag falls back to the stored default.
        assert_eq!(effective_channel(None, Channel::Alpha), Channel::Alpha);
        assert_eq!(effective_channel(None, Channel::Stable), Channel::Stable);
        // The out-of-the-box default is stable.
        assert_eq!(Channel::default(), Channel::Stable);
    }

    #[test]
    fn update_config_toml_roundtrip() {
        let text = toml::to_string_pretty(&UpdateConfig {
            channel: Channel::Alpha,
        })
        .unwrap();
        assert!(text.contains("channel = \"alpha\""));

        let parsed: UpdateConfig = toml::from_str(&text).unwrap();
        assert_eq!(parsed.channel, Channel::Alpha);

        // A missing/empty config deserializes to the stable default.
        let empty: UpdateConfig = toml::from_str("").unwrap();
        assert_eq!(empty.channel, Channel::Stable);
    }

    #[test]
    fn select_alpha_picks_newest_prerelease() {
        let mk = |tag: &str, prerelease: bool| GithubRelease {
            tag_name: tag.to_string(),
            prerelease,
            assets: vec![],
        };

        let picked = select_alpha(vec![
            mk("v0.2.6", false), // stable, must be ignored
            mk("v0.2.7-alpha.1", true),
            mk("v0.2.7-alpha.3", true), // newest pre-release
            mk("v0.2.7-alpha.2", true),
        ])
        .expect("a pre-release should be selected");
        assert_eq!(picked.tag_name, "v0.2.7-alpha.3");

        // No pre-releases available → nothing to select.
        assert!(select_alpha(vec![mk("v0.2.6", false)]).is_none());
    }

    #[test]
    fn parse_checksum_finds_entry() {
        let checksums = "\
            abc123def456  kin-darwin-arm64.tar.gz\n\
            789abc012def  kin-linux-amd64.tar.gz\n";
        assert_eq!(
            parse_checksum(checksums, "kin-darwin-arm64.tar.gz"),
            Some("abc123def456".to_string())
        );
        assert_eq!(
            parse_checksum(checksums, "kin-linux-amd64.tar.gz"),
            Some("789abc012def".to_string())
        );
        assert_eq!(parse_checksum(checksums, "kin-windows-amd64.zip"), None);
    }

    #[test]
    fn parse_checksum_handles_comments_and_blanks() {
        let checksums = "\
            # SHA-256 checksums for kin v0.2.0\n\
            \n\
            abc123  kin-darwin-arm64.tar.gz\n";
        assert_eq!(
            parse_checksum(checksums, "kin-darwin-arm64.tar.gz"),
            Some("abc123".to_string())
        );
    }

    #[test]
    fn parse_checksum_normalizes_case() {
        let checksums = "ABCDEF123456  kin-linux-amd64.tar.gz\n";
        assert_eq!(
            parse_checksum(checksums, "kin-linux-amd64.tar.gz"),
            Some("abcdef123456".to_string())
        );
    }

    #[test]
    fn signature_verification_roundtrip() {
        use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};

        // Generate a test keypair.
        let signing_key = SigningKey::from_bytes(&[42u8; 32]);
        let verifying_key = VerifyingKey::from(&signing_key);

        let message = b"abc123  kin-darwin-arm64.tar.gz\n";
        let signature: Signature = signing_key.sign(message);

        // Good signature passes.
        assert!(verifying_key.verify_strict(message, &signature).is_ok());

        // Tampered message fails.
        let tampered = b"xxx123  kin-darwin-arm64.tar.gz\n";
        assert!(verifying_key.verify_strict(tampered, &signature).is_err());
    }
}
