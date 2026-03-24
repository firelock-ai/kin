// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result};
use std::path::PathBuf;

const CURRENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const GITHUB_RELEASES_URL: &str =
    "https://api.github.com/repos/firelock-ai/kin/releases/latest";

#[derive(serde::Deserialize)]
struct GithubRelease {
    tag_name: String,
    assets: Vec<GithubAsset>,
}

#[derive(serde::Deserialize)]
struct GithubAsset {
    name: String,
    browser_download_url: String,
}

pub async fn run() -> Result<()> {
    println!("Current version: v{CURRENT_VERSION}");
    println!("Checking for updates...");

    let client = reqwest::Client::builder()
        .user_agent("kin-cli")
        .build()?;

    let release: GithubRelease = client
        .get(GITHUB_RELEASES_URL)
        .send()
        .await
        .context("failed to reach GitHub releases API")?
        .error_for_status()
        .context("GitHub API returned an error")?
        .json()
        .await
        .context("failed to parse release JSON")?;

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

    let bytes = client
        .get(&asset.browser_download_url)
        .send()
        .await
        .context("failed to download release archive")?
        .error_for_status()
        .context("download returned an error")?
        .bytes()
        .await
        .context("failed to read archive bytes")?;

    let kin_home = kin_home_dir()?;
    let bin_dir = kin_home.join("bin");
    let lib_dir = kin_home.join("lib");

    std::fs::create_dir_all(&bin_dir).context("failed to create ~/.kin/bin")?;
    std::fs::create_dir_all(&lib_dir).context("failed to create ~/.kin/lib")?;

    extract_archive(&bytes, &asset.name, &bin_dir, &lib_dir)?;

    println!("Updated to v{latest} successfully.");
    Ok(())
}

/// Compare two semver-style version strings. Returns true if `latest` > `current`.
fn is_newer(latest: &str, current: &str) -> bool {
    let parse = |v: &str| -> Vec<u64> {
        v.split('.')
            .filter_map(|s| s.parse::<u64>().ok())
            .collect()
    };
    let l = parse(latest);
    let c = parse(current);
    l > c
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

fn extract_zip(
    bytes: &[u8],
    bin_dir: &std::path::Path,
    lib_dir: &std::path::Path,
) -> Result<()> {
    use std::io::Read;
    let cursor = std::io::Cursor::new(bytes);
    let mut archive = zip::ZipArchive::new(cursor).context("failed to open zip archive")?;

    for i in 0..archive.len() {
        let mut file = archive.by_index(i).context("corrupt zip entry")?;
        let Some(file_name) = file.enclosed_name().and_then(|p| p.file_name().map(|f| f.to_owned())) else {
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
