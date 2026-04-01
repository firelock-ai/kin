// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::path::Path;

/// Run `cargo package` for each package, then upload the `.crate` files to the
/// registry.  If no `-p` packages are given, packages the crate in the current
/// directory.
pub async fn run(packages: Vec<String>, registry: String, dry_run: bool) -> Result<()> {
    let packages = if packages.is_empty() {
        // Infer the package name from the Cargo.toml in the current directory.
        let manifest = std::env::current_dir()?.join("Cargo.toml");
        let name = read_package_name(&manifest)
            .context("no -p flag and no Cargo.toml in current directory")?;
        vec![name]
    } else {
        packages
    };

    for package in &packages {
        let version = resolve_version(package)?;
        println!("Packaging {}@{} ...", package, version);

        // Run cargo package
        let output = std::process::Command::new("cargo")
            .args(["package", "-p", package, "--allow-dirty"])
            .output()
            .context("failed to spawn cargo")?;

        if !output.status.success() {
            bail!(
                "cargo package failed for {}:\n{}",
                package,
                String::from_utf8_lossy(&output.stderr)
            );
        }

        // Locate the .crate file
        let crate_file = format!("target/package/{}-{}.crate", package, version);
        let crate_bytes =
            std::fs::read(&crate_file).with_context(|| format!("could not read {}", crate_file))?;

        // Compute checksum
        let mut hasher = Sha256::new();
        hasher.update(&crate_bytes);
        let checksum = hex::encode(hasher.finalize());

        if dry_run {
            println!(
                "[dry-run] Would publish {} ({} bytes, sha256: {})",
                crate_file,
                crate_bytes.len(),
                checksum
            );
            continue;
        }

        // Upload
        publish_crate(&registry, package, &version, &crate_bytes).await?;
        println!("Published {}@{} (sha256: {})", package, version, checksum);
    }

    Ok(())
}

/// POST the `.crate` bytes to the registry endpoint.
async fn publish_crate(
    registry: &str,
    name: &str,
    version: &str,
    crate_bytes: &[u8],
) -> Result<()> {
    let url = format!(
        "{}/registry/cargo/api/v1/crates/publish?name={}&version={}",
        registry.trim_end_matches('/'),
        name,
        version
    );

    let client = reqwest::Client::new();
    let response = client
        .post(&url)
        .header("content-type", "application/octet-stream")
        .body(crate_bytes.to_vec())
        .send()
        .await
        .context("failed to reach registry")?;

    if !response.status().is_success() {
        let status = response.status();
        let error_text = response.text().await.unwrap_or_default();
        bail!("publish failed ({}): {}", status, error_text);
    }

    Ok(())
}

/// Read the `[package] name` field from a Cargo.toml.
fn read_package_name(manifest_path: &Path) -> Result<String> {
    let text = std::fs::read_to_string(manifest_path)
        .with_context(|| format!("cannot read {}", manifest_path.display()))?;
    extract_toml_field(&text, "name")
        .ok_or_else(|| anyhow::anyhow!("no [package] name in {}", manifest_path.display()))
}

/// Resolve the version of a cargo package by running `cargo metadata`.
fn resolve_version(package: &str) -> Result<String> {
    let output = std::process::Command::new("cargo")
        .args(["metadata", "--no-deps", "--format-version=1"])
        .output()
        .context("failed to spawn cargo metadata")?;

    if !output.status.success() {
        bail!(
            "cargo metadata failed:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let json: serde_json::Value =
        serde_json::from_slice(&output.stdout).context("invalid cargo metadata JSON")?;

    let packages = json["packages"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("no packages in cargo metadata"))?;

    for pkg in packages {
        if pkg["name"].as_str() == Some(package) {
            if let Some(version) = pkg["version"].as_str() {
                return Ok(version.to_string());
            }
        }
    }

    bail!("package '{}' not found in cargo metadata", package)
}

/// Minimal TOML field extraction (avoids pulling in toml crate just for one field).
fn extract_toml_field(text: &str, field: &str) -> Option<String> {
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with(&format!("{} ", field))
            || trimmed.starts_with(&format!("{}=", field))
        {
            // name = "foo"  or  name="foo"
            if let Some((_left, right)) = trimmed.split_once('=') {
                let value = right.trim().trim_matches('"');
                return Some(value.to_string());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_name_from_toml() {
        let toml = r#"
[package]
name = "my-crate"
version = "0.1.0"
"#;
        assert_eq!(
            extract_toml_field(toml, "name"),
            Some("my-crate".to_string())
        );
    }

    #[test]
    fn extract_name_no_spaces() {
        let toml = r#"
[package]
name="compact"
"#;
        assert_eq!(
            extract_toml_field(toml, "name"),
            Some("compact".to_string())
        );
    }

    #[test]
    fn extract_missing_field() {
        assert_eq!(
            extract_toml_field("[package]\nversion = \"1\"", "name"),
            None
        );
    }
}
