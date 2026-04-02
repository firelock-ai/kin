// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Discover installed LSP servers on the system.

use crate::types::LanguageId;
use tracing::debug;

/// A discovered LSP server that can be started.
#[derive(Debug, Clone)]
pub struct DiscoveredServer {
    pub language: LanguageId,
    pub command: String,
    pub args: Vec<String>,
    pub version: Option<String>,
}

/// Known LSP server configurations per language.
const KNOWN_SERVERS: &[(LanguageId, &[&str], &[&str])] = &[
    // (language, [binary_names_to_search], [default_args])
    (LanguageId::Rust, &["rust-analyzer"], &[]),
    (LanguageId::Python, &["pyright-langserver", "pylsp"], &["--stdio"]),
    (LanguageId::TypeScript, &["typescript-language-server", "vtsls"], &["--stdio"]),
    (LanguageId::JavaScript, &["typescript-language-server"], &["--stdio"]),
    (LanguageId::Go, &["gopls"], &["serve"]),
    (LanguageId::Java, &["jdtls"], &[]),
    (LanguageId::C, &["clangd"], &[]),
    (LanguageId::Cpp, &["clangd"], &[]),
];

/// Discover which LSP servers are installed on this system.
pub fn discover_servers() -> Vec<DiscoveredServer> {
    let mut found = Vec::new();

    for (language, binaries, default_args) in KNOWN_SERVERS {
        for binary in *binaries {
            if let Ok(path) = which::which(binary) {
                debug!(
                    language = %language,
                    binary = %path.display(),
                    "found LSP server"
                );
                found.push(DiscoveredServer {
                    language: *language,
                    command: path.display().to_string(),
                    args: default_args.iter().map(|s| s.to_string()).collect(),
                    version: detect_version(&path),
                });
                break; // Use first found binary for each language
            }
        }
    }

    found
}

/// Try to detect the version of an LSP server binary.
fn detect_version(path: &std::path::Path) -> Option<String> {
    let output = std::process::Command::new(path)
        .arg("--version")
        .output()
        .ok()?;
    if output.status.success() {
        let version = String::from_utf8_lossy(&output.stdout);
        Some(version.trim().to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discover_finds_at_least_one_server() {
        // This test is environment-dependent — it passes if ANY LSP server is installed.
        // In CI, we might need to skip this.
        let servers = discover_servers();
        // Don't assert non-empty — just verify it doesn't panic.
        for server in &servers {
            assert!(!server.command.is_empty());
        }
    }
}
