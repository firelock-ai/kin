// SPDX-License-Identifier: BUSL-1.1
// Copyright 2026 Firelock, LLC

use serde::{Deserialize, Serialize};
use std::process::Command;

/// Information about a detected assistant CLI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CliInfo {
    pub name: String,
    pub binary: String,
    pub version: Option<String>,
}

/// Detect which assistant CLIs are available on PATH.
/// Checks for: claude, codex, kin-pilot, gemini.
pub fn detect_available_clis() -> Vec<CliInfo> {
    let checks = vec![
        ("Claude Code", "claude"),
        ("Codex", "codex"),
        ("Kin Pilot", "kin-pilot"),
        ("Gemini CLI", "gemini"),
    ];

    let mut clis = Vec::new();
    for (name, binary) in checks {
        if let Some(version) = check_cli(binary) {
            clis.push(CliInfo {
                name: name.to_string(),
                binary: binary.to_string(),
                version,
            });
        }
    }
    clis
}

/// Check if a CLI binary exists and get its version.
fn check_cli(binary: &str) -> Option<Option<String>> {
    let output = Command::new(binary).arg("--version").output().ok()?;

    if output.status.success() {
        let version = String::from_utf8_lossy(&output.stdout).trim().to_string();
        Some(if version.is_empty() {
            None
        } else {
            Some(version)
        })
    } else {
        // Some CLIs return non-zero for --version but still exist.
        // Try --help as fallback.
        let help = Command::new(binary).arg("--help").output().ok()?;
        if help.status.success() || !String::from_utf8_lossy(&help.stdout).is_empty() {
            Some(None) // exists but couldn't get version
        } else {
            None
        }
    }
}

/// Filter CLIs by name (case-insensitive match on name or binary).
pub fn filter_clis(clis: Vec<CliInfo>, filter: &str) -> Vec<CliInfo> {
    let filter_lower = filter.to_lowercase();
    clis.into_iter()
        .filter(|c| {
            c.binary.to_lowercase() == filter_lower || c.name.to_lowercase().contains(&filter_lower)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_returns_vec() {
        // May be empty in CI or environments without assistant CLIs installed.
        let clis = detect_available_clis();
        // Just assert we get a vec back — can't assume any CLI is installed.
        let _ = clis.len();
    }

    #[test]
    fn filter_clis_by_binary() {
        let clis = vec![
            CliInfo {
                name: "Claude Code".to_string(),
                binary: "claude".to_string(),
                version: Some("1.0".to_string()),
            },
            CliInfo {
                name: "Codex".to_string(),
                binary: "codex".to_string(),
                version: None,
            },
        ];

        let filtered = filter_clis(clis, "claude");
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].binary, "claude");
    }

    #[test]
    fn filter_clis_by_name_substring() {
        let clis = vec![
            CliInfo {
                name: "Claude Code".to_string(),
                binary: "claude".to_string(),
                version: None,
            },
            CliInfo {
                name: "Gemini CLI".to_string(),
                binary: "gemini".to_string(),
                version: None,
            },
        ];

        let filtered = filter_clis(clis, "gemini");
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].name, "Gemini CLI");
    }

    #[test]
    fn filter_clis_case_insensitive() {
        let clis = vec![CliInfo {
            name: "Claude Code".to_string(),
            binary: "claude".to_string(),
            version: None,
        }];

        let filtered = filter_clis(clis, "CLAUDE");
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn filter_clis_no_match() {
        let clis = vec![CliInfo {
            name: "Claude Code".to_string(),
            binary: "claude".to_string(),
            version: None,
        }];

        let filtered = filter_clis(clis, "nonexistent");
        assert!(filtered.is_empty());
    }

    #[test]
    fn cli_info_serialization_roundtrip() {
        let info = CliInfo {
            name: "Claude Code".to_string(),
            binary: "claude".to_string(),
            version: Some("1.2.3".to_string()),
        };
        let json = serde_json::to_string(&info).unwrap();
        let parsed: CliInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "Claude Code");
        assert_eq!(parsed.binary, "claude");
        assert_eq!(parsed.version, Some("1.2.3".to_string()));
    }
}
