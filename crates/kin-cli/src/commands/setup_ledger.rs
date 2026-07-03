// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Install ledger for `kin setup`.
//!
//! Records exactly what `kin setup` wrote and where, each with a SHA-256
//! fingerprint of the specific slice Kin owns — not the whole file, because Kin
//! merges into shared user config (a client's JSON has other MCP servers, a
//! shell rc has other lines). The ledger powers three things:
//!
//! - **Verification** — `kin setup status`, `kin doctor`, and `kin setup
//!   --check` compare current disk state against what Kin recorded: present and
//!   unmodified, modified since install, or removed.
//! - **Idempotent uninstall** — `kin setup uninstall` removes exactly the slice
//!   Kin wrote and refuses to touch anything modified since install (fingerprint
//!   mismatch → left in place and reported), so a user's own edits are never
//!   clobbered.
//! - **Idempotent re-install** — re-recording an artifact updates its entry in
//!   place, preserving the original install timestamp.
//!
//! The data model and every verify/uninstall primitive here are pure over
//! explicit paths so they are unit-testable without touching a real `$HOME`.
//! The glue that knows *what* `kin setup` writes lives in [`super::setup`].

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};

/// Current on-disk schema version for the ledger file. Bump when the shape of
/// [`LedgerEntry`] changes incompatibly.
pub const LEDGER_SCHEMA_VERSION: u32 = 1;

/// The class of artifact an entry tracks. Determines how the owned slice is
/// fingerprinted, verified, and removed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    /// The `mcpServers.kin` entry merged into an AI client's JSON config. The
    /// owned slice is that one sub-value; siblings are untouched.
    McpConfig,
    /// A `~/.kin/shell/kin-vfs.<shell>` hook file Kin owns entirely.
    ShellHook,
    /// The `source <hook>` block Kin appended to a shell rc file. The owned
    /// slice is the appended text captured in [`LedgerEntry::snippet`].
    ShellRcLine,
    /// The VFS shim copied into `~/.kin/lib`. Kin owns the file.
    VfsShim,
    /// The Kin-first discovery block appended to an agent instruction file
    /// (`~/.claude/CLAUDE.md`, `~/.codex/AGENTS.md`). The owned slice is the
    /// appended text captured in [`LedgerEntry::snippet`].
    DiscoveryReminder,
    /// The `~/.kin/config/setup.toml` daemon config file Kin owns entirely.
    DaemonConfig,
}

impl ArtifactKind {
    /// Whether the owned slice is a distinct substring appended to a shared file
    /// (rc line, discovery reminder) rather than a whole file or JSON key.
    fn is_appended_marker(self) -> bool {
        matches!(self, Self::ShellRcLine | Self::DiscoveryReminder)
    }

    fn label(self) -> &'static str {
        match self {
            Self::McpConfig => "MCP config",
            Self::ShellHook => "shell hook",
            Self::ShellRcLine => "shell rc line",
            Self::VfsShim => "VFS shim",
            Self::DiscoveryReminder => "discovery reminder",
            Self::DaemonConfig => "daemon config",
        }
    }
}

/// One artifact `kin setup` wrote, with a fingerprint of the exact slice Kin
/// owns at `path`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct LedgerEntry {
    pub kind: ArtifactKind,
    /// Stable identifier for the target within its kind: a client id
    /// (`"claude"`), a shell name (`"zsh"`), or an instruction-file label
    /// (`"claude-md"`). `(kind, target, path)` is the entry's identity.
    pub target: String,
    /// Absolute path Kin wrote to.
    pub path: PathBuf,
    /// SHA-256 (hex) of the exact slice Kin owns at `path`.
    pub fingerprint: String,
    /// For appended-marker kinds only: the exact text Kin appended, so uninstall
    /// can excise precisely it and verification can confirm it is still present
    /// verbatim. Absent for whole-file and JSON-key kinds, whose owned slice is
    /// recomputed from disk.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub snippet: Option<String>,
    /// Kin version that last wrote this artifact.
    pub kin_version: String,
    /// RFC 3339 timestamp of the first time Kin recorded this artifact.
    pub written_at: String,
    /// RFC 3339 timestamp of the most recent (re-)record.
    pub updated_at: String,
}

impl LedgerEntry {
    /// Build an entry for a whole-file artifact (Kin owns every byte).
    pub fn whole_file(
        kind: ArtifactKind,
        target: impl Into<String>,
        path: PathBuf,
        bytes: &[u8],
    ) -> Self {
        let now = now_rfc3339();
        Self {
            kind,
            target: target.into(),
            path,
            fingerprint: sha256_hex(bytes),
            snippet: None,
            kin_version: kin_version(),
            written_at: now.clone(),
            updated_at: now,
        }
    }

    /// Build an entry for a merged `mcpServers.kin` JSON sub-value.
    pub fn mcp(target: impl Into<String>, path: PathBuf, kin_entry: &serde_json::Value) -> Self {
        let now = now_rfc3339();
        Self {
            kind: ArtifactKind::McpConfig,
            target: target.into(),
            path,
            fingerprint: fingerprint_mcp_entry(kin_entry),
            snippet: None,
            kin_version: kin_version(),
            written_at: now.clone(),
            updated_at: now,
        }
    }

    /// Build an entry for an appended-marker artifact (rc line, discovery
    /// reminder), capturing the exact appended text.
    pub fn appended(
        kind: ArtifactKind,
        target: impl Into<String>,
        path: PathBuf,
        snippet: impl Into<String>,
    ) -> Self {
        debug_assert!(
            kind.is_appended_marker(),
            "appended() is only for marker kinds"
        );
        let snippet = snippet.into();
        let now = now_rfc3339();
        Self {
            kind,
            target: target.into(),
            fingerprint: sha256_hex(snippet.as_bytes()),
            path,
            snippet: Some(snippet),
            kin_version: kin_version(),
            written_at: now.clone(),
            updated_at: now,
        }
    }
}

/// The full install ledger, persisted as JSON at
/// `~/.kin/config/setup-ledger.json`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SetupLedger {
    pub schema_version: u32,
    pub entries: Vec<LedgerEntry>,
}

impl Default for SetupLedger {
    fn default() -> Self {
        Self {
            schema_version: LEDGER_SCHEMA_VERSION,
            entries: Vec::new(),
        }
    }
}

impl SetupLedger {
    /// Load the ledger from `path`. A missing file yields an empty ledger (setup
    /// has not run yet); a present-but-unparseable file is an error rather than
    /// being silently discarded, so we never lose track of what to uninstall.
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }
        let content = fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        let ledger: SetupLedger = serde_json::from_str(&content).with_context(|| {
            format!(
                "install ledger {} is not valid JSON — fix or remove it and re-run `kin setup`",
                path.display()
            )
        })?;
        Ok(ledger)
    }

    /// Serialize the ledger to `path` (pretty), creating the parent directory.
    /// An empty ledger removes the file so a clean uninstall leaves no residue.
    pub fn save(&self, path: &Path) -> Result<()> {
        if self.entries.is_empty() {
            if path.exists() {
                fs::remove_file(path)
                    .with_context(|| format!("failed to remove empty ledger {}", path.display()))?;
            }
            return Ok(());
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("failed to create directory {}", parent.display()))?;
        }
        let formatted =
            serde_json::to_string_pretty(self).context("failed to serialize install ledger")?;
        fs::write(path, formatted)
            .with_context(|| format!("failed to write {}", path.display()))?;
        Ok(())
    }

    /// Upsert `entry` by its `(kind, target, path)` identity. A re-record keeps
    /// the original `written_at` and refreshes `fingerprint`, `updated_at`, and
    /// `kin_version`, so idempotent re-runs of `kin setup` do not duplicate
    /// entries or lose the original install time.
    pub fn record(&mut self, mut entry: LedgerEntry) {
        if let Some(existing) = self.find_mut(entry.kind, &entry.target, &entry.path) {
            entry.written_at = existing.written_at.clone();
            *existing = entry;
        } else {
            self.entries.push(entry);
        }
    }

    fn find_mut(
        &mut self,
        kind: ArtifactKind,
        target: &str,
        path: &Path,
    ) -> Option<&mut LedgerEntry> {
        self.entries
            .iter_mut()
            .find(|e| e.kind == kind && e.target == target && e.path == path)
    }
}

/// Verification state of a single ledger entry against current disk state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryState {
    /// Present on disk and byte-identical to what Kin recorded.
    Verified,
    /// Present but changed since Kin wrote it (a user or a newer Kin edited it).
    Modified,
    /// The slice Kin wrote is gone (file deleted, or the `kin` key removed).
    Removed,
}

/// Result of verifying one entry.
#[derive(Debug, Clone, serde::Serialize)]
pub struct EntryVerification {
    pub entry: LedgerEntry,
    pub state: EntryState,
    pub detail: String,
}

/// Compute the fingerprint of the slice Kin owns for `entry` from current disk
/// state. Returns `None` when that slice is absent (file missing/corrupt, the
/// `kin` MCP key removed, or the appended marker gone).
fn current_owned_fingerprint(entry: &LedgerEntry) -> Option<String> {
    match entry.kind {
        ArtifactKind::McpConfig => {
            let content = fs::read_to_string(&entry.path).ok()?;
            let root: serde_json::Value = serde_json::from_str(&content).ok()?;
            let kin = root.get("mcpServers")?.get("kin")?;
            Some(fingerprint_mcp_entry(kin))
        }
        ArtifactKind::ShellHook | ArtifactKind::VfsShim | ArtifactKind::DaemonConfig => {
            let bytes = fs::read(&entry.path).ok()?;
            Some(sha256_hex(&bytes))
        }
        ArtifactKind::ShellRcLine | ArtifactKind::DiscoveryReminder => {
            let snippet = entry.snippet.as_ref()?;
            let content = fs::read_to_string(&entry.path).ok()?;
            content
                .contains(snippet.as_str())
                .then(|| sha256_hex(snippet.as_bytes()))
        }
    }
}

/// Verify one entry against current disk state.
pub fn verify_entry(entry: &LedgerEntry) -> EntryVerification {
    let (state, detail) = match current_owned_fingerprint(entry) {
        None => (
            EntryState::Removed,
            format!("{} gone from {}", entry.kind.label(), entry.path.display()),
        ),
        Some(fp) if fp == entry.fingerprint => (
            EntryState::Verified,
            format!("{} present and unmodified", entry.kind.label()),
        ),
        Some(_) => (
            EntryState::Modified,
            format!(
                "{} at {} changed since install — Kin will not touch it",
                entry.kind.label(),
                entry.path.display()
            ),
        ),
    };
    EntryVerification {
        entry: entry.clone(),
        state,
        detail,
    }
}

/// What `uninstall_entry` did (or, under `dry_run`, would do).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RemovalAction {
    /// The owned slice was removed.
    Removed,
    /// Left in place because it was modified since install (needs `--force`).
    SkippedModified,
    /// Already absent — nothing to do.
    AlreadyAbsent,
    /// Removal was attempted but failed.
    Failed,
}

/// Result of uninstalling one entry.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RemovalOutcome {
    pub entry: LedgerEntry,
    pub action: RemovalAction,
    pub detail: String,
}

impl RemovalOutcome {
    /// True when the entry no longer needs tracking (it is gone) and can be
    /// pruned from the ledger.
    fn is_cleared(&self) -> bool {
        matches!(
            self.action,
            RemovalAction::Removed | RemovalAction::AlreadyAbsent
        )
    }
}

/// Remove exactly the slice Kin owns for one entry.
///
/// Safety model: a modified slice is left untouched unless `force` is set, so a
/// user's own edits are never clobbered. Under `dry_run` the action is
/// classified but nothing is written.
pub fn uninstall_entry(entry: &LedgerEntry, dry_run: bool, force: bool) -> RemovalOutcome {
    let verification = verify_entry(entry);
    match verification.state {
        EntryState::Removed => RemovalOutcome {
            entry: entry.clone(),
            action: RemovalAction::AlreadyAbsent,
            detail: format!("{} already absent", entry.kind.label()),
        },
        EntryState::Modified if !force => RemovalOutcome {
            entry: entry.clone(),
            action: RemovalAction::SkippedModified,
            detail: format!(
                "{} at {} was modified since install — left in place (re-run with --force to remove)",
                entry.kind.label(),
                entry.path.display()
            ),
        },
        EntryState::Verified | EntryState::Modified => {
            if dry_run {
                return RemovalOutcome {
                    entry: entry.clone(),
                    action: RemovalAction::Removed,
                    detail: format!("would remove {} at {}", entry.kind.label(), entry.path.display()),
                };
            }
            match remove_owned_slice(entry) {
                Ok(detail) => RemovalOutcome {
                    entry: entry.clone(),
                    action: RemovalAction::Removed,
                    detail,
                },
                Err(e) => RemovalOutcome {
                    entry: entry.clone(),
                    action: RemovalAction::Failed,
                    detail: format!("failed to remove {}: {e}", entry.path.display()),
                },
            }
        }
    }
}

/// Perform the actual removal of the owned slice. Callers gate this on
/// verification, so it assumes the slice is present.
fn remove_owned_slice(entry: &LedgerEntry) -> Result<String> {
    match entry.kind {
        ArtifactKind::McpConfig => {
            let content = fs::read_to_string(&entry.path)
                .with_context(|| format!("failed to read {}", entry.path.display()))?;
            let mut root: serde_json::Value = serde_json::from_str(&content)
                .with_context(|| format!("{} is not valid JSON", entry.path.display()))?;
            if let Some(servers) = root.get_mut("mcpServers").and_then(|s| s.as_object_mut()) {
                servers.remove("kin");
            }
            // Leave the (possibly now-empty) shared config file in place; Kin
            // never deletes a user's config, only its own key within it.
            let formatted =
                serde_json::to_string_pretty(&root).context("failed to serialize MCP config")?;
            fs::write(&entry.path, formatted)
                .with_context(|| format!("failed to write {}", entry.path.display()))?;
            Ok(format!(
                "removed mcpServers.kin from {}",
                entry.path.display()
            ))
        }
        ArtifactKind::ShellHook | ArtifactKind::VfsShim | ArtifactKind::DaemonConfig => {
            fs::remove_file(&entry.path)
                .with_context(|| format!("failed to remove {}", entry.path.display()))?;
            Ok(format!("removed {}", entry.path.display()))
        }
        ArtifactKind::ShellRcLine | ArtifactKind::DiscoveryReminder => {
            let snippet = entry
                .snippet
                .as_ref()
                .context("appended-marker entry has no recorded snippet")?;
            let content = fs::read_to_string(&entry.path)
                .with_context(|| format!("failed to read {}", entry.path.display()))?;
            // Excise exactly the block Kin appended; surrounding content is
            // preserved. The shared file itself is never deleted.
            let stripped = content.replacen(snippet.as_str(), "", 1);
            fs::write(&entry.path, stripped)
                .with_context(|| format!("failed to write {}", entry.path.display()))?;
            Ok(format!(
                "removed {} block from {}",
                entry.kind.label(),
                entry.path.display()
            ))
        }
    }
}

/// Load the ledger at `ledger_path`, uninstall every entry, and rewrite the
/// ledger to drop cleared entries. Entries left in place (modified, or a failed
/// removal) stay tracked. Returns the per-entry outcomes.
pub fn run_uninstall(
    ledger_path: &Path,
    dry_run: bool,
    force: bool,
) -> Result<Vec<RemovalOutcome>> {
    let mut ledger = SetupLedger::load(ledger_path)?;
    let outcomes: Vec<RemovalOutcome> = ledger
        .entries
        .iter()
        .map(|entry| uninstall_entry(entry, dry_run, force))
        .collect();

    if !dry_run {
        // Keep only entries that still need tracking (modified-and-skipped or
        // failed removals); drop everything successfully cleared.
        let keep: Vec<bool> = outcomes.iter().map(|o| !o.is_cleared()).collect();
        let mut idx = 0;
        ledger.entries.retain(|_| {
            let k = keep[idx];
            idx += 1;
            k
        });
        ledger.save(ledger_path)?;
    }

    Ok(outcomes)
}

/// Verify every entry in the ledger at `ledger_path` against disk.
pub fn verify_ledger(ledger_path: &Path) -> Result<Vec<EntryVerification>> {
    let ledger = SetupLedger::load(ledger_path)?;
    Ok(ledger.entries.iter().map(verify_entry).collect())
}

/// The default ledger path: `~/.kin/config/setup-ledger.json`.
pub fn ledger_path() -> Result<PathBuf> {
    Ok(super::setup::kin_dir()?
        .join("config")
        .join("setup-ledger.json"))
}

// ---------------------------------------------------------------------------
// Fingerprint helpers
// ---------------------------------------------------------------------------

/// SHA-256 of `bytes`, lowercase hex.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Deterministic fingerprint of an MCP `kin` server entry, independent of JSON
/// key order, so re-serialization never spuriously reads as "modified".
pub fn fingerprint_mcp_entry(entry: &serde_json::Value) -> String {
    let canonical = canonicalize_json(entry);
    let bytes = serde_json::to_vec(&canonical).unwrap_or_default();
    sha256_hex(&bytes)
}

/// Recursively sort object keys so a value serializes to stable bytes.
fn canonicalize_json(value: &serde_json::Value) -> serde_json::Value {
    match value {
        serde_json::Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let mut sorted = serde_json::Map::new();
            for key in keys {
                sorted.insert(key.clone(), canonicalize_json(&map[key]));
            }
            serde_json::Value::Object(sorted)
        }
        serde_json::Value::Array(items) => {
            serde_json::Value::Array(items.iter().map(canonicalize_json).collect())
        }
        other => other.clone(),
    }
}

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339()
}

fn kin_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(path: &Path, content: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, content).unwrap();
    }

    #[test]
    fn sha256_hex_matches_known_vector() {
        // SHA-256 of the empty input.
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn mcp_fingerprint_is_key_order_independent() {
        let a = serde_json::json!({
            "command": "kin",
            "args": ["mcp", "start"],
            "env": { "KIN_MCP_TOOL_PROFILE": "agent-default" }
        });
        // Same content, different textual key order.
        let b: serde_json::Value = serde_json::from_str(
            r#"{"env":{"KIN_MCP_TOOL_PROFILE":"agent-default"},"args":["mcp","start"],"command":"kin"}"#,
        )
        .unwrap();
        assert_eq!(fingerprint_mcp_entry(&a), fingerprint_mcp_entry(&b));

        // A real change (different profile) changes the fingerprint.
        let c = serde_json::json!({
            "command": "kin",
            "args": ["mcp", "start"],
            "env": { "KIN_MCP_TOOL_PROFILE": "full" }
        });
        assert_ne!(fingerprint_mcp_entry(&a), fingerprint_mcp_entry(&c));
    }

    #[test]
    fn record_upserts_and_preserves_written_at() {
        let mut ledger = SetupLedger::default();
        let path = PathBuf::from("/tmp/x/config.json");
        let mut first =
            LedgerEntry::whole_file(ArtifactKind::ShellHook, "zsh", path.clone(), b"v1");
        first.written_at = "2020-01-01T00:00:00+00:00".to_string();
        ledger.record(first);
        assert_eq!(ledger.entries.len(), 1);

        // Re-record the same (kind, target, path) with new bytes.
        let second =
            LedgerEntry::whole_file(ArtifactKind::ShellHook, "zsh", path.clone(), b"v2-changed");
        let new_fp = second.fingerprint.clone();
        ledger.record(second);

        assert_eq!(ledger.entries.len(), 1, "re-record must not duplicate");
        let entry = &ledger.entries[0];
        assert_eq!(entry.fingerprint, new_fp, "fingerprint updated");
        assert_eq!(
            entry.written_at, "2020-01-01T00:00:00+00:00",
            "original install time preserved"
        );

        // A different target is a distinct entry.
        ledger.record(LedgerEntry::whole_file(
            ArtifactKind::ShellHook,
            "bash",
            PathBuf::from("/tmp/x/bash"),
            b"b",
        ));
        assert_eq!(ledger.entries.len(), 2);
    }

    #[test]
    fn save_load_round_trips_and_missing_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config").join("setup-ledger.json");

        // Missing file → empty ledger.
        assert!(SetupLedger::load(&path).unwrap().entries.is_empty());

        let mut ledger = SetupLedger::default();
        ledger.record(LedgerEntry::whole_file(
            ArtifactKind::DaemonConfig,
            "daemon",
            dir.path().join("setup.toml"),
            b"auto_start = true",
        ));
        ledger.save(&path).unwrap();

        let loaded = SetupLedger::load(&path).unwrap();
        assert_eq!(loaded.schema_version, LEDGER_SCHEMA_VERSION);
        assert_eq!(loaded.entries.len(), 1);
        assert_eq!(loaded.entries[0].target, "daemon");
    }

    #[test]
    fn load_corrupt_ledger_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("setup-ledger.json");
        write(&path, "not json {{{");
        assert!(SetupLedger::load(&path).is_err());
    }

    #[test]
    fn save_empty_ledger_removes_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("setup-ledger.json");
        write(&path, "{}");
        SetupLedger::default().save(&path).unwrap();
        assert!(!path.exists(), "empty ledger leaves no residue on disk");
    }

    #[test]
    fn verify_whole_file_detects_all_three_states() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("hook.zsh");
        write(&file, "HOOK BODY");
        let entry =
            LedgerEntry::whole_file(ArtifactKind::ShellHook, "zsh", file.clone(), b"HOOK BODY");

        assert_eq!(verify_entry(&entry).state, EntryState::Verified);

        write(&file, "USER EDITED");
        assert_eq!(verify_entry(&entry).state, EntryState::Modified);

        fs::remove_file(&file).unwrap();
        assert_eq!(verify_entry(&entry).state, EntryState::Removed);
    }

    #[test]
    fn verify_mcp_entry_states() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("claude.json");
        let kin = serde_json::json!({
            "command": "kin",
            "args": ["mcp", "start"],
            "env": { "KIN_MCP_TOOL_PROFILE": "agent-default" }
        });
        write(
            &path,
            &serde_json::to_string_pretty(&serde_json::json!({
                "mcpServers": { "other": { "command": "x" }, "kin": kin }
            }))
            .unwrap(),
        );
        let entry = LedgerEntry::mcp("claude", path.clone(), &kin);
        assert_eq!(verify_entry(&entry).state, EntryState::Verified);

        // User edits the kin entry → Modified.
        write(
            &path,
            &serde_json::to_string_pretty(&serde_json::json!({
                "mcpServers": { "kin": { "command": "kin", "args": ["mcp", "start"], "env": {} } }
            }))
            .unwrap(),
        );
        assert_eq!(verify_entry(&entry).state, EntryState::Modified);

        // User removes the kin entry → Removed (siblings irrelevant).
        write(
            &path,
            &serde_json::to_string_pretty(&serde_json::json!({
                "mcpServers": { "other": { "command": "x" } }
            }))
            .unwrap(),
        );
        assert_eq!(verify_entry(&entry).state, EntryState::Removed);
    }

    #[test]
    fn verify_appended_marker_presence() {
        let dir = tempfile::tempdir().unwrap();
        let rc = dir.path().join(".zshrc");
        let snippet = "\n# kin-vfs shell integration\nsource /home/u/.kin/shell/kin-vfs.zsh\n";
        write(
            &rc,
            &format!("export PATH=/usr/bin{snippet}alias ll='ls -l'\n"),
        );
        let entry = LedgerEntry::appended(ArtifactKind::ShellRcLine, "zsh", rc.clone(), snippet);
        assert_eq!(verify_entry(&entry).state, EntryState::Verified);

        // Remove the block → Removed.
        write(&rc, "export PATH=/usr/bin\nalias ll='ls -l'\n");
        assert_eq!(verify_entry(&entry).state, EntryState::Removed);
    }

    #[test]
    fn uninstall_mcp_removes_only_kin_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("claude.json");
        let kin = serde_json::json!({
            "command": "kin",
            "args": ["mcp", "start"],
            "env": { "KIN_MCP_TOOL_PROFILE": "agent-default" }
        });
        write(
            &path,
            &serde_json::to_string_pretty(&serde_json::json!({
                "mcpServers": { "other": { "command": "x" }, "kin": kin },
                "userSetting": true
            }))
            .unwrap(),
        );
        let entry = LedgerEntry::mcp("claude", path.clone(), &kin);

        let outcome = uninstall_entry(&entry, false, false);
        assert_eq!(outcome.action, RemovalAction::Removed);

        let root: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert!(root["mcpServers"]["kin"].is_null(), "kin key removed");
        assert!(
            root["mcpServers"]["other"].is_object(),
            "sibling server kept"
        );
        assert_eq!(root["userSetting"], true, "unrelated keys kept");
    }

    #[test]
    fn uninstall_never_clobbers_a_modified_entry() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("claude.json");
        let recorded = serde_json::json!({
            "command": "kin",
            "args": ["mcp", "start"],
            "env": { "KIN_MCP_TOOL_PROFILE": "agent-default" }
        });
        let entry = LedgerEntry::mcp("claude", path.clone(), &recorded);

        // On disk the user has hand-edited the kin entry.
        let user_edited = serde_json::json!({
            "mcpServers": { "kin": { "command": "/custom/kin", "args": ["mcp", "start"], "env": {} } }
        });
        write(&path, &serde_json::to_string_pretty(&user_edited).unwrap());

        let outcome = uninstall_entry(&entry, false, false);
        assert_eq!(outcome.action, RemovalAction::SkippedModified);
        let after: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            after["mcpServers"]["kin"]["command"], "/custom/kin",
            "user's edited entry must be left intact"
        );

        // --force overrides and removes it.
        let forced = uninstall_entry(&entry, false, true);
        assert_eq!(forced.action, RemovalAction::Removed);
        let after: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert!(after["mcpServers"]["kin"].is_null());
    }

    #[test]
    fn uninstall_whole_file_deletes_and_dry_run_does_not() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("lib").join("libkin_vfs_shim.dylib");
        write(&file, "SHIMBYTES");
        let entry =
            LedgerEntry::whole_file(ArtifactKind::VfsShim, "shim", file.clone(), b"SHIMBYTES");

        // Dry run reports the action but leaves the file.
        let dry = uninstall_entry(&entry, true, false);
        assert_eq!(dry.action, RemovalAction::Removed);
        assert!(file.exists(), "dry-run must not delete");

        let real = uninstall_entry(&entry, false, false);
        assert_eq!(real.action, RemovalAction::Removed);
        assert!(!file.exists(), "real uninstall deletes the owned file");
    }

    #[test]
    fn uninstall_rc_line_excises_block_only() {
        let dir = tempfile::tempdir().unwrap();
        let rc = dir.path().join(".bashrc");
        // The block is bounded by newlines exactly as `install_shell_hook`
        // appends it: the rc already ends with `\n`, then the block adds a blank
        // separator line + the comment + the source line + a trailing `\n`.
        let snippet = "\n# kin-vfs shell integration\nsource /home/u/.kin/shell/kin-vfs.bash\n";
        let original = "# user rc\nexport EDITOR=vim\nalias g=git\n";
        write(&rc, &format!("{original}{snippet}"));
        let entry = LedgerEntry::appended(ArtifactKind::ShellRcLine, "bash", rc.clone(), snippet);

        let outcome = uninstall_entry(&entry, false, false);
        assert_eq!(outcome.action, RemovalAction::Removed);
        let after = fs::read_to_string(&rc).unwrap();
        assert_eq!(
            after, original,
            "removing the exact block restores the pre-install rc content"
        );
        assert!(rc.exists(), "the shared rc file itself is never deleted");
    }

    #[test]
    fn uninstall_absent_entry_is_already_absent() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("gone.toml");
        let entry = LedgerEntry::whole_file(ArtifactKind::DaemonConfig, "daemon", file, b"x");
        assert_eq!(
            uninstall_entry(&entry, false, false).action,
            RemovalAction::AlreadyAbsent
        );
    }

    #[test]
    fn run_uninstall_prunes_cleared_entries_and_keeps_modified() {
        let dir = tempfile::tempdir().unwrap();
        let ledger_path = dir.path().join("setup-ledger.json");

        // Verified whole-file entry (will be removed + pruned).
        let hook = dir.path().join("hook.zsh");
        write(&hook, "HOOK");
        // Modified entry (will be skipped + kept).
        let cfg = dir.path().join("setup.toml");
        write(&cfg, "USER CHANGED");

        let mut ledger = SetupLedger::default();
        ledger.record(LedgerEntry::whole_file(
            ArtifactKind::ShellHook,
            "zsh",
            hook.clone(),
            b"HOOK",
        ));
        ledger.record(LedgerEntry::whole_file(
            ArtifactKind::DaemonConfig,
            "daemon",
            cfg.clone(),
            b"ORIGINAL",
        ));
        ledger.save(&ledger_path).unwrap();

        let outcomes = run_uninstall(&ledger_path, false, false).unwrap();
        assert_eq!(outcomes.len(), 2);
        assert!(!hook.exists(), "verified hook removed");
        assert!(cfg.exists(), "modified config left in place");

        // Ledger keeps only the skipped-modified entry.
        let remaining = SetupLedger::load(&ledger_path).unwrap();
        assert_eq!(remaining.entries.len(), 1);
        assert_eq!(remaining.entries[0].kind, ArtifactKind::DaemonConfig);
    }

    #[test]
    fn run_uninstall_dry_run_mutates_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let ledger_path = dir.path().join("setup-ledger.json");
        let hook = dir.path().join("hook.zsh");
        write(&hook, "HOOK");
        let mut ledger = SetupLedger::default();
        ledger.record(LedgerEntry::whole_file(
            ArtifactKind::ShellHook,
            "zsh",
            hook.clone(),
            b"HOOK",
        ));
        ledger.save(&ledger_path).unwrap();

        let outcomes = run_uninstall(&ledger_path, true, false).unwrap();
        assert_eq!(outcomes[0].action, RemovalAction::Removed);
        assert!(hook.exists(), "dry-run leaves artifacts");
        assert_eq!(
            SetupLedger::load(&ledger_path).unwrap().entries.len(),
            1,
            "dry-run leaves the ledger unchanged"
        );
    }
}
