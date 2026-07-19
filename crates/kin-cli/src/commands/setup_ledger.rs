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

#[cfg(test)]
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
    /// The kin MCP server entry merged into an AI client's config — the
    /// `mcpServers.kin` sub-value of a JSON config, or the `mcp_servers.kin`
    /// table of a TOML config (Codex). The owned slice is that one sub-value;
    /// siblings are untouched.
    McpConfig,
    /// A `~/.kin/shell/kin-vfs.<shell>` hook file Kin owns entirely.
    ShellHook,
    /// The `source <hook>` block Kin appended to a shell rc file. The owned
    /// slice is the appended text captured in [`LedgerEntry::snippet`].
    ShellRcLine,
    /// The PATH export block Kin appended to a shell rc file so managed
    /// binaries under `~/.kin/bin` are available in new shells.
    ShellPathLine,
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
        matches!(
            self,
            Self::ShellRcLine | Self::ShellPathLine | Self::DiscoveryReminder
        )
    }

    fn label(self) -> &'static str {
        match self {
            Self::McpConfig => "MCP config",
            Self::ShellHook => "shell hook",
            Self::ShellRcLine => "shell rc line",
            Self::ShellPathLine => "shell PATH line",
            Self::VfsShim => "VFS shim",
            Self::DiscoveryReminder => "discovery reminder",
            Self::DaemonConfig => "daemon config",
        }
    }
}

/// One artifact `kin setup` wrote, with a fingerprint of the exact slice Kin
/// owns at `path`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
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

    /// Build an entry for a merged kin MCP server sub-value (JSON `mcpServers.kin`
    /// or TOML `mcp_servers.kin`, normalized to JSON by the caller).
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
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
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
        let bytes = super::setup::read_private_file_nofollow(path)?;
        Self::from_locked_bytes(path, bytes.as_deref())
    }

    fn from_locked_bytes(path: &Path, bytes: Option<&[u8]>) -> Result<Self> {
        let Some(bytes) = bytes else {
            return Ok(Self::default());
        };
        let ledger: SetupLedger = serde_json::from_slice(bytes).with_context(|| {
            format!(
                "install ledger {} is not valid JSON — fix or remove it and re-run `kin setup`",
                path.display()
            )
        })?;
        if ledger.schema_version != LEDGER_SCHEMA_VERSION {
            anyhow::bail!(
                "install ledger {} uses unsupported schema version {}; expected {}. Its bytes were retained unchanged",
                path.display(),
                ledger.schema_version,
                LEDGER_SCHEMA_VERSION
            );
        }
        Ok(ledger)
    }

    /// Serialize the ledger to `path` (pretty), creating the parent directory.
    /// An empty ledger removes the file so a clean uninstall leaves no residue.
    pub fn save(&self, path: &Path) -> Result<()> {
        let lock = super::setup::ConfigLock::acquire_nofollow(path)?;
        let original = lock.original_bytes(path)?;
        self.save_locked(path, &lock, original.as_deref())
    }

    fn save_locked(
        &self,
        path: &Path,
        lock: &super::setup::ConfigLock,
        original: Option<&[u8]>,
    ) -> Result<()> {
        if self.entries.is_empty() {
            lock.remove_guarded(path, original)?;
            return Ok(());
        }
        let formatted =
            serde_json::to_string_pretty(self).context("failed to serialize install ledger")?;
        lock.write_private_guarded(path, formatted.as_bytes(), original)?;
        Ok(())
    }

    /// Perform a locked load-modify-save transaction. Every ledger writer uses
    /// this path so concurrent setup, doctor, updater repair, and uninstall
    /// operations cannot overwrite one another's entries.
    pub fn update<R>(path: &Path, mutate: impl FnOnce(&mut SetupLedger) -> Result<R>) -> Result<R> {
        let lock = super::setup::ConfigLock::acquire_nofollow(path)?;
        let original = lock.original_bytes(path)?;
        let mut ledger = Self::from_locked_bytes(path, original.as_deref())?;
        let result = mutate(&mut ledger)?;
        ledger.save_locked(path, &lock, original.as_deref())?;
        Ok(result)
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

fn current_owned_fingerprint_from_bytes(entry: &LedgerEntry, content: &[u8]) -> Option<String> {
    match entry.kind {
        ArtifactKind::McpConfig => current_mcp_fingerprint_from_bytes(entry, content),
        ArtifactKind::ShellHook | ArtifactKind::VfsShim | ArtifactKind::DaemonConfig => {
            Some(sha256_hex(content))
        }
        ArtifactKind::ShellRcLine
        | ArtifactKind::ShellPathLine
        | ArtifactKind::DiscoveryReminder => {
            let snippet = entry.snippet.as_ref()?;
            let content = std::str::from_utf8(content).ok()?;
            content
                .contains(snippet.as_str())
                .then(|| sha256_hex(snippet.as_bytes()))
        }
    }
}

fn current_mcp_fingerprint_from_bytes(entry: &LedgerEntry, content: &[u8]) -> Option<String> {
    // Codex's config.toml is TOML (`mcp_servers.kin`); every other client
    // config is JSON (`mcpServers.kin`). Normalize to JSON so the fingerprint
    // matches what the install path recorded.
    let kin = if entry.path.extension().and_then(|e| e.to_str()) == Some("toml") {
        let content = std::str::from_utf8(content).ok()?;
        let root: toml::Value = toml::from_str(content).ok()?;
        let kin = root.get("mcp_servers")?.get("kin")?;
        serde_json::to_value(kin).ok()?
    } else {
        let root: serde_json::Value = serde_json::from_slice(content).ok()?;
        root.get("mcpServers")?.get("kin")?.clone()
    };
    Some(fingerprint_mcp_entry(&kin))
}

pub(crate) fn verify_entry_locked(
    entry: &LedgerEntry,
    lock: &super::setup::ConfigLock,
) -> Result<EntryVerification> {
    let bytes = lock.original_bytes(&entry.path)?;
    let (state, detail) = match bytes
        .as_deref()
        .and_then(|bytes| current_owned_fingerprint_from_bytes(entry, bytes))
    {
        None => (
            EntryState::Removed,
            format!("{} gone from {}", entry.kind.label(), entry.path.display()),
        ),
        Some(fingerprint) if fingerprint == entry.fingerprint => (
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
    Ok(EntryVerification {
        entry: entry.clone(),
        state,
        detail,
    })
}

/// Verify one entry against current disk state.
pub fn verify_entry(entry: &LedgerEntry) -> EntryVerification {
    match super::setup::ConfigLock::acquire(&entry.path)
        .and_then(|lock| verify_entry_locked(entry, &lock))
    {
        Ok(verification) => verification,
        Err(error) => EntryVerification {
            entry: entry.clone(),
            // Unsafe ownership, links, path types, or lock ambiguity are
            // present state that Kin cannot authenticate. Treat them as
            // modified so no marker reconciliation or uninstall path can
            // mistake the object for an absent or verified artifact.
            state: EntryState::Modified,
            detail: format!(
                "{} at {} could not be safely verified — Kin will not trust or touch it: {error:#}",
                entry.kind.label(),
                entry.path.display()
            ),
        },
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
    if !dry_run {
        return match super::setup::ConfigLock::acquire(&entry.path) {
            Ok(lock) => uninstall_entry_with_lock(entry, false, force, &lock),
            Err(error) => RemovalOutcome {
                entry: entry.clone(),
                action: RemovalAction::Failed,
                detail: format!(
                    "failed to lock setup-owned path {}: {error:#}",
                    entry.path.display()
                ),
            },
        };
    }
    uninstall_entry_with_verification(entry, dry_run, force, verify_entry(entry), None)
}

fn uninstall_entry_with_lock(
    entry: &LedgerEntry,
    dry_run: bool,
    force: bool,
    lock: &super::setup::ConfigLock,
) -> RemovalOutcome {
    match verify_entry_locked(entry, lock) {
        Ok(verification) => {
            uninstall_entry_with_verification(entry, dry_run, force, verification, Some(lock))
        }
        Err(error) => RemovalOutcome {
            entry: entry.clone(),
            action: RemovalAction::Failed,
            detail: format!(
                "failed to verify locked setup-owned path {}: {error:#}",
                entry.path.display()
            ),
        },
    }
}

fn uninstall_entry_with_verification(
    entry: &LedgerEntry,
    dry_run: bool,
    force: bool,
    verification: EntryVerification,
    target_lock: Option<&super::setup::ConfigLock>,
) -> RemovalOutcome {
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
            let removed = match target_lock {
                Some(lock) => remove_owned_slice_locked(entry, lock),
                None => remove_owned_slice(entry),
            };
            match removed {
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
    let _ = entry;
    anyhow::bail!("setup-owned removal requires its persistent ConfigLock authority")
}

fn remove_owned_slice_locked(
    entry: &LedgerEntry,
    lock: &super::setup::ConfigLock,
) -> Result<String> {
    let original = lock
        .original_bytes(&entry.path)?
        .with_context(|| format!("setup-owned path disappeared: {}", entry.path.display()))?;
    if entry.kind == ArtifactKind::McpConfig
        && entry
            .path
            .extension()
            .and_then(|extension| extension.to_str())
            == Some("toml")
    {
        // Codex's config.toml: excise only the [mcp_servers.kin] table with a
        // format-preserving edit; unrelated bytes remain under one CAS write.
        let content = std::str::from_utf8(&original)
            .with_context(|| format!("{} is not UTF-8", entry.path.display()))?;
        let mut document: toml_edit::DocumentMut = content
            .parse()
            .with_context(|| format!("{} is not valid TOML", entry.path.display()))?;
        if let Some(servers) = document
            .get_mut("mcp_servers")
            .and_then(|servers| servers.as_table_like_mut())
        {
            servers.remove("kin");
        }
        lock.write_guarded(
            &entry.path,
            document.to_string().as_bytes(),
            Some(&original),
        )?;
        return Ok(format!(
            "removed mcp_servers.kin from {}",
            entry.path.display()
        ));
    }
    if entry.kind == ArtifactKind::McpConfig {
        let mut root: serde_json::Value = serde_json::from_slice(&original)
            .with_context(|| format!("{} is not valid JSON", entry.path.display()))?;
        if let Some(servers) = root
            .get_mut("mcpServers")
            .and_then(serde_json::Value::as_object_mut)
        {
            servers.remove("kin");
        }
        // Leave the (possibly now-empty) shared config file in place; Kin never
        // deletes a user's config, only its own key within it.
        let formatted =
            serde_json::to_vec_pretty(&root).context("failed to serialize MCP config")?;
        lock.write_guarded(&entry.path, &formatted, Some(&original))?;
        return Ok(format!(
            "removed mcpServers.kin from {}",
            entry.path.display()
        ));
    }
    if entry.kind.is_appended_marker() {
        let snippet = entry
            .snippet
            .as_ref()
            .context("appended-marker entry has no recorded snippet")?;
        let content = std::str::from_utf8(&original)
            .with_context(|| format!("{} is not UTF-8", entry.path.display()))?;
        let stripped = content.replacen(snippet.as_str(), "", 1);
        lock.write_guarded(&entry.path, stripped.as_bytes(), Some(&original))?;
        return Ok(format!(
            "removed {} block from {}",
            entry.kind.label(),
            entry.path.display()
        ));
    }
    lock.remove_guarded(&entry.path, Some(&original))?;
    Ok(format!("removed {}", entry.path.display()))
}

/// Load the ledger at `ledger_path`, uninstall every entry, and rewrite the
/// ledger to drop cleared entries. Entries left in place (modified, or a failed
/// removal) stay tracked. Returns the per-entry outcomes.
pub fn run_uninstall(
    ledger_path: &Path,
    dry_run: bool,
    force: bool,
) -> Result<Vec<RemovalOutcome>> {
    if dry_run {
        let ledger = SetupLedger::load(ledger_path)?;
        return Ok(ledger
            .entries
            .iter()
            .map(|entry| uninstall_entry(entry, true, force))
            .collect());
    }
    // Global writer order is MCP topology, canonical target locks, then the
    // setup-ledger lock. Updater repair uses the same order. A snapshot
    // supplies the target set; once the ledger lock is acquired below, any
    // entry/topology change makes the operation fail closed before the first
    // artifact is removed.
    let snapshot = SetupLedger::load(ledger_path)?;
    let snapshot_entries = snapshot.entries.clone();
    let normalized_ledger_path = super::setup::ConfigLock::normalized_path(ledger_path)?;
    let mut target_paths = snapshot
        .entries
        .iter()
        .map(|entry| super::setup::ConfigLock::normalized_path(&entry.path))
        .collect::<Result<Vec<_>>>()?;
    target_paths.sort();
    target_paths.dedup();
    let mut authority_paths = target_paths
        .iter()
        .cloned()
        .map(|path| (path, false))
        .collect::<Vec<_>>();
    authority_paths.push((normalized_ledger_path.clone(), true));
    super::setup::ConfigLock::preflight_distinct(&authority_paths).context(
        "setup ledger and uninstall targets contain aliased sidecar authority; refusing nested lock acquisition",
    )?;
    // Preflight is non-locking. Acquire the topology authority only after it
    // proves the target and ledger sidecars are distinct, then preserve the
    // global topology -> target -> ledger lock order below.
    let _topology = super::setup::McpTopologyLock::acquire_for_ledger(ledger_path)?;
    let mut target_locks = super::setup::ConfigLock::acquire_many(&target_paths)?;
    SetupLedger::update(ledger_path, |ledger| {
        if ledger.entries != snapshot_entries {
            anyhow::bail!(
                "setup ledger changed while uninstall acquired target locks; retry uninstall"
            );
        }
        let mut outcomes = Vec::with_capacity(ledger.entries.len());
        for entry in &ledger.entries {
            let normalized = match super::setup::ConfigLock::normalized_path(&entry.path) {
                Ok(path) => path,
                Err(error) => {
                    outcomes.push(RemovalOutcome {
                        entry: entry.clone(),
                        action: RemovalAction::Failed,
                        detail: format!(
                            "failed to normalize setup-owned path {}: {error:#}",
                            entry.path.display()
                        ),
                    });
                    continue;
                }
            };
            let Some(lock_index) = target_paths.iter().position(|path| *path == normalized) else {
                outcomes.push(RemovalOutcome {
                    entry: entry.clone(),
                    action: RemovalAction::Failed,
                    detail: "locked setup target disappeared from uninstall authority".to_string(),
                });
                continue;
            };
            let lock = &mut target_locks[lock_index];
            let mut outcome = uninstall_entry_with_lock(entry, false, force, lock);
            if outcome.action == RemovalAction::Removed {
                if let Err(error) = lock.refresh_locked_state() {
                    // The owned slice is already gone, but retain its ledger
                    // entry so a later uninstall can reconcile it as absent.
                    // More importantly, never apply a second mutation to this
                    // path using the stale pre-mutation CAS baseline.
                    outcome.action = RemovalAction::Failed;
                    outcome.detail = format!(
                        "removed {}, but failed to refresh its locked CAS authority: {error:#}",
                        entry.path.display()
                    );
                }
            }
            outcomes.push(outcome);
        }
        let keep: Vec<bool> = outcomes
            .iter()
            .map(|outcome| !outcome.is_cleared())
            .collect();
        let mut index = 0;
        ledger.entries.retain(|_| {
            let retain = keep[index];
            index += 1;
            retain
        });
        Ok(outcomes)
    })
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

    #[cfg(unix)]
    #[test]
    fn ledger_load_rejects_symlink_and_unsafe_mode() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.json");
        write(&target, r#"{"schema_version":1,"entries":[]}"#);
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.path().join("linked-ledger.json");
        symlink(&target, &link).unwrap();
        assert!(SetupLedger::load(&link).is_err());

        let unsafe_mode = dir.path().join("unsafe-ledger.json");
        write(&unsafe_mode, r#"{"schema_version":1,"entries":[]}"#);
        fs::set_permissions(&unsafe_mode, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(SetupLedger::load(&unsafe_mode).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn ledger_and_persistent_lock_are_mode_0600() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("setup-ledger.json");
        let mut ledger = SetupLedger::default();
        ledger.record(LedgerEntry::whole_file(
            ArtifactKind::DaemonConfig,
            "daemon",
            dir.path().join("setup.toml"),
            b"[daemon]",
        ));
        ledger.save(&path).unwrap();
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let lock = dir.path().join(".setup-ledger.json.kin-update.lock");
        assert!(lock.is_file(), "ledger lock must remain persistent");
        assert_eq!(
            fs::metadata(lock).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn save_empty_ledger_removes_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("setup-ledger.json");
        write(&path, "{}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
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

    #[cfg(unix)]
    #[test]
    fn verify_mcp_rejects_byte_identical_symlink_replacement() {
        use std::os::unix::fs::symlink;

        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real.json");
        let path = dir.path().join("claude.json");
        let kin = serde_json::json!({
            "command": "kin",
            "args": ["mcp", "start"]
        });
        let bytes = serde_json::to_vec_pretty(&serde_json::json!({
            "mcpServers": { "kin": kin }
        }))
        .unwrap();
        fs::write(&real, &bytes).unwrap();
        symlink(&real, &path).unwrap();
        let entry = LedgerEntry::mcp("claude", path, &kin);

        let verification = verify_entry(&entry);

        assert_eq!(verification.state, EntryState::Modified);
        assert!(verification.detail.contains("could not be safely verified"));
    }

    #[cfg(unix)]
    #[test]
    fn verify_mcp_rejects_byte_identical_hardlink_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real.json");
        let path = dir.path().join("claude.json");
        let kin = serde_json::json!({
            "command": "kin",
            "args": ["mcp", "start"]
        });
        let bytes = serde_json::to_vec_pretty(&serde_json::json!({
            "mcpServers": { "kin": kin }
        }))
        .unwrap();
        fs::write(&real, &bytes).unwrap();
        fs::hard_link(&real, &path).unwrap();
        let entry = LedgerEntry::mcp("claude", path, &kin);

        let verification = verify_entry(&entry);

        assert_eq!(verification.state, EntryState::Modified);
        assert!(verification.detail.contains("could not be safely verified"));
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
    fn verify_and_uninstall_mcp_toml_config() {
        // Codex registers its MCP entry in config.toml (`mcp_servers.kin`),
        // not an mcp.json — the ledger must verify and excise it there.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        write(
            &path,
            "# codex settings\nmodel = \"o3\"\n\n[mcp_servers.other]\ncommand = \"x\"\n\n[mcp_servers.kin]\ncommand = \"kin\"\nargs = [\"mcp\", \"start\"]\nenv = { KIN_MCP_TOOL_PROFILE = \"agent-default\" }\n",
        );
        let kin = serde_json::json!({
            "command": "kin",
            "args": ["mcp", "start"],
            "env": { "KIN_MCP_TOOL_PROFILE": "agent-default" }
        });
        let entry = LedgerEntry::mcp("codex", path.clone(), &kin);

        // The on-disk TOML entry fingerprints identically to the recorded
        // JSON-normalized value.
        assert_eq!(verify_entry(&entry).state, EntryState::Verified);

        let outcome = uninstall_entry(&entry, false, false);
        assert_eq!(outcome.action, RemovalAction::Removed);

        let content = fs::read_to_string(&path).unwrap();
        let root: toml::Value = toml::from_str(&content).unwrap();
        assert!(
            root["mcp_servers"].get("kin").is_none(),
            "kin table removed"
        );
        assert_eq!(
            root["mcp_servers"]["other"]["command"].as_str(),
            Some("x"),
            "sibling server kept"
        );
        assert_eq!(root["model"].as_str(), Some("o3"), "unrelated keys kept");
        assert!(content.contains("# codex settings"), "comments kept");
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
    fn run_uninstall_chains_cas_baselines_for_two_blocks_in_one_rc_file() {
        let dir = tempfile::tempdir().unwrap();
        let ledger_path = dir.path().join("config/setup-ledger.json");
        let rc = dir.path().join("home/.zshrc");
        let user = "# user rc\nexport EDITOR=vim\n";
        let hook = "\n# kin-vfs shell integration\nsource /managed/kin-vfs.zsh\n";
        let path = "\n# Kin managed PATH\nexport PATH=\"/managed/bin:$PATH\"\n";
        write(&rc, &format!("{user}{hook}{path}"));

        let mut ledger = SetupLedger::default();
        ledger.record(LedgerEntry::appended(
            ArtifactKind::ShellRcLine,
            "zsh",
            rc.clone(),
            hook,
        ));
        ledger.record(LedgerEntry::appended(
            ArtifactKind::ShellPathLine,
            "zsh",
            rc.clone(),
            path,
        ));
        ledger.save(&ledger_path).unwrap();

        let outcomes = run_uninstall(&ledger_path, false, false).unwrap();
        assert_eq!(outcomes.len(), 2);
        assert!(outcomes
            .iter()
            .all(|outcome| outcome.action == RemovalAction::Removed));
        assert_eq!(fs::read_to_string(&rc).unwrap(), user);
        assert!(SetupLedger::load(&ledger_path).unwrap().entries.is_empty());
    }

    #[test]
    fn run_uninstall_rejects_target_ledger_sidecar_alias_before_wal_guard() {
        let dir = tempfile::tempdir().unwrap();
        let ledger_path = dir.path().join("config/setup-ledger.json");
        let mut ledger = SetupLedger::default();
        ledger.record(LedgerEntry::whole_file(
            ArtifactKind::DaemonConfig,
            "self-alias",
            ledger_path.clone(),
            b"not-the-ledger-bytes",
        ));
        ledger.save(&ledger_path).unwrap();
        let before = fs::read(&ledger_path).unwrap();

        super::super::setup::reset_config_transaction_acquire_count();
        let error = run_uninstall(&ledger_path, false, false)
            .expect_err("ledger/target sidecar alias must fail before nested guard acquisition");

        assert!(format!("{error:#}").contains("aliased sidecar authority"));
        assert_eq!(
            super::super::setup::config_transaction_acquire_count(),
            0,
            "preflight alias rejection must happen before any WAL guard acquisition"
        );
        assert_eq!(fs::read(&ledger_path).unwrap(), before);
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

    #[test]
    fn incompatible_or_unknown_ledger_data_is_retained_byte_for_byte() {
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

        for mutation in ["schema", "ledger-field", "entry-field"] {
            let mut value = serde_json::to_value(&ledger).unwrap();
            match mutation {
                "schema" => value["schema_version"] = serde_json::json!(99),
                "ledger-field" => {
                    value["future_lifecycle"] = serde_json::json!({"acknowledged": true})
                }
                "entry-field" => {
                    value["entries"][0]["future_authority"] = serde_json::json!("external")
                }
                _ => unreachable!(),
            }
            let bytes = serde_json::to_vec_pretty(&value).unwrap();
            fs::write(&ledger_path, &bytes).unwrap();

            assert!(
                run_uninstall(&ledger_path, false, false).is_err(),
                "{mutation}"
            );
            assert_eq!(fs::read(&ledger_path).unwrap(), bytes, "{mutation}");
            assert_eq!(fs::read(&hook).unwrap(), b"HOOK", "{mutation}");
        }
    }

    #[test]
    fn uninstall_waits_for_shared_path_lock_and_preserves_concurrent_shell_edit() {
        let dir = tempfile::tempdir().unwrap();
        let ledger_path = dir.path().join("config/setup-ledger.json");
        let rc = dir.path().join("home/.zshrc");
        let snippet = "\n# Kin block\nsource /managed/hook\n";
        let original = format!("# user\n{snippet}");
        write(&rc, &original);
        let mut ledger = SetupLedger::default();
        ledger.record(LedgerEntry::appended(
            ArtifactKind::ShellRcLine,
            "zsh",
            rc.clone(),
            snippet,
        ));
        ledger.save(&ledger_path).unwrap();

        let held = super::super::setup::ConfigLock::acquire(&rc).unwrap();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let worker_ledger = ledger_path.clone();
        let worker = std::thread::spawn(move || {
            started_tx.send(()).unwrap();
            run_uninstall(&worker_ledger, false, false).unwrap()
        });
        started_rx.recv().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));
        let edited = format!("# concurrent user edit\n{original}");
        fs::write(&rc, &edited).unwrap();
        drop(held);

        let outcomes = worker.join().unwrap();
        assert_eq!(outcomes[0].action, RemovalAction::Removed);
        assert_eq!(
            fs::read_to_string(&rc).unwrap(),
            "# concurrent user edit\n# user\n",
            "the concurrent user bytes survive while only Kin's exact block is removed"
        );
        assert!(SetupLedger::load(&ledger_path).unwrap().entries.is_empty());
    }

    #[test]
    fn uninstall_preserves_concurrently_replaced_whole_file() {
        let dir = tempfile::tempdir().unwrap();
        let ledger_path = dir.path().join("config/setup-ledger.json");
        let hook = dir.path().join("shell/kin-vfs.zsh");
        write(&hook, "KIN OWNED");
        let mut ledger = SetupLedger::default();
        ledger.record(LedgerEntry::whole_file(
            ArtifactKind::ShellHook,
            "zsh",
            hook.clone(),
            b"KIN OWNED",
        ));
        ledger.save(&ledger_path).unwrap();

        let held = super::super::setup::ConfigLock::acquire(&hook).unwrap();
        let worker_ledger = ledger_path.clone();
        let worker = std::thread::spawn(move || run_uninstall(&worker_ledger, false, false));
        std::thread::sleep(std::time::Duration::from_millis(50));
        fs::write(&hook, b"USER REPLACEMENT").unwrap();
        drop(held);

        let outcomes = worker.join().unwrap().unwrap();
        assert_eq!(outcomes[0].action, RemovalAction::SkippedModified);
        assert_eq!(fs::read(&hook).unwrap(), b"USER REPLACEMENT");
        assert_eq!(SetupLedger::load(&ledger_path).unwrap().entries.len(), 1);
    }
}
