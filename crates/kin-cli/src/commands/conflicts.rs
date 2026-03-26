// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;
use serde::{Deserialize, Serialize};

use kin_reconcile::MergeConflictKind;

/// Persisted merge conflict state written to `.kin/merge_state.json`.
///
/// Created by `kin merge` when conflicts are detected, consumed by
/// `kin conflicts` (display) and `kin resolve` (resolution). Cleared
/// on successful resolution or `kin resolve --abort`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedMergeState {
    /// Branch being merged from.
    pub source_branch: String,
    /// Branch being merged into.
    pub target_branch: String,
    /// Head of the target branch at merge time.
    pub target_head: String,
    /// Head of the source branch at merge time.
    pub source_head: String,
    /// Merge strategy used (structural or semantic).
    pub strategy: String,
    /// Individual entity-level conflicts.
    pub conflicts: Vec<PersistedConflict>,
}

/// A single persisted merge conflict with its resolution state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedConflict {
    pub entity_id: String,
    pub entity_name: String,
    pub file_origin: Option<String>,
    pub kind: String,
    /// Resolution choice, if any.
    pub resolution: Option<ConflictResolution>,
}

/// How a conflict was resolved.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConflictResolution {
    /// Keep the version from the current (target) branch.
    Ours,
    /// Keep the version from the source branch.
    Theirs,
}

impl PersistedMergeState {
    /// Number of unresolved conflicts.
    pub fn unresolved_count(&self) -> usize {
        self.conflicts
            .iter()
            .filter(|c| c.resolution.is_none())
            .count()
    }

    /// Whether all conflicts have been resolved.
    pub fn all_resolved(&self) -> bool {
        self.conflicts.iter().all(|c| c.resolution.is_some())
    }
}

impl PersistedConflict {
    /// Human-readable label for the conflict kind.
    pub fn kind_label(&self) -> &str {
        if self.kind.starts_with("VisibilityChange") {
            return "visibility change (public/private)";
        }
        match self.kind.as_str() {
            "Divergent" => "divergent (both sides modified differently)",
            "Convergent" => "convergent (identical changes, auto-resolvable)",
            "ModifyDelete" => "modify/delete (one side modified, other removed)",
            "AddAdd" => "add/add (both sides added with different content)",
            "SignatureChange" => "signature change (API contract break)",
            other => other,
        }
    }

    /// Short symbol for the conflict kind.
    pub fn kind_symbol(&self) -> &str {
        if self.kind.starts_with("VisibilityChange") {
            return "!V";
        }
        match self.kind.as_str() {
            "Divergent" => "~~",
            "Convergent" => "==",
            "ModifyDelete" => "~X",
            "AddAdd" => "++",
            "SignatureChange" => "!S",
            _ => "??",
        }
    }
}

/// Serialize a `MergeConflictKind` to a stable string tag.
pub fn conflict_kind_tag(kind: &MergeConflictKind) -> String {
    match kind {
        MergeConflictKind::Divergent => "Divergent".to_string(),
        MergeConflictKind::Convergent => "Convergent".to_string(),
        MergeConflictKind::ModifyDelete => "ModifyDelete".to_string(),
        MergeConflictKind::AddAdd => "AddAdd".to_string(),
        MergeConflictKind::SignatureChange => "SignatureChange".to_string(),
        MergeConflictKind::VisibilityChange { from, to } => {
            format!("VisibilityChange({:?}->{:?})", from, to)
        }
    }
}

/// Load persisted merge state from `.kin/merge_state.json`.
pub fn load_merge_state(layout: &kin_core::KinLayout) -> Result<Option<PersistedMergeState>> {
    let path = layout.merge_state_path();
    if !path.exists() {
        return Ok(None);
    }
    let data = std::fs::read_to_string(&path)?;
    let state: PersistedMergeState = serde_json::from_str(&data)?;
    Ok(Some(state))
}

/// Save persisted merge state to `.kin/merge_state.json`.
pub fn save_merge_state(
    layout: &kin_core::KinLayout,
    state: &PersistedMergeState,
) -> Result<()> {
    let path = layout.merge_state_path();
    let data = serde_json::to_string_pretty(state)?;
    std::fs::write(&path, data)?;
    Ok(())
}

/// Clear persisted merge state (delete `.kin/merge_state.json`).
pub fn clear_merge_state(layout: &kin_core::KinLayout) -> Result<()> {
    let path = layout.merge_state_path();
    if path.exists() {
        std::fs::remove_file(&path)?;
    }
    Ok(())
}

/// `kin conflicts` — Show active merge conflicts.
pub async fn run() -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;

    let state = load_merge_state(&layout)?;
    let state = match state {
        Some(s) => s,
        None => {
            println!("No merge in progress.");
            return Ok(());
        }
    };

    let total = state.conflicts.len();
    let unresolved = state.unresolved_count();
    let resolved = total - unresolved;

    println!(
        "Merge in progress: '{}' -> '{}'  (strategy: {})",
        state.source_branch, state.target_branch, state.strategy
    );
    println!(
        "  {} conflict(s) total, {} resolved, {} remaining\n",
        total, resolved, unresolved
    );

    // Group conflicts by file origin for readable display.
    let mut by_file: std::collections::BTreeMap<String, Vec<&PersistedConflict>> =
        std::collections::BTreeMap::new();
    for conflict in &state.conflicts {
        let file_key = conflict
            .file_origin
            .clone()
            .unwrap_or_else(|| "(no file)".to_string());
        by_file.entry(file_key).or_default().push(conflict);
    }

    for (file, conflicts) in &by_file {
        println!("  {}:", file);
        for c in conflicts {
            let status = match &c.resolution {
                Some(ConflictResolution::Ours) => "[resolved: ours]",
                Some(ConflictResolution::Theirs) => "[resolved: theirs]",
                None => "[UNRESOLVED]",
            };
            println!(
                "    {} {} {} — {}  {}",
                c.kind_symbol(),
                c.entity_name,
                c.entity_id,
                c.kind_label(),
                status
            );
        }
        println!();
    }

    if unresolved > 0 {
        println!("To resolve conflicts:");
        println!("  kin resolve --ours <entity>      Keep your version");
        println!("  kin resolve --theirs <entity>     Keep incoming version");
        println!("  kin resolve --all-ours            Resolve all: keep yours");
        println!("  kin resolve --all-theirs           Resolve all: keep incoming");
        println!("  kin resolve --continue             Complete merge (all must be resolved)");
        println!("  kin resolve --abort                Abort merge and clear state");
    } else {
        println!("All conflicts resolved. Run `kin resolve --continue` to complete the merge.");
    }

    Ok(())
}
