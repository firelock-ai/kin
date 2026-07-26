// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Exact in-place Git migration.
//!
//! The former snapshot conversion and semantic-change synthesis pipeline is
//! intentionally gone. Migration delegates to the same atomic repository-v6
//! admission boundary as `kin init`, so there is one Git-to-Kin authority path.

use std::sync::Arc;
use std::time::Instant;

use chrono::{DateTime, Utc};
use kin_db::{LocalFileBackend, RepositoryAuthorityManager};
use serde::{Deserialize, Serialize};

use crate::error::{MigrateError, Result};
use crate::strategy::{MigrationPlan, MigrationStrategy};

/// Result of a completed exact Git authority migration.
#[derive(Debug, Serialize, Deserialize)]
pub struct MigrationResult {
    /// Path to the published Kin repository root.
    pub kin_root: String,
    /// Migration strategy used.
    pub strategy: MigrationStrategy,
    /// Number of reachable Git commits admitted into exact authority.
    pub commits_imported: usize,
    /// Number of exact workspace artifacts admitted, independent of language.
    pub artifacts_admitted: usize,
    /// Semantic enrichment is separate from repository authority admission.
    pub files_indexed: usize,
    /// Semantic enrichment is separate from repository authority admission.
    pub entities_extracted: usize,
    /// Semantic enrichment is separate from repository authority admission.
    pub relations_extracted: usize,
    /// Initial graph-owned semantic change, when the Git repository was born.
    pub initial_change_id: Option<String>,
    /// Published default branch, when representable as UTF-8.
    pub default_branch: Option<String>,
    /// Committed repository authority generation.
    pub authority_generation: u64,
    /// Duration in milliseconds.
    pub duration_ms: u64,
    /// When publication completed.
    pub completed_at: DateTime<Utc>,
}

/// Execute an in-place, full-reachable-history migration.
///
/// Distinct-target projection and snapshot-only history are not aliases for
/// exact repository admission and therefore fail closed.
pub fn execute_migration_persisted(plan: &MigrationPlan) -> Result<MigrationResult> {
    let start = Instant::now();
    if plan.strategy != MigrationStrategy::Full {
        return Err(MigrateError::Other(
            "snapshot migration was removed; Kin admits complete reachable Git history only"
                .to_string(),
        ));
    }

    let source = plan
        .source
        .canonicalize()
        .map_err(|error| MigrateError::io(&plan.source, error))?;
    let target = if plan.target.exists() {
        plan.target
            .canonicalize()
            .map_err(|error| MigrateError::io(&plan.target, error))?
    } else {
        plan.target.clone()
    };
    if target != source {
        return Err(MigrateError::Other(format!(
            "exact Git migration is in-place only; source={} target={}",
            source.display(),
            target.display()
        )));
    }

    let initialized =
        kin_core::init_from_git(&source).map_err(|error| MigrateError::Init(error.to_string()))?;
    let authority = RepositoryAuthorityManager::open(
        initialized.repository_id.clone(),
        Arc::new(LocalFileBackend::new(initialized.layout.kindb_dir())),
    )
    .map_err(|error| MigrateError::Graph(error.to_string()))?;
    let lease = authority.read_authority();
    let metadata = lease.metadata();
    let commits_imported = metadata
        .git_external_authority
        .as_ref()
        .map_or(0, |git| git.commit_projections.len());
    let artifacts_admitted = metadata
        .workspaces
        .iter()
        .find(|workspace| workspace.workspace_id == initialized.workspace_id)
        .map_or(0, |workspace| workspace.tree.len());

    let result = MigrationResult {
        kin_root: source.display().to_string(),
        strategy: MigrationStrategy::Full,
        commits_imported,
        artifacts_admitted,
        files_indexed: 0,
        entities_extracted: 0,
        relations_extracted: 0,
        initial_change_id: initialized
            .authority
            .initial_change_id
            .map(|change| change.to_string()),
        default_branch: metadata
            .ref_state
            .default_ref
            .as_ref()
            .and_then(kin_model::RefName::as_utf8)
            .and_then(|reference| reference.strip_prefix("refs/heads/"))
            .map(str::to_owned),
        authority_generation: initialized.authority.receipt.generation,
        duration_ms: start.elapsed().as_millis() as u64,
        completed_at: Utc::now(),
    };
    tracing::info!(
        commits = result.commits_imported,
        artifacts = result.artifacts_admitted,
        generation = result.authority_generation,
        "exact Git repository authority published"
    );
    Ok(result)
}

impl MigrationResult {
    /// Generate a human-readable, authority-accurate summary.
    pub fn summary(&self) -> String {
        use std::fmt::Write;

        let mut out = String::new();
        writeln!(out, "=== Kin Exact Git Admission Complete ===").unwrap();
        writeln!(out, "Repository: {}", self.kin_root).unwrap();
        writeln!(out, "Authority: repository-v6").unwrap();
        writeln!(out, "Reachable commits admitted: {}", self.commits_imported).unwrap();
        writeln!(
            out,
            "Workspace artifacts admitted: {}",
            self.artifacts_admitted
        )
        .unwrap();
        writeln!(out, "Authority generation: {}", self.authority_generation).unwrap();
        writeln!(out, "Semantic enrichment: not run").unwrap();
        writeln!(out, "Duration: {}ms", self.duration_ms).unwrap();
        if let Some(branch) = &self.default_branch {
            writeln!(out, "Default branch: {branch}").unwrap();
        }
        out
    }
}
