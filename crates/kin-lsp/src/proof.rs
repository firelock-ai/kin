// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! LSP enrichment proof: completion accounting and the fail-loud citable gate.
//!
//! In a citable / proof run, LSP enrichment must be PROVEN, not assumed:
//!
//! - which servers ran, at which versions (provenance),
//! - enrichment completion per language (files attempted / enriched / failed),
//! - and failures fail LOUD — a citable run may never silently degrade to
//!   unenriched.
//!
//! This module owns the record shape ([`LspEnrichmentProof`]) and the
//! accumulator ([`ProofRecorder`]) the enrichment driver feeds during a run.
//! The record is build-agnostic on purpose: the Kin side pairs it with
//! `kin-buildinfo` (binary sha / dirty / version) when it attaches the proof to
//! its provenance surface, so this crate stays free of Kin runtime types.

use std::collections::BTreeSet;
use std::fmt;

use kin_model::LanguageId;
use serde::{Deserialize, Serialize};

use crate::registry::{LspCapability, ProviderGap, ProviderId, ProviderProbe};

/// The contract a run is held to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofMode {
    /// Best-effort enrichment; gaps are recorded but not fatal.
    #[default]
    Advisory,
    /// Citable / proof run; required-language gaps and silent file failures are
    /// violations of the proof contract.
    Citable,
}

/// A single file whose enrichment failed. Retained (not swallowed) so a citable
/// run can point at exactly what degraded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileFailure {
    pub file: String,
    pub reason: String,
}

/// Per-language enrichment accounting within a proof run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LanguageEnrichment {
    pub language: LanguageId,
    /// The provider that ran, once one was resolved and probed.
    pub provider: Option<ProviderId>,
    pub version: Option<String>,
    /// Capabilities the live server reported (source of truth for what ran).
    pub probed_capabilities: BTreeSet<LspCapability>,
    /// Expected-but-not-probed capabilities — drift between design and server.
    pub missing_capabilities: BTreeSet<LspCapability>,
    pub files_attempted: u64,
    pub files_enriched: u64,
    pub files_failed: u64,
    pub relations_emitted: u64,
    /// Detail for each failed file (empty on a clean language).
    pub failures: Vec<FileFailure>,
}

impl LanguageEnrichment {
    fn new(language: LanguageId) -> Self {
        Self {
            language,
            provider: None,
            version: None,
            probed_capabilities: BTreeSet::new(),
            missing_capabilities: BTreeSet::new(),
            files_attempted: 0,
            files_enriched: 0,
            files_failed: 0,
            relations_emitted: 0,
            failures: Vec::new(),
        }
    }

    /// Whether the live server met the citable capability floor.
    pub fn meets_minimum(&self) -> bool {
        LspCapability::CITABLE_MINIMUM
            .into_iter()
            .all(|cap| self.probed_capabilities.contains(&cap))
    }

    /// Citable-floor capabilities the server did not report.
    pub fn missing_minimum(&self) -> BTreeSet<LspCapability> {
        LspCapability::CITABLE_MINIMUM
            .into_iter()
            .filter(|cap| !self.probed_capabilities.contains(cap))
            .collect()
    }
}

/// A registry-level gap (no provider / no binary) recorded into the proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofGap {
    pub language: LanguageId,
    pub detail: String,
    /// Whether the gap is for a language the repo config marked required.
    pub required: bool,
}

/// A specific way a run violated the citable proof contract.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofViolation {
    /// A required language never resolved / ran a provider.
    MissingRequiredProvider(LanguageId),
    /// A required language's live server was below the capability floor.
    BelowMinimumCapabilities {
        language: LanguageId,
        missing: BTreeSet<LspCapability>,
    },
    /// A required language had per-file enrichment failures (silent degrade).
    FileFailures { language: LanguageId, failed: u64 },
    /// A required language had an unresolved registry gap.
    UnresolvedRequiredGap {
        language: LanguageId,
        detail: String,
    },
}

impl fmt::Display for ProofViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProofViolation::MissingRequiredProvider(language) => write!(
                f,
                "required language '{language}' ran no LSP provider (enrichment never happened)"
            ),
            ProofViolation::BelowMinimumCapabilities { language, missing } => write!(
                f,
                "required language '{language}' server is below the citable capability floor (missing: {})",
                slug_list(missing)
            ),
            ProofViolation::FileFailures { language, failed } => write!(
                f,
                "required language '{language}' had {failed} file(s) fail enrichment — a citable run cannot silently degrade"
            ),
            ProofViolation::UnresolvedRequiredGap { language, detail } => {
                write!(f, "required language '{language}' has an unresolved gap: {detail}")
            }
        }
    }
}

fn slug_list(caps: &BTreeSet<LspCapability>) -> String {
    caps.iter()
        .map(|c| c.as_slug())
        .collect::<Vec<_>>()
        .join(", ")
}

/// The proof record for one LSP enrichment pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LspEnrichmentProof {
    pub mode: ProofMode,
    /// Languages the repo config asserted as required for this citable run.
    pub required: Vec<LanguageId>,
    /// Per-language accounting, sorted by language slug for determinism.
    pub languages: Vec<LanguageEnrichment>,
    /// Registry-level gaps, sorted by language slug for determinism.
    pub gaps: Vec<ProofGap>,
}

impl LspEnrichmentProof {
    /// The per-language record for a language, if any enrichment was recorded.
    pub fn language(&self, language: LanguageId) -> Option<&LanguageEnrichment> {
        self.languages.iter().find(|l| l.language == language)
    }

    /// Total relations emitted across all languages.
    pub fn total_relations(&self) -> u64 {
        self.languages.iter().map(|l| l.relations_emitted).sum()
    }

    /// Whether any file failed or any gap exists (regardless of mode).
    pub fn has_failures(&self) -> bool {
        !self.gaps.is_empty() || self.languages.iter().any(|l| l.files_failed > 0)
    }

    /// Check the citable proof contract. For every required language:
    /// a provider must have run, its live server must meet the capability floor,
    /// it must have no per-file failures, and it must have no unresolved gap.
    /// Returns every violation (empty `Ok` means the run is citable-clean).
    pub fn verify_citable(&self) -> Result<(), Vec<ProofViolation>> {
        let mut violations = Vec::new();

        for &language in &self.required {
            // Unresolved registry gap for a required language.
            if let Some(gap) = self
                .gaps
                .iter()
                .find(|g| g.language == language && g.required)
            {
                violations.push(ProofViolation::UnresolvedRequiredGap {
                    language,
                    detail: gap.detail.clone(),
                });
            }

            match self.language(language) {
                None => {
                    // No record at all → enrichment never happened for a
                    // language the run asserted it needs. Only report this when
                    // there is not already a gap explaining the absence.
                    if !self.gaps.iter().any(|g| g.language == language) {
                        violations.push(ProofViolation::MissingRequiredProvider(language));
                    }
                }
                Some(record) => {
                    if record.provider.is_none() {
                        violations.push(ProofViolation::MissingRequiredProvider(language));
                    } else if !record.meets_minimum() {
                        violations.push(ProofViolation::BelowMinimumCapabilities {
                            language,
                            missing: record.missing_minimum(),
                        });
                    }
                    if record.files_failed > 0 {
                        violations.push(ProofViolation::FileFailures {
                            language,
                            failed: record.files_failed,
                        });
                    }
                }
            }
        }

        if violations.is_empty() {
            Ok(())
        } else {
            Err(violations)
        }
    }

    /// A one-line human summary for logs / status surfaces.
    pub fn summary(&self) -> String {
        let files_attempted: u64 = self.languages.iter().map(|l| l.files_attempted).sum();
        let files_enriched: u64 = self.languages.iter().map(|l| l.files_enriched).sum();
        let files_failed: u64 = self.languages.iter().map(|l| l.files_failed).sum();
        format!(
            "lsp-proof[{:?}]: {} language(s), {} relations, files {}/{}/{} attempted/enriched/failed, {} gap(s)",
            self.mode,
            self.languages.len(),
            self.total_relations(),
            files_attempted,
            files_enriched,
            files_failed,
            self.gaps.len(),
        )
    }
}

/// Accumulator the enrichment driver feeds during a run, producing an
/// [`LspEnrichmentProof`] via [`ProofRecorder::finish`].
#[derive(Debug, Clone)]
pub struct ProofRecorder {
    mode: ProofMode,
    required: Vec<LanguageId>,
    languages: Vec<LanguageEnrichment>,
    gaps: Vec<ProofGap>,
}

impl ProofRecorder {
    /// A recorder in the given mode with no required languages.
    pub fn new(mode: ProofMode) -> Self {
        Self {
            mode,
            required: Vec::new(),
            languages: Vec::new(),
            gaps: Vec::new(),
        }
    }

    /// A recorder in the given mode with the required-language set the registry
    /// resolved from repo config.
    pub fn with_required(mode: ProofMode, required: &[LanguageId]) -> Self {
        Self {
            mode,
            required: required.to_vec(),
            languages: Vec::new(),
            gaps: Vec::new(),
        }
    }

    fn entry_mut(&mut self, language: LanguageId) -> &mut LanguageEnrichment {
        if let Some(idx) = self.languages.iter().position(|l| l.language == language) {
            &mut self.languages[idx]
        } else {
            self.languages.push(LanguageEnrichment::new(language));
            self.languages.last_mut().expect("just pushed")
        }
    }

    fn is_required(&self, language: LanguageId) -> bool {
        self.required.contains(&language)
    }

    /// Record the provider that ran for a language and the capabilities its
    /// live server reported.
    pub fn record_probe(&mut self, probe: &ProviderProbe) {
        let missing_expected = probe.missing_expected();
        let language = probe.resolved.language;
        let entry = self.entry_mut(language);
        entry.provider = Some(probe.resolved.id.clone());
        entry.version = probe.resolved.version.clone();
        entry.probed_capabilities = probe.probed_capabilities.clone();
        entry.missing_capabilities = missing_expected;
    }

    /// Record a registry gap (no provider / no binary) for a language.
    pub fn record_gap(&mut self, gap: &ProviderGap) {
        let required = self.is_required(gap.language);
        self.gaps.push(ProofGap {
            language: gap.language,
            detail: gap.reason.to_string(),
            required,
        });
    }

    /// A file was attempted for a language.
    pub fn file_attempted(&mut self, language: LanguageId) {
        self.entry_mut(language).files_attempted += 1;
    }

    /// A file was enriched successfully, contributing `relations` edges.
    pub fn file_enriched(&mut self, language: LanguageId, relations: u64) {
        let entry = self.entry_mut(language);
        entry.files_enriched += 1;
        entry.relations_emitted += relations;
    }

    /// A file failed enrichment (server error / timeout). Fail-loud: the failure
    /// is retained in the record rather than swallowed.
    pub fn file_failed(
        &mut self,
        language: LanguageId,
        file: impl Into<String>,
        reason: impl Into<String>,
    ) {
        let entry = self.entry_mut(language);
        entry.files_failed += 1;
        entry.failures.push(FileFailure {
            file: file.into(),
            reason: reason.into(),
        });
    }

    /// Finalize into a deterministic proof record (languages and gaps sorted by
    /// language slug).
    pub fn finish(mut self) -> LspEnrichmentProof {
        self.languages.sort_by_key(|l| l.language.to_string());
        self.gaps.sort_by_key(|g| g.language.to_string());
        let mut required = self.required;
        required.sort_by_key(|l| l.to_string());
        required.dedup();
        LspEnrichmentProof {
            mode: self.mode,
            required,
            languages: self.languages,
            gaps: self.gaps,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::registry::{ProviderGapReason, ProviderRegistry, ResolvedProvider};
    use std::path::PathBuf;

    fn probe(
        language: LanguageId,
        provider: &str,
        version: Option<&str>,
        caps: &[LspCapability],
    ) -> ProviderProbe {
        ProviderProbe {
            resolved: ResolvedProvider {
                id: ProviderId::new(provider),
                language,
                command: PathBuf::from(format!("/usr/bin/{provider}")),
                args: vec![],
                version: version.map(|v| v.to_string()),
                expected_capabilities: ProviderRegistry::with_defaults()
                    .candidates(language)
                    .iter()
                    .find(|s| s.id.as_str() == provider)
                    .map(|s| s.expected_capabilities.clone())
                    .unwrap_or_default(),
            },
            probed_capabilities: caps.iter().copied().collect(),
        }
    }

    #[test]
    fn clean_required_run_is_citable() {
        let mut rec = ProofRecorder::with_required(ProofMode::Citable, &[LanguageId::Rust]);
        rec.record_probe(&probe(
            LanguageId::Rust,
            "rust-analyzer",
            Some("rust-analyzer 1.79.0"),
            &LspCapability::ALL,
        ));
        rec.file_attempted(LanguageId::Rust);
        rec.file_enriched(LanguageId::Rust, 7);
        let proof = rec.finish();

        assert_eq!(proof.total_relations(), 7);
        assert!(!proof.has_failures());
        assert!(proof.verify_citable().is_ok());
        let rust = proof.language(LanguageId::Rust).unwrap();
        assert_eq!(rust.version.as_deref(), Some("rust-analyzer 1.79.0"));
        assert_eq!(rust.files_enriched, 1);
    }

    #[test]
    fn missing_required_provider_fails_citable() {
        // Required python, but nothing ever ran.
        let rec = ProofRecorder::with_required(ProofMode::Citable, &[LanguageId::Python]);
        let proof = rec.finish();
        let violations = proof.verify_citable().unwrap_err();
        assert_eq!(
            violations,
            vec![ProofViolation::MissingRequiredProvider(LanguageId::Python)]
        );
    }

    #[test]
    fn required_gap_is_a_violation_and_not_double_counted() {
        let mut rec = ProofRecorder::with_required(ProofMode::Citable, &[LanguageId::Go]);
        rec.record_gap(&ProviderGap {
            language: LanguageId::Go,
            reason: ProviderGapReason::NoBinaryOnPath,
            tried: vec![ProviderId::new("gopls")],
        });
        let proof = rec.finish();
        let violations = proof.verify_citable().unwrap_err();
        // Exactly one violation: the unresolved required gap (NOT also a
        // MissingRequiredProvider, since the gap already explains the absence).
        assert_eq!(violations.len(), 1);
        assert!(matches!(
            violations[0],
            ProofViolation::UnresolvedRequiredGap {
                language: LanguageId::Go,
                ..
            }
        ));
    }

    #[test]
    fn below_minimum_capabilities_fails_citable() {
        let mut rec = ProofRecorder::with_required(ProofMode::Citable, &[LanguageId::Rust]);
        // Server serves only call hierarchy — below the definition+references floor.
        rec.record_probe(&probe(
            LanguageId::Rust,
            "rust-analyzer",
            None,
            &[LspCapability::CallHierarchy],
        ));
        rec.file_attempted(LanguageId::Rust);
        let proof = rec.finish();
        let violations = proof.verify_citable().unwrap_err();
        assert!(matches!(
            &violations[0],
            ProofViolation::BelowMinimumCapabilities { language: LanguageId::Rust, missing }
                if missing.contains(&LspCapability::Definition)
                    && missing.contains(&LspCapability::References)
        ));
    }

    #[test]
    fn file_failure_fails_citable_but_advisory_tolerates_it() {
        let build = || {
            let mut rec = ProofRecorder::new(ProofMode::Citable);
            rec.record_probe(&probe(
                LanguageId::Rust,
                "rust-analyzer",
                None,
                &LspCapability::ALL,
            ));
            rec.file_attempted(LanguageId::Rust);
            rec.file_failed(LanguageId::Rust, "src/lib.rs", "server timeout");
            rec
        };

        // Required → violation.
        let mut rec = build();
        rec.required = vec![LanguageId::Rust];
        let proof = rec.finish();
        assert!(proof.has_failures());
        let violations = proof.verify_citable().unwrap_err();
        assert!(matches!(
            violations[0],
            ProofViolation::FileFailures {
                language: LanguageId::Rust,
                failed: 1
            }
        ));

        // Not required → the failure is recorded but not a citable violation.
        let proof2 = build().finish();
        assert!(proof2.has_failures());
        assert!(proof2.verify_citable().is_ok());
        assert_eq!(
            proof2.language(LanguageId::Rust).unwrap().failures[0].reason,
            "server timeout"
        );
    }

    #[test]
    fn missing_expected_capabilities_recorded_without_failing_floor() {
        let mut rec = ProofRecorder::with_required(ProofMode::Citable, &[LanguageId::Python]);
        // pyright expects call hierarchy too, but this server only reports the floor.
        rec.record_probe(&probe(
            LanguageId::Python,
            "pyright",
            Some("pyright 1.1.400"),
            &[LspCapability::Definition, LspCapability::References],
        ));
        rec.file_attempted(LanguageId::Python);
        rec.file_enriched(LanguageId::Python, 3);
        let proof = rec.finish();
        // Floor met → citable-clean, but the expected-vs-probed drift is visible.
        assert!(proof.verify_citable().is_ok());
        let py = proof.language(LanguageId::Python).unwrap();
        assert!(py
            .missing_capabilities
            .contains(&LspCapability::CallHierarchy));
    }

    #[test]
    fn finish_is_deterministic_across_insertion_order() {
        let build = |order: &[LanguageId]| {
            let mut rec = ProofRecorder::new(ProofMode::Advisory);
            for &lang in order {
                rec.file_attempted(lang);
            }
            rec.finish()
        };
        let a = build(&[LanguageId::Rust, LanguageId::Go, LanguageId::Python]);
        let b = build(&[LanguageId::Python, LanguageId::Rust, LanguageId::Go]);
        let langs_a: Vec<_> = a.languages.iter().map(|l| l.language).collect();
        let langs_b: Vec<_> = b.languages.iter().map(|l| l.language).collect();
        assert_eq!(langs_a, langs_b);
    }

    #[test]
    fn proof_json_round_trips() {
        let mut rec = ProofRecorder::with_required(ProofMode::Citable, &[LanguageId::Rust]);
        rec.record_probe(&probe(
            LanguageId::Rust,
            "rust-analyzer",
            Some("rust-analyzer 1.79.0"),
            &LspCapability::ALL,
        ));
        rec.file_attempted(LanguageId::Rust);
        rec.file_enriched(LanguageId::Rust, 4);
        let proof = rec.finish();
        let json = serde_json::to_string(&proof).unwrap();
        let decoded: LspEnrichmentProof = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, proof);
    }
}
