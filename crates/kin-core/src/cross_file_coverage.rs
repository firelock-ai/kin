// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! How much of a graph's knowledge crosses a file boundary, and why the rest
//! does not.
//!
//! A graph whose edges all stay inside one file cannot answer what calls what,
//! which is the whole claim the semantic substrate makes over text search. That
//! shortfall used to be invisible: every status surface reported the graph
//! healthy, and the only trace was a relations-per-entity ratio a reader had to
//! know the expected value of. This module measures the shortfall from graph
//! truth and names the two mechanisms that cause it, so a surface can disclose
//! it instead of leaving it to be inferred.
//!
//! Nothing here probes the filesystem or the process table. Callers supply the
//! entity/relation counts they already hold and the set of languages whose
//! language server they found, and the assessment is a pure function of those.
//! That keeps one vocabulary, the serialized `cross_file_coverage` object,
//! shared by `kin doctor`, `kin graph status`, and the retrieval envelope that
//! decides whether an empty result is safe to call an absence.

use std::collections::HashSet;

use kin_model::LanguageId;
use serde::{Deserialize, Serialize};

/// Languages this build can enrich with language-server evidence.
///
/// Reference, override, and type-use edges are not derivable from a
/// single-file parse: they need a resolved program, which Kin gets from an
/// external language server. The daemon wires an adapter for exactly these
/// languages, so every other language carries no such edge by construction, no
/// matter what is installed on the host.
pub const ENRICHABLE_LANGUAGES: &[LanguageId] = &[LanguageId::Rust, LanguageId::Python];

/// Whether cross-file reference evidence is available for one language.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReferenceEnrichment {
    /// An adapter is wired and its language server was found.
    Available,
    /// An adapter is wired but no language server for it is installed, so
    /// reference and override edges cannot be produced on this host.
    NoLanguageServer,
    /// This build wires no adapter for the language, so reference and override
    /// edges are unavailable regardless of what is installed.
    Unsupported,
}

impl ReferenceEnrichment {
    /// Whether this state should be surfaced as needing attention.
    ///
    /// A missing language server is a host gap an operator can close.
    /// `Unsupported` is a property of the build, and a row a reader can do
    /// nothing about is noise rather than a finding.
    pub fn is_actionable_gap(&self) -> bool {
        matches!(self, ReferenceEnrichment::NoLanguageServer)
    }
}

/// Whether the language server for `language` can enrich this host's graph.
pub fn reference_enrichment_for(
    language: LanguageId,
    servers_found: &HashSet<LanguageId>,
) -> ReferenceEnrichment {
    if !ENRICHABLE_LANGUAGES.contains(&language) {
        return ReferenceEnrichment::Unsupported;
    }
    if servers_found.contains(&language) {
        ReferenceEnrichment::Available
    } else {
        ReferenceEnrichment::NoLanguageServer
    }
}

/// Measured cross-file coverage for one language in the graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LanguageCoverage {
    pub language: String,
    pub entities: usize,
    /// Entity-to-entity relations whose source entity is in this language and
    /// whose endpoints live in different files.
    pub cross_file_relations: usize,
    pub reference_enrichment: ReferenceEnrichment,
}

/// Cross-file coverage of a graph, measured rather than assumed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossFileCoverage {
    /// Entity-to-entity relations counted, both endpoints resolved to entities.
    pub entity_relations: usize,
    /// How many of those cross a file boundary.
    pub cross_file_entity_relations: usize,
    /// Artifact-to-artifact import and include edges.
    pub artifact_import_relations: usize,
    /// One entry per language the graph actually holds entities for, ordered by
    /// entity count so the language a reader cares about leads.
    pub languages: Vec<LanguageCoverage>,
}

impl CrossFileCoverage {
    /// Assemble a report from counts the caller measured against graph truth.
    ///
    /// `per_language` carries `(language, entities, cross_file_relations)`.
    pub fn assemble(
        entity_relations: usize,
        cross_file_entity_relations: usize,
        artifact_import_relations: usize,
        per_language: impl IntoIterator<Item = (LanguageId, usize, usize)>,
        servers_found: &HashSet<LanguageId>,
    ) -> Self {
        let mut languages: Vec<LanguageCoverage> = per_language
            .into_iter()
            .map(
                |(language, entities, cross_file_relations)| LanguageCoverage {
                    language: language.to_string(),
                    entities,
                    cross_file_relations,
                    reference_enrichment: reference_enrichment_for(language, servers_found),
                },
            )
            .collect();
        languages.sort_by(|a, b| {
            b.entities
                .cmp(&a.entities)
                .then_with(|| a.language.cmp(&b.language))
        });
        Self {
            entity_relations,
            cross_file_entity_relations,
            artifact_import_relations,
            languages,
        }
    }

    /// Whether the graph holds entities but no edge between two files.
    ///
    /// This is the state the ratio used to hide. It is deliberately keyed on a
    /// hard zero: a graph with even one cross-file edge is answering the
    /// question, and how well it answers is a recall question this counter
    /// cannot settle.
    pub fn holds_no_cross_file_edges(&self) -> bool {
        self.entity_relations > 0 && self.cross_file_entity_relations == 0
    }

    /// Languages whose missing language server an operator could install.
    pub fn languages_missing_a_language_server(&self) -> Vec<&str> {
        self.languages
            .iter()
            .filter(|coverage| coverage.reference_enrichment.is_actionable_gap())
            .map(|coverage| coverage.language.as_str())
            .collect()
    }

    /// Whether any surface should present this as needing attention.
    pub fn needs_attention(&self) -> bool {
        self.holds_no_cross_file_edges() || !self.languages_missing_a_language_server().is_empty()
    }

    /// Human disclosure for a status surface, one statement per line.
    ///
    /// Every line states a measured count or a probed absence. None of them
    /// asserts the graph is complete, because nothing measured here can say so.
    pub fn disclosure_lines(&self) -> Vec<String> {
        let mut lines = vec![format!(
            "Cross-file entity relations: {} of {} ({} artifact import/include edges)",
            self.cross_file_entity_relations, self.entity_relations, self.artifact_import_relations
        )];

        if self.holds_no_cross_file_edges() {
            lines.push(
                "  no relation in this graph crosses a file boundary, so `find_references` and \
                 `trace_data_flow` cannot leave the file they start in"
                    .to_string(),
            );
        }

        let missing = self.languages_missing_a_language_server();
        if !missing.is_empty() {
            lines.push(format!(
                "  cross-file reference and override edges unavailable for {}: no language server found",
                missing.join(", ")
            ));
        }

        let unsupported: Vec<&str> = self
            .languages
            .iter()
            .filter(|coverage| {
                coverage.reference_enrichment == ReferenceEnrichment::Unsupported
                    && coverage.entities > 0
            })
            .map(|coverage| coverage.language.as_str())
            .collect();
        if !unsupported.is_empty() {
            lines.push(format!(
                "  cross-file reference and override edges unsupported for {}: this build wires no language-server adapter",
                unsupported.join(", ")
            ));
        }

        lines
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn servers(found: &[LanguageId]) -> HashSet<LanguageId> {
        found.iter().copied().collect()
    }

    #[test]
    fn a_wired_language_without_its_server_is_an_actionable_gap() {
        assert_eq!(
            reference_enrichment_for(LanguageId::Python, &servers(&[])),
            ReferenceEnrichment::NoLanguageServer
        );
        assert_eq!(
            reference_enrichment_for(LanguageId::Python, &servers(&[LanguageId::Python])),
            ReferenceEnrichment::Available
        );
    }

    #[test]
    fn an_unwired_language_stays_unsupported_even_with_a_server_installed() {
        // gopls on PATH does not give Go reference edges, because no adapter
        // consumes it. Reporting Available here would promise edges that can
        // never appear.
        assert_eq!(
            reference_enrichment_for(LanguageId::Go, &servers(&[LanguageId::Go])),
            ReferenceEnrichment::Unsupported
        );
        assert!(!ReferenceEnrichment::Unsupported.is_actionable_gap());
    }

    #[test]
    fn a_graph_with_only_same_file_edges_is_disclosed_not_inferred() {
        let coverage = CrossFileCoverage::assemble(
            17,
            0,
            0,
            [(LanguageId::Python, 15, 0)],
            &servers(&[LanguageId::Python]),
        );
        assert!(coverage.holds_no_cross_file_edges());
        assert!(coverage.needs_attention());
        let disclosure = coverage.disclosure_lines().join("\n");
        assert!(
            disclosure.contains("no relation in this graph crosses a file boundary"),
            "the shortfall must be stated, not left to a ratio: {disclosure}"
        );
    }

    #[test]
    fn a_graph_that_crosses_files_makes_no_shortfall_claim() {
        let coverage = CrossFileCoverage::assemble(
            17,
            6,
            3,
            [(LanguageId::Python, 15, 6)],
            &servers(&[LanguageId::Python]),
        );
        assert!(!coverage.holds_no_cross_file_edges());
        assert!(!coverage.needs_attention());
        let disclosure = coverage.disclosure_lines().join("\n");
        assert!(disclosure.contains("6 of 17"));
        assert!(!disclosure.contains("no relation in this graph"));
    }

    #[test]
    fn a_missing_language_server_is_named_with_its_language() {
        let coverage =
            CrossFileCoverage::assemble(40, 12, 4, [(LanguageId::Python, 15, 12)], &servers(&[]));
        assert_eq!(
            coverage.languages_missing_a_language_server(),
            vec!["python"]
        );
        assert!(coverage.needs_attention());
        assert!(coverage
            .disclosure_lines()
            .join("\n")
            .contains("unavailable for python: no language server found"));
    }

    #[test]
    fn languages_lead_with_the_one_holding_the_most_entities() {
        let coverage = CrossFileCoverage::assemble(
            0,
            0,
            0,
            [
                (LanguageId::Python, 3, 0),
                (LanguageId::Rust, 90, 40),
                (LanguageId::Go, 3, 1),
            ],
            &servers(&[LanguageId::Rust]),
        );
        let order: Vec<&str> = coverage
            .languages
            .iter()
            .map(|c| c.language.as_str())
            .collect();
        assert_eq!(order, vec!["rust", "go", "python"]);
    }

    #[test]
    fn the_report_round_trips_as_the_cross_file_coverage_object() {
        let coverage =
            CrossFileCoverage::assemble(17, 0, 0, [(LanguageId::Python, 15, 0)], &servers(&[]));
        let json = serde_json::to_string(&coverage).expect("serializes");
        assert!(json.contains("\"reference_enrichment\":\"no_language_server\""));
        let parsed: CrossFileCoverage = serde_json::from_str(&json).expect("round trips");
        assert_eq!(parsed, coverage);
    }
}
