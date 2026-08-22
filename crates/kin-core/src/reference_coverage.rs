// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Reference-edge completeness of the graph, per language.
//!
//! Five shipped surfaces answer from reference edges (`find_references`,
//! `trace_data_flow`, impact, xref, dead-code) and, before this, no surface
//! could say how many of those edges the graph actually holds. `graph validate`
//! reports integrity, `graph status` reported density, and a graph carrying a
//! fifth of its call edges passed both while a delete list built on the missing
//! four fifths read as fact.
//!
//! The measurement is graph-owned on both sides. The parse side is recorded at
//! extraction time on every entity of a file
//! (`kin_parser::FILE_PARSED_CALL_SITES_KEY`,
//! `kin_parser::FILE_PARSED_IMPORT_STATEMENTS_KEY`); the resolved side is
//! counted off the same relation table `find_references` reads. Nothing here
//! reads a working-tree file.
//!
//! This module is the ONE graph-completeness vocabulary. A second one used to
//! sit beside it in `cross_file_coverage`, measuring the overlapping fact from
//! its own walk and wiring its own `kin graph status` section and `kin doctor`
//! row. The two agreed on every number they shared and still left a reader two
//! sections about one graph, with no way to tell which denominator answered the
//! question they arrived with. Its unique halves live here now: the whole-graph
//! relation totals in [`GraphRelationTotals`] and the language-server state in
//! [`ReferenceEnrichment`]. Anything that needs a third completeness signal
//! belongs in this type, not beside it.

use std::collections::{BTreeMap, HashMap, HashSet};

use kin_model::{Entity, EntityId, EntityKind, EntityStore, GraphNodeId, LanguageId, RelationKind};
use serde::{Deserialize, Serialize};

/// Languages this build can enrich with language-server evidence.
///
/// Reference, override, and type-use edges are not derivable from a
/// single-file parse: they need a resolved program, which Kin gets from an
/// external language server. The daemon wires an adapter for exactly these
/// languages, so every other language carries no such edge by construction, no
/// matter what is installed on the host.
///
/// JavaScript and TypeScript are one entry each rather than one shared entry,
/// because this list is read per language the repository actually holds and a
/// JavaScript-only repository must not be told its enrichment rides on a
/// TypeScript row. Both resolve to the same adapter and the same server binary.
///
/// "The daemon wires an adapter for exactly these" is an assertion, not a
/// comment: `kin_daemon` holds one adapter map and a test there fails if the
/// two sets ever disagree. They disagreed silently before, which is how a
/// JavaScript repository read `unsupported` while the adapter it needed already
/// existed in kin-lsp.
pub const ENRICHABLE_LANGUAGES: &[LanguageId] = &[
    LanguageId::Rust,
    LanguageId::Python,
    LanguageId::TypeScript,
    LanguageId::JavaScript,
];

/// What a host's language server can actually do for one language.
///
/// Three states, not two, because a missing server and a present-but-broken one
/// need different repairs and a surface handed a boolean cannot tell an operator
/// which it is in. `Unusable` carries the server's own message, which is the
/// only text that names the repair.
///
/// Produced by whichever process can actually start a server and PUBLISHED to
/// the query paths, which must not spawn subprocesses to answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LanguageServerReadiness {
    /// Resolved, completed the initialize handshake, and reported capabilities.
    Usable,
    /// A binary was found and the server refused to initialize.
    Unusable { reason: String },
    /// No server binary for this language was found at all.
    Absent,
}

/// Per-language readiness as published by the process that probed.
pub type LanguageServerReadinessMap =
    std::collections::HashMap<LanguageId, LanguageServerReadiness>;

/// Whether cross-file reference evidence is available for one language.

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReferenceEnrichment {
    /// Nothing told this report which language servers the host has, so the
    /// state is unread rather than absent. The default, because a measurement
    /// taken without that input must not report a gap it never looked for.
    #[default]
    Unknown,
    /// An adapter is wired and its language server was found.
    Available,
    /// An adapter is wired but no language server for it is installed, so
    /// reference and override edges cannot be produced on this host.
    NoLanguageServer,
    /// An adapter is wired and a server binary was found, but the server
    /// refuses to initialize, so no edge can be produced either.
    ///
    /// Kept apart from [`ReferenceEnrichment::NoLanguageServer`] because the
    /// repairs differ: one is an install, the other is a broken install, and a
    /// host reporting the wrong one sends an operator to the wrong fix. Binary
    /// presence alone cannot tell them apart, which is why this state only
    /// exists once something asks the server to start.
    LanguageServerUnusable,
    /// This build wires no adapter for the language, so reference and override
    /// edges are unavailable regardless of what is installed.
    Unsupported,
}

impl ReferenceEnrichment {
    /// Whether this state should be surfaced as needing attention.
    ///
    /// A missing language server is a host gap an operator can close.
    /// `Unsupported` is a property of the build, and a row a reader can do
    /// nothing about is noise rather than a finding. `Unknown` is not a gap
    /// either: nothing looked, so nothing was found missing.
    pub fn is_actionable_gap(&self) -> bool {
        matches!(
            self,
            ReferenceEnrichment::NoLanguageServer | ReferenceEnrichment::LanguageServerUnusable
        )
    }
}

/// Whether the language server for `language` can enrich this host's graph.
pub fn reference_enrichment_for(
    language: LanguageId,
    readiness: &LanguageServerReadinessMap,
) -> ReferenceEnrichment {
    if !ENRICHABLE_LANGUAGES.contains(&language) {
        return ReferenceEnrichment::Unsupported;
    }
    match readiness.get(&language) {
        Some(LanguageServerReadiness::Usable) => ReferenceEnrichment::Available,
        Some(LanguageServerReadiness::Unusable { .. }) => {
            ReferenceEnrichment::LanguageServerUnusable
        }
        Some(LanguageServerReadiness::Absent) | None => ReferenceEnrichment::NoLanguageServer,
    }
}

/// Whole-graph relation totals, across EVERY entity-to-entity relation kind.
///
/// Deliberately a wider scope than the per-language rows below, which count
/// only the three reference kinds five shipped surfaces answer from. Both are
/// true about one graph and they are different numbers, so they are named apart
/// and the summary says which is which; a reader handed two bare totals cannot
/// tell which denominator applies to the question they actually asked.
///
/// Supplied by the caller that already walked the relation table rather than
/// re-walked here, so one response counts each edge once.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphRelationTotals {
    /// Entity-to-entity relations counted, both endpoints resolved to entities.
    pub entity_relations: usize,
    /// How many of those cross a file boundary.
    pub cross_file_entity_relations: usize,
    /// Artifact-to-artifact import and include edges, which no entity-rooted
    /// query reaches.
    pub artifact_import_relations: usize,
}

impl GraphRelationTotals {
    /// Whether the graph holds entity relations but no edge between two files.
    ///
    /// This is the state a relations-per-entity ratio used to hide. It is
    /// deliberately keyed on a hard zero: a graph with even one cross-file edge
    /// is answering the question, and how well it answers is a recall question
    /// this counter cannot settle.
    pub fn holds_no_cross_file_edges(&self) -> bool {
        self.entity_relations > 0 && self.cross_file_entity_relations == 0
    }
}

/// Reference kinds every consulting surface treats as a reference.
///
/// The same set `find_references` defaults to. Dead-code, coverage, and
/// references must not each carry their own list: the four-entity contradiction
/// FIR-2356 records is what two lists produce.
/// The two artifact-level edge kinds an import statement can resolve to.
///
/// `Includes` is here because a C or C++ `#include` of a repo-local header
/// resolves through the same import path and lands on the same artifact-level
/// edge; counting only `Imports` would under-report those languages the same
/// way `Imports` alone under-reported JavaScript.
const ARTIFACT_IMPORT_RELATION_KINDS: [RelationKind; 2] =
    [RelationKind::Imports, RelationKind::Includes];

pub const REFERENCE_RELATION_KINDS: [RelationKind; 3] = [
    RelationKind::Calls,
    RelationKind::Imports,
    RelationKind::References,
];

/// How much of a language's parsed reference surface reached the graph.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReferenceResolution {
    /// Nothing gave this language a call-site denominator, so the ratio is
    /// unknown. Either no file carries a parse-side count (a store ingested
    /// before the count was recorded reads this way), or every file that
    /// carries one recorded zero. Unmeasured is not zero and it is not
    /// complete.
    Unmeasured,
    /// The parser read call sites and the graph holds no call edge at all. The
    /// strongest available evidence that resolution is broken for this language
    /// rather than merely partial.
    NoneResolved,
    /// Some resolved, fewer than were parsed. Expected on every real
    /// repository: a call into a third-party or standard library has no in-repo
    /// target to resolve to, so this is not on its own a defect.
    PartiallyResolved,
    /// At least as many edges resolved as sites were parsed.
    FullyResolved,
}

impl ReferenceResolution {
    pub fn label(self) -> &'static str {
        match self {
            Self::Unmeasured => "unmeasured",
            Self::NoneResolved => "none resolved",
            Self::PartiallyResolved => "partial",
            Self::FullyResolved => "resolved",
        }
    }
}

/// How much of a language's call parse side carries a graph-owned count.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallSiteMeasurement {
    /// No file recorded a call-site count. Absent, not zero.
    None,
    /// Some files recorded one and some did not, so the sum is drawn from a
    /// different set of files than the resolved edges are.
    Partial,
    /// Every file of this language recorded one, so the pair is a ratio.
    Complete,
}

/// Reference-edge completeness for one language present in the graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LanguageReferenceCoverage {
    pub language: String,
    /// Files of this language that own at least one entity.
    pub files: usize,
    /// Files of this language carrying a graph-owned parse-side count.
    pub files_measured: usize,
    pub entities: usize,
    /// Call sites the parser read across measured files, before resolution.
    /// `None` when no file of this language carries the count.
    pub parsed_call_sites: Option<u64>,
    /// Files of this language that recorded a CALL-site count specifically.
    ///
    /// Distinct from `files_measured`, which is satisfied by an import count
    /// alone, and the distinction is the whole defect. Python removes the
    /// call-site count from any file whose call extraction was incomplete and
    /// keeps it on any file that had no calls at all, so on a real repository
    /// the only files reporting a call count are the ones with no calls. Summed
    /// blind that is a measured zero, and `calls 238/0` is what every Python
    /// user read: 238 call edges against a denominator drawn from the files
    /// that could not contribute one.
    #[serde(default)]
    pub call_sites_measured_files: usize,
    /// Import statements the parser read across measured files.
    pub parsed_import_statements: Option<u64>,
    /// `Calls` edges the graph holds whose caller is of this language.
    pub resolved_call_edges: u64,
    /// `Imports` and `Includes` edges the graph holds whose importer is of this
    /// language, counted at BOTH levels.
    ///
    /// An import of a module this repository owns resolves to an
    /// artifact-to-artifact edge. Counting only the entity-rooted ones reported
    /// `imports 0/220 (0%)` for a JavaScript repository whose relative
    /// `require` specifiers had all resolved, because a CommonJS module is a
    /// file and its import edge therefore joins two artifacts. Zero here still
    /// does not on its own decide `resolution`: an import can only resolve to a
    /// target the repository holds.
    pub resolved_import_edges: u64,
    /// Of `parsed_import_statements`, how many name a module outside this
    /// repository, so no resolver could have produced an in-repo target.
    ///
    /// `None` when no file of this language carries the count, which is every
    /// language whose specifier syntax does not settle the question. Reported
    /// beside the ratio so a low percentage is readable: an ECMAScript
    /// repository whose dependencies outnumber its own modules has a low import
    /// ratio by construction, not by defect.
    #[serde(default)]
    pub external_module_imports: Option<u64>,
    /// Reference edges (calls, imports, references) between two entities of
    /// this repository that live in DIFFERENT files. The count a
    /// whole-repository absence claim rests on.
    pub cross_file_reference_edges: u64,
    /// Reference edges whose endpoints share a file.
    pub intra_file_reference_edges: u64,
    /// Reference edges pointing at a target this repository does not own (an
    /// external placeholder). Counted apart from `cross_file_reference_edges`
    /// so resolving imports to third-party packages cannot stand in for
    /// resolving them inside the repository.
    pub external_reference_edges: u64,
    pub resolution: ReferenceResolution,
    /// Whether a language server can supply this language's reference and
    /// override edges on this host. The collector cannot know that from graph
    /// truth, so it leaves `Unknown` and
    /// [`ReferenceEdgeCoverage::with_language_servers`] fills it in on the
    /// surfaces that probed.
    #[serde(default)]
    pub reference_enrichment: ReferenceEnrichment,
}

impl LanguageReferenceCoverage {
    /// Percent of parsed call sites that produced an edge, capped at 100.
    ///
    /// A call site can fan out to several same-named targets, so the raw ratio
    /// can exceed 1; the cap keeps the figure readable as coverage.
    pub fn call_percent(&self) -> Option<u32> {
        if self.call_site_measurement() != CallSiteMeasurement::Complete {
            return None;
        }
        percent(self.parsed_call_sites, self.resolved_call_edges)
    }

    /// How much of this language's call parse side was actually measured.
    ///
    /// A count summed over some files cannot be a denominator for edges counted
    /// over all of them. Naming the three states keeps the renderer, the
    /// percentage and any future consumer reading the same rule instead of each
    /// re-deriving it from two integers.
    pub fn call_site_measurement(&self) -> CallSiteMeasurement {
        match self.parsed_call_sites {
            None => CallSiteMeasurement::None,
            Some(_) if self.call_sites_measured_files == 0 => CallSiteMeasurement::None,
            Some(_) if self.call_sites_measured_files < self.files => CallSiteMeasurement::Partial,
            Some(_) => CallSiteMeasurement::Complete,
        }
    }

    pub fn import_percent(&self) -> Option<u32> {
        percent(self.parsed_import_statements, self.resolved_import_edges)
    }

    /// Whether an absence answered from this language's edges can be trusted.
    ///
    /// False in exactly the two states that produced the founding failure: a
    /// language whose parsed reference surface resolved to nothing, and a
    /// multi-file language holding no cross-file reference edge at all while
    /// its files do import across modules (or while nothing measured them).
    pub fn absence_is_supportable(&self) -> bool {
        self.unsupportable_reason().is_none()
    }

    /// Why absence cannot be concluded for this language, in one sentence the
    /// output can print verbatim.
    pub fn unsupportable_reason(&self) -> Option<String> {
        if self.resolution == ReferenceResolution::NoneResolved {
            let parsed = self.parsed_call_sites.unwrap_or(0);
            return Some(format!(
                "{}: {parsed} parsed call sites resolved to 0 call edges",
                self.language
            ));
        }

        if self.files < 2 || self.cross_file_reference_edges > 0 {
            return None;
        }

        match self.parsed_import_statements {
            Some(0) => None,
            Some(imports) => Some(format!(
                "{}: {} files carry {imports} import statements and the graph holds no cross-file \
                 reference edge between them",
                self.language, self.files
            )),
            None => Some(format!(
                "{}: {} files and no cross-file reference edge between them, with no parse-side \
                 count recorded to compare against",
                self.language, self.files
            )),
        }
    }
}

/// Whether this entity kind's INCOMING call edges are under-resolved by the
/// linker, so an empty reference result for it is not an authoritative absence.
///
/// Receiver-method calls (`x.method()`) are linked by bare name while method
/// entities are keyed by their qualified name, so a method's incoming `Calls`
/// edges are frequently dropped. That is a fact about the linker rather than
/// about any one surface, which is why it lives beside the other
/// graph-completeness verdicts instead of at a caller.
///
/// It moved here because two surfaces over one graph answered opposite things
/// about one entity (FIR-2550). The MCP negative envelope refused to certify
/// `IngestReport.summary` as absent, naming this exact gap, while `kin
/// dead-code` printed the same entity in a delete list under a bare "Found 7
/// unreferenced entities". The rule was stated once, inside `kin-mcp`, and the
/// CLI had no path to it. One statement, both readers.
///
/// Not gated on language, and deliberately so. The MCP gate is not, and a
/// language condition on this copy alone would put the two surfaces back into
/// disagreement on whichever languages the condition excluded, which is the
/// failure this function exists to end. A language whose receiver calls all
/// resolve produces no candidate rows to label, so the gate costs it nothing.
pub fn kind_under_resolves_incoming_calls(kind: EntityKind) -> bool {
    kind == EntityKind::Method
}

/// [`kind_under_resolves_incoming_calls`] for a payload that carries its kind
/// as the serde name rather than as the enum.
///
/// Parses the name back into the kind instead of restating the match, so the
/// JSON-shaped reader and the graph-shaped reader cannot drift apart. An
/// unparseable name is not a method, because inventing a gate for a kind that
/// was never reported would label rows on a payload shape nobody validated.
pub fn kind_name_under_resolves_incoming_calls(kind_name: &str) -> bool {
    serde_json::from_value::<EntityKind>(serde_json::Value::String(kind_name.to_ascii_lowercase()))
        .is_ok_and(kind_under_resolves_incoming_calls)
}

/// The limiting factor a surface reports when [`kind_under_resolves_incoming_calls`]
/// holds for the entity it answered about.
///
/// `subject` names what came back empty, so one sentence reads correctly for a
/// reference list, a pack, a walk and a delete-list row. The wording is the
/// wording `find_references` has published since FIR-2404 and is asserted
/// verbatim by tests on both sides; changing it changes what a caller keys on.
pub fn method_absence_limiting_factor(subject: &str) -> String {
    format!(
        "method_call_resolution_incomplete: receiver-method calls are linked by bare name and \
         may be unresolved, so {subject} is not an authoritative absence for a method"
    )
}

/// The bare label of [`method_absence_limiting_factor`], for a surface with room
/// for a tag but not a sentence.
pub const METHOD_ABSENCE_LIMITING_FACTOR: &str = "method_call_resolution_incomplete";

fn percent(parsed: Option<u64>, resolved: u64) -> Option<u32> {
    let parsed = parsed?;
    if parsed == 0 {
        return None;
    }
    Some(((resolved.saturating_mul(100) / parsed).min(100)) as u32)
}

/// Reference-edge completeness of a whole graph, one row per language.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReferenceEdgeCoverage {
    pub languages: Vec<LanguageReferenceCoverage>,
    /// Whole-graph relation totals, when the caller measured them. `None` means
    /// nobody counted, which is not the same as a graph holding no edges, so no
    /// surface may render a zero for it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub totals: Option<GraphRelationTotals>,
    /// Parse coverage of the same graph, when the caller measured it.
    ///
    /// Carried here rather than beside this type because this module is the one
    /// graph-completeness vocabulary, and a reader arriving at a status page
    /// with "why does Kin not know about this file" must not be handed two
    /// sections with two denominators. `None` means nobody counted, which is
    /// not the same as a graph whose files are all parsed, so no surface may
    /// render an all-clear for it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parse: Option<ParseCoverageCensus>,
}

impl ReferenceEdgeCoverage {
    /// Attach the whole-graph totals the caller already counted.
    pub fn with_totals(mut self, totals: GraphRelationTotals) -> Self {
        self.totals = Some(totals);
        self
    }

    /// Attach the parse census the caller collected from the repository tree.
    ///
    /// Kept off the collector for the reason [`Self::with_language_servers`] is:
    /// this module's collector starts from the entity table and a file with no
    /// entities is invisible to it by construction, which is precisely the
    /// population a parse hole lives in. The census reads the repository tree
    /// and the layout table instead, and [`collect_parse_coverage`] is where it
    /// comes from.
    pub fn with_parse_coverage(mut self, parse: ParseCoverageCensus) -> Self {
        self.parse = Some(parse);
        self
    }

    /// Languages whose parse coverage withholds this store's all-clear.
    ///
    /// Empty when nobody measured, because an unmeasured census has not shown a
    /// hole any more than it has shown coverage.
    pub fn parse_warning_lines(&self) -> Vec<String> {
        self.parse
            .as_ref()
            .map(ParseCoverageCensus::warning_lines)
            .unwrap_or_default()
    }

    /// Fill in each language's enrichment state from the readiness a caller
    /// probed.
    ///
    /// Kept off the collector because probing the host is not reading the graph,
    /// and this module measures graph truth alone. Readiness rather than a set
    /// of found binaries, because a server that is present and cannot start
    /// produces exactly as many edges as one that is absent, and only the
    /// repair differs.
    pub fn with_language_servers(mut self, readiness: &LanguageServerReadinessMap) -> Self {
        for language in &mut self.languages {
            // The rows carry a language's display name, and kin-model has no
            // parse back from one. Matching against the enrichable set's own
            // names keeps the mapping in a single place: a name outside that set
            // is Unsupported by definition, which is the answer either way.
            let enrichable = ENRICHABLE_LANGUAGES
                .iter()
                .copied()
                .find(|candidate| candidate.to_string() == language.language);
            language.reference_enrichment = match enrichable {
                Some(id) => reference_enrichment_for(id, readiness),
                None => ReferenceEnrichment::Unsupported,
            };
        }
        self
    }

    /// Languages whose edges cannot support an absence claim, worst first.
    pub fn unsupportable_absence_reasons(&self) -> Vec<String> {
        self.languages
            .iter()
            .filter_map(LanguageReferenceCoverage::unsupportable_reason)
            .collect()
    }

    /// Whether every language present can support an absence claim.
    pub fn absence_is_supportable(&self) -> bool {
        self.languages
            .iter()
            .all(LanguageReferenceCoverage::absence_is_supportable)
    }

    /// Whether the graph holds entity relations but no edge between two files.
    ///
    /// False when nobody counted the totals: an unmeasured graph has not been
    /// shown to hold no cross-file edge.
    pub fn holds_no_cross_file_edges(&self) -> bool {
        self.totals
            .is_some_and(|totals| totals.holds_no_cross_file_edges())
    }

    /// Languages whose missing language server an operator could install.
    pub fn languages_missing_a_language_server(&self) -> Vec<&str> {
        self.languages
            .iter()
            .filter(|language| language.reference_enrichment.is_actionable_gap())
            .map(|language| language.language.as_str())
            .collect()
    }

    /// Whether any surface should present this as needing attention.
    pub fn needs_attention(&self) -> bool {
        self.holds_no_cross_file_edges()
            || !self.languages_missing_a_language_server().is_empty()
            || !self.absence_is_supportable()
    }

    /// Terminal rendering, one line per language plus the caveat a reader needs
    /// to keep a sub-100% ratio from reading as a defect.
    ///
    /// This is the whole completeness section for a status surface. It used to
    /// be two, printed from two types, and neither said which of its two
    /// denominators the other was using.
    pub fn summary_lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        // Parse coverage first, because it is the denominator every line under
        // it inherits. A language whose files never reached an adapter has no
        // parsed call site to resolve and no entity to hold an edge, so a
        // resolved-edge ratio computed over it describes the part of the
        // repository Kin managed to read rather than the repository.
        if let Some(parse) = self.parse.as_ref() {
            lines.extend(parse.summary_lines());
            lines.push(String::new());
        }
        if let Some(totals) = self.totals {
            lines.push(format!(
                "Cross-file entity relations: {} of {} across all relation kinds ({} artifact \
                 import/include edges)",
                totals.cross_file_entity_relations,
                totals.entity_relations,
                totals.artifact_import_relations
            ));
            if totals.holds_no_cross_file_edges() {
                lines.push(
                    "  no relation in this graph crosses a file boundary, so `find_references` \
                     and `trace_data_flow` cannot leave the file they start in"
                        .to_string(),
                );
            }
        }

        if self.languages.is_empty() {
            lines
                .push("Reference edge coverage: no language entities in the graph yet".to_string());
            return lines;
        }

        lines.push("Reference edge coverage (resolved edges / parsed sites):".to_string());
        for language in &self.languages {
            lines.push(format!("  {}", language_summary(language)));
        }

        let missing = self.languages_missing_a_language_server();
        if !missing.is_empty() {
            lines.push(format!(
                "  cross-file reference and override edges unavailable for {}: no language server \
                 found",
                missing.join(", ")
            ));
        }
        let unsupported: Vec<&str> = self
            .languages
            .iter()
            .filter(|language| {
                language.reference_enrichment == ReferenceEnrichment::Unsupported
                    && language.entities > 0
            })
            .map(|language| language.language.as_str())
            .collect();
        if !unsupported.is_empty() {
            lines.push(format!(
                "  cross-file reference and override edges unsupported for {}: this build wires \
                 no language-server adapter",
                unsupported.join(", ")
            ));
        }

        lines.push(
            "  Counts entity-level reference edges only, which is what find_references, \
             trace_data_flow, impact and dead-code answer from; a local import statement also \
             resolves to an artifact-level edge those queries never reach. The all-kinds total \
             above is the wider count and is not this denominator."
                .to_string(),
        );
        lines.push(
            "  A call ratio below 100% is expected: a call into a third-party or standard library \
             has no in-repo target. Zero call edges, or zero cross-file edges across several \
             files, is not."
                .to_string(),
        );
        lines
    }
}

fn language_summary(coverage: &LanguageReferenceCoverage) -> String {
    let calls = match (coverage.parsed_call_sites, coverage.call_percent()) {
        (Some(parsed), Some(percent)) => format!(
            "calls {}/{parsed} ({percent}%)",
            coverage.resolved_call_edges
        ),
        // Some files recorded a call count and some did not. Printing the sum
        // against edges counted over every file states a ratio between two
        // different populations, which is how a working Python graph reported
        // itself as `calls 238/0`. Say which files the parse side came from.
        (Some(parsed), None)
            if coverage.call_site_measurement() == CallSiteMeasurement::Partial =>
        {
            format!(
                "calls {} resolved, parse side measured on {} of {} files ({parsed} sites there)",
                coverage.resolved_call_edges, coverage.call_sites_measured_files, coverage.files
            )
        }
        // `call_percent` declines exactly when there is no denominator, so this
        // arm is the zero-parse-side case. Printing it as a fraction produced
        // `calls 238/0` beside `imports 0/40 (0%)`, which reads as two fields
        // in opposite orders rather than as the one thing it is: a count with
        // nothing to compare it against.
        (Some(_), None) => format!(
            "calls {} resolved, parse side counted no call sites",
            coverage.resolved_call_edges
        ),
        (None, _) => format!(
            "calls {} resolved, parse side unmeasured",
            coverage.resolved_call_edges
        ),
    };
    let external = match coverage.external_module_imports {
        Some(external) if external > 0 => {
            format!(", {external} name a module outside this repository")
        }
        _ => String::new(),
    };
    let imports = match (coverage.parsed_import_statements, coverage.import_percent()) {
        (Some(parsed), Some(percent)) => format!(
            "imports {}/{parsed} ({percent}%){external}",
            coverage.resolved_import_edges
        ),
        (Some(_), None) => format!(
            "imports {} resolved, parse side counted no import statements",
            coverage.resolved_import_edges
        ),
        (None, _) => format!(
            "imports {} resolved, parse side unmeasured",
            coverage.resolved_import_edges
        ),
    };
    format!(
        "{}: {} files, {calls}, {imports}, cross-file {}, intra-file {} [{}]",
        coverage.language,
        coverage.files,
        coverage.cross_file_reference_edges,
        coverage.intra_file_reference_edges,
        coverage.resolution.label()
    )
}

#[derive(Default)]
struct LanguageTally {
    files: HashSet<String>,
    measured_files: HashSet<String>,
    entities: usize,
    parsed_call_sites: u64,
    parsed_import_statements: u64,
    call_site_files: usize,
    import_statement_files: usize,
    resolved_call_edges: u64,
    resolved_import_edges: u64,
    external_module_imports: u64,
    external_module_import_files: usize,
    cross_file: u64,
    intra_file: u64,
    external: u64,
}

/// Measure reference-edge completeness against graph truth alone.
///
/// Reads the same relation table `find_references` reads, and the same
/// parse-side counts extraction recorded, so the ratio it reports is about the
/// graph a query would be answered from.
pub fn collect_reference_edge_coverage<S>(store: &S) -> Result<ReferenceEdgeCoverage, S::Error>
where
    S: EntityStore + ?Sized,
{
    let entities = store.list_all_entities()?;
    collect_reference_edge_coverage_from(store, &entities)
}

/// Same measurement against an entity list the caller already holds.
pub fn collect_reference_edge_coverage_from<S>(
    store: &S,
    entities: &[Entity],
) -> Result<ReferenceEdgeCoverage, S::Error>
where
    S: EntityStore + ?Sized,
{
    let mut by_id: HashMap<EntityId, (LanguageId, Option<String>)> = HashMap::new();
    for entity in entities {
        by_id.insert(
            entity.id,
            (
                entity.language,
                entity.file_origin.as_ref().map(|file| file.0.clone()),
            ),
        );
    }

    let mut tallies: BTreeMap<String, LanguageTally> = BTreeMap::new();
    let mut seen_parse_counts: HashSet<(String, String)> = HashSet::new();

    for entity in entities {
        // An external reference target stands for a symbol another repository
        // owns: no file, no span, uniform kind. Counting it as a file of this
        // language would put a file count in the report that no artifact backs.
        if kin_index::is_external_reference_target(entity) {
            continue;
        }
        let language = entity.language.to_string();
        let tally = tallies.entry(language.clone()).or_default();
        tally.entities += 1;
        let Some(file) = entity.file_origin.as_ref().map(|file| file.0.clone()) else {
            continue;
        };
        tally.files.insert(file.clone());

        if !seen_parse_counts.insert((language, file.clone())) {
            continue;
        }
        let calls = read_count(entity, kin_parser::FILE_PARSED_CALL_SITES_KEY);
        let imports = read_count(entity, kin_parser::FILE_PARSED_IMPORT_STATEMENTS_KEY);
        if calls.is_some() || imports.is_some() {
            tally.measured_files.insert(file);
        }
        if let Some(calls) = calls {
            tally.parsed_call_sites += calls;
            tally.call_site_files += 1;
        }
        if let Some(imports) = imports {
            tally.parsed_import_statements += imports;
            tally.import_statement_files += 1;
        }
        if let Some(external) =
            read_count(entity, kin_parser::FILE_PARSED_EXTERNAL_MODULE_IMPORTS_KEY)
        {
            tally.external_module_imports += external;
            tally.external_module_import_files += 1;
        }
    }

    let allowed: HashSet<RelationKind> = REFERENCE_RELATION_KINDS.iter().copied().collect();
    let mut seen_relations: HashSet<kin_model::RelationId> = HashSet::new();
    for entity in entities {
        for relation in store.get_all_relations_for_entity(&entity.id)? {
            if !allowed.contains(&relation.kind) || !seen_relations.insert(relation.id) {
                continue;
            }
            let (GraphNodeId::Entity(src), GraphNodeId::Entity(dst)) = (relation.src, relation.dst)
            else {
                continue;
            };
            let Some((language, src_file)) = by_id.get(&src) else {
                continue;
            };
            let tally = tallies.entry(language.to_string()).or_default();
            match relation.kind {
                RelationKind::Calls => tally.resolved_call_edges += 1,
                RelationKind::Imports => tally.resolved_import_edges += 1,
                _ => {}
            }
            match by_id.get(&dst).and_then(|(_, file)| file.as_ref()) {
                Some(dst_file) => match src_file {
                    Some(src_file) if src_file == dst_file => tally.intra_file += 1,
                    Some(_) => tally.cross_file += 1,
                    None => tally.external += 1,
                },
                None => tally.external += 1,
            }
        }
    }

    // An import of a module this repository owns joins two ARTIFACTS, not two
    // entities, so nothing above can see it: the loop reads relations rooted at
    // an entity, and then keeps only the ones whose endpoints are both
    // entities. Every relative `require` and every resolved ESM specifier lands
    // in that blind spot, which is how a JavaScript repository whose imports
    // had all resolved still reported `imports 0/220 (0%)`. Ask the graph for
    // them by artifact instead, attributed to the language of the file that
    // wrote the import.
    let mut counted_artifact_relations: HashSet<kin_model::RelationId> = HashSet::new();
    for tally in tallies.values_mut() {
        let mut files: Vec<&String> = tally.files.iter().collect();
        files.sort();
        for file in files {
            let Ok(repo_path) = kin_model::RepoPath::from_bytes(file.as_bytes()) else {
                continue;
            };
            let Some(artifact_id) = store.artifact_id_at_path(&repo_path) else {
                continue;
            };
            let node = GraphNodeId::Artifact(artifact_id);
            let neighborhood = store.traverse(&node, &ARTIFACT_IMPORT_RELATION_KINDS, 1)?;
            for relation in neighborhood.relations {
                // `traverse` walks both directions, so an edge INTO this file
                // shows up here too and belongs to the importer's language, not
                // this one.
                if relation.src != node
                    || !ARTIFACT_IMPORT_RELATION_KINDS.contains(&relation.kind)
                    || !counted_artifact_relations.insert(relation.id)
                {
                    continue;
                }
                tally.resolved_import_edges += 1;
            }
        }
    }

    let languages = tallies
        .into_iter()
        .map(|(language, tally)| {
            let parsed_call_sites = (tally.call_site_files > 0).then_some(tally.parsed_call_sites);
            let parsed_import_statements =
                (tally.import_statement_files > 0).then_some(tally.parsed_import_statements);
            let resolution = classify(
                tally.measured_files.len(),
                parsed_call_sites,
                tally.resolved_call_edges,
            );
            LanguageReferenceCoverage {
                language,
                files: tally.files.len(),
                files_measured: tally.measured_files.len(),
                entities: tally.entities,
                parsed_call_sites,
                call_sites_measured_files: tally.call_site_files,
                parsed_import_statements,
                resolved_call_edges: tally.resolved_call_edges,
                resolved_import_edges: tally.resolved_import_edges,
                external_module_imports: (tally.external_module_import_files > 0)
                    .then_some(tally.external_module_imports),
                cross_file_reference_edges: tally.cross_file,
                intra_file_reference_edges: tally.intra_file,
                external_reference_edges: tally.external,
                resolution,
                reference_enrichment: ReferenceEnrichment::Unknown,
            }
        })
        .collect();

    Ok(ReferenceEdgeCoverage {
        parse: None,
        languages,
        totals: None,
    })
}

/// Classify off call sites alone.
///
/// Calls are the only dimension whose parse side and resolved side describe the
/// same edges: a local import statement resolves to an artifact-level edge no
/// entity-rooted query reaches, so keying a verdict on entity-level import
/// edges would report every repository whose imports are all local as broken.
fn classify(
    measured_files: usize,
    parsed_call_sites: Option<u64>,
    resolved_call_edges: u64,
) -> ReferenceResolution {
    if measured_files == 0 {
        return ReferenceResolution::Unmeasured;
    }
    match parsed_call_sites {
        // No denominator, so no ratio and no verdict. A parse side that
        // recorded nothing is not evidence that everything it would have
        // recorded reached the graph, and reading it as one is what let a
        // language holding 238 call edges against a zero parse count print
        // `[resolved]` under a no-issues banner.
        None | Some(0) => ReferenceResolution::Unmeasured,
        Some(_) if resolved_call_edges == 0 => ReferenceResolution::NoneResolved,
        Some(parsed) if resolved_call_edges < parsed => ReferenceResolution::PartiallyResolved,
        Some(_) => ReferenceResolution::FullyResolved,
    }
}

fn read_count(entity: &Entity, key: &str) -> Option<u64> {
    entity
        .metadata
        .extra
        .get(key)
        .and_then(|value| value.as_u64())
}

/// Share of one language's tracked files that may produce no parsed layout
/// before the store stops reading as healthy, in percent.
///
/// Chosen from what the store itself holds rather than from a preference. The
/// two readings this rule has to separate are both in the ticket: an express
/// checkout where 75 of 141 admitted files produce no entity and
/// `lib/express.js` is one of them, and a repository carrying one stray script
/// no adapter claims. At a tenth, the first is a hole a reader cannot close by
/// hand and the second is not: below this share a reader can open every
/// unparsed file and see for themselves, and above it they cannot, which is
/// exactly when a surface has to say so instead of leaving it to them.
///
/// The number is a shouting threshold and nothing rests on its precision. No
/// answer is certified by it: [`ParseCoverageCensus::hole_reasons`] consults no
/// threshold at all and refuses on any file in scope that produced nothing,
/// whatever this says, so a store one file under the line still cannot certify
/// an absence over that file.
pub const PARSE_HOLE_SHARE_PERCENT: usize = 10;

/// Unparsed files a language needs before the share above is consulted.
///
/// A share alone cannot separate the two readings on a small repository, where
/// one stray script out of eight is 12 percent and is still one stray script.
/// Three is the count the ticket's own evidence names on the failing side
/// (`lib/application.js`, `lib/express.js`, `test/exports.js` on express), and
/// one or two files is the case it names on the passing side, so the floor sits
/// between them rather than between two numbers nothing measured.
pub const PARSE_HOLE_MIN_FILES: usize = 3;

/// Unparsed paths named on a status line before it stops being readable.
const PARSE_HOLE_SAMPLE: usize = 5;

/// Whether a language's parse coverage is incomplete enough for a surface to
/// withhold its all-clear.
///
/// Both conditions are read off the store: how many files of this language the
/// repository tree admits, and how many of those carry a layout. Stated once
/// here because the status line, the doctor row and the tests must not each
/// re-derive it from two integers.
pub fn parse_coverage_is_materially_incomplete(tracked: usize, unparsed: usize) -> bool {
    unparsed >= PARSE_HOLE_MIN_FILES
        && tracked > 0
        && unparsed.saturating_mul(100) >= tracked.saturating_mul(PARSE_HOLE_SHARE_PERCENT)
}

/// How much of one language the extractor actually parsed.
///
/// The denominator is the repository tree's own admitted file set, not the set
/// of files that produced an entity, and that is the whole point of the type.
/// Every other counter in this module starts from an entity and therefore
/// cannot see a file that produced none, which is the exact population a parse
/// hole lives in: on express, `lib/express.js` is admitted, is JavaScript, has
/// a full adapter registered for its extension, and holds no layout at all.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LanguageParseCoverage {
    pub language: String,
    /// Files of this language the repository tree admits and a full adapter is
    /// registered for.
    pub tracked: usize,
    /// Of those, how many produced at least one entity.
    pub with_entities: usize,
    /// Of those, how many produced none. This is the population
    /// `list_file_entities` reports one file at a time as `tier: "none"`, and
    /// the count the express run quoted as 75 of 141.
    pub unparsed: usize,
    /// Unparsed paths, shallowest first, then alphabetical.
    ///
    /// Shallowest rather than largest, and the ordering is named on the line
    /// that prints it. The repository tree records a blob hash per path and no
    /// size, so a "biggest files" ranking would be the one part of this report
    /// a reader could not check against the store. Path depth is a real
    /// property of the tree and puts a library root above a deep fixture, which
    /// is the ordering the question actually wants.
    pub sample: Vec<String>,
}

impl LanguageParseCoverage {
    /// Percent of this language's admitted files that produced an entity.
    pub fn parsed_percent(&self) -> Option<usize> {
        (self.tracked > 0).then(|| self.with_entities.saturating_mul(100) / self.tracked)
    }

    /// Whether this language's parse coverage withholds a store-wide all-clear.
    pub fn is_materially_incomplete(&self) -> bool {
        parse_coverage_is_materially_incomplete(self.tracked, self.unparsed)
    }

    /// The one sentence a status line or a doctor row prints for this language.
    pub fn hole_sentence(&self) -> String {
        let percent = self
            .parsed_percent()
            .map(|percent| format!("{percent}%"))
            .unwrap_or_else(|| "no".to_string());
        let named = if self.sample.is_empty() {
            String::new()
        } else {
            format!(
                ", including {} (shallowest paths first)",
                self.sample.join(", ")
            )
        };
        format!(
            "{} parse coverage is incomplete: {} of {} admitted files produced no entity, so \
             {percent} of this language reached the graph{named}",
            self.language, self.unparsed, self.tracked
        )
    }
}

/// Parse coverage of a whole graph, one row per language.
///
/// Collected from the repository tree and the layout table rather than from the
/// entity table, so it can count the files every other counter here is blind
/// to. See [`collect_parse_coverage`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParseCoverageCensus {
    pub languages: Vec<LanguageParseCoverage>,
}

impl ParseCoverageCensus {
    /// Languages whose parse coverage withholds an all-clear, worst share first.
    pub fn materially_incomplete(&self) -> Vec<&LanguageParseCoverage> {
        let mut rows: Vec<&LanguageParseCoverage> = self
            .languages
            .iter()
            .filter(|language| language.is_materially_incomplete())
            .collect();
        rows.sort_by_key(|language| language.parsed_percent().unwrap_or(0));
        rows
    }

    /// One warning sentence per language a surface must not report clean.
    pub fn warning_lines(&self) -> Vec<String> {
        self.materially_incomplete()
            .into_iter()
            .map(LanguageParseCoverage::hole_sentence)
            .collect()
    }

    /// Terminal rendering, one line per language that admits a file.
    ///
    /// Rendered in every state, including the whole-clean one. A section that
    /// fell silent when coverage was complete would be indistinguishable from a
    /// build that never measured it, which is the reading this census exists to
    /// end.
    pub fn summary_lines(&self) -> Vec<String> {
        if self.languages.is_empty() {
            return vec![
                "Parse coverage: the repository tree admits no file a full adapter parses"
                    .to_string(),
            ];
        }
        let mut lines =
            vec!["Parse coverage (files that produced an entity / files admitted):".to_string()];
        for language in &self.languages {
            let percent = language
                .parsed_percent()
                .map(|percent| format!(" ({percent}%)"))
                .unwrap_or_default();
            lines.push(format!(
                "  {}: {}/{}{percent}",
                language.language, language.with_entities, language.tracked
            ));
        }
        lines.push(
            "  An admitted file that produced no entity is absent from every enumeration, \
             caller count and dead-code answer over it, rather than reported as a gap in one. \
             It cannot be listed as unreferenced and it cannot supply the edge that would keep \
             something else off that list."
                .to_string(),
        );
        lines
    }

    /// Whether any language in this census holds an unparsed file.
    pub fn holds_a_parse_hole(&self) -> bool {
        self.languages.iter().any(|language| language.unparsed > 0)
    }

    /// Why an answer computed over this whole graph cannot certify an absence,
    /// one reason per language, or empty when every admitted file was parsed.
    ///
    /// Consults no threshold, and that is deliberate. [`Self::warning_lines`]
    /// decides when a store-wide page stops reading clean and needs a line a
    /// reader will not learn to skip; this decides whether one answer may print
    /// a zero, and a single unparsed file is enough to make that zero a claim
    /// about Kin's parse coverage rather than about the code. A surface that
    /// shouted on one stray script would be ignored; an answer that certified
    /// over one would be wrong.
    pub fn hole_reasons(&self) -> Vec<String> {
        self.languages
            .iter()
            .filter(|language| language.unparsed > 0)
            .map(|language| {
                let named = if language.sample.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", language.sample.join(", "))
                };
                format!(
                    "{PARSE_HOLE_LIMITING_FACTOR}: {} of {} admitted {} files produced no \
                     entity{named}, so they hold no entity for this scan to have found and no \
                     edge for one to have kept off the list",
                    language.unparsed, language.tracked, language.language
                )
            })
            .collect()
    }
}

/// Measure parse coverage against graph truth alone.
///
/// Two graph-owned reads and no filesystem walk. The repository tree says which
/// paths this graph admits; the entity table says which of them produced
/// anything. `kin_index::FileClassifier` and the adapter registry are consulted
/// about the path STRING the tree already holds, which is the same
/// classification `collect_supported_inputs` performs to print the admitted
/// count, and neither opens a file.
///
/// The signal is entity presence rather than a parsed layout, and that was
/// measured rather than assumed. A correctly admitted repository whose entities
/// all extracted carries ZERO rows in `list_file_layouts`: the layout table is
/// not part of the workspace graph snapshot a query is answered from, so a
/// census keyed on it would report every healthy store as a total parse hole
/// and could never do anything else. Entity presence is the reading the express
/// run itself quoted ("75 of 141 files produce no entity") and the one every
/// query actually answers from.
pub fn collect_parse_coverage(
    graph: &kin_db::InMemoryGraph,
) -> Result<ParseCoverageCensus, kin_db::KinDbError> {
    let resolved_tree = graph.resolved_tree();
    let entities = graph.list_all_entities()?;
    Ok(collect_parse_coverage_from(&resolved_tree, &entities))
}

/// The census rule with both graph readings as inputs, so every branch is
/// testable without a store.
pub fn collect_parse_coverage_from(
    resolved_tree: &kin_model::ResolvedTree,
    entities: &[Entity],
) -> ParseCoverageCensus {
    let registry = kin_parser::AdapterRegistry::new();
    let producing: HashSet<&str> = entities
        .iter()
        .filter(|entity| !kin_index::is_external_reference_target(entity))
        .filter_map(|entity| entity.file_origin.as_ref().map(|file| file.0.as_str()))
        .collect();
    let mut tallies: BTreeMap<String, ParseTally> = BTreeMap::new();

    for artifact in resolved_tree.artifacts_by_path() {
        if !matches!(artifact.entry, kin_model::TreeEntry::Blob { .. }) {
            continue;
        }
        let Some(path) = artifact.path.as_utf8() else {
            continue;
        };
        // Only files a FULL adapter is registered for. A shallow-syntax file
        // produces no entity by construction, so counting one as a hole would
        // report a gap where the design says there is none, and the express
        // shape is entirely inside the full-adapter set.
        if !matches!(
            kin_index::FileClassifier::classify(std::path::Path::new(path)),
            kin_index::FileClassification::EntitySource
        ) {
            continue;
        }
        let extension = std::path::Path::new(path)
            .extension()
            .and_then(|extension| extension.to_str())
            .unwrap_or_default();
        let Some(adapter) = registry.get_by_extension(extension) else {
            continue;
        };
        let tally = tallies.entry(adapter.language_id().to_string()).or_default();
        tally.tracked += 1;
        if producing.contains(path) {
            tally.with_entities += 1;
        } else {
            tally.unparsed += 1;
            tally.unparsed_paths.push(path.to_string());
        }
    }

    ParseCoverageCensus {
        languages: tallies
            .into_iter()
            .map(|(language, tally)| tally.into_row(language))
            .collect(),
    }
}

#[derive(Default)]
struct ParseTally {
    tracked: usize,
    with_entities: usize,
    unparsed: usize,
    unparsed_paths: Vec<String>,
}

impl ParseTally {
    fn into_row(mut self, language: String) -> LanguageParseCoverage {
        // Shallowest first, then alphabetical, so the ordering is total and the
        // same store always names the same files. `lib/express.js` sorts above
        // `test/fixtures/blog/index.js` because a library root is what a reader
        // asking "what did Kin miss" means by the biggest one.
        self.unparsed_paths.sort_by(|left, right| {
            let depth = |path: &String| path.matches('/').count();
            depth(left).cmp(&depth(right)).then_with(|| left.cmp(right))
        });
        self.unparsed_paths.truncate(PARSE_HOLE_SAMPLE);
        LanguageParseCoverage {
            language,
            tracked: self.tracked,
            with_entities: self.with_entities,
            unparsed: self.unparsed,
            sample: self.unparsed_paths,
        }
    }
}

/// The tag every parse-hole sentence opens with, for a surface with room for
/// a label but not a sentence, and for a caller keying on the class rather
/// than reading the prose.
pub const PARSE_HOLE_LIMITING_FACTOR: &str = "parse_hole";

#[cfg(test)]
mod tests {
    /// A host where exactly these languages have a usable server.
    fn usable(languages: &[LanguageId]) -> LanguageServerReadinessMap {
        languages
            .iter()
            .map(|language| (*language, LanguageServerReadiness::Usable))
            .collect()
    }

    use super::*;
    use kin_db::InMemoryGraph;
    use kin_model::entity::{
        Entity, EntityKind, EntityMetadata, EntityRole, FingerprintAlgorithm, SemanticFingerprint,
        Visibility,
    };
    use kin_model::ids::{FilePathId, Hash256, RelationId};
    use kin_model::relation::{Relation, RelationOrigin};

    fn entity(name: &str, file: &str, calls: Option<u64>, imports: Option<u64>) -> Entity {
        let mut metadata = EntityMetadata::default();
        if let Some(calls) = calls {
            metadata.extra.insert(
                kin_parser::FILE_PARSED_CALL_SITES_KEY.into(),
                serde_json::Value::from(calls),
            );
        }
        if let Some(imports) = imports {
            metadata.extra.insert(
                kin_parser::FILE_PARSED_IMPORT_STATEMENTS_KEY.into(),
                serde_json::Value::from(imports),
            );
        }
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Python,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0; 32]),
                signature_hash: Hash256::from_bytes([0; 32]),
                behavior_hash: Hash256::from_bytes([0; 32]),
                equivalence_hash: Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new(file)),
            span: None,
            signature: format!("def {name}()"),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata,
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    fn calls(src: EntityId, dst: EntityId) -> Relation {
        Relation {
            id: RelationId::new(),
            kind: RelationKind::Calls,
            src: GraphNodeId::Entity(src),
            dst: GraphNodeId::Entity(dst),
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
            evidence: vec![],
        }
    }

    /// Build a graph whose repository tree admits every named path, so
    /// `artifact_id_at_path` answers and artifact-rooted traversal can run.
    fn graph_with_artifacts(paths: &[&str]) -> (InMemoryGraph, Vec<kin_model::ArtifactId>) {
        let mut artifacts = Vec::new();
        let mut ids = Vec::new();
        for (index, path) in paths.iter().enumerate() {
            let artifact_id = kin_model::ArtifactId::new();
            ids.push(artifact_id);
            artifacts.push(kin_model::ResolvedArtifact::new(
                artifact_id,
                kin_model::RepoPath::from_utf8(*path).expect("repo-relative fixture path"),
                kin_model::TreeEntry::blob(Hash256::from_bytes([index as u8; 32]), false),
            ));
        }
        let mut snapshot = kin_db::GraphSnapshot::empty();
        snapshot.resolved_tree =
            kin_model::ResolvedTree::from_artifacts(artifacts).expect("distinct fixture paths");
        let graph = InMemoryGraph::from_snapshot(snapshot).expect("snapshot loads");
        (graph, ids)
    }

    fn js_entity(name: &str, file: &str, imports: u64, external: u64) -> Entity {
        let mut entity = entity(name, file, Some(1), Some(imports));
        entity.language = LanguageId::JavaScript;
        entity.metadata.extra.insert(
            kin_parser::FILE_PARSED_EXTERNAL_MODULE_IMPORTS_KEY.into(),
            serde_json::Value::from(external),
        );
        entity
    }

    fn artifact_import(src: kin_model::ArtifactId, dst: kin_model::ArtifactId) -> Relation {
        Relation {
            id: RelationId::new(),
            kind: RelationKind::Imports,
            src: GraphNodeId::Artifact(src),
            dst: GraphNodeId::Artifact(dst),
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: Some("./express".to_string()),
            evidence: vec![],
        }
    }

    /// FIR-2440. A resolved `require('./lib/express')` joins two ARTIFACTS,
    /// because a CommonJS module is a file. Counting only entity-rooted edges
    /// reported `imports 0/220 (0%)` for a repository whose relative specifiers
    /// had all resolved, and a reader took that for a broken graph.
    #[test]
    fn a_resolved_module_import_counts_even_though_it_joins_two_artifacts() {
        let (graph, ids) = graph_with_artifacts(&["index.js", "lib/express.js"]);
        graph
            .upsert_entity(&js_entity("createApplication", "lib/express.js", 3, 3))
            .unwrap();
        graph
            .upsert_entity(&js_entity("moduleExports", "index.js", 1, 0))
            .unwrap();
        graph
            .upsert_relation(&artifact_import(ids[0], ids[1]))
            .unwrap();

        let coverage = collect_reference_edge_coverage(&graph).unwrap();
        let js = coverage
            .languages
            .iter()
            .find(|row| row.language == LanguageId::JavaScript.to_string())
            .expect("javascript row");

        assert_eq!(js.parsed_import_statements, Some(4));
        assert_eq!(
            js.resolved_import_edges, 1,
            "the artifact-level import edge is the resolution, and must be counted"
        );
        assert_eq!(js.import_percent(), Some(25));
        assert_eq!(js.external_module_imports, Some(3));
    }

    /// The importing file's language owns the edge. `traverse` walks both
    /// directions from a node, so an edge INTO a file must not be counted a
    /// second time under the imported file's language.
    #[test]
    fn an_artifact_import_edge_is_counted_once_under_the_importer() {
        let (graph, ids) = graph_with_artifacts(&["app.js", "helper.py"]);
        graph
            .upsert_entity(&js_entity("run", "app.js", 1, 0))
            .unwrap();
        // `entity` builds a Python entity, which is the imported side here.
        graph
            .upsert_entity(&entity("helper", "helper.py", Some(0), Some(0)))
            .unwrap();
        graph
            .upsert_relation(&artifact_import(ids[0], ids[1]))
            .unwrap();

        let coverage = collect_reference_edge_coverage(&graph).unwrap();
        let js = coverage
            .languages
            .iter()
            .find(|row| row.language == LanguageId::JavaScript.to_string())
            .expect("javascript row");
        let python = coverage
            .languages
            .iter()
            .find(|row| row.language == LanguageId::Python.to_string())
            .expect("python row");
        assert_eq!(js.resolved_import_edges, 1);
        assert_eq!(
            python.resolved_import_edges, 0,
            "the imported file did not write the import statement"
        );
    }

    /// The rendered line names the external share, so a low ratio reads as a
    /// repository with more dependencies than modules rather than as a defect.
    #[test]
    fn the_summary_line_discloses_imports_that_name_a_module_outside_the_repository() {
        let (graph, ids) = graph_with_artifacts(&["index.js", "lib/express.js"]);
        graph
            .upsert_entity(&js_entity("createApplication", "lib/express.js", 3, 3))
            .unwrap();
        graph
            .upsert_entity(&js_entity("moduleExports", "index.js", 1, 0))
            .unwrap();
        graph
            .upsert_relation(&artifact_import(ids[0], ids[1]))
            .unwrap();

        let coverage = collect_reference_edge_coverage(&graph).unwrap();
        let line = coverage
            .summary_lines()
            .into_iter()
            .find(|line| line.contains("javascript:"))
            .expect("javascript row is rendered");
        assert!(
            line.contains("imports 1/4 (25%), 3 name a module outside this repository"),
            "{line}"
        );
    }

    /// The Python shape, reproduced from the parser's own behaviour: a file
    /// whose call extraction was incomplete removes its call count, and a file
    /// with no calls at all keeps one that reads zero. So the only files
    /// contributing a denominator are the ones that had nothing to count, and
    /// summing them blind published a measured zero against every resolved edge
    /// in the language.
    #[test]
    fn a_parse_side_measured_on_only_some_files_is_never_a_denominator() {
        let graph = InMemoryGraph::new();
        // Call-bearing file: extraction was incomplete, so no call count.
        let caller = entity("resolve", "requests/sessions.py", None, Some(4));
        let callee = entity("send", "requests/adapters.py", None, Some(3));
        // Callless file: nothing to count, so it records a truthful zero.
        let constant = entity(
            "DEFAULT_PORTS",
            "requests/status_codes.py",
            Some(0),
            Some(1),
        );
        for e in [&caller, &callee, &constant] {
            graph.upsert_entity(e).unwrap();
        }
        graph.upsert_relation(&calls(caller.id, callee.id)).unwrap();

        let coverage = collect_reference_edge_coverage(&graph).unwrap();
        let python = coverage
            .languages
            .iter()
            .find(|l| l.language == "python")
            .expect("python row");

        assert_eq!(python.files, 3);
        assert_eq!(python.call_sites_measured_files, 1);
        assert_eq!(python.resolved_call_edges, 1);
        assert_eq!(python.call_site_measurement(), CallSiteMeasurement::Partial);
        assert_eq!(
            python.call_percent(),
            None,
            "a sum over 1 of 3 files is not a percentage of the edges counted over all 3"
        );

        let rendered = coverage.summary_lines().join("\n");
        assert!(
            rendered.contains("parse side measured on 1 of 3 files"),
            "the line must say where its denominator came from: {rendered}"
        );
        assert!(
            !rendered.contains("calls 1/0"),
            "the shape every Python user read must not reappear: {rendered}"
        );
    }

    /// The same rule where the partial sum is not zero, which is the case a
    /// zero denominator cannot stand in for.
    ///
    /// A sum of 5 call sites read from one of three files, against call edges
    /// counted over all three, would divide cleanly and print a percentage
    /// comparing two different populations. That number is worse than the
    /// missing one, because it looks answerable.
    #[test]
    fn a_nonzero_partial_sum_still_publishes_no_percentage() {
        let graph = InMemoryGraph::new();
        let caller = entity("resolve", "requests/sessions.py", None, Some(4));
        let callee = entity("send", "requests/adapters.py", None, Some(3));
        let counted = entity("helper", "requests/utils.py", Some(5), Some(1));
        for e in [&caller, &callee, &counted] {
            graph.upsert_entity(e).unwrap();
        }
        graph.upsert_relation(&calls(caller.id, callee.id)).unwrap();

        let coverage = collect_reference_edge_coverage(&graph).unwrap();
        let python = coverage
            .languages
            .iter()
            .find(|l| l.language == "python")
            .expect("python row");

        assert_eq!(python.parsed_call_sites, Some(5));
        assert_eq!(python.call_sites_measured_files, 1);
        assert_eq!(python.files, 3);
        assert_eq!(python.call_site_measurement(), CallSiteMeasurement::Partial);
        assert_eq!(
            python.call_percent(),
            None,
            "1 resolved edge over 5 sites read from one of three files is not 20% of anything"
        );

        let rendered = coverage.summary_lines().join("\n");
        assert!(
            rendered.contains("parse side measured on 1 of 3 files (5 sites there)"),
            "the partial denominator and its scope must both be named: {rendered}"
        );
        assert!(
            !rendered.contains("calls 1/5"),
            "a ratio between two populations must not be printed: {rendered}"
        );
    }

    /// The founding shape: every resolved call edge is intra-file, the files
    /// import across modules, and no cross-file edge exists, so absence must
    /// not be concluded.
    #[test]
    fn intra_file_only_edges_cannot_support_absence() {
        let graph = InMemoryGraph::new();
        let caller = entity("parse_note", "nk/parsing.py", Some(2), Some(1));
        let callee = entity("extract_tags", "nk/parsing.py", Some(2), Some(1));
        let other = entity("ingest_dir", "nk/storage.py", Some(1), Some(2));
        graph.upsert_entity(&caller).unwrap();
        graph.upsert_entity(&callee).unwrap();
        graph.upsert_entity(&other).unwrap();
        graph.upsert_relation(&calls(caller.id, callee.id)).unwrap();

        let coverage = collect_reference_edge_coverage(&graph).unwrap();
        let python = coverage
            .languages
            .iter()
            .find(|row| row.language == LanguageId::Python.to_string())
            .expect("python row");

        assert_eq!(python.files, 2);
        assert_eq!(python.parsed_import_statements, Some(3));
        assert_eq!(python.resolved_import_edges, 0);
        assert_eq!(python.cross_file_reference_edges, 0);
        assert_eq!(python.intra_file_reference_edges, 1);
        assert!(!coverage.absence_is_supportable());
        let reasons = coverage.unsupportable_absence_reasons();
        assert!(
            reasons
                .iter()
                .any(|reason| reason.contains("no cross-file reference edge")),
            "the reason names the missing cross-file edges: {reasons:?}"
        );
    }

    /// Parsed call sites that resolved to nothing at all: the one state where
    /// the ratio alone is enough to refuse an absence claim.
    #[test]
    fn parsed_calls_resolving_to_no_edges_read_as_none_resolved() {
        let graph = InMemoryGraph::new();
        let only = entity("parse_note", "nk/parsing.py", Some(6), Some(0));
        graph.upsert_entity(&only).unwrap();

        let coverage = collect_reference_edge_coverage(&graph).unwrap();
        let python = &coverage.languages[0];
        assert_eq!(python.resolution, ReferenceResolution::NoneResolved);
        assert_eq!(python.call_percent(), Some(0));
        let reasons = coverage.unsupportable_absence_reasons();
        assert!(
            reasons
                .iter()
                .any(|reason| reason.contains("6 parsed call sites resolved to 0 call edges")),
            "{reasons:?}"
        );
    }

    /// A repository whose cross-file edges resolved can support absence, so the
    /// gate does not fire on a healthy graph.
    #[test]
    fn resolved_cross_file_edges_support_absence() {
        let graph = InMemoryGraph::new();
        let caller = entity("ingest_dir", "nk/storage.py", Some(1), Some(1));
        let callee = entity("parse_note", "nk/parsing.py", Some(1), Some(0));
        graph.upsert_entity(&caller).unwrap();
        graph.upsert_entity(&callee).unwrap();
        graph.upsert_relation(&calls(caller.id, callee.id)).unwrap();

        let coverage = collect_reference_edge_coverage(&graph).unwrap();
        let python = &coverage.languages[0];
        assert_eq!(python.cross_file_reference_edges, 1);
        assert_eq!(python.resolved_call_edges, 1);
        assert_eq!(python.resolution, ReferenceResolution::PartiallyResolved);
        assert!(coverage.absence_is_supportable(), "{python:?}");
    }

    /// A store ingested before the parse side was recorded reads unmeasured,
    /// which is neither zero nor complete, and a multi-file unmeasured language
    /// with no cross-file edge still cannot support absence.
    /// FIR-2370. Two completeness types each wired their own `kin graph status`
    /// section and their own `kin doctor` row, agreeing on every number they
    /// shared. A reader got two sections about one graph and no way to tell
    /// which denominator answered the question they arrived with. One type now
    /// carries both scopes, and the section names them apart rather than
    /// printing two totals a reader must reconcile.
    #[test]
    fn one_section_carries_both_scopes_and_names_which_is_which() {
        let coverage = ReferenceEdgeCoverage {
            parse: None,
            languages: vec![LanguageReferenceCoverage {
                language: "python".to_string(),
                files: 12,
                files_measured: 12,
                entities: 46,
                parsed_call_sites: Some(78),
                call_sites_measured_files: 12,
                parsed_import_statements: Some(16),
                resolved_call_edges: 16,
                resolved_import_edges: 0,
                external_module_imports: None,
                cross_file_reference_edges: 0,
                intra_file_reference_edges: 16,
                external_reference_edges: 0,
                resolution: ReferenceResolution::PartiallyResolved,
                reference_enrichment: ReferenceEnrichment::NoLanguageServer,
            }],
            totals: Some(GraphRelationTotals {
                entity_relations: 17,
                cross_file_entity_relations: 0,
                artifact_import_relations: 3,
            }),
        };

        let rendered = coverage.summary_lines().join("\n");

        assert!(
            rendered.contains("Cross-file entity relations: 0 of 17 across all relation kinds"),
            "the all-kinds scope, labelled as such: {rendered}"
        );
        assert!(
            rendered.contains("no relation in this graph crosses a file boundary"),
            "the shortfall is stated, not left to a ratio: {rendered}"
        );
        assert!(
            rendered.contains("python: 12 files, calls 16/78"),
            "the reference-kind scope, per language: {rendered}"
        );
        assert!(
            rendered.contains(
                "The all-kinds total above is the wider count and is not this \
                               denominator"
            ),
            "and the two are told apart: {rendered}"
        );
        assert!(
            rendered.contains("unavailable for python: no language server found"),
            "the language-server state travels with the same object: {rendered}"
        );
        assert_eq!(
            rendered.matches("Reference edge coverage").count(),
            1,
            "one section, not two: {rendered}"
        );
        assert!(coverage.needs_attention());
    }

    /// A measurement nobody handed totals to reports no cross-file verdict at
    /// all. Unmeasured is not zero, and a surface that rendered a zero here
    /// would claim a graph holds no cross-file edge on the strength of nobody
    /// having counted.
    #[test]
    fn unmeasured_totals_produce_no_cross_file_claim() {
        let coverage = ReferenceEdgeCoverage::default();
        let rendered = coverage.summary_lines().join("\n");

        assert!(!coverage.holds_no_cross_file_edges());
        assert!(
            !rendered.contains("Cross-file entity relations"),
            "{rendered}"
        );
        assert!(
            rendered.contains("no language entities in the graph yet"),
            "{rendered}"
        );
    }

    /// The language-server state is filled from a probe the caller ran, not
    /// guessed here. A language this build wires no adapter for is Unsupported
    /// whatever is installed, which is why gopls on PATH buys Go nothing.
    #[test]
    fn language_server_state_is_attached_rather_than_assumed() {
        let unfilled = ReferenceEdgeCoverage {
            parse: None,
            languages: vec![
                language_row("python", ReferenceEnrichment::Unknown),
                language_row("go", ReferenceEnrichment::Unknown),
            ],
            totals: None,
        };
        assert!(
            unfilled.languages_missing_a_language_server().is_empty(),
            "nothing looked, so nothing was found missing"
        );

        let filled = unfilled
            .clone()
            .with_language_servers(&usable(&[LanguageId::Go]));
        assert_eq!(
            filled.languages_missing_a_language_server(),
            vec!["python"],
            "a wired language with no server is the actionable gap"
        );
        assert_eq!(
            filled.languages[1].reference_enrichment,
            ReferenceEnrichment::Unsupported,
            "gopls on PATH gives Go nothing: no adapter consumes it"
        );

        let complete =
            unfilled.with_language_servers(&usable(&[LanguageId::Python, LanguageId::Rust]));
        assert!(complete.languages_missing_a_language_server().is_empty());
    }

    fn language_row(name: &str, enrichment: ReferenceEnrichment) -> LanguageReferenceCoverage {
        LanguageReferenceCoverage {
            language: name.to_string(),
            files: 2,
            files_measured: 2,
            entities: 4,
            parsed_call_sites: Some(4),
            call_sites_measured_files: 2,
            parsed_import_statements: Some(2),
            resolved_call_edges: 4,
            resolved_import_edges: 2,
            external_module_imports: None,
            cross_file_reference_edges: 2,
            intra_file_reference_edges: 2,
            external_reference_edges: 0,
            resolution: ReferenceResolution::FullyResolved,
            reference_enrichment: enrichment,
        }
    }

    #[test]
    fn a_store_without_parse_counts_reads_unmeasured() {
        let graph = InMemoryGraph::new();
        let first = entity("alpha", "pkg/a.py", None, None);
        let second = entity("beta", "pkg/b.py", None, None);
        graph.upsert_entity(&first).unwrap();
        graph.upsert_entity(&second).unwrap();

        let coverage = collect_reference_edge_coverage(&graph).unwrap();
        let python = &coverage.languages[0];
        assert_eq!(python.resolution, ReferenceResolution::Unmeasured);
        assert_eq!(python.parsed_call_sites, None);
        assert_eq!(python.files_measured, 0);
        assert!(!coverage.absence_is_supportable());
    }

    /// The header names the order the rows actually print.
    ///
    /// The shipped header read `(parsed -> resolved)` while `language_summary`
    /// printed resolved first, so a reader handed `calls 238/0, imports 0/40
    /// (0%)` saw two fields in what looked like opposite orders and had no way
    /// to tell which number was which. Pinning the header against a row whose
    /// two numbers differ is what stops the label and the rows drifting apart
    /// again.
    #[test]
    fn the_header_names_the_order_the_rows_print() {
        let mut row = language_row("python", ReferenceEnrichment::Available);
        row.parsed_call_sites = Some(10);
        row.resolved_call_edges = 3;
        row.parsed_import_statements = Some(8);
        row.resolved_import_edges = 2;
        let coverage = ReferenceEdgeCoverage {
            parse: None,
            languages: vec![row],
            totals: None,
        };
        let rendered = coverage.summary_lines().join("\n");

        assert!(
            rendered.contains("calls 3/10 (30%)"),
            "a row prints resolved over parsed: {rendered}"
        );
        assert!(
            rendered.contains("imports 2/8 (25%)"),
            "and both halves print the same way round: {rendered}"
        );

        let header = rendered
            .lines()
            .find(|line| line.starts_with("Reference edge coverage"))
            .expect("the section header");
        let resolved_at = header
            .find("resolved")
            .expect("the header names the resolved side");
        let parsed_at = header
            .find("parsed")
            .expect("the header names the parsed side");
        assert!(
            resolved_at < parsed_at,
            "the header must name the numerator first, as every row prints it: {header}"
        );
    }

    /// A parse side that counted nothing is not a ratio and not a verdict.
    ///
    /// A stranger's run printed `calls 238/0` and labelled the row `[resolved]`
    /// under a no-issues banner: call edges in the graph against a parse side
    /// reporting zero call sites, divided by nothing and then read as complete
    /// resolution. Zero parsed sites is the absence of a denominator, so the
    /// row says so in words and classifies as unmeasured.
    #[test]
    fn a_zero_parse_side_is_neither_a_ratio_nor_a_resolved_verdict() {
        let graph = InMemoryGraph::new();
        let caller = entity("main", "pkg/a.py", Some(0), Some(0));
        let callee = entity("helper", "pkg/b.py", Some(0), Some(0));
        graph.upsert_entity(&caller).unwrap();
        graph.upsert_entity(&callee).unwrap();
        graph.upsert_relation(&calls(caller.id, callee.id)).unwrap();

        let coverage = collect_reference_edge_coverage(&graph).unwrap();
        let python = &coverage.languages[0];
        assert_eq!(python.parsed_call_sites, Some(0));
        assert_eq!(python.resolved_call_edges, 1);
        assert_eq!(
            python.resolution,
            ReferenceResolution::Unmeasured,
            "a zero denominator is not evidence that every parsed site resolved"
        );

        let rendered = coverage.summary_lines().join("\n");
        assert!(
            rendered.contains("calls 1 resolved, parse side counted no call sites"),
            "the count is stated rather than divided by nothing: {rendered}"
        );
        assert!(
            !rendered.contains("calls 1/0"),
            "and no fraction over a zero denominator survives: {rendered}"
        );
    }

    /// One file cannot have a cross-file edge, so a single-file language is not
    /// gated for lacking one.
    #[test]
    fn a_single_file_language_is_not_gated_for_lacking_cross_file_edges() {
        let graph = InMemoryGraph::new();
        let caller = entity("main", "solo.py", Some(1), Some(0));
        let callee = entity("helper", "solo.py", Some(1), Some(0));
        graph.upsert_entity(&caller).unwrap();
        graph.upsert_entity(&callee).unwrap();
        graph.upsert_relation(&calls(caller.id, callee.id)).unwrap();

        let coverage = collect_reference_edge_coverage(&graph).unwrap();
        assert!(coverage.absence_is_supportable());
    }

    /// A repository tree admitting exactly these paths as blobs.
    fn tree_of(paths: &[&str]) -> kin_model::ResolvedTree {
        kin_model::ResolvedTree::from_artifacts(paths.iter().map(|path| {
            kin_model::ResolvedArtifact::new(
                kin_model::ArtifactId::new(),
                kin_model::RepoPath::from_utf8(*path).expect("utf8 path"),
                kin_model::TreeEntry::blob(Hash256::from_bytes([0u8; 32]), false),
            )
        }))
        .expect("build tree")
    }

    /// One row, built by hand, so the threshold rule is testable without a
    /// store. `sample` carries the paths a surface names.
    fn parse_row(language: &str, tracked: usize, unparsed: usize) -> LanguageParseCoverage {
        LanguageParseCoverage {
            language: language.to_string(),
            tracked,
            with_entities: tracked.saturating_sub(unparsed),
            unparsed,
            sample: (0..unparsed.min(PARSE_HOLE_SAMPLE))
                .map(|index| format!("lib/file{index}.js"))
                .collect(),
        }
    }

    /// The two readings the threshold exists to separate, and they are the two
    /// the ticket names. The express shape is a language most of whose admitted
    /// files never reached an adapter; the passing shape is a repository
    /// carrying one script no adapter claims. A rule that cannot tell them
    /// apart is either a page nobody reads or a page that never fires.
    #[test]
    fn the_express_shape_trips_the_threshold_and_a_stray_script_does_not() {
        // express as the run measured it: 141 admitted files, 75 of them with
        // no entity, `lib/express.js` among them.
        let express = parse_row("javascript", 141, 75);
        assert!(
            express.is_materially_incomplete(),
            "the shape this ticket was filed about must withhold the all-clear: {express:?}"
        );

        // One stray script, on a repository of any size. This is the case the
        // ticket says must stay quiet, and it stays quiet on the count alone,
        // so no repository is small enough to make one file trip it.
        for tracked in [1, 8, 141, 5000] {
            let stray = parse_row("javascript", tracked, 1);
            assert!(
                !stray.is_materially_incomplete(),
                "one unparsed file out of {tracked} is not a hole a page should shout about"
            );
        }
    }

    /// The two conditions are independent, and each is the only thing standing
    /// between a real store and a wrong verdict. Without the count, a small
    /// repository's two stray scripts read as a 20% hole; without the share, a
    /// large repository's three stray scripts out of five thousand read as one.
    #[test]
    fn each_half_of_the_threshold_is_load_bearing_on_its_own() {
        // Share satisfied, count not: 2 of 8 is 25% and is still two files.
        let small = parse_row("javascript", 8, 2);
        assert_eq!(small.parsed_percent(), Some(75));
        assert!(
            !small.is_materially_incomplete(),
            "the file floor is what keeps a small repository's strays quiet"
        );

        // Count satisfied, share not: 3 of 5000 is three files.
        let large = parse_row("javascript", 5_000, 3);
        assert!(
            !large.is_materially_incomplete(),
            "the share is what keeps a large repository's strays quiet"
        );

        // Both satisfied at the exact boundary: 3 of 30 is 10% and three files.
        let boundary = parse_row("javascript", 30, 3);
        assert_eq!(boundary.parsed_percent(), Some(90));
        assert!(
            boundary.is_materially_incomplete(),
            "the rule is at-or-above the share, not above it"
        );
    }

    /// A census with a hole must name it, and a census without one must not
    /// invent a warning. The sentence carries the count, the denominator and
    /// the paths, because a warning a reader cannot check is a warning they
    /// learn to skip.
    #[test]
    fn the_warning_names_the_count_the_denominator_and_the_files() {
        let clean = ParseCoverageCensus {
            languages: vec![parse_row("rust", 200, 0)],
        };
        assert!(
            clean.warning_lines().is_empty(),
            "a fully parsed store gets no warning"
        );
        assert!(
            !clean.holds_a_parse_hole(),
            "a fully parsed store holds no hole"
        );
        assert!(
            clean.hole_reasons().is_empty(),
            "a fully parsed store refuses nothing"
        );

        let holed = ParseCoverageCensus {
            languages: vec![parse_row("javascript", 141, 75)],
        };
        let warnings = holed.warning_lines();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        let warning = &warnings[0];
        for expected in ["javascript", "75", "141", "lib/file0.js"] {
            assert!(
                warning.contains(expected),
                "the warning must carry {expected}: {warning}"
            );
        }
    }

    /// The refusal reads the hole itself and never the threshold. A store one
    /// file under the shouting line still cannot certify an absence over that
    /// file, because the question an answer asks is whether the scope it was
    /// computed over was whole.
    #[test]
    fn a_hole_too_small_to_warn_still_refuses_an_absence() {
        let census = ParseCoverageCensus {
            languages: vec![parse_row("javascript", 5_000, 1)],
        };
        assert!(
            census.warning_lines().is_empty(),
            "one file of five thousand is under the shouting line"
        );
        assert!(
            census.holds_a_parse_hole(),
            "it is still a hole, and an answer over it is still uncertified"
        );
        let reasons = census.hole_reasons();
        assert_eq!(reasons.len(), 1, "{reasons:?}");
        assert!(
            reasons[0].starts_with(PARSE_HOLE_LIMITING_FACTOR),
            "the tag is what a caller keys on: {}",
            reasons[0]
        );
        assert!(
            reasons[0].contains("lib/file0.js"),
            "the refusal names the file it is about: {}",
            reasons[0]
        );
    }

    /// The census counts the repository tree against the entity table, and that
    /// is the whole reason it exists: every other counter here starts from an
    /// entity, so a file that produced none is invisible to it, and that is
    /// exactly what a parse hole is. The fixture is the express shape in
    /// miniature, with the library files silent and the root file producing.
    #[test]
    fn the_census_counts_admitted_files_that_produced_no_entity() {
        let tree = tree_of(&[
            "lib/express.js",
            "lib/application.js",
            "lib/router/index.js",
            "index.js",
            "README.md",
        ]);
        let produced = [
            entity("createApplication", "index.js", None, None),
            entity("handle", "lib/router/index.js", None, None),
        ];

        let census = collect_parse_coverage_from(&tree, &produced);
        assert_eq!(census.languages.len(), 1, "{census:?}");
        let row = &census.languages[0];
        assert_eq!(row.language, "javascript");
        assert_eq!(row.tracked, 4, "README.md is not a full-adapter input");
        assert_eq!(row.with_entities, 2);
        assert_eq!(row.unparsed, 2);
        assert_eq!(
            row.sample,
            vec![
                "lib/application.js".to_string(),
                "lib/express.js".to_string()
            ],
            "shallowest first, then alphabetical"
        );
        assert_eq!(row.parsed_percent(), Some(50));
    }

    /// A file the tree does not admit cannot be a hole in it, and a file the
    /// tree admits that no adapter is registered for is not one either. Both
    /// halves keep the denominator honest: without the first a stale entity
    /// would inflate coverage, and without the second every Markdown file in a
    /// repository would read as an unparsed one.
    #[test]
    fn only_admitted_files_a_full_adapter_claims_are_counted() {
        let tree = tree_of(&["lib/express.js", "README.md", "Makefile"]);
        // An entity whose file the tree no longer admits.
        let stale = [entity("gone", "lib/removed.js", None, None)];
        let census = collect_parse_coverage_from(&tree, &stale);
        let row = &census.languages[0];
        assert_eq!(
            row.tracked, 1,
            "only lib/express.js is a full-adapter input: {census:?}"
        );
        assert_eq!(
            row.with_entities, 0,
            "an entity on an unadmitted path credits nothing"
        );
        assert_eq!(row.unparsed, 1);
    }

    /// Ordering is a claim the store can back, and "biggest" is not one: the
    /// repository tree records a blob hash per path and no size. A library root
    /// must outrank a deep fixture, and the same store must always name the
    /// same files in the same order.
    #[test]
    fn the_named_files_are_ordered_by_path_depth_and_never_by_a_size_nobody_recorded() {
        let tree = tree_of(&[
            "test/fixtures/blog/deep/a.js",
            "lib/express.js",
            "test/exports.js",
            "lib/application.js",
        ]);
        let census = collect_parse_coverage_from(&tree, &[]);
        let row = &census.languages[0];
        assert_eq!(
            row.sample,
            vec![
                "lib/application.js".to_string(),
                "lib/express.js".to_string(),
                "test/exports.js".to_string(),
                "test/fixtures/blog/deep/a.js".to_string(),
            ],
            "a library root outranks a deep fixture"
        );
    }

    /// A store the extractor read completely must not grow a section that reads
    /// like a complaint, and a store nobody measured must not read like one
    /// that was measured and found clean.
    #[test]
    fn an_unmeasured_census_is_not_an_all_clear() {
        let unmeasured = ReferenceEdgeCoverage::default();
        assert!(
            unmeasured.parse.is_none(),
            "nobody counted, so there is nothing to render"
        );
        assert!(
            unmeasured.parse_warning_lines().is_empty(),
            "an unmeasured census has not shown a hole"
        );
        assert!(
            !unmeasured
                .summary_lines()
                .iter()
                .any(|line| line.contains("Parse coverage")),
            "an unmeasured census prints no parse section at all"
        );

        let measured = ReferenceEdgeCoverage::default().with_parse_coverage(ParseCoverageCensus {
            languages: vec![parse_row("rust", 200, 0)],
        });
        assert!(
            measured
                .summary_lines()
                .iter()
                .any(|line| line.contains("rust: 200/200")),
            "a measured and clean census still prints its section: {:?}",
            measured.summary_lines()
        );
    }
}
