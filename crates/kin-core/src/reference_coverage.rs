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
    LanguageId::Go,
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
    /// Import STATEMENTS the linker resolved to a file this repository holds.
    ///
    /// Read from each file's coverage certificate, which is the only place the
    /// number exists. It is deliberately NOT counted from edges: one resolved
    /// import produces an artifact edge and, where the importer carries a module
    /// entity, an entity edge beside it, so counting edges scores one import
    /// twice and drives the ratio past its own denominator. Worse, the unit is
    /// wrong in the other direction too, because `from storage import Store,
    /// open_db` and the same two names on separate lines produce identical
    /// edges while being one statement and two.
    ///
    /// `None` when no file of this language carried a certificate, which means
    /// the resolved count is UNMEASURED rather than zero.
    pub resolved_import_statements: Option<u64>,
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
        percent(
            self.parsed_import_statements,
            self.resolved_import_statements?,
        )
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

    /// The missing-language-server condition as a WARNING, carrying the count
    /// of files it affects.
    ///
    /// The same condition already appears as an indented detail under the
    /// coverage section, where a reader looking for whether the graph is
    /// trustworthy does not find it. Measured on a five-file Python corpus with
    /// and without pyright, one arm each: entity-to-entity relations 13 against
    /// 29, and `UsesType` absent entirely from the arm with no server while
    /// carrying 11 edges in the arm with one. Entities were identical at 12, so
    /// what a missing server costs is relations, not what the graph knows
    /// exists, and a clean-looking status over that is a false all-clear.
    ///
    /// The count is what IS AFFECTED, never an estimate of what is missing.
    /// Kin cannot know how many edges a server would have produced without
    /// running one, and a warning that guessed would be wrong by an unknown
    /// amount on any repository unlike the one measured. `files` is a number the
    /// graph already holds.
    pub fn missing_language_server_warning(&self) -> Option<String> {
        let missing: Vec<&LanguageReferenceCoverage> = self
            .languages
            .iter()
            .filter(|language| language.reference_enrichment.is_actionable_gap())
            .collect();
        if missing.is_empty() {
            return None;
        }
        let named: Vec<String> = missing
            .iter()
            .map(|language| {
                format!(
                    "{} ({} file{})",
                    language.language,
                    language.files,
                    if language.files == 1 { "" } else { "s" }
                )
            })
            .collect();
        Some(format!(
            "no language server for {}; cross-file reference and override edges are absent for \
             those files, so this graph is incomplete rather than clean",
            named.join(", ")
        ))
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
    let imports = match (
        coverage.parsed_import_statements,
        coverage.resolved_import_statements,
        coverage.import_percent(),
    ) {
        (Some(parsed), Some(resolved), Some(percent)) => {
            format!("imports {resolved}/{parsed} ({percent}%){external}")
        }
        // A parse side that read no import statements has no denominator, so
        // stating a fraction would be a ratio against nothing.
        (Some(_), Some(resolved), None) => {
            format!(
                "imports {resolved} resolved, parse side counted no import statements{external}"
            )
        }
        (None, Some(resolved), _) => {
            format!("imports {resolved} resolved, parse side unmeasured{external}")
        }
        // No file of this language carried a coverage certificate, so how many
        // of its imports resolved was never measured. Printing a count here
        // would report an absence as a zero, which is the whole failure this
        // surface exists to avoid.
        //
        // The external share still prints. It is measured on its own path, off
        // specifier syntax for JavaScript and off the certificate elsewhere, so
        // an unmeasured RESOLUTION says nothing about it. Dropping it here cost
        // a JavaScript repository the one line that explains why its import
        // ratio is low, which is the disclosure this surface exists for.
        (Some(parsed), None, _) => {
            format!("imports resolution unmeasured, parse side read {parsed} statements{external}")
        }
        (None, None, _) => format!("imports unmeasured{external}"),
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
    /// Import STATEMENTS the linker resolved to a file this repository holds,
    /// summed from each file's coverage certificate.
    ///
    /// The certificate is the only place this number exists. It cannot be
    /// recovered from edges: `from storage import Store, open_db` and the same
    /// two names on separate lines produce byte-identical graph content while
    /// differing in statement count, so an edge-derived numerator states a ratio
    /// against a denominator drawn from a different population.
    certified_resolved_statements: u64,
    /// Statements the certificates accounted for. Carried beside the parser's
    /// own count so a disagreement between the two is visible rather than
    /// absorbed into a ratio.
    certified_statements: u64,
    /// Files of this language whose certificate was found. Zero means the
    /// resolved count is UNMEASURED for this language, not that it is zero.
    certified_files: usize,
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
            // Imports are deliberately absent here. One resolved import can
            // produce an edge at BOTH levels, so counting them scores a single
            // import twice, and the edge unit cannot express statements anyway.
            // The count comes from each file's coverage certificate below.
            if relation.kind == RelationKind::Calls {
                tally.resolved_call_edges += 1;
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

    // The artifact pass that used to sit here counted artifact-rooted import
    // edges, because the entity walk above could not see them. Both are gone
    // from the import count now: an edge count cannot express STATEMENTS, which
    // is the unit the denominator is in, and once the entity pass began
    // producing import edges the two passes scored the same import twice. The
    // certificate below carries the number the linker actually knows.

    // Read each file's coverage certificate for the counts only the linker could
    // produce. The certificate is an artifact self-loop of kind `DependsOn`, so
    // it is invisible to both passes above, which is exactly why it can carry a
    // STATEMENT count without disturbing an EDGE count.
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
            let neighborhood = store.traverse(&node, &[RelationKind::DependsOn], 1)?;
            for relation in neighborhood.relations {
                if relation.src != node {
                    continue;
                }
                for evidence in &relation.evidence {
                    if evidence.parser_rule.as_deref()
                        != Some(kin_index::IMPORT_RESOLUTION_COVERAGE_V1)
                    {
                        continue;
                    }
                    // A certificate whose resolved count cannot be read says
                    // nothing; it does not say zero.
                    let Some(resolved) = evidence
                        .token
                        .as_deref()
                        .and_then(|raw| raw.parse::<u64>().ok())
                    else {
                        continue;
                    };
                    tally.certified_statements += u64::from(evidence.occurrence_count);
                    tally.certified_resolved_statements += resolved;
                    tally.certified_files += 1;
                }
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
                resolved_import_statements: (tally.certified_files > 0)
                    .then_some(tally.certified_resolved_statements),
                // JavaScript and TypeScript settle externality from specifier
                // syntax at parse time. Every other language cannot, so its
                // external count comes from the certificate instead: a statement
                // that reached no file this repository holds names something
                // outside it, which is strictly better evidence than a
                // syntactic bare-specifier proxy. Absent when neither source
                // measured it, so a reader sees unmeasured rather than zero.
                external_module_imports: if tally.external_module_import_files > 0 {
                    Some(tally.external_module_imports)
                } else if tally.certified_files > 0 {
                    Some(
                        tally
                            .certified_statements
                            .saturating_sub(tally.certified_resolved_statements),
                    )
                } else {
                    None
                },
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
        // Fully resolved is the claim that every parsed call site became an
        // edge, and only an exact match says that. MORE edges than sites is not
        // a stronger result, it is fan-out: one ambiguous call site binds
        // several same-named targets under the linker's fanout cap, so the
        // numerator counts edges the denominator never counted sites for and
        // the ratio stops being coverage. Reading that as `[resolved]` is the
        // same wrong word the zero-denominator case above produced, arrived at
        // from the other side, and it became reachable for Python the moment
        // the parse side started being measured at all.
        Some(parsed) if resolved_call_edges == parsed => ReferenceResolution::FullyResolved,
        Some(_) => ReferenceResolution::PartiallyResolved,
    }
}

fn read_count(entity: &Entity, key: &str) -> Option<u64> {
    entity
        .metadata
        .extra
        .get(key)
        .and_then(|value| value.as_u64())
}

/// Silent paths named on a status line before it stops being readable.
const PARSE_HOLE_SAMPLE: usize = 5;

/// The tag every sentence about a file that produced nothing opens with, for a
/// caller keying on the class rather than reading the prose.
///
/// `no_entity` rather than `parse_hole`, because this census cannot establish
/// that a parse failed. It can establish that a file the tree admits produced
/// nothing, which is what the word says.
pub const NO_ENTITY_OBSERVATION: &str = "no_entity";

/// The heading the parse-coverage section prints, in one place because two
/// surfaces and an acceptance grader all key on it.
///
/// The numerator says "whose current bytes produced an entity" rather than
/// "that produced an entity", and the two extra words are the whole point. A
/// file whose syntax broke keeps the entities its last good parse produced, so
/// under the old wording it was counted as parsed and a store answering about it
/// at positions its bytes no longer hold printed 100%.
pub const PARSE_COVERAGE_HEADING: &str =
    "Parse coverage (files whose current bytes produced an entity / files admitted):";

/// How many of one language's admitted files reached the entity table.
///
/// The denominator is the repository tree's own admitted file set, not the set
/// of files that produced an entity. Every other counter in this module starts
/// from an entity and therefore cannot see a file that produced none, which is
/// the population the express run counted when it reported 75 of 141.
///
/// This type carries no verdict, and the reason is measured rather than
/// cautious. A file that produced no entity is not necessarily one the
/// extractor failed on: a side-effect script, a re-export and a comment-only
/// file each correctly produce nothing. On a five-file JavaScript repository
/// holding one real module beside one of each, this reads 1/5, a LOWER ratio
/// than the express checkout the census was built for. Nothing in graph-owned
/// state separates the two readings today, so the count is published with the
/// paths beside it and the reading is left to someone who can open them.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LanguageParseCoverage {
    pub language: String,
    /// Files of this language the repository tree admits and a full adapter is
    /// registered for.
    pub tracked: usize,
    /// Of those, how many produced at least one entity.
    pub with_entities: usize,
    /// Of those, how many produced none.
    pub silent: usize,
    /// Of those, how many did not parse from their CURRENT bytes, so the
    /// entities the graph holds for them came from an earlier parse.
    ///
    /// Its own bucket rather than folded into either counter beside it, because
    /// it is neither. Counting a retained file under `with_entities` is the
    /// defect this field closes: a file whose syntax broke kept the entities its
    /// last good parse produced, so it read exactly like one Kin parses
    /// correctly, and a store answering about it at positions its bytes no
    /// longer hold printed 100%. Counting it under `silent` would be the
    /// opposite lie, because the file is not silent at all; the graph is
    /// answering about it, from bytes that are gone.
    ///
    /// `with_entities + silent + retained == tracked`.
    #[serde(default)]
    pub retained: usize,
    /// Silent paths, shallowest first, then alphabetical.
    ///
    /// Shallowest rather than largest, and the ordering is named on the line
    /// that prints it. The repository tree records a blob hash per path and no
    /// size, so a "biggest files" ranking would be the one part of this report
    /// a reader could not check against the store.
    pub sample: Vec<String>,
    /// Retained paths with the parse-error count the reconciler reported for
    /// each, under the same ordering rule as `sample`.
    ///
    /// The count is carried rather than recomputed. The same missing bracket
    /// produced three errors in one measured file and four in another, so no
    /// surface may assert a number of its own.
    #[serde(default)]
    pub retained_sample: Vec<String>,
}

impl LanguageParseCoverage {
    /// Percent of this language's admitted files that produced an entity.
    pub fn entity_percent(&self) -> Option<usize> {
        (self.tracked > 0).then(|| self.with_entities.saturating_mul(100) / self.tracked)
    }

    /// The one sentence a surface prints naming this language's silent files.
    pub fn silent_sentence(&self) -> String {
        let named = if self.sample.is_empty() {
            String::new()
        } else {
            format!(
                ", including {} (shallowest paths first)",
                self.sample.join(", ")
            )
        };
        format!(
            "{NO_ENTITY_OBSERVATION}: {} of {} admitted {} files produced no entity{named}",
            self.silent, self.tracked, self.language
        )
    }

    /// The one sentence a surface prints naming this language's retained files.
    ///
    /// Unlike [`Self::silent_sentence`] this one names a next step, because
    /// unlike a silent file a retained one is unambiguously a gap: its bytes are
    /// on disk, they do not parse, and every answer over it describes bytes that
    /// are gone. A side-effect script that declares nothing is correct; a file
    /// whose syntax is broken is not a second correct case.
    pub fn retained_sentence(&self) -> String {
        let named = if self.retained_sample.is_empty() {
            String::new()
        } else {
            format!(
                ", including {} (shallowest paths first)",
                self.retained_sample.join(", ")
            )
        };
        format!(
            "{}: {} of {} admitted {} files did not parse from their current bytes, so the \
             entities the graph holds for them came from an earlier parse and every span, \
             reference and enumeration over them describes bytes that are gone{named}. Fix the \
             syntax and the next admission re-derives them.",
            crate::retained_parse::RETAINED_OBSERVATION,
            self.retained,
            self.tracked,
            self.language
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
    /// One sentence per language holding a file that produced no entity.
    ///
    /// Disclosure, never a verdict. A caller rendering these must not treat a
    /// non-empty result as a defect it has established.
    pub fn silent_file_lines(&self) -> Vec<String> {
        self.languages
            .iter()
            .filter(|language| language.silent > 0)
            .map(LanguageParseCoverage::silent_sentence)
            .collect()
    }

    /// One sentence per language holding a file the graph is answering about
    /// from an earlier parse.
    ///
    /// A verdict, unlike the disclosure beside it, and a caller rendering these
    /// may treat a non-empty result as a gap it has established.
    pub fn retained_file_lines(&self) -> Vec<String> {
        self.languages
            .iter()
            .filter(|language| language.retained > 0)
            .map(LanguageParseCoverage::retained_sentence)
            .collect()
    }

    /// Every retained path across every language, for a caller that needs the
    /// set rather than the prose.
    pub fn retained_paths(&self) -> Vec<&str> {
        self.languages
            .iter()
            .flat_map(|language| language.retained_sample.iter().map(String::as_str))
            .collect()
    }

    /// Whether any language holds a file retained from an earlier parse.
    pub fn any_retained(&self) -> bool {
        self.languages.iter().any(|language| language.retained > 0)
    }

    /// Terminal rendering, one line per language that admits a file.
    ///
    /// Rendered in every state, including the whole-clean one. A section that
    /// fell silent when every file produced an entity would be
    /// indistinguishable from a build that never measured it.
    pub fn summary_lines(&self) -> Vec<String> {
        if self.languages.is_empty() {
            return vec![
                "Parse coverage: the repository tree admits no file a full adapter parses"
                    .to_string(),
            ];
        }
        let mut lines = vec![PARSE_COVERAGE_HEADING.to_string()];
        for language in &self.languages {
            let percent = language
                .entity_percent()
                .map(|percent| format!(" ({percent}%)"))
                .unwrap_or_default();
            lines.push(format!(
                "  {}: {}/{}{percent}",
                language.language, language.with_entities, language.tracked
            ));
        }
        for line in self.silent_file_lines() {
            lines.push(format!("  {line}"));
        }
        // Printed after the silent lines and before the disclaimer, because it
        // is the one row on this section a reader should act on rather than
        // investigate. The disclaimer below is about silent files and says so.
        for line in self.retained_file_lines() {
            lines.push(format!("  {line}"));
        }
        lines.push(
            "  A file that produced no entity is absent from every enumeration, caller count and \
             dead-code answer over it rather than reported as a gap in one. It is NOT on its own \
             evidence that anything failed: a side-effect script, a re-export and a comment-only \
             file each correctly produce nothing, and no graph-owned signal separates those from \
             a file an adapter could not read. Open the named paths to tell them apart. A file \
             named on a retained line above is the one case that IS established: its bytes are on \
             disk, they do not parse, and the numerator excludes it because the entities the graph \
             still holds for it came from bytes it no longer has."
                .to_string(),
        );
        lines
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
    retained: &crate::retained_parse::RetainedParseRead,
) -> Result<ParseCoverageCensus, kin_db::KinDbError> {
    let resolved_tree = graph.resolved_tree();
    let entities = graph.list_all_entities()?;
    Ok(collect_parse_coverage_from(
        &resolved_tree,
        &entities,
        retained,
    ))
}

/// The census rule with both graph readings as inputs, so every branch is
/// testable without a store.
///
/// The two readings are not fenced against each other, and the caller decides
/// the order. Reading the tree FIRST is the safe order: a file admitted between
/// the two reads is then absent from the tree and present in the entity list,
/// which under-reports silence. The reverse order puts it in the tree and not
/// in the entity list, which invents a silent file that parsed fine.
/// `collect_parse_coverage` below takes them in the safe order.
/// `graph_health` takes its entity listing from the response renderer before it
/// clones the tree, so it takes them in the other one.
///
/// That is recorded rather than fixed because the cost of being wrong here is
/// now one transient row in a disclosure, and it was a refusal only while this
/// module carried a verdict. Fixing it properly means fencing both reads behind
/// one epoch the way `mcp_graph_status_with_stable_authority` does, which is a
/// change to the report's whole read discipline rather than to this function.
///
/// `retained` is the daemon's durable record of the paths whose CURRENT bytes did
/// not parse. It is a third input rather than something this function could
/// derive, and that is structural: the reconciler is the only thing that ever
/// attempts the parse, the graph deliberately keeps the last good reading, and
/// nothing left in graph-owned state afterwards distinguishes a file Kin read
/// correctly from one it read a week ago. `Absent` and `Unreadable` both count
/// nothing as retained, which is exactly the behaviour this section had before
/// the record existed; the unreadable case is not thereby silent, because the
/// surfaces render it as its own line from
/// [`crate::retained_parse::RetainedParseRead::describe`].
pub fn collect_parse_coverage_from(
    resolved_tree: &kin_model::ResolvedTree,
    entities: &[Entity],
    retained: &crate::retained_parse::RetainedParseRead,
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
        // `.h` is left out rather than guessed at. Ingest resolves the C/C++
        // collision by reading the file (`get_by_extension_and_content`), and
        // this census reads no file, so the only answer available here is the
        // one the extension gives: C. Counting a C++ project's headers under a
        // `c` row would name a language the repository does not hold, one line
        // above a reference-edge section keying on the entity's own language
        // that shows `cpp` and no `c` row at all. Worse, adding real C files
        // would dilute the same header shortfall out of the report. A number
        // that cannot be attributed is left out rather than attributed wrongly.
        if extension == "h" {
            continue;
        }
        let Some(adapter) = registry.get_by_extension(extension) else {
            continue;
        };
        let tally = tallies
            .entry(adapter.language_id().to_string())
            .or_default();
        tally.tracked += 1;
        // Retained is tested FIRST, and the order is the fix rather than a
        // preference. A retained file is in `producing` by construction, because
        // the entities its last good parse produced are still in the table, so
        // testing `producing` first would count it as parsed and this whole
        // third bucket would never receive anything.
        if let Some(errors) = retained.errors_for(path) {
            tally.retained += 1;
            tally
                .retained_paths
                .push(format!("{path} ({errors} parse errors)"));
        } else if producing.contains(path) {
            tally.with_entities += 1;
        } else {
            tally.silent += 1;
            tally.silent_paths.push(path.to_string());
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
    silent: usize,
    retained: usize,
    silent_paths: Vec<String>,
    retained_paths: Vec<String>,
}

impl ParseTally {
    fn into_row(mut self, language: String) -> LanguageParseCoverage {
        // Shallowest first, then alphabetical, so the ordering is total and the
        // same store always names the same files. `lib/express.js` sorts above
        // `test/fixtures/blog/index.js` because a library root is what a reader
        // asking "what did Kin miss" means by the biggest one.
        let shallowest_first = |left: &String, right: &String| {
            let depth = |path: &String| path.matches('/').count();
            depth(left).cmp(&depth(right)).then_with(|| left.cmp(right))
        };
        self.silent_paths.sort_by(shallowest_first);
        self.silent_paths.truncate(PARSE_HOLE_SAMPLE);
        self.retained_paths.sort_by(shallowest_first);
        self.retained_paths.truncate(PARSE_HOLE_SAMPLE);
        LanguageParseCoverage {
            language,
            tracked: self.tracked,
            with_entities: self.with_entities,
            silent: self.silent,
            retained: self.retained,
            sample: self.silent_paths,
            retained_sample: self.retained_paths,
        }
    }
}

/// The tag every parse-hole sentence opens with, for a surface with room for
/// a label but not a sentence, and for a caller keying on the class rather
/// than reading the prose.
pub const PARSE_HOLE_LIMITING_FACTOR: &str = "parse_hole";

#[cfg(test)]
mod tests {
    use crate::retained_parse::{ObservedParse, RetainedParseRead};

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
    use kin_model::relation::RelationEvidence;
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

    /// A file's coverage certificate, in the shape the linker emits.
    ///
    /// An artifact self-loop of kind `DependsOn` whose evidence carries the
    /// import counts: `occurrence_count` the statements the parser read, `token`
    /// how many of them resolved to a file this repository holds. This is the
    /// only channel those numbers travel on, because they cannot be recovered
    /// from edges, so a fixture that omits it is a fixture where import
    /// resolution is genuinely unmeasured.
    fn import_certificate(
        artifact_id: kin_model::ArtifactId,
        path: &str,
        statements: u32,
        resolved: u64,
    ) -> Relation {
        let node = GraphNodeId::Artifact(artifact_id);
        Relation {
            id: RelationId::new(),
            kind: RelationKind::DependsOn,
            src: node,
            dst: node,
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
            evidence: vec![RelationEvidence {
                token: Some(resolved.to_string()),
                source_path: Some(path.to_string()),
                parser_rule: Some(kin_index::IMPORT_RESOLUTION_COVERAGE_V1.to_string()),
                occurrence_count: statements,
                ..RelationEvidence::default()
            }],
        }
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
    fn an_artifact_import_edge_is_not_a_resolved_statement_count() {
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
            js.resolved_import_statements, None,
            "this graph holds an artifact import edge and no coverage certificate. \
             An edge is not a statement count: one statement naming two symbols and \
             two statements naming one each produce byte-identical graph content, so \
             deriving the numerator from edges states a ratio against a denominator \
             drawn from a different population. Unmeasured is the honest reading"
        );
        assert_eq!(
            js.import_percent(),
            None,
            "and no percentage can be stated without a numerator"
        );
        assert_eq!(
            js.external_module_imports,
            Some(3),
            "the external share is measured off specifier syntax, so it survives an \
             unmeasured resolution"
        );
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
        assert_eq!(
            js.parsed_import_statements,
            Some(1),
            "the importing file's language owns the statement"
        );
        assert_eq!(
            python.parsed_import_statements,
            Some(0),
            "and `traverse` walks both directions from a node, so the edge INTO \
             helper.py must not credit Python with app.js's import statement"
        );
        assert_eq!(js.resolved_import_statements, None);
        assert_eq!(
            python.resolved_import_statements, None,
            "neither language carried a coverage certificate, so how many of their \
             imports resolved was never measured on this path"
        );
    }

    /// The rendered line names the external share, so a low ratio reads as a
    /// repository with more dependencies than modules rather than as a defect.
    /// The rendered line names the external share, so a low ratio reads as a
    /// repository with more dependencies than modules rather than as a defect.
    /// The four-file Python project the v0.5.52 stranger wrote, at the numbers
    /// this lane measured on it, rendering the line it should always have.
    ///
    /// Kin reported `imports 1/10 (10%)` on that project with no external
    /// clause, and it was handed to this lane as evidence that Python import
    /// resolution was broken. It was not. An independent count with CPython's
    /// own `ast` module found 9 statements, 4 naming a module in the repository
    /// and 5 naming `re`, `typing`, `json`, `pathlib` and `pytest`. The linker
    /// resolves all 4.
    ///
    /// What was broken was the reporting: `specifier_syntax_settles_externality`
    /// is true only for JavaScript and TypeScript, so a Python row printed no
    /// external clause and its ratio read as a 90 percent failure against a
    /// denominator nine tenths of which could never have resolved.
    #[test]
    fn the_four_file_python_project_line_discloses_its_external_imports() {
        let (graph, ids) = graph_with_artifacts(&["notekeeper/parsing.py"]);
        // 9 statements read across the project, 4 of them resolving in-repo.
        graph
            .upsert_entity(&entity(
                "parsing",
                "notekeeper/parsing.py",
                Some(0),
                Some(9),
            ))
            .unwrap();
        graph
            .upsert_relation(&import_certificate(ids[0], "notekeeper/parsing.py", 9, 4))
            .unwrap();

        let coverage = collect_reference_edge_coverage(&graph).unwrap();
        let line = coverage
            .summary_lines()
            .into_iter()
            .find(|line| line.contains("python:"))
            .expect("python row is rendered");

        assert!(
            line.contains("imports 4/9 (44%), 5 name a module outside this repository"),
            "the python line must read its resolved statements against its parsed ones AND \
             disclose the external count; got: {line}"
        );
    }

    /// The certificate's statement count and the parser's must agree, because
    /// they are two independent counts of one population.
    ///
    /// The parser stamps `parsed_import_statements` per file at extraction; the
    /// linker counts the same `FileImport`s again when it writes the
    /// certificate. Computing both and comparing neither would leave a
    /// disagreement invisible, and a disagreement is the tell that the two are
    /// counting different populations, which is the failure this change exists
    /// to remove.
    ///
    /// They can legitimately differ when only SOME files of a language carry a
    /// certificate, because three link paths supply no completeness map and emit
    /// none. That partition gap is FIR-2686. This fixture gives every file a
    /// certificate, so the two counts must match exactly.
    #[test]
    fn the_certificate_and_the_parser_count_the_same_statements() {
        let (graph, ids) = graph_with_artifacts(&["app/main.py", "app/storage.py"]);
        graph
            .upsert_entity(&entity("main", "app/main.py", Some(0), Some(3)))
            .unwrap();
        graph
            .upsert_entity(&entity("Store", "app/storage.py", Some(0), Some(0)))
            .unwrap();
        graph
            .upsert_relation(&import_certificate(ids[0], "app/main.py", 3, 1))
            .unwrap();
        graph
            .upsert_relation(&import_certificate(ids[1], "app/storage.py", 0, 0))
            .unwrap();

        let coverage = collect_reference_edge_coverage(&graph).unwrap();
        let python = coverage
            .languages
            .iter()
            .find(|row| row.language == LanguageId::Python.to_string())
            .expect("python row");

        let parsed = python
            .parsed_import_statements
            .expect("the parser counted statements");
        let resolved = python
            .resolved_import_statements
            .expect("every file carried a certificate");
        let external = python
            .external_module_imports
            .expect("the certificate settles externality here");

        assert_eq!(
            resolved + external,
            parsed,
            "resolved plus external must partition the parsed statements exactly"
        );
    }

    /// Python's external count comes from the certificate, not from specifier
    /// syntax, and the line says so.
    ///
    /// `specifier_syntax_settles_externality` is true only for JavaScript and
    /// TypeScript, because a Python `import re` could name a local `re.py`. So
    /// Python printed no external clause at all, and `imports 1/10` read as a 90
    /// percent failure when nine of the ten were stdlib and could never have
    /// resolved. The linker knows the answer, because `known_files` decides it,
    /// and the certificate carries it here.
    #[test]
    fn a_python_row_reports_its_external_imports_from_the_certificate() {
        let (graph, ids) = graph_with_artifacts(&["app/main.py", "app/storage.py"]);
        graph
            .upsert_entity(&entity("main", "app/main.py", Some(0), Some(3)))
            .unwrap();
        graph
            .upsert_entity(&entity("Store", "app/storage.py", Some(0), Some(0)))
            .unwrap();
        // Three statements read, one reached a file this repository holds. The
        // other two are `re` and `typing`.
        graph
            .upsert_relation(&import_certificate(ids[0], "app/main.py", 3, 1))
            .unwrap();

        let coverage = collect_reference_edge_coverage(&graph).unwrap();
        let python = coverage
            .languages
            .iter()
            .find(|row| row.language == LanguageId::Python.to_string())
            .expect("python row");
        assert_eq!(python.resolved_import_statements, Some(1));
        assert_eq!(
            python.external_module_imports,
            Some(2),
            "two statements named a module outside the repository"
        );

        let line = coverage
            .summary_lines()
            .into_iter()
            .find(|line| line.contains("python:"))
            .expect("python row is rendered");
        assert!(
            line.contains("name a module outside this repository"),
            "a python line must disclose its external imports, got: {line}"
        );
    }

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
            line.contains(
                "imports resolution unmeasured, parse side read 4 statements, \
                 3 name a module outside this repository"
            ),
            "the external share is what this line exists to disclose, and an \
             unmeasured resolution must not take it down with it: {line}"
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
        assert_eq!(
            python.resolved_import_statements, None,
            "unmeasured rather than zero: this graph carries no coverage certificate"
        );
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
                resolved_import_statements: Some(0),
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
    /// whatever is installed, which is why jdtls on PATH buys Java nothing.
    ///
    /// The unwired example used to be Go, and Go was the right one until the
    /// daemon gained its `gopls` arm. The property this test guards outlives
    /// any one language, so it moved to Java rather than being deleted: kin-lsp
    /// carries a complete `jdtls` provider that the daemon deliberately does not
    /// construct, which is exactly the shape the assertion is about.
    #[test]
    fn language_server_state_is_attached_rather_than_assumed() {
        let unfilled = ReferenceEdgeCoverage {
            parse: None,
            languages: vec![
                language_row("python", ReferenceEnrichment::Unknown),
                language_row("java", ReferenceEnrichment::Unknown),
            ],
            totals: None,
        };
        assert!(
            unfilled.languages_missing_a_language_server().is_empty(),
            "nothing looked, so nothing was found missing"
        );

        let filled = unfilled
            .clone()
            .with_language_servers(&usable(&[LanguageId::Java]));
        assert_eq!(
            filled.languages_missing_a_language_server(),
            vec!["python"],
            "a wired language with no server is the actionable gap"
        );
        assert_eq!(
            filled.languages[1].reference_enrichment,
            ReferenceEnrichment::Unsupported,
            "jdtls on PATH gives Java nothing: no adapter consumes it"
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
            resolved_import_statements: Some(2),
            external_module_imports: None,
            cross_file_reference_edges: 2,
            intra_file_reference_edges: 2,
            external_reference_edges: 0,
            resolution: ReferenceResolution::FullyResolved,
            reference_enrichment: enrichment,
        }
    }

    /// Fan-out can put more edges on the numerator than the denominator ever
    /// counted sites for, and the word `resolved` must not follow it there.
    ///
    /// One ambiguous call site binds several same-named targets under the
    /// linker's fanout cap, so `resolved > parsed` is a real state on a real
    /// repository rather than a hypothetical. It became reachable for Python
    /// the moment the parse side started being measured at all: before that,
    /// the zero denominator held every Python row at `Unmeasured`. Reading it
    /// as `FullyResolved` prints `[resolved]` and `100%` off a ratio that is no
    /// longer coverage, which is the same wrong word the zero-denominator case
    /// produced, arrived at from the other side.
    #[test]
    fn more_edges_than_sites_is_not_fully_resolved() {
        assert_eq!(
            classify(1, Some(4), 4),
            ReferenceResolution::FullyResolved,
            "an exact match is the only thing that says every parsed site became an edge"
        );
        assert_eq!(
            classify(1, Some(4), 5),
            ReferenceResolution::PartiallyResolved,
            "more edges than sites is fan-out, not a stronger result, so the row must not claim \
             the call side is fully resolved"
        );
        // The controls on either side of the new arm, so a fix that floors
        // everything to partial is visible here rather than in a later ticket.
        assert_eq!(
            classify(1, Some(4), 3),
            ReferenceResolution::PartiallyResolved,
            "fewer edges than sites is still partial"
        );
        assert_eq!(
            classify(1, Some(4), 0),
            ReferenceResolution::NoneResolved,
            "and no edges at all is still the state an absence cannot be concluded from"
        );
        assert_eq!(
            classify(1, None, 5),
            ReferenceResolution::Unmeasured,
            "and an absent parse side is still unmeasured rather than resolved"
        );
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
        row.resolved_import_statements = Some(2);
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

    /// One row, built by hand, so the rendering is testable without a store.
    fn parse_row(language: &str, tracked: usize, silent: usize) -> LanguageParseCoverage {
        LanguageParseCoverage {
            language: language.to_string(),
            tracked,
            with_entities: tracked.saturating_sub(silent),
            silent,
            retained: 0,
            sample: (0..silent.min(PARSE_HOLE_SAMPLE))
                .map(|index| format!("lib/file{index}.js"))
                .collect(),
            retained_sample: Vec::new(),
        }
    }

    /// A row for a language holding files the graph answers about from an
    /// earlier parse, so the numerator drops rather than the denominator.
    fn retained_row(language: &str, tracked: usize, retained: usize) -> LanguageParseCoverage {
        LanguageParseCoverage {
            language: language.to_string(),
            tracked,
            with_entities: tracked.saturating_sub(retained),
            silent: 0,
            retained,
            sample: Vec::new(),
            retained_sample: (0..retained.min(PARSE_HOLE_SAMPLE))
                .map(|index| format!("lib/broken{index}.py (4 parse errors)"))
                .collect(),
        }
    }

    /// The census publishes a count and the paths behind it, and never a
    /// verdict. This is the assertion that keeps it that way: a file producing
    /// no entity is not on its own evidence that anything failed, because a
    /// side-effect script, a re-export and a comment-only file each correctly
    /// produce nothing, and nothing in graph-owned state separates those from a
    /// file an adapter could not read. A change that grows a verdict here has to
    /// delete this test to do it.
    #[test]
    fn the_census_reports_a_count_and_never_a_verdict() {
        let holed = ParseCoverageCensus {
            languages: vec![parse_row("javascript", 141, 75)],
        };
        let lines = holed.summary_lines();
        let rendered = lines.join("\n");
        assert!(
            rendered.contains("javascript: 66/141 (46%)"),
            "the ratio is published: {rendered}"
        );
        assert!(
            rendered.contains("lib/file0.js"),
            "the paths are published beside it: {rendered}"
        );
        // The caveat is allowed the words the rows are not, so the rows are what
        // this checks. A row calling the count incomplete, or failed, or marking
        // it with the warning glyph, claims something the store cannot back.
        let rows: Vec<&String> = lines
            .iter()
            .filter(|line| !line.contains("NOT on its own evidence"))
            .collect();
        for barred in ["incomplete", "failed", "defect", "⚠"] {
            assert!(
                rows.iter().all(|line| !line.contains(barred)),
                "no row may read as a verdict, found {barred:?}: {rows:?}"
            );
        }
        assert!(
            rendered.contains("NOT on its own evidence"),
            "the caveat rides with the number rather than in a doc nobody opens: {rendered}"
        );
    }

    /// A store every file of which produced an entity still prints its section.
    /// A section that fell silent when there was nothing to report would be
    /// indistinguishable from a build that never measured it.
    #[test]
    fn a_fully_producing_store_still_prints_its_numbers_and_names_no_file() {
        let clean = ParseCoverageCensus {
            languages: vec![parse_row("rust", 200, 0)],
        };
        assert!(
            clean.silent_file_lines().is_empty(),
            "no file is named when none is silent"
        );
        let rendered = clean.summary_lines().join("\n");
        assert!(rendered.contains("rust: 200/200 (100%)"), "{rendered}");
    }

    /// Disclosure is per language, so one language's silence never speaks for
    /// another's.
    #[test]
    fn each_language_is_disclosed_on_its_own_numbers() {
        let mixed = ParseCoverageCensus {
            languages: vec![parse_row("javascript", 10, 4), parse_row("rust", 200, 0)],
        };
        let lines = mixed.silent_file_lines();
        assert_eq!(lines.len(), 1, "{lines:?}");
        assert!(lines[0].starts_with(NO_ENTITY_OBSERVATION), "{}", lines[0]);
        assert!(
            lines[0].contains("javascript") && !lines[0].contains("rust"),
            "{}",
            lines[0]
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

        let census = collect_parse_coverage_from(&tree, &produced, &RetainedParseRead::Absent);
        assert_eq!(census.languages.len(), 1, "{census:?}");
        let row = &census.languages[0];
        assert_eq!(row.language, "javascript");
        assert_eq!(row.tracked, 4, "README.md is not a full-adapter input");
        assert_eq!(row.with_entities, 2);
        assert_eq!(row.silent, 2);
        assert_eq!(
            row.sample,
            vec![
                "lib/application.js".to_string(),
                "lib/express.js".to_string()
            ],
            "shallowest first, then alphabetical"
        );
        assert_eq!(row.entity_percent(), Some(50));
    }

    /// The census stops counting a file whose CURRENT bytes did not parse.
    ///
    /// This is the arithmetic behind journey GAP-9. The daemon reconciles under
    /// fallback-to-last-known-good, so a file with a syntax error keeps the
    /// entities its previous parse produced and is therefore in `producing` by
    /// construction. Counting it there is what made a store answering about
    /// `search.py` at retired positions print `python: 2/2 (100%)` while its own
    /// daemon log carried `broken AST, retaining LKG state`.
    ///
    /// The second half is the control that makes the first mean something: the
    /// SAME tree and the SAME entities with an absent record read 2/2 again, so
    /// a census that had simply stopped counting python files would fail here.
    #[test]
    fn a_file_retained_from_an_earlier_parse_leaves_the_numerator() {
        let tree = tree_of(&["search.py", "store.py"]);
        let produced = [
            entity("tokenize", "search.py", None, None),
            entity("put", "store.py", None, None),
        ];
        let record = crate::retained_parse::fold(
            &[],
            &[ObservedParse::retained("search.py", 4)],
            chrono::Utc::now(),
        );
        let retained = RetainedParseRead::Recorded(record);

        let census = collect_parse_coverage_from(&tree, &produced, &retained);
        let row = &census.languages[0];
        assert_eq!(row.language, "python");
        assert_eq!(row.tracked, 2, "the denominator is every admitted file");
        assert_eq!(
            row.with_entities, 1,
            "search.py answers from bytes it no longer has"
        );
        assert_eq!(row.retained, 1);
        assert_eq!(
            row.silent, 0,
            "a retained file is not silent; the graph answers about it"
        );
        assert_eq!(
            row.with_entities + row.silent + row.retained,
            row.tracked,
            "the three buckets partition the admitted set: {row:?}"
        );
        assert_eq!(row.entity_percent(), Some(50));

        let control = collect_parse_coverage_from(&tree, &produced, &RetainedParseRead::Absent);
        assert_eq!(
            control.languages[0].with_entities, 2,
            "with no record the same tree and entities read exactly as before"
        );
        assert_eq!(control.languages[0].retained, 0);
    }

    /// The section names the file and says what a reader is being served,
    /// because a count nobody can act on is the state this row was already in.
    #[test]
    fn the_section_names_a_retained_file_and_reaches_a_verdict_about_it() {
        let census = ParseCoverageCensus {
            languages: vec![retained_row("python", 2, 1)],
        };
        assert!(census.any_retained());
        let lines = census.summary_lines().join("\n");
        assert!(
            lines.contains(PARSE_COVERAGE_HEADING),
            "the heading says whose bytes the numerator counts: {lines}"
        );
        assert!(lines.contains("  python: 1/2 (50%)"), "{lines}");
        assert!(
            lines.contains(crate::retained_parse::RETAINED_OBSERVATION),
            "the class is taggable rather than only readable: {lines}"
        );
        assert!(lines.contains("lib/broken0.py (4 parse errors)"), "{lines}");
        assert!(
            lines.contains("did not parse from their current bytes"),
            "{lines}"
        );

        // The control. A census with nothing retained says nothing about it, or
        // every clean store reads as one holding a broken file.
        let clean = ParseCoverageCensus {
            languages: vec![parse_row("python", 2, 0)],
        };
        assert!(!clean.any_retained());
        let clean_lines = clean.summary_lines().join("\n");
        assert!(
            !clean_lines.contains(crate::retained_parse::RETAINED_OBSERVATION),
            "a store with nothing retained must not claim one: {clean_lines}"
        );
        assert!(
            clean_lines.contains("  python: 2/2 (100%)"),
            "{clean_lines}"
        );
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
        let census = collect_parse_coverage_from(&tree, &stale, &RetainedParseRead::Absent);
        let row = &census.languages[0];
        assert_eq!(
            row.tracked, 1,
            "only lib/express.js is a full-adapter input: {census:?}"
        );
        assert_eq!(
            row.with_entities, 0,
            "an entity on an unadmitted path credits nothing"
        );
        assert_eq!(row.silent, 1);
    }

    /// A `.h` file is left out of every row, because the census reads no file
    /// and the extension alone cannot say whether a header is C or C++. The
    /// alternative is a `c` row on a repository holding no C.
    #[test]
    fn a_header_is_left_out_rather_than_attributed_to_the_wrong_language() {
        let tree = tree_of(&["src/widget.h", "src/widget.cpp", "src/other.cpp"]);
        let census = collect_parse_coverage_from(&tree, &[], &RetainedParseRead::Absent);
        assert_eq!(census.languages.len(), 1, "{census:?}");
        let row = &census.languages[0];
        assert_eq!(row.language, "cpp", "the .cpp files are attributable");
        assert_eq!(
            row.tracked, 2,
            "widget.h is in no row, so no c row exists to dilute or mislabel: {census:?}"
        );
        assert!(
            !census
                .languages
                .iter()
                .any(|language| language.language == "c"),
            "{census:?}"
        );
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
        let census = collect_parse_coverage_from(&tree, &[], &RetainedParseRead::Absent);
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
