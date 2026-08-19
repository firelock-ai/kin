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

use kin_model::{Entity, EntityId, EntityStore, GraphNodeId, LanguageId, RelationKind};
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
}

impl ReferenceEdgeCoverage {
    /// Attach the whole-graph totals the caller already counted.
    pub fn with_totals(mut self, totals: GraphRelationTotals) -> Self {
        self.totals = Some(totals);
        self
    }

    /// Fill in each language's enrichment state from the servers a caller found.
    ///
    /// Kept off the collector because probing the host is not reading the graph,
    /// and this module measures graph truth alone.
    pub fn with_language_servers(mut self, servers_found: &HashSet<LanguageId>) -> Self {
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
                Some(id) => reference_enrichment_for(id, servers_found),
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

#[cfg(test)]
mod tests {
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
            .with_language_servers(&[LanguageId::Go].into_iter().collect());
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

        let complete = unfilled
            .with_language_servers(&[LanguageId::Python, LanguageId::Rust].into_iter().collect());
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
}
