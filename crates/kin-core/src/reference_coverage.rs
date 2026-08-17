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

use std::collections::{BTreeMap, HashMap, HashSet};

use kin_model::{Entity, EntityId, EntityStore, GraphNodeId, LanguageId, RelationKind};
use serde::{Deserialize, Serialize};

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
    /// No file of this language carries a parse-side count, so the ratio is
    /// unknown. A store ingested before the count was recorded reads this way.
    /// Unmeasured is not zero and it is not complete.
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
    /// Import statements the parser read across measured files.
    pub parsed_import_statements: Option<u64>,
    /// `Calls` edges the graph holds whose caller is of this language.
    pub resolved_call_edges: u64,
    /// Entity-level `Imports` edges the graph holds whose importer is of this
    /// language.
    ///
    /// An import of a module this repository owns resolves to an
    /// ARTIFACT-to-artifact edge, which no entity-rooted query reaches, so this
    /// counter is normally driven by imports of code outside the repository.
    /// That is why it does not on its own decide `resolution`: zero here is not
    /// evidence of a broken graph the way zero call edges is.
    pub resolved_import_edges: u64,
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
}

impl LanguageReferenceCoverage {
    /// Percent of parsed call sites that produced an edge, capped at 100.
    ///
    /// A call site can fan out to several same-named targets, so the raw ratio
    /// can exceed 1; the cap keeps the figure readable as coverage.
    pub fn call_percent(&self) -> Option<u32> {
        percent(self.parsed_call_sites, self.resolved_call_edges)
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
}

impl ReferenceEdgeCoverage {
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

    /// Terminal rendering, one line per language plus the caveat a reader needs
    /// to keep a sub-100% ratio from reading as a defect.
    pub fn summary_lines(&self) -> Vec<String> {
        if self.languages.is_empty() {
            return vec![
                "Reference edge coverage: no language entities in the graph yet".to_string(),
            ];
        }

        let mut lines = vec!["Reference edge coverage (parsed -> resolved):".to_string()];
        for language in &self.languages {
            lines.push(format!("  {}", language_summary(language)));
        }
        lines.push(
            "  Counts entity-level reference edges only, which is what find_references, \
             trace_data_flow, impact and dead-code answer from; a local import statement also \
             resolves to an artifact-level edge those queries never reach."
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
        (Some(parsed), None) => format!("calls {}/{parsed}", coverage.resolved_call_edges),
        (None, _) => format!("calls {} resolved, parse side unmeasured", coverage.resolved_call_edges),
    };
    let imports = match (coverage.parsed_import_statements, coverage.import_percent()) {
        (Some(parsed), Some(percent)) => format!(
            "imports {}/{parsed} ({percent}%)",
            coverage.resolved_import_edges
        ),
        (Some(parsed), None) => format!("imports {}/{parsed}", coverage.resolved_import_edges),
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
    }

    let allowed: HashSet<RelationKind> = REFERENCE_RELATION_KINDS.iter().copied().collect();
    let mut seen_relations: HashSet<kin_model::RelationId> = HashSet::new();
    for entity in entities {
        for relation in store.get_all_relations_for_entity(&entity.id)? {
            if !allowed.contains(&relation.kind) || !seen_relations.insert(relation.id) {
                continue;
            }
            let (GraphNodeId::Entity(src), GraphNodeId::Entity(dst)) =
                (relation.src, relation.dst)
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
                parsed_import_statements,
                resolved_call_edges: tally.resolved_call_edges,
                resolved_import_edges: tally.resolved_import_edges,
                cross_file_reference_edges: tally.cross_file,
                intra_file_reference_edges: tally.intra_file,
                external_reference_edges: tally.external,
                resolution,
            }
        })
        .collect();

    Ok(ReferenceEdgeCoverage { languages })
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
        None | Some(0) => ReferenceResolution::FullyResolved,
        Some(_) if resolved_call_edges == 0 => ReferenceResolution::NoneResolved,
        Some(parsed) if resolved_call_edges < parsed => ReferenceResolution::PartiallyResolved,
        Some(_) => ReferenceResolution::FullyResolved,
    }
}

fn read_count(entity: &Entity, key: &str) -> Option<u64> {
    entity.metadata.extra.get(key).and_then(|value| value.as_u64())
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
