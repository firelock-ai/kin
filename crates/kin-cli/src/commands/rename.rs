// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Wire contract and graph-authoritative planner for repository-v6 rename.
//!
//! Planning consumes only an exact repository graph and immutable source
//! bodies supplied by the caller. The CLI never reads a working file. The
//! daemon owns application because it is the only process that can hold the
//! repository compare-and-swap and the projection journal together.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::Path;

use anyhow::{bail, Context, Result};
use kin_model::{
    AuthorId, Entity, EntityFilter, EntityId, EntityKind, EntityStore, FilePathId, GraphNodeId,
    GraphStore, Hash256, LanguageId, OperationId, ParseCompleteness, Relation, RelationKind,
    RepoPath, SourceSpan,
};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RenameRequest {
    pub symbol: String,
    pub new_name: String,
    #[serde(default)]
    pub file: Option<String>,
    #[serde(default)]
    pub line: Option<u32>,
    #[serde(default)]
    pub column: Option<u32>,
    #[serde(default)]
    pub json: bool,
    pub operation_id: OperationId,
    pub actor: AuthorId,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RenameEdit {
    pub file: FilePathId,
    pub start_byte: usize,
    pub end_byte: usize,
    #[serde(rename = "startLine")]
    pub start_line: u32,
    #[serde(rename = "startCol")]
    pub start_col: u32,
    #[serde(rename = "endLine")]
    pub end_line: u32,
    #[serde(rename = "endCol")]
    pub end_col: u32,
    #[serde(rename = "oldText")]
    pub old_text: String,
    #[serde(rename = "newText")]
    pub new_text: String,
    pub reason: String,
    /// The one occurrence that names the declaration whose graph identity is
    /// retained across the reparse.
    #[serde(default)]
    pub declaration: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RenamePlan {
    pub entity_id: EntityId,
    pub entity_kind: EntityKind,
    pub old_name: String,
    pub new_name: String,
    pub declaration_file: FilePathId,
    pub edits: Vec<RenameEdit>,
    pub relation_ids: Vec<kin_model::RelationId>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RenameReport {
    pub authority: String,
    pub operation_id: OperationId,
    pub change_id: kin_model::SemanticChangeId,
    pub authority_generation: u64,
    pub entity_id: EntityId,
    pub old_name: String,
    pub new_name: String,
    pub edited_files: Vec<FilePathId>,
    pub edit_count: usize,
    pub idempotent: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenameResponse {
    #[serde(default)]
    pub lines: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub report: Option<RenameReport>,
}

pub async fn run(
    symbol: String,
    new_name: String,
    file: Option<String>,
    line: Option<u32>,
    column: Option<u32>,
    json: bool,
) -> Result<()> {
    validate_cursor(file.as_deref(), line, column)?;
    let layout = crate::commands::require_repository_layout()?;
    let daemon_url = crate::daemon_client::resolve_daemon_url(&layout)
        .await?
        .ok_or_else(|| crate::daemon_client::daemon_required_error("rename", &layout))?;
    let request = RenameRequest {
        symbol,
        new_name,
        file: file.map(|hint| normalize_file_hint(&layout, &hint)),
        line,
        column,
        json,
        operation_id: OperationId::new(),
        actor: crate::commands::require_commit_author()?,
    };
    let daemon = crate::daemon_client::DaemonClient::from_base_url_for_layout(daemon_url, &layout)?;
    let response = daemon.rename(&request).await?;
    if json {
        let report = response
            .report
            .ok_or_else(|| anyhow::anyhow!("daemon rename response omitted its report"))?;
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        for line in response.lines {
            println!("{line}");
        }
    }
    Ok(())
}

/// Build one complete rename plan from graph relations and immutable source
/// bodies. `load_source` must resolve the exact digest named by `graph` from
/// repository-owned CAS; a missing body is a hard authority gap.
pub fn plan_rename<F>(
    graph: &kin_db::InMemoryGraph,
    request: &RenameRequest,
    mut load_source: F,
) -> Result<RenamePlan>
where
    F: FnMut(&RepoPath, Hash256) -> Result<Vec<u8>>,
{
    validate_cursor(request.file.as_deref(), request.line, request.column)?;
    if !looks_like_identifier(&request.new_name) {
        bail!(
            "rename target '{}' is not a simple source identifier",
            request.new_name
        );
    }
    let tree = graph.resolved_tree();
    let mut bodies = HashMap::<FilePathId, String>::new();
    let target = resolve_target(graph, request, &tree, &mut bodies, &mut load_source)?;
    if target.name == request.new_name {
        bail!("rename target already has name '{}'", request.new_name);
    }
    reject_local_name_collision(graph, &target, &request.new_name)?;

    let declaration_file = target.file_origin.clone().ok_or_else(|| {
        anyhow::anyhow!(
            "entity {} has no exact source origin; graph-only entities cannot be renamed",
            target.id
        )
    })?;
    let declaration_span = target.span.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "entity {} has no exact source span; rename cannot anchor its declaration",
            target.id
        )
    })?;
    if declaration_span.file != declaration_file {
        bail!(
            "entity {} source span file {} disagrees with origin {}",
            target.id,
            declaration_span.file,
            declaration_file
        );
    }

    let source_languages = require_repository_reference_coverage(
        graph,
        &target,
        &tree,
        &mut bodies,
        &mut load_source,
    )?;

    let mut grouped: BTreeMap<EntityId, ReferenceGroup> = BTreeMap::new();
    let mut relation_ids = BTreeSet::new();
    for relation in graph.get_all_relations_for_entity(&target.id)? {
        if relation.dst != GraphNodeId::Entity(target.id) || !rename_reference_kind(relation.kind) {
            continue;
        }
        let source_id = relation.src.as_entity().ok_or_else(|| {
            anyhow::anyhow!(
                "rename relation {} ({:?}) reaches target {} from non-entity {}; exact source site is unavailable",
                relation.id,
                relation.kind,
                target.id,
                relation.src
            )
        })?;
        let source = graph.get_entity(&source_id)?.ok_or_else(|| {
            anyhow::anyhow!(
                "rename relation {} names missing source entity {}",
                relation.id,
                source_id
            )
        })?;
        let (unspanned, spanned) = relation_occurrence_split(&relation)?;
        let group = grouped
            .entry(source_id)
            .or_insert_with(|| ReferenceGroup::new(source));
        group.expected = group
            .expected
            .checked_add(unspanned)
            .ok_or_else(|| anyhow::anyhow!("rename reference occurrence count overflow"))?;
        group.scoped.extend(spanned);
        group
            .kinds
            .insert(format!("{:?}", relation.kind).to_ascii_lowercase());
        group.relation_ids.insert(relation.id);
        relation_ids.insert(relation.id);
    }

    // The declaration is an independently required occurrence. If the target
    // recursively references itself, the relation count adds those sites.
    let declaration_group = grouped
        .entry(target.id)
        .or_insert_with(|| ReferenceGroup::new(target.clone()));
    declaration_group.expected = declaration_group
        .expected
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("rename occurrence count overflow"))?;
    declaration_group.declaration = true;

    let mut edits = Vec::new();
    let mut seen = HashMap::new();
    for group in grouped.values() {
        let file = group.entity.file_origin.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "graph-linked rename source entity {} has no exact file origin",
                group.entity.id
            )
        })?;
        let span = group.entity.span.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "graph-linked rename source entity {} has no exact source span",
                group.entity.id
            )
        })?;
        if span.file != *file {
            bail!(
                "graph-linked rename source entity {} span file {} disagrees with origin {}",
                group.entity.id,
                span.file,
                file
            );
        }
        require_complete_layout(graph, file)?;
        let body = load_cached_body(&tree, file, &mut bodies, &mut load_source)?;
        let reason = if group.declaration && group.kinds.is_empty() {
            "declaration".to_string()
        } else if group.declaration {
            format!("declaration+{}", relation_reason(&group.kinds))
        } else {
            relation_reason(&group.kinds)
        };

        // One search per span the group expects occurrences in, rather than one
        // search over the source entity. The entity-wide pass runs only when
        // some evidence asked for it, so an edge whose evidence named its own
        // span is never searched across the whole entity.
        //
        // The entity pass keeps `declaration: true` for its first occurrence
        // and a scoped pass never claims it: the declaration is a site in the
        // entity's own span by definition, and a scoped span is a reference
        // somewhere else.
        let mut passes: Vec<(&kin_model::SourceSpan, usize, bool)> = Vec::new();
        if group.expected > 0 || group.declaration {
            passes.push((span, group.expected, true));
        }
        for (scoped_span, scoped_expected) in &group.scoped {
            if scoped_span.file != *file {
                bail!(
                    "graph-linked rename evidence for entity {} names a span in {} but the entity's origin is {}",
                    group.entity.id,
                    scoped_span.file,
                    file
                );
            }
            passes.push((scoped_span, *scoped_expected, false));
        }

        for (search_span, expected, is_entity_span) in passes {
            let occurrences =
                find_token_occurrences(body, &target.name, search_span, group.entity.language)?;
            if occurrences.len() != expected {
                bail!(
                "rename authority is incomplete for entity {} in {}: graph relations plus declaration require {} '{}' occurrence(s) inside the exact source span {}..{}, but repository CAS contains {}; refusing a partial or over-broad edit",
                group.entity.id,
                file,
                expected,
                target.name,
                search_span.start_byte,
                search_span.end_byte,
                occurrences.len()
            );
            }
            for (occurrence_index, occurrence) in occurrences.into_iter().enumerate() {
                let key = (file.clone(), occurrence.start_byte, occurrence.end_byte);
                if let Some(other_entity) = seen.insert(key, group.entity.id) {
                    bail!(
                    "rename occurrence {}:{}..{} is claimed by overlapping graph source entities {} and {}; refusing to count one token as two relation sites",
                    file,
                    occurrence.start_byte,
                    occurrence.end_byte,
                    other_entity,
                    group.entity.id
                );
                }
                edits.push(RenameEdit {
                    file: file.clone(),
                    start_byte: occurrence.start_byte,
                    end_byte: occurrence.end_byte,
                    start_line: occurrence.start_line,
                    start_col: occurrence.start_col,
                    end_line: occurrence.end_line,
                    end_col: occurrence.end_col,
                    old_text: target.name.clone(),
                    new_text: request.new_name.clone(),
                    reason: reason.clone(),
                    declaration: is_entity_span && group.declaration && occurrence_index == 0,
                });
            }
        }
    }
    edits.sort_by(|left, right| {
        left.file
            .0
            .cmp(&right.file.0)
            .then(left.start_byte.cmp(&right.start_byte))
    });
    if edits.is_empty() {
        bail!("rename planner produced no exact edits");
    }
    prove_repository_occurrence_accounting(graph, &target, &source_languages, &bodies, &edits)?;

    Ok(RenamePlan {
        entity_id: target.id,
        entity_kind: target.kind,
        old_name: target.name,
        new_name: request.new_name.clone(),
        declaration_file,
        edits,
        relation_ids: relation_ids.into_iter().collect(),
    })
}

fn require_repository_reference_coverage<F>(
    graph: &kin_db::InMemoryGraph,
    target: &Entity,
    tree: &kin_model::ResolvedTree,
    bodies: &mut HashMap<FilePathId, String>,
    load_source: &mut F,
) -> Result<HashMap<FilePathId, LanguageId>>
where
    F: FnMut(&RepoPath, Hash256) -> Result<Vec<u8>>,
{
    let pipeline = kin_index::IndexPipeline::new();
    let layouts = graph
        .list_file_layouts()?
        .into_iter()
        .map(|layout| (layout.file_id.clone(), layout))
        .collect::<HashMap<_, _>>();
    let snapshot = graph.to_snapshot();
    let mut full_reference_coverage = HashSet::<String>::new();
    let mut incomplete_reference_coverage = HashSet::<String>::new();
    for relation in snapshot.relations.values() {
        for evidence in &relation.evidence {
            match evidence.parser_rule.as_deref() {
                Some(kin_index::CALL_SHAPE_PARSE_COVERAGE_FULL_V1) => {
                    if let Some(path) = evidence.source_path.as_ref() {
                        full_reference_coverage.insert(path.clone());
                    }
                }
                Some(
                    kin_index::CALL_SHAPE_PARSE_COVERAGE_INCOMPLETE_V1
                    | kin_index::CALL_SHAPE_EXTRACTION_COVERAGE_INCOMPLETE_V1,
                ) => {
                    if let Some(path) = evidence.source_path.as_ref() {
                        incomplete_reference_coverage.insert(path.clone());
                    }
                }
                _ => {}
            }
        }
    }
    // A missing layout is itself a graph-authority gap. Do not limit this
    // check to files that already expose an entity or relation: a source file
    // containing only a named import can still require a rename edit. Path
    // classification is routing metadata over the graph-owned tree, not a
    // filesystem answer or content fallback.
    for artifact in tree.artifacts_by_path() {
        if artifact.entry.blob_identity().is_none() {
            continue;
        }
        let Some(path) = artifact.path.as_utf8() else {
            bail!(
                "repository tree contains a non-UTF-8 blob path; repository-wide rename coverage is unproven"
            );
        };
        match kin_index::FileClassifier::classify(Path::new(path)) {
            kin_index::FileClassification::EntitySource => {
                let file = FilePathId::new(path);
                if !layouts.contains_key(&file) {
                    bail!(
                        "repository source {} has no graph-owned file layout; repository-wide rename coverage is unproven",
                        file
                    );
                }
            }
            kin_index::FileClassification::ShallowSyntax { .. } => {
                bail!(
                    "repository source {} has only shallow syntax coverage; exact rename coverage is unproven",
                    path
                );
            }
            kin_index::FileClassification::StructuredArtifact(_)
            | kin_index::FileClassification::OpaqueArtifact { .. } => {}
        }
    }
    // Artifact-level import edges are intentionally not the sole coverage
    // authority here. Some supported linkers resolve entity edges without
    // emitting an artifact import edge (for example a Python `from` import).
    // Reparse every graph-owned source body from the exact repository tree so
    // a named import can never be silently omitted from a rename plan.
    let mut source_languages = HashMap::new();
    for layout in layouts.into_values() {
        let importer_file = layout.file_id;
        if layout.parse_completeness != ParseCompleteness::Full {
            bail!(
                "graph source {} has {} parse coverage; repository-wide import rename coverage is unproven",
                importer_file,
                layout.parse_completeness.bucket()
            );
        }
        if incomplete_reference_coverage.contains(&importer_file.0) {
            bail!(
                "graph source {} carries an explicit extraction-incomplete certificate; exhaustive rename-reference coverage is unproven",
                importer_file
            );
        }
        if !full_reference_coverage.contains(&importer_file.0) {
            bail!(
                "graph source {} has no positive versioned full-reference-coverage certificate; exhaustive rename-reference coverage is unproven",
                importer_file
            );
        }
        let body = load_cached_body(tree, &importer_file, bodies, load_source)?;
        let indexed = pipeline
            .index_any_content(
                &importer_file,
                body.as_bytes(),
                kin_blobs::digest(body.as_bytes()),
            )
            .with_context(|| format!("reparse graph-linked importer {importer_file}"))?;
        let kin_index::IndexedAny::EntitySource(indexed) = indexed else {
            bail!(
                "graph source {} is not fully classifiable as entity source; rename import coverage is unproven",
                importer_file
            );
        };
        if indexed.file_layout.parse_completeness != ParseCompleteness::Full {
            bail!(
                "graph source {} reparsed with {} coverage; rename import coverage is unproven",
                importer_file,
                indexed.file_layout.parse_completeness.bucket()
            );
        }
        if indexed
            .extracted_relations
            .iter()
            .any(kin_parser::is_call_extraction_incomplete_marker)
        {
            bail!(
                "repository CAS source {} reparses with incomplete named-reference extraction; refusing a partial rename",
                importer_file
            );
        }
        let imported_target = indexed.imports.iter().any(|import| {
            import.specifiers.iter().any(|specifier| {
                specifier
                    .original_name
                    .as_deref()
                    .unwrap_or(&specifier.local_name)
                    == target.name
            })
        });
        if imported_target {
            // The parser sees this file importing the target. That used to be
            // an automatic refusal, and the refusal was right at the time: an
            // import edge is sourced at the importing file's module entity,
            // whose span is the whole file, so the planner's only reachable
            // span found every mention of the name rather than the import site
            // and could not satisfy any count. FIR-1825 gave call sites spans
            // and left import sites without; this is its residual, FIR-2690.
            //
            // The question is no longer "is it imported" but "did the site
            // survive into the graph". Refuse only when it did not, so a store
            // indexed before import spans existed still refuses loudly rather
            // than renaming against evidence it does not have.
            let spanned_here = graph
                .get_all_relations_for_entity(&target.id)?
                .into_iter()
                .any(|relation| {
                    relation.dst == GraphNodeId::Entity(target.id)
                        && relation.kind == RelationKind::Imports
                        && relation.evidence.iter().any(|evidence| {
                            evidence
                                .source_span
                                .as_ref()
                                .is_some_and(|span| span.file == importer_file)
                        })
                });
            if !spanned_here {
                bail!(
                    "{} imports '{}', but graph import evidence has no exact source span; refusing to skip or guess at that edit site",
                    importer_file,
                    target.name
                );
            }
        }
        source_languages.insert(importer_file, indexed.language);
    }
    Ok(source_languages)
}

/// Prove that every identifier-shaped occurrence of the selected spelling in
/// every graph-owned source body is explained by either a declaration identity
/// or a rename-relevant graph edge. This is deliberately repository-CAS
/// accounting, never a working-tree search. It complements the graph's
/// positive extraction certificate and makes comments, strings, hidden dynamic
/// references, and unmodeled relation classes fail closed instead of being
/// silently stranded.
fn prove_repository_occurrence_accounting(
    graph: &kin_db::InMemoryGraph,
    target: &Entity,
    source_languages: &HashMap<FilePathId, LanguageId>,
    bodies: &HashMap<FilePathId, String>,
    edits: &[RenameEdit],
) -> Result<()> {
    let snapshot = graph.to_snapshot();
    let mut expected = HashMap::<EntityId, usize>::new();
    for entity in snapshot.entities.values() {
        if entity_leaf(&entity.name) == target.name {
            expected.insert(entity.id, 1);
        }
    }
    for relation in snapshot.relations.values() {
        if !rename_reference_kind(relation.kind) {
            continue;
        }
        let (Some(source_id), Some(target_id)) =
            (relation.src.as_entity(), relation.dst.as_entity())
        else {
            continue;
        };
        let Some(relation_target) = snapshot.entities.get(&target_id) else {
            bail!(
                "rename relation {} points at missing graph entity {}",
                relation.id,
                target_id
            );
        };
        if entity_leaf(&relation_target.name) != target.name {
            continue;
        }
        // The repository-wide accounting wants the TOTAL, span or no span. Its
        // observed side attributes every occurrence to the smallest entity span
        // containing it, so a top-level import statement lands on the module
        // entity, which is the same entity the import edge is sourced at. The
        // split matters to the planner, which searches per span; it does not
        // matter here, where both sides count whole entities.
        let (unspanned, spanned) = relation_occurrence_split(relation)?;
        let count = spanned
            .iter()
            .try_fold(unspanned, |total, (_, scoped)| total.checked_add(*scoped))
            .ok_or_else(|| anyhow::anyhow!("repository rename occurrence count overflow"))?;
        let entry = expected.entry(source_id).or_default();
        *entry = entry
            .checked_add(count)
            .ok_or_else(|| anyhow::anyhow!("repository rename occurrence count overflow"))?;
    }

    let planned = edits
        .iter()
        .map(|edit| (edit.file.clone(), edit.start_byte, edit.end_byte))
        .collect::<HashSet<_>>();
    let mut observed = HashMap::<EntityId, usize>::new();
    let mut observed_sites = HashSet::new();
    for (file, language) in source_languages {
        let body = bodies.get(file).ok_or_else(|| {
            anyhow::anyhow!("rename coverage body for graph source {file} was not retained")
        })?;
        if body.is_empty() {
            continue;
        }
        let whole_file = SourceSpan {
            file: file.clone(),
            start_byte: 0,
            end_byte: body.len(),
            start_line: 0,
            start_col: 0,
            end_line: 0,
            end_col: 0,
        };
        let occurrences = find_token_occurrences(body, &target.name, &whole_file, *language)?;
        let file_entities = snapshot
            .entities
            .values()
            .filter(|entity| entity.file_origin.as_ref() == Some(file))
            .filter_map(|entity| entity.span.as_ref().map(|span| (entity, span)))
            .collect::<Vec<_>>();
        for occurrence in occurrences {
            let owner = file_entities
                .iter()
                .filter(|(_, span)| {
                    span.start_byte <= occurrence.start_byte
                        && occurrence.end_byte <= span.end_byte
                })
                .min_by_key(|(_, span)| span.end_byte.saturating_sub(span.start_byte))
                .map(|(entity, _)| *entity)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "repository CAS contains unowned '{}' occurrence at {}:{}..{}; graph reference coverage is incomplete",
                        target.name,
                        file,
                        occurrence.start_byte,
                        occurrence.end_byte
                    )
                })?;
            *observed.entry(owner.id).or_default() += 1;
            observed_sites.insert((file.clone(), occurrence.start_byte, occurrence.end_byte));
        }
    }

    for entity_id in expected
        .keys()
        .chain(observed.keys())
        .copied()
        .collect::<BTreeSet<_>>()
    {
        let expected_count = expected.get(&entity_id).copied().unwrap_or(0);
        let observed_count = observed.get(&entity_id).copied().unwrap_or(0);
        if expected_count != observed_count {
            bail!(
                "exhaustive rename-reference coverage disagrees for graph entity {}: graph declarations and edges require {} '{}' occurrence(s), but repository CAS assigns {}; refusing a partial refactor",
                entity_id,
                expected_count,
                target.name,
                observed_count
            );
        }
    }
    if !planned.is_subset(&observed_sites) {
        bail!("rename plan contains an edit outside the exhaustive repository occurrence census");
    }
    Ok(())
}

fn entity_leaf(name: &str) -> &str {
    name.rsplit_once("::")
        .or_else(|| name.rsplit_once('.'))
        .map(|(_, leaf)| leaf)
        .unwrap_or(name)
}

struct ReferenceGroup {
    entity: Entity,
    /// Occurrences expected inside the SOURCE ENTITY's own span, from evidence
    /// that named no span of its own. This is every edge's behaviour before
    /// FIR-2690 and stays exactly that.
    expected: usize,
    /// Occurrences expected inside a span the evidence named itself.
    ///
    /// An entity-level import edge is sourced at the importing file's module
    /// entity, whose span is the whole file. Searching that span finds every
    /// mention of the name rather than the import site, so the count can never
    /// match and `kin rename` refused outright. Evidence that carries its own
    /// span is searched inside THAT span instead, which turns one impossible
    /// whole-file check into one exact check per import statement.
    scoped: Vec<(kin_model::SourceSpan, usize)>,
    kinds: BTreeSet<String>,
    relation_ids: BTreeSet<kin_model::RelationId>,
    declaration: bool,
}

impl ReferenceGroup {
    fn new(entity: Entity) -> Self {
        Self {
            entity,
            expected: 0,
            scoped: Vec::new(),
            kinds: BTreeSet::new(),
            relation_ids: BTreeSet::new(),
            declaration: false,
        }
    }
}

/// Split a relation's expected occurrences into the ones searched inside the
/// SOURCE ENTITY's span and the ones searched inside a span the evidence named.
///
/// Evidence that names no span behaves exactly as it always did: its count is
/// added to the entity-wide expectation. Evidence that names one is checked
/// inside that span alone, which is what makes an import edge renameable. An
/// import edge is sourced at a module entity spanning the whole file, so the
/// entity-wide search finds every mention of the name and the count can never
/// match; the import statement's own span contains exactly the occurrences the
/// evidence counted.
///
/// A relation with no evidence at all still expects one occurrence in the
/// entity span, unchanged.
fn relation_occurrence_split(
    relation: &Relation,
) -> Result<(usize, Vec<(kin_model::SourceSpan, usize)>)> {
    if relation.evidence.is_empty() {
        return Ok((1, Vec::new()));
    }
    let mut unspanned = 0_usize;
    let mut spanned = Vec::new();
    for evidence in &relation.evidence {
        let count = usize::try_from(evidence.occurrence_count)
            .context("rename relation occurrence count does not fit usize")?;
        if count == 0 {
            bail!(
                "rename relation {} carries a zero occurrence evidence record",
                relation.id
            );
        }
        match evidence.source_span.as_ref() {
            Some(span) => spanned.push((span.clone(), count)),
            None => {
                unspanned = unspanned
                    .checked_add(count)
                    .ok_or_else(|| anyhow::anyhow!("rename relation occurrence count overflow"))?
            }
        }
    }
    Ok((unspanned, spanned))
}

fn require_complete_layout(graph: &impl GraphStore, file: &FilePathId) -> Result<()> {
    let layout = graph.get_file_layout(file)?.ok_or_else(|| {
        anyhow::anyhow!(
            "rename source {} has no graph-owned file layout; exact token coverage is unproven",
            file
        )
    })?;
    if layout.parse_completeness != ParseCompleteness::Full {
        bail!(
            "rename source {} has {} parse coverage; full graph coverage is required",
            file,
            layout.parse_completeness.bucket()
        );
    }
    Ok(())
}

fn load_cached_body<'a, F>(
    tree: &kin_model::ResolvedTree,
    file: &FilePathId,
    bodies: &'a mut HashMap<FilePathId, String>,
    load_source: &mut F,
) -> Result<&'a str>
where
    F: FnMut(&RepoPath, Hash256) -> Result<Vec<u8>>,
{
    if !bodies.contains_key(file) {
        let path = RepoPath::from_utf8(file.0.clone())
            .with_context(|| format!("rename source {file} is not a valid repository path"))?;
        let artifact = tree.artifact_at_path(&path).ok_or_else(|| {
            anyhow::anyhow!("rename source {file} is absent from the exact workspace tree")
        })?;
        let hash = artifact.entry.blob_identity().ok_or_else(|| {
            anyhow::anyhow!("rename source {file} is not an immutable source blob")
        })?;
        let bytes = load_source(&path, hash).with_context(|| {
            format!("load repository-v6 source CAS body {hash} for rename source {file}")
        })?;
        if kin_blobs::digest_bytes(&bytes) != *hash.as_bytes() {
            bail!(
                "repository-v6 source CAS returned bytes with the wrong digest for {file}: expected {hash}"
            );
        }
        let content = String::from_utf8(bytes)
            .with_context(|| format!("rename source {file} is not valid UTF-8"))?;
        bodies.insert(file.clone(), content);
    }
    Ok(bodies
        .get(file)
        .expect("rename body was inserted before lookup"))
}

fn resolve_target<F>(
    graph: &impl GraphStore,
    request: &RenameRequest,
    tree: &kin_model::ResolvedTree,
    bodies: &mut HashMap<FilePathId, String>,
    load_source: &mut F,
) -> Result<Entity>
where
    F: FnMut(&RepoPath, Hash256) -> Result<Vec<u8>>,
{
    let leaf = entity_leaf(&request.symbol);
    let mut matches = graph.query_entities(&EntityFilter {
        name_pattern: Some(leaf.to_string()),
        ..EntityFilter::default()
    })?;
    matches.retain(|entity| entity.name == request.symbol || entity.name == leaf);
    if let Some(file) = request.file.as_deref() {
        let normalized = normalize_repo_hint(file);
        if let Some(user_line) = request.line {
            let graph_line = user_line - 1;
            let mut containing = graph
                .query_entities(&EntityFilter {
                    file_path: Some(FilePathId::new(normalized.clone())),
                    ..EntityFilter::default()
                })?
                .into_iter()
                .filter(|entity| {
                    entity
                        .span
                        .as_ref()
                        .is_some_and(|span| span_contains(span, graph_line, request.column))
                })
                .collect::<Vec<_>>();
            containing.sort_by_key(|entity| {
                (
                    entity
                        .span
                        .as_ref()
                        .map(|span| span.end_byte.saturating_sub(span.start_byte))
                        .unwrap_or(usize::MAX),
                    entity.id,
                )
            });
            if containing.is_empty() {
                bail!(
                    "no graph source entity contains {}:{}; rename file/line hint cannot be proven",
                    normalized,
                    user_line
                );
            }

            // A same-named declaration is eligible only when the cursor is
            // inside that declaration's own graph span. Never keep another
            // declaration merely because it shares the file and spelling.
            let containing_ids = containing
                .iter()
                .map(|entity| entity.id)
                .collect::<HashSet<_>>();
            let mut declarations = Vec::new();
            for candidate in &matches {
                if containing_ids.contains(&candidate.id)
                    && cursor_hits_declaration(
                        candidate,
                        user_line,
                        request.column,
                        tree,
                        bodies,
                        load_source,
                    )?
                {
                    declarations.push(candidate.clone());
                }
            }
            if !declarations.is_empty() {
                matches = declarations;
            } else {
                // Resolve from the smallest containing source entity first. If
                // a nested scope has no applicable edge, move outward one
                // owner at a time; never combine unrelated scope candidates.
                let mut related = Vec::new();
                for owner in containing {
                    let targets = graph
                        .get_all_relations_for_entity(&owner.id)?
                        .into_iter()
                        .filter(|relation| {
                            relation.src == GraphNodeId::Entity(owner.id)
                                && rename_reference_kind(relation.kind)
                        })
                        .filter_map(|relation| relation.dst.as_entity())
                        .collect::<HashSet<_>>();
                    related = matches
                        .iter()
                        .filter(|entity| targets.contains(&entity.id))
                        .cloned()
                        .collect::<Vec<_>>();
                    if !related.is_empty() {
                        break;
                    }
                }
                if related.is_empty() {
                    bail!(
                        "entity '{}' is not graph-linked from {}:{}; rename file/line hint cannot be proven",
                        request.symbol,
                        normalized,
                        user_line
                    );
                }
                matches = related;
            }
        } else {
            let declarations = matches
                .iter()
                .filter(|entity| {
                    entity
                        .file_origin
                        .as_ref()
                        .is_some_and(|origin| origin.0 == normalized)
                })
                .cloned()
                .collect::<Vec<_>>();
            if declarations.is_empty() {
                return Err(anyhow::anyhow!(
                    "entity '{}' is not declared in graph file {}; provide a declaration file or a graph-linked --line cursor",
                    request.symbol,
                    normalized
                ));
            }
            matches = declarations;
        }
    }
    matches.sort_by_key(|entity| {
        (
            entity.file_origin.as_ref().map(|file| file.0.clone()),
            entity.span.as_ref().map(|span| span.start_byte),
            entity.id,
        )
    });
    matches.dedup_by_key(|entity| entity.id);
    match matches.as_slice() {
        [] => bail!(
            "entity '{}' not found in repository-v6 graph authority",
            request.symbol
        ),
        [target] => Ok(target.clone()),
        candidates => {
            let choices = candidates
                .iter()
                .map(|entity| {
                    format!(
                        "{}:{}",
                        entity
                            .file_origin
                            .as_ref()
                            .map(|file| file.0.as_str())
                            .unwrap_or("<graph-only>"),
                        entity
                            .span
                            .as_ref()
                            .map(|span| span.start_line + 1)
                            .unwrap_or(0)
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");
            bail!(
                "entity '{}' is ambiguous across {} graph identities ({choices}); provide --file and --line",
                request.symbol,
                candidates.len()
            )
        }
    }
}

fn cursor_hits_declaration<F>(
    candidate: &Entity,
    user_line: u32,
    byte_column: Option<u32>,
    tree: &kin_model::ResolvedTree,
    bodies: &mut HashMap<FilePathId, String>,
    load_source: &mut F,
) -> Result<bool>
where
    F: FnMut(&RepoPath, Hash256) -> Result<Vec<u8>>,
{
    let file = candidate.file_origin.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "cursor declaration candidate {} has no graph source file",
            candidate.id
        )
    })?;
    let span = candidate.span.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "cursor declaration candidate {} has no graph source span",
            candidate.id
        )
    })?;
    let body = load_cached_body(tree, file, bodies, load_source)?;
    let leaf = entity_leaf(&candidate.name);
    let occurrences = find_token_occurrences(body, leaf, span, candidate.language)?;
    let Some(declaration) = occurrences.first() else {
        bail!(
            "graph declaration {} named '{}' has no exact identifier token in its repository-CAS span",
            candidate.id,
            candidate.name
        );
    };
    if declaration.start_line != user_line {
        return Ok(false);
    }
    Ok(byte_column
        .is_none_or(|column| declaration.start_col <= column && column < declaration.end_col))
}

fn reject_local_name_collision(
    graph: &impl GraphStore,
    target: &Entity,
    new_name: &str,
) -> Result<()> {
    let collisions = graph.query_entities(&EntityFilter {
        name_pattern: Some(new_name.to_string()),
        ..EntityFilter::default()
    })?;
    if let Some(collision) = collisions.into_iter().find(|entity| {
        entity.id != target.id && entity.name == new_name && entity.kind == target.kind
    }) {
        bail!(
            "rename would collide with graph entity {} named '{}' in {}; cross-file namespace equivalence is unproven",
            collision.id,
            new_name,
            collision
                .file_origin
                .as_ref()
                .map(|file| file.0.as_str())
                .unwrap_or("<graph-only>")
        );
    }
    Ok(())
}

fn rename_reference_kind(kind: RelationKind) -> bool {
    matches!(
        kind,
        RelationKind::Extends
            | RelationKind::Implements
            | RelationKind::Overrides
            | RelationKind::Calls
            | RelationKind::Instantiates
            | RelationKind::References
            | RelationKind::UsesMacro
            | RelationKind::UsesType
            | RelationKind::Imports
            | RelationKind::EmitsEvent
            | RelationKind::SubscribesTo
            | RelationKind::DefinesContract
            | RelationKind::ConsumesContract
            | RelationKind::SendsMessage
            | RelationKind::Spawns
            | RelationKind::Tests
            | RelationKind::Covers
    )
}

fn relation_reason(kinds: &BTreeSet<String>) -> String {
    let labels = kinds.iter().cloned().collect::<Vec<_>>().join("+");
    format!("graph-reference:{labels}")
}

#[derive(Clone, Copy)]
struct TokenOccurrence {
    start_byte: usize,
    end_byte: usize,
    start_line: u32,
    start_col: u32,
    end_line: u32,
    end_col: u32,
}

fn find_token_occurrences(
    content: &str,
    symbol: &str,
    span: &SourceSpan,
    language: LanguageId,
) -> Result<Vec<TokenOccurrence>> {
    if span.start_byte >= span.end_byte || span.end_byte > content.len() {
        bail!(
            "graph source span {}..{} for {} is outside its {}-byte repository CAS body",
            span.start_byte,
            span.end_byte,
            span.file,
            content.len()
        );
    }
    if !content.is_char_boundary(span.start_byte) || !content.is_char_boundary(span.end_byte) {
        bail!(
            "graph source span for {} is not on UTF-8 boundaries",
            span.file
        );
    }
    let mut line_starts = vec![0_usize];
    for (index, byte) in content.bytes().enumerate() {
        if byte == b'\n' {
            line_starts.push(index + 1);
        }
    }
    let mut occurrences = Vec::new();
    for (relative, _) in content[span.start_byte..span.end_byte].match_indices(symbol) {
        let start = span.start_byte + relative;
        let end = start + symbol.len();
        if !is_symbol_boundary(content, start, symbol.len(), language) {
            continue;
        }
        let line_index = line_starts.partition_point(|line_start| *line_start <= start) - 1;
        let line_start = line_starts[line_index];
        let end_line_index = line_starts.partition_point(|line_start| *line_start <= end) - 1;
        let end_line_start = line_starts[end_line_index];
        occurrences.push(TokenOccurrence {
            start_byte: start,
            end_byte: end,
            start_line: u32::try_from(line_index + 1).context("source line exceeds u32")?,
            start_col: u32::try_from(start - line_start).context("source column exceeds u32")?,
            end_line: u32::try_from(end_line_index + 1).context("source line exceeds u32")?,
            end_col: u32::try_from(end - end_line_start).context("source column exceeds u32")?,
        });
    }
    Ok(occurrences)
}

fn is_symbol_boundary(
    content: &str,
    start: usize,
    symbol_len: usize,
    language: LanguageId,
) -> bool {
    let before = content[..start].chars().next_back();
    let after = content[start + symbol_len..].chars().next();
    before.is_none_or(|character| !is_identifier_continue(language, character))
        && after.is_none_or(|character| !is_identifier_continue(language, character))
}

fn span_contains(span: &SourceSpan, graph_line: u32, byte_column: Option<u32>) -> bool {
    if graph_line < span.start_line || graph_line > span.end_line {
        return false;
    }
    let Some(byte_column) = byte_column else {
        return graph_line < span.end_line || span.end_col > 0;
    };
    (graph_line > span.start_line || byte_column >= span.start_col)
        && (graph_line < span.end_line || byte_column < span.end_col)
}

fn looks_like_identifier(candidate: &str) -> bool {
    let mut characters = candidate.chars();
    let Some(first) = characters.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || matches!(first, '_' | '$'))
        && characters.all(|character| is_identifier_continue(LanguageId::TypeScript, character))
}

fn is_identifier_continue(_language: LanguageId, character: char) -> bool {
    // Unicode XID is the common safe core across the supported language
    // families. The extras are a conservative superset used only as a
    // boundary refusal: accepting too much here can reject a rename, while
    // accepting too little can splice an ASCII leaf out of a larger identifier.
    unicode_ident::is_xid_continue(character)
        || matches!(character, '_' | '$' | '\u{200c}' | '\u{200d}' | '?' | '!')
}

fn validate_cursor(file: Option<&str>, line: Option<u32>, column: Option<u32>) -> Result<()> {
    if line == Some(0) {
        bail!("--line is 1-based and must be greater than zero");
    }
    if column.is_some() && line.is_none() {
        bail!("--column requires --line and is measured in 0-based UTF-8 bytes");
    }
    if line.is_some() && file.is_none() {
        bail!("--line requires --file so the cursor coordinate has one graph source domain");
    }
    Ok(())
}

fn normalize_file_hint(layout: &kin_core::KinLayout, hint: &str) -> String {
    let normalized = hint.replace('\\', "/");
    let path = std::path::Path::new(&normalized);
    if path.is_absolute() {
        if let Ok(relative) = path.strip_prefix(layout.working_dir()) {
            return relative.to_string_lossy().replace('\\', "/");
        }
    }
    normalize_repo_hint(&normalized)
}

fn normalize_repo_hint(hint: &str) -> String {
    let normalized = hint.replace('\\', "/");
    let relative = normalized.trim_start_matches("./");
    relative
        .strip_prefix(".kin/source-root/")
        .unwrap_or(relative)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_occurrences_are_byte_exact_and_identifier_bounded() {
        let file = FilePathId::new("src/lib.rs");
        let source = "fn target() { target(); target_extra(); }\n";
        let span = SourceSpan {
            file,
            start_byte: 0,
            end_byte: source.len(),
            start_line: 1,
            start_col: 0,
            end_line: 1,
            end_col: source.len() as u32,
        };
        let occurrences =
            find_token_occurrences(source, "target", &span, LanguageId::Rust).unwrap();
        assert_eq!(occurrences.len(), 2);
        assert_eq!(
            &source[occurrences[0].start_byte..occurrences[0].end_byte],
            "target"
        );
        assert_eq!(
            &source[occurrences[1].start_byte..occurrences[1].end_byte],
            "target"
        );
    }

    #[test]
    fn unicode_identifier_neighbors_are_not_ascii_token_boundaries() {
        let file = FilePathId::new("caller.py");
        let source = "def caller():\n    return éfoo() + fooé()\n";
        let span = SourceSpan {
            file,
            start_byte: 0,
            end_byte: source.len(),
            start_line: 0,
            start_col: 0,
            end_line: 1,
            end_col: 31,
        };
        assert!(
            find_token_occurrences(source, "foo", &span, LanguageId::Python)
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn cursor_coordinates_are_one_based_lines_and_exclusive_byte_columns() {
        assert!(validate_cursor(Some("src/lib.rs"), Some(1), Some(0)).is_ok());
        assert!(validate_cursor(Some("src/lib.rs"), Some(0), None).is_err());
        assert!(validate_cursor(Some("src/lib.rs"), None, Some(0)).is_err());
        assert!(validate_cursor(None, Some(1), None).is_err());

        let span = SourceSpan {
            file: FilePathId::new("src/lib.rs"),
            start_byte: 2,
            end_byte: 8,
            start_line: 0,
            start_col: 2,
            end_line: 0,
            end_col: 8,
        };
        assert!(span_contains(&span, 0, Some(2)));
        assert!(span_contains(&span, 0, Some(7)));
        assert!(!span_contains(&span, 0, Some(8)));
    }

    #[test]
    fn zero_occurrence_evidence_is_rejected() {
        let relation = Relation {
            id: kin_model::RelationId::new(),
            kind: RelationKind::Calls,
            src: GraphNodeId::Entity(EntityId::new()),
            dst: GraphNodeId::Entity(EntityId::new()),
            confidence: 1.0,
            origin: kin_model::RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
            evidence: vec![kin_model::RelationEvidence {
                occurrence_count: 0,
                ..kin_model::RelationEvidence::default()
            }],
        };
        assert!(relation_occurrence_split(&relation)
            .unwrap_err()
            .to_string()
            .contains("zero occurrence"));
    }
}
