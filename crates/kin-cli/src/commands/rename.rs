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
    GraphStore, Hash256, OperationId, ParseCompleteness, Relation, RelationKind, RepoPath,
    SourceSpan,
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
    let layout = crate::commands::require_repository_layout()?;
    let daemon_url = crate::daemon_client::resolve_daemon_url(&layout)
        .await?
        .ok_or_else(|| {
            anyhow::anyhow!("Kin daemon is required for rename but no daemon endpoint is available")
        })?;
    let request = RenameRequest {
        symbol,
        new_name,
        file: file.map(|hint| normalize_file_hint(&layout, &hint)),
        line,
        column,
        json,
        operation_id: OperationId::new(),
        actor: AuthorId::new(kin_core::whoami()),
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
    if !looks_like_identifier(&request.new_name) {
        bail!(
            "rename target '{}' is not a simple source identifier",
            request.new_name
        );
    }
    let target = resolve_target(graph, request)?;
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

    let tree = graph.resolved_tree();
    let mut bodies = HashMap::<FilePathId, String>::new();
    reject_unspanned_import_sites(graph, &target, &tree, &mut bodies, &mut load_source)?;

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
        let expected = relation_occurrence_count(&relation)?;
        let group = grouped
            .entry(source_id)
            .or_insert_with(|| ReferenceGroup::new(source));
        group.expected = group
            .expected
            .checked_add(expected)
            .ok_or_else(|| anyhow::anyhow!("rename reference occurrence count overflow"))?;
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
        let occurrences = find_token_occurrences(body, &target.name, span)?;
        if occurrences.len() != group.expected {
            bail!(
                "rename authority is incomplete for entity {} in {}: graph relations plus declaration require {} '{}' occurrence(s) inside the exact source span, but repository CAS contains {}; refusing a partial or over-broad edit",
                group.entity.id,
                file,
                group.expected,
                target.name,
                occurrences.len()
            );
        }
        let reason = if group.declaration && group.kinds.is_empty() {
            "declaration".to_string()
        } else if group.declaration {
            format!("declaration+{}", relation_reason(&group.kinds))
        } else {
            relation_reason(&group.kinds)
        };
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
                declaration: group.declaration && occurrence_index == 0,
            });
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

fn reject_unspanned_import_sites<F>(
    graph: &kin_db::InMemoryGraph,
    target: &Entity,
    tree: &kin_model::ResolvedTree,
    bodies: &mut HashMap<FilePathId, String>,
    load_source: &mut F,
) -> Result<()>
where
    F: FnMut(&RepoPath, Hash256) -> Result<Vec<u8>>,
{
    let pipeline = kin_index::IndexPipeline::new();
    let layouts = graph
        .list_file_layouts()?
        .into_iter()
        .map(|layout| (layout.file_id.clone(), layout))
        .collect::<HashMap<_, _>>();
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
    for layout in layouts.into_values() {
        let importer_file = layout.file_id;
        if layout.parse_completeness != ParseCompleteness::Full {
            bail!(
                "graph source {} has {} parse coverage; repository-wide import rename coverage is unproven",
                importer_file,
                layout.parse_completeness.bucket()
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
            bail!(
                "{} imports '{}', but graph import evidence has no exact source span; refusing to skip or guess at that edit site",
                importer_file,
                target.name
            );
        }
    }
    Ok(())
}

struct ReferenceGroup {
    entity: Entity,
    expected: usize,
    kinds: BTreeSet<String>,
    relation_ids: BTreeSet<kin_model::RelationId>,
    declaration: bool,
}

impl ReferenceGroup {
    fn new(entity: Entity) -> Self {
        Self {
            entity,
            expected: 0,
            kinds: BTreeSet::new(),
            relation_ids: BTreeSet::new(),
            declaration: false,
        }
    }
}

fn relation_occurrence_count(relation: &Relation) -> Result<usize> {
    if relation.evidence.is_empty() {
        return Ok(1);
    }
    relation
        .evidence
        .iter()
        .try_fold(0_usize, |total, evidence| {
            let count = usize::try_from(evidence.occurrence_count)
                .context("rename relation occurrence count does not fit usize")?;
            if count == 0 {
                bail!(
                    "rename relation {} carries a zero occurrence evidence record",
                    relation.id
                );
            }
            total
                .checked_add(count)
                .ok_or_else(|| anyhow::anyhow!("rename relation occurrence count overflow"))
        })
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

fn resolve_target(graph: &impl GraphStore, request: &RenameRequest) -> Result<Entity> {
    let leaf = request
        .symbol
        .rsplit_once("::")
        .or_else(|| request.symbol.rsplit_once('.'))
        .map(|(_, leaf)| leaf)
        .unwrap_or(&request.symbol);
    let mut matches = graph.query_entities(&EntityFilter {
        name_pattern: Some(leaf.to_string()),
        ..EntityFilter::default()
    })?;
    matches.retain(|entity| entity.name == request.symbol || entity.name == leaf);
    if let Some(file) = request.file.as_deref() {
        let normalized = normalize_repo_hint(file);
        let at_file = matches
            .iter()
            .filter(|entity| {
                entity
                    .file_origin
                    .as_ref()
                    .is_some_and(|origin| origin.0 == normalized)
            })
            .cloned()
            .collect::<Vec<_>>();
        if !at_file.is_empty() {
            matches = at_file;
        } else if let Some(line) = request.line {
            let containing = graph
                .query_entities(&EntityFilter {
                    file_path: Some(FilePathId::new(normalized.clone())),
                    ..EntityFilter::default()
                })?
                .into_iter()
                .filter(|entity| {
                    entity
                        .span
                        .as_ref()
                        .is_some_and(|span| span_contains(span, line, request.column))
                })
                .min_by_key(|entity| {
                    entity
                        .span
                        .as_ref()
                        .map(|span| span.end_byte.saturating_sub(span.start_byte))
                        .unwrap_or(usize::MAX)
                });
            let containing = containing.ok_or_else(|| {
                anyhow::anyhow!(
                    "no graph source entity contains {}:{}; rename file/line hint cannot be proven",
                    normalized,
                    line
                )
            })?;
            let targets = graph
                .get_all_relations_for_entity(&containing.id)?
                .into_iter()
                .filter(|relation| {
                    relation.src == GraphNodeId::Entity(containing.id)
                        && rename_reference_kind(relation.kind)
                })
                .filter_map(|relation| relation.dst.as_entity())
                .collect::<HashSet<_>>();
            let related = matches
                .iter()
                .filter(|entity| targets.contains(&entity.id))
                .cloned()
                .collect::<Vec<_>>();
            if related.is_empty() {
                bail!(
                    "entity '{}' is not graph-linked from {}:{}; rename file/line hint cannot be proven",
                    request.symbol,
                    normalized,
                    line
                );
            }
            matches = related;
        } else {
            bail!(
                "entity '{}' is not declared in graph file {}; provide a declaration file or a graph-linked --line cursor",
                request.symbol,
                normalized
            );
        }
    }
    if let Some(line) = request.line {
        let containing = matches
            .iter()
            .filter(|entity| {
                entity
                    .span
                    .as_ref()
                    .is_some_and(|span| span_contains(span, line, request.column))
            })
            .cloned()
            .collect::<Vec<_>>();
        if !containing.is_empty() {
            matches = containing;
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
                            .map(|span| span.start_line)
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
        if !is_symbol_boundary(content, start, symbol.len()) {
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

fn is_symbol_boundary(content: &str, start: usize, symbol_len: usize) -> bool {
    let before = content[..start].chars().next_back();
    let after = content[start + symbol_len..].chars().next();
    before.is_none_or(|character| !is_identifier_char(character))
        && after.is_none_or(|character| !is_identifier_char(character))
}

fn span_contains(span: &SourceSpan, line: u32, column: Option<u32>) -> bool {
    if line < span.start_line || line > span.end_line {
        return false;
    }
    let Some(column) = column else { return true };
    (line != span.start_line || column >= span.start_col)
        && (line != span.end_line || column <= span.end_col)
}

fn looks_like_identifier(candidate: &str) -> bool {
    let mut characters = candidate.chars();
    let Some(first) = characters.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || matches!(first, '_' | '$'))
        && characters.all(is_identifier_char)
}

fn is_identifier_char(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '_' | '$')
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
        let occurrences = find_token_occurrences(source, "target", &span).unwrap();
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
        assert!(relation_occurrence_count(&relation)
            .unwrap_err()
            .to_string()
            .contains("zero occurrence"));
    }
}
