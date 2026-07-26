// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result};
use kin_model::{
    Entity, EntityFilter, EntityId, FilePathId, GraphNodeId, GraphStore, RelationKind, SourceSpan,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

#[derive(Serialize)]
struct RenameEntityJson {
    kind: String,
    name: String,
    file: String,
    line: u32,
    signature: Option<String>,
}

#[derive(Serialize)]
struct RenameEditJson {
    file: String,
    #[serde(rename = "startLine")]
    start_line: u32,
    #[serde(rename = "startCol")]
    start_col: u32,
    #[serde(rename = "endLine")]
    end_line: u32,
    #[serde(rename = "endCol")]
    end_col: u32,
    #[serde(rename = "oldText")]
    old_text: String,
    #[serde(rename = "newText")]
    new_text: String,
    reason: String,
}

#[derive(Serialize)]
struct RenamePlanJson {
    entity: RenameEntityJson,
    #[serde(rename = "newName")]
    new_name: String,
    edits: Vec<RenameEditJson>,
    warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RenameResponse {
    #[serde(default)]
    pub lines: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub json: Option<String>,
}

pub async fn run(
    symbol: String,
    new_name: String,
    file: Option<String>,
    line: Option<u32>,
    column: Option<u32>,
    json: bool,
) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let response = run_daemon_rename(
        &layout,
        &RenameRequest {
            symbol,
            new_name,
            file,
            line,
            column,
            json,
        },
    )
    .await?;
    if let Some(json) = response.json {
        println!("{json}");
    } else {
        for line in response.lines {
            println!("{line}");
        }
    }
    Ok(())
}

async fn run_daemon_rename(
    layout: &kin_core::KinLayout,
    request: &RenameRequest,
) -> Result<RenameResponse> {
    let daemon_url = std::env::var("KIN_DAEMON_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(Some)
        .unwrap_or(crate::daemon_client::resolve_daemon_url(layout).await?);
    let base_url = daemon_url.ok_or_else(|| {
        anyhow::anyhow!("Kin daemon is required for rename but no daemon endpoint is available")
    })?;
    let client = crate::daemon_client::DaemonClient::from_base_url(base_url)?;
    client.rename(request).await.context("daemon rename failed")
}

pub fn build_rename_response(
    layout: &kin_core::KinLayout,
    graph: &kin_db::InMemoryGraph,
    request: &RenameRequest,
) -> Result<RenameResponse> {
    let target = resolve_target(
        layout,
        graph,
        &request.symbol,
        request.file.as_deref(),
        request.line,
        request.column,
    )?
    .ok_or_else(|| anyhow::anyhow!("entity '{}' not found", request.symbol))?;
    let plan = build_rename_plan(layout, graph, &target, &request.new_name)?;

    if request.json {
        Ok(RenameResponse {
            lines: Vec::new(),
            json: Some(serde_json::to_string(&plan)?),
        })
    } else {
        let mut lines = vec![
            format!(
                "Rename plan for {} ({}) -> {}",
                plan.entity.name, plan.entity.kind, plan.new_name
            ),
            format!(
                "{} edit(s) across {} file(s)",
                plan.edits.len(),
                unique_file_count(&plan.edits)
            ),
        ];
        for edit in &plan.edits {
            lines.push(format!(
                "  {}:{}:{} {} -> {} ({})",
                edit.file,
                edit.start_line,
                edit.start_col,
                edit.old_text,
                edit.new_text,
                edit.reason
            ));
        }
        if !plan.warnings.is_empty() {
            lines.push(String::new());
            lines.push("Warnings:".to_string());
            for warning in &plan.warnings {
                lines.push(format!("  - {}", warning));
            }
        }
        Ok(RenameResponse { lines, json: None })
    }
}

fn build_rename_plan(
    layout: &kin_core::KinLayout,
    graph: &impl GraphStore,
    target: &Entity,
    new_name: &str,
) -> Result<RenamePlanJson> {
    let mut warnings = Vec::new();
    if target.name == new_name {
        warnings.push("new name matches the existing name; plan is a no-op".to_string());
    }
    if !looks_like_identifier(new_name) {
        warnings.push(
            "new name does not look like a simple identifier; review language-specific syntax before applying"
                .to_string(),
        );
    }

    let mut edits = Vec::new();
    let mut seen = HashSet::new();
    let mut reader = GraphSourceReader::new(layout, graph)?;
    // Gaps are collected in a sorted set so a plan reports the same warnings in
    // the same order regardless of relation iteration order.
    let mut reference_gaps = BTreeSet::new();

    if let (Some(file_origin), Some(span)) = (&target.file_origin, &target.span) {
        // A gap on the declaration file is fatal: without graph-owned bytes for
        // it there is no trustworthy anchor for any edit, and emitting a plan
        // built from whatever the working tree happens to hold is exactly the
        // silent-miscoordinate failure this path must not have.
        add_first_span_edit(
            layout,
            &mut reader,
            &file_origin.0,
            span.start_byte,
            span.end_byte,
            &target.name,
            new_name,
            "declaration".to_string(),
            &mut edits,
            &mut seen,
        )
        .map_err(|GraphContentGap(reason)| {
            anyhow::anyhow!(
                "graph gap: cannot anchor the rename of '{}' because graph truth cannot supply the contents of its declaration file '{}': {reason}. Rename coordinates are measured against graph-owned bytes, never the working tree — re-ingest the repo so the file's content is recorded in graph truth",
                target.name,
                file_origin.0
            )
        })?;
    } else {
        warnings.push(
            "target entity has no stable file/span; declaration edit could not be anchored"
                .to_string(),
        );
    }

    for rel in graph.get_all_relations_for_entity(&target.id)? {
        if rel.dst != GraphNodeId::Entity(target.id)
            || !matches!(
                rel.kind,
                RelationKind::Calls | RelationKind::Imports | RelationKind::References
            )
        {
            continue;
        }
        if let Some(source_id) = rel.src.as_entity() {
            if let Some(source) = graph.get_entity(&source_id)? {
                if let (Some(file_origin), Some(span)) = (&source.file_origin, &source.span) {
                    // A gap on a referencing file leaves the plan incomplete
                    // rather than unusable, so it is reported as a named
                    // warning. It is never backfilled from the working tree.
                    if let Err(GraphContentGap(reason)) = add_span_edits(
                        layout,
                        &mut reader,
                        &file_origin.0,
                        span.start_byte,
                        span.end_byte,
                        &target.name,
                        new_name,
                        relation_reason(&[rel.kind]),
                        &mut edits,
                        &mut seen,
                    ) {
                        reference_gaps.insert(format!(
                            "graph gap: references in '{}' were not planned because graph truth cannot supply its contents: {reason}",
                            file_origin.0
                        ));
                    }
                }
            }
        }
    }

    warnings.extend(reference_gaps);

    edits.sort_by(|left, right| {
        left.file
            .cmp(&right.file)
            .then(left.start_line.cmp(&right.start_line))
            .then(left.start_col.cmp(&right.start_col))
    });

    if edits.is_empty() {
        warnings
            .push("no semantically anchored occurrences were found for this symbol".to_string());
    } else {
        warnings.push(
            "coordinates are token-boundary matches measured against graph-owned file content inside semantically selected declaration and reference spans; a working tree that has drifted from graph truth must be reconciled before the plan is applied"
                .to_string(),
        );
    }

    Ok(RenamePlanJson {
        entity: RenameEntityJson {
            kind: format!("{:?}", target.kind),
            name: target.name.clone(),
            file: target
                .file_origin
                .as_ref()
                .map(|f| display_read_path(layout, &f.0))
                .unwrap_or_default(),
            line: target
                .span
                .as_ref()
                .map(|span| span.start_line)
                .unwrap_or(0),
            signature: (!target.signature.is_empty()).then(|| target.signature.clone()),
        },
        new_name: new_name.to_string(),
        edits,
        warnings,
    })
}

fn resolve_target(
    layout: &kin_core::KinLayout,
    graph: &impl GraphStore,
    symbol: &str,
    file_hint: Option<&str>,
    line_hint: Option<u32>,
    column_hint: Option<u32>,
) -> Result<Option<Entity>> {
    let mut matches = graph.query_entities(&EntityFilter {
        name_pattern: Some(symbol.to_string()),
        ..Default::default()
    })?;

    if matches.is_empty() {
        if let Some((_, leaf)) = symbol.rsplit_once("::").or_else(|| symbol.rsplit_once('.')) {
            matches = graph.query_entities(&EntityFilter {
                name_pattern: Some(leaf.to_string()),
                ..Default::default()
            })?;
        }
    }

    if matches.is_empty() {
        return Ok(None);
    }

    let normalized_file_hint = file_hint.and_then(|hint| normalize_file_hint(layout, hint));
    let containing = find_containing_entity(
        graph,
        normalized_file_hint.as_deref(),
        line_hint,
        column_hint,
    )?;
    let containing_targets = containing
        .as_ref()
        .map(|entity| outgoing_relation_targets(graph, &entity.id))
        .transpose()?
        .unwrap_or_default();
    matches.sort_by_key(|entity| {
        let declaration_match = normalized_file_hint
            .as_ref()
            .and_then(|hint| {
                entity.file_origin.as_ref().and_then(|file| {
                    entity
                        .span
                        .as_ref()
                        .map(|span| file.0 == *hint && span_contains(span, line_hint, column_hint))
                })
            })
            .unwrap_or(false);
        let relation_match = containing_targets.contains(&entity.id);
        let same_file = normalized_file_hint
            .as_ref()
            .and_then(|hint| entity.file_origin.as_ref().map(|file| file.0 == *hint))
            .unwrap_or(false);
        let line_match = entity
            .span
            .as_ref()
            .map(|span| span_contains(span, line_hint, column_hint))
            .unwrap_or(false);
        let exact = entity.name == symbol;
        let suffix = entity.name.ends_with(&format!(".{symbol}"))
            || entity.name.ends_with(&format!("::{symbol}"));
        (
            !declaration_match,
            !relation_match,
            !line_match,
            !same_file,
            !exact,
            !suffix,
            entity.name.len(),
            entity
                .span
                .as_ref()
                .map(|span| span.start_line)
                .unwrap_or(u32::MAX),
        )
    });

    Ok(matches.into_iter().next())
}

fn add_span_edits<G: GraphStore>(
    layout: &kin_core::KinLayout,
    reader: &mut GraphSourceReader<'_, G>,
    rel_path: &str,
    start_byte: usize,
    end_byte: usize,
    old_name: &str,
    new_name: &str,
    reason: String,
    edits: &mut Vec<RenameEditJson>,
    seen: &mut HashSet<String>,
) -> Result<(), GraphContentGap> {
    let occurrences = {
        let content = reader.content(rel_path)?;
        find_token_occurrences(content, old_name, Some((start_byte, end_byte)))
    };
    for occurrence in occurrences {
        push_edit(
            layout,
            rel_path,
            occurrence.start_line,
            occurrence.start_col,
            occurrence.end_line,
            occurrence.end_col,
            old_name,
            new_name,
            reason.clone(),
            edits,
            seen,
        );
    }
    Ok(())
}

fn add_first_span_edit<G: GraphStore>(
    layout: &kin_core::KinLayout,
    reader: &mut GraphSourceReader<'_, G>,
    rel_path: &str,
    start_byte: usize,
    end_byte: usize,
    old_name: &str,
    new_name: &str,
    reason: String,
    edits: &mut Vec<RenameEditJson>,
    seen: &mut HashSet<String>,
) -> Result<(), GraphContentGap> {
    let occurrence = {
        let content = reader.content(rel_path)?;
        find_token_occurrences(content, old_name, Some((start_byte, end_byte)))
            .into_iter()
            .next()
    };
    if let Some(occurrence) = occurrence {
        push_edit(
            layout,
            rel_path,
            occurrence.start_line,
            occurrence.start_col,
            occurrence.end_line,
            occurrence.end_col,
            old_name,
            new_name,
            reason.clone(),
            edits,
            seen,
        );
    }
    Ok(())
}

fn push_edit(
    layout: &kin_core::KinLayout,
    rel_path: &str,
    start_line: u32,
    start_col: u32,
    end_line: u32,
    end_col: u32,
    old_name: &str,
    new_name: &str,
    reason: String,
    edits: &mut Vec<RenameEditJson>,
    seen: &mut HashSet<String>,
) {
    let key = format!("{rel_path}:{start_line}:{start_col}:{end_line}:{end_col}");
    if !seen.insert(key) {
        return;
    }
    edits.push(RenameEditJson {
        file: display_read_path(layout, rel_path),
        start_line,
        start_col,
        end_line,
        end_col,
        old_text: old_name.to_string(),
        new_text: new_name.to_string(),
        reason,
    });
}

/// A file the graph cannot supply, carrying the reason it could not.
///
/// Kept distinct from a plan-level error so a gap in one referencing file is
/// reported in the plan's warnings while a gap on the declaration file, which
/// no plan can be anchored without, fails the command outright.
struct GraphContentGap(String);

/// Supplies the file bytes a rename plan's coordinates are measured against,
/// resolved from graph-owned truth alone.
///
/// Rename is a mutation-planning authority path: every line and column it emits
/// becomes an edit. Measuring them against the working tree makes a tree that
/// has drifted from the graph — an un-ingested edit, a stale checkout, a
/// partially reconciled projection — silently yield coordinates that point at
/// the wrong bytes. So content is addressed by the hash the graph recorded for
/// the file and read from the content-addressed blob store, which verifies the
/// bytes against that address on read. A file the graph cannot supply is
/// reported as a gap; it is never filled in from disk.
struct GraphSourceReader<'a, G: GraphStore> {
    layout: &'a kin_core::KinLayout,
    graph: &'a G,
    blobs: kin_blobs::BlobStore,
    contents: HashMap<String, Result<String, String>>,
}

impl<'a, G: GraphStore> GraphSourceReader<'a, G> {
    fn new(layout: &'a kin_core::KinLayout, graph: &'a G) -> Result<Self> {
        Ok(Self {
            layout,
            graph,
            blobs: kin_blobs::BlobStore::new(layout.objects_dir()).context(
                "graph blob store is unavailable; rename cannot read graph-owned source",
            )?,
            contents: HashMap::new(),
        })
    }

    /// Graph-recorded content of `rel_path`, or the gap that prevents it.
    fn content(&mut self, rel_path: &str) -> Result<&str, GraphContentGap> {
        if !self.contents.contains_key(rel_path) {
            let resolved = self.resolve(rel_path).map_err(|err| err.to_string());
            self.contents.insert(rel_path.to_string(), resolved);
        }
        match &self.contents[rel_path] {
            Ok(content) => Ok(content.as_str()),
            Err(reason) => Err(GraphContentGap(reason.clone())),
        }
    }

    fn resolve(&self, rel_path: &str) -> Result<String> {
        let file_id = FilePathId::new(rel_path);
        let entry = self.recorded_entry(&file_id)?;
        let blob_hash = kin_blobs::Hash256(*entry.blob_hash.as_bytes());
        let bytes = self.blobs.read(&blob_hash).with_context(|| {
            format!("graph blob for file '{rel_path}' is unavailable (hash {blob_hash})")
        })?;
        String::from_utf8(bytes).with_context(|| {
            format!("graph-owned content for file '{rel_path}' is not valid UTF-8")
        })
    }

    /// The exact graph-owned tree entry for `file_id`, preferring working-tree
    /// truth and falling back to the committed tree at the current branch head.
    /// Both are graph reads; neither consults the filesystem.
    fn recorded_entry(&self, file_id: &FilePathId) -> Result<kin_model::TreeEntry> {
        if let Some(entry) = self.graph.get_tree_entry(file_id)? {
            return Ok(entry);
        }

        let branch_name = kin_core::read_current_branch(self.layout)?;
        let branch = match self.graph.get_branch(&branch_name)? {
            Some(branch) => branch,
            None => self
                .graph
                .list_branches()?
                .into_iter()
                .next()
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "graph records no tree entry for file '{}' and no branch is available to resolve one",
                        file_id.0
                    )
                })?,
        };
        let genesis = kin_core::build_genesis_change();
        let tree = kin_core::build_file_tree(self.graph, &genesis.id, &branch.head)?;
        tree.get(file_id).copied().ok_or_else(|| {
            anyhow::anyhow!(
                "file '{}' is not in the graph file tree at branch '{}'",
                file_id.0,
                branch.name
            )
        })
    }
}

#[derive(Clone, Copy)]
struct TokenOccurrence {
    start_line: u32,
    start_col: u32,
    end_line: u32,
    end_col: u32,
}

fn find_token_occurrences(
    content: &str,
    symbol: &str,
    byte_window: Option<(usize, usize)>,
) -> Vec<TokenOccurrence> {
    let mut occurrences = Vec::new();
    let mut cursor = 0usize;

    for (idx, raw_line) in content.split_inclusive('\n').enumerate() {
        let line = trim_line_ending(raw_line);
        let line_no = idx as u32 + 1;
        if is_comment_only(line) {
            cursor += raw_line.len();
            continue;
        }
        let searchable = strip_inline_comment(line);
        for start in symbol_match_indices(searchable, symbol) {
            let absolute_start = cursor + start;
            let absolute_end = absolute_start + symbol.len();
            if let Some((range_start, range_end)) = byte_window {
                if absolute_start < range_start || absolute_end > range_end {
                    continue;
                }
            }
            occurrences.push(TokenOccurrence {
                start_line: line_no,
                start_col: start as u32,
                end_line: line_no,
                end_col: (start + symbol.len()) as u32,
            });
        }
        cursor += raw_line.len();
    }

    occurrences
}

fn trim_line_ending(raw_line: &str) -> &str {
    raw_line
        .strip_suffix("\r\n")
        .or_else(|| raw_line.strip_suffix('\n'))
        .unwrap_or(raw_line)
}

fn strip_inline_comment(line: &str) -> &str {
    if let Some(index) = line.find("//") {
        return &line[..index];
    }
    if let Some(index) = line.find('#') {
        let trimmed = line.trim_start();
        if !trimmed.starts_with("#include") {
            return &line[..index];
        }
    }
    line
}

fn symbol_match_indices<'a>(line: &'a str, symbol: &'a str) -> impl Iterator<Item = usize> + 'a {
    line.match_indices(symbol)
        .map(|(idx, _)| idx)
        .filter(move |idx| is_symbol_boundary(line, *idx, symbol.len()))
}

fn is_symbol_boundary(line: &str, index: usize, symbol_len: usize) -> bool {
    let before = line[..index].chars().next_back();
    let after = line[index + symbol_len..].chars().next();
    before.is_none_or(|c| !is_identifier_char(c)) && after.is_none_or(|c| !is_identifier_char(c))
}

fn is_identifier_char(ch: char) -> bool {
    ch.is_ascii_alphanumeric() || matches!(ch, '_' | '$')
}

fn is_comment_only(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("//")
        || (trimmed.starts_with('#') && !trimmed.starts_with("#include"))
        || trimmed.starts_with("/*")
        || trimmed.starts_with('*')
}

fn display_read_path(_layout: &kin_core::KinLayout, rel_path: &str) -> String {
    rel_path.to_string()
}

fn normalize_file_hint(layout: &kin_core::KinLayout, hint: &str) -> Option<String> {
    let normalized = hint.replace('\\', "/");
    if let Some(stripped) = normalized.strip_prefix(".kin/source-root/") {
        return Some(stripped.to_string());
    }

    let source_root = kin_core::source_dir(layout);
    let repo_root = layout.working_dir();
    let as_path = PathBuf::from(&normalized);

    if as_path.is_absolute() {
        if let Ok(rel) = as_path.strip_prefix(&source_root) {
            return Some(normalize_rel_path(rel));
        }
        if let Ok(rel) = as_path.strip_prefix(repo_root) {
            let candidate = normalize_rel_path(rel);
            if let Some(stripped) = candidate.strip_prefix(".kin/source-root/") {
                return Some(stripped.to_string());
            }
            return Some(candidate);
        }
    }

    Some(normalized.trim_start_matches("./").to_string())
}

fn normalize_rel_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn find_containing_entity(
    graph: &impl GraphStore,
    file_hint: Option<&str>,
    line_hint: Option<u32>,
    column_hint: Option<u32>,
) -> Result<Option<Entity>> {
    let Some(file_hint) = file_hint else {
        return Ok(None);
    };
    let Some(line_hint) = line_hint else {
        return Ok(None);
    };

    let entities = graph.query_entities(&EntityFilter {
        name_pattern: None,
        ..Default::default()
    })?;

    Ok(entities
        .into_iter()
        .filter(|entity| {
            entity
                .file_origin
                .as_ref()
                .map(|file| file.0 == file_hint)
                .unwrap_or(false)
                && entity
                    .span
                    .as_ref()
                    .map(|span| span_contains(span, Some(line_hint), column_hint))
                    .unwrap_or(false)
        })
        .min_by_key(|entity| {
            entity
                .span
                .as_ref()
                .map(|span| span.end_byte.saturating_sub(span.start_byte))
                .unwrap_or(usize::MAX)
        }))
}

fn outgoing_relation_targets(
    graph: &impl GraphStore,
    entity_id: &EntityId,
) -> Result<HashSet<EntityId>> {
    let mut targets = HashSet::new();
    for relation in graph.get_all_relations_for_entity(entity_id)? {
        if relation.src == GraphNodeId::Entity(*entity_id)
            && matches!(
                relation.kind,
                RelationKind::Calls | RelationKind::Imports | RelationKind::References
            )
        {
            if let Some(target_id) = relation.dst.as_entity() {
                targets.insert(target_id);
            }
        }
    }
    Ok(targets)
}

fn span_contains(span: &SourceSpan, line_hint: Option<u32>, column_hint: Option<u32>) -> bool {
    let Some(line_hint) = line_hint else {
        return false;
    };
    if line_hint < span.start_line || line_hint > span.end_line {
        return false;
    }
    let Some(column_hint) = column_hint else {
        return true;
    };
    if line_hint == span.start_line && column_hint < span.start_col {
        return false;
    }
    if line_hint == span.end_line && column_hint > span.end_col {
        return false;
    }
    true
}

fn relation_reason(kinds: &[RelationKind]) -> String {
    let mut labels = kinds
        .iter()
        .map(|kind| relation_kind_label(*kind).to_string())
        .collect::<Vec<_>>();
    labels.sort();
    labels.dedup();
    relation_reason_from_labels(&labels.into_iter().collect())
}

fn relation_reason_from_labels(labels: &BTreeSet<String>) -> String {
    if labels.is_empty() {
        "reference".to_string()
    } else {
        format!(
            "reference:{}",
            labels.iter().cloned().collect::<Vec<_>>().join("+")
        )
    }
}

fn relation_kind_label(kind: RelationKind) -> &'static str {
    match kind {
        RelationKind::Imports => "import",
        RelationKind::Calls => "call",
        RelationKind::References => "reference",
        _ => "related",
    }
}

fn looks_like_identifier(candidate: &str) -> bool {
    let mut chars = candidate.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    (first.is_ascii_alphabetic() || matches!(first, '_' | '$')) && chars.all(is_identifier_char)
}

fn unique_file_count(edits: &[RenameEditJson]) -> usize {
    edits
        .iter()
        .map(|edit| edit.file.as_str())
        .collect::<HashSet<_>>()
        .len()
}

#[cfg(test)]
mod tests {
    use super::{build_rename_response, RenameRequest};
    use kin_db::InMemoryGraph;
    use kin_model::{
        ArtifactDelta, ArtifactDeltaKind, AuthorId, Branch, BranchName, ChangeStore, Entity,
        EntityId, EntityKind, EntityMetadata, EntityRole, EntityStore, FilePathId,
        FingerprintAlgorithm, GraphNodeId, Hash256, LanguageId, Relation, RelationId, RelationKind,
        RelationOrigin, SemanticChange, SemanticChangeId, SemanticFingerprint, SourceSpan,
        Timestamp, Visibility,
    };

    struct Fixture {
        _temp: tempfile::TempDir,
        repo: std::path::PathBuf,
        layout: kin_core::KinLayout,
        graph: InMemoryGraph,
    }

    /// Build a repo whose graph owns the content of `graph_files`.
    ///
    /// Each file's bytes are written to the content-addressed blob store and
    /// recorded on a change, which is exactly how ingestion establishes the
    /// content a rename plan's coordinates must be measured against.
    fn fixture(graph_files: &[(&str, &str)]) -> Fixture {
        let temp = tempfile::tempdir().unwrap();
        let repo = temp.path().to_path_buf();
        let kin_root = repo.join(".kin");
        std::fs::create_dir_all(kin_root.join("objects")).unwrap();
        let layout = kin_core::KinLayout::new(kin_root);
        let graph = InMemoryGraph::new();

        let genesis = kin_core::build_genesis_change();
        graph.create_change(&genesis).unwrap();

        let blobs = kin_blobs::BlobStore::new(layout.objects_dir()).unwrap();
        let mut artifact_deltas = Vec::new();
        let mut projected_files = Vec::new();
        for (path, content) in graph_files {
            let hash = blobs.write(content.as_bytes()).unwrap();
            let file_id = FilePathId::new(*path);
            artifact_deltas.push(ArtifactDelta {
                file_id: file_id.clone(),
                kind: ArtifactDeltaKind::Added,
                old_hash: None,
                new_hash: Some(Hash256::from_bytes(hash.0)),
            });
            projected_files.push(file_id);
        }

        let branch_name = BranchName::new("main");
        let change_id = SemanticChangeId::from_hash(Hash256::from_bytes([0x42; 32]));
        graph
            .create_change(&SemanticChange {
                id: change_id,
                parents: vec![genesis.id],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "seed graph-owned source".to_string(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                artifact_deltas,
                projected_files,
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: Some(branch_name.clone()),
            })
            .unwrap();
        graph
            .create_branch(&Branch {
                name: branch_name.clone(),
                head: change_id,
            })
            .unwrap();
        kin_core::write_current_branch(&layout, &branch_name).unwrap();

        Fixture {
            _temp: temp,
            repo,
            layout,
            graph,
        }
    }

    fn entity(name: &str, file: &str, span: SourceSpan) -> Entity {
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0; 32]),
                signature_hash: Hash256::from_bytes([0; 32]),
                behavior_hash: Hash256::from_bytes([0; 32]),
                equivalence_hash: Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new(file)),
            span: Some(span),
            signature: name.to_string(),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    fn span(file: &str, content: &str, start_line: u32) -> SourceSpan {
        SourceSpan {
            file: FilePathId::new(file),
            start_byte: 0,
            end_byte: content.len(),
            start_line,
            start_col: 0,
            end_line: start_line + content.lines().count() as u32,
            end_col: 0,
        }
    }

    fn rename_json(fixture: &Fixture, symbol: &str) -> String {
        build_rename_response(
            &fixture.layout,
            &fixture.graph,
            &RenameRequest {
                symbol: symbol.to_string(),
                new_name: "renamed_symbol".to_string(),
                file: None,
                line: None,
                column: None,
                json: true,
            },
        )
        .unwrap()
        .json
        .expect("rename plan json")
    }

    /// A `kin rename` plan may only anchor edits on graph-owned truth: the
    /// declaration span and graph relation edges. A caller that lives in the
    /// working tree but is not linked into the graph must never receive an edit,
    /// because the plan no longer discovers edit sites by scanning the raw source
    /// tree.
    #[test]
    fn rename_plan_edits_come_from_graph_not_source_tree_scan() {
        let decl_src = "fn probe_symbol() -> i32 { 0 }\n";
        let caller_src = "pub fn linked() -> i32 { probe_symbol() }\n";
        let fixture = fixture(&[("decl.rs", decl_src), ("caller.rs", caller_src)]);

        // A caller present only in the working tree, never linked into the graph.
        // The retired scan would have planned edits here off the `use` import.
        std::fs::write(
            fixture.repo.join("disk_only_caller.rs"),
            "use crate::decl::probe_symbol;\npub fn disk_only() -> i32 { probe_symbol() }\n",
        )
        .unwrap();

        let target = entity("probe_symbol", "decl.rs", span("decl.rs", decl_src, 1));
        let caller = entity("linked", "caller.rs", span("caller.rs", caller_src, 1));
        fixture.graph.upsert_entity(&target).unwrap();
        fixture.graph.upsert_entity(&caller).unwrap();
        fixture
            .graph
            .upsert_relation(&Relation {
                id: RelationId::new(),
                kind: RelationKind::Calls,
                src: GraphNodeId::Entity(caller.id),
                dst: GraphNodeId::Entity(target.id),
                confidence: 1.0,
                origin: RelationOrigin::Parsed,
                created_in: None,
                import_source: None,
                evidence: Vec::new(),
            })
            .unwrap();

        let json = rename_json(&fixture, "probe_symbol");

        // The graph-anchored declaration edit is present...
        assert!(
            json.contains("\"reason\":\"declaration\""),
            "graph-anchored declaration edit must be present: {json}"
        );
        // ...so is the edit for the caller the graph links in...
        assert!(
            json.contains("caller.rs"),
            "graph-linked caller must receive an edit: {json}"
        );
        // ...and no edit is planned for the working-tree-only caller.
        assert!(
            !json.contains("disk_only_caller.rs"),
            "rename must not plan edits discovered by scanning the raw source tree: {json}"
        );
    }

    /// The coordinates in a rename plan are the edit. They must be measured
    /// against the bytes graph truth records for a file, never against whatever
    /// the working tree currently holds — a tree that has drifted from the graph
    /// otherwise yields a plan whose line/column numbers point at the wrong
    /// bytes, silently, on a mutation-planning path.
    #[test]
    fn rename_plan_coordinates_come_from_graph_content_not_the_working_tree() {
        let graph_src = "fn probe_symbol() -> i32 { 0 }\n";
        let fixture = fixture(&[("decl.rs", graph_src)]);

        // The working tree has drifted: same declaration, three lines lower.
        // Reading it would place the declaration edit on line 4.
        std::fs::write(fixture.repo.join("decl.rs"), format!("\n\n\n{graph_src}")).unwrap();

        let target = entity("probe_symbol", "decl.rs", span("decl.rs", graph_src, 1));
        fixture.graph.upsert_entity(&target).unwrap();

        let json = rename_json(&fixture, "probe_symbol");

        assert!(
            json.contains("\"startLine\":1"),
            "declaration edit must be anchored on graph-owned content (line 1): {json}"
        );
        assert!(
            !json.contains("\"startLine\":4"),
            "declaration edit must not be anchored on the drifted working tree (line 4): {json}"
        );
    }

    /// When graph truth cannot supply the declaration file's content there is no
    /// trustworthy anchor for any edit. The command must say so rather than
    /// quietly measuring coordinates against the working tree.
    #[test]
    fn rename_reports_the_graph_gap_instead_of_reading_the_working_tree() {
        let decl_src = "fn probe_symbol() -> i32 { 0 }\n";
        // Nothing is seeded into graph-owned content for decl.rs...
        let fixture = fixture(&[("unrelated.rs", "fn other() {}\n")]);
        // ...even though the working tree has a perfectly readable copy.
        std::fs::write(fixture.repo.join("decl.rs"), decl_src).unwrap();

        let target = entity("probe_symbol", "decl.rs", span("decl.rs", decl_src, 1));
        fixture.graph.upsert_entity(&target).unwrap();

        let err = build_rename_response(
            &fixture.layout,
            &fixture.graph,
            &RenameRequest {
                symbol: "probe_symbol".to_string(),
                new_name: "renamed_symbol".to_string(),
                file: None,
                line: None,
                column: None,
                json: true,
            },
        )
        .expect_err("a graph gap on the declaration file must fail loud");
        let err = format!("{err:#}");

        assert!(err.contains("graph gap"), "{err}");
        assert!(err.contains("decl.rs"), "{err}");
    }
}
