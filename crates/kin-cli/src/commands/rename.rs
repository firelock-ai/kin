// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Context, Result};
use kin_model::{
    Entity, EntityFilter, EntityId, GraphNodeId, GraphStore, RelationKind, SourceSpan,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashSet};
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

    if let (Some(file_origin), Some(span)) = (&target.file_origin, &target.span) {
        add_first_span_edit(
            layout,
            &file_origin.0,
            span.start_byte,
            span.end_byte,
            &target.name,
            new_name,
            "declaration".to_string(),
            &mut edits,
            &mut seen,
        )?;
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
                    add_span_edits(
                        layout,
                        &file_origin.0,
                        span.start_byte,
                        span.end_byte,
                        &target.name,
                        new_name,
                        relation_reason(&[rel.kind]),
                        &mut edits,
                        &mut seen,
                    )?;
                }
            }
        }
    }

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
            "plan is token-boundary based inside semantically selected declarations and reference files; review the workspace diff after applying"
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

fn add_span_edits(
    layout: &kin_core::KinLayout,
    rel_path: &str,
    start_byte: usize,
    end_byte: usize,
    old_name: &str,
    new_name: &str,
    reason: String,
    edits: &mut Vec<RenameEditJson>,
    seen: &mut HashSet<String>,
) -> Result<()> {
    let content = read_repo_file(layout, rel_path)?;
    for occurrence in find_token_occurrences(&content, old_name, Some((start_byte, end_byte))) {
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

fn add_first_span_edit(
    layout: &kin_core::KinLayout,
    rel_path: &str,
    start_byte: usize,
    end_byte: usize,
    old_name: &str,
    new_name: &str,
    reason: String,
    edits: &mut Vec<RenameEditJson>,
    seen: &mut HashSet<String>,
) -> Result<()> {
    let content = read_repo_file(layout, rel_path)?;
    if let Some(occurrence) =
        find_token_occurrences(&content, old_name, Some((start_byte, end_byte)))
            .into_iter()
            .next()
    {
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

fn read_repo_file(layout: &kin_core::KinLayout, rel_path: &str) -> Result<String> {
    let path = kin_core::source_dir(layout).join(rel_path);
    Ok(std::fs::read_to_string(path)?)
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

    /// A `kin rename` plan may only anchor edits on graph-owned truth: the
    /// declaration span and graph relation edges. A caller that lives in the
    /// working tree but is not linked into the graph must never receive an edit,
    /// because the plan no longer discovers edit sites by scanning the raw source
    /// tree.
    #[test]
    fn rename_plan_edits_come_from_graph_not_source_tree_scan() {
        use kin_db::InMemoryGraph;
        use kin_model::{
            Entity, EntityId, EntityKind, EntityMetadata, EntityRole, EntityStore, FilePathId,
            FingerprintAlgorithm, Hash256, LanguageId, SemanticFingerprint, SourceSpan, Visibility,
        };

        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path();
        std::fs::create_dir_all(repo.join(".kin")).unwrap();
        let layout = kin_core::KinLayout::new(repo.join(".kin"));

        let decl_src = "fn probe_symbol() -> i32 { 0 }\n";
        std::fs::write(repo.join("decl.rs"), decl_src).unwrap();
        // A caller present only in the working tree, never linked into the graph.
        // The retired scan would have planned edits here off the `use` import.
        std::fs::write(
            repo.join("disk_only_caller.rs"),
            "use crate::decl::probe_symbol;\npub fn disk_only() -> i32 { probe_symbol() }\n",
        )
        .unwrap();

        let target = Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: "probe_symbol".to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0; 32]),
                signature_hash: Hash256::from_bytes([0; 32]),
                behavior_hash: Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new("decl.rs")),
            span: Some(SourceSpan {
                file: FilePathId::new("decl.rs"),
                start_byte: 0,
                end_byte: decl_src.len(),
                start_line: 1,
                start_col: 0,
                end_line: 1,
                end_col: decl_src.len() as u32,
            }),
            signature: "probe_symbol".to_string(),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        };

        let graph = InMemoryGraph::new();
        graph.upsert_entity(&target).unwrap();

        let response = build_rename_response(
            &layout,
            &graph,
            &RenameRequest {
                symbol: "probe_symbol".to_string(),
                new_name: "renamed_symbol".to_string(),
                file: None,
                line: None,
                column: None,
                json: true,
            },
        )
        .unwrap();
        let json = response.json.expect("rename plan json");

        // The graph-anchored declaration edit is present...
        assert!(
            json.contains("\"reason\":\"declaration\""),
            "graph-anchored declaration edit must be present: {json}"
        );
        // ...and no edit is planned for the working-tree-only caller.
        assert!(
            !json.contains("disk_only_caller.rs"),
            "rename must not plan edits discovered by scanning the raw source tree: {json}"
        );
    }
}
