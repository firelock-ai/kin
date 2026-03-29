// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;
use kin_model::EntityStore;
use kin_model::{Entity, EntityFilter, EntityKind, GraphStore, LanguageId, Visibility};
use serde::Serialize;
use std::collections::{HashMap, HashSet};

#[derive(Serialize)]
struct SearchJsonEntity {
    kind: String,
    name: String,
    file: String,
    line: u32,
    signature: Option<String>,
}

pub async fn run(
    pattern: String,
    kind: Option<String>,
    language: Option<String>,
    show_body: bool,
    body_limit: Option<usize>,
) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;

    // Fast path: use the slim read-only index if available (27MB vs 73MB snapshot)
    let idx_path = crate::backend::kindb_snapshot_path(&layout).with_extension("kidx");
    if idx_path.exists() && !show_body && kind.is_none() && language.is_none() {
        return run_with_index(&idx_path, &pattern);
    }

    // Fallback: full graph access (needed for --show-body which requires signatures)
    let snap = crate::backend::open_snapshot_daemon_first_read_only(&layout).await?;
    let graph = snap.graph();
    run_with_store(
        &layout, &*graph, pattern, kind, language, show_body, body_limit,
    )
}

pub async fn run_json(
    pattern: String,
    kind: Option<String>,
    language: Option<String>,
    _show_body: bool,
    _body_limit: Option<usize>,
) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;

    let snap = crate::backend::open_snapshot_daemon_first_read_only(&layout).await?;
    let graph = snap.graph();
    let results = collect_search_results(&*graph, &pattern, kind.as_deref(), language.as_deref())?;
    let payload = results
        .iter()
        .map(|entity| entity_to_json(&layout, entity))
        .collect::<Vec<_>>();
    println!("{}", serde_json::to_string(&payload)?);
    Ok(())
}

fn run_with_index(idx_path: &std::path::Path, pattern: &str) -> Result<()> {
    let index = kin_db::ReadIndex::load(idx_path)?;
    let matching = index.search_by_name(pattern);

    if matching.is_empty() {
        println!("No entities matching '{}'", pattern);
        return Ok(());
    }

    let entities: Vec<&kin_db::storage::index::IndexEntity> = matching
        .iter()
        .filter_map(|&idx| index.entities.get(idx as usize))
        .collect();

    // Build raw hits for kin-search ranking (lexical-only from name match).
    let raw_hits: Vec<kin_ranking::RawHit> = entities
        .iter()
        .enumerate()
        .map(|(i, e)| kin_ranking::RawHit {
            entity_id: format!("idx:{}", i),
            entity_name: e.name.clone(),
            // Score inversely by match position: first matches rank higher.
            bm25_score: Some(1.0 / (i as f32 + 1.0)),
            cosine_distance: None,
            graph_score: None,
            proof_score: None,
            provenance_score: None,
        })
        .collect();
    let query = kin_ranking::SearchQuery::new(pattern);
    let ranked = kin_ranking::rank_raw_hits(&query, &raw_hits);

    println!(
        "Lexical read-index matches for '{}' (degraded: no graph/proof/provenance signals):",
        pattern
    );
    println!("Found {} entities:", ranked.len());
    for result in &ranked {
        // Map ranked result back to the index entity via the idx:N id.
        let idx: usize = result
            .id
            .strip_prefix("idx:")
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        if let Some(e) = entities.get(idx) {
            let kind_name = match e.kind {
                0 => "Function",
                1 => "Class",
                2 => "Interface",
                3 => "TraitDef",
                4 => "TypeAlias",
                5 => "Module",
                13 => "Method",
                14 => "EnumDef",
                16 => "Constant",
                _ => "Other",
            };
            let lang_name = match e.language {
                0 => "typescript",
                1 => "javascript",
                2 => "python",
                3 => "go",
                4 => "java",
                5 => "rust",
                6 => "c",
                7 => "cpp",
                8 => "csharp",
                9 => "ruby",
                _ => "unknown",
            };
            println!(
                "  {} ({}, {}) - {}",
                e.name, kind_name, lang_name, e.file_path
            );
        }
    }

    Ok(())
}

#[cfg(not(feature = "vector"))]
pub async fn run_semantic(
    query: String,
    kind: Option<String>,
    language: Option<String>,
    limit: usize,
) -> anyhow::Result<()> {
    // Vector feature not compiled in — silently fall back to text search.
    run(query, kind, language, false, Some(limit)).await
}

#[cfg(feature = "vector")]
pub async fn run_semantic(
    query: String,
    kind: Option<String>,
    language: Option<String>,
    limit: usize,
) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;

    let snap = crate::backend::open_snapshot_daemon_first_read_only(&layout).await?;
    let graph = snap.graph();

    // Use the graph's built-in semantic search (embeddings computed on upsert)
    let vector_results = graph.semantic_search(&query, limit)?;

    // If no vector results, fall back to graph text search with an explicit note.
    if vector_results.is_empty() {
        println!(
            "No vector matches for '{}'; using graph text search fallback:",
            query
        );
        return run_with_store(&layout, &*graph, query, kind, language, false, Some(limit));
    }

    let kind_ref = kind.as_deref();
    let kinds = kind_ref.and_then(parse_kinds);
    let languages = language.and_then(|l| parse_language(&l));

    let mut raw_hits = Vec::new();
    let mut entity_map: HashMap<String, kin_model::Entity> = HashMap::new();
    let mut seen_ids: HashSet<String> = HashSet::new();

    // Vector results
    for (entity_id, distance) in &vector_results {
        if let Some(entity) = graph.get_entity(entity_id)? {
            if let Some(ref ks) = kinds {
                if !ks.contains(&entity.kind) {
                    continue;
                }
            }
            if let Some(ref lang) = languages {
                if entity.language != *lang {
                    continue;
                }
            }
            let id_str = entity_id.to_string();
            raw_hits.push(build_semantic_raw_hit(
                &*graph,
                entity_id,
                &entity,
                None,
                Some(*distance),
            )?);
            seen_ids.insert(id_str.clone());
            entity_map.insert(id_str, entity);
        }
    }

    // Hybrid: merge text search results
    let text_hits = graph.text_search(&query, limit * 2)?;
    for (entity_id, bm25_score) in &text_hits {
        let id_str = entity_id.to_string();
        if seen_ids.contains(&id_str) {
            if let Some(hit) = raw_hits.iter_mut().find(|h| h.entity_id == id_str) {
                hit.bm25_score = Some(*bm25_score);
            }
            continue;
        }
        if let Some(entity) = graph.get_entity(entity_id)? {
            if let Some(ref ks) = kinds {
                if !ks.contains(&entity.kind) {
                    continue;
                }
            }
            if let Some(ref lang) = languages {
                if entity.language != *lang {
                    continue;
                }
            }
            raw_hits.push(build_semantic_raw_hit(
                &*graph,
                entity_id,
                &entity,
                Some(*bm25_score),
                None,
            )?);
            seen_ids.insert(id_str.clone());
            entity_map.insert(id_str, entity);
        }
    }

    if raw_hits.is_empty() {
        println!("No matches for '{}'", query);
        return Ok(());
    }

    let search_query = kin_ranking::SearchQuery {
        text: query.clone(),
        require_proof: false,
        limit,
    };
    let ranked = kin_ranking::rank_raw_hits(&search_query, &raw_hits);

    println!("Semantic matches for '{}':", query);
    for result in &ranked {
        if let Some(entity) = entity_map.get(&result.id) {
            let file_str = entity
                .file_origin
                .as_ref()
                .map(|f| display_read_path(&layout, &f.0))
                .unwrap_or_else(|| "no file".to_string());
            println!(
                "  {:.3}  {} ({:?}, {}) - {}",
                result.score, entity.name, entity.kind, entity.language, file_str
            );
        }
    }
    Ok(())
}

#[cfg(not(feature = "vector"))]
pub async fn run_semantic_json(
    query: String,
    kind: Option<String>,
    language: Option<String>,
    limit: usize,
) -> anyhow::Result<()> {
    // Vector feature not compiled in — silently fall back to text search JSON.
    run_json(query, kind, language, false, Some(limit)).await
}

#[cfg(feature = "vector")]
pub async fn run_semantic_json(
    query: String,
    kind: Option<String>,
    language: Option<String>,
    limit: usize,
) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;

    let snap = crate::backend::open_snapshot_daemon_first_read_only(&layout).await?;
    let graph = snap.graph();
    let vector_results = graph.semantic_search(&query, limit)?;

    // If no vector results, fall back to graph text search JSON.
    if vector_results.is_empty() {
        let results =
            collect_search_results(&*graph, &query, kind.as_deref(), language.as_deref())?;
        let payload: Vec<_> = results
            .iter()
            .map(|entity| entity_to_json(&layout, entity))
            .collect();
        println!("{}", serde_json::to_string(&payload)?);
        return Ok(());
    }

    let kind_ref = kind.as_deref();
    let kinds = kind_ref.and_then(parse_kinds);
    let languages = language.as_deref().and_then(parse_language);

    let mut raw_hits = Vec::new();
    let mut entity_map: HashMap<String, kin_model::Entity> = HashMap::new();
    let mut seen_ids: HashSet<String> = HashSet::new();

    for (entity_id, distance) in &vector_results {
        if let Some(entity) = graph.get_entity(entity_id)? {
            if let Some(ref ks) = kinds {
                if !ks.contains(&entity.kind) {
                    continue;
                }
            }
            if let Some(ref lang) = languages {
                if entity.language != *lang {
                    continue;
                }
            }
            let id_str = entity_id.to_string();
            raw_hits.push(build_semantic_raw_hit(
                &*graph,
                entity_id,
                &entity,
                None,
                Some(*distance),
            )?);
            seen_ids.insert(id_str.clone());
            entity_map.insert(id_str, entity);
        }
    }

    // Hybrid: merge text search results
    let text_hits = graph.text_search(&query, limit * 2)?;
    for (entity_id, bm25_score) in &text_hits {
        let id_str = entity_id.to_string();
        if seen_ids.contains(&id_str) {
            if let Some(hit) = raw_hits.iter_mut().find(|h| h.entity_id == id_str) {
                hit.bm25_score = Some(*bm25_score);
            }
            continue;
        }
        if let Some(entity) = graph.get_entity(entity_id)? {
            if let Some(ref ks) = kinds {
                if !ks.contains(&entity.kind) {
                    continue;
                }
            }
            if let Some(ref lang) = languages {
                if entity.language != *lang {
                    continue;
                }
            }
            raw_hits.push(build_semantic_raw_hit(
                &*graph,
                entity_id,
                &entity,
                Some(*bm25_score),
                None,
            )?);
            seen_ids.insert(id_str.clone());
            entity_map.insert(id_str, entity);
        }
    }

    let search_query = kin_ranking::SearchQuery {
        text: query.clone(),
        require_proof: false,
        limit,
    };
    let ranked = kin_ranking::rank_raw_hits(&search_query, &raw_hits);

    let mut payload = Vec::new();
    for result in &ranked {
        if let Some(entity) = entity_map.get(&result.id) {
            payload.push(entity_to_json(&layout, entity));
        }
    }
    println!("{}", serde_json::to_string(&payload)?);
    Ok(())
}

fn collect_search_results(
    graph: &kin_db::InMemoryGraph,
    pattern: &str,
    kind: Option<&str>,
    language: Option<&str>,
) -> Result<Vec<Entity>> {
    let kinds = kind.and_then(parse_kinds);
    let languages = language.and_then(parse_language);

    if pattern.trim().is_empty() {
        let mut all = graph.list_all_entities()?;
        all.sort_by(|left, right| left.name.cmp(&right.name).then(left.id.0.cmp(&right.id.0)));
        if let Some(ref ks) = kinds {
            all.retain(|entity| ks.contains(&entity.kind));
        }
        if let Some(ref lang) = languages {
            all.retain(|entity| entity.language == *lang);
        }
        return Ok(all);
    }

    let sub_patterns: Vec<&str> = pattern
        .split('|')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();

    let mut seen = HashSet::new();
    let mut results = Vec::new();
    for sub in &sub_patterns {
        let filter = EntityFilter {
            name_pattern: Some(sub.to_string()),
            kinds: kinds.clone(),
            languages: languages.as_ref().map(|l| vec![*l]),
            ..Default::default()
        };
        for entity in graph.query_entities(&filter)? {
            if seen.insert(entity.id) {
                results.push(entity);
            }
        }
    }

    // Full-text search fallback for JSON path too
    if results.len() < 5 {
        let text_hits = graph.text_search(pattern, 20)?;
        for (entity_id, _score) in text_hits {
            if seen.insert(entity_id) {
                if let Some(entity) = graph.get_entity(&entity_id)? {
                    if let Some(ref ks) = kinds {
                        if !ks.contains(&entity.kind) {
                            continue;
                        }
                    }
                    if let Some(ref lang) = languages {
                        if entity.language != *lang {
                            continue;
                        }
                    }
                    results.push(entity);
                }
            }
        }
    }

    results.sort_by(|left, right| left.name.cmp(&right.name).then(left.id.0.cmp(&right.id.0)));
    Ok(results)
}

fn build_semantic_raw_hit(
    graph: &impl GraphStore,
    entity_id: &kin_model::EntityId,
    entity: &Entity,
    bm25_score: Option<f32>,
    cosine_distance: Option<f32>,
) -> Result<kin_ranking::RawHit> {
    let relation_count = graph.get_all_relations_for_entity(entity_id)?.len() as f32;
    let proof_count = graph.get_tests_for_entity(entity_id)?.len() as f32;
    let proof_score = (proof_count / 3.0).min(1.0);
    let provenance_score = entity_provenance_signal(graph, entity)?;

    Ok(kin_ranking::RawHit {
        entity_id: entity_id.to_string(),
        entity_name: entity.name.clone(),
        bm25_score,
        cosine_distance,
        graph_score: Some(relation_count),
        proof_score: Some(proof_score),
        provenance_score: Some(provenance_score),
    })
}

fn entity_provenance_signal(graph: &impl GraphStore, entity: &Entity) -> Result<f32> {
    let mut score: f32 = match entity.visibility {
        Visibility::Public => 1.0,
        Visibility::Internal | Visibility::Crate => 0.75,
        Visibility::Private => 0.55,
    };

    if let Some(path) = entity
        .file_origin
        .as_ref()
        .map(|origin| origin.0.to_ascii_lowercase())
    {
        if looks_non_production_path(&path) {
            score *= 0.35;
        }
    }

    if let Some(change_id) = entity.created_in.as_ref() {
        let approvals = graph.get_approvals_for_change(change_id)?;
        if !approvals.is_empty() {
            score = score.max(0.9);
        }
    }

    Ok(score.clamp(0.0, 1.0))
}

fn looks_non_production_path(path: &str) -> bool {
    let markers = [
        "/test/",
        "/tests/",
        "/spec/",
        "/specs/",
        "/fixture/",
        "/fixtures/",
        "/example/",
        "/examples/",
        "/bench/",
        "/benches/",
        "__tests__",
    ];

    markers.iter().any(|marker| path.contains(marker))
        || path.ends_with("_test.rs")
        || path.ends_with(".spec.ts")
        || path.ends_with(".spec.tsx")
        || path.ends_with(".test.ts")
        || path.ends_with(".test.tsx")
        || path.ends_with(".spec.js")
        || path.ends_with(".test.js")
}

fn entity_to_json(layout: &kin_core::KinLayout, entity: &Entity) -> SearchJsonEntity {
    SearchJsonEntity {
        kind: format!("{:?}", entity.kind),
        name: entity.name.clone(),
        file: entity
            .file_origin
            .as_ref()
            .map(|f| display_read_path(layout, &f.0))
            .unwrap_or_default(),
        line: entity
            .span
            .as_ref()
            .map(|span| span.start_line)
            .unwrap_or(1),
        signature: (!entity.signature.is_empty()).then(|| entity.signature.clone()),
    }
}

fn run_with_store(
    layout: &kin_core::KinLayout,
    graph: &impl GraphStore,
    pattern: String,
    kind: Option<String>,
    language: Option<String>,
    show_body: bool,
    body_limit: Option<usize>,
) -> Result<()> {
    let kind_ref = kind.as_deref();
    let kinds = kind_ref.and_then(parse_kinds);
    let languages = language.and_then(|l| parse_language(&l));

    // Multi-pattern OR search: split on '|', deduplicate by entity ID
    let sub_patterns: Vec<&str> = pattern
        .split('|')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();

    enforce_precise_search_mode(&pattern, &sub_patterns, kind_ref, show_body, body_limit)?;

    let mut seen = HashSet::new();
    let mut results = Vec::new();
    for sub in &sub_patterns {
        let filter = EntityFilter {
            name_pattern: Some(sub.to_string()),
            kinds: kinds.clone(),
            languages: languages.as_ref().map(|l| vec![*l]),
            ..Default::default()
        };
        for entity in graph.query_entities(&filter)? {
            if seen.insert(entity.id) {
                results.push(entity);
            }
        }
    }

    if results.is_empty() {
        println!("No entities matching '{}'", pattern);
    } else if show_body {
        let work_dir = kin_core::source_dir(layout);
        let max_lines = body_limit.unwrap_or(10);
        println!("Found {} entities:", results.len());
        for e in &results {
            let file_str = e
                .file_origin
                .as_ref()
                .map(|f| display_read_path(layout, &f.0))
                .unwrap_or_else(|| "unknown".to_string());
            let line_num = e.span.as_ref().map(|s| s.start_line).unwrap_or(0);
            println!("{} ({:?}) @ {}:{}", e.name, e.kind, file_str, line_num);
            if let (Some(ref fo), Some(ref span)) = (&e.file_origin, &e.span) {
                let path = work_dir.join(&fo.0);
                if let Ok(content) = std::fs::read(&path) {
                    let start = span.start_byte.min(content.len());
                    let end = span.end_byte.min(content.len());
                    if start < end {
                        let body = String::from_utf8_lossy(&content[start..end]);
                        let lines: Vec<&str> = body.lines().collect();
                        let shown = lines.len().min(max_lines);
                        for line in &lines[..shown] {
                            println!("{}", line);
                        }
                        if lines.len() > max_lines {
                            println!("  ...(+{} lines)", lines.len() - max_lines);
                        }
                    }
                }
            }
        }
    } else {
        println!("Found {} entities:", results.len());
        for e in &results {
            println!(
                "  {} ({:?}, {}) - {}",
                e.name,
                e.kind,
                e.language,
                e.file_origin
                    .as_ref()
                    .map(|f| display_read_path(layout, &f.0))
                    .unwrap_or_else(|| "no file".to_string())
            );
        }
    }

    Ok(())
}

fn enforce_precise_search_mode(
    pattern: &str,
    sub_patterns: &[&str],
    kind: Option<&str>,
    show_body: bool,
    body_limit: Option<usize>,
) -> Result<()> {
    let precise = matches!(
        std::env::var("KIN_SEARCH_MODE").ok().as_deref(),
        Some("precise")
    );
    if !precise || !show_body {
        return Ok(());
    }

    if body_limit.unwrap_or(5) > 5 {
        anyhow::bail!(
            "precise native search: `--show-body` is limited to `--limit 5`. Use `kin trace <ExactName>` first, or narrow with `--kind`."
        );
    }

    if sub_patterns.len() > 2 {
        anyhow::bail!(
            "precise native search: too many OR terms in `{}`. Use at most two exact names, or start with `kin trace <ExactName>`.",
            pattern
        );
    }

    let has_kind = kind.is_some();
    if let Some(bad) = sub_patterns
        .iter()
        .find(|sub| !looks_precise_name(sub, has_kind))
    {
        anyhow::bail!(
            "precise native search: `{}` is too broad for `--show-body`. Use an exact symbol like `ZodString`, `$ZodType`, `Router::route`, or add `--kind`.",
            bad
        );
    }

    Ok(())
}

fn looks_precise_name(pattern: &str, has_kind: bool) -> bool {
    let trimmed = pattern.trim();
    if trimmed.is_empty() {
        return false;
    }

    if trimmed.contains("::")
        || trimmed.contains('.')
        || trimmed.contains('/')
        || trimmed.contains('$')
    {
        return true;
    }

    let mut chars = trimmed.chars();
    if let Some(first) = chars.next() {
        if first.is_uppercase() {
            return true;
        }
    }

    if trimmed
        .chars()
        .skip(1)
        .any(|c| c.is_uppercase() || c.is_ascii_digit())
    {
        return true;
    }

    let len = trimmed.chars().count();
    if has_kind && len >= 6 {
        return true;
    }

    len >= 10
}

fn display_read_path(layout: &kin_core::KinLayout, rel_path: &str) -> String {
    if kin_core::read_repo_mode(layout) == kin_core::RepoMode::Native {
        format!(".kin/source-root/{}", rel_path)
    } else {
        rel_path.to_string()
    }
}

fn parse_kinds(s: &str) -> Option<Vec<EntityKind>> {
    match s.to_lowercase().as_str() {
        "function" | "fn" => Some(vec![EntityKind::Function, EntityKind::Method]),
        "class" => Some(vec![EntityKind::Class]),
        "interface" => Some(vec![EntityKind::Interface]),
        "trait" => Some(vec![EntityKind::TraitDef]),
        "type" => Some(vec![EntityKind::TypeAlias]),
        "module" | "mod" => Some(vec![EntityKind::Module]),
        "test" => Some(vec![EntityKind::Test]),
        "method" => Some(vec![EntityKind::Method]),
        "enum" => Some(vec![EntityKind::EnumDef]),
        "const" => Some(vec![EntityKind::Constant]),
        _ => None,
    }
}

fn parse_language(s: &str) -> Option<LanguageId> {
    match s.to_lowercase().as_str() {
        "typescript" | "ts" => Some(LanguageId::TypeScript),
        "javascript" | "js" => Some(LanguageId::JavaScript),
        "python" | "py" => Some(LanguageId::Python),
        "go" => Some(LanguageId::Go),
        "java" => Some(LanguageId::Java),
        "rust" | "rs" => Some(LanguageId::Rust),
        "c" => Some(LanguageId::C),
        "cpp" | "c++" | "hpp" | "cc" | "cxx" => Some(LanguageId::Cpp),
        "csharp" | "c#" | "cs" => Some(LanguageId::CSharp),
        "ruby" | "rb" => Some(LanguageId::Ruby),
        "kotlin" | "kt" | "kts" => Some(LanguageId::Kotlin),
        "hcl" | "terraform" | "tf" => Some(LanguageId::Hcl),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{enforce_precise_search_mode, looks_precise_name, parse_kinds};
    use kin_model::EntityKind;
    use serial_test::serial;

    #[test]
    fn function_kind_includes_methods() {
        let kinds = parse_kinds("function").unwrap();
        assert!(kinds.contains(&EntityKind::Function));
        assert!(kinds.contains(&EntityKind::Method));
    }

    #[test]
    fn method_kind_is_specific() {
        let kinds = parse_kinds("method").unwrap();
        assert_eq!(kinds, vec![EntityKind::Method]);
    }

    #[test]
    fn precise_mode_accepts_exact_symbol_names() {
        assert!(looks_precise_name("ZodString", false));
        assert!(looks_precise_name("safeParse", false));
        assert!(looks_precise_name("$ZodType", false));
        assert!(looks_precise_name("Router::route", false));
        assert!(looks_precise_name("src/parser.ts", false));
    }

    #[test]
    fn precise_mode_rejects_broad_lowercase_terms() {
        assert!(!looks_precise_name("run", false));
        assert!(!looks_precise_name("parse", false));
        assert!(!looks_precise_name("_parse", false));
    }

    #[test]
    fn precise_mode_allows_kind_narrowed_midlength_terms() {
        assert!(looks_precise_name("persist", true));
        assert!(!looks_precise_name("save", true));
    }

    #[test]
    #[serial]
    fn precise_mode_rejects_broad_show_body_searches() {
        std::env::set_var("KIN_SEARCH_MODE", "precise");
        let err = enforce_precise_search_mode(
            "parse|safeParse|_parse|run",
            &["parse", "safeParse", "_parse", "run"],
            None,
            true,
            Some(20),
        )
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("limited to `--limit 5`") || msg.contains("too many OR terms"));
        std::env::remove_var("KIN_SEARCH_MODE");
    }

    #[test]
    #[serial]
    fn precise_mode_accepts_small_exact_or_searches() {
        std::env::set_var("KIN_SEARCH_MODE", "precise");
        let result = enforce_precise_search_mode(
            "$ZodType|$ZodTypeInternals",
            &["$ZodType", "$ZodTypeInternals"],
            None,
            true,
            Some(5),
        );
        assert!(result.is_ok());
        std::env::remove_var("KIN_SEARCH_MODE");
    }
}
