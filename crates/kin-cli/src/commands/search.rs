use crate::backend::with_read_store;
use anyhow::Result;
use kin_model::{EntityFilter, EntityKind, GraphStore, LanguageId};
use std::collections::{HashMap, HashSet};

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

    // Fallback: full snapshot (needed for --show-body which requires signatures)
    with_read_store!(layout, |graph| {
        run_with_store(
            &layout, graph, pattern, kind, language, show_body, body_limit,
        )
    })
}

fn run_with_index(idx_path: &std::path::Path, pattern: &str) -> Result<()> {
    let index = kin_db::ReadIndex::load(idx_path)?;
    let matching = index.search_by_name(pattern);

    if matching.is_empty() {
        println!("No entities matching '{}'", pattern);
        return Ok(());
    }

    let mut results: Vec<&kin_db::storage::index::IndexEntity> = matching
        .iter()
        .filter_map(|&idx| index.entities.get(idx as usize))
        .collect();

    // Sort by name
    results.sort_by(|a, b| a.name.cmp(&b.name));

    println!("Found {} entities:", results.len());
    for e in &results {
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

    Ok(())
}

pub async fn run_semantic(
    query: String,
    kind: Option<String>,
    language: Option<String>,
    limit: usize,
) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;

    let vectors_path = crate::backend::kindb_vectors_path(&layout);
    if !vectors_path.exists() {
        anyhow::bail!(
            "No vector index found at {}. Run `kin convert-backend` first to generate embeddings.",
            vectors_path.display()
        );
    }

    // Load stored embeddings
    let vectors_data = std::fs::read(&vectors_path)?;
    let vectors: HashMap<String, Vec<f32>> = serde_json::from_slice(&vectors_data)?;

    if vectors.is_empty() {
        println!("No embeddings in vector index.");
        return Ok(());
    }

    // Determine dimensionality from first vector
    let dims = vectors.values().next().unwrap().len();

    // Build HNSW index
    let index = kin_db::VectorIndex::new(dims)?;
    for (id_str, embedding) in &vectors {
        let uuid: uuid::Uuid = id_str.parse()?;
        let entity_id = kin_model::EntityId(uuid);
        index.upsert(entity_id, embedding)?;
    }

    // Embed the query
    eprintln!("Embedding query...");
    let embedder = kin_db::CodeEmbedder::new()?;
    let query_embedding = embedder.embed_entity(&query, "", "")?;

    // Search for nearest neighbors
    let results = index.search_similar(&query_embedding, limit)?;

    if results.is_empty() {
        println!("No semantic matches for '{}'", query);
        return Ok(());
    }

    // Look up entity details from the graph store
    with_read_store!(layout, |graph| {
        let kind_ref = kind.as_deref();
        let kinds = kind_ref.and_then(parse_kinds);
        let languages = language.and_then(|l| parse_language(&l));

        let mut shown = 0usize;
        println!("Semantic matches for '{}':", query);
        for (entity_id, distance) in &results {
            if let Some(entity) = graph.get_entity(entity_id)? {
                // Apply kind/language filters if specified
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

                let similarity = 1.0 - distance;
                let file_str = entity
                    .file_origin
                    .as_ref()
                    .map(|f| display_read_path(&layout, &f.0))
                    .unwrap_or_else(|| "no file".to_string());
                println!(
                    "  {:.3}  {} ({:?}, {}) - {}",
                    similarity, entity.name, entity.kind, entity.language, file_str
                );
                shown += 1;
            }
        }
        if shown == 0 {
            println!("  (no matches after filtering)");
        }
        Ok(())
    })
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
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{enforce_precise_search_mode, looks_precise_name, parse_kinds};
    use kin_model::EntityKind;

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
    fn precise_mode_rejects_broad_show_body_searches() {
        unsafe {
            std::env::set_var("KIN_SEARCH_MODE", "precise");
        }
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
        unsafe {
            std::env::remove_var("KIN_SEARCH_MODE");
        }
    }

    #[test]
    fn precise_mode_accepts_small_exact_or_searches() {
        unsafe {
            std::env::set_var("KIN_SEARCH_MODE", "precise");
        }
        let result = enforce_precise_search_mode(
            "$ZodType|$ZodTypeInternals",
            &["$ZodType", "$ZodTypeInternals"],
            None,
            true,
            Some(5),
        );
        assert!(result.is_ok());
        unsafe {
            std::env::remove_var("KIN_SEARCH_MODE");
        }
    }
}
