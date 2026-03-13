use anyhow::Result;
use kin_model::{EntityFilter, EntityKind, GraphStore, LanguageId};
use std::collections::HashSet;

pub async fn run(
    pattern: String,
    kind: Option<String>,
    language: Option<String>,
    show_body: bool,
    body_limit: Option<usize>,
) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let graph = kin_graph::KuzuGraphStore::open_read_only(&layout.graph_dir())?;

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
            languages: languages.as_ref().map(|l| vec![l.clone()]),
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
        let work_dir = kin_core::source_dir(&layout);
        println!("Found {} entities:\n", results.len());
        for e in &results {
            let file_str = e
                .file_origin
                .as_ref()
                .map(|f| f.0.as_str())
                .unwrap_or("unknown");
            println!(
                "--- {} ({:?}, {}) - {} ---",
                e.name, e.kind, e.language, file_str
            );
            if let (Some(ref fo), Some(ref span)) = (&e.file_origin, &e.span) {
                let path = work_dir.join(&fo.0);
                if let Ok(content) = std::fs::read(&path) {
                    let start = span.start_byte.min(content.len());
                    let end = span.end_byte.min(content.len());
                    if start < end {
                        let body = String::from_utf8_lossy(&content[start..end]);
                        if let Some(max_lines) = body_limit {
                            let lines: Vec<&str> = body.lines().collect();
                            let shown = lines.len().min(max_lines);
                            for line in &lines[..shown] {
                                println!("{}", line);
                            }
                            if lines.len() > max_lines {
                                println!("  ... ({} more lines)", lines.len() - max_lines);
                            }
                        } else {
                            println!("{}", body);
                        }
                    }
                }
            }
            println!();
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
                    .map(|f| f.to_string())
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
