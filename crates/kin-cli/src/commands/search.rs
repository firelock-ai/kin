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

    let kinds = kind.and_then(|k| parse_kinds(&k));
    let languages = language.and_then(|l| parse_language(&l));

    // Multi-pattern OR search: split on '|', deduplicate by entity ID
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
    use super::parse_kinds;
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
}
