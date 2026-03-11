use anyhow::Result;
use kin_model::{EntityFilter, EntityKind, GraphStore, LanguageId};

pub async fn run(pattern: String, kind: Option<String>, language: Option<String>) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let graph = kin_graph::KuzuGraphStore::open(&layout.graph_dir())?;

    let kinds = kind.and_then(|k| parse_kind(&k));
    let languages = language.and_then(|l| parse_language(&l));

    let filter = EntityFilter {
        name_pattern: Some(pattern.clone()),
        kinds: kinds.map(|k| vec![k]),
        languages: languages.map(|l| vec![l]),
        ..Default::default()
    };

    let results = graph.query_entities(&filter)?;

    if results.is_empty() {
        println!("No entities matching '{}'", pattern);
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

fn parse_kind(s: &str) -> Option<EntityKind> {
    match s.to_lowercase().as_str() {
        "function" | "fn" => Some(EntityKind::Function),
        "class" => Some(EntityKind::Class),
        "interface" => Some(EntityKind::Interface),
        "trait" => Some(EntityKind::TraitDef),
        "type" => Some(EntityKind::TypeAlias),
        "module" | "mod" => Some(EntityKind::Module),
        "test" => Some(EntityKind::Test),
        "method" => Some(EntityKind::Method),
        "enum" => Some(EntityKind::EnumDef),
        "const" => Some(EntityKind::Constant),
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
