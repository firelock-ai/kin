// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use kin_model::{Entity, RelationKind};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextReferenceMatch {
    pub file_path: String,
    pub start_line: Option<u32>,
    pub relation_kinds: Vec<RelationKind>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TextReferenceOccurrence {
    pub start_line: u32,
    pub start_col: u32,
    pub end_line: u32,
    pub end_col: u32,
    pub relation_kinds: Vec<RelationKind>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TextReferenceOccurrenceMatch {
    pub file_path: String,
    pub occurrences: Vec<TextReferenceOccurrence>,
}

pub fn find_text_references(
    source_root: &Path,
    target: &Entity,
    requested_kinds: &[RelationKind],
) -> Vec<TextReferenceMatch> {
    let Some(target_file) = target.file_origin.as_ref().map(|path| path.0.as_str()) else {
        return Vec::new();
    };
    if !source_root.is_dir() {
        return Vec::new();
    }

    let module_hints = module_hint_candidates(target_file);
    if module_hints.is_empty() {
        return Vec::new();
    }

    let requested: HashSet<_> = requested_kinds.iter().copied().collect();
    let mut matches = Vec::new();
    let mut stack = vec![source_root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(_) => continue,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let file_type = match entry.file_type() {
                Ok(file_type) => file_type,
                Err(_) => continue,
            };

            if file_type.is_dir() {
                if should_skip_dir(&path) {
                    continue;
                }
                stack.push(path);
                continue;
            }

            if !is_supported_source_file(&path) {
                continue;
            }

            let Ok(rel_path) = path.strip_prefix(source_root) else {
                continue;
            };
            let rel_path = normalize_rel_path(rel_path);
            if rel_path == target_file {
                continue;
            }

            let content = match std::fs::read_to_string(&path) {
                Ok(content) => content,
                Err(_) => continue,
            };

            if let Some(found) =
                scan_source_file(&rel_path, &content, &target.name, &module_hints, &requested)
            {
                matches.push(found);
            }
        }
    }

    matches.sort_by(|left, right| left.file_path.cmp(&right.file_path));
    matches
}

pub fn find_text_reference_occurrences(
    source_root: &Path,
    target: &Entity,
    requested_kinds: &[RelationKind],
) -> Vec<TextReferenceOccurrenceMatch> {
    let Some(target_file) = target.file_origin.as_ref().map(|path| path.0.as_str()) else {
        return Vec::new();
    };
    if !source_root.is_dir() {
        return Vec::new();
    }

    let module_hints = module_hint_candidates(target_file);
    if module_hints.is_empty() {
        return Vec::new();
    }

    let requested: HashSet<_> = requested_kinds.iter().copied().collect();
    let mut matches = Vec::new();
    let mut stack = vec![source_root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(_) => continue,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let file_type = match entry.file_type() {
                Ok(file_type) => file_type,
                Err(_) => continue,
            };

            if file_type.is_dir() {
                if should_skip_dir(&path) {
                    continue;
                }
                stack.push(path);
                continue;
            }

            if !is_supported_source_file(&path) {
                continue;
            }

            let Ok(rel_path) = path.strip_prefix(source_root) else {
                continue;
            };
            let rel_path = normalize_rel_path(rel_path);
            if rel_path == target_file {
                continue;
            }

            let content = match std::fs::read_to_string(&path) {
                Ok(content) => content,
                Err(_) => continue,
            };

            if let Some(found) = scan_source_file_occurrences(
                &rel_path,
                &content,
                &target.name,
                &module_hints,
                &requested,
            ) {
                matches.push(found);
            }
        }
    }

    matches.sort_by(|left, right| left.file_path.cmp(&right.file_path));
    matches
}

fn scan_source_file(
    rel_path: &str,
    content: &str,
    symbol: &str,
    module_hints: &[String],
    requested: &HashSet<RelationKind>,
) -> Option<TextReferenceMatch> {
    let import_line = find_import_line(content, symbol, module_hints)?;

    let call_line = if requested.contains(&RelationKind::Calls) {
        find_call_line(content, symbol, import_line)
    } else {
        None
    };
    let reference_line = if requested.contains(&RelationKind::References) {
        find_reference_line(content, symbol, import_line)
    } else {
        None
    };

    let mut relation_kinds = Vec::new();
    if requested.contains(&RelationKind::Imports) {
        relation_kinds.push(RelationKind::Imports);
    }
    if call_line.is_some() {
        relation_kinds.push(RelationKind::Calls);
    }
    if reference_line.is_some() {
        relation_kinds.push(RelationKind::References);
    }

    if relation_kinds.is_empty() {
        return None;
    }

    relation_kinds.sort_by_key(relation_kind_rank);

    Some(TextReferenceMatch {
        file_path: rel_path.to_string(),
        start_line: Some(import_line).or(call_line).or(reference_line),
        relation_kinds,
    })
}

fn scan_source_file_occurrences(
    rel_path: &str,
    content: &str,
    symbol: &str,
    module_hints: &[String],
    requested: &HashSet<RelationKind>,
) -> Option<TextReferenceOccurrenceMatch> {
    let import_line = find_import_line(content, symbol, module_hints)?;
    let mut occurrences = Vec::new();

    for (idx, raw_line) in content.lines().enumerate() {
        let line_no = idx as u32 + 1;
        if line_no != import_line && is_comment_only(raw_line) {
            continue;
        }

        let mut kinds = Vec::new();
        if line_no == import_line && requested.contains(&RelationKind::Imports) {
            kinds.push(RelationKind::Imports);
        }
        let include_calls = line_no != import_line && requested.contains(&RelationKind::Calls);
        let include_refs = line_no != import_line && requested.contains(&RelationKind::References);
        if !include_calls && !include_refs && kinds.is_empty() {
            continue;
        }

        for occurrence in line_token_occurrences(raw_line, symbol, line_no) {
            let mut relation_kinds = kinds.clone();
            if include_calls && token_is_call(raw_line, occurrence.start_col as usize, symbol.len())
            {
                relation_kinds.push(RelationKind::Calls);
            }
            if include_refs {
                relation_kinds.push(RelationKind::References);
            }
            if relation_kinds.is_empty() {
                continue;
            }
            relation_kinds.sort_by_key(relation_kind_rank);
            relation_kinds.dedup();
            occurrences.push(TextReferenceOccurrence {
                start_line: occurrence.start_line,
                start_col: occurrence.start_col,
                end_line: occurrence.end_line,
                end_col: occurrence.end_col,
                relation_kinds,
            });
        }
    }

    if occurrences.is_empty() {
        return None;
    }

    occurrences.sort_by(|left, right| {
        left.start_line
            .cmp(&right.start_line)
            .then_with(|| left.start_col.cmp(&right.start_col))
            .then_with(|| left.end_col.cmp(&right.end_col))
    });

    Some(TextReferenceOccurrenceMatch {
        file_path: rel_path.to_string(),
        occurrences,
    })
}

fn find_import_line(content: &str, symbol: &str, module_hints: &[String]) -> Option<u32> {
    for (idx, raw_line) in content.lines().enumerate() {
        if is_static_import_line(raw_line, symbol, module_hints) {
            return Some(idx as u32 + 1);
        }
    }
    None
}

fn find_call_line(content: &str, symbol: &str, import_line: u32) -> Option<u32> {
    for (idx, raw_line) in content.lines().enumerate() {
        let line_no = idx as u32 + 1;
        if line_no == import_line || is_comment_only(raw_line) {
            continue;
        }
        if contains_symbol_call(raw_line, symbol) {
            return Some(line_no);
        }
    }
    None
}

fn find_reference_line(content: &str, symbol: &str, import_line: u32) -> Option<u32> {
    for (idx, raw_line) in content.lines().enumerate() {
        let line_no = idx as u32 + 1;
        if line_no == import_line || is_comment_only(raw_line) {
            continue;
        }
        if contains_symbol_token(raw_line, symbol) {
            return Some(line_no);
        }
    }
    None
}

fn is_static_import_line(raw_line: &str, symbol: &str, module_hints: &[String]) -> bool {
    let trimmed = raw_line.trim_start();
    if trimmed.is_empty() || is_comment_only(trimmed) {
        return false;
    }
    let mentions_symbol = contains_symbol_token(trimmed, symbol);

    if trimmed.contains("await import(") || trimmed.contains("import_module(") {
        return false;
    }

    if raw_line == trimmed
        && (trimmed.starts_with("from ") || trimmed.starts_with("import "))
        && line_matches_module_hint(trimmed, module_hints)
    {
        return mentions_symbol;
    }

    if (trimmed.starts_with("import ") || trimmed.starts_with("export "))
        && trimmed.contains(" from ")
        && line_matches_module_hint(trimmed, module_hints)
    {
        return mentions_symbol;
    }

    if (trimmed.starts_with("use ") || trimmed.starts_with("pub use "))
        && line_matches_module_hint(trimmed, module_hints)
    {
        return mentions_symbol;
    }

    if trimmed.starts_with("#include") && line_matches_module_hint(trimmed, module_hints) {
        return true;
    }

    if trimmed.starts_with("using ") && line_matches_module_hint(trimmed, module_hints) {
        return true;
    }

    if (trimmed.starts_with("require ") || trimmed.starts_with("require_relative "))
        && line_matches_module_hint(trimmed, module_hints)
    {
        return true;
    }

    if trimmed.contains("require(") && line_matches_static_require(trimmed, module_hints) {
        return true;
    }

    false
}

fn line_matches_static_require(line: &str, module_hints: &[String]) -> bool {
    module_hints.iter().any(|hint| {
        line.contains(&format!("require('{hint}')"))
            || line.contains(&format!("require(\"{hint}\")"))
    })
}

fn line_matches_module_hint(line: &str, module_hints: &[String]) -> bool {
    module_hints.iter().any(|hint| line.contains(hint))
}

fn contains_symbol_call(line: &str, symbol: &str) -> bool {
    for index in symbol_match_indices(line, symbol) {
        let rest = &line[index + symbol.len()..];
        if rest.trim_start().starts_with('(') {
            return true;
        }
    }
    false
}

fn contains_symbol_token(line: &str, symbol: &str) -> bool {
    symbol_match_indices(line, symbol).next().is_some()
}

fn line_token_occurrences(line: &str, symbol: &str, line_no: u32) -> Vec<TextReferenceOccurrence> {
    symbol_match_indices(line, symbol)
        .map(|start| TextReferenceOccurrence {
            start_line: line_no,
            start_col: start as u32,
            end_line: line_no,
            end_col: (start + symbol.len()) as u32,
            relation_kinds: Vec::new(),
        })
        .collect()
}

fn token_is_call(line: &str, start: usize, symbol_len: usize) -> bool {
    let rest = &line[start + symbol_len..];
    rest.trim_start().starts_with('(')
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

fn relation_kind_rank(kind: &RelationKind) -> usize {
    match kind {
        RelationKind::Imports => 0,
        RelationKind::Calls => 1,
        RelationKind::References => 2,
        _ => 3,
    }
}

fn module_hint_candidates(rel_path: &str) -> Vec<String> {
    let path = Path::new(rel_path);
    let mut hints = HashSet::new();

    if let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) {
        hints.insert(stem.to_string());
        hints.insert(format!("./{stem}"));
        hints.insert(format!(".{stem}"));
    }

    let mut hints = hints.into_iter().collect::<Vec<_>>();
    hints.sort_by_key(|hint| std::cmp::Reverse(hint.len()));
    hints
}

fn normalize_rel_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn should_skip_dir(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    matches!(
        name,
        ".git"
            | ".kin"
            | "node_modules"
            | "__pycache__"
            | "target"
            | "dist"
            | "build"
            | "vendor"
            | "out"
            | ".venv"
            | "venv"
            | "coverage"
    ) || name.starts_with(".kin-")
}

fn is_supported_source_file(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|ext| ext.to_str()).unwrap_or(""),
        "ts" | "tsx"
            | "js"
            | "jsx"
            | "py"
            | "rs"
            | "go"
            | "java"
            | "c"
            | "h"
            | "cpp"
            | "hpp"
            | "cc"
            | "cxx"
            | "cs"
            | "rb"
    )
}

fn is_comment_only(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("//")
        || (trimmed.starts_with('#') && !trimmed.starts_with("#include"))
        || trimmed.starts_with("/*")
        || trimmed.starts_with('*')
}

#[cfg(test)]
mod tests {
    use super::{find_text_references, TextReferenceMatch};
    use kin_model::{
        Entity, EntityId, EntityKind, EntityMetadata, EntityRole, FilePathId, FingerprintAlgorithm,
        Hash256, LanguageId, RelationKind, SemanticFingerprint, Visibility,
    };
    use pretty_assertions::assert_eq;

    fn test_entity(rel_path: &str, name: &str, kind: EntityKind, language: LanguageId) -> Entity {
        Entity {
            id: EntityId::new(),
            kind,
            name: name.to_string(),
            language,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0; 32]),
                signature_hash: Hash256::from_bytes([0; 32]),
                behavior_hash: Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new(rel_path)),
            span: None,
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

    fn write(path: &std::path::Path, content: &str) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, content).unwrap();
    }

    #[test]
    fn finds_static_js_importers_and_callers_only() {
        let dir = tempfile::tempdir().unwrap();
        write(
            &dir.path().join("planted/callers/shared_abc123.ts"),
            "export function probeFormat_abc123(value: string) { return value; }\n",
        );
        write(
            &dir.path().join("planted/callers/use_abc123_0.ts"),
            "import { probeFormat_abc123 } from './shared_abc123';\n\
             export function useFormat_abc123_0(value: string) {\n\
               return probeFormat_abc123(value);\n\
             }\n",
        );
        write(
            &dir.path().join("planted/callers/reexport_abc123_0.ts"),
            "import { probeFormat_abc123 } from './shared_abc123';\n\
             export { probeFormat_abc123 };\n",
        );
        write(
            &dir.path().join("planted/callers/local_abc123_0.ts"),
            "function probeFormat_abc123(value: string) { return value.trim(); }\n\
             export function localUse(value: string) { return probeFormat_abc123(value); }\n",
        );
        write(
            &dir.path().join("planted/callers/subtle_abc123_0.ts"),
            "// import { probeFormat_abc123 } from './shared_abc123';\n\
             function probeFormat_abc123(value: string) { return value; }\n",
        );
        write(
            &dir.path().join("planted/callers/subtle_abc123_1.ts"),
            "let probeFormat_abc123: (value: string) => string;\n\
             if (false) {\n\
               const mod = await import('./shared_abc123');\n\
               probeFormat_abc123 = mod.probeFormat_abc123;\n\
             }\n",
        );
        write(
            &dir.path().join("planted/callers/subtle_abc123_2.ts"),
            "const _moduleName = './shared_abc123';\n\
             const _mod = require(_moduleName);\n\
             const probeFormat_abc123 = _mod.probeFormat_abc123;\n",
        );

        let target = test_entity(
            "planted/callers/shared_abc123.ts",
            "probeFormat_abc123",
            EntityKind::Function,
            LanguageId::TypeScript,
        );

        let matches = find_text_references(
            dir.path(),
            &target,
            &[
                RelationKind::Calls,
                RelationKind::Imports,
                RelationKind::References,
            ],
        );

        assert_eq!(
            matches,
            vec![
                TextReferenceMatch {
                    file_path: "planted/callers/reexport_abc123_0.ts".to_string(),
                    start_line: Some(1),
                    relation_kinds: vec![RelationKind::Imports, RelationKind::References,],
                },
                TextReferenceMatch {
                    file_path: "planted/callers/use_abc123_0.ts".to_string(),
                    start_line: Some(1),
                    relation_kinds: vec![
                        RelationKind::Imports,
                        RelationKind::Calls,
                        RelationKind::References,
                    ],
                },
            ]
        );
    }

    #[test]
    fn ignores_indented_python_dead_imports() {
        let dir = tempfile::tempdir().unwrap();
        write(
            &dir.path().join("planted/impact/config_abc123.py"),
            "class ProbeConfig_abc123:\n    pass\n",
        );
        write(
            &dir.path().join("planted/impact/apply_host_abc123.py"),
            "from .config_abc123 import ProbeConfig_abc123\n\
             \n\
             def apply_config(cfg: ProbeConfig_abc123):\n\
                 return cfg\n",
        );
        write(
            &dir.path().join("planted/impact/subtle_abc123.py"),
            "if False:\n    from .config_abc123 import ProbeConfig_abc123\n",
        );

        let target = test_entity(
            "planted/impact/config_abc123.py",
            "ProbeConfig_abc123",
            EntityKind::Interface,
            LanguageId::Python,
        );

        let matches = find_text_references(dir.path(), &target, &[RelationKind::Imports]);

        assert_eq!(
            matches,
            vec![TextReferenceMatch {
                file_path: "planted/impact/apply_host_abc123.py".to_string(),
                start_line: Some(1),
                relation_kinds: vec![RelationKind::Imports],
            }]
        );
    }

    #[test]
    fn finds_static_rust_importers_and_callers_only() {
        let dir = tempfile::tempdir().unwrap();
        write(
            &dir.path().join("planted/callers/shared_abc123.rs"),
            "pub fn probe_format_abc123(value: &str) -> String { value.to_string() }\n",
        );
        write(
            &dir.path().join("planted/callers/use_abc123_0.rs"),
            "use crate::planted::callers::shared_abc123::probe_format_abc123;\n\
             pub fn use_format_abc123_0(value: &str) -> String {\n\
               probe_format_abc123(value)\n\
             }\n",
        );
        write(
            &dir.path().join("planted/callers/reexport_abc123_0.rs"),
            "pub use crate::planted::callers::shared_abc123::probe_format_abc123;\n\
             pub const IMPORT_ONLY_MARKER_abc123_0: &str = \"imported-not-called\";\n",
        );
        write(
            &dir.path().join("planted/callers/local_abc123_0.rs"),
            "fn probe_format_abc123(value: &str) -> String { value.trim().to_string() }\n\
             pub fn local_use(value: &str) -> String { probe_format_abc123(value) }\n",
        );
        write(
            &dir.path().join("planted/callers/subtle_abc123_0.rs"),
            "// use crate::planted::callers::shared_abc123::probe_format_abc123;\n\
             fn probe_format_abc123(value: &str) -> String { value.to_string() }\n",
        );

        let target = test_entity(
            "planted/callers/shared_abc123.rs",
            "probe_format_abc123",
            EntityKind::Function,
            LanguageId::Rust,
        );

        let matches = find_text_references(
            dir.path(),
            &target,
            &[
                RelationKind::Calls,
                RelationKind::Imports,
                RelationKind::References,
            ],
        );

        assert_eq!(
            matches,
            vec![
                TextReferenceMatch {
                    file_path: "planted/callers/reexport_abc123_0.rs".to_string(),
                    start_line: Some(1),
                    relation_kinds: vec![RelationKind::Imports],
                },
                TextReferenceMatch {
                    file_path: "planted/callers/use_abc123_0.rs".to_string(),
                    start_line: Some(1),
                    relation_kinds: vec![
                        RelationKind::Imports,
                        RelationKind::Calls,
                        RelationKind::References,
                    ],
                },
            ]
        );
    }

    #[test]
    fn finds_static_c_importers_and_callers_only() {
        let dir = tempfile::tempdir().unwrap();
        write(
            &dir.path().join("planted/callers/shared_abc123.h"),
            "int probe_format_abc123(const char* value);\n",
        );
        write(
            &dir.path().join("planted/callers/use_abc123_0.c"),
            "#include \"shared_abc123.h\"\n\
             int use_format_abc123_0(const char* value) {\n\
               return probe_format_abc123(value);\n\
             }\n",
        );

        let target = test_entity(
            "planted/callers/shared_abc123.h",
            "probe_format_abc123",
            EntityKind::Function,
            LanguageId::C,
        );

        let matches = find_text_references(
            dir.path(),
            &target,
            &[
                RelationKind::Calls,
                RelationKind::Imports,
                RelationKind::References,
            ],
        );

        assert_eq!(
            matches,
            vec![TextReferenceMatch {
                file_path: "planted/callers/use_abc123_0.c".to_string(),
                start_line: Some(1),
                relation_kinds: vec![
                    RelationKind::Imports,
                    RelationKind::Calls,
                    RelationKind::References,
                ],
            }]
        );
    }

    #[test]
    fn finds_static_ruby_require_and_calls() {
        let dir = tempfile::tempdir().unwrap();
        write(
            &dir.path().join("planted/callers/shared_abc123.rb"),
            "def probe_format_abc123(value)\n  value.strip\nend\n",
        );
        write(
            &dir.path().join("planted/callers/use_abc123_0.rb"),
            "require_relative './shared_abc123'\n\
             def use_format_abc123_0(value)\n\
               probe_format_abc123(value)\n\
             end\n",
        );

        let target = test_entity(
            "planted/callers/shared_abc123.rb",
            "probe_format_abc123",
            EntityKind::Function,
            LanguageId::Ruby,
        );

        let matches = find_text_references(
            dir.path(),
            &target,
            &[
                RelationKind::Calls,
                RelationKind::Imports,
                RelationKind::References,
            ],
        );

        assert_eq!(
            matches,
            vec![TextReferenceMatch {
                file_path: "planted/callers/use_abc123_0.rb".to_string(),
                start_line: Some(1),
                relation_kinds: vec![
                    RelationKind::Imports,
                    RelationKind::Calls,
                    RelationKind::References,
                ],
            }]
        );
    }

    #[test]
    fn finds_static_go_importers_and_callers_only() {
        let dir = tempfile::tempdir().unwrap();
        write(
            &dir.path().join("planted/callers/shared_abc123.go"),
            "package shared_abc123\n\nfunc probe_format_abc123(value string) string { return value }\n",
        );
        write(
            &dir.path().join("planted/callers/use_abc123_0.go"),
            "package use_abc123_0\n\nimport shared_abc123 \"./shared_abc123\" // probe_format_abc123\n\nfunc use_format_abc123_0(value string) string {\n  return shared_abc123.probe_format_abc123(value)\n}\n",
        );
        write(
            &dir.path().join("planted/callers/reexport_abc123_0.go"),
            "package reexport_abc123_0\n\nimport shared_abc123 \"./shared_abc123\" // probe_format_abc123\n\nvar _ = shared_abc123.probe_format_abc123\n",
        );
        write(
            &dir.path().join("planted/callers/local_abc123_0.go"),
            "package local_abc123_0\n\nfunc probe_format_abc123(value string) string { return value + \"-local\" }\n",
        );

        let target = test_entity(
            "planted/callers/shared_abc123.go",
            "probe_format_abc123",
            EntityKind::Function,
            LanguageId::Go,
        );

        let matches = find_text_references(
            dir.path(),
            &target,
            &[
                RelationKind::Calls,
                RelationKind::Imports,
                RelationKind::References,
            ],
        );

        assert_eq!(
            matches,
            vec![
                TextReferenceMatch {
                    file_path: "planted/callers/reexport_abc123_0.go".to_string(),
                    start_line: Some(3),
                    relation_kinds: vec![RelationKind::Imports, RelationKind::References],
                },
                TextReferenceMatch {
                    file_path: "planted/callers/use_abc123_0.go".to_string(),
                    start_line: Some(3),
                    relation_kinds: vec![
                        RelationKind::Imports,
                        RelationKind::Calls,
                        RelationKind::References,
                    ],
                },
            ]
        );
    }

    #[test]
    fn finds_static_java_importers_and_callers_only() {
        let dir = tempfile::tempdir().unwrap();
        write(
            &dir.path().join("planted/callers/shared_abc123.java"),
            "package planted.callers;\n\nclass shared_abc123 {\n  static String probeFormat_abc123(String value) { return value; }\n}\n",
        );
        write(
            &dir.path().join("planted/callers/use_abc123_0.java"),
            "package planted.callers;\n\nimport static planted.callers.shared_abc123.probeFormat_abc123;\n\nclass use_abc123_0 {\n  static String useFormat(String value) { return probeFormat_abc123(value); }\n}\n",
        );
        write(
            &dir.path().join("planted/callers/reexport_abc123_0.java"),
            "package planted.callers;\n\nimport static planted.callers.shared_abc123.probeFormat_abc123;\n\nclass reexport_abc123_0 {\n  static final Object MARKER = probeFormat_abc123;\n}\n",
        );
        write(
            &dir.path().join("planted/callers/local_abc123_0.java"),
            "package planted.callers;\n\nclass local_abc123_0 {\n  static String probeFormat_abc123(String value) { return value + \"-local\"; }\n}\n",
        );

        let target = test_entity(
            "planted/callers/shared_abc123.java",
            "probeFormat_abc123",
            EntityKind::Method,
            LanguageId::Java,
        );

        let matches = find_text_references(
            dir.path(),
            &target,
            &[
                RelationKind::Calls,
                RelationKind::Imports,
                RelationKind::References,
            ],
        );

        assert_eq!(
            matches,
            vec![
                TextReferenceMatch {
                    file_path: "planted/callers/reexport_abc123_0.java".to_string(),
                    start_line: Some(3),
                    relation_kinds: vec![RelationKind::Imports, RelationKind::References],
                },
                TextReferenceMatch {
                    file_path: "planted/callers/use_abc123_0.java".to_string(),
                    start_line: Some(3),
                    relation_kinds: vec![
                        RelationKind::Imports,
                        RelationKind::Calls,
                        RelationKind::References,
                    ],
                },
            ]
        );
    }
}
