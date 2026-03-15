use kin_model::{FileLayout, ImportItem, LanguageId};

use crate::splice::Splice;

/// Add an import statement to a file's import section.
///
/// Returns a Splice that inserts the import at the end of the existing
/// import section. Language-specific formatting is applied.
pub fn add_import(
    layout: &FileLayout,
    language: LanguageId,
    source: &str,
    symbols: &[String],
) -> Splice {
    let insert_pos = layout.imports.byte_range.end;
    let import_text = format_import(language, source, symbols);

    Splice {
        byte_range: insert_pos..insert_pos,
        new_content: import_text.into_bytes(),
    }
}

/// Remove an import statement from a file's import section.
///
/// Finds the ImportItem matching `source` and returns a Splice that
/// removes it. Returns None if the import is not found.
pub fn remove_import(layout: &FileLayout, source: &str) -> Option<Splice> {
    let item = layout.imports.items.iter().find(|i| i.source == source)?;

    Some(Splice {
        byte_range: item.byte_range.clone(),
        new_content: Vec::new(),
    })
}

/// Update an existing import to add or remove symbols.
///
/// If the import source exists, regenerate the import line with the new
/// symbol list. Returns None if the import is not found.
pub fn update_import_symbols(
    layout: &FileLayout,
    language: LanguageId,
    source: &str,
    new_symbols: &[String],
) -> Option<Splice> {
    let item = layout.imports.items.iter().find(|i| i.source == source)?;

    let import_text = format_import(language, source, new_symbols);

    Some(Splice {
        byte_range: item.byte_range.clone(),
        new_content: import_text.into_bytes(),
    })
}

/// Format an import statement for a specific language.
fn format_import(language: LanguageId, source: &str, symbols: &[String]) -> String {
    match language {
        LanguageId::TypeScript | LanguageId::JavaScript => {
            if symbols.is_empty() {
                format!("import '{source}';\n")
            } else {
                let syms = symbols.join(", ");
                format!("import {{ {syms} }} from '{source}';\n")
            }
        }
        LanguageId::Python => {
            if symbols.is_empty() {
                format!("import {source}\n")
            } else {
                let syms = symbols.join(", ");
                format!("from {source} import {syms}\n")
            }
        }
        LanguageId::Rust => {
            if symbols.is_empty() {
                format!("use {source};\n")
            } else if symbols.len() == 1 {
                format!("use {}::{};\n", source, symbols[0])
            } else {
                let syms = symbols.join(", ");
                format!("use {source}::{{{syms}}};\n")
            }
        }
        LanguageId::Go => {
            // Go imports don't have named symbols in the same way
            format!("import \"{source}\"\n")
        }
        LanguageId::Java => {
            if symbols.is_empty() {
                format!("import {source}.*;\n")
            } else {
                let mut result = String::new();
                for sym in symbols {
                    result.push_str(&format!("import {source}.{sym};\n"));
                }
                result
            }
        }
        LanguageId::C | LanguageId::Cpp => format!("#include \"{source}\"\n"),
        LanguageId::CSharp => format!("using {source};\n"),
        LanguageId::Ruby => {
            if source.starts_with("./") || source.starts_with("../") {
                format!("require_relative '{source}'\n")
            } else {
                format!("require '{source}'\n")
            }
        }
    }
}

/// Check if two import sections conflict (same source, different symbols).
pub fn imports_conflict(a: &ImportItem, b: &ImportItem) -> bool {
    a.source == b.source && a.symbols != b.symbols
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{FilePathId, ImportSection};

    fn make_layout_with_imports(items: Vec<ImportItem>, import_end: usize) -> FileLayout {
        FileLayout {
            file_id: FilePathId::new("test.ts"),
            imports: ImportSection {
                byte_range: 0..import_end,
                items,
            },
            regions: vec![],
        }
    }

    #[test]
    fn format_typescript_import_with_symbols() {
        let result = format_import(
            LanguageId::TypeScript,
            "react",
            &["useState".to_string(), "useEffect".to_string()],
        );
        assert_eq!(result, "import { useState, useEffect } from 'react';\n");
    }

    #[test]
    fn format_typescript_side_effect_import() {
        let result = format_import(LanguageId::TypeScript, "./styles.css", &[]);
        assert_eq!(result, "import './styles.css';\n");
    }

    #[test]
    fn format_python_from_import() {
        let result = format_import(
            LanguageId::Python,
            "os.path",
            &["join".to_string(), "exists".to_string()],
        );
        assert_eq!(result, "from os.path import join, exists\n");
    }

    #[test]
    fn format_python_bare_import() {
        let result = format_import(LanguageId::Python, "os", &[]);
        assert_eq!(result, "import os\n");
    }

    #[test]
    fn format_rust_use() {
        let result = format_import(
            LanguageId::Rust,
            "std::collections",
            &["HashMap".to_string(), "HashSet".to_string()],
        );
        assert_eq!(result, "use std::collections::{HashMap, HashSet};\n");
    }

    #[test]
    fn format_rust_single_use() {
        let result = format_import(LanguageId::Rust, "std::io", &["Read".to_string()]);
        assert_eq!(result, "use std::io::Read;\n");
    }

    #[test]
    fn format_go_import() {
        let result = format_import(LanguageId::Go, "fmt", &[]);
        assert_eq!(result, "import \"fmt\"\n");
    }

    #[test]
    fn format_java_import() {
        let result = format_import(LanguageId::Java, "java.util", &["List".to_string()]);
        assert_eq!(result, "import java.util.List;\n");
    }

    #[test]
    fn format_c_include() {
        let result = format_import(LanguageId::C, "shared.h", &[]);
        assert_eq!(result, "#include \"shared.h\"\n");
    }

    #[test]
    fn format_csharp_using() {
        let result = format_import(LanguageId::CSharp, "System.Collections.Generic", &[]);
        assert_eq!(result, "using System.Collections.Generic;\n");
    }

    #[test]
    fn format_ruby_require_relative() {
        let result = format_import(LanguageId::Ruby, "./user_service", &[]);
        assert_eq!(result, "require_relative './user_service'\n");
    }

    #[test]
    fn add_import_creates_splice_at_end() {
        let layout = make_layout_with_imports(vec![], 30);
        let splice = add_import(
            &layout,
            LanguageId::TypeScript,
            "lodash",
            &["map".to_string()],
        );
        assert_eq!(splice.byte_range, 30..30);
        assert_eq!(
            String::from_utf8(splice.new_content).unwrap(),
            "import { map } from 'lodash';\n"
        );
    }

    #[test]
    fn remove_import_creates_splice() {
        let items = vec![ImportItem {
            source: "react".to_string(),
            symbols: vec!["useState".to_string()],
            byte_range: 0..35,
        }];
        let layout = make_layout_with_imports(items, 35);
        let splice = remove_import(&layout, "react").unwrap();
        assert_eq!(splice.byte_range, 0..35);
        assert!(splice.new_content.is_empty());
    }

    #[test]
    fn remove_import_returns_none_for_missing() {
        let layout = make_layout_with_imports(vec![], 0);
        assert!(remove_import(&layout, "nonexistent").is_none());
    }

    #[test]
    fn update_import_symbols_works() {
        let items = vec![ImportItem {
            source: "react".to_string(),
            symbols: vec!["useState".to_string()],
            byte_range: 0..35,
        }];
        let layout = make_layout_with_imports(items, 35);
        let splice = update_import_symbols(
            &layout,
            LanguageId::TypeScript,
            "react",
            &["useState".to_string(), "useEffect".to_string()],
        )
        .unwrap();
        assert_eq!(splice.byte_range, 0..35);
        assert_eq!(
            String::from_utf8(splice.new_content).unwrap(),
            "import { useState, useEffect } from 'react';\n"
        );
    }

    #[test]
    fn imports_conflict_detects_mismatch() {
        let a = ImportItem {
            source: "react".to_string(),
            symbols: vec!["useState".to_string()],
            byte_range: 0..30,
        };
        let b = ImportItem {
            source: "react".to_string(),
            symbols: vec!["useEffect".to_string()],
            byte_range: 0..30,
        };
        assert!(imports_conflict(&a, &b));
    }

    #[test]
    fn imports_no_conflict_when_same() {
        let a = ImportItem {
            source: "react".to_string(),
            symbols: vec!["useState".to_string()],
            byte_range: 0..30,
        };
        let b = ImportItem {
            source: "react".to_string(),
            symbols: vec!["useState".to_string()],
            byte_range: 30..60,
        };
        assert!(!imports_conflict(&a, &b));
    }
}
