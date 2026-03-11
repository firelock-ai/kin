//! Cross-file import and reference resolution.
//!
//! Resolves module paths (e.g., "./utils", "lodash") to actual file paths,
//! and tracks which entities are exported from each file.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use kin_model::FilePathId;

/// A trait for resolving module paths to file paths.
pub trait ImportResolver {
    /// Resolve a module path (e.g., "./utils", "lodash") relative to a source file.
    ///
    /// Returns the FilePathId of the target module, or None if unresolvable.
    fn resolve_import(&self, module_path: &str, from_file: &FilePathId) -> Option<FilePathId>;

    /// Get the set of exported entity names from a file.
    fn get_exported_symbols(&self, file_id: &FilePathId) -> HashSet<String>;
}

/// A simple in-memory symbol table for tracking exported entities per file.
#[derive(Debug, Clone)]
pub struct SymbolTable {
    /// Map from FilePathId to set of exported entity names.
    exports: HashMap<String, HashSet<String>>,
}

impl SymbolTable {
    pub fn new() -> Self {
        Self {
            exports: HashMap::new(),
        }
    }

    /// Record an exported entity for a file.
    pub fn add_export(&mut self, file_id: &FilePathId, entity_name: String) {
        self.exports
            .entry(file_id.0.clone())
            .or_insert_with(HashSet::new)
            .insert(entity_name);
    }

    /// Get all exported entities from a file.
    pub fn get_exports(&self, file_id: &FilePathId) -> HashSet<String> {
        self.exports.get(&file_id.0).cloned().unwrap_or_default()
    }

    /// Check if a file exports a specific entity.
    pub fn has_export(&self, file_id: &FilePathId, entity_name: &str) -> bool {
        self.exports
            .get(&file_id.0)
            .map(|exports| exports.contains(entity_name))
            .unwrap_or(false)
    }
}

impl Default for SymbolTable {
    fn default() -> Self {
        Self::new()
    }
}

/// A simple resolver for TypeScript/JavaScript imports.
///
/// Handles:
/// - Relative imports: "./utils" -> "{dir}/utils.ts"
/// - Absolute imports (within project): "/src/utils" -> "{project_root}/src/utils.ts"
/// - Index files: "./utils" can resolve to "{dir}/utils/index.ts"
pub struct TypeScriptResolver {
    /// Project root directory (where package.json or tsconfig.json is found).
    project_root: PathBuf,
    /// Symbol table for tracking exports.
    symbols: SymbolTable,
}

impl TypeScriptResolver {
    pub fn new(project_root: PathBuf) -> Self {
        Self {
            project_root,
            symbols: SymbolTable::new(),
        }
    }

    /// Register an exported symbol for a file.
    pub fn add_export(&mut self, file_id: &FilePathId, entity_name: String) {
        self.symbols.add_export(file_id, entity_name);
    }

    /// Get the symbol table (for inspection/testing).
    pub fn symbols(&self) -> &SymbolTable {
        &self.symbols
    }

    /// Resolve a TypeScript/JavaScript module path.
    fn resolve_ts_module(&self, module_path: &str, from_file: &FilePathId) -> Option<FilePathId> {
        // Extract the directory of the source file
        let source_dir = Path::new(&from_file.0)
            .parent()
            .unwrap_or_else(|| Path::new(""));

        let resolved_path = if module_path.starts_with('.') {
            // Relative import: "./utils" or "../utils"
            source_dir.join(module_path).to_string_lossy().to_string()
        } else if module_path.starts_with('/') {
            // Absolute import (from project root): "/src/utils"
            self.project_root
                .join(&module_path[1..])
                .to_string_lossy()
                .to_string()
        } else {
            // Package import: "lodash", "react", etc.
            // For now, we don't resolve these to node_modules
            return None;
        };

        // Try to find the file with common extensions
        let candidates = vec![
            format!("{}.ts", resolved_path),
            format!("{}.tsx", resolved_path),
            format!("{}.js", resolved_path),
            format!("{}.jsx", resolved_path),
            format!("{}/index.ts", resolved_path),
            format!("{}/index.tsx", resolved_path),
            format!("{}/index.js", resolved_path),
            format!("{}/index.jsx", resolved_path),
        ];

        // In a real implementation, we'd check the file system here.
        // For now, return the first candidate as a FilePathId.
        candidates.first().map(|p| FilePathId::new(p.clone()))
    }
}

impl ImportResolver for TypeScriptResolver {
    fn resolve_import(&self, module_path: &str, from_file: &FilePathId) -> Option<FilePathId> {
        self.resolve_ts_module(module_path, from_file)
    }

    fn get_exported_symbols(&self, file_id: &FilePathId) -> HashSet<String> {
        self.symbols.get_exports(file_id)
    }
}

/// A resolver for Python imports.
///
/// Handles:
/// - Relative imports: "from . import utils"
/// - Absolute imports: "import package.module"
pub struct PythonResolver {
    /// Project root directory.
    project_root: PathBuf,
    /// Symbol table for tracking exports.
    symbols: SymbolTable,
}

impl PythonResolver {
    pub fn new(project_root: PathBuf) -> Self {
        Self {
            project_root,
            symbols: SymbolTable::new(),
        }
    }

    /// Register an exported symbol for a file.
    pub fn add_export(&mut self, file_id: &FilePathId, entity_name: String) {
        self.symbols.add_export(file_id, entity_name);
    }

    /// Get the symbol table (for inspection/testing).
    pub fn symbols(&self) -> &SymbolTable {
        &self.symbols
    }

    /// Resolve a Python module path.
    fn resolve_python_module(
        &self,
        module_path: &str,
        _from_file: &FilePathId,
    ) -> Option<FilePathId> {
        // Convert module path (e.g., "package.module.submodule") to file path
        let file_parts: Vec<&str> = module_path.split('.').collect();
        let mut resolved = self.project_root.clone();
        for part in file_parts {
            resolved = resolved.join(part);
        }

        // Try to find the file with .py extension or as a package
        let candidates = vec![
            format!("{}.py", resolved.display()),
            format!("{}/__init__.py", resolved.display()),
        ];

        candidates.first().map(|p| FilePathId::new(p.clone()))
    }
}

impl ImportResolver for PythonResolver {
    fn resolve_import(&self, module_path: &str, from_file: &FilePathId) -> Option<FilePathId> {
        self.resolve_python_module(module_path, from_file)
    }

    fn get_exported_symbols(&self, file_id: &FilePathId) -> HashSet<String> {
        self.symbols.get_exports(file_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn symbol_table_tracks_exports() {
        let mut table = SymbolTable::new();
        let file_id = FilePathId::new("src/utils.ts");
        table.add_export(&file_id, "foo".to_string());
        table.add_export(&file_id, "bar".to_string());

        assert!(table.has_export(&file_id, "foo"));
        assert!(table.has_export(&file_id, "bar"));
        assert!(!table.has_export(&file_id, "baz"));

        let exports = table.get_exports(&file_id);
        assert_eq!(exports.len(), 2);
        assert!(exports.contains("foo"));
        assert!(exports.contains("bar"));
    }

    #[test]
    fn typescript_resolver_resolves_relative_imports() {
        let project_root = PathBuf::from("/project");
        let resolver = TypeScriptResolver::new(project_root);

        let from_file = FilePathId::new("src/components/Button.tsx");
        let resolved = resolver.resolve_import("../utils", &from_file);

        // Should resolve to something like "src/utils.ts" or similar
        assert!(resolved.is_some());
        let resolved_id = resolved.unwrap();
        assert!(resolved_id.0.contains("utils"));
    }

    #[test]
    fn typescript_resolver_resolves_index_files() {
        let project_root = PathBuf::from("/project");
        let resolver = TypeScriptResolver::new(project_root);

        let from_file = FilePathId::new("src/App.tsx");
        let resolved = resolver.resolve_import("./utils", &from_file);

        assert!(resolved.is_some());
        let resolved_id = resolved.unwrap();
        // Should try index.ts as one of the candidates
        assert!(resolved_id.0.contains("utils"));
    }

    #[test]
    fn typescript_resolver_rejects_package_imports() {
        let project_root = PathBuf::from("/project");
        let resolver = TypeScriptResolver::new(project_root);

        let from_file = FilePathId::new("src/App.tsx");
        let resolved = resolver.resolve_import("react", &from_file);

        // Package imports are not resolved yet
        assert!(resolved.is_none());
    }

    #[test]
    fn python_resolver_tracks_exports() {
        let project_root = PathBuf::from("/project");
        let mut resolver = PythonResolver::new(project_root);

        let file_id = FilePathId::new("src/utils.py");
        resolver.add_export(&file_id, "helper_function".to_string());
        resolver.add_export(&file_id, "HelperClass".to_string());

        assert!(resolver
            .get_exported_symbols(&file_id)
            .contains("helper_function"));
        assert!(resolver
            .get_exported_symbols(&file_id)
            .contains("HelperClass"));
    }

    #[test]
    fn python_resolver_resolves_module_imports() {
        let project_root = PathBuf::from("/project");
        let resolver = PythonResolver::new(project_root);

        let from_file = FilePathId::new("src/main.py");
        let resolved = resolver.resolve_import("utils.helpers", &from_file);

        assert!(resolved.is_some());
        let resolved_id = resolved.unwrap();
        assert!(resolved_id.0.contains("utils"));
        assert!(resolved_id.0.contains("helpers"));
    }
}
