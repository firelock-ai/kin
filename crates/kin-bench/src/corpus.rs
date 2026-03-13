//! Real-repo corpus harness for validating Kin indexing.
//!
//! Walks real repositories, classifies every file, attempts entity extraction,
//! and reports coverage / fallback metrics.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::error::BenchError;
use kin_index::{FileClassification, FileClassifier};
use kin_model::FilePathId;
use kin_parser::AdapterRegistry;

/// Directories to skip when walking repositories.
const SKIP_DIRS: &[&str] = &[
    "node_modules",
    "target",
    "build",
    "dist",
    "__pycache__",
    "vendor",
    ".git",
];

/// Configuration for a corpus run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorpusConfig {
    pub repo_paths: Vec<PathBuf>,
}

/// Per-repo metrics from a corpus run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorpusResult {
    pub repo_name: String,
    pub repo_path: PathBuf,
    pub total_files: usize,
    pub entity_source_files: usize,
    pub structured_artifact_files: usize,
    pub opaque_artifact_files: usize,
    pub entity_count: usize,
    pub parse_failures: usize,
    pub extensions_seen: HashMap<String, usize>,
    pub structured_kinds: HashMap<String, usize>,
    pub fallback_rate: f64,
}

/// Aggregate summary across all repos.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorpusSummary {
    pub total_repos: usize,
    pub total_files: usize,
    pub total_entity_source: usize,
    pub total_structured: usize,
    pub total_opaque: usize,
    pub total_entities: usize,
    pub total_parse_failures: usize,
    pub overall_fallback_rate: f64,
    pub results: Vec<CorpusResult>,
}

impl CorpusSummary {
    /// Format the summary for terminal display.
    pub fn display(&self) -> String {
        let mut out = String::new();
        out.push_str("=== Corpus Analysis Summary ===\n\n");
        out.push_str(&format!("Repos analyzed:        {}\n", self.total_repos));
        out.push_str(&format!("Total files:           {}\n", self.total_files));
        out.push_str(&format!(
            "Entity source files:   {}\n",
            self.total_entity_source
        ));
        out.push_str(&format!(
            "Structured artifacts:  {}\n",
            self.total_structured
        ));
        out.push_str(&format!("Opaque artifacts:      {}\n", self.total_opaque));
        out.push_str(&format!("Total entities:        {}\n", self.total_entities));
        out.push_str(&format!(
            "Parse failures:        {}\n",
            self.total_parse_failures
        ));
        out.push_str(&format!(
            "Overall fallback rate: {:.1}%\n",
            self.overall_fallback_rate * 100.0
        ));

        if !self.results.is_empty() {
            out.push_str("\n--- Per-Repo Results ---\n");
            for r in &self.results {
                out.push_str(&format!(
                    "\n  {} ({})\n",
                    r.repo_name,
                    r.repo_path.display()
                ));
                out.push_str(&format!(
                    "    Files: {} (entity: {}, structured: {}, opaque: {})\n",
                    r.total_files,
                    r.entity_source_files,
                    r.structured_artifact_files,
                    r.opaque_artifact_files
                ));
                out.push_str(&format!(
                    "    Entities: {}, Parse failures: {}\n",
                    r.entity_count, r.parse_failures
                ));
                out.push_str(&format!(
                    "    Fallback rate: {:.1}%\n",
                    r.fallback_rate * 100.0
                ));

                if !r.extensions_seen.is_empty() {
                    let mut exts: Vec<_> = r.extensions_seen.iter().collect();
                    exts.sort_by(|a, b| b.1.cmp(a.1));
                    let top: Vec<_> = exts
                        .iter()
                        .take(10)
                        .map(|(k, v)| format!(".{}({})", k, v))
                        .collect();
                    out.push_str(&format!("    Top extensions: {}\n", top.join(", ")));
                }
            }
        }

        out
    }
}

/// Runs corpus analysis over real repositories.
pub struct CorpusRunner {
    registry: AdapterRegistry,
}

impl CorpusRunner {
    pub fn new() -> Self {
        Self {
            registry: AdapterRegistry::new(),
        }
    }

    /// Analyze all configured repositories and produce a summary.
    pub fn run(&self, config: &CorpusConfig) -> CorpusSummary {
        let mut results = Vec::new();

        for repo_path in &config.repo_paths {
            match self.analyze_repo(repo_path) {
                Ok(result) => results.push(result),
                Err(e) => {
                    tracing::warn!(
                        repo = %repo_path.display(),
                        error = %e,
                        "skipping repo due to error"
                    );
                }
            }
        }

        let total_repos = results.len();
        let total_files: usize = results.iter().map(|r| r.total_files).sum();
        let total_entity_source: usize = results.iter().map(|r| r.entity_source_files).sum();
        let total_structured: usize = results.iter().map(|r| r.structured_artifact_files).sum();
        let total_opaque: usize = results.iter().map(|r| r.opaque_artifact_files).sum();
        let total_entities: usize = results.iter().map(|r| r.entity_count).sum();
        let total_parse_failures: usize = results.iter().map(|r| r.parse_failures).sum();
        let overall_fallback_rate = if total_files > 0 {
            total_opaque as f64 / total_files as f64
        } else {
            0.0
        };

        CorpusSummary {
            total_repos,
            total_files,
            total_entity_source,
            total_structured,
            total_opaque,
            total_entities,
            total_parse_failures,
            overall_fallback_rate,
            results,
        }
    }

    fn analyze_repo(&self, repo_path: &Path) -> Result<CorpusResult, BenchError> {
        let repo_name = repo_path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown")
            .to_string();

        let mut total_files = 0usize;
        let mut entity_source_files = 0usize;
        let mut structured_artifact_files = 0usize;
        let mut opaque_artifact_files = 0usize;
        let mut entity_count = 0usize;
        let mut parse_failures = 0usize;
        let mut extensions_seen: HashMap<String, usize> = HashMap::new();
        let mut structured_kinds: HashMap<String, usize> = HashMap::new();

        let files = walk_files(repo_path);

        for file_path in &files {
            total_files += 1;

            // Track extension
            if let Some(ext) = file_path.extension().and_then(|e| e.to_str()) {
                *extensions_seen.entry(ext.to_string()).or_default() += 1;
            }

            let classification = FileClassifier::classify(file_path);

            match &classification {
                FileClassification::EntitySource => {
                    entity_source_files += 1;

                    // Try parsing with adapter
                    if let Some(ext) = file_path.extension().and_then(|e| e.to_str()) {
                        if let Some(adapter) = self.registry.get_by_extension(ext) {
                            match std::fs::read(file_path) {
                                Ok(source) => match adapter.parse(&source) {
                                    Ok(tree) => {
                                        let file_id =
                                            FilePathId::new(file_path.display().to_string());
                                        match adapter.extract(&tree, &source, &file_id) {
                                            Ok(output) => {
                                                entity_count += output.entities.len();
                                            }
                                            Err(_) => {
                                                parse_failures += 1;
                                            }
                                        }
                                    }
                                    Err(_) => {
                                        parse_failures += 1;
                                    }
                                },
                                Err(_) => {
                                    // Can't read file — count as parse failure
                                    parse_failures += 1;
                                }
                            }
                        }
                    }
                }
                FileClassification::ShallowSyntax { .. } => {
                    // C2: count as entity-source-adjacent for corpus analysis
                    entity_source_files += 1;
                }
                FileClassification::StructuredArtifact(kind) => {
                    structured_artifact_files += 1;
                    *structured_kinds.entry(format!("{:?}", kind)).or_default() += 1;
                }
                FileClassification::OpaqueArtifact { .. } => {
                    opaque_artifact_files += 1;
                }
            }
        }

        let fallback_rate = if total_files > 0 {
            opaque_artifact_files as f64 / total_files as f64
        } else {
            0.0
        };

        Ok(CorpusResult {
            repo_name,
            repo_path: repo_path.to_path_buf(),
            total_files,
            entity_source_files,
            structured_artifact_files,
            opaque_artifact_files,
            entity_count,
            parse_failures,
            extensions_seen,
            structured_kinds,
            fallback_rate,
        })
    }
}

impl Default for CorpusRunner {
    fn default() -> Self {
        Self::new()
    }
}

/// Walk all files under `root`, skipping hidden directories and common non-source dirs.
fn walk_files(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];

    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(_) => continue,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            let file_name = entry.file_name();
            let name = file_name.to_string_lossy();

            if path.is_dir() {
                // Skip hidden directories (starting with '.')
                if name.starts_with('.') {
                    continue;
                }
                // Skip common non-source directories
                if SKIP_DIRS.contains(&name.as_ref()) {
                    continue;
                }
                stack.push(path);
            } else if path.is_file() {
                files.push(path);
            }
        }
    }

    files
}

/// Discover directories that look like repositories under a parent directory.
///
/// A directory is considered a repo if it contains `src/`, `lib/`, or common
/// source files like `Cargo.toml`, `package.json`, `pyproject.toml`, `go.mod`,
/// `pom.xml`, or a `main.*` file.
pub fn discover_repos(github_dir: &Path) -> Vec<PathBuf> {
    let mut repos = Vec::new();

    let entries = match std::fs::read_dir(github_dir) {
        Ok(e) => e,
        Err(_) => return repos,
    };

    let markers_dirs = ["src", "lib"];
    let markers_files = [
        "Cargo.toml",
        "package.json",
        "pyproject.toml",
        "go.mod",
        "pom.xml",
    ];

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        // Skip hidden dirs
        let name = entry.file_name();
        if name.to_string_lossy().starts_with('.') {
            continue;
        }

        let is_repo = markers_dirs.iter().any(|d| path.join(d).is_dir())
            || markers_files.iter().any(|f| path.join(f).exists())
            || has_main_source_file(&path);

        if is_repo {
            repos.push(path);
        }
    }

    repos.sort();
    repos
}

/// Check if a directory has a main.* source file.
fn has_main_source_file(dir: &Path) -> bool {
    let main_exts = ["rs", "py", "go", "java", "ts", "js"];
    main_exts
        .iter()
        .any(|ext| dir.join(format!("main.{}", ext)).exists())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn walk_files_skips_hidden_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let hidden = tmp.path().join(".hidden");
        std::fs::create_dir_all(&hidden).unwrap();
        std::fs::write(hidden.join("secret.txt"), "secret").unwrap();
        std::fs::write(tmp.path().join("visible.txt"), "visible").unwrap();

        let files = walk_files(tmp.path());
        assert_eq!(files.len(), 1);
        assert!(files[0].ends_with("visible.txt"));
    }

    #[test]
    fn walk_files_skips_node_modules() {
        let tmp = tempfile::tempdir().unwrap();
        let nm = tmp.path().join("node_modules");
        std::fs::create_dir_all(&nm).unwrap();
        std::fs::write(nm.join("dep.js"), "//dep").unwrap();
        std::fs::write(tmp.path().join("app.js"), "//app").unwrap();

        let files = walk_files(tmp.path());
        assert_eq!(files.len(), 1);
        assert!(files[0].ends_with("app.js"));
    }

    #[test]
    fn walk_files_skips_target_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let target = tmp.path().join("target");
        std::fs::create_dir_all(&target).unwrap();
        std::fs::write(target.join("debug.rs"), "//build").unwrap();
        std::fs::write(tmp.path().join("lib.rs"), "//lib").unwrap();

        let files = walk_files(tmp.path());
        assert_eq!(files.len(), 1);
        assert!(files[0].ends_with("lib.rs"));
    }

    #[test]
    fn corpus_runner_empty_config() {
        let runner = CorpusRunner::new();
        let config = CorpusConfig { repo_paths: vec![] };
        let summary = runner.run(&config);
        assert_eq!(summary.total_repos, 0);
        assert_eq!(summary.total_files, 0);
        assert_eq!(summary.overall_fallback_rate, 0.0);
    }

    #[test]
    fn corpus_runner_analyzes_simple_repo() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        std::fs::create_dir_all(&src).unwrap();

        // Entity source file
        std::fs::write(src.join("main.rs"), "fn main() {}").unwrap();
        // Structured artifact
        std::fs::write(tmp.path().join("Cargo.toml"), "[package]\nname = \"test\"").unwrap();
        // Opaque file
        std::fs::write(tmp.path().join("README.md"), "# Hello").unwrap();

        let runner = CorpusRunner::new();
        let config = CorpusConfig {
            repo_paths: vec![tmp.path().to_path_buf()],
        };
        let summary = runner.run(&config);

        assert_eq!(summary.total_repos, 1);
        assert_eq!(summary.total_files, 3);
        assert_eq!(summary.total_entity_source, 1);
        assert_eq!(summary.total_structured, 1);
        assert_eq!(summary.total_opaque, 1);
        // main.rs should produce at least one entity (fn main)
        assert!(summary.total_entities >= 1);
        assert_eq!(summary.total_parse_failures, 0);
    }

    #[test]
    fn corpus_summary_display_not_empty() {
        let summary = CorpusSummary {
            total_repos: 1,
            total_files: 10,
            total_entity_source: 5,
            total_structured: 2,
            total_opaque: 3,
            total_entities: 20,
            total_parse_failures: 1,
            overall_fallback_rate: 0.3,
            results: vec![],
        };
        let display = summary.display();
        assert!(display.contains("Corpus Analysis Summary"));
        assert!(display.contains("10"));
        assert!(display.contains("30.0%"));
    }

    #[test]
    fn discover_repos_finds_cargo_project() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("my-rust-project");
        std::fs::create_dir_all(&repo).unwrap();
        std::fs::write(repo.join("Cargo.toml"), "[package]").unwrap();

        // Also a non-repo directory
        let other = tmp.path().join("random-dir");
        std::fs::create_dir_all(&other).unwrap();
        std::fs::write(other.join("notes.txt"), "notes").unwrap();

        let repos = discover_repos(tmp.path());
        assert_eq!(repos.len(), 1);
        assert!(repos[0].ends_with("my-rust-project"));
    }

    #[test]
    fn discover_repos_finds_src_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let repo = tmp.path().join("some-project");
        std::fs::create_dir_all(repo.join("src")).unwrap();

        let repos = discover_repos(tmp.path());
        assert_eq!(repos.len(), 1);
    }

    #[test]
    fn discover_repos_skips_hidden() {
        let tmp = tempfile::tempdir().unwrap();
        let hidden = tmp.path().join(".hidden-project");
        std::fs::create_dir_all(hidden.join("src")).unwrap();

        let repos = discover_repos(tmp.path());
        assert_eq!(repos.len(), 0);
    }

    #[test]
    fn discover_repos_nonexistent_dir() {
        let repos = discover_repos(Path::new("/nonexistent/path/that/does/not/exist"));
        assert!(repos.is_empty());
    }

    #[test]
    fn corpus_runner_default() {
        let runner = CorpusRunner::default();
        let config = CorpusConfig { repo_paths: vec![] };
        let summary = runner.run(&config);
        assert_eq!(summary.total_repos, 0);
    }

    #[test]
    fn fallback_rate_computation() {
        let tmp = tempfile::tempdir().unwrap();
        // Only opaque files
        std::fs::write(tmp.path().join("data.bin"), &[0u8; 4]).unwrap();
        std::fs::write(tmp.path().join("README.md"), "hello").unwrap();

        let runner = CorpusRunner::new();
        let config = CorpusConfig {
            repo_paths: vec![tmp.path().to_path_buf()],
        };
        let summary = runner.run(&config);
        // Both files are opaque
        assert_eq!(summary.total_files, 2);
        assert_eq!(summary.total_opaque, 2);
        assert!((summary.overall_fallback_rate - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn extensions_tracked() {
        let tmp = tempfile::tempdir().unwrap();
        std::fs::write(tmp.path().join("a.rs"), "fn a() {}").unwrap();
        std::fs::write(tmp.path().join("b.rs"), "fn b() {}").unwrap();
        std::fs::write(tmp.path().join("c.py"), "def c(): pass").unwrap();

        let runner = CorpusRunner::new();
        let config = CorpusConfig {
            repo_paths: vec![tmp.path().to_path_buf()],
        };
        let summary = runner.run(&config);
        let result = &summary.results[0];
        assert_eq!(result.extensions_seen.get("rs"), Some(&2));
        assert_eq!(result.extensions_seen.get("py"), Some(&1));
    }
}
