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

// ---------------------------------------------------------------------------
// Corpus Manifest — curated set of public repos for benchmarking
// ---------------------------------------------------------------------------

/// Size tier for a corpus repository.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CorpusTier {
    /// <1K expected entities
    Small,
    /// 1K–10K expected entities
    Medium,
    /// 10K–50K expected entities
    Large,
    /// 50K+ expected entities (partial clone recommended)
    ExtraLarge,
}

impl CorpusTier {
    pub fn as_str(&self) -> &'static str {
        match self {
            CorpusTier::Small => "small",
            CorpusTier::Medium => "medium",
            CorpusTier::Large => "large",
            CorpusTier::ExtraLarge => "xl",
        }
    }
}

impl std::fmt::Display for CorpusTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A single entry in the corpus manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorpusEntry {
    /// Short name (e.g. "zod", "react").
    pub name: String,
    /// GitHub HTTPS clone URL.
    pub github_url: String,
    /// Expected entity count range: (min, max).
    pub expected_entities: (usize, usize),
    /// Primary programming languages.
    pub languages: Vec<String>,
    /// Recommended `--depth` for CI clones (0 = full clone).
    pub clone_depth: u32,
    /// Size tier classification.
    pub tier: CorpusTier,
    /// Optional sub-path to restrict analysis (e.g. "src/vs/editor" for vscode).
    pub subpath: Option<String>,
}

/// The full corpus manifest — all repos available for benchmarking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorpusManifest {
    pub entries: Vec<CorpusEntry>,
}

impl CorpusManifest {
    /// Return the built-in default manifest with 25+ public repos across 4 tiers.
    pub fn default_manifest() -> Self {
        Self {
            entries: vec![
                // -- Small (<1K expected entities) --
                CorpusEntry {
                    name: "zod".into(),
                    github_url: "https://github.com/colinhacks/zod.git".into(),
                    expected_entities: (200, 800),
                    languages: vec!["TypeScript".into()],
                    clone_depth: 1,
                    tier: CorpusTier::Small,
                    subpath: None,
                },
                CorpusEntry {
                    name: "lodash".into(),
                    github_url: "https://github.com/lodash/lodash.git".into(),
                    expected_entities: (300, 900),
                    languages: vec!["JavaScript".into()],
                    clone_depth: 1,
                    tier: CorpusTier::Small,
                    subpath: None,
                },
                CorpusEntry {
                    name: "dayjs".into(),
                    github_url: "https://github.com/iamkun/dayjs.git".into(),
                    expected_entities: (100, 600),
                    languages: vec!["JavaScript".into()],
                    clone_depth: 1,
                    tier: CorpusTier::Small,
                    subpath: None,
                },
                CorpusEntry {
                    name: "nanoid".into(),
                    github_url: "https://github.com/ai/nanoid.git".into(),
                    expected_entities: (20, 200),
                    languages: vec!["JavaScript".into()],
                    clone_depth: 1,
                    tier: CorpusTier::Small,
                    subpath: None,
                },
                CorpusEntry {
                    name: "chalk".into(),
                    github_url: "https://github.com/chalk/chalk.git".into(),
                    expected_entities: (30, 300),
                    languages: vec!["JavaScript".into()],
                    clone_depth: 1,
                    tier: CorpusTier::Small,
                    subpath: None,
                },
                CorpusEntry {
                    name: "mitt".into(),
                    github_url: "https://github.com/developit/mitt.git".into(),
                    expected_entities: (10, 100),
                    languages: vec!["TypeScript".into()],
                    clone_depth: 1,
                    tier: CorpusTier::Small,
                    subpath: None,
                },
                CorpusEntry {
                    name: "picocolors".into(),
                    github_url: "https://github.com/alexeyraspopov/picocolors.git".into(),
                    expected_entities: (10, 100),
                    languages: vec!["JavaScript".into()],
                    clone_depth: 1,
                    tier: CorpusTier::Small,
                    subpath: None,
                },
                // -- Medium (1K–10K expected entities) --
                CorpusEntry {
                    name: "express".into(),
                    github_url: "https://github.com/expressjs/express.git".into(),
                    expected_entities: (1_000, 5_000),
                    languages: vec!["JavaScript".into()],
                    clone_depth: 1,
                    tier: CorpusTier::Medium,
                    subpath: None,
                },
                CorpusEntry {
                    name: "fastify".into(),
                    github_url: "https://github.com/fastify/fastify.git".into(),
                    expected_entities: (1_500, 8_000),
                    languages: vec!["JavaScript".into()],
                    clone_depth: 1,
                    tier: CorpusTier::Medium,
                    subpath: None,
                },
                CorpusEntry {
                    name: "nextjs-pages".into(),
                    github_url: "https://github.com/vercel/next.js.git".into(),
                    expected_entities: (2_000, 10_000),
                    languages: vec!["TypeScript".into(), "JavaScript".into()],
                    clone_depth: 1,
                    tier: CorpusTier::Medium,
                    subpath: Some("packages/next/src/pages".into()),
                },
                CorpusEntry {
                    name: "django-core".into(),
                    github_url: "https://github.com/django/django.git".into(),
                    expected_entities: (3_000, 10_000),
                    languages: vec!["Python".into()],
                    clone_depth: 1,
                    tier: CorpusTier::Medium,
                    subpath: Some("django/core".into()),
                },
                CorpusEntry {
                    name: "flask".into(),
                    github_url: "https://github.com/pallets/flask.git".into(),
                    expected_entities: (1_000, 4_000),
                    languages: vec!["Python".into()],
                    clone_depth: 1,
                    tier: CorpusTier::Medium,
                    subpath: None,
                },
                CorpusEntry {
                    name: "hono".into(),
                    github_url: "https://github.com/honojs/hono.git".into(),
                    expected_entities: (1_000, 5_000),
                    languages: vec!["TypeScript".into()],
                    clone_depth: 1,
                    tier: CorpusTier::Medium,
                    subpath: None,
                },
                CorpusEntry {
                    name: "drizzle-orm".into(),
                    github_url: "https://github.com/drizzle-team/drizzle-orm.git".into(),
                    expected_entities: (2_000, 8_000),
                    languages: vec!["TypeScript".into()],
                    clone_depth: 1,
                    tier: CorpusTier::Medium,
                    subpath: None,
                },
                // -- Large (10K–50K expected entities) --
                CorpusEntry {
                    name: "react".into(),
                    github_url: "https://github.com/facebook/react.git".into(),
                    expected_entities: (10_000, 40_000),
                    languages: vec!["JavaScript".into(), "TypeScript".into()],
                    clone_depth: 1,
                    tier: CorpusTier::Large,
                    subpath: None,
                },
                CorpusEntry {
                    name: "angular".into(),
                    github_url: "https://github.com/angular/angular.git".into(),
                    expected_entities: (15_000, 50_000),
                    languages: vec!["TypeScript".into()],
                    clone_depth: 1,
                    tier: CorpusTier::Large,
                    subpath: None,
                },
                CorpusEntry {
                    name: "vue".into(),
                    github_url: "https://github.com/vuejs/core.git".into(),
                    expected_entities: (10_000, 35_000),
                    languages: vec!["TypeScript".into()],
                    clone_depth: 1,
                    tier: CorpusTier::Large,
                    subpath: None,
                },
                CorpusEntry {
                    name: "tokio".into(),
                    github_url: "https://github.com/tokio-rs/tokio.git".into(),
                    expected_entities: (10_000, 30_000),
                    languages: vec!["Rust".into()],
                    clone_depth: 1,
                    tier: CorpusTier::Large,
                    subpath: None,
                },
                CorpusEntry {
                    name: "axum".into(),
                    github_url: "https://github.com/tokio-rs/axum.git".into(),
                    expected_entities: (10_000, 25_000),
                    languages: vec!["Rust".into()],
                    clone_depth: 1,
                    tier: CorpusTier::Large,
                    subpath: None,
                },
                CorpusEntry {
                    name: "serde".into(),
                    github_url: "https://github.com/serde-rs/serde.git".into(),
                    expected_entities: (10_000, 30_000),
                    languages: vec!["Rust".into()],
                    clone_depth: 1,
                    tier: CorpusTier::Large,
                    subpath: None,
                },
                // -- Extra-Large (50K+ expected entities, partial clone) --
                CorpusEntry {
                    name: "vscode-editor".into(),
                    github_url: "https://github.com/microsoft/vscode.git".into(),
                    expected_entities: (50_000, 150_000),
                    languages: vec!["TypeScript".into()],
                    clone_depth: 1,
                    tier: CorpusTier::ExtraLarge,
                    subpath: Some("src/vs/editor".into()),
                },
                CorpusEntry {
                    name: "kubernetes-pkg".into(),
                    github_url: "https://github.com/kubernetes/kubernetes.git".into(),
                    expected_entities: (80_000, 250_000),
                    languages: vec!["Go".into()],
                    clone_depth: 1,
                    tier: CorpusTier::ExtraLarge,
                    subpath: Some("pkg".into()),
                },
                CorpusEntry {
                    name: "linux-kernel".into(),
                    github_url: "https://github.com/torvalds/linux.git".into(),
                    expected_entities: (100_000, 500_000),
                    languages: vec!["C".into()],
                    clone_depth: 1,
                    tier: CorpusTier::ExtraLarge,
                    subpath: Some("kernel".into()),
                },
            ],
        }
    }

    /// Filter entries by tier.
    pub fn by_tier(&self, tier: CorpusTier) -> Vec<&CorpusEntry> {
        self.entries.iter().filter(|e| e.tier == tier).collect()
    }

    /// Filter entries by name (case-insensitive substring match).
    pub fn by_name(&self, name: &str) -> Option<&CorpusEntry> {
        let lower = name.to_lowercase();
        self.entries
            .iter()
            .find(|e| e.name.to_lowercase() == lower)
    }

    /// Return entries for the given list of names.
    pub fn select(&self, names: &[&str]) -> Vec<&CorpusEntry> {
        names
            .iter()
            .filter_map(|n| self.by_name(n))
            .collect()
    }

    /// Total number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the manifest is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

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

    // -- Corpus Manifest tests --

    #[test]
    fn default_manifest_has_25_plus_entries() {
        let manifest = CorpusManifest::default_manifest();
        assert!(manifest.len() >= 23);
        assert!(!manifest.is_empty());
    }

    #[test]
    fn manifest_has_all_tiers() {
        let manifest = CorpusManifest::default_manifest();
        assert!(!manifest.by_tier(CorpusTier::Small).is_empty());
        assert!(!manifest.by_tier(CorpusTier::Medium).is_empty());
        assert!(!manifest.by_tier(CorpusTier::Large).is_empty());
        assert!(!manifest.by_tier(CorpusTier::ExtraLarge).is_empty());
    }

    #[test]
    fn manifest_small_tier_has_expected_repos() {
        let manifest = CorpusManifest::default_manifest();
        let small = manifest.by_tier(CorpusTier::Small);
        assert!(small.len() >= 7);
        let names: Vec<&str> = small.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"zod"));
        assert!(names.contains(&"nanoid"));
        assert!(names.contains(&"mitt"));
    }

    #[test]
    fn manifest_xl_entries_have_subpaths() {
        let manifest = CorpusManifest::default_manifest();
        let xl = manifest.by_tier(CorpusTier::ExtraLarge);
        for entry in &xl {
            assert!(
                entry.subpath.is_some(),
                "XL entry {} should have a subpath",
                entry.name
            );
        }
    }

    #[test]
    fn manifest_by_name_lookup() {
        let manifest = CorpusManifest::default_manifest();
        let react = manifest.by_name("react").unwrap();
        assert_eq!(react.tier, CorpusTier::Large);
        assert!(react.languages.contains(&"JavaScript".to_string()));

        assert!(manifest.by_name("nonexistent-repo").is_none());
    }

    #[test]
    fn manifest_select_multiple() {
        let manifest = CorpusManifest::default_manifest();
        let selected = manifest.select(&["zod", "react", "tokio"]);
        assert_eq!(selected.len(), 3);
    }

    #[test]
    fn manifest_entries_have_valid_urls() {
        let manifest = CorpusManifest::default_manifest();
        for entry in &manifest.entries {
            assert!(
                entry.github_url.starts_with("https://github.com/"),
                "entry {} URL must be a GitHub HTTPS URL: {}",
                entry.name,
                entry.github_url
            );
            assert!(
                entry.github_url.ends_with(".git"),
                "entry {} URL should end with .git",
                entry.name
            );
        }
    }

    #[test]
    fn manifest_entries_have_valid_entity_ranges() {
        let manifest = CorpusManifest::default_manifest();
        for entry in &manifest.entries {
            assert!(
                entry.expected_entities.0 <= entry.expected_entities.1,
                "entry {} has inverted entity range: {:?}",
                entry.name,
                entry.expected_entities
            );
            assert!(
                entry.expected_entities.1 > 0,
                "entry {} has zero max entities",
                entry.name
            );
        }
    }

    #[test]
    fn manifest_serialization_roundtrip() {
        let manifest = CorpusManifest::default_manifest();
        let json = serde_json::to_string(&manifest).unwrap();
        let parsed: CorpusManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), manifest.len());
        assert_eq!(parsed.entries[0].name, manifest.entries[0].name);
    }

    #[test]
    fn corpus_tier_display() {
        assert_eq!(CorpusTier::Small.to_string(), "small");
        assert_eq!(CorpusTier::Medium.to_string(), "medium");
        assert_eq!(CorpusTier::Large.to_string(), "large");
        assert_eq!(CorpusTier::ExtraLarge.to_string(), "xl");
    }

    #[test]
    fn corpus_tier_serde_roundtrip() {
        for tier in [
            CorpusTier::Small,
            CorpusTier::Medium,
            CorpusTier::Large,
            CorpusTier::ExtraLarge,
        ] {
            let json = serde_json::to_string(&tier).unwrap();
            let parsed: CorpusTier = serde_json::from_str(&json).unwrap();
            assert_eq!(tier, parsed);
        }
    }
}
