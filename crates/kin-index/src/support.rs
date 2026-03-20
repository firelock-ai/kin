// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Coverage and support reporting.
//!
//! Walks a directory tree, classifies every file, and produces a summary
//! showing how many files fall into each classification bucket.

use std::collections::HashMap;
use std::path::Path;

use crate::classifier::{FileClassification, FileClassifier};
use crate::error::IndexError;
use kin_model::ArtifactKind;

/// Aggregated coverage report over a directory tree.
#[derive(Debug, Clone, Default)]
pub struct CoverageReport {
    pub entity_source_count: usize,
    pub entity_source_extensions: HashMap<String, usize>,
    pub c5_cross_file_count: usize,
    pub c5_languages: HashMap<String, usize>,
    pub c4_intra_file_count: usize,
    pub c4_languages: HashMap<String, usize>,
    pub shallow_syntax_count: usize,
    pub shallow_syntax_languages: HashMap<String, usize>,
    pub structured_artifact_count: usize,
    pub structured_artifacts_by_kind: HashMap<String, usize>,
    pub opaque_artifact_count: usize,
    pub opaque_extensions: HashMap<String, usize>,
    pub total_files: usize,
}

/// Walk `root` and classify every file, returning a [`CoverageReport`].
pub fn compute_coverage_report(root: &Path) -> crate::Result<CoverageReport> {
    let files = collect_all_files(root)?;
    let mut report = CoverageReport::default();

    for file_path in &files {
        report.total_files += 1;

        let classification = FileClassifier::classify(file_path);
        let ext = file_path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("")
            .to_string();

        match classification {
            FileClassification::EntitySource => {
                report.entity_source_count += 1;
                *report
                    .entity_source_extensions
                    .entry(ext.clone())
                    .or_insert(0) += 1;

                // Sub-classify into C5 (cross-file) vs C4 (intra-file)
                // based on whether the file contains import statements.
                let has_imports = std::fs::read_to_string(file_path)
                    .map(|content| file_has_imports(&ext, &content))
                    .unwrap_or(false);

                if has_imports {
                    report.c5_cross_file_count += 1;
                    *report.c5_languages.entry(ext).or_insert(0) += 1;
                } else {
                    report.c4_intra_file_count += 1;
                    *report.c4_languages.entry(ext).or_insert(0) += 1;
                }
            }
            FileClassification::ShallowSyntax { language_hint } => {
                report.shallow_syntax_count += 1;
                *report
                    .shallow_syntax_languages
                    .entry(language_hint)
                    .or_insert(0) += 1;
            }
            FileClassification::StructuredArtifact(kind) => {
                report.structured_artifact_count += 1;
                let kind_name = artifact_kind_name(kind);
                *report
                    .structured_artifacts_by_kind
                    .entry(kind_name)
                    .or_insert(0) += 1;
            }
            FileClassification::OpaqueArtifact { .. } => {
                report.opaque_artifact_count += 1;
                let key = if ext.is_empty() {
                    "(no ext)".to_string()
                } else {
                    ext
                };
                *report.opaque_extensions.entry(key).or_insert(0) += 1;
            }
        }
    }

    Ok(report)
}

impl CoverageReport {
    /// Format the report for terminal display using C0-C5 coverage tiers.
    ///
    /// Coverage tiers (from kin-open-core-coverage-roadmap.md):
    /// - C0: Opaque — tracked as content + metadata only
    /// - C1: Structured Artifact — meaningful structure, not source code
    /// - C2: Shallow Syntax — grammar-backed coarse extraction (future)
    /// - C5: Cross-File Semantics
    pub fn summary(&self) -> String {
        let mut out = String::new();

        out.push_str(&format!("Coverage Report  ({} files)\n", self.total_files));
        out.push_str("═══════════════════════════════════════\n");

        // C5 Cross-File Semantics (entity source files with imports)
        out.push_str(&format!(
            "C5  Cross-File Semantics: {:>5}  ({:.0}%)\n",
            self.c5_cross_file_count,
            pct(self.c5_cross_file_count, self.total_files),
        ));
        out.push_str("    Entity extraction + call resolution + cross-file linking\n");
        for (ext, count) in sorted_map(&self.c5_languages) {
            out.push_str(&format!("      .{:<16} {:>3}  [C5]\n", ext, count));
        }

        // C4 Intra-File Relations (entity source files without imports)
        out.push_str(&format!(
            "C4  Intra-File Relations: {:>5}  ({:.0}%)\n",
            self.c4_intra_file_count,
            pct(self.c4_intra_file_count, self.total_files),
        ));
        out.push_str("    Entity extraction + call resolution (no imports)\n");
        for (ext, count) in sorted_map(&self.c4_languages) {
            out.push_str(&format!("      .{:<16} {:>3}  [C4]\n", ext, count));
        }

        // C1 Structured Artifact
        out.push_str(&format!(
            "C1  Structured:        {:>5}  ({:.0}%)\n",
            self.structured_artifact_count,
            pct(self.structured_artifact_count, self.total_files),
        ));
        out.push_str("    Normalized fingerprint, semantic fields, artifact tracking\n");
        for (kind, count) in sorted_map(&self.structured_artifacts_by_kind) {
            out.push_str(&format!("      {:<20} {}\n", kind, count));
        }

        // C0 Opaque Artifact
        out.push_str(&format!(
            "C0  Opaque:            {:>5}  ({:.0}%)\n",
            self.opaque_artifact_count,
            pct(self.opaque_artifact_count, self.total_files),
        ));
        out.push_str("    Content hash + metadata, no semantic extraction\n");
        for (ext, count) in sorted_map(&self.opaque_extensions) {
            out.push_str(&format!("      {:<20} {}\n", ext, count));
        }

        // C2 Shallow Syntax
        out.push_str(&format!(
            "C2  Shallow Syntax:    {:>5}  ({:.0}%)\n",
            self.shallow_syntax_count,
            pct(self.shallow_syntax_count, self.total_files),
        ));
        out.push_str("    Grammar-backed coarse extraction: declarations, imports, fingerprints\n");
        for (lang, count) in sorted_map(&self.shallow_syntax_languages) {
            out.push_str(&format!("      {:<18} {:>3}  [C2]\n", lang, count));
        }

        out.push_str("═══════════════════════════════════════\n");

        // Semantic depth summary
        let c5_pct = pct(self.c5_cross_file_count, self.total_files);
        let c4_pct = pct(self.c4_intra_file_count, self.total_files);
        let shallow_pct = pct(self.shallow_syntax_count, self.total_files);
        let structured_pct = pct(self.structured_artifact_count, self.total_files);
        let opaque_pct = pct(self.opaque_artifact_count, self.total_files);
        out.push_str(&format!(
            "Semantic depth: {:.0}% cross-file (C5), {:.0}% intra-file (C4), {:.0}% shallow (C2), {:.0}% structured (C1), {:.0}% opaque (C0)\n",
            c5_pct, c4_pct, shallow_pct, structured_pct, opaque_pct,
        ));

        out
    }
}

// ── helpers ────────────────────────────────────────────────────────────

/// Heuristic: does this entity-source file contain import statements?
/// Files with imports are cross-file linkable (C5); without are intra-file only (C4).
fn file_has_imports(ext: &str, content: &str) -> bool {
    match ext {
        "ts" | "tsx" | "js" | "jsx" => content.contains("import ") || content.contains("require("),
        "py" => content.contains("import ") || content.contains("from "),
        "rs" => content.contains("use "),
        "go" => content.contains("import "),
        "java" => content.contains("import "),
        _ => false,
    }
}

fn artifact_kind_name(kind: ArtifactKind) -> String {
    match kind {
        ArtifactKind::PackageManifest => "PackageManifest".to_string(),
        ArtifactKind::SqlMigration => "SqlMigration".to_string(),
        ArtifactKind::CiConfig => "CiConfig".to_string(),
        ArtifactKind::Dockerfile => "Dockerfile".to_string(),
        ArtifactKind::ComposeFile => "ComposeFile".to_string(),
        ArtifactKind::Makefile => "Makefile".to_string(),
    }
}

fn pct(part: usize, total: usize) -> f64 {
    if total == 0 {
        0.0
    } else {
        (part as f64 / total as f64) * 100.0
    }
}

fn sorted_map(map: &HashMap<String, usize>) -> Vec<(&String, &usize)> {
    let mut entries: Vec<_> = map.iter().collect();
    entries.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
    entries
}

/// Collect all files from a directory, skipping hidden dirs and common
/// non-source directories (same logic as `collect_all_files` in kin-cli commit).
fn collect_all_files(root: &Path) -> crate::Result<Vec<std::path::PathBuf>> {
    let mut files = Vec::new();
    collect_files_recursive(root, &mut files)?;
    Ok(files)
}

fn collect_files_recursive(dir: &Path, files: &mut Vec<std::path::PathBuf>) -> crate::Result<()> {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => return Err(IndexError::io(dir.display().to_string(), e)),
    };

    for entry in entries {
        let entry = entry.map_err(|e| IndexError::io(dir.display().to_string(), e))?;
        let path = entry.path();
        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // Skip hidden directories and files starting with '.'
        if name_str.starts_with('.') {
            continue;
        }

        if path.is_dir() {
            if matches!(
                name_str.as_ref(),
                "node_modules" | "target" | "build" | "dist" | "__pycache__" | "vendor"
            ) {
                continue;
            }
            collect_files_recursive(&path, files)?;
        } else if path.is_file() {
            files.push(path);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn coverage_report_empty_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let report = compute_coverage_report(tmp.path()).unwrap();
        assert_eq!(report.total_files, 0);
        assert_eq!(report.entity_source_count, 0);
        assert_eq!(report.structured_artifact_count, 0);
        assert_eq!(report.opaque_artifact_count, 0);
    }

    #[test]
    fn coverage_report_mixed_files() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();

        // Entity sources (no imports → all C4)
        fs::write(root.join("main.rs"), "fn main() {}").unwrap();
        fs::write(root.join("app.ts"), "export default {}").unwrap();
        fs::write(root.join("lib.py"), "pass").unwrap();

        // Structured artifacts
        fs::write(root.join("Dockerfile"), "FROM alpine").unwrap();
        fs::write(
            root.join("compose.yaml"),
            "services:\n  web:\n    image: nginx",
        )
        .unwrap();
        fs::write(root.join("Makefile"), "all:").unwrap();
        fs::write(root.join("package.json"), "{}").unwrap();

        // Opaque artifacts
        fs::write(root.join("README.md"), "# Hello").unwrap();
        fs::write(root.join("logo.png"), [0u8; 4]).unwrap();

        let report = compute_coverage_report(root).unwrap();

        assert_eq!(report.total_files, 9);
        assert_eq!(report.entity_source_count, 3);
        assert_eq!(report.c5_cross_file_count, 0);
        assert_eq!(report.c4_intra_file_count, 3);
        assert_eq!(report.shallow_syntax_count, 0);
        assert_eq!(report.structured_artifact_count, 4);
        assert_eq!(report.opaque_artifact_count, 2);

        // Check extension breakdown
        assert_eq!(report.entity_source_extensions.get("rs"), Some(&1));
        assert_eq!(report.entity_source_extensions.get("ts"), Some(&1));
        assert_eq!(report.entity_source_extensions.get("py"), Some(&1));

        // All without imports → C4
        assert_eq!(report.c4_languages.get("rs"), Some(&1));
        assert_eq!(report.c4_languages.get("ts"), Some(&1));
        assert_eq!(report.c4_languages.get("py"), Some(&1));

        // Check artifact kind breakdown
        assert_eq!(
            report.structured_artifacts_by_kind.get("Dockerfile"),
            Some(&1)
        );
        assert_eq!(
            report.structured_artifacts_by_kind.get("ComposeFile"),
            Some(&1)
        );
        assert_eq!(
            report.structured_artifacts_by_kind.get("Makefile"),
            Some(&1)
        );
        assert_eq!(
            report.structured_artifacts_by_kind.get("PackageManifest"),
            Some(&1)
        );
    }

    #[test]
    fn coverage_report_c2_shallow_syntax() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();

        // Entity source (C4 — no imports)
        fs::write(root.join("main.rs"), "fn main() {}").unwrap();

        // Additional entity-source languages promoted from C2.
        fs::write(root.join("helper.c"), "int main() { return 0; }").unwrap();
        fs::write(root.join("lib.h"), "#include <stdio.h>").unwrap();
        fs::write(root.join("app.rb"), "class Foo; end").unwrap();

        // Opaque
        fs::write(root.join("README.md"), "# Hello").unwrap();

        let report = compute_coverage_report(root).unwrap();

        assert_eq!(report.total_files, 5);
        assert_eq!(report.entity_source_count, 4);
        assert_eq!(report.shallow_syntax_count, 0);
        assert_eq!(report.opaque_artifact_count, 1);

        assert_eq!(report.entity_source_extensions.get("c"), Some(&1));
        assert_eq!(report.entity_source_extensions.get("h"), Some(&1));
        assert_eq!(report.entity_source_extensions.get("rb"), Some(&1));
    }

    #[test]
    fn coverage_report_skips_hidden_and_excluded_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();

        fs::write(root.join("visible.rs"), "fn f() {}").unwrap();

        // Hidden dir
        let hidden = root.join(".hidden");
        fs::create_dir(&hidden).unwrap();
        fs::write(hidden.join("secret.rs"), "fn s() {}").unwrap();

        // node_modules
        let nm = root.join("node_modules");
        fs::create_dir(&nm).unwrap();
        fs::write(nm.join("dep.js"), "module.exports = {}").unwrap();

        // target
        let target = root.join("target");
        fs::create_dir(&target).unwrap();
        fs::write(target.join("built.rs"), "fn b() {}").unwrap();

        let report = compute_coverage_report(root).unwrap();
        assert_eq!(report.total_files, 1);
        assert_eq!(report.entity_source_count, 1);
    }

    #[test]
    fn coverage_report_nested_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();

        let sub = root.join("src").join("utils");
        fs::create_dir_all(&sub).unwrap();
        fs::write(sub.join("helper.ts"), "export {}").unwrap();
        fs::write(
            root.join("src").join("main.ts"),
            "import { foo } from './foo'",
        )
        .unwrap();

        let report = compute_coverage_report(root).unwrap();
        assert_eq!(report.total_files, 2);
        assert_eq!(report.entity_source_count, 2);
        // main.ts has "import " → C5; helper.ts has no imports → C4
        assert_eq!(report.c5_cross_file_count, 1);
        assert_eq!(report.c4_intra_file_count, 1);
    }

    #[test]
    fn summary_format_contains_c0_c5_tiers() {
        let mut shallow_langs = HashMap::new();
        shallow_langs.insert("c".to_string(), 2);
        let mut c5_langs = HashMap::new();
        c5_langs.insert("ts".to_string(), 3);
        let mut c4_langs = HashMap::new();
        c4_langs.insert("rs".to_string(), 2);
        let report = CoverageReport {
            entity_source_count: 5,
            c5_cross_file_count: 3,
            c5_languages: c5_langs,
            c4_intra_file_count: 2,
            c4_languages: c4_langs,
            shallow_syntax_count: 2,
            shallow_syntax_languages: shallow_langs,
            structured_artifact_count: 2,
            opaque_artifact_count: 3,
            total_files: 12,
            ..Default::default()
        };
        let s = report.summary();
        assert!(s.contains("C5  Cross-File Semantics:"));
        assert!(s.contains("C4  Intra-File Relations:"));
        assert!(s.contains("C1  Structured:"));
        assert!(s.contains("C0  Opaque:"));
        assert!(s.contains("C2  Shallow Syntax:"));
        assert!(s.contains("12 files"));
        assert!(s.contains("Semantic depth:"));
        assert!(s.contains("cross-file (C5)"));
        assert!(s.contains("intra-file (C4)"));
    }

    #[test]
    fn coverage_report_c4_vs_c5() {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path();

        // C5: files with imports (cross-file linkable)
        fs::write(
            root.join("app.ts"),
            "import { Component } from './component';\nexport class App {}",
        )
        .unwrap();
        fs::write(root.join("main.py"), "from os import path\ndef run(): pass").unwrap();
        fs::write(
            root.join("lib.rs"),
            "use std::collections::HashMap;\nfn main() {}",
        )
        .unwrap();
        fs::write(root.join("Server.go"), "import \"fmt\"\nfunc main() {}").unwrap();
        fs::write(
            root.join("App.java"),
            "import java.util.List;\nclass App {}",
        )
        .unwrap();
        fs::write(
            root.join("index.js"),
            "const fs = require('fs');\nmodule.exports = {}",
        )
        .unwrap();

        // C4: files without imports (intra-file only)
        fs::write(
            root.join("util.ts"),
            "export function add(a: number, b: number) { return a + b; }",
        )
        .unwrap();
        fs::write(
            root.join("helper.py"),
            "def greet(name): return f'hi {name}'",
        )
        .unwrap();
        fs::write(root.join("pure.rs"), "fn double(x: i32) -> i32 { x * 2 }").unwrap();

        let report = compute_coverage_report(root).unwrap();

        assert_eq!(report.total_files, 9);
        assert_eq!(report.entity_source_count, 9);
        assert_eq!(report.c5_cross_file_count, 6);
        assert_eq!(report.c4_intra_file_count, 3);

        // C5 language breakdown
        assert_eq!(report.c5_languages.get("ts"), Some(&1));
        assert_eq!(report.c5_languages.get("py"), Some(&1));
        assert_eq!(report.c5_languages.get("rs"), Some(&1));
        assert_eq!(report.c5_languages.get("go"), Some(&1));
        assert_eq!(report.c5_languages.get("java"), Some(&1));
        assert_eq!(report.c5_languages.get("js"), Some(&1));

        // C4 language breakdown
        assert_eq!(report.c4_languages.get("ts"), Some(&1));
        assert_eq!(report.c4_languages.get("py"), Some(&1));
        assert_eq!(report.c4_languages.get("rs"), Some(&1));

        // entity_source_count is still the total
        assert_eq!(
            report.c5_cross_file_count + report.c4_intra_file_count,
            report.entity_source_count,
        );
    }
}
