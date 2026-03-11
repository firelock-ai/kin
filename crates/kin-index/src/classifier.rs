//! File classification for the never-drop indexing pipeline.
//!
//! Every file is classified into one of three categories so that nothing
//! is silently skipped during indexing.

use std::path::Path;

use kin_model::ArtifactKind;

/// Classification result for a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileClassification {
    /// File has a tree-sitter adapter — full entity extraction.
    EntitySource,
    /// C2: File has grammar support but no full semantic adapter.
    /// Shallow syntax extraction: declarations, imports, fingerprints.
    ShallowSyntax { language_hint: String },
    /// File has known structure — use artifact extractor.
    StructuredArtifact(ArtifactKind),
    /// Unknown file — track as opaque blob.
    OpaqueArtifact { mime_hint: Option<String> },
}

/// Extensions that have tree-sitter adapters for full entity extraction.
const ENTITY_SOURCE_EXTENSIONS: &[&str] = &["ts", "tsx", "js", "jsx", "py", "go", "java", "rs"];

/// Extensions eligible for C2 shallow syntax extraction.
/// These have tree-sitter grammars available but no full Kin semantic adapter.
const SHALLOW_SYNTAX_EXTENSIONS: &[(&str, &str)] = &[
    ("c", "c"),
    ("h", "c"),
    ("cpp", "cpp"),
    ("hpp", "cpp"),
    ("cc", "cpp"),
    ("cxx", "cpp"),
    ("rb", "ruby"),
    ("swift", "swift"),
    ("kt", "kotlin"),
    ("kts", "kotlin"),
    ("scala", "scala"),
    ("cs", "csharp"),
    ("lua", "lua"),
    ("r", "r"),
    ("R", "r"),
    ("zig", "zig"),
    ("ex", "elixir"),
    ("exs", "elixir"),
    ("erl", "erlang"),
    ("hs", "haskell"),
    ("ml", "ocaml"),
    ("mli", "ocaml"),
    ("php", "php"),
    ("pl", "perl"),
    ("pm", "perl"),
];

/// Package manifest filenames.
const PACKAGE_MANIFEST_FILENAMES: &[&str] = &[
    "Cargo.toml",
    "package.json",
    "pyproject.toml",
    "go.mod",
    "pom.xml",
    "Gemfile",
    "requirements.txt",
    "composer.json",
];

/// Classifies files by path/extension for the indexing pipeline.
pub struct FileClassifier;

impl FileClassifier {
    /// Classify a file path into the appropriate indexing category.
    pub fn classify(path: &Path) -> FileClassification {
        let file_name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

        let extension = path.extension().and_then(|e| e.to_str()).unwrap_or("");

        // 1. EntitySource: known parser extensions (C3+)
        if ENTITY_SOURCE_EXTENSIONS.contains(&extension) {
            return FileClassification::EntitySource;
        }

        // 2. ShallowSyntax: grammar-backed but no full adapter (C2)
        if let Some((_, lang)) = SHALLOW_SYNTAX_EXTENSIONS.iter().find(|(ext, _)| *ext == extension) {
            return FileClassification::ShallowSyntax {
                language_hint: lang.to_string(),
            };
        }

        // 3. StructuredArtifact checks

        // Dockerfile: exact match or "Dockerfile.*" prefix
        if file_name == "Dockerfile" || file_name.starts_with("Dockerfile.") {
            return FileClassification::StructuredArtifact(ArtifactKind::Dockerfile);
        }

        // Package manifests
        if PACKAGE_MANIFEST_FILENAMES.contains(&file_name) {
            return FileClassification::StructuredArtifact(ArtifactKind::PackageManifest);
        }

        // CI configs
        if is_ci_config(path, file_name, extension) {
            return FileClassification::StructuredArtifact(ArtifactKind::CiConfig);
        }

        // Makefile
        if file_name == "Makefile" || file_name == "makefile" || file_name == "GNUmakefile" {
            return FileClassification::StructuredArtifact(ArtifactKind::Makefile);
        }

        // SQL migrations
        if extension == "sql" {
            let path_str = path.to_string_lossy().to_lowercase();
            if path_str.contains("migration") {
                return FileClassification::StructuredArtifact(ArtifactKind::SqlMigration);
            }
        }

        // 3. OpaqueArtifact: everything else
        FileClassification::OpaqueArtifact {
            mime_hint: mime_hint_from_extension(extension),
        }
    }
}

/// Check if a file is a CI configuration file.
fn is_ci_config(path: &Path, file_name: &str, extension: &str) -> bool {
    // GitHub Actions: .github/workflows/*.yml or *.yaml
    if (extension == "yml" || extension == "yaml") && path_contains_github_workflows(path) {
        return true;
    }

    // GitLab CI
    if file_name == ".gitlab-ci.yml" {
        return true;
    }

    // Jenkinsfile
    if file_name == "Jenkinsfile" {
        return true;
    }

    // CircleCI: .circleci/config.yml
    if file_name == "config.yml" && path_contains_circleci(path) {
        return true;
    }

    false
}

/// Check if the path contains `.github/workflows/`.
fn path_contains_github_workflows(path: &Path) -> bool {
    let path_str = path.to_string_lossy();
    path_str.contains(".github/workflows/") || path_str.contains(".github\\workflows\\")
}

/// Check if the path contains `.circleci/`.
fn path_contains_circleci(path: &Path) -> bool {
    let path_str = path.to_string_lossy();
    path_str.contains(".circleci/") || path_str.contains(".circleci\\")
}

/// Derive a MIME type hint from a file extension.
fn mime_hint_from_extension(ext: &str) -> Option<String> {
    match ext {
        // Images
        "png" => Some("image/png".to_string()),
        "jpg" | "jpeg" => Some("image/jpeg".to_string()),
        "gif" => Some("image/gif".to_string()),
        "svg" => Some("image/svg".to_string()),
        "webp" => Some("image/webp".to_string()),
        // Documents
        "pdf" => Some("application/pdf".to_string()),
        // Archives
        "zip" | "tar" | "gz" => Some("application/archive".to_string()),
        // Text formats
        "md" | "txt" | "csv" | "json" | "yaml" | "yml" | "toml" | "xml" | "html" => {
            Some(format!("text/{ext}"))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn classify(s: &str) -> FileClassification {
        FileClassifier::classify(Path::new(s))
    }

    // ── EntitySource extensions ──────────────────────────────────────

    #[test]
    fn entity_source_ts() {
        assert_eq!(classify("src/app.ts"), FileClassification::EntitySource);
    }

    #[test]
    fn entity_source_tsx() {
        assert_eq!(classify("src/App.tsx"), FileClassification::EntitySource);
    }

    #[test]
    fn entity_source_js() {
        assert_eq!(classify("lib/index.js"), FileClassification::EntitySource);
    }

    #[test]
    fn entity_source_jsx() {
        assert_eq!(
            classify("components/Btn.jsx"),
            FileClassification::EntitySource
        );
    }

    #[test]
    fn entity_source_py() {
        assert_eq!(classify("main.py"), FileClassification::EntitySource);
    }

    #[test]
    fn entity_source_go() {
        assert_eq!(classify("cmd/server.go"), FileClassification::EntitySource);
    }

    #[test]
    fn entity_source_java() {
        assert_eq!(classify("src/Main.java"), FileClassification::EntitySource);
    }

    #[test]
    fn entity_source_rs() {
        assert_eq!(classify("src/lib.rs"), FileClassification::EntitySource);
    }

    // ── StructuredArtifact: Dockerfile ──────────────────────────────

    #[test]
    fn dockerfile_exact() {
        assert_eq!(
            classify("Dockerfile"),
            FileClassification::StructuredArtifact(ArtifactKind::Dockerfile),
        );
    }

    #[test]
    fn dockerfile_with_stage() {
        assert_eq!(
            classify("Dockerfile.production"),
            FileClassification::StructuredArtifact(ArtifactKind::Dockerfile),
        );
    }

    #[test]
    fn dockerfile_nested() {
        assert_eq!(
            classify("deploy/Dockerfile"),
            FileClassification::StructuredArtifact(ArtifactKind::Dockerfile),
        );
    }

    // ── StructuredArtifact: PackageManifest ─────────────────────────

    #[test]
    fn cargo_toml() {
        assert_eq!(
            classify("crates/foo/Cargo.toml"),
            FileClassification::StructuredArtifact(ArtifactKind::PackageManifest),
        );
    }

    #[test]
    fn package_json() {
        assert_eq!(
            classify("package.json"),
            FileClassification::StructuredArtifact(ArtifactKind::PackageManifest),
        );
    }

    #[test]
    fn pyproject_toml() {
        assert_eq!(
            classify("pyproject.toml"),
            FileClassification::StructuredArtifact(ArtifactKind::PackageManifest),
        );
    }

    #[test]
    fn go_mod() {
        assert_eq!(
            classify("go.mod"),
            FileClassification::StructuredArtifact(ArtifactKind::PackageManifest),
        );
    }

    #[test]
    fn pom_xml() {
        assert_eq!(
            classify("pom.xml"),
            FileClassification::StructuredArtifact(ArtifactKind::PackageManifest),
        );
    }

    #[test]
    fn gemfile() {
        assert_eq!(
            classify("Gemfile"),
            FileClassification::StructuredArtifact(ArtifactKind::PackageManifest),
        );
    }

    #[test]
    fn requirements_txt() {
        assert_eq!(
            classify("requirements.txt"),
            FileClassification::StructuredArtifact(ArtifactKind::PackageManifest),
        );
    }

    #[test]
    fn composer_json() {
        assert_eq!(
            classify("composer.json"),
            FileClassification::StructuredArtifact(ArtifactKind::PackageManifest),
        );
    }

    // ── StructuredArtifact: CiConfig ────────────────────────────────

    #[test]
    fn github_actions_yml() {
        assert_eq!(
            classify(".github/workflows/ci.yml"),
            FileClassification::StructuredArtifact(ArtifactKind::CiConfig),
        );
    }

    #[test]
    fn github_actions_yaml() {
        assert_eq!(
            classify(".github/workflows/deploy.yaml"),
            FileClassification::StructuredArtifact(ArtifactKind::CiConfig),
        );
    }

    #[test]
    fn gitlab_ci() {
        assert_eq!(
            classify(".gitlab-ci.yml"),
            FileClassification::StructuredArtifact(ArtifactKind::CiConfig),
        );
    }

    #[test]
    fn jenkinsfile() {
        assert_eq!(
            classify("Jenkinsfile"),
            FileClassification::StructuredArtifact(ArtifactKind::CiConfig),
        );
    }

    #[test]
    fn circleci_config() {
        assert_eq!(
            classify(".circleci/config.yml"),
            FileClassification::StructuredArtifact(ArtifactKind::CiConfig),
        );
    }

    // ── StructuredArtifact: Makefile ────────────────────────────────

    #[test]
    fn makefile_capitalized() {
        assert_eq!(
            classify("Makefile"),
            FileClassification::StructuredArtifact(ArtifactKind::Makefile),
        );
    }

    #[test]
    fn makefile_lowercase() {
        assert_eq!(
            classify("makefile"),
            FileClassification::StructuredArtifact(ArtifactKind::Makefile),
        );
    }

    #[test]
    fn gnu_makefile() {
        assert_eq!(
            classify("GNUmakefile"),
            FileClassification::StructuredArtifact(ArtifactKind::Makefile),
        );
    }

    // ── StructuredArtifact: SqlMigration ────────────────────────────

    #[test]
    fn sql_migration() {
        assert_eq!(
            classify("db/migrations/001_create_users.sql"),
            FileClassification::StructuredArtifact(ArtifactKind::SqlMigration),
        );
    }

    #[test]
    fn sql_migration_case_insensitive() {
        assert_eq!(
            classify("db/Migration/002_add_email.sql"),
            FileClassification::StructuredArtifact(ArtifactKind::SqlMigration),
        );
    }

    #[test]
    fn sql_not_migration() {
        // A .sql file that is NOT in a migration path -> opaque
        assert_eq!(
            classify("scripts/seed.sql"),
            FileClassification::OpaqueArtifact { mime_hint: None },
        );
    }

    // ── OpaqueArtifact with MIME hints ──────────────────────────────

    #[test]
    fn opaque_png() {
        assert_eq!(
            classify("assets/logo.png"),
            FileClassification::OpaqueArtifact {
                mime_hint: Some("image/png".to_string()),
            },
        );
    }

    #[test]
    fn opaque_jpg() {
        assert_eq!(
            classify("photo.jpg"),
            FileClassification::OpaqueArtifact {
                mime_hint: Some("image/jpeg".to_string()),
            },
        );
    }

    #[test]
    fn opaque_jpeg() {
        assert_eq!(
            classify("photo.jpeg"),
            FileClassification::OpaqueArtifact {
                mime_hint: Some("image/jpeg".to_string()),
            },
        );
    }

    #[test]
    fn opaque_gif() {
        assert_eq!(
            classify("anim.gif"),
            FileClassification::OpaqueArtifact {
                mime_hint: Some("image/gif".to_string()),
            },
        );
    }

    #[test]
    fn opaque_svg() {
        assert_eq!(
            classify("icon.svg"),
            FileClassification::OpaqueArtifact {
                mime_hint: Some("image/svg".to_string()),
            },
        );
    }

    #[test]
    fn opaque_webp() {
        assert_eq!(
            classify("banner.webp"),
            FileClassification::OpaqueArtifact {
                mime_hint: Some("image/webp".to_string()),
            },
        );
    }

    #[test]
    fn opaque_pdf() {
        assert_eq!(
            classify("docs/manual.pdf"),
            FileClassification::OpaqueArtifact {
                mime_hint: Some("application/pdf".to_string()),
            },
        );
    }

    #[test]
    fn opaque_zip() {
        assert_eq!(
            classify("release.zip"),
            FileClassification::OpaqueArtifact {
                mime_hint: Some("application/archive".to_string()),
            },
        );
    }

    #[test]
    fn opaque_tar() {
        assert_eq!(
            classify("backup.tar"),
            FileClassification::OpaqueArtifact {
                mime_hint: Some("application/archive".to_string()),
            },
        );
    }

    #[test]
    fn opaque_gz() {
        assert_eq!(
            classify("data.gz"),
            FileClassification::OpaqueArtifact {
                mime_hint: Some("application/archive".to_string()),
            },
        );
    }

    #[test]
    fn opaque_markdown() {
        assert_eq!(
            classify("README.md"),
            FileClassification::OpaqueArtifact {
                mime_hint: Some("text/md".to_string()),
            },
        );
    }

    #[test]
    fn opaque_txt() {
        assert_eq!(
            classify("notes.txt"),
            FileClassification::OpaqueArtifact {
                mime_hint: Some("text/txt".to_string()),
            },
        );
    }

    #[test]
    fn opaque_json() {
        // Note: plain .json files are opaque (package.json is a PackageManifest)
        assert_eq!(
            classify("data.json"),
            FileClassification::OpaqueArtifact {
                mime_hint: Some("text/json".to_string()),
            },
        );
    }

    #[test]
    fn opaque_yaml() {
        // A .yaml file NOT under .github/workflows -> opaque
        assert_eq!(
            classify("config.yaml"),
            FileClassification::OpaqueArtifact {
                mime_hint: Some("text/yaml".to_string()),
            },
        );
    }

    #[test]
    fn opaque_csv() {
        assert_eq!(
            classify("data.csv"),
            FileClassification::OpaqueArtifact {
                mime_hint: Some("text/csv".to_string()),
            },
        );
    }

    #[test]
    fn opaque_html() {
        assert_eq!(
            classify("index.html"),
            FileClassification::OpaqueArtifact {
                mime_hint: Some("text/html".to_string()),
            },
        );
    }

    #[test]
    fn opaque_xml() {
        assert_eq!(
            classify("config.xml"),
            FileClassification::OpaqueArtifact {
                mime_hint: Some("text/xml".to_string()),
            },
        );
    }

    // ── ShallowSyntax (C2) ───────────────────────────────────────────

    #[test]
    fn shallow_syntax_c() {
        assert_eq!(
            classify("src/main.c"),
            FileClassification::ShallowSyntax {
                language_hint: "c".to_string(),
            },
        );
    }

    #[test]
    fn shallow_syntax_h() {
        assert_eq!(
            classify("include/header.h"),
            FileClassification::ShallowSyntax {
                language_hint: "c".to_string(),
            },
        );
    }

    #[test]
    fn shallow_syntax_cpp() {
        assert_eq!(
            classify("src/engine.cpp"),
            FileClassification::ShallowSyntax {
                language_hint: "cpp".to_string(),
            },
        );
    }

    #[test]
    fn shallow_syntax_ruby() {
        assert_eq!(
            classify("app/models/user.rb"),
            FileClassification::ShallowSyntax {
                language_hint: "ruby".to_string(),
            },
        );
    }

    #[test]
    fn shallow_syntax_swift() {
        assert_eq!(
            classify("Sources/App.swift"),
            FileClassification::ShallowSyntax {
                language_hint: "swift".to_string(),
            },
        );
    }

    #[test]
    fn shallow_syntax_kotlin() {
        assert_eq!(
            classify("src/Main.kt"),
            FileClassification::ShallowSyntax {
                language_hint: "kotlin".to_string(),
            },
        );
    }

    #[test]
    fn shallow_syntax_csharp() {
        assert_eq!(
            classify("Program.cs"),
            FileClassification::ShallowSyntax {
                language_hint: "csharp".to_string(),
            },
        );
    }

    #[test]
    fn shallow_syntax_php() {
        assert_eq!(
            classify("index.php"),
            FileClassification::ShallowSyntax {
                language_hint: "php".to_string(),
            },
        );
    }

    #[test]
    fn shallow_syntax_does_not_override_entity_source() {
        // .rs is EntitySource (C3+), NOT ShallowSyntax
        assert_eq!(classify("src/lib.rs"), FileClassification::EntitySource);
        assert_eq!(classify("main.py"), FileClassification::EntitySource);
    }

    // ── Edge cases ──────────────────────────────────────────────────

    #[test]
    fn no_extension() {
        assert_eq!(
            classify("LICENSE"),
            FileClassification::OpaqueArtifact { mime_hint: None },
        );
    }

    #[test]
    fn hidden_file_no_extension() {
        assert_eq!(
            classify(".gitignore"),
            FileClassification::OpaqueArtifact { mime_hint: None },
        );
    }

    #[test]
    fn hidden_file_with_extension() {
        assert_eq!(
            classify(".env.local"),
            FileClassification::OpaqueArtifact { mime_hint: None },
        );
    }

    #[test]
    fn deeply_nested_entity_source() {
        assert_eq!(
            classify("packages/core/src/utils/helpers.ts"),
            FileClassification::EntitySource,
        );
    }

    #[test]
    fn deeply_nested_makefile() {
        assert_eq!(
            classify("services/api/Makefile"),
            FileClassification::StructuredArtifact(ArtifactKind::Makefile),
        );
    }

    #[test]
    fn unknown_extension() {
        assert_eq!(
            classify("data.parquet"),
            FileClassification::OpaqueArtifact { mime_hint: None },
        );
    }

    #[test]
    fn toml_not_manifest() {
        // A random .toml file that isn't Cargo.toml or pyproject.toml
        assert_eq!(
            classify("config.toml"),
            FileClassification::OpaqueArtifact {
                mime_hint: Some("text/toml".to_string()),
            },
        );
    }

    #[test]
    fn yml_not_ci() {
        // A .yml file that is NOT a CI config
        assert_eq!(
            classify("docker-compose.yml"),
            FileClassification::OpaqueArtifact {
                mime_hint: Some("text/yml".to_string()),
            },
        );
    }

    #[test]
    fn requirements_txt_is_manifest() {
        assert_eq!(
            classify("backend/requirements.txt"),
            FileClassification::StructuredArtifact(ArtifactKind::PackageManifest),
        );
    }

    #[test]
    fn github_actions_nested_path() {
        assert_eq!(
            classify("repo/.github/workflows/release.yml"),
            FileClassification::StructuredArtifact(ArtifactKind::CiConfig),
        );
    }
}
