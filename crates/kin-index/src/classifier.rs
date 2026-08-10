// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

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
///
/// This must mirror the adapters registered in `kin-parser`'s `AdapterRegistry`:
/// an extension the registry parses via `get_by_extension` but that is missing
/// here would route whole-repo ingest to a shallower tier than incremental edits
/// (which resolve the adapter directly), producing a smaller graph for the same
/// repo depending on ingest path.
const ENTITY_SOURCE_EXTENSIONS: &[&str] = &[
    "ts", "tsx", "js", "jsx", "mjs", "cjs", "py", "pyi", "go", "java", "rs", "c", "h", "cpp",
    "hpp", "cc", "cxx", "cs", "rb", "kt", "kts", "swift", "php", "tf", "tfvars",
];

/// Extensions eligible for C2 shallow syntax extraction: a tree-sitter grammar
/// exists (see `get_shallow_grammar` in `kin-parser`) but there is no full Kin
/// semantic adapter.
///
/// Currently empty by design. Every language that has a shallow grammar
/// (c, cpp, csharp, ruby, php, swift) also has a full entity-extraction adapter,
/// so all of them classify as `EntitySource` above. Only add an extension here
/// if `get_shallow_grammar` can parse it AND it has no full adapter — otherwise
/// `classify` returns `ShallowSyntax` for a language that shallow parsing cannot
/// handle, and ingest silently falls back to opaque (see `pipeline.rs`).
const SHALLOW_SYNTAX_EXTENSIONS: &[(&str, &str)] = &[];

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
        if let Some((_, lang)) = SHALLOW_SYNTAX_EXTENSIONS
            .iter()
            .find(|(ext, _)| *ext == extension)
        {
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

        // Compose files
        if is_compose_file(file_name) {
            return FileClassification::StructuredArtifact(ArtifactKind::ComposeFile);
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

    /// Classify a file using both its path and exact bytes.
    ///
    /// A parser-capable extension is only an enrichment hint. Bytes that are
    /// not text must remain valid repository content and are therefore routed
    /// to the opaque facet instead of being forced through a language parser.
    pub fn classify_with_content(path: &Path, content: &[u8]) -> FileClassification {
        if is_binary_content(content) {
            return FileClassification::OpaqueArtifact {
                mime_hint: Some("application/octet-stream".to_string()),
            };
        }
        Self::classify(path)
    }
}

/// Conservative binary detection for semantic-enrichment routing.
///
/// This does not decide whether a file belongs in the repository tree: every
/// admitted regular file is tree truth. It only prevents arbitrary bytes from
/// being interpreted as source text. UTF-16 and other NUL-bearing encodings
/// remain available exactly through their blob/tree entry and may gain a
/// dedicated enrichment adapter later.
fn is_binary_content(content: &[u8]) -> bool {
    content.contains(&0) || std::str::from_utf8(content).is_err()
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

/// Check if a file is a Docker Compose / Compose configuration file.
fn is_compose_file(file_name: &str) -> bool {
    matches!(
        file_name,
        "docker-compose.yml" | "docker-compose.yaml" | "compose.yml" | "compose.yaml"
    )
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

    /// Every extension the adapter registry claims must classify as an entity
    /// source, computed by iterating the registry HERE rather than restating it.
    ///
    /// The registry is the supported set. An extension it parses but that this
    /// list omits routes whole-repo ingest to a shallower tier than incremental
    /// edits, so the same repository yields a smaller graph depending on which
    /// path admitted it, and `kin languages` still advertises the extension as
    /// supported. A test that spelled the extensions out would pass forever
    /// while the two lists drifted, which is the drift it exists to prevent.
    #[test]
    fn every_registry_extension_is_an_entity_source() {
        let registry = kin_parser::AdapterRegistry::new();
        let registered = registry.supported_languages_with_extensions();
        assert!(
            !registered.is_empty(),
            "an empty registry would make every assertion here vacuous"
        );
        for (language, extensions) in registered {
            assert!(
                !extensions.is_empty(),
                "{language} claims no extension, so nothing could ever route to it"
            );
            for ext in extensions {
                assert!(
                    ENTITY_SOURCE_EXTENSIONS.contains(ext),
                    "{language} parses .{ext} but whole-repo ingest would classify it \
                     opaque, so the graph depends on the ingest path"
                );
                assert_eq!(
                    FileClassifier::classify(Path::new(&format!("probe.{ext}"))),
                    FileClassification::EntitySource,
                    "{language} parses .{ext} but a path carrying it does not classify \
                     as an entity source"
                );
            }
        }
        assert!(
            !ENTITY_SOURCE_EXTENSIONS.contains(&"kin-not-a-real-extension"),
            "the containment probe must be able to answer no, or the assertions above \
             prove nothing"
        );
    }

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

    #[test]
    fn binary_bytes_override_a_parser_supported_extension() {
        assert_eq!(
            FileClassifier::classify_with_content(Path::new("src/lib.rs"), b"\0\xff\x01"),
            FileClassification::OpaqueArtifact {
                mime_hint: Some("application/octet-stream".to_string())
            }
        );
    }

    #[test]
    fn valid_utf8_keeps_path_based_classification() {
        assert_eq!(
            FileClassifier::classify_with_content(
                Path::new("compose.yaml"),
                b"services:\n  web:\n    image: nginx\n"
            ),
            FileClassification::StructuredArtifact(ArtifactKind::ComposeFile)
        );
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

    // ── StructuredArtifact: ComposeFile ─────────────────────────────

    #[test]
    fn docker_compose_yml() {
        assert_eq!(
            classify("docker-compose.yml"),
            FileClassification::StructuredArtifact(ArtifactKind::ComposeFile),
        );
    }

    #[test]
    fn docker_compose_yaml() {
        assert_eq!(
            classify("docker-compose.yaml"),
            FileClassification::StructuredArtifact(ArtifactKind::ComposeFile),
        );
    }

    #[test]
    fn compose_yaml() {
        assert_eq!(
            classify("compose.yaml"),
            FileClassification::StructuredArtifact(ArtifactKind::ComposeFile),
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

    // ── Grammar-backed languages with full adapters (EntitySource) ───

    #[test]
    fn entity_source_c() {
        assert_eq!(classify("src/main.c"), FileClassification::EntitySource);
    }

    #[test]
    fn entity_source_h() {
        assert_eq!(
            classify("include/header.h"),
            FileClassification::EntitySource
        );
    }

    #[test]
    fn entity_source_cpp() {
        assert_eq!(classify("src/engine.cpp"), FileClassification::EntitySource);
    }

    #[test]
    fn entity_source_ruby() {
        assert_eq!(
            classify("app/models/user.rb"),
            FileClassification::EntitySource,
        );
    }

    #[test]
    fn entity_source_swift() {
        assert_eq!(
            classify("Sources/App.swift"),
            FileClassification::EntitySource
        );
    }

    #[test]
    fn entity_source_kotlin() {
        assert_eq!(classify("src/Main.kt"), FileClassification::EntitySource);
    }

    #[test]
    fn entity_source_kts() {
        assert_eq!(
            classify("build.gradle.kts"),
            FileClassification::EntitySource
        );
    }

    #[test]
    fn entity_source_csharp() {
        assert_eq!(classify("Program.cs"), FileClassification::EntitySource);
    }

    #[test]
    fn entity_source_php() {
        assert_eq!(classify("index.php"), FileClassification::EntitySource);
    }

    #[test]
    fn entity_source_tf() {
        assert_eq!(classify("infra/main.tf"), FileClassification::EntitySource);
    }

    #[test]
    fn entity_source_tfvars() {
        assert_eq!(
            classify("infra/prod.tfvars"),
            FileClassification::EntitySource
        );
    }

    #[test]
    fn entity_source_precedence_over_other_tiers() {
        // EntitySource is checked first, so full-adapter languages never fall
        // through to shallow/opaque classification.
        assert_eq!(classify("src/lib.rs"), FileClassification::EntitySource);
        assert_eq!(classify("main.py"), FileClassification::EntitySource);
    }

    // ── Grammarless extensions: honest opaque (no shallow grammar) ───

    #[test]
    fn removed_grammarless_shallow_extensions_are_opaque() {
        // These languages were listed for C2 shallow extraction, but
        // `get_shallow_grammar` in kin-parser has no grammar for them: shallow
        // parsing always returned None and ingest silently fell back to opaque.
        // Classify them as opaque directly instead of advertising a tier that
        // cannot be delivered.
        let opaque = FileClassification::OpaqueArtifact { mime_hint: None };
        assert_eq!(classify("Main.scala"), opaque);
        assert_eq!(classify("script.lua"), opaque);
        assert_eq!(classify("analysis.r"), opaque);
        assert_eq!(classify("analysis.R"), opaque);
        assert_eq!(classify("main.zig"), opaque);
        assert_eq!(classify("app.ex"), opaque);
        assert_eq!(classify("app.exs"), opaque);
        assert_eq!(classify("gen_server.erl"), opaque);
        assert_eq!(classify("Main.hs"), opaque);
        assert_eq!(classify("types.ml"), opaque);
        assert_eq!(classify("types.mli"), opaque);
        assert_eq!(classify("script.pl"), opaque);
        assert_eq!(classify("Module.pm"), opaque);
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
        // A .yml file that is NOT a CI config or compose file
        assert_eq!(
            classify("deploy/service.yml"),
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
