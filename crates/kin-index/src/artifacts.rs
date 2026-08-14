// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Extractors for structured repository files (Dockerfiles, manifests, CI configs, etc.).
//!
//! These files aren't source code but have meaningful structure. The extractors
//! normalize content so that semantically equivalent files produce the same hash,
//! making formatting-only changes invisible to the dependency graph.

use kin_model::{ArtifactKind, FilePathId, Hash256, StructuredArtifact};
use sha2::{Digest, Sha256};

/// Error type for artifact extraction.
#[derive(Debug, thiserror::Error)]
pub enum ArtifactError {
    #[error("invalid UTF-8 in artifact file")]
    InvalidUtf8,
}

pub type Result<T> = std::result::Result<T, ArtifactError>;

/// Extract a structured artifact from file content.
///
/// The content is normalized according to the artifact kind so that
/// semantically equivalent files produce the same content hash.
pub fn extract_artifact(
    kind: ArtifactKind,
    content: &[u8],
    file_id: &FilePathId,
) -> Result<StructuredArtifact> {
    let normalized = normalize_content(kind, content)?;
    let hash = hash_normalized(&normalized);
    Ok(StructuredArtifact {
        file_id: file_id.clone(),
        kind,
        content_hash: hash,
        text_preview: preview_text(&normalized),
    })
}

/// Normalize content based on artifact kind.
fn normalize_content(kind: ArtifactKind, content: &[u8]) -> Result<String> {
    let text = std::str::from_utf8(content).map_err(|_| ArtifactError::InvalidUtf8)?;

    match kind {
        ArtifactKind::Dockerfile => normalize_dockerfile(text),
        ArtifactKind::PackageManifest => normalize_package_manifest(text),
        ArtifactKind::CiConfig => normalize_ci_config(text),
        ArtifactKind::ComposeFile => normalize_compose_file(text),
        ArtifactKind::Makefile => normalize_makefile(text),
        ArtifactKind::SqlMigration => normalize_sql_migration(text),
    }
}

/// Dockerfile: extract instruction lines, skip blanks and comments, trim whitespace.
/// Order is preserved (instruction order matters).
fn normalize_dockerfile(text: &str) -> Result<String> {
    let instructions = [
        "FROM",
        "COPY",
        "ADD",
        "RUN",
        "ENV",
        "EXPOSE",
        "ENTRYPOINT",
        "CMD",
        "WORKDIR",
        "ARG",
        "LABEL",
        "VOLUME",
        "USER",
        "SHELL",
    ];

    let lines: Vec<&str> = text
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter(|l| {
            let upper = l.to_uppercase();
            instructions.iter().any(|inst| {
                if !upper.starts_with(inst) {
                    return false;
                }
                // Match if line is exactly the instruction or next char is whitespace/=
                upper.len() == inst.len()
                    || upper.as_bytes()[inst.len()].is_ascii_whitespace()
                    || upper.as_bytes()[inst.len()] == b'='
            })
        })
        .collect();

    Ok(lines.join("\n"))
}

/// PackageManifest: filter blanks/comments, trim, sort alphabetically.
/// Key order doesn't matter semantically in most manifests.
fn normalize_package_manifest(text: &str) -> Result<String> {
    let mut lines: Vec<&str> = text
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();

    lines.sort();
    Ok(lines.join("\n"))
}

/// CiConfig: filter blanks/comments, trim whitespace, preserve order.
fn normalize_ci_config(text: &str) -> Result<String> {
    let lines: Vec<&str> = text
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();

    Ok(lines.join("\n"))
}

/// Compose files are operational YAML. Preserve order but strip comments/blank lines.
fn normalize_compose_file(text: &str) -> Result<String> {
    let lines: Vec<&str> = text
        .lines()
        .map(|l| l.trim_end())
        .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
        .collect();

    Ok(lines.join("\n"))
}

/// Makefile: filter blanks/comments, trim trailing whitespace (preserve leading tabs).
/// Order is preserved.
fn normalize_makefile(text: &str) -> Result<String> {
    let lines: Vec<&str> = text
        .lines()
        .map(|l| l.trim_end())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect();

    Ok(lines.join("\n"))
}

/// SqlMigration: uppercase, filter blanks/SQL comments, trim, collapse whitespace.
fn normalize_sql_migration(text: &str) -> Result<String> {
    let upper = text.to_uppercase();
    let lines: Vec<String> = upper
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with("--"))
        .map(collapse_whitespace)
        .collect();

    Ok(lines.join("\n"))
}

/// Collapse runs of whitespace into a single space.
fn collapse_whitespace(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut prev_ws = false;
    for c in s.chars() {
        if c.is_whitespace() {
            if !prev_ws {
                result.push(' ');
                prev_ws = true;
            }
        } else {
            result.push(c);
            prev_ws = false;
        }
    }
    result
}

/// Hash normalized content with SHA-256.
fn hash_normalized(content: &str) -> Hash256 {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    Hash256::from_bytes(bytes)
}

fn preview_text(content: &str) -> Option<String> {
    let collapsed = content
        .split_whitespace()
        .take(64)
        .collect::<Vec<_>>()
        .join(" ");
    let trimmed = collapsed.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.chars().take(320).collect())
    }
}

/// Upper bound, in characters, on the text a tracked artifact retains for
/// retrieval enrichment.
///
/// A tracked artifact is its own text and nothing else: this retained text is
/// the only content the text index and the artifact embedding ever see, so a
/// head-sized cap silently unindexes everything below it. The bound matches
/// the historical-source retention used by ref materialization. It is a
/// retention cap, not a display size; surfaces that render a preview apply
/// their own display bound.
pub const ARTIFACT_TEXT_RETENTION_CHARS: usize = 256_000;

/// Bounded full text of a tracked artifact, when its bytes are text at all.
///
/// A textual MIME hint qualifies the bytes outright. Without one, they qualify
/// by being at least 92% printable, which keeps extensionless binaries out of
/// the text index. Either way the bytes must be valid UTF-8. Returns `None`
/// for binary or empty content, never an empty string.
pub fn opaque_text_preview(content: &[u8], mime_hint: Option<&str>) -> Option<String> {
    let text = std::str::from_utf8(content).ok()?;
    let textual_mime = mime_hint.is_some_and(|mime| {
        mime.starts_with("text/")
            || mime.contains("json")
            || mime.contains("yaml")
            || mime.contains("toml")
            || mime.contains("xml")
            || mime.contains("javascript")
            || mime.contains("shell")
    });
    if !textual_mime {
        let printable = content
            .iter()
            .copied()
            .filter(|byte| byte.is_ascii_graphic() || byte.is_ascii_whitespace())
            .count();
        if content.is_empty() || printable * 100 / content.len() < 92 {
            return None;
        }
    }
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }
    Some(
        trimmed
            .chars()
            .take(ARTIFACT_TEXT_RETENTION_CHARS)
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_file_id() -> FilePathId {
        FilePathId::new("test/file")
    }

    #[test]
    fn dockerfile_normalization() {
        let a = b"# build stage\nFROM rust:1.75\n\n# copy source\nCOPY . /app\nRUN cargo build\n";
        let b = b"FROM rust:1.75\nCOPY . /app\n\n\n# different comment\nRUN cargo build\n";

        let hash_a = extract_artifact(ArtifactKind::Dockerfile, a, &make_file_id())
            .unwrap()
            .content_hash;
        let hash_b = extract_artifact(ArtifactKind::Dockerfile, b, &make_file_id())
            .unwrap()
            .content_hash;

        assert_eq!(
            hash_a, hash_b,
            "comment/whitespace changes should not affect hash"
        );
    }

    #[test]
    fn package_manifest_normalization() {
        let a = b"[package]\nname = \"foo\"\nversion = \"1.0\"\n";
        let b = b"version = \"1.0\"\n[package]\nname = \"foo\"\n";

        let hash_a = extract_artifact(ArtifactKind::PackageManifest, a, &make_file_id())
            .unwrap()
            .content_hash;
        let hash_b = extract_artifact(ArtifactKind::PackageManifest, b, &make_file_id())
            .unwrap()
            .content_hash;

        assert_eq!(hash_a, hash_b, "key reordering should not affect hash");
    }

    #[test]
    fn ci_config_normalization() {
        let a = b"# CI config\nname: build\non: push\nsteps:\n  - run: echo hi\n";
        let b = b"name: build\non: push\nsteps:\n  - run: echo hi\n";

        let hash_a = extract_artifact(ArtifactKind::CiConfig, a, &make_file_id())
            .unwrap()
            .content_hash;
        let hash_b = extract_artifact(ArtifactKind::CiConfig, b, &make_file_id())
            .unwrap()
            .content_hash;

        assert_eq!(hash_a, hash_b, "comment removal should produce same hash");

        // Verify order is preserved: swapping lines should change hash.
        let c = b"on: push\nname: build\nsteps:\n  - run: echo hi\n";
        let hash_c = extract_artifact(ArtifactKind::CiConfig, c, &make_file_id())
            .unwrap()
            .content_hash;
        assert_ne!(hash_a, hash_c, "order should be preserved");
    }

    #[test]
    fn makefile_normalization() {
        let a = b"# Build targets\n\nbuild:\n\tcargo build\n\ntest:\n\tcargo test\n";
        let b = b"build:\n\tcargo build\ntest:\n\tcargo test\n";

        let hash_a = extract_artifact(ArtifactKind::Makefile, a, &make_file_id())
            .unwrap()
            .content_hash;
        let hash_b = extract_artifact(ArtifactKind::Makefile, b, &make_file_id())
            .unwrap()
            .content_hash;

        assert_eq!(
            hash_a, hash_b,
            "comment/blank removal should produce same hash"
        );

        // Verify tabs are preserved — leading tabs are significant.
        let c = b"build:\n    cargo build\ntest:\n    cargo test\n";
        let hash_c = extract_artifact(ArtifactKind::Makefile, c, &make_file_id())
            .unwrap()
            .content_hash;
        assert_ne!(
            hash_b, hash_c,
            "tab vs spaces should produce different hash"
        );
    }

    #[test]
    fn compose_file_normalization() {
        let a = b"# Compose config\nservices:\n  web:\n    image: nginx:latest\n";
        let b = b"services:\n  web:\n    image: nginx:latest\n";

        let hash_a = extract_artifact(ArtifactKind::ComposeFile, a, &make_file_id())
            .unwrap()
            .content_hash;
        let hash_b = extract_artifact(ArtifactKind::ComposeFile, b, &make_file_id())
            .unwrap()
            .content_hash;

        assert_eq!(hash_a, hash_b, "comment removal should produce same hash");
    }

    #[test]
    fn sql_migration_normalization() {
        let a = b"-- Create users table\nCREATE TABLE users (\n  id  INT  PRIMARY KEY\n);\n";
        let b = b"create table users (\nid int primary key\n);\n";

        let hash_a = extract_artifact(ArtifactKind::SqlMigration, a, &make_file_id())
            .unwrap()
            .content_hash;
        let hash_b = extract_artifact(ArtifactKind::SqlMigration, b, &make_file_id())
            .unwrap()
            .content_hash;

        assert_eq!(
            hash_a, hash_b,
            "case and whitespace changes should not affect hash"
        );
    }

    #[test]
    fn empty_content_doesnt_panic() {
        for kind in [
            ArtifactKind::Dockerfile,
            ArtifactKind::PackageManifest,
            ArtifactKind::CiConfig,
            ArtifactKind::ComposeFile,
            ArtifactKind::Makefile,
            ArtifactKind::SqlMigration,
        ] {
            let result = extract_artifact(kind, b"", &make_file_id());
            assert!(
                result.is_ok(),
                "empty content should not panic for {:?}",
                kind
            );
        }
    }

    #[test]
    fn extract_artifact_produces_correct_kind() {
        for kind in [
            ArtifactKind::Dockerfile,
            ArtifactKind::PackageManifest,
            ArtifactKind::CiConfig,
            ArtifactKind::ComposeFile,
            ArtifactKind::Makefile,
            ArtifactKind::SqlMigration,
        ] {
            let artifact = extract_artifact(kind, b"some content", &make_file_id()).unwrap();
            assert_eq!(artifact.kind, kind, "kind should be preserved");
            assert_eq!(
                artifact.file_id,
                make_file_id(),
                "file_id should be preserved"
            );
        }
    }
}
