//! Never-drop indexing tests: verify that all file types are tracked,
//! not just source code files.

use std::path::Path;

use kin_blobs::BlobStore;
use kin_index::{FileClassification, FileClassifier, IndexPipeline, IndexedAny};

/// Helper to write a file in a directory, creating parent dirs as needed.
fn write_file(dir: &Path, rel_path: &str, content: &[u8]) -> std::path::PathBuf {
    let path = dir.join(rel_path);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).unwrap();
    }
    std::fs::write(&path, content).unwrap();
    path
}

#[test]
fn unsupported_file_degrades_to_opaque() {
    let dir = tempfile::tempdir().unwrap();
    let blob_store = BlobStore::new(dir.path().join("blobs")).unwrap();
    let pipeline = IndexPipeline::new();

    // A .png file should not error — it should be tracked as opaque
    let png_path = write_file(dir.path(), "assets/logo.png", b"\x89PNG\r\n\x1a\n fake png");
    let result = pipeline.index_any_file(&png_path, &blob_store);
    assert!(result.is_ok(), "opaque file should not error");
    assert!(
        matches!(result.unwrap(), IndexedAny::OpaqueArtifact(_)),
        "png should be classified as OpaqueArtifact"
    );

    // A .txt file should also not error
    let txt_path = write_file(dir.path(), "notes.txt", b"just some notes");
    let result = pipeline.index_any_file(&txt_path, &blob_store);
    assert!(result.is_ok(), "txt file should not error");
    assert!(
        matches!(result.unwrap(), IndexedAny::OpaqueArtifact(_)),
        "txt should be classified as OpaqueArtifact"
    );
}

#[test]
fn dockerfile_classified_as_structured() {
    let dir = tempfile::tempdir().unwrap();
    let blob_store = BlobStore::new(dir.path().join("blobs")).unwrap();
    let pipeline = IndexPipeline::new();

    let dockerfile_path = write_file(
        dir.path(),
        "Dockerfile",
        b"FROM rust:1.75\nCOPY . /app\nRUN cargo build --release\n",
    );

    let result = pipeline.index_any_file(&dockerfile_path, &blob_store);
    assert!(result.is_ok());
    assert!(
        matches!(result.unwrap(), IndexedAny::StructuredArtifact(_)),
        "Dockerfile should be classified as StructuredArtifact"
    );
}

#[test]
fn package_json_classified_as_structured() {
    let dir = tempfile::tempdir().unwrap();
    let blob_store = BlobStore::new(dir.path().join("blobs")).unwrap();
    let pipeline = IndexPipeline::new();

    let pkg_path = write_file(
        dir.path(),
        "package.json",
        b"{\"name\": \"my-app\", \"version\": \"1.0.0\"}",
    );

    let result = pipeline.index_any_file(&pkg_path, &blob_store);
    assert!(result.is_ok());
    assert!(
        matches!(result.unwrap(), IndexedAny::StructuredArtifact(_)),
        "package.json should be classified as StructuredArtifact"
    );
}

#[test]
fn mixed_repo_indexes_all_files() {
    let dir = tempfile::tempdir().unwrap();
    let blob_store = BlobStore::new(dir.path().join("blobs")).unwrap();
    let pipeline = IndexPipeline::new();

    // Source file
    let ts_path = write_file(
        dir.path(),
        "src/app.ts",
        b"export function main(): void { console.log('hello'); }",
    );

    // Structured artifact
    let dockerfile_path = write_file(
        dir.path(),
        "Dockerfile",
        b"FROM node:18\nCOPY . /app\nRUN npm install\n",
    );

    // Opaque file
    let png_path = write_file(dir.path(), "logo.png", b"\x89PNG fake");

    // All three should succeed
    let ts_result = pipeline.index_any_file(&ts_path, &blob_store).unwrap();
    assert!(
        matches!(ts_result, IndexedAny::EntitySource(_)),
        "ts file should be EntitySource"
    );

    let docker_result = pipeline
        .index_any_file(&dockerfile_path, &blob_store)
        .unwrap();
    assert!(
        matches!(docker_result, IndexedAny::StructuredArtifact(_)),
        "Dockerfile should be StructuredArtifact"
    );

    let png_result = pipeline.index_any_file(&png_path, &blob_store).unwrap();
    assert!(
        matches!(png_result, IndexedAny::OpaqueArtifact(_)),
        "png should be OpaqueArtifact"
    );

    // Verify classifier directly too
    assert_eq!(
        FileClassifier::classify(Path::new("src/app.ts")),
        FileClassification::EntitySource,
    );
    assert_eq!(
        FileClassifier::classify(Path::new("Dockerfile")),
        FileClassification::StructuredArtifact(kin_model::ArtifactKind::Dockerfile),
    );
    assert_eq!(
        FileClassifier::classify(Path::new("logo.png")),
        FileClassification::OpaqueArtifact {
            mime_hint: Some("image/png".to_string()),
        },
    );
}
