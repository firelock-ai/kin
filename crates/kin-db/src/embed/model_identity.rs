// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Local artifact locations are acquisition details, never embedding identity.

use super::{parse_model_config, BertConfig, EMBEDDING_CACHE_PIPELINE_EPOCH, EMBED_MAX_SEQ_LEN};
use crate::error::KinDbError;
use sha2::{Digest, Sha256};
use std::fs::{File, Metadata};
use std::io::{Read, Seek};
use std::path::Path;

pub(super) const LOCAL_CONTENT_PREFIX: &str = "local-content-sha256:";
const IDENTITY_SCHEMA: &[u8] = b"kin-local-embedding-space-v1";
const PROCESSING_SCHEMA: &str = "right-truncate;longest-first;batch-longest-pad;right-pad;pad-type-0;mean-or-config-pool;l2-normalize-v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct LocalModelIdentity {
    pub model_id: String,
    pub dimensions: usize,
    pub query_prefix: String,
}

/// Metadata detects replacements and some concurrent writes, but equal metadata
/// cannot attest equal bytes: filesystem timestamps can repeat across writes.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ArtifactGeneration {
    len: u64,
    modified: Option<std::time::SystemTime>,
    #[cfg(unix)]
    unix: (u64, u64, i64, i64),
}

impl ArtifactGeneration {
    fn from_metadata(metadata: &Metadata) -> Result<Self, KinDbError> {
        if !metadata.is_file() {
            return Err(KinDbError::IndexError(
                "model artifact is not a regular file".into(),
            ));
        }
        Ok(Self {
            len: metadata.len(),
            modified: metadata.modified().ok(),
            #[cfg(unix)]
            unix: {
                use std::os::unix::fs::MetadataExt;
                (
                    metadata.dev(),
                    metadata.ino(),
                    metadata.ctime(),
                    metadata.ctime_nsec(),
                )
            },
        })
    }
}

fn artifact_error(path: &Path, error: impl std::fmt::Display) -> KinDbError {
    KinDbError::IndexError(format!(
        "cannot identify model artifact {}: {error}",
        path.display()
    ))
}

fn artifact_generation(path: &Path) -> Result<ArtifactGeneration, KinDbError> {
    ArtifactGeneration::from_metadata(
        &std::fs::metadata(path).map_err(|error| artifact_error(path, error))?,
    )
}

#[cfg(test)]
std::thread_local! {
    static HASH_READS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static AFTER_HASH: std::cell::RefCell<Option<Box<dyn FnOnce()>>> = const { std::cell::RefCell::new(None) };
}

/// Hash a mutable artifact with bounded memory at an acquisition/reopen boundary.
/// Equal mtime/ctime values are not a content generation, even on Unix. Compare
/// two complete reads as well as metadata; loaded embedders retain their own
/// identity instead of calling this on each semantic query. This detects changes
/// between the reads, but is not an atomic snapshot against an adversarial writer.
fn artifact_digest(path: &Path) -> Result<[u8; 32], KinDbError> {
    artifact_digest_with_generation(path, ArtifactGeneration::from_metadata)
}

fn read_digest(file: &mut File, path: &Path) -> Result<[u8; 32], KinDbError> {
    #[cfg(test)]
    HASH_READS.with(|reads| reads.set(reads.get() + 1));
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| artifact_error(path, error))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hasher.finalize().into())
}

fn artifact_digest_with_generation(
    path: &Path,
    generation: impl Fn(&Metadata) -> Result<ArtifactGeneration, KinDbError>,
) -> Result<[u8; 32], KinDbError> {
    let mut file = File::open(path).map_err(|error| artifact_error(path, error))?;
    let before = generation(
        &file
            .metadata()
            .map_err(|error| artifact_error(path, error))?,
    )?;
    let digest = read_digest(&mut file, path)?;
    #[cfg(test)]
    AFTER_HASH.with(|hook| {
        if let Some(hook) = hook.borrow_mut().take() {
            hook();
        }
    });
    file.rewind().map_err(|error| artifact_error(path, error))?;
    let verified_digest = read_digest(&mut file, path)?;
    let after = generation(
        &file
            .metadata()
            .map_err(|error| artifact_error(path, error))?,
    )?;
    let public =
        generation(&std::fs::metadata(path).map_err(|error| artifact_error(path, error))?)?;
    if digest != verified_digest || before != after || after != public {
        return Err(artifact_error(
            path,
            "artifact changed while its identity was resolved",
        ));
    }
    Ok(digest)
}

#[cfg(test)]
pub(super) fn hash_reads() -> usize {
    HASH_READS.with(|reads| reads.get())
}

fn hash_field(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

/// Content digest for a set of model artifacts in canonical role order.
/// Paths locate the bytes but do not contribute to the digest.
pub(super) fn artifact_identity<const N: usize>(
    paths: [&Path; N],
    dimensions: usize,
    pipeline: &str,
    query_prefix: &str,
    max_sequence_len: usize,
) -> Result<String, KinDbError> {
    let mut hasher = Sha256::new();
    hash_field(&mut hasher, IDENTITY_SCHEMA);
    hash_field(&mut hasher, pipeline.as_bytes());
    hash_field(&mut hasher, PROCESSING_SCHEMA.as_bytes());
    hash_field(&mut hasher, query_prefix.as_bytes());
    hash_field(&mut hasher, &(dimensions as u64).to_le_bytes());
    hash_field(&mut hasher, &(max_sequence_len as u64).to_le_bytes());
    for (role, path) in paths.into_iter().enumerate() {
        hash_field(&mut hasher, &(role as u64).to_le_bytes());
        hash_field(&mut hasher, &artifact_digest(path)?);
    }
    Ok(format!(
        "{LOCAL_CONTENT_PREFIX}{}",
        hex::encode(hasher.finalize())
    ))
}

pub(super) fn resolve(dir: &Path) -> Result<LocalModelIdentity, KinDbError> {
    let (config_path, tokenizer_path, weights_path) = super::resolve_local_model_artifacts(dir)?;
    let paths = [&config_path, &tokenizer_path, &weights_path];
    let before = paths
        .map(|path| artifact_generation(path))
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    let config_data = std::fs::read_to_string(&config_path)
        .map_err(|error| artifact_error(&config_path, error))?;
    let config: BertConfig =
        parse_model_config(&config_data).map_err(|error| artifact_error(&config_path, error))?;
    let raw: serde_json::Value =
        serde_json::from_str(&config_data).map_err(|error| artifact_error(&config_path, error))?;
    let query_prefix = match raw.get("kin_query_prefix") {
        Some(serde_json::Value::String(prefix)) => prefix.clone(),
        Some(_) => {
            return Err(artifact_error(
                &config_path,
                "kin_query_prefix must be a string",
            ))
        }
        None => super::local_query_prefix("", config.model_type.as_deref()),
    };
    let dimensions = config.hidden_size;
    if dimensions == 0 {
        return Err(artifact_error(&config_path, "hidden_size must be positive"));
    }
    let model_id = artifact_identity(
        [&config_path, &tokenizer_path, &weights_path],
        dimensions,
        EMBEDDING_CACHE_PIPELINE_EPOCH,
        &query_prefix,
        config.effective_max_seq_len().min(EMBED_MAX_SEQ_LEN),
    )?;
    let after = paths
        .map(|path| artifact_generation(path))
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    let verified_config = std::fs::read_to_string(&config_path)
        .map_err(|error| artifact_error(&config_path, error))?;
    if before != after || config_data != verified_config {
        return Err(artifact_error(
            dir,
            "model artifacts changed while their identity was resolved",
        ));
    }
    Ok(LocalModelIdentity {
        model_id,
        dimensions,
        query_prefix,
    })
}

#[cfg(test)]
pub(super) fn write_test_model(dir: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join("config.json"), br#"{"hidden_size":2,"num_hidden_layers":1,"num_attention_heads":1,"intermediate_size":4,"max_position_embeddings":512,"vocab_size":8,"model_type":"bert"}"#).unwrap();
    std::fs::write(dir.join("tokenizer.json"), b"test-tokenizer").unwrap();
    std::fs::write(dir.join("model.safetensors"), b"test-weights").unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_model_content_identity_survives_move_and_directory_names() {
        let root = tempfile::tempdir().unwrap();
        let first = root.path().join("swerank-linux");
        let second = root.path().join("mac");
        write_test_model(&first);
        write_test_model(&second);
        let a = resolve(&first).unwrap();
        let b = resolve(&second).unwrap();
        assert_eq!(a, b);
        assert!(
            a.query_prefix.is_empty(),
            "directory names cannot choose preprocessing"
        );
        assert!(!a.model_id.contains(root.path().to_str().unwrap()));
    }

    #[test]
    fn local_model_content_identity_rejects_each_changed_artifact() {
        let root = tempfile::tempdir().unwrap();
        for name in ["model.safetensors", "tokenizer.json", "config.json"] {
            write_test_model(root.path());
            let before = resolve(root.path()).unwrap();
            let path = root.path().join(name);
            let mut content = std::fs::read(&path).unwrap();
            if name == "config.json" {
                // Keep valid JSON while changing the effective model config.
                content = String::from_utf8(content)
                    .unwrap()
                    .replace("512", "256")
                    .into_bytes();
            } else {
                content[0] ^= 1; // Same size, same locator, same revision label.
            }
            std::fs::write(path, content).unwrap();
            assert_ne!(
                before.model_id,
                resolve(root.path()).unwrap().model_id,
                "{name}"
            );
        }
    }

    #[test]
    fn local_model_content_identity_binds_processing() {
        let root = tempfile::tempdir().unwrap();
        write_test_model(root.path());
        let paths = super::super::resolve_local_model_artifacts(root.path()).unwrap();
        let paths = [&*paths.0, &*paths.1, &*paths.2];
        let base = artifact_identity(paths, 2, "pipeline", "query", 512).unwrap();
        for changed in [
            artifact_identity(paths, 3, "pipeline", "query", 512),
            artifact_identity(paths, 2, "pipeline-v2", "query", 512),
            artifact_identity(paths, 2, "pipeline", "different-query", 512),
            artifact_identity(paths, 2, "pipeline", "query", 256),
        ] {
            assert_ne!(base, changed.unwrap());
        }
    }

    #[test]
    fn local_model_content_identity_missing_artifact_fails_closed() {
        let root = tempfile::tempdir().unwrap();
        write_test_model(root.path());
        std::fs::remove_file(root.path().join("model.safetensors")).unwrap();
        assert!(resolve(root.path()).is_err());
    }

    #[test]
    fn local_model_content_identity_resolution_verifies_mutable_bytes() {
        let root = tempfile::tempdir().unwrap();
        write_test_model(root.path());
        HASH_READS.with(|reads| reads.set(0));
        let first = resolve(root.path()).unwrap();
        assert_eq!(hash_reads(), 6);
        assert_eq!(first, resolve(root.path()).unwrap());
        assert_eq!(hash_reads(), 12);
    }

    // Model a filesystem whose timestamps do not advance across these writes.
    // Keep length and inode identity real, so the control changes only the
    // assumption that timestamps uniquely identify a content generation.
    fn unchanged_timestamps(metadata: &Metadata) -> Result<ArtifactGeneration, KinDbError> {
        let mut generation = ArtifactGeneration::from_metadata(metadata)?;
        generation.modified = Some(std::time::UNIX_EPOCH);
        #[cfg(unix)]
        {
            generation.unix.2 = 0;
            generation.unix.3 = 0;
        }
        Ok(generation)
    }

    #[test]
    fn local_model_content_identity_equal_metadata_cannot_reuse_changed_bytes() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("weights");
        std::fs::write(&path, b"first").unwrap();
        let before = unchanged_timestamps(&std::fs::metadata(&path).unwrap()).unwrap();
        let first = artifact_digest_with_generation(&path, unchanged_timestamps).unwrap();
        std::fs::write(&path, b"later").unwrap();
        let after = unchanged_timestamps(&std::fs::metadata(&path).unwrap()).unwrap();
        assert_eq!(
            before, after,
            "the control must preserve the metadata tuple"
        );
        let later = artifact_digest_with_generation(&path, unchanged_timestamps).unwrap();
        assert_ne!(first, later);
    }

    #[test]
    fn local_model_content_identity_rejects_equal_metadata_change_during_hash() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("weights");
        std::fs::write(&path, b"first").unwrap();
        let before = unchanged_timestamps(&std::fs::metadata(&path).unwrap()).unwrap();
        let changed = path.clone();
        AFTER_HASH.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                std::fs::write(&changed, b"later").unwrap();
                let after = unchanged_timestamps(&std::fs::metadata(&changed).unwrap()).unwrap();
                assert_eq!(before, after);
            }));
        });
        assert!(artifact_digest_with_generation(&path, unchanged_timestamps)
            .unwrap_err()
            .to_string()
            .contains("changed"));
        // A refused first read must not poison a later stable identity.
        assert_eq!(
            artifact_digest(&path).unwrap(),
            Sha256::digest(b"later").as_slice()
        );
    }

    #[test]
    fn local_model_content_identity_rejects_change_during_hash() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("weights");
        std::fs::write(&path, b"first").unwrap();
        let changed = path.clone();
        AFTER_HASH.with(|hook| {
            *hook.borrow_mut() = Some(Box::new(move || {
                std::fs::write(changed, b"later").unwrap();
            }));
        });
        assert!(artifact_digest(&path)
            .unwrap_err()
            .to_string()
            .contains("changed"));
    }
}
