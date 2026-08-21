// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{anyhow, bail, Context, Result};
use serde::Serialize;
use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Manifest field naming the repository-v6 store a prepared state carries.
const REPOSITORY_ID_KEY: &str = "repository_id";
/// Manifest field naming that store's authority generation.
const AUTHORITY_GENERATION_KEY: &str = "authority_generation";

const PREPARED_PUBLISH_SCHEMA: &str = "kin.prepared-state.publish.v2";
const PREPARED_MATERIALIZE_SCHEMA: &str = "kin.prepared-state.materialize.v2";
const PREPARED_MANIFEST_SCHEMA: &str = "kin.prepared-state.v2";
const EMBEDDED_PREPARED_MANIFEST: &str = ".kin/bench/prepared-manifest.json";

const VALIDATION_KEYS: &[&str] = &[
    "cache_key",
    "repo_identity",
    "git_head",
    "git_tree",
    "graph_build_pipeline_epoch",
    "parser_schema_epoch",
    "layout_schema_version",
    "graph_snapshot_version",
    "text_index_format_version",
    "vector_index_metadata_version",
    "feature_flags",
    "embedding_model_id",
    "embedding_model_revision",
    "embedding_pipeline_epoch",
    "embeddings_enabled",
    "vector_enabled",
    "metal_enabled",
    "kin_commit",
    "kin_dirty",
];

#[derive(Debug, Serialize)]
struct PublishResult {
    schema: &'static str,
    prepared_dir: String,
    manifest_path: String,
    cache_key: String,
    repo_identity: String,
    text_index_present: bool,
    vector_index_present: bool,
}

#[derive(Debug, Serialize)]
struct MaterializeResult {
    schema: &'static str,
    source_dir: String,
    repo_path: String,
    manifest_path: String,
    cache_key: String,
    repo_identity: String,
    validated: bool,
    text_index_present: bool,
    vector_index_present: bool,
}

pub async fn publish(target: PathBuf, json: bool) -> Result<()> {
    let repo_path = std::env::current_dir()?;
    let kin_dir = repo_path.join(".kin");
    if !kin_dir.exists() {
        // The condition is this exact directory rather than a discovery: a
        // prepared state is published from the repository root it was built
        // in, not from anywhere beneath it. The refusal is still the shared
        // one, so the remedy cannot drift away from every other command's.
        return Err(crate::commands::not_a_kin_repository());
    }

    let mut manifest = expected_manifest(&repo_path)?;
    stamp_repository_authority_identity(&mut manifest, &kin_dir)?;
    if prepared_state_expects_vectors(&manifest) {
        require_complete_prepared_embeddings(&kin_dir)?;
    }
    write_embedded_prepared_manifest(&kin_dir, &manifest)?;
    publish_prepared_state_from_kin_dir(&kin_dir, &target, &manifest)?;

    let result = PublishResult {
        schema: PREPARED_PUBLISH_SCHEMA,
        prepared_dir: target.display().to_string(),
        manifest_path: target.join("manifest.json").display().to_string(),
        cache_key: manifest_string(&manifest, "cache_key")?,
        repo_identity: manifest_string(&manifest, "repo_identity")?,
        text_index_present: target.join(".kin/kindb/text-index").exists(),
        vector_index_present: target.join(".kin/kindb/graph.kvec").exists()
            && target.join(".kin/kindb/graph.kvec.meta.json").exists(),
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("published prepared state to {}", result.prepared_dir);
        println!("cache_key: {}", result.cache_key);
        println!("repo_identity: {}", result.repo_identity);
    }

    Ok(())
}

pub async fn materialize(source: PathBuf, json: bool) -> Result<()> {
    let repo_path = std::env::current_dir()?;
    let expected_manifest = expected_manifest(&repo_path)?;
    let actual_manifest = validate_prepared_state(&source, &expected_manifest)?;
    materialize_prepared_state(&source, &repo_path)?;

    let result = MaterializeResult {
        schema: PREPARED_MATERIALIZE_SCHEMA,
        source_dir: source.display().to_string(),
        repo_path: repo_path.display().to_string(),
        manifest_path: source.join("manifest.json").display().to_string(),
        cache_key: manifest_string(&actual_manifest, "cache_key")?,
        repo_identity: manifest_string(&actual_manifest, "repo_identity")?,
        validated: true,
        text_index_present: source.join(".kin/kindb/text-index").exists(),
        vector_index_present: source.join(".kin/kindb/graph.kvec").exists()
            && source.join(".kin/kindb/graph.kvec.meta.json").exists(),
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("materialized prepared state from {}", result.source_dir);
        println!("cache_key: {}", result.cache_key);
        println!("repo_identity: {}", result.repo_identity);
    }

    Ok(())
}

fn expected_manifest(repo_path: &Path) -> Result<Value> {
    let meta = crate::commands::bench_meta::build_meta()?;
    let (prepared_manifest, _) =
        crate::commands::bench_meta::build_prepared_manifests(&meta, repo_path)?;
    serde_json::to_value(&prepared_manifest).context("serialize prepared-state manifest")
}

fn validate_prepared_state(prepared_dir: &Path, expected_manifest: &Value) -> Result<Value> {
    let manifest_path = prepared_dir.join("manifest.json");
    if !prepared_dir.exists() {
        bail!("missing prepared state");
    }
    if !manifest_path.exists() {
        bail!("prepared manifest missing");
    }

    let actual_manifest: Value = serde_json::from_str(
        &fs::read_to_string(&manifest_path)
            .with_context(|| format!("read prepared manifest {}", manifest_path.display()))?,
    )
    .with_context(|| format!("parse prepared manifest {}", manifest_path.display()))?;

    if actual_manifest
        .get("schema")
        .and_then(Value::as_str)
        .unwrap_or_default()
        != PREPARED_MANIFEST_SCHEMA
    {
        bail!("schema version mismatch");
    }

    for key in VALIDATION_KEYS {
        if actual_manifest.get(*key) != expected_manifest.get(*key) {
            bail!("{} mismatch", key.replace('_', " "));
        }
    }
    validate_embedded_prepared_manifest(prepared_dir, expected_manifest)?;

    for relative_path in required_prepared_entries() {
        if !prepared_dir.join(relative_path).exists() {
            bail!("prepared artifact missing {}", relative_path.display());
        }
    }
    require_matching_repository_authority_identity(&prepared_dir.join(".kin"), &actual_manifest)?;

    // When the prepared state declares an embeddings-capable runtime, the
    // vector sidecar is part of the graph-native truth a reuse must restore.
    // Without this check a vector-blind prepared dir (graph and text index but
    // no graph.kvec) validates as "good" and reuse silently re-opens with an
    // empty index — the dormant-index trap. Non-embedded runtimes
    // (embeddings_enabled = false) are valid and skip this requirement.
    if prepared_state_expects_vectors(&actual_manifest) {
        for relative_path in required_vector_entries() {
            if !prepared_dir.join(relative_path).exists() {
                bail!(
                    "prepared artifact missing {} (manifest declares embeddings enabled; \
                     reuse would run with an empty vector index)",
                    relative_path.display()
                );
            }
        }
        require_complete_prepared_embeddings(&prepared_dir.join(".kin"))?;
    }

    Ok(actual_manifest)
}

/// The repository-v6 store a `.kin` directory carries, opened through the same
/// retained-authority read path the daemon and CLI use.
///
/// Repository-v6 keeps the graph under `.kin/kindb/<repository-id>/snapshots/`
/// and names the current generation in that namespace's authority record. The
/// retired single-file `.kin/kindb/graph.kndb` is never written, so prepared
/// state must resolve the snapshot through authority rather than address a
/// fixed file name. Opening the manager also decodes and digest-checks that
/// snapshot, which is a stronger guarantee than the path existing.
struct PreparedRepositoryAuthority {
    repository_id: String,
    generation: u64,
    #[cfg(feature = "vector")]
    graph: kin_db::InMemoryGraph,
}

fn open_prepared_repository_authority(kin_dir: &Path) -> Result<PreparedRepositoryAuthority> {
    let layout = kin_core::KinLayout::new(kin_dir.to_path_buf());
    let binding = kin_core::LocalRepositoryAuthorityBinding::from_layout(&layout)
        .with_context(|| format!("open repository authority at {}", kin_dir.display()))?;
    let manager = binding.open_manager().map_err(|error| {
        anyhow!(
            "open repository authority at {}: {error}",
            kin_dir.display()
        )
    })?;
    let lease = manager.read_authority();
    let generation = lease.roots().generation;
    let workspace_id = binding.workspace_id();
    // Same workspace-scoped materialization the daemon loads its query graph
    // from, so prepared-state coverage is measured against the graph a reuse
    // will actually serve.
    let workspace_snapshot = lease
        .workspace_graph_snapshot(&workspace_id)
        .map_err(|error| {
            anyhow!(
                "resolve workspace {workspace_id} graph at {}: {error}",
                kin_dir.display()
            )
        })?
        .ok_or_else(|| {
            anyhow!(
                "repository authority at {} has no manifest workspace {workspace_id}",
                kin_dir.display()
            )
        })?;
    // Decoding stays unconditional: it is the digest check that proves the
    // authority snapshot is intact, even when no vector validation retains it.
    let graph = kin_db::InMemoryGraph::from_snapshot(workspace_snapshot)
        .map_err(|error| anyhow!("decode repository graph at {}: {error}", kin_dir.display()))?;
    #[cfg(not(feature = "vector"))]
    let _ = graph;
    Ok(PreparedRepositoryAuthority {
        repository_id: binding.repository_id().to_string(),
        generation,
        #[cfg(feature = "vector")]
        graph,
    })
}

/// Record which repository-v6 store and generation this prepared state carries.
fn stamp_repository_authority_identity(manifest: &mut Value, kin_dir: &Path) -> Result<()> {
    let authority = open_prepared_repository_authority(kin_dir)?;
    let object = manifest
        .as_object_mut()
        .context("prepared manifest is not a JSON object")?;
    object.insert(
        REPOSITORY_ID_KEY.to_string(),
        Value::String(authority.repository_id),
    );
    object.insert(
        AUTHORITY_GENERATION_KEY.to_string(),
        Value::from(authority.generation),
    );
    Ok(())
}

/// Reject a prepared state whose manifest does not describe the repository-v6
/// store its own payload carries. Identity here is the repository id plus the
/// authority generation, never a snapshot file path: the file name is a
/// projection of the generation, so comparing paths would accept a payload from
/// a different store that happens to sit at the same generation.
fn require_matching_repository_authority_identity(kin_dir: &Path, manifest: &Value) -> Result<()> {
    let authority = open_prepared_repository_authority(kin_dir)?;
    let declared_repository = manifest
        .get(REPOSITORY_ID_KEY)
        .and_then(Value::as_str)
        .with_context(|| format!("prepared manifest missing string field {REPOSITORY_ID_KEY}"))?;
    if declared_repository != authority.repository_id {
        bail!(
            "repository identity mismatch: manifest declares {declared_repository}, prepared \
             state carries {}",
            authority.repository_id
        );
    }
    let declared_generation = manifest
        .get(AUTHORITY_GENERATION_KEY)
        .and_then(Value::as_u64)
        .with_context(|| {
            format!("prepared manifest missing integer field {AUTHORITY_GENERATION_KEY}")
        })?;
    if declared_generation != authority.generation {
        bail!(
            "authority generation mismatch: manifest declares {declared_generation}, prepared \
             state carries {}",
            authority.generation
        );
    }
    Ok(())
}

#[cfg(feature = "vector")]
fn require_complete_prepared_embeddings(kin_dir: &Path) -> Result<()> {
    let layout = kin_core::KinLayout::new(kin_dir.to_path_buf());
    // The vector index is a derived sidecar that repository-v6 still keeps at
    // `.kin/kindb/graph.kvec`, next to the other derived indexes, so its path
    // stays layout-derived even though the graph itself moved into the
    // per-repository authority namespace.
    let vector_path = layout.kindb_vector_index_path();
    let graph = open_prepared_repository_authority(kin_dir)?.graph;
    let loaded = kin_db::SnapshotManager::load_vector_index_into_graph_if_valid(
        &graph,
        &layout.kindb_snapshot_path(),
        None,
    )
    .with_context(|| format!("validate prepared vector index {}", vector_path.display()))?;
    if !loaded.attached {
        bail!(
            "prepared vector index {} is missing or incompatible with its graph/model metadata",
            vector_path.display()
        );
    }
    let status = graph.embedding_status();
    if status.indexed != status.total || status.pending != 0 {
        bail!(
            "prepared embeddings incomplete: {}/{} indexed, {} unindexed, {} pending",
            status.indexed,
            status.total,
            status.total.saturating_sub(status.indexed),
            status.pending
        );
    }
    Ok(())
}

#[cfg(not(feature = "vector"))]
fn require_complete_prepared_embeddings(_kin_dir: &Path) -> Result<()> {
    bail!(
        "prepared state requires vector embeddings, but this Kin build has vector support disabled"
    )
}

/// Whether a prepared-state manifest declares an embeddings-capable runtime,
/// meaning the vector sidecar must be present for the reuse to be vector-sound.
fn prepared_state_expects_vectors(manifest: &Value) -> bool {
    let flag = |key: &str| manifest.get(key).and_then(Value::as_bool).unwrap_or(false);
    flag("embeddings_enabled") && flag("vector_enabled")
}

fn required_prepared_entries() -> &'static [PathBuf] {
    use std::sync::OnceLock;

    static REQUIRED: OnceLock<Vec<PathBuf>> = OnceLock::new();
    REQUIRED
        .get_or_init(|| {
            vec![
                PathBuf::from(".kin"),
                PathBuf::from(".kin/version"),
                PathBuf::from(".kin/manifest.json"),
                PathBuf::from(".kin/kindb/text-index"),
                PathBuf::from(EMBEDDED_PREPARED_MANIFEST),
            ]
        })
        .as_slice()
}

/// Vector-sidecar artifacts required only when the manifest declares embeddings
/// are enabled (see `prepared_state_expects_vectors`).
fn required_vector_entries() -> &'static [PathBuf] {
    use std::sync::OnceLock;

    static REQUIRED: OnceLock<Vec<PathBuf>> = OnceLock::new();
    REQUIRED
        .get_or_init(|| {
            vec![
                PathBuf::from(".kin/kindb/graph.kvec"),
                PathBuf::from(".kin/kindb/graph.kvec.meta.json"),
            ]
        })
        .as_slice()
}

fn publish_prepared_state_from_kin_dir(
    source_kin_dir: &Path,
    target_dir: &Path,
    manifest: &Value,
) -> Result<()> {
    let parent = target_dir
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    fs::create_dir_all(&parent)?;
    let file_name = target_dir
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("prepared");
    let staging_dir = parent.join(format!(
        ".{file_name}.tmp.{}.{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    ));
    remove_path_if_exists(&staging_dir)?;
    fs::create_dir_all(&staging_dir)?;
    copy_dir_recursive(source_kin_dir, &staging_dir.join(".kin"))?;
    write_embedded_prepared_manifest(&staging_dir.join(".kin"), manifest)?;
    fs::write(
        staging_dir.join("manifest.json"),
        serde_json::to_string_pretty(manifest)?,
    )?;

    if target_dir.exists() {
        remove_path_if_exists(target_dir)?;
    }
    fs::rename(&staging_dir, target_dir)
        .with_context(|| format!("replace prepared dir {}", target_dir.display()))?;
    Ok(())
}

fn materialize_prepared_state(source_dir: &Path, repo_path: &Path) -> Result<()> {
    let kin_dir = repo_path.join(".kin");
    remove_path_if_exists(&kin_dir)?;
    copy_dir_recursive(&source_dir.join(".kin"), &kin_dir)
}

fn write_embedded_prepared_manifest(kin_dir: &Path, manifest: &Value) -> Result<()> {
    let manifest_path = kin_dir
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(EMBEDDED_PREPARED_MANIFEST);
    if let Some(parent) = manifest_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(manifest_path, serde_json::to_string_pretty(manifest)?)
        .context("write embedded prepared-state manifest")?;
    Ok(())
}

fn validate_embedded_prepared_manifest(
    prepared_dir: &Path,
    expected_manifest: &Value,
) -> Result<()> {
    let manifest_path = prepared_dir.join(EMBEDDED_PREPARED_MANIFEST);
    if !manifest_path.exists() {
        bail!(
            "prepared artifact missing {} (runtime fingerprint marker required)",
            EMBEDDED_PREPARED_MANIFEST
        );
    }

    let embedded: Value = serde_json::from_str(
        &fs::read_to_string(&manifest_path)
            .with_context(|| format!("read embedded manifest {}", manifest_path.display()))?,
    )
    .with_context(|| format!("parse embedded manifest {}", manifest_path.display()))?;

    if embedded
        .get("schema")
        .and_then(Value::as_str)
        .unwrap_or_default()
        != PREPARED_MANIFEST_SCHEMA
    {
        bail!("embedded prepared manifest schema version mismatch");
    }

    for key in VALIDATION_KEYS {
        if embedded.get(*key) != expected_manifest.get(*key) {
            bail!("embedded {} mismatch", key.replace('_', " "));
        }
    }

    Ok(())
}

fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src).with_context(|| format!("read {}", src.display()))? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        let file_type = entry.file_type()?;
        if file_type.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else if file_type.is_file() {
            if let Some(parent) = dst_path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::copy(&src_path, &dst_path).with_context(|| {
                format!("copy {} -> {}", src_path.display(), dst_path.display())
            })?;
        }
    }
    Ok(())
}

fn remove_path_if_exists(path: &Path) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let metadata = fs::symlink_metadata(path)?;
    if metadata.is_dir() {
        fs::remove_dir_all(path)?;
    } else {
        fs::remove_file(path)?;
    }
    Ok(())
}

fn manifest_string(manifest: &Value, key: &str) -> Result<String> {
    manifest
        .get(key)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .with_context(|| format!("prepared manifest missing string field {key}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Build a prepared dir over a real repository-v6 store, plus a manifest
    /// stamped with that store's identity. `with_vectors` controls whether the
    /// optional vector sidecar is written; the manifest flags control whether
    /// validation should require it.
    fn make_prepared_dir(
        dir: &Path,
        embeddings_enabled: bool,
        vector_enabled: bool,
        with_vectors: bool,
    ) -> Value {
        let initialized = kin_core::init(dir).expect("initialize prepared repository");
        let layout = initialized.layout;
        let kindb = layout.kindb_dir();
        fs::create_dir_all(layout.text_index_dir()).unwrap();
        if with_vectors {
            fs::write(layout.kindb_vector_index_path(), b"kvec").unwrap();
            fs::write(kindb.join("graph.kvec.meta.json"), b"{}").unwrap();
        }
        let authority = open_prepared_repository_authority(layout.root())
            .expect("read prepared repository authority");

        let mut manifest = json!({
            "schema": PREPARED_MANIFEST_SCHEMA,
            "embeddings_enabled": embeddings_enabled,
            "vector_enabled": vector_enabled,
            REPOSITORY_ID_KEY: authority.repository_id,
            AUTHORITY_GENERATION_KEY: authority.generation,
        });
        // Every validation key must be present (and matched) for the
        // expected/actual comparison to pass; fill the rest with stable stubs.
        for key in VALIDATION_KEYS {
            manifest
                .as_object_mut()
                .unwrap()
                .entry(*key)
                .or_insert(json!("stub"));
        }
        fs::write(
            dir.join("manifest.json"),
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .unwrap();
        fs::create_dir_all(dir.join(".kin/bench")).unwrap();
        fs::write(
            dir.join(EMBEDDED_PREPARED_MANIFEST),
            serde_json::to_string_pretty(&manifest).unwrap(),
        )
        .unwrap();
        manifest
    }

    #[test]
    fn expects_vectors_only_when_both_flags_true() {
        assert!(prepared_state_expects_vectors(
            &json!({"embeddings_enabled": true, "vector_enabled": true})
        ));
        assert!(!prepared_state_expects_vectors(
            &json!({"embeddings_enabled": true, "vector_enabled": false})
        ));
        assert!(!prepared_state_expects_vectors(
            &json!({"embeddings_enabled": false, "vector_enabled": true})
        ));
        assert!(!prepared_state_expects_vectors(&json!({})));
    }

    #[test]
    fn validation_rejects_vector_blind_prepared_state_when_embeddings_expected() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = make_prepared_dir(dir.path(), true, true, /* with_vectors */ false);

        let err = validate_prepared_state(dir.path(), &manifest)
            .expect_err("vector-blind prepared state must be rejected when embeddings expected");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("graph.kvec"),
            "error should name the missing vector sidecar, got: {msg}"
        );
    }

    #[test]
    fn validation_rejects_prepared_state_without_embedded_runtime_manifest() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = make_prepared_dir(dir.path(), false, true, /* with_vectors */ false);
        fs::remove_file(dir.path().join(EMBEDDED_PREPARED_MANIFEST)).unwrap();

        let err = validate_prepared_state(dir.path(), &manifest)
            .expect_err("prepared state without embedded runtime manifest must be rejected");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("runtime fingerprint marker"),
            "error should explain missing runtime marker, got: {msg}"
        );
    }

    /// Vector-gated: the message asserted here comes from opening the sidecar
    /// and finding it invalid, which is work only a build with a vector index
    /// can do. A vector-free build refuses the same prepared state earlier and
    /// for a different reason, asserted separately below, so both builds are
    /// held to a refusal rather than one of them being left unchecked.
    #[cfg(feature = "vector")]
    #[test]
    fn validation_rejects_invalid_vector_sidecar_when_embeddings_expected() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = make_prepared_dir(dir.path(), true, true, /* with_vectors */ true);

        let err = validate_prepared_state(dir.path(), &manifest)
            .expect_err("invalid vector sidecar must be rejected when embeddings expected");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("validate prepared vector index") && msg.contains("graph.kvec"),
            "error should explain coverage validation failed, got: {msg}"
        );
    }

    /// A build with vector support compiled out cannot restore an embeddings
    /// prepared state at all, so reuse must refuse it and say why. Silently
    /// accepting it would reopen with an empty index, which is the dormant-index
    /// trap the vector-gated case above guards from the other side.
    #[cfg(not(feature = "vector"))]
    #[test]
    fn vector_free_validation_refuses_prepared_state_that_expects_embeddings() {
        let dir = tempfile::tempdir().unwrap();
        let manifest = make_prepared_dir(dir.path(), true, true, /* with_vectors */ true);

        let err = validate_prepared_state(dir.path(), &manifest)
            .expect_err("a vector-free build must refuse an embeddings prepared state");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("vector support disabled"),
            "error should explain the build cannot serve embeddings, got: {msg}"
        );
    }

    #[test]
    fn validation_accepts_vectorless_prepared_state_when_embeddings_disabled() {
        let dir = tempfile::tempdir().unwrap();
        // embeddings_enabled = false: a vector-less prepared dir is legitimate.
        let manifest = make_prepared_dir(dir.path(), false, true, /* with_vectors */ false);

        validate_prepared_state(dir.path(), &manifest)
            .expect("non-embedded prepared state must validate without a vector sidecar");
    }
}
