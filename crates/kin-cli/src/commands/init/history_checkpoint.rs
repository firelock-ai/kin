// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Durable, deterministic history-hydration checkpoints.
//!
//! Checkpoints are split into four independently verified artifacts:
//! interval-bounded immutable delta segments, separate parser-state and linker
//! frontier objects per boundary, and a small boundary manifest that points to
//! all three object digests. Segment objects form a backwards chain, so a
//! manifest is O(1) in history length and no checkpoint boundary reserializes
//! the completed prefix. Keeping the two frontier domains separate also makes
//! their compatibility and corruption boundaries explicit.

use super::{insert_relation_indexes, ImportedCommitSemanticState, ImportedSemanticFileState};
use anyhow::{anyhow, Context, Result};
use kin_model::SemanticChangeId;
use kin_model::{ArtifactId, EntityDelta, EntityId, Relation, RelationDelta, RelationId};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

const MANIFEST_SCHEMA: &str = "kin.history-hydration.manifest.v2";
const SEGMENT_SCHEMA: &str = "kin.history-hydration.delta-segment.v2";
const PARSER_FRONTIER_SCHEMA: &str = "kin.history-hydration.parser-frontier.v2";
const LINKER_FRONTIER_SCHEMA: &str = "kin.history-hydration.linker-frontier.v2";
const FORMAT_VERSION: u32 = 2;
/// Bump for a replay semantic change even when the artifact shapes are stable.
const HYDRATION_SEMANTICS_VERSION: u32 = 2;
const DEFAULT_INTERVAL: usize = 2_000;
const DEFAULT_MANIFESTS_PER_HISTORY: usize = 6;
const DEFAULT_HISTORY_LIMIT: usize = 2;
const DEFAULT_BYTE_CAP: u64 = 2 * 1024 * 1024 * 1024;

pub(super) const BASE_LINK_MESSAGE: &str = "kin import: base-link (window base universe)";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckpointVersionKeyV2 {
    clean_git_sha: String,
    graph_snapshot_version: u32,
    parser_semantics_version: u32,
    hydration_semantics_version: u32,
    incremental_linker_checkpoint_version: u32,
    kin_index_crate_version: String,
    kin_cli_crate_version: String,
}

impl CheckpointVersionKeyV2 {
    fn for_clean_sha(clean_git_sha: impl Into<String>) -> Self {
        Self {
            clean_git_sha: clean_git_sha.into(),
            graph_snapshot_version: kin_db::GraphSnapshot::CURRENT_VERSION,
            parser_semantics_version: kin_parser::PARSER_SEMANTICS_VERSION,
            hydration_semantics_version: HYDRATION_SEMANTICS_VERSION,
            incremental_linker_checkpoint_version: kin_index::INCREMENTAL_LINKER_CHECKPOINT_VERSION,
            kin_index_crate_version: kin_index::KIN_INDEX_CRATE_VERSION.to_string(),
            kin_cli_crate_version: env!("CARGO_PKG_VERSION").to_string(),
        }
    }
}

#[derive(Debug, Clone)]
enum CheckpointBuildPolicy {
    Enabled(CheckpointVersionKeyV2),
    Disabled(String),
}

#[derive(Debug, Clone)]
pub(super) struct HydrationCheckpointConfig {
    kin_root: PathBuf,
    interval: usize,
    manifests_per_history: usize,
    history_limit: usize,
    byte_cap: u64,
    build_policy: CheckpointBuildPolicy,
}

impl HydrationCheckpointConfig {
    pub(super) fn production(kin_root: &Path) -> Self {
        let build = kin_buildinfo::get();
        let build_policy = checkpoint_build_policy(build.sha, build.dirty);
        Self {
            kin_root: kin_root.to_path_buf(),
            interval: DEFAULT_INTERVAL,
            manifests_per_history: DEFAULT_MANIFESTS_PER_HISTORY,
            history_limit: DEFAULT_HISTORY_LIMIT,
            byte_cap: DEFAULT_BYTE_CAP,
            build_policy,
        }
    }

    #[cfg(test)]
    pub(super) fn clean_for_test(
        kin_root: &Path,
        clean_git_sha: &str,
        interval: usize,
        byte_cap: u64,
    ) -> Self {
        Self {
            kin_root: kin_root.to_path_buf(),
            interval: interval.max(1),
            manifests_per_history: DEFAULT_MANIFESTS_PER_HISTORY,
            history_limit: DEFAULT_HISTORY_LIMIT,
            byte_cap,
            build_policy: CheckpointBuildPolicy::Enabled(CheckpointVersionKeyV2::for_clean_sha(
                clean_git_sha,
            )),
        }
    }

    #[cfg(test)]
    pub(super) fn disabled_for_test(kin_root: &Path, reason: &str) -> Self {
        Self {
            kin_root: kin_root.to_path_buf(),
            interval: 1,
            manifests_per_history: DEFAULT_MANIFESTS_PER_HISTORY,
            history_limit: DEFAULT_HISTORY_LIMIT,
            byte_cap: DEFAULT_BYTE_CAP,
            build_policy: CheckpointBuildPolicy::Disabled(reason.to_string()),
        }
    }

    #[cfg(test)]
    pub(super) fn with_retention_for_test(
        mut self,
        manifests_per_history: usize,
        history_limit: usize,
    ) -> Self {
        self.manifests_per_history = manifests_per_history.max(2);
        self.history_limit = history_limit.max(1);
        self
    }
}

fn checkpoint_build_policy(embedded_sha: &str, embedded_dirty: bool) -> CheckpointBuildPolicy {
    if embedded_dirty {
        return CheckpointBuildPolicy::Disabled(format!(
            "checkpoint reuse/write disabled: kin build {embedded_sha} is dirty; performing a full semantic replay"
        ));
    }
    if embedded_sha.trim().is_empty() || embedded_sha == "unknown" {
        return CheckpointBuildPolicy::Disabled(
            "checkpoint reuse/write disabled: kin build SHA is unknown; performing a full semantic replay"
                .to_string(),
        );
    }
    CheckpointBuildPolicy::Enabled(CheckpointVersionKeyV2::for_clean_sha(embedded_sha))
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(super) struct CheckpointIoStats {
    pub(super) serialized_units: usize,
    pub(super) serialized_bytes: u64,
    pub(super) written_units: usize,
    pub(super) written_bytes: u64,
    pub(super) reused_units: usize,
    pub(super) read_units: usize,
    pub(super) read_bytes: u64,
    pub(super) max_serialized_unit_bytes: u64,
    pub(super) retained_bytes: u64,
}

impl CheckpointIoStats {
    fn record_serialized(&mut self, bytes: usize) {
        let bytes = bytes as u64;
        self.serialized_units += 1;
        self.serialized_bytes = self.serialized_bytes.saturating_add(bytes);
        self.max_serialized_unit_bytes = self.max_serialized_unit_bytes.max(bytes);
    }

    fn record_read(&mut self, bytes: usize) {
        self.read_units += 1;
        self.read_bytes = self.read_bytes.saturating_add(bytes as u64);
    }
}

pub(super) struct HydrationResumeState {
    pub(super) processed_count: usize,
    pub(super) remaining_children: Vec<usize>,
    pub(super) frontier: HashMap<SemanticChangeId, ImportedCommitSemanticState>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum HydrationCheckpointBoundary {
    BaseLink,
    Periodic,
    Final,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CheckpointEnvelope {
    schema: String,
    payload_sha256: String,
    payload: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestPayloadV2 {
    format_version: u32,
    version_key: CheckpointVersionKeyV2,
    history_digest: String,
    processed_count: usize,
    prefix_digest: String,
    boundary_change_id: SemanticChangeId,
    boundary: HydrationCheckpointBoundary,
    delta_tail_digest: String,
    parser_frontier_digest: String,
    linker_frontier_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CompletedSemanticDeltasV2 {
    change_id: SemanticChangeId,
    entity_deltas: Vec<EntityDelta>,
    relation_deltas: Vec<RelationDelta>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DeltaSegmentPayloadV2 {
    format_version: u32,
    version_key: CheckpointVersionKeyV2,
    start_position: usize,
    end_position: usize,
    prefix_before: String,
    prefix_after: String,
    previous_segment_digest: Option<String>,
    completed: Vec<CompletedSemanticDeltasV2>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EntityRelationIndexV2 {
    entity_id: EntityId,
    relation_ids: Vec<RelationId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactRelationIndexV2 {
    artifact_id: ArtifactId,
    relation_ids: Vec<RelationId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportedCommitParserStateV2 {
    files: Vec<(String, ImportedSemanticFileState)>,
    relations: Vec<(RelationId, Relation)>,
    relations_by_src: Vec<EntityRelationIndexV2>,
    relations_by_src_artifact: Vec<ArtifactRelationIndexV2>,
    relations_by_dst: Vec<EntityRelationIndexV2>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ParserFrontierStateV2 {
    change_id: SemanticChangeId,
    state: ImportedCommitParserStateV2,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ParserFrontierPayloadV2 {
    format_version: u32,
    version_key: CheckpointVersionKeyV2,
    processed_count: usize,
    prefix_digest: String,
    boundary_change_id: SemanticChangeId,
    states: Vec<ParserFrontierStateV2>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LinkerFrontierStateV2 {
    change_id: SemanticChangeId,
    linker: kin_index::IncrementalLinkerCheckpointV1,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LinkerFrontierPayloadV2 {
    format_version: u32,
    version_key: CheckpointVersionKeyV2,
    processed_count: usize,
    prefix_digest: String,
    boundary_change_id: SemanticChangeId,
    states: Vec<LinkerFrontierStateV2>,
}

#[derive(Serialize)]
struct HistoryIdentityEntry<'a> {
    git_oid: &'a str,
    change_id: SemanticChangeId,
    parents: &'a [SemanticChangeId],
    message: &'a str,
    artifact_deltas: &'a [kin_model::ArtifactDelta],
}

fn canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    fn sort(value: serde_json::Value) -> serde_json::Value {
        match value {
            serde_json::Value::Object(map) => serde_json::Value::Object(
                map.into_iter()
                    .collect::<BTreeMap<_, _>>()
                    .into_iter()
                    .map(|(key, value)| (key, sort(value)))
                    .collect(),
            ),
            serde_json::Value::Array(values) => {
                serde_json::Value::Array(values.into_iter().map(sort).collect())
            }
            other => other,
        }
    }

    let value = serde_json::to_value(value).context("serialize hydration checkpoint unit")?;
    serde_json::to_vec(&sort(value)).context("encode canonical hydration checkpoint JSON")
}

fn encode_envelope<T: Serialize>(schema: &str, payload: &T) -> Result<Vec<u8>> {
    let payload_value = serde_json::to_value(payload).context("serialize checkpoint payload")?;
    let payload_bytes = canonical_json_bytes(&payload_value)?;
    let envelope = CheckpointEnvelope {
        schema: schema.to_string(),
        payload_sha256: hex::encode(Sha256::digest(&payload_bytes)),
        payload: payload_value,
    };
    canonical_json_bytes(&envelope)
}

fn decode_envelope<T: DeserializeOwned>(schema: &str, path: &Path, bytes: &[u8]) -> Result<T> {
    let envelope: CheckpointEnvelope = serde_json::from_slice(bytes).map_err(|error| {
        anyhow!(
            "REFUSED hydration checkpoint {}: invalid envelope: {}",
            path.display(),
            error
        )
    })?;
    if envelope.schema != schema {
        return Err(anyhow!(
            "REFUSED hydration checkpoint {}: schema '{}' does not match '{}'",
            path.display(),
            envelope.schema,
            schema
        ));
    }
    let actual = hex::encode(Sha256::digest(canonical_json_bytes(&envelope.payload)?));
    if actual != envelope.payload_sha256 {
        return Err(anyhow!(
            "REFUSED hydration checkpoint {}: payload digest mismatch",
            path.display()
        ));
    }
    serde_json::from_value(envelope.payload).map_err(|error| {
        anyhow!(
            "REFUSED hydration checkpoint {}: incompatible payload: {}",
            path.display(),
            error
        )
    })
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn history_prefix_digests(
    imported: &[kin_git::ImportedChange],
    order: &[usize],
) -> Result<Vec<String>> {
    let mut current = Sha256::digest(b"kin-history-hydration-prefix-v2\0").to_vec();
    let mut output = Vec::with_capacity(order.len() + 1);
    output.push(hex::encode(&current));
    for index in order {
        let entry = &imported[*index];
        let identity = HistoryIdentityEntry {
            git_oid: &entry.git_oid,
            change_id: entry.change.id,
            parents: &entry.change.parents,
            message: &entry.change.message,
            artifact_deltas: &entry.change.artifact_deltas,
        };
        let mut hasher = Sha256::new();
        hasher.update(b"kin-history-hydration-prefix-step-v2\0");
        hasher.update(&current);
        hasher.update(canonical_json_bytes(&identity)?);
        current = hasher.finalize().to_vec();
        output.push(hex::encode(&current));
    }
    Ok(output)
}

fn sorted_relation_ids(ids: &HashSet<RelationId>) -> Vec<RelationId> {
    let mut ids: Vec<_> = ids.iter().copied().collect();
    ids.sort_by_key(|id| id.0);
    ids
}

impl ImportedCommitSemanticState {
    fn to_parser_checkpoint_v2(&self) -> ImportedCommitParserStateV2 {
        let Self {
            files,
            relations,
            relations_by_src,
            relations_by_src_artifact,
            relations_by_dst,
            linker: _,
        } = self;

        let mut files: Vec<_> = files
            .iter()
            .map(|(path, state)| (path.clone(), state.clone()))
            .collect();
        files.sort_by(|a, b| a.0.cmp(&b.0));
        let mut relations: Vec<_> = relations
            .iter()
            .map(|(id, relation)| (*id, relation.clone()))
            .collect();
        relations.sort_by_key(|(id, _)| id.0);
        let mut relations_by_src: Vec<_> = relations_by_src
            .iter()
            .map(|(entity_id, ids)| EntityRelationIndexV2 {
                entity_id: *entity_id,
                relation_ids: sorted_relation_ids(ids),
            })
            .collect();
        relations_by_src.sort_by_key(|entry| entry.entity_id);
        let mut relations_by_src_artifact: Vec<_> = relations_by_src_artifact
            .iter()
            .map(|(artifact_id, ids)| ArtifactRelationIndexV2 {
                artifact_id: *artifact_id,
                relation_ids: sorted_relation_ids(ids),
            })
            .collect();
        relations_by_src_artifact.sort_by_key(|entry| entry.artifact_id);
        let mut relations_by_dst: Vec<_> = relations_by_dst
            .iter()
            .map(|(entity_id, ids)| EntityRelationIndexV2 {
                entity_id: *entity_id,
                relation_ids: sorted_relation_ids(ids),
            })
            .collect();
        relations_by_dst.sort_by_key(|entry| entry.entity_id);

        ImportedCommitParserStateV2 {
            files,
            relations,
            relations_by_src,
            relations_by_src_artifact,
            relations_by_dst,
        }
    }

    fn from_checkpoint_v2(
        parser: ImportedCommitParserStateV2,
        linker: kin_index::IncrementalLinkerCheckpointV1,
    ) -> Result<Self> {
        let ImportedCommitParserStateV2 {
            files,
            relations,
            relations_by_src,
            relations_by_src_artifact,
            relations_by_dst,
        } = parser;
        let state = Self {
            files: collect_unique_pairs(files, "files")?,
            relations: collect_unique_pairs(relations, "relations")?,
            relations_by_src: collect_entity_relation_index(relations_by_src, "relations_by_src")?,
            relations_by_src_artifact: collect_artifact_relation_index(
                relations_by_src_artifact,
                "relations_by_src_artifact",
            )?,
            relations_by_dst: collect_entity_relation_index(relations_by_dst, "relations_by_dst")?,
            linker: kin_index::IncrementalLinker::from_checkpoint_v1(linker)
                .map_err(|error| anyhow!(error))?,
        };
        validate_state_indexes(&state)?;
        Ok(state)
    }
}

fn collect_unique_pairs<K, V>(entries: Vec<(K, V)>, field: &str) -> Result<HashMap<K, V>>
where
    K: std::hash::Hash + Eq,
{
    let mut output = HashMap::with_capacity(entries.len());
    for (key, value) in entries {
        if output.insert(key, value).is_some() {
            return Err(anyhow!("checkpoint contains duplicate key in {field}"));
        }
    }
    Ok(output)
}

fn relation_id_set(ids: Vec<RelationId>, field: &str) -> Result<HashSet<RelationId>> {
    let expected = ids.len();
    let output: HashSet<_> = ids.into_iter().collect();
    if output.len() != expected {
        return Err(anyhow!(
            "checkpoint contains duplicate relation id in {field}"
        ));
    }
    Ok(output)
}

fn collect_entity_relation_index(
    entries: Vec<EntityRelationIndexV2>,
    field: &str,
) -> Result<HashMap<EntityId, HashSet<RelationId>>> {
    collect_unique_pairs(
        entries
            .into_iter()
            .map(|entry| {
                relation_id_set(entry.relation_ids, field).map(|ids| (entry.entity_id, ids))
            })
            .collect::<Result<Vec<_>>>()?,
        field,
    )
}

fn collect_artifact_relation_index(
    entries: Vec<ArtifactRelationIndexV2>,
    field: &str,
) -> Result<HashMap<ArtifactId, HashSet<RelationId>>> {
    collect_unique_pairs(
        entries
            .into_iter()
            .map(|entry| {
                relation_id_set(entry.relation_ids, field).map(|ids| (entry.artifact_id, ids))
            })
            .collect::<Result<Vec<_>>>()?,
        field,
    )
}

fn validate_state_indexes(state: &ImportedCommitSemanticState) -> Result<()> {
    let mut by_src = HashMap::new();
    let mut by_src_artifact = HashMap::new();
    let mut by_dst = HashMap::new();
    for relation in state.relations.values() {
        insert_relation_indexes(&mut by_src, &mut by_src_artifact, &mut by_dst, relation);
    }
    if state.relations_by_src != by_src
        || state.relations_by_src_artifact != by_src_artifact
        || state.relations_by_dst != by_dst
    {
        return Err(anyhow!(
            "checkpoint relation indexes do not match persisted relation truth"
        ));
    }
    Ok(())
}

fn remaining_children_after_prefix(
    initial: &[usize],
    first_parent_index: &[Option<usize>],
    order: &[usize],
    processed_count: usize,
) -> Result<Vec<usize>> {
    let mut remaining = initial.to_vec();
    for index in order.iter().take(processed_count).copied() {
        if let Some(parent) = first_parent_index[index] {
            remaining[parent] = remaining[parent].checked_sub(1).ok_or_else(|| {
                anyhow!("checkpoint prefix underflowed deterministic remaining-child count")
            })?;
        }
    }
    Ok(remaining)
}

fn checkpoint_root(config: &HydrationCheckpointConfig) -> PathBuf {
    config
        .kin_root
        .join("checkpoints")
        .join("history-hydration")
}

fn segment_dir(config: &HydrationCheckpointConfig) -> PathBuf {
    checkpoint_root(config).join("objects").join("segments")
}

fn parser_frontier_dir(config: &HydrationCheckpointConfig) -> PathBuf {
    checkpoint_root(config)
        .join("objects")
        .join("parser-frontiers")
}

fn linker_frontier_dir(config: &HydrationCheckpointConfig) -> PathBuf {
    checkpoint_root(config)
        .join("objects")
        .join("linker-frontiers")
}

fn histories_dir(config: &HydrationCheckpointConfig) -> PathBuf {
    checkpoint_root(config).join("histories")
}

fn manifest_dir(config: &HydrationCheckpointConfig, history_digest: &str) -> PathBuf {
    histories_dir(config).join(history_digest).join("manifests")
}

fn manifest_path(
    config: &HydrationCheckpointConfig,
    history_digest: &str,
    processed_count: usize,
    prefix_digest: &str,
) -> PathBuf {
    manifest_dir(config, history_digest).join(format!(
        "{processed_count:020}-{prefix_digest}.manifest.json"
    ))
}

fn write_new_or_identical(
    path: &Path,
    bytes: &[u8],
    stats: &mut CheckpointIoStats,
) -> Result<bool> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    if path.exists() {
        let existing = fs::read(path)?;
        if existing != bytes {
            return Err(anyhow!(
                "REFUSED hydration checkpoint {}: deterministic destination already exists with different bytes",
                path.display()
            ));
        }
        stats.reused_units += 1;
        return Ok(false);
    }

    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("artifact");
    let temp = path.with_file_name(format!(".{file_name}.tmp.{}", std::process::id()));
    if temp.exists() {
        fs::remove_file(&temp)?;
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temp)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);

    match fs::hard_link(&temp, path) {
        Ok(()) => {
            // Persist the newly installed directory entry before removing the
            // temporary link. Without the directory fsync, a power loss could
            // leave a durable manifest whose referenced object link vanished.
            sync_parent_directory(path)?;
            fs::remove_file(&temp)?;
            sync_parent_directory(path)?;
            stats.written_units += 1;
            stats.written_bytes = stats.written_bytes.saturating_add(bytes.len() as u64);
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let existing = fs::read(path)?;
            fs::remove_file(&temp)?;
            sync_parent_directory(path)?;
            if existing != bytes {
                return Err(anyhow!(
                    "REFUSED hydration checkpoint {}: concurrent deterministic write produced different bytes",
                    path.display()
                ));
            }
            stats.reused_units += 1;
            Ok(false)
        }
        Err(error) => {
            let _ = fs::remove_file(&temp);
            Err(error).with_context(|| format!("install checkpoint artifact {}", path.display()))
        }
    }
}

fn sync_parent_directory(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("checkpoint path {} has no parent", path.display()))?;
    fs::File::open(parent)
        .and_then(|directory| directory.sync_all())
        .with_context(|| format!("sync checkpoint directory {}", parent.display()))
}

fn write_content_addressed(
    dir: &Path,
    bytes: &[u8],
    stats: &mut CheckpointIoStats,
) -> Result<String> {
    stats.record_serialized(bytes.len());
    let digest = sha256_hex(bytes);
    let path = dir.join(format!("{digest}.json"));
    write_new_or_identical(&path, bytes, stats)?;
    Ok(digest)
}

fn read_content_addressed(
    dir: &Path,
    digest: &str,
    stats: &mut CheckpointIoStats,
) -> Result<(PathBuf, Vec<u8>)> {
    let path = dir.join(format!("{digest}.json"));
    let bytes =
        fs::read(&path).with_context(|| format!("read checkpoint object {}", path.display()))?;
    stats.record_read(bytes.len());
    if sha256_hex(&bytes) != digest {
        return Err(anyhow!(
            "REFUSED hydration checkpoint {}: content-address digest mismatch",
            path.display()
        ));
    }
    Ok((path, bytes))
}

fn read_manifest(path: &Path, stats: &mut CheckpointIoStats) -> Result<ManifestPayloadV2> {
    let bytes = fs::read(path)?;
    stats.record_read(bytes.len());
    decode_envelope(MANIFEST_SCHEMA, path, &bytes)
}

fn list_files(dir: &Path, suffix: &str) -> Result<Vec<PathBuf>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut files = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_file() && entry.file_name().to_string_lossy().ends_with(suffix) {
            files.push(entry.path());
        }
    }
    files.sort();
    Ok(files)
}

fn all_manifest_paths(config: &HydrationCheckpointConfig) -> Result<Vec<PathBuf>> {
    let mut output = Vec::new();
    for history in list_directories(&histories_dir(config))? {
        output.extend(list_files(&history.join("manifests"), ".manifest.json")?);
    }
    output.sort();
    Ok(output)
}

fn list_directories(dir: &Path) -> Result<Vec<PathBuf>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let mut output = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            output.push(entry.path());
        }
    }
    output.sort();
    Ok(output)
}

fn validate_version(
    stored: &CheckpointVersionKeyV2,
    current: &CheckpointVersionKeyV2,
    path: &Path,
) -> Result<()> {
    if stored != current {
        return Err(anyhow!(
            "REFUSED hydration checkpoint {}: clean build/version key mismatch (stored {:?}, current {:?})",
            path.display(),
            stored,
            current
        ));
    }
    Ok(())
}

pub(super) struct HydrationCheckpointSession {
    config: HydrationCheckpointConfig,
    version_key: Option<CheckpointVersionKeyV2>,
    prefix_digests: Vec<String>,
    history_digest: String,
    last_boundary: usize,
    delta_tail_digest: Option<String>,
    io_stats: CheckpointIoStats,
    disabled_after_cap: bool,
}

impl HydrationCheckpointSession {
    pub(super) fn prepare(
        config: HydrationCheckpointConfig,
        imported: &mut [kin_git::ImportedChange],
        order: &[usize],
        first_parent_index: &[Option<usize>],
        initial_remaining_children: &[usize],
    ) -> Result<(Self, Option<HydrationResumeState>)> {
        let prefix_digests = history_prefix_digests(imported, order)?;
        let history_digest = prefix_digests
            .last()
            .cloned()
            .unwrap_or_else(|| sha256_hex(b"kin-empty-history-v2"));
        let version_key = match &config.build_policy {
            CheckpointBuildPolicy::Enabled(version) => Some(version.clone()),
            CheckpointBuildPolicy::Disabled(reason) => {
                eprintln!("  Hydration Checkpoint: {reason}");
                None
            }
        };
        let mut session = Self {
            config,
            version_key,
            prefix_digests,
            history_digest,
            last_boundary: 0,
            delta_tail_digest: None,
            io_stats: CheckpointIoStats::default(),
            disabled_after_cap: false,
        };
        let resume = if session.version_key.is_some() {
            session.load_nearest(
                imported,
                order,
                first_parent_index,
                initial_remaining_children,
            )?
        } else {
            None
        };
        if let Some(resume) = &resume {
            session.last_boundary = resume.processed_count;
        }
        Ok((session, resume))
    }

    pub(super) fn enabled(&self) -> bool {
        self.version_key.is_some() && !self.disabled_after_cap
    }

    pub(super) fn interval(&self) -> usize {
        self.config.interval
    }

    pub(super) fn io_stats(&self) -> CheckpointIoStats {
        self.io_stats
    }

    fn load_nearest(
        &mut self,
        imported: &mut [kin_git::ImportedChange],
        order: &[usize],
        first_parent_index: &[Option<usize>],
        initial_remaining_children: &[usize],
    ) -> Result<Option<HydrationResumeState>> {
        let version = self
            .version_key
            .as_ref()
            .expect("enabled session has version");
        let mut nearest: Option<(PathBuf, ManifestPayloadV2)> = None;
        for path in all_manifest_paths(&self.config)? {
            let manifest = read_manifest(&path, &mut self.io_stats)?;
            if manifest.format_version != FORMAT_VERSION {
                return Err(anyhow!(
                    "REFUSED hydration checkpoint {}: format version mismatch",
                    path.display()
                ));
            }
            if manifest.processed_count == 0 || manifest.processed_count > order.len() {
                continue;
            }
            if manifest.prefix_digest != self.prefix_digests[manifest.processed_count] {
                continue;
            }
            let expected_boundary = imported[order[manifest.processed_count - 1]].change.id;
            if manifest.boundary_change_id != expected_boundary {
                return Err(anyhow!(
                    "REFUSED hydration checkpoint {}: prefix matched but boundary id differed",
                    path.display()
                ));
            }
            validate_version(&manifest.version_key, version, &path)?;

            if let Some((existing_path, existing)) = &nearest {
                if existing.processed_count == manifest.processed_count
                    && (existing.delta_tail_digest != manifest.delta_tail_digest
                        || existing.parser_frontier_digest != manifest.parser_frontier_digest
                        || existing.linker_frontier_digest != manifest.linker_frontier_digest)
                {
                    return Err(anyhow!(
                        "REFUSED hydration checkpoints {} and {}: same prefix boundary points to different artifacts",
                        existing_path.display(),
                        path.display()
                    ));
                }
            }
            if nearest
                .as_ref()
                .map(|(_, existing)| manifest.processed_count > existing.processed_count)
                .unwrap_or(true)
            {
                nearest = Some((path, manifest));
            }
        }
        let Some((manifest_path, manifest)) = nearest else {
            return Ok(None);
        };

        self.restore_segments(&manifest, &manifest_path, imported, order)?;
        let remaining_children = remaining_children_after_prefix(
            initial_remaining_children,
            first_parent_index,
            order,
            manifest.processed_count,
        )?;
        let expected_frontier: HashSet<_> = order[..manifest.processed_count]
            .iter()
            .copied()
            .filter(|index| remaining_children[*index] > 0)
            .map(|index| imported[index].change.id)
            .collect();
        let frontier = self.restore_frontier(&manifest, &expected_frontier)?;
        self.delta_tail_digest = Some(manifest.delta_tail_digest.clone());
        eprintln!(
            "  Hydration Checkpoint: resumed {}/{} commits from {}",
            manifest.processed_count,
            imported.len(),
            manifest_path.display()
        );
        Ok(Some(HydrationResumeState {
            processed_count: manifest.processed_count,
            remaining_children,
            frontier,
        }))
    }

    fn restore_segments(
        &mut self,
        manifest: &ManifestPayloadV2,
        manifest_path: &Path,
        imported: &mut [kin_git::ImportedChange],
        order: &[usize],
    ) -> Result<()> {
        let version = self
            .version_key
            .as_ref()
            .expect("enabled session has version");
        let mut expected_end = manifest.processed_count;
        let mut digest = Some(manifest.delta_tail_digest.clone());
        while let Some(current_digest) = digest {
            let (path, bytes) = read_content_addressed(
                &segment_dir(&self.config),
                &current_digest,
                &mut self.io_stats,
            )?;
            let segment: DeltaSegmentPayloadV2 = decode_envelope(SEGMENT_SCHEMA, &path, &bytes)?;
            validate_version(&segment.version_key, version, &path)?;
            if segment.format_version != FORMAT_VERSION
                || segment.end_position != expected_end
                || segment.start_position >= segment.end_position
                || segment.completed.len() != segment.end_position - segment.start_position
                || segment.prefix_before != self.prefix_digests[segment.start_position]
                || segment.prefix_after != self.prefix_digests[segment.end_position]
            {
                return Err(anyhow!(
                    "REFUSED hydration checkpoint {}: invalid segment range/prefix chain",
                    path.display()
                ));
            }
            for (offset, completed) in segment.completed.iter().enumerate() {
                let position = segment.start_position + offset;
                if completed.change_id != imported[order[position]].change.id {
                    return Err(anyhow!(
                        "REFUSED hydration checkpoint {}: segment change id mismatch at position {}",
                        path.display(),
                        position
                    ));
                }
            }
            // Each segment owns a disjoint position range. Restore it now,
            // while walking backwards, instead of retaining a second O(history)
            // copy of every completed delta merely to replay chronologically.
            for (offset, completed) in segment.completed.into_iter().enumerate() {
                let change = &mut imported[order[segment.start_position + offset]].change;
                change.entity_deltas = completed.entity_deltas;
                change.relation_deltas = completed.relation_deltas;
            }
            expected_end = segment.start_position;
            digest = segment.previous_segment_digest;
        }
        if expected_end != 0 {
            return Err(anyhow!(
                "REFUSED hydration checkpoint {}: delta segment chain ended at {}, not genesis",
                manifest_path.display(),
                expected_end
            ));
        }
        Ok(())
    }

    fn restore_frontier(
        &mut self,
        manifest: &ManifestPayloadV2,
        expected_frontier: &HashSet<SemanticChangeId>,
    ) -> Result<HashMap<SemanticChangeId, ImportedCommitSemanticState>> {
        let version = self
            .version_key
            .as_ref()
            .expect("enabled session has version");
        let (parser_path, parser_bytes) = read_content_addressed(
            &parser_frontier_dir(&self.config),
            &manifest.parser_frontier_digest,
            &mut self.io_stats,
        )?;
        let parser_frontier: ParserFrontierPayloadV2 =
            decode_envelope(PARSER_FRONTIER_SCHEMA, &parser_path, &parser_bytes)?;
        validate_version(&parser_frontier.version_key, version, &parser_path)?;

        let (linker_path, linker_bytes) = read_content_addressed(
            &linker_frontier_dir(&self.config),
            &manifest.linker_frontier_digest,
            &mut self.io_stats,
        )?;
        let linker_frontier: LinkerFrontierPayloadV2 =
            decode_envelope(LINKER_FRONTIER_SCHEMA, &linker_path, &linker_bytes)?;
        validate_version(&linker_frontier.version_key, version, &linker_path)?;

        let parser_binding = (
            parser_frontier.format_version,
            parser_frontier.processed_count,
            parser_frontier.prefix_digest.as_str(),
            parser_frontier.boundary_change_id,
        );
        let linker_binding = (
            linker_frontier.format_version,
            linker_frontier.processed_count,
            linker_frontier.prefix_digest.as_str(),
            linker_frontier.boundary_change_id,
        );
        let expected_binding = (
            FORMAT_VERSION,
            manifest.processed_count,
            manifest.prefix_digest.as_str(),
            manifest.boundary_change_id,
        );
        if parser_binding != expected_binding || linker_binding != expected_binding {
            return Err(anyhow!(
                "REFUSED hydration checkpoint frontiers {} and {}: parser/linker state is not bound to its manifest boundary",
                parser_path.display(),
                linker_path.display()
            ));
        }

        let parser_ids: HashSet<_> = parser_frontier
            .states
            .iter()
            .map(|entry| entry.change_id)
            .collect();
        let linker_ids: HashSet<_> = linker_frontier
            .states
            .iter()
            .map(|entry| entry.change_id)
            .collect();
        if parser_ids.len() != parser_frontier.states.len()
            || linker_ids.len() != linker_frontier.states.len()
            || parser_ids != linker_ids
            || !parser_ids.contains(&manifest.boundary_change_id)
            || !expected_frontier.is_subset(&parser_ids)
        {
            return Err(anyhow!(
                "REFUSED hydration checkpoint frontiers {} and {}: incomplete, duplicate, or mismatched parser/linker states",
                parser_path.display(),
                linker_path.display()
            ));
        }

        let mut linkers: HashMap<_, _> = linker_frontier
            .states
            .into_iter()
            .map(|entry| (entry.change_id, entry.linker))
            .collect();
        let mut restored = HashMap::with_capacity(expected_frontier.len());
        for entry in parser_frontier.states {
            if !expected_frontier.contains(&entry.change_id) {
                continue;
            }
            let linker = linkers.remove(&entry.change_id).ok_or_else(|| {
                anyhow!(
                    "REFUSED hydration checkpoint {}: linker state {} disappeared during restore",
                    linker_path.display(),
                    entry.change_id
                )
            })?;
            let state = ImportedCommitSemanticState::from_checkpoint_v2(entry.state, linker)
                .with_context(|| format!("restore frontier state {}", entry.change_id))?;
            restored.insert(entry.change_id, state);
        }
        Ok(restored)
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn persist_boundary(
        &mut self,
        imported: &[kin_git::ImportedChange],
        order: &[usize],
        processed_count: usize,
        boundary: HydrationCheckpointBoundary,
        frontier: &HashMap<SemanticChangeId, ImportedCommitSemanticState>,
        detached_boundary_state: Option<&ImportedCommitSemanticState>,
    ) -> Result<()> {
        if !self.enabled() {
            return Ok(());
        }
        let version = self
            .version_key
            .clone()
            .expect("enabled session has version");
        if processed_count <= self.last_boundary {
            return Err(anyhow!(
                "checkpoint boundary {} did not advance past {}",
                processed_count,
                self.last_boundary
            ));
        }
        if processed_count - self.last_boundary > self.config.interval {
            return Err(anyhow!(
                "checkpoint delta segment {}..{} exceeds configured interval {}",
                self.last_boundary,
                processed_count,
                self.config.interval
            ));
        }

        let completed = order[self.last_boundary..processed_count]
            .iter()
            .map(|index| CompletedSemanticDeltasV2 {
                change_id: imported[*index].change.id,
                entity_deltas: imported[*index].change.entity_deltas.clone(),
                relation_deltas: imported[*index].change.relation_deltas.clone(),
            })
            .collect();
        let segment = DeltaSegmentPayloadV2 {
            format_version: FORMAT_VERSION,
            version_key: version.clone(),
            start_position: self.last_boundary,
            end_position: processed_count,
            prefix_before: self.prefix_digests[self.last_boundary].clone(),
            prefix_after: self.prefix_digests[processed_count].clone(),
            previous_segment_digest: self.delta_tail_digest.clone(),
            completed,
        };
        let segment_bytes = encode_envelope(SEGMENT_SCHEMA, &segment)?;
        let segment_digest = write_content_addressed(
            &segment_dir(&self.config),
            &segment_bytes,
            &mut self.io_stats,
        )?;

        let boundary_change_id = imported[order[processed_count - 1]].change.id;
        let mut parser_states: Vec<_> = frontier
            .iter()
            .map(|(change_id, state)| ParserFrontierStateV2 {
                change_id: *change_id,
                state: state.to_parser_checkpoint_v2(),
            })
            .collect();
        let mut linker_states: Vec<_> = frontier
            .iter()
            .map(|(change_id, state)| LinkerFrontierStateV2 {
                change_id: *change_id,
                linker: state.linker.to_checkpoint_v1(),
            })
            .collect();
        if !frontier.contains_key(&boundary_change_id) {
            let state = detached_boundary_state.ok_or_else(|| {
                anyhow!(
                    "checkpoint boundary state {} was not retained",
                    boundary_change_id
                )
            })?;
            parser_states.push(ParserFrontierStateV2 {
                change_id: boundary_change_id,
                state: state.to_parser_checkpoint_v2(),
            });
            linker_states.push(LinkerFrontierStateV2 {
                change_id: boundary_change_id,
                linker: state.linker.to_checkpoint_v1(),
            });
        }
        parser_states.sort_by(|a, b| a.change_id.to_string().cmp(&b.change_id.to_string()));
        linker_states.sort_by(|a, b| a.change_id.to_string().cmp(&b.change_id.to_string()));
        let parser_frontier_payload = ParserFrontierPayloadV2 {
            format_version: FORMAT_VERSION,
            version_key: version.clone(),
            processed_count,
            prefix_digest: self.prefix_digests[processed_count].clone(),
            boundary_change_id,
            states: parser_states,
        };
        let parser_frontier_bytes =
            encode_envelope(PARSER_FRONTIER_SCHEMA, &parser_frontier_payload)?;
        let parser_frontier_digest = write_content_addressed(
            &parser_frontier_dir(&self.config),
            &parser_frontier_bytes,
            &mut self.io_stats,
        )?;

        let linker_frontier_payload = LinkerFrontierPayloadV2 {
            format_version: FORMAT_VERSION,
            version_key: version.clone(),
            processed_count,
            prefix_digest: self.prefix_digests[processed_count].clone(),
            boundary_change_id,
            states: linker_states,
        };
        let linker_frontier_bytes =
            encode_envelope(LINKER_FRONTIER_SCHEMA, &linker_frontier_payload)?;
        let linker_frontier_digest = write_content_addressed(
            &linker_frontier_dir(&self.config),
            &linker_frontier_bytes,
            &mut self.io_stats,
        )?;

        let manifest = ManifestPayloadV2 {
            format_version: FORMAT_VERSION,
            version_key: version,
            history_digest: self.history_digest.clone(),
            processed_count,
            prefix_digest: self.prefix_digests[processed_count].clone(),
            boundary_change_id,
            boundary,
            delta_tail_digest: segment_digest.clone(),
            parser_frontier_digest,
            linker_frontier_digest,
        };
        let manifest_bytes = encode_envelope(MANIFEST_SCHEMA, &manifest)?;
        self.io_stats.record_serialized(manifest_bytes.len());
        let manifest_path = manifest_path(
            &self.config,
            &self.history_digest,
            processed_count,
            &self.prefix_digests[processed_count],
        );
        write_new_or_identical(&manifest_path, &manifest_bytes, &mut self.io_stats)?;

        self.last_boundary = processed_count;
        self.delta_tail_digest = Some(segment_digest);
        let retention = enforce_retention(
            &self.config,
            &self.history_digest,
            processed_count == imported.len(),
            &mut self.io_stats,
        )?;
        self.io_stats.retained_bytes = retention.total_bytes;
        if !retention.current_history_retained {
            self.disabled_after_cap = true;
            eprintln!(
                "  Hydration Checkpoint: discarded current history because retained bytes exceeded cap {}",
                self.config.byte_cap
            );
        } else {
            eprintln!(
                "  Hydration Checkpoint: boundary {}/{} retained={} bytes cap={} segment={}B parser_frontier={}B linker_frontier={}B max_unit={}B",
                processed_count,
                imported.len(),
                retention.total_bytes,
                self.config.byte_cap,
                segment_bytes.len(),
                parser_frontier_bytes.len(),
                linker_frontier_bytes.len(),
                self.io_stats.max_serialized_unit_bytes
            );
        }
        Ok(())
    }
}

#[derive(Debug)]
struct RetentionOutcome {
    total_bytes: u64,
    current_history_retained: bool,
}

fn evenly_spaced_manifest_positions(
    manifests: &[(PathBuf, ManifestPayloadV2)],
    limit: usize,
) -> BTreeSet<usize> {
    if manifests.len() <= limit {
        return (0..manifests.len()).collect();
    }
    let mut selected = BTreeSet::new();
    let base_idx = manifests
        .iter()
        .position(|(_, manifest)| manifest.boundary == HydrationCheckpointBoundary::BaseLink)
        .unwrap_or(0);
    let latest_idx = manifests.len() - 1;
    selected.insert(base_idx);
    selected.insert(latest_idx);
    let slots = limit.saturating_sub(selected.len());
    for slot in 1..=slots {
        let target = manifests[base_idx].1.processed_count
            + (manifests[latest_idx].1.processed_count - manifests[base_idx].1.processed_count)
                * slot
                / (slots + 1);
        let candidate = manifests
            .iter()
            .enumerate()
            .filter(|(idx, _)| !selected.contains(idx))
            .min_by_key(|(_, (_, manifest))| {
                (
                    manifest.processed_count.abs_diff(target),
                    manifest.processed_count,
                )
            })
            .map(|(idx, _)| idx);
        if let Some(candidate) = candidate {
            selected.insert(candidate);
        }
    }
    selected
}

fn prune_manifests_per_history(
    config: &HydrationCheckpointConfig,
    stats: &mut CheckpointIoStats,
) -> Result<()> {
    for history in list_directories(&histories_dir(config))? {
        let mut manifests = Vec::new();
        for path in list_files(&history.join("manifests"), ".manifest.json")? {
            manifests.push((path.clone(), read_manifest(&path, stats)?));
        }
        manifests.sort_by_key(|(_, manifest)| manifest.processed_count);
        let keep = evenly_spaced_manifest_positions(&manifests, config.manifests_per_history);
        for (idx, (path, _)) in manifests.into_iter().enumerate() {
            if !keep.contains(&idx) {
                fs::remove_file(path)?;
            }
        }
    }
    Ok(())
}

fn prune_history_identities(
    config: &HydrationCheckpointConfig,
    current_history_digest: &str,
    stats: &mut CheckpointIoStats,
) -> Result<bool> {
    let histories = list_directories(&histories_dir(config))?;
    if histories.len() <= config.history_limit {
        return Ok(false);
    }
    let mut ranked = Vec::new();
    for history in histories {
        let digest = history
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default()
            .to_string();
        let mut max_boundary = 0usize;
        for path in list_files(&history.join("manifests"), ".manifest.json")? {
            max_boundary = max_boundary.max(read_manifest(&path, stats)?.processed_count);
        }
        ranked.push((history, digest, max_boundary));
    }
    ranked.sort_by(|a, b| {
        let a_current = a.1 == current_history_digest;
        let b_current = b.1 == current_history_digest;
        b_current
            .cmp(&a_current)
            .then_with(|| b.2.cmp(&a.2))
            .then_with(|| a.1.cmp(&b.1))
    });
    let mut removed = false;
    for (path, _, _) in ranked.into_iter().skip(config.history_limit) {
        fs::remove_dir_all(path)?;
        removed = true;
    }
    Ok(removed)
}

fn referenced_frontiers(
    config: &HydrationCheckpointConfig,
    stats: &mut CheckpointIoStats,
) -> Result<(BTreeSet<String>, BTreeSet<String>)> {
    let mut parser_frontiers = BTreeSet::new();
    let mut linker_frontiers = BTreeSet::new();
    for path in all_manifest_paths(config)? {
        let manifest = read_manifest(&path, stats)?;
        parser_frontiers.insert(manifest.parser_frontier_digest);
        linker_frontiers.insert(manifest.linker_frontier_digest);
    }
    Ok((parser_frontiers, linker_frontiers))
}

fn referenced_segments(
    config: &HydrationCheckpointConfig,
    stats: &mut CheckpointIoStats,
) -> Result<BTreeSet<String>> {
    let mut segments = BTreeSet::new();
    let mut tails = Vec::new();
    for path in all_manifest_paths(config)? {
        tails.push(read_manifest(&path, stats)?.delta_tail_digest);
    }
    tails.sort();
    tails.dedup();
    for mut digest in tails {
        loop {
            if !segments.insert(digest.clone()) {
                break;
            }
            let (path, bytes) = read_content_addressed(&segment_dir(config), &digest, stats)?;
            let segment: DeltaSegmentPayloadV2 = decode_envelope(SEGMENT_SCHEMA, &path, &bytes)?;
            let Some(previous) = segment.previous_segment_digest else {
                break;
            };
            digest = previous;
        }
    }
    Ok(segments)
}

fn garbage_collect_frontiers(
    config: &HydrationCheckpointConfig,
    stats: &mut CheckpointIoStats,
) -> Result<()> {
    let (parser_frontiers, linker_frontiers) = referenced_frontiers(config, stats)?;
    for path in list_files(&parser_frontier_dir(config), ".json")? {
        let digest = path
            .file_stem()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        if !parser_frontiers.contains(digest) {
            fs::remove_file(path)?;
        }
    }
    for path in list_files(&linker_frontier_dir(config), ".json")? {
        let digest = path
            .file_stem()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        if !linker_frontiers.contains(digest) {
            fs::remove_file(path)?;
        }
    }
    Ok(())
}

/// Segment reachability requires walking each immutable backwards chain. This
/// is intentionally not run at every periodic boundary: doing so would decode
/// the growing completed prefix K times for K checkpoints. New boundaries
/// extend the live tail, so segments cannot become unreachable until a history
/// identity is removed, a run completes, or the byte cap requires compaction.
fn garbage_collect_segments(
    config: &HydrationCheckpointConfig,
    stats: &mut CheckpointIoStats,
) -> Result<()> {
    let segments = referenced_segments(config, stats)?;
    for path in list_files(&segment_dir(config), ".json")? {
        let digest = path
            .file_stem()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        if !segments.contains(digest) {
            fs::remove_file(path)?;
        }
    }
    Ok(())
}

fn retained_bytes(config: &HydrationCheckpointConfig) -> Result<u64> {
    fn sum_files(dir: &Path) -> Result<u64> {
        if !dir.exists() {
            return Ok(0);
        }
        let mut total = 0u64;
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                total = total.saturating_add(sum_files(&entry.path())?);
            } else if entry.file_type()?.is_file() {
                total = total.saturating_add(entry.metadata()?.len());
            }
        }
        Ok(total)
    }
    sum_files(&checkpoint_root(config))
}

fn enforce_retention(
    config: &HydrationCheckpointConfig,
    current_history_digest: &str,
    final_boundary: bool,
    stats: &mut CheckpointIoStats,
) -> Result<RetentionOutcome> {
    prune_manifests_per_history(config, stats)?;
    let removed_history = prune_history_identities(config, current_history_digest, stats)?;
    garbage_collect_frontiers(config, stats)?;
    if final_boundary || removed_history {
        garbage_collect_segments(config, stats)?;
    }
    let mut total = retained_bytes(config)?;

    if total > config.byte_cap {
        // An interrupted prior write may have left an unreferenced segment.
        // Collect those before discarding any still-usable history.
        garbage_collect_segments(config, stats)?;
        total = retained_bytes(config)?;
    }
    if total > config.byte_cap {
        let mut histories = list_directories(&histories_dir(config))?;
        histories.sort_by(|a, b| {
            let a_current = a.file_name().and_then(|n| n.to_str()) == Some(current_history_digest);
            let b_current = b.file_name().and_then(|n| n.to_str()) == Some(current_history_digest);
            a_current.cmp(&b_current).then_with(|| a.cmp(b))
        });
        for history in histories {
            if total <= config.byte_cap {
                break;
            }
            fs::remove_dir_all(&history)?;
            garbage_collect_frontiers(config, stats)?;
            garbage_collect_segments(config, stats)?;
            total = retained_bytes(config)?;
        }
    }
    let current_retained = manifest_dir(config, current_history_digest).exists();
    Ok(RetentionOutcome {
        total_bytes: total,
        current_history_retained: current_retained,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evenly_spaced_retention_keeps_base_latest_and_interior_quantiles() {
        let version = CheckpointVersionKeyV2::for_clean_sha("abc123");
        let manifests: Vec<_> = (1..=10)
            .map(|position| {
                (
                    PathBuf::from(format!("{position}.json")),
                    ManifestPayloadV2 {
                        format_version: FORMAT_VERSION,
                        version_key: version.clone(),
                        history_digest: "history".into(),
                        processed_count: position * 1_000,
                        prefix_digest: format!("prefix-{position}"),
                        boundary_change_id: SemanticChangeId::from_hash(
                            kin_model::Hash256::from_bytes([position as u8; 32]),
                        ),
                        boundary: if position == 1 {
                            HydrationCheckpointBoundary::BaseLink
                        } else if position == 10 {
                            HydrationCheckpointBoundary::Final
                        } else {
                            HydrationCheckpointBoundary::Periodic
                        },
                        delta_tail_digest: format!("segment-{position}"),
                        parser_frontier_digest: format!("parser-frontier-{position}"),
                        linker_frontier_digest: format!("linker-frontier-{position}"),
                    },
                )
            })
            .collect();
        let kept = evenly_spaced_manifest_positions(&manifests, 4);
        let positions: Vec<_> = kept
            .into_iter()
            .map(|idx| manifests[idx].1.processed_count)
            .collect();
        assert_eq!(positions, vec![1_000, 4_000, 7_000, 10_000]);
    }

    #[test]
    fn deterministic_destination_refuses_different_existing_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("boundary.json");
        let mut stats = CheckpointIoStats::default();
        assert!(write_new_or_identical(&path, b"first", &mut stats).unwrap());
        assert!(!write_new_or_identical(&path, b"first", &mut stats).unwrap());
        let error = write_new_or_identical(&path, b"different", &mut stats).unwrap_err();
        assert!(error.to_string().contains("different bytes"));
    }

    #[test]
    fn missing_imported_state_field_is_never_defaulted() {
        let mut value =
            serde_json::to_value(ImportedCommitSemanticState::default().to_parser_checkpoint_v2())
                .unwrap();
        value.as_object_mut().unwrap().remove("relations_by_dst");
        assert!(serde_json::from_value::<ImportedCommitParserStateV2>(value).is_err());
    }

    #[test]
    fn checkpoint_build_policy_refuses_dirty_or_unknown_source_identity() {
        assert!(matches!(
            checkpoint_build_policy("abc123def456", false),
            CheckpointBuildPolicy::Enabled(_)
        ));
        assert!(matches!(
            checkpoint_build_policy("abc123def456", true),
            CheckpointBuildPolicy::Disabled(_)
        ));
        assert!(matches!(
            checkpoint_build_policy("unknown", false),
            CheckpointBuildPolicy::Disabled(_)
        ));
    }
}
