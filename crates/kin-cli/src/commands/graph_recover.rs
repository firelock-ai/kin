// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Explicit, evidence-bound recovery for pre-authority local KinDB snapshots.
//!
//! This command is intentionally separate from ordinary graph opens. It never
//! inspects workspace source files and never infers repository identity. Every
//! graph byte that participates in recovery is named by an operator-supplied
//! SHA-256, and the reconstructed graph must match an operator-supplied Merkle
//! root before KinDB's locked CAS promotion is allowed to run.

use anyhow::{anyhow, bail, Context, Result};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

const RECEIPT_VERSION: u32 = 2;
const AUTHORITY_VERSION: u32 = 3;

#[derive(Debug, Clone)]
pub struct RecoverAuthorityOptions {
    pub repo: PathBuf,
    pub expected_head_generation: u64,
    pub expected_snapshot_sha256: String,
    pub expected_root: String,
    pub expected_deltas: Vec<String>,
    pub repo_id: String,
    pub confirm_quiesced: bool,
    pub json: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum RecoveryMode {
    SnapshotPromotion,
    LegacyJournalRebuild,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ArtifactEvidence {
    path: String,
    sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct DeltaEvidence {
    generation: u64,
    path: String,
    sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct RecoveryInputEvidence {
    repo_root: String,
    snapshot: ArtifactEvidence,
    deltas: Vec<DeltaEvidence>,
    expected_head_generation: u64,
    expected_root: String,
    repo_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct GraphStateEvidence {
    generation: u64,
    root: String,
    entity_count: usize,
    relation_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct PreparedRecoveryReceipt {
    version: u32,
    mode: RecoveryMode,
    input: RecoveryInputEvidence,
    manifest_preexisting: bool,
    base_generation: u64,
    base_root: String,
    before: GraphStateEvidence,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct ManifestEvidence {
    path: String,
    repo_id: String,
    sha256: String,
    created_by_recovery: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct RecoveredArtifacts {
    authority: ArtifactEvidence,
    authoritative_snapshot: ArtifactEvidence,
    compatibility_snapshot: ArtifactEvidence,
    projection_generation: ArtifactEvidence,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct CommittedRecoveryReceipt {
    version: u32,
    prepared_receipt_sha256: String,
    after: GraphStateEvidence,
    artifacts: RecoveredArtifacts,
    manifest: ManifestEvidence,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum RecoveryStatus {
    Recovered,
    AlreadyRecovered,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct RecoveryReceipts {
    prepared: ArtifactEvidence,
    committed: ArtifactEvidence,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct RecoveryReport {
    status: RecoveryStatus,
    mode: RecoveryMode,
    repo_root: String,
    snapshot_path: String,
    before: GraphStateEvidence,
    after: GraphStateEvidence,
    manifest: ManifestEvidence,
    input_artifacts: Vec<ArtifactEvidence>,
    recovered_artifacts: RecoveredArtifacts,
    receipts: RecoveryReceipts,
    workspace_source_files_read: bool,
}

#[derive(Debug, Clone, Deserialize)]
struct LocalAuthorityView {
    version: u32,
    snapshot_generation: u64,
    head_generation: u64,
    snapshot_file: String,
    snapshot_root_hash: String,
    snapshot_sha256: String,
    #[serde(default)]
    acknowledged_deltas: Vec<AuthorityDeltaView>,
    #[serde(default)]
    retired_deltas: Vec<AuthorityDeltaView>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
struct AuthorityDeltaView {
    generation: u64,
    sha256: String,
}

struct RecoveryCandidate {
    graph: kin_db::InMemoryGraph,
    mode: RecoveryMode,
    base_generation: u64,
    base_root: String,
    before: GraphStateEvidence,
}

struct RepoPaths {
    root: PathBuf,
    snapshot: PathBuf,
    authority: PathBuf,
    delta_dir: PathBuf,
    projection_generation: PathBuf,
    manifest: PathBuf,
    prepared_receipt: PathBuf,
    committed_receipt: PathBuf,
    recovery_lock: PathBuf,
}

struct ManifestPlan {
    repo_id: String,
    existing: bool,
}

/// `kin graph recover-authority` entry point.
pub async fn recover_authority(options: RecoverAuthorityOptions) -> Result<()> {
    let report = recover_authority_inner(&options)?;
    if options.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!(
            "Graph authority {:?}: generation {} -> {}, root {}",
            report.status, report.before.generation, report.after.generation, report.after.root
        );
        println!("Repository: {}", report.repo_root);
        println!(
            "Manifest: {} ({})",
            report.manifest.path, report.manifest.repo_id
        );
        println!(
            "Authority: {} ({})",
            report.recovered_artifacts.authority.path, report.recovered_artifacts.authority.sha256
        );
    }
    Ok(())
}

fn recover_authority_inner(options: &RecoverAuthorityOptions) -> Result<RecoveryReport> {
    if !options.confirm_quiesced {
        bail!(
            "graph authority recovery refused: --confirm-quiesced is required after stopping every daemon, VFS, and legacy graph writer for this repository"
        );
    }

    let paths = resolve_repo_paths(&options.repo)?;
    let _recovery_lock = acquire_recovery_lock(&paths.recovery_lock)?;
    // Fast fail before durable receipts. The KinDB recovery API independently
    // reacquires this lock and binds all evidence under it before mutation.
    verify_kindb_unlocked(&paths.snapshot)?;
    let expected_root = parse_hash("expected graph Merkle root", &options.expected_root)?;
    let expected_root_hex = hex::encode(expected_root);
    let expected_snapshot_sha256 = normalize_hash(
        "expected snapshot SHA-256",
        &options.expected_snapshot_sha256,
    )?;
    let expected_delta_hashes = parse_expected_deltas(&options.expected_deltas)?;
    let manifest_plan = inspect_manifest_plan(&paths.manifest, &options.repo_id)?;

    let input = RecoveryInputEvidence {
        repo_root: display_path(&paths.root),
        snapshot: ArtifactEvidence {
            path: display_path(&paths.snapshot),
            sha256: expected_snapshot_sha256,
        },
        deltas: expected_delta_hashes
            .iter()
            .map(|(generation, sha256)| DeltaEvidence {
                generation: *generation,
                path: display_path(&delta_path(&paths.delta_dir, *generation)),
                sha256: sha256.clone(),
            })
            .collect(),
        expected_head_generation: options.expected_head_generation,
        expected_root: expected_root_hex,
        repo_id: manifest_plan.repo_id.clone(),
    };

    let prepared_on_disk = read_optional_json::<PreparedRecoveryReceipt>(
        &paths.prepared_receipt,
        "prepared recovery receipt",
    )?;
    if let Some(prepared) = prepared_on_disk.as_ref() {
        if prepared.version != RECEIPT_VERSION {
            bail!(
                "unsupported prepared recovery receipt version {} in {}",
                prepared.version,
                paths.prepared_receipt.display()
            );
        }
        if prepared.input != input {
            bail!(
                "recovery evidence does not match the durable prepared receipt {}; refusing an ambiguous retry",
                paths.prepared_receipt.display()
            );
        }
    }

    let authority_exists = inspect_optional_regular_file(&paths.authority, "graph authority")?;
    let committed_on_disk = read_optional_json::<CommittedRecoveryReceipt>(
        &paths.committed_receipt,
        "committed recovery receipt",
    )?;

    if let Some(committed) = committed_on_disk.as_ref() {
        let prepared = prepared_on_disk.as_ref().ok_or_else(|| {
            anyhow!(
                "committed recovery receipt {} exists without its prepared receipt",
                paths.committed_receipt.display()
            )
        })?;
        if !authority_exists {
            bail!(
                "committed recovery receipt {} exists but graph authority {} is missing",
                paths.committed_receipt.display(),
                paths.authority.display()
            );
        }
        validate_committed_receipt(prepared, committed, &paths)?;
        return build_report(
            RecoveryStatus::AlreadyRecovered,
            prepared,
            committed,
            &paths,
        );
    }

    if authority_exists {
        let prepared = prepared_on_disk.as_ref().ok_or_else(|| {
            anyhow!(
                "graph authority {} already exists without a matching prepared recovery receipt; refusing to infer prior recovery evidence",
                paths.authority.display()
            )
        })?;
        resume_committed_authority(prepared, &paths)?;
        let committed = finalize_committed_state(prepared, &paths)?;
        create_json_once(
            &paths.committed_receipt,
            &committed,
            "committed recovery receipt",
        )?;
        return build_report(
            RecoveryStatus::AlreadyRecovered,
            prepared,
            &committed,
            &paths,
        );
    }

    let candidate = load_candidate(&paths, &input, expected_root)?;
    let prepared = PreparedRecoveryReceipt {
        version: RECEIPT_VERSION,
        mode: candidate.mode,
        input,
        manifest_preexisting: prepared_on_disk
            .as_ref()
            .map_or(manifest_plan.existing, |prepared| {
                prepared.manifest_preexisting
            }),
        base_generation: candidate.base_generation,
        base_root: candidate.base_root,
        before: candidate.before,
    };

    if let Some(existing) = prepared_on_disk.as_ref() {
        if existing != &prepared {
            bail!(
                "reconstructed graph state does not match prepared recovery receipt {}; no graph bytes were changed",
                paths.prepared_receipt.display()
            );
        }
    } else {
        create_json_once(
            &paths.prepared_receipt,
            &prepared,
            "prepared recovery receipt",
        )?;
    }

    let kindb_evidence = kindb_recovery_evidence(&prepared.input)?;
    let (committed_root, committed_generation) =
        kin_db::SnapshotManager::recover_local_authority_with_evidence(
            &paths.snapshot,
            &candidate.graph,
            &kindb_evidence,
        )
        .with_context(|| {
            format!(
                "KinDB evidence-bound authority recovery failed for {}",
                paths.snapshot.display()
            )
        })?;

    let expected_committed_generation = options
        .expected_head_generation
        .checked_add(1)
        .ok_or_else(|| anyhow!("expected head generation is exhausted"))?;
    if committed_generation != expected_committed_generation {
        bail!(
            "KinDB committed unexpected recovery generation {committed_generation}; expected {expected_committed_generation}"
        );
    }
    if committed_root != expected_root {
        bail!(
            "KinDB committed unexpected recovery root {}; expected {}",
            hex::encode(committed_root),
            prepared.input.expected_root
        );
    }

    let committed = finalize_committed_state(&prepared, &paths)?;
    create_json_once(
        &paths.committed_receipt,
        &committed,
        "committed recovery receipt",
    )?;
    build_report(RecoveryStatus::Recovered, &prepared, &committed, &paths)
}

fn resolve_repo_paths(repo: &Path) -> Result<RepoPaths> {
    if !repo.is_absolute() {
        bail!("--repo must be an absolute path; got {}", repo.display());
    }
    require_directory(repo, "repository root")?;
    let root = fs::canonicalize(repo)
        .with_context(|| format!("failed to canonicalize repository root {}", repo.display()))?;
    let kin_dir = root.join(".kin");
    require_directory(&kin_dir, "Kin metadata directory")?;
    let kindb_dir = kin_dir.join("kindb");
    require_directory(&kindb_dir, "KinDB directory")?;
    let snapshot = kindb_dir.join("graph.kndb");
    require_regular_file(&snapshot, "legacy graph snapshot")?;
    let delta_dir = append_suffix(&snapshot, ".deltas");
    Ok(RepoPaths {
        root,
        authority: append_suffix(&snapshot, ".authority.json"),
        projection_generation: append_suffix(&snapshot, ".projection-generation"),
        manifest: kin_dir.join("manifest.json"),
        prepared_receipt: append_suffix(&snapshot, ".recovery.prepared.json"),
        committed_receipt: append_suffix(&snapshot, ".recovery.committed.json"),
        recovery_lock: append_suffix(&snapshot, ".recovery.lock"),
        snapshot,
        delta_dir,
    })
}

fn load_candidate(
    paths: &RepoPaths,
    input: &RecoveryInputEvidence,
    expected_root: [u8; 32],
) -> Result<RecoveryCandidate> {
    let snapshot_bytes = read_regular(&paths.snapshot, "legacy graph snapshot")?;
    let snapshot_sha256 = sha256_bytes(&snapshot_bytes);
    if snapshot_sha256 != input.snapshot.sha256 {
        bail!(
            "legacy snapshot SHA-256 mismatch for {}: expected {}, found {}",
            paths.snapshot.display(),
            input.snapshot.sha256,
            snapshot_sha256
        );
    }

    let mut snapshot = kin_db::GraphSnapshot::from_bytes(&snapshot_bytes)
        .with_context(|| format!("failed to decode {}", paths.snapshot.display()))?;
    let base_root = hex::encode(kin_db::compute_graph_root_hash(&snapshot));
    let actual_deltas = read_delta_artifacts(paths)?;
    if actual_deltas != input.deltas {
        bail!(
            "legacy delta artifact set does not match the exact expected generations and SHA-256 values"
        );
    }
    let legacy_generation = read_generation_marker(paths)?;
    if legacy_generation != input.expected_head_generation {
        bail!(
            "legacy generation marker mismatch: expected {}, found {legacy_generation}",
            input.expected_head_generation
        );
    }

    let mode = if actual_deltas.is_empty() {
        RecoveryMode::SnapshotPromotion
    } else {
        RecoveryMode::LegacyJournalRebuild
    };
    let mut base_generation = input.expected_head_generation;
    let mut previous_generation = None;
    for evidence in &actual_deltas {
        let bytes = read_regular(Path::new(&evidence.path), "legacy graph delta")?;
        let delta = kin_db::GraphSnapshotDelta::from_bytes(&bytes)
            .with_context(|| format!("failed to decode legacy delta {}", evidence.path))?;
        let declared_generation = delta.base_generation.checked_add(1).ok_or_else(|| {
            anyhow!(
                "legacy delta generation exhausted at {}",
                delta.base_generation
            )
        })?;
        if declared_generation != evidence.generation {
            bail!(
                "legacy delta {} declares base generation {}, expected {}",
                evidence.path,
                delta.base_generation,
                evidence.generation - 1
            );
        }
        if let Some(previous) = previous_generation {
            if evidence.generation != previous + 1 {
                bail!(
                    "legacy delta chain is incomplete: generation {} follows {previous}",
                    evidence.generation
                );
            }
        } else {
            base_generation = delta.base_generation;
        }
        kin_db::apply_graph_delta(&mut snapshot, &delta);
        previous_generation = Some(evidence.generation);
    }
    if let Some(last) = previous_generation {
        if last != input.expected_head_generation {
            bail!(
                "legacy delta chain ends at generation {last}, expected head is {}",
                input.expected_head_generation
            );
        }
    }

    let recovered_root = kin_db::compute_graph_root_hash(&snapshot);
    if recovered_root != expected_root {
        bail!(
            "recovered graph Merkle root mismatch: expected {}, found {}",
            input.expected_root,
            hex::encode(recovered_root)
        );
    }
    // Build the actual graph KinDB will serialize. This applies KinDB's
    // graph-native schema migrations (if any); the expected root must bind the
    // post-migration authority too, not merely the decoded legacy frame.
    let graph = kin_db::InMemoryGraph::from_snapshot(snapshot);
    let graph_root = graph.recompute_root_hash();
    if graph_root != expected_root {
        bail!(
            "post-migration graph Merkle root mismatch: expected {}, found {}",
            input.expected_root,
            hex::encode(graph_root)
        );
    }
    let before = GraphStateEvidence {
        generation: input.expected_head_generation,
        root: input.expected_root.clone(),
        entity_count: graph.entity_count(),
        relation_count: graph.relation_count(),
    };
    Ok(RecoveryCandidate {
        graph,
        mode,
        base_generation,
        base_root,
        before,
    })
}

fn finalize_committed_state(
    prepared: &PreparedRecoveryReceipt,
    paths: &RepoPaths,
) -> Result<CommittedRecoveryReceipt> {
    let (after, artifacts) = inspect_recovered_graph(prepared, paths)?;
    let manifest_plan = ManifestPlan {
        repo_id: prepared.input.repo_id.clone(),
        existing: prepared.manifest_preexisting,
    };
    let manifest = ensure_manifest_after_graph(&manifest_plan, &paths.manifest)?;
    let prepared_bytes = read_regular(&paths.prepared_receipt, "prepared recovery receipt")?;
    Ok(CommittedRecoveryReceipt {
        version: RECEIPT_VERSION,
        prepared_receipt_sha256: sha256_bytes(&prepared_bytes),
        after,
        artifacts,
        manifest,
    })
}

/// Finish KinDB's durable evidence-bound retry after an authority commit whose
/// downstream compatibility projection or retired-journal cleanup was
/// interrupted.
///
/// The authoritative versioned snapshot is the only graph input here. Its
/// digest, generation, root, journal identities, and graph counts must all
/// match the durable prepared receipt before KinDB is called. KinDB validates
/// the original snapshot/journal identities under `graph.lock` and resumes
/// projection directly from authoritative bytes, without requiring a fresh
/// hash map to serialize byte-identically to the prior process.
fn resume_committed_authority(prepared: &PreparedRecoveryReceipt, paths: &RepoPaths) -> Result<()> {
    let expected_generation = prepared
        .input
        .expected_head_generation
        .checked_add(1)
        .ok_or_else(|| anyhow!("expected head generation is exhausted"))?;
    let expected_after = GraphStateEvidence {
        generation: expected_generation,
        root: prepared.input.expected_root.clone(),
        entity_count: prepared.before.entity_count,
        relation_count: prepared.before.relation_count,
    };

    let authority_bytes = read_regular(&paths.authority, "graph authority")?;
    let authority: LocalAuthorityView = serde_json::from_slice(&authority_bytes)
        .with_context(|| format!("invalid graph authority {}", paths.authority.display()))?;
    validate_authority_view(&authority, prepared, &expected_after)?;

    let authoritative_snapshot_path =
        append_suffix(&paths.snapshot, ".snapshots").join(&authority.snapshot_file);
    let authoritative_bytes = read_regular(
        &authoritative_snapshot_path,
        "authoritative graph snapshot retry source",
    )?;
    let authoritative_sha256 = sha256_bytes(&authoritative_bytes);
    if authoritative_sha256 != authority.snapshot_sha256 {
        bail!(
            "authoritative snapshot SHA-256 mismatch for {}: authority {}, found {}",
            authoritative_snapshot_path.display(),
            authority.snapshot_sha256,
            authoritative_sha256
        );
    }
    let snapshot = kin_db::GraphSnapshot::from_bytes(&authoritative_bytes).with_context(|| {
        format!(
            "failed to decode authoritative graph snapshot {}",
            authoritative_snapshot_path.display()
        )
    })?;
    let graph = kin_db::InMemoryGraph::from_snapshot(snapshot);
    let graph_root = graph.recompute_root_hash();
    if hex::encode(graph_root) != prepared.input.expected_root
        || graph.entity_count() != prepared.before.entity_count
        || graph.relation_count() != prepared.before.relation_count
    {
        bail!("authoritative retry graph does not match prepared recovery root/counts");
    }

    let evidence = kindb_recovery_evidence(&prepared.input)?;
    let (root, generation) = kin_db::SnapshotManager::recover_local_authority_with_evidence(
        &paths.snapshot,
        &graph,
        &evidence,
    )
    .with_context(|| {
        format!(
            "failed to finish KinDB's evidence-bound authority retry for {}",
            paths.snapshot.display()
        )
    })?;
    require_recovery_commit(
        "committed-authority retry",
        root,
        generation,
        &expected_after,
    )
}

fn kindb_recovery_evidence(
    input: &RecoveryInputEvidence,
) -> Result<kin_db::LocalAuthorityRecoveryEvidence> {
    Ok(kin_db::LocalAuthorityRecoveryEvidence {
        expected_head_generation: input.expected_head_generation,
        snapshot_sha256: parse_hash("prepared snapshot SHA-256", &input.snapshot.sha256)?,
        expected_root_hash: parse_hash("prepared graph root", &input.expected_root)?,
        deltas: input
            .deltas
            .iter()
            .map(|delta| {
                Ok(kin_db::LocalAuthorityRecoveryDeltaEvidence {
                    generation: delta.generation,
                    sha256: parse_hash("prepared delta SHA-256", &delta.sha256)?,
                })
            })
            .collect::<Result<Vec<_>>>()?,
    })
}

fn require_recovery_commit(
    role: &str,
    root: [u8; 32],
    generation: u64,
    expected: &GraphStateEvidence,
) -> Result<()> {
    if generation != expected.generation || hex::encode(root) != expected.root {
        bail!(
            "{role} returned generation {generation}, root {}; expected generation {}, root {}",
            hex::encode(root),
            expected.generation,
            expected.root
        );
    }
    Ok(())
}

fn inspect_recovered_graph(
    prepared: &PreparedRecoveryReceipt,
    paths: &RepoPaths,
) -> Result<(GraphStateEvidence, RecoveredArtifacts)> {
    if !read_delta_artifacts(paths)?.is_empty() {
        bail!(
            "legacy delta artifacts remain after recovery in {}; refusing to report committed recovery",
            paths.delta_dir.display()
        );
    }
    let manager = kin_db::SnapshotManager::open_read_only(&paths.snapshot).with_context(|| {
        format!(
            "failed to reopen recovered graph {}",
            paths.snapshot.display()
        )
    })?;
    let graph = manager.graph();
    let after = GraphStateEvidence {
        generation: manager.generation(),
        root: hex::encode(graph.recompute_root_hash()),
        entity_count: graph.entity_count(),
        relation_count: graph.relation_count(),
    };
    drop(graph);
    drop(manager);

    let expected_generation = prepared
        .input
        .expected_head_generation
        .checked_add(1)
        .ok_or_else(|| anyhow!("expected head generation is exhausted"))?;
    if after.generation != expected_generation
        || after.root != prepared.input.expected_root
        || after.entity_count != prepared.before.entity_count
        || after.relation_count != prepared.before.relation_count
    {
        bail!(
            "reopened graph does not match recovered authority: expected generation {expected_generation}, root {}, entities {}, relations {}; found generation {}, root {}, entities {}, relations {}",
            prepared.input.expected_root,
            prepared.before.entity_count,
            prepared.before.relation_count,
            after.generation,
            after.root,
            after.entity_count,
            after.relation_count
        );
    }

    let authority_bytes = read_regular(&paths.authority, "graph authority")?;
    let authority: LocalAuthorityView = serde_json::from_slice(&authority_bytes)
        .with_context(|| format!("invalid graph authority {}", paths.authority.display()))?;
    validate_authority_view(&authority, prepared, &after)?;

    let snapshot_versions = append_suffix(&paths.snapshot, ".snapshots");
    let authoritative_snapshot_path = snapshot_versions.join(&authority.snapshot_file);
    let authoritative_snapshot_sha256 =
        sha256_file(&authoritative_snapshot_path, "authoritative graph snapshot")?;
    if authoritative_snapshot_sha256 != authority.snapshot_sha256 {
        bail!(
            "authoritative snapshot SHA-256 mismatch for {}: authority {}, found {}",
            authoritative_snapshot_path.display(),
            authority.snapshot_sha256,
            authoritative_snapshot_sha256
        );
    }
    let compatibility_snapshot_sha256 = sha256_file(&paths.snapshot, "compatibility snapshot")?;
    if compatibility_snapshot_sha256 != authority.snapshot_sha256 {
        bail!(
            "compatibility snapshot {} did not converge to authoritative bytes: expected {}, found {}",
            paths.snapshot.display(),
            authority.snapshot_sha256,
            compatibility_snapshot_sha256
        );
    }
    let projection_generation =
        read_generation_file(&paths.projection_generation, "projection generation marker")?;
    if projection_generation != after.generation {
        bail!(
            "projection generation mismatch for {}: expected {}, found {projection_generation}",
            paths.projection_generation.display(),
            after.generation
        );
    }

    Ok((
        after,
        RecoveredArtifacts {
            authority: ArtifactEvidence {
                path: display_path(&paths.authority),
                sha256: sha256_bytes(&authority_bytes),
            },
            authoritative_snapshot: ArtifactEvidence {
                path: display_path(&authoritative_snapshot_path),
                sha256: authoritative_snapshot_sha256,
            },
            compatibility_snapshot: ArtifactEvidence {
                path: display_path(&paths.snapshot),
                sha256: compatibility_snapshot_sha256,
            },
            projection_generation: ArtifactEvidence {
                path: display_path(&paths.projection_generation),
                sha256: sha256_file(&paths.projection_generation, "projection generation marker")?,
            },
        },
    ))
}

fn validate_authority_view(
    authority: &LocalAuthorityView,
    prepared: &PreparedRecoveryReceipt,
    after: &GraphStateEvidence,
) -> Result<()> {
    if authority.version != AUTHORITY_VERSION {
        bail!(
            "unexpected local authority version {}; expected {AUTHORITY_VERSION}",
            authority.version
        );
    }
    if authority.snapshot_generation != after.generation
        || authority.head_generation != after.generation
        || normalize_hash("authority root", &authority.snapshot_root_hash)? != after.root
    {
        bail!("local authority generations/root do not match the reopened graph");
    }
    let expected_snapshot_file = format!("{:020}.kndb", after.generation);
    if authority.snapshot_file != expected_snapshot_file {
        bail!(
            "local authority snapshot file mismatch: expected {expected_snapshot_file}, found {}",
            authority.snapshot_file
        );
    }
    normalize_hash("authority snapshot SHA-256", &authority.snapshot_sha256)?;
    if !authority.acknowledged_deltas.is_empty() {
        bail!("recovered full-snapshot authority unexpectedly retains acknowledged deltas");
    }
    let mut retired = authority.retired_deltas.clone();
    retired.sort();
    let expected_retired: Vec<_> = prepared
        .input
        .deltas
        .iter()
        .map(|delta| AuthorityDeltaView {
            generation: delta.generation,
            sha256: delta.sha256.clone(),
        })
        .collect();
    if retired != expected_retired {
        bail!("recovered authority does not bind the exact retired legacy journal bytes");
    }
    Ok(())
}

fn validate_committed_receipt(
    prepared: &PreparedRecoveryReceipt,
    committed: &CommittedRecoveryReceipt,
    paths: &RepoPaths,
) -> Result<()> {
    if committed.version != RECEIPT_VERSION {
        bail!(
            "unsupported committed recovery receipt version {} in {}",
            committed.version,
            paths.committed_receipt.display()
        );
    }
    let prepared_bytes = read_regular(&paths.prepared_receipt, "prepared recovery receipt")?;
    if committed.prepared_receipt_sha256 != sha256_bytes(&prepared_bytes) {
        bail!("committed recovery receipt does not bind the prepared receipt bytes");
    }
    let current = finalize_committed_state(prepared, paths)?;
    if &current != committed {
        bail!(
            "current graph/manifest artifacts do not match committed recovery receipt {}; refusing stale success",
            paths.committed_receipt.display()
        );
    }
    Ok(())
}

fn build_report(
    status: RecoveryStatus,
    prepared: &PreparedRecoveryReceipt,
    committed: &CommittedRecoveryReceipt,
    paths: &RepoPaths,
) -> Result<RecoveryReport> {
    let mut input_artifacts = vec![prepared.input.snapshot.clone()];
    input_artifacts.extend(prepared.input.deltas.iter().map(|delta| ArtifactEvidence {
        path: delta.path.clone(),
        sha256: delta.sha256.clone(),
    }));
    Ok(RecoveryReport {
        status,
        mode: prepared.mode,
        repo_root: prepared.input.repo_root.clone(),
        snapshot_path: prepared.input.snapshot.path.clone(),
        before: prepared.before.clone(),
        after: committed.after.clone(),
        manifest: committed.manifest.clone(),
        input_artifacts,
        recovered_artifacts: committed.artifacts.clone(),
        receipts: RecoveryReceipts {
            prepared: ArtifactEvidence {
                path: display_path(&paths.prepared_receipt),
                sha256: sha256_file(&paths.prepared_receipt, "prepared recovery receipt")?,
            },
            committed: ArtifactEvidence {
                path: display_path(&paths.committed_receipt),
                sha256: sha256_file(&paths.committed_receipt, "committed recovery receipt")?,
            },
        },
        workspace_source_files_read: false,
    })
}

fn inspect_manifest_plan(path: &Path, explicit_repo_id: &str) -> Result<ManifestPlan> {
    let explicit = normalize_repo_id(explicit_repo_id)?;
    match inspect_optional_regular_file(path, "Kin manifest")? {
        true => {
            let bytes = read_regular(path, "Kin manifest")?;
            let manifest: kin_core::KinManifest = serde_json::from_slice(&bytes)
                .with_context(|| format!("invalid existing Kin manifest {}", path.display()))?;
            let existing = normalize_repo_id(&manifest.repo_id)?;
            if explicit != existing {
                bail!(
                    "explicit repo ID {explicit} does not match existing manifest repo ID {existing}"
                );
            }
            if !manifest.is_compatible() {
                bail!(
                    "existing Kin manifest {} is incompatible with this Kin build",
                    path.display()
                );
            }
            Ok(ManifestPlan {
                repo_id: existing,
                existing: true,
            })
        }
        false => Ok(ManifestPlan {
            repo_id: explicit,
            existing: false,
        }),
    }
}

fn ensure_manifest_after_graph(plan: &ManifestPlan, path: &Path) -> Result<ManifestEvidence> {
    if !inspect_optional_regular_file(path, "Kin manifest")? {
        if plan.existing {
            bail!(
                "existing manifest {} disappeared during graph recovery",
                path.display()
            );
        }
        let manifest = kin_core::KinManifest {
            kin_version: env!("CARGO_PKG_VERSION").to_string(),
            languages: Vec::new(),
            adapters: Vec::new(),
            repo_id: plan.repo_id.clone(),
            created_at: chrono::Utc::now().to_rfc3339(),
        };
        let bytes = serde_json::to_vec_pretty(&manifest)?;
        match atomic_create_once(path, &bytes, "Kin manifest") {
            Ok(()) => {}
            Err(error)
                if error
                    .downcast_ref::<std::io::Error>()
                    .is_some_and(|io| io.kind() == std::io::ErrorKind::AlreadyExists) =>
            {
                bail!(
                    "Kin manifest {} appeared while recovery was creating it; refusing ambiguous creation attribution",
                    path.display()
                )
            }
            Err(error) => return Err(error),
        }
    }
    let bytes = read_regular(path, "Kin manifest")?;
    let manifest: kin_core::KinManifest = serde_json::from_slice(&bytes)
        .with_context(|| format!("invalid Kin manifest after recovery: {}", path.display()))?;
    if normalize_repo_id(&manifest.repo_id)? != plan.repo_id {
        bail!(
            "manifest repo ID changed during recovery: expected {}, found {}",
            plan.repo_id,
            manifest.repo_id
        );
    }
    if !manifest.is_compatible() {
        bail!(
            "final Kin manifest {} is incompatible with this Kin build",
            path.display()
        );
    }
    Ok(ManifestEvidence {
        path: display_path(path),
        repo_id: plan.repo_id.clone(),
        sha256: sha256_bytes(&bytes),
        created_by_recovery: !plan.existing,
    })
}

fn parse_expected_deltas(values: &[String]) -> Result<BTreeMap<u64, String>> {
    let mut parsed = BTreeMap::new();
    for value in values {
        let (generation, sha256) = value.split_once('=').ok_or_else(|| {
            anyhow!("invalid --expected-delta {value:?}; expected GENERATION=SHA256")
        })?;
        let generation = generation
            .parse::<u64>()
            .with_context(|| format!("invalid delta generation in {value:?}"))?;
        if generation == 0 {
            bail!("delta generation 0 is reserved");
        }
        let sha256 = normalize_hash("expected delta SHA-256", sha256)?;
        if parsed.insert(generation, sha256).is_some() {
            bail!("duplicate expected delta generation {generation}");
        }
    }
    Ok(parsed)
}

fn read_delta_artifacts(paths: &RepoPaths) -> Result<Vec<DeltaEvidence>> {
    match fs::symlink_metadata(&paths.delta_dir) {
        Ok(metadata) => {
            if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
                bail!(
                    "legacy delta authority {} must be a non-symlink directory",
                    paths.delta_dir.display()
                );
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to inspect delta directory {}",
                    paths.delta_dir.display()
                )
            })
        }
    }
    let mut deltas = Vec::new();
    for entry in fs::read_dir(&paths.delta_dir)
        .with_context(|| format!("failed to read {}", paths.delta_dir.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow!("non-UTF-8 entry in {}", paths.delta_dir.display()))?;
        let generation = parse_canonical_delta_name(&name).ok_or_else(|| {
            anyhow!(
                "unexpected artifact {} in legacy delta authority; recovery requires an exact canonical journal",
                path.display()
            )
        })?;
        require_regular_file(&path, "legacy graph delta")?;
        deltas.push(DeltaEvidence {
            generation,
            path: display_path(&path),
            sha256: sha256_file(&path, "legacy graph delta")?,
        });
    }
    deltas.sort_by_key(|delta| delta.generation);
    Ok(deltas)
}

fn parse_canonical_delta_name(name: &str) -> Option<u64> {
    let stem = name.strip_suffix(".kndd")?;
    if stem.len() != 20 || !stem.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let generation = stem.parse::<u64>().ok()?;
    (generation > 0 && name == format!("{generation:020}.kndd")).then_some(generation)
}

fn read_generation_marker(paths: &RepoPaths) -> Result<u64> {
    let path = paths
        .snapshot
        .parent()
        .ok_or_else(|| anyhow!("snapshot has no parent directory"))?
        .join("generation");
    match fs::symlink_metadata(&path) {
        Ok(_) => read_generation_file(&path, "legacy generation marker"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(error)
            .with_context(|| format!("failed to inspect generation marker {}", path.display())),
    }
}

fn read_generation_file(path: &Path, role: &str) -> Result<u64> {
    let bytes = read_regular(path, role)?;
    let value = std::str::from_utf8(&bytes)
        .with_context(|| format!("{role} {} is not UTF-8", path.display()))?;
    value
        .trim()
        .parse::<u64>()
        .with_context(|| format!("invalid generation in {role} {}", path.display()))
}

fn acquire_recovery_lock(path: &Path) -> Result<File> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            bail!("recovery lock {} is not a regular file", path.display());
        }
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options
        .open(path)
        .with_context(|| format!("failed to open recovery lock {}", path.display()))?;
    file.try_lock_exclusive()
        .with_context(|| format!("another graph authority recovery holds {}", path.display()))?;
    Ok(file)
}

fn verify_kindb_unlocked(snapshot: &Path) -> Result<()> {
    let lock_path = snapshot.with_extension("lock");
    if let Ok(metadata) = fs::symlink_metadata(&lock_path) {
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            bail!("KinDB lock {} is not a regular file", lock_path.display());
        }
    }
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options
        .open(&lock_path)
        .with_context(|| format!("failed to open KinDB lock {}", lock_path.display()))?;
    file.try_lock_exclusive().with_context(|| {
        format!(
            "KinDB lock {} is active; recovery refuses to wait on or interrupt a live graph holder",
            lock_path.display()
        )
    })?;
    FileExt::unlock(&file)
        .with_context(|| format!("failed to release KinDB lock probe {}", lock_path.display()))?;
    Ok(())
}

fn create_json_once<T: Serialize>(path: &Path, value: &T, role: &str) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value)?;
    match atomic_create_once(path, &bytes, role) {
        Ok(()) => Ok(()),
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|io| io.kind() == std::io::ErrorKind::AlreadyExists) =>
        {
            let existing = read_regular(path, role)?;
            if existing == bytes {
                Ok(())
            } else {
                bail!("existing {role} {} has different bytes", path.display())
            }
        }
        Err(error) => Err(error),
    }
}

fn atomic_create_once(path: &Path, bytes: &[u8], role: &str) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow!("{role} path {} has no parent", path.display()))?;
    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow!("{role} path {} has no file name", path.display()))?;
    let temp = parent.join(format!(
        ".{}.{}.tmp",
        file_name.to_string_lossy(),
        uuid::Uuid::new_v4()
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(&temp)
        .with_context(|| format!("failed to create temporary {role} {}", temp.display()))?;
    let result = (|| -> Result<()> {
        file.write_all(bytes)
            .with_context(|| format!("failed to write temporary {role} {}", temp.display()))?;
        file.sync_all()
            .with_context(|| format!("failed to sync temporary {role} {}", temp.display()))?;
        fs::hard_link(&temp, path).map_err(anyhow::Error::from)?;
        sync_directory(parent)?;
        fs::remove_file(&temp)
            .with_context(|| format!("failed to remove temporary {role} {}", temp.display()))?;
        sync_directory(parent)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<()> {
    File::open(path)
        .with_context(|| format!("failed to open directory {} for sync", path.display()))?
        .sync_all()
        .with_context(|| format!("failed to sync directory {}", path.display()))?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<()> {
    Ok(())
}

fn read_optional_json<T: for<'de> Deserialize<'de>>(path: &Path, role: &str) -> Result<Option<T>> {
    if !inspect_optional_regular_file(path, role)? {
        return Ok(None);
    }
    let bytes = read_regular(path, role)?;
    serde_json::from_slice(&bytes)
        .with_context(|| format!("invalid {role} {}", path.display()))
        .map(Some)
}

fn inspect_optional_regular_file(path: &Path, role: &str) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                bail!(
                    "{role} {} must be a regular non-symlink file",
                    path.display()
                );
            }
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => {
            Err(error).with_context(|| format!("failed to inspect {role} {}", path.display()))
        }
    }
}

fn require_directory(path: &Path, role: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {role} {}", path.display()))?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        bail!("{role} {} must be a non-symlink directory", path.display());
    }
    Ok(())
}

fn require_regular_file(path: &Path, role: &str) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect {role} {}", path.display()))?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        bail!(
            "{role} {} must be a regular non-symlink file",
            path.display()
        );
    }
    Ok(())
}

fn read_regular(path: &Path, role: &str) -> Result<Vec<u8>> {
    require_regular_file(path, role)?;
    #[cfg(unix)]
    let before = fs::symlink_metadata(path)?;
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("failed to open {role} {}", path.display()))?;
    let after = file.metadata()?;
    if !after.is_file() {
        bail!("{role} {} changed type while opening", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            bail!("{role} {} changed while opening", path.display());
        }
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .with_context(|| format!("failed to read {role} {}", path.display()))?;
    Ok(bytes)
}

fn sha256_file(path: &Path, role: &str) -> Result<String> {
    Ok(sha256_bytes(&read_regular(path, role)?))
}

fn sha256_bytes(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn parse_hash(role: &str, value: &str) -> Result<[u8; 32]> {
    let normalized = normalize_hash(role, value)?;
    let bytes = hex::decode(&normalized).expect("normalized hash is valid hex");
    bytes
        .try_into()
        .map_err(|_| anyhow!("{role} must contain exactly 32 bytes"))
}

fn normalize_hash(role: &str, value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.len() != 64 || !normalized.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("{role} must be exactly 64 hexadecimal characters");
    }
    Ok(normalized)
}

fn normalize_repo_id(value: &str) -> Result<String> {
    let parsed = uuid::Uuid::parse_str(value.trim())
        .with_context(|| format!("repo ID {value:?} is not a UUID"))?;
    Ok(parsed.to_string())
}

fn append_suffix(path: &Path, suffix: &str) -> PathBuf {
    let mut name = std::ffi::OsString::from(path.as_os_str());
    name.push(suffix);
    PathBuf::from(name)
}

fn delta_path(delta_dir: &Path, generation: u64) -> PathBuf {
    delta_dir.join(format!("{generation:020}.kndd"))
}

fn display_path(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    const REPO_ID: &str = "2f3eb300-f6c9-4d72-8d39-c232eaf8ae99";

    struct Fixture {
        _temp: TempDir,
        root: PathBuf,
        snapshot: PathBuf,
    }

    fn make_fixture(snapshot: &kin_db::GraphSnapshot) -> Fixture {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("repo");
        let kindb = root.join(".kin/kindb");
        fs::create_dir_all(&kindb).unwrap();
        let graph_path = kindb.join("graph.kndb");
        fs::write(&graph_path, snapshot.to_bytes().unwrap()).unwrap();
        Fixture {
            _temp: temp,
            root,
            snapshot: graph_path,
        }
    }

    fn options(fixture: &Fixture, root: [u8; 32]) -> RecoverAuthorityOptions {
        RecoverAuthorityOptions {
            repo: fixture.root.clone(),
            expected_head_generation: 0,
            expected_snapshot_sha256: sha256_file(&fixture.snapshot, "fixture").unwrap(),
            expected_root: hex::encode(root),
            expected_deltas: Vec::new(),
            repo_id: REPO_ID.to_string(),
            confirm_quiesced: true,
            json: true,
        }
    }

    fn authority_path(snapshot: &Path) -> PathBuf {
        append_suffix(snapshot, ".authority.json")
    }

    fn prepared_path(snapshot: &Path) -> PathBuf {
        append_suffix(snapshot, ".recovery.prepared.json")
    }

    #[test]
    fn recovers_no_delta_graph_and_missing_manifest_atomically() {
        let mut snapshot = kin_db::GraphSnapshot::empty();
        snapshot.file_hashes.insert("graph-only.rs".into(), [7; 32]);
        let root = kin_db::compute_graph_root_hash(&snapshot);
        let fixture = make_fixture(&snapshot);

        let report = recover_authority_inner(&options(&fixture, root)).unwrap();

        assert_eq!(report.status, RecoveryStatus::Recovered);
        assert_eq!(report.mode, RecoveryMode::SnapshotPromotion);
        assert_eq!(report.before.generation, 0);
        assert_eq!(report.after.generation, 1);
        assert_eq!(report.after.root, hex::encode(root));
        assert!(authority_path(&fixture.snapshot).is_file());
        let manifest =
            kin_core::KinManifest::load(&fixture.root.join(".kin/manifest.json")).unwrap();
        assert_eq!(manifest.repo_id, REPO_ID);
        assert!(report.manifest.created_by_recovery);
    }

    #[test]
    fn replays_and_promotes_exact_legacy_journal() {
        let mut base = kin_db::GraphSnapshot::empty();
        base.file_hashes.insert("base.rs".into(), [1; 32]);
        let fixture = make_fixture(&base);
        let delta_dir = append_suffix(&fixture.snapshot, ".deltas");
        fs::create_dir_all(&delta_dir).unwrap();

        // Match the real pre-authority KinLab shape: a generation-2 base and
        // one exact contiguous journal artifact for every generation 3..=6.
        let mut previous = base;
        let mut expected_deltas = Vec::new();
        for generation in 3..=6 {
            let mut next = previous.clone();
            next.file_hashes
                .insert(format!("delta-{generation}.rs"), [generation as u8; 32]);
            let delta = kin_db::compute_graph_delta(&previous, &next, generation - 1);
            let path = delta_path(&delta_dir, generation);
            fs::write(&path, delta.to_bytes().unwrap()).unwrap();
            expected_deltas.push(format!(
                "{generation}={}",
                sha256_file(&path, "fixture delta").unwrap()
            ));
            previous = next;
        }
        let target = previous;
        fs::write(fixture.snapshot.parent().unwrap().join("generation"), b"6").unwrap();
        let root = kin_db::compute_graph_root_hash(&target);
        let mut opts = options(&fixture, root);
        opts.expected_head_generation = 6;
        opts.expected_deltas = expected_deltas;

        let report = recover_authority_inner(&opts).unwrap();

        assert_eq!(report.mode, RecoveryMode::LegacyJournalRebuild);
        assert_eq!(report.before.generation, 6);
        assert_eq!(report.after.generation, 7);
        assert_eq!(report.after.root, hex::encode(root));
        assert!(
            read_delta_artifacts(&resolve_repo_paths(&fixture.root).unwrap())
                .unwrap()
                .is_empty()
        );
        let reopened = kin_db::SnapshotManager::open_read_only(&fixture.snapshot).unwrap();
        assert_eq!(reopened.generation(), 7);
        assert_eq!(reopened.graph().get_file_hash("delta-6.rs"), Some([6; 32]));
    }

    #[test]
    fn exact_retry_is_idempotent() {
        let mut snapshot = kin_db::GraphSnapshot::empty();
        snapshot.file_hashes.insert("stable.rs".into(), [4; 32]);
        let root = kin_db::compute_graph_root_hash(&snapshot);
        let fixture = make_fixture(&snapshot);
        let opts = options(&fixture, root);

        let first = recover_authority_inner(&opts).unwrap();
        let authority_before = fs::read(authority_path(&fixture.snapshot)).unwrap();
        fs::remove_file(append_suffix(&fixture.snapshot, ".recovery.committed.json")).unwrap();
        let second = recover_authority_inner(&opts).unwrap();
        let third = recover_authority_inner(&opts).unwrap();
        let authority_after = fs::read(authority_path(&fixture.snapshot)).unwrap();

        assert_eq!(first.status, RecoveryStatus::Recovered);
        assert_eq!(second.status, RecoveryStatus::AlreadyRecovered);
        assert_eq!(third.status, RecoveryStatus::AlreadyRecovered);
        assert!(first.manifest.created_by_recovery);
        assert!(second.manifest.created_by_recovery);
        assert!(third.manifest.created_by_recovery);
        assert_eq!(first.after, second.after);
        assert_eq!(second.after, third.after);
        assert_eq!(authority_before, authority_after);
        assert_eq!(second.after.generation, 1);
    }

    #[test]
    fn retry_finishes_interrupted_compatibility_projection() {
        let mut snapshot = kin_db::GraphSnapshot::empty();
        snapshot
            .file_hashes
            .insert("interrupted.rs".into(), [12; 32]);
        let original_bytes = snapshot.to_bytes().unwrap();
        let root = kin_db::compute_graph_root_hash(&snapshot);
        let fixture = make_fixture(&snapshot);
        let opts = options(&fixture, root);

        let first = recover_authority_inner(&opts).unwrap();
        let authority: LocalAuthorityView =
            serde_json::from_slice(&fs::read(authority_path(&fixture.snapshot)).unwrap()).unwrap();
        fs::remove_file(append_suffix(&fixture.snapshot, ".recovery.committed.json")).unwrap();

        // Model the documented crash window after authority commit but before
        // the best-effort compatibility projection reaches the new cursor.
        fs::write(&fixture.snapshot, &original_bytes).unwrap();
        fs::write(fixture.snapshot.parent().unwrap().join("generation"), b"0").unwrap();
        let projection_generation = append_suffix(&fixture.snapshot, ".projection-generation");
        if projection_generation.exists() {
            fs::remove_file(&projection_generation).unwrap();
        }

        let retried = recover_authority_inner(&opts).unwrap();

        assert_eq!(first.status, RecoveryStatus::Recovered);
        assert_eq!(retried.status, RecoveryStatus::AlreadyRecovered);
        assert_eq!(retried.after.generation, 1);
        assert_eq!(
            sha256_file(&fixture.snapshot, "compatibility snapshot").unwrap(),
            authority.snapshot_sha256
        );
        assert_eq!(
            read_generation_file(&projection_generation, "projection generation").unwrap(),
            1
        );
    }

    #[test]
    fn refuses_all_primary_evidence_mismatches_before_mutation() {
        let mut snapshot = kin_db::GraphSnapshot::empty();
        snapshot.file_hashes.insert("truth.rs".into(), [8; 32]);
        let root = kin_db::compute_graph_root_hash(&snapshot);

        let fixture = make_fixture(&snapshot);
        let mut bad_hash = options(&fixture, root);
        bad_hash.expected_snapshot_sha256 = "00".repeat(32);
        assert!(recover_authority_inner(&bad_hash)
            .unwrap_err()
            .to_string()
            .contains("snapshot SHA-256 mismatch"));
        assert!(!authority_path(&fixture.snapshot).exists());
        assert!(!prepared_path(&fixture.snapshot).exists());

        let fixture = make_fixture(&snapshot);
        let mut bad_root = options(&fixture, root);
        bad_root.expected_root = "11".repeat(32);
        assert!(recover_authority_inner(&bad_root)
            .unwrap_err()
            .to_string()
            .contains("Merkle root mismatch"));
        assert!(!authority_path(&fixture.snapshot).exists());
        assert!(!prepared_path(&fixture.snapshot).exists());

        let fixture = make_fixture(&snapshot);
        fs::write(fixture.snapshot.parent().unwrap().join("generation"), b"7").unwrap();
        let bad_generation = options(&fixture, root);
        assert!(recover_authority_inner(&bad_generation)
            .unwrap_err()
            .to_string()
            .contains("generation marker mismatch"));
        assert!(!authority_path(&fixture.snapshot).exists());
        assert!(!prepared_path(&fixture.snapshot).exists());
    }

    #[test]
    fn refuses_invalid_or_conflicting_repo_identity_before_mutation() {
        let snapshot = kin_db::GraphSnapshot::empty();
        let root = kin_db::compute_graph_root_hash(&snapshot);
        let fixture = make_fixture(&snapshot);
        let mut invalid = options(&fixture, root);
        invalid.repo_id.clear();
        assert!(recover_authority_inner(&invalid)
            .unwrap_err()
            .to_string()
            .contains("is not a UUID"));
        assert!(!authority_path(&fixture.snapshot).exists());

        let fixture = make_fixture(&snapshot);
        let manifest = kin_core::KinManifest {
            kin_version: env!("CARGO_PKG_VERSION").into(),
            languages: Vec::new(),
            adapters: Vec::new(),
            repo_id: REPO_ID.into(),
            created_at: chrono::Utc::now().to_rfc3339(),
        };
        manifest
            .save(&fixture.root.join(".kin/manifest.json"))
            .unwrap();
        let mut conflicting = options(&fixture, root);
        conflicting.repo_id = "8fa1b75d-e140-4b34-a4ca-06f22d0caf06".into();
        assert!(recover_authority_inner(&conflicting)
            .unwrap_err()
            .to_string()
            .contains("does not match existing manifest"));
        assert!(!authority_path(&fixture.snapshot).exists());
    }

    #[test]
    fn refuses_an_incompatible_manifest_that_appears_at_finalization() {
        let snapshot = kin_db::GraphSnapshot::empty();
        let fixture = make_fixture(&snapshot);
        let path = fixture.root.join(".kin/manifest.json");
        let incompatible = kin_core::KinManifest {
            kin_version: "0.1.99".into(),
            languages: Vec::new(),
            adapters: Vec::new(),
            repo_id: REPO_ID.into(),
            created_at: chrono::Utc::now().to_rfc3339(),
        };
        incompatible.save(&path).unwrap();
        let plan = ManifestPlan {
            repo_id: REPO_ID.into(),
            existing: false,
        };

        let error = ensure_manifest_after_graph(&plan, &path).unwrap_err();

        assert!(error.to_string().contains("incompatible"));
    }

    #[test]
    fn refuses_delta_hash_and_continuity_mismatches_before_mutation() {
        let base = kin_db::GraphSnapshot::empty();
        let target = base.clone();
        let fixture = make_fixture(&base);
        let delta_dir = append_suffix(&fixture.snapshot, ".deltas");
        fs::create_dir_all(&delta_dir).unwrap();
        let second = kin_db::GraphSnapshotDelta::empty(1).to_bytes().unwrap();
        let fourth = kin_db::GraphSnapshotDelta::empty(3).to_bytes().unwrap();
        let second_path = delta_path(&delta_dir, 2);
        let fourth_path = delta_path(&delta_dir, 4);
        fs::write(&second_path, &second).unwrap();
        fs::write(&fourth_path, &fourth).unwrap();
        fs::write(fixture.snapshot.parent().unwrap().join("generation"), b"4").unwrap();
        let mut opts = options(&fixture, kin_db::compute_graph_root_hash(&target));
        opts.expected_head_generation = 4;
        opts.expected_deltas = vec![
            format!("2={}", sha256_bytes(&second)),
            format!("4={}", sha256_bytes(&fourth)),
        ];
        assert!(recover_authority_inner(&opts)
            .unwrap_err()
            .to_string()
            .contains("chain is incomplete"));
        assert!(!authority_path(&fixture.snapshot).exists());
        assert!(!prepared_path(&fixture.snapshot).exists());

        let fixture = make_fixture(&base);
        let delta_dir = append_suffix(&fixture.snapshot, ".deltas");
        fs::create_dir_all(&delta_dir).unwrap();
        let delta_path = delta_path(&delta_dir, 1);
        let delta = kin_db::GraphSnapshotDelta::empty(0).to_bytes().unwrap();
        fs::write(&delta_path, &delta).unwrap();
        fs::write(fixture.snapshot.parent().unwrap().join("generation"), b"1").unwrap();
        let mut opts = options(&fixture, kin_db::compute_graph_root_hash(&base));
        opts.expected_head_generation = 1;
        opts.expected_deltas = vec![format!("1={}", "ab".repeat(32))];
        assert!(recover_authority_inner(&opts)
            .unwrap_err()
            .to_string()
            .contains("artifact set does not match"));
        assert!(!authority_path(&fixture.snapshot).exists());
        assert!(!prepared_path(&fixture.snapshot).exists());
    }

    #[test]
    fn requires_explicit_quiescence_confirmation() {
        let snapshot = kin_db::GraphSnapshot::empty();
        let root = kin_db::compute_graph_root_hash(&snapshot);
        let fixture = make_fixture(&snapshot);
        let mut opts = options(&fixture, root);
        opts.confirm_quiesced = false;
        assert!(recover_authority_inner(&opts)
            .unwrap_err()
            .to_string()
            .contains("--confirm-quiesced"));
        assert!(!authority_path(&fixture.snapshot).exists());
    }

    #[cfg(unix)]
    #[test]
    fn refuses_an_active_kindb_lock_without_waiting_or_writing_receipts() {
        let snapshot = kin_db::GraphSnapshot::empty();
        let root = kin_db::compute_graph_root_hash(&snapshot);
        let fixture = make_fixture(&snapshot);
        let lock_path = fixture.snapshot.with_extension("lock");
        let holder = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .unwrap();
        holder.try_lock_exclusive().unwrap();

        let error = recover_authority_inner(&options(&fixture, root)).unwrap_err();

        assert!(error.to_string().contains("is active"));
        assert!(!authority_path(&fixture.snapshot).exists());
        assert!(!prepared_path(&fixture.snapshot).exists());
        FileExt::unlock(&holder).unwrap();
    }
}
