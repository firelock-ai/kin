// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Durable record of how deeply a lazy Git-ref hydration imported history.
//!
//! Both hydration depths import the same commits and the same artifact deltas.
//! Only the deeper one replays per-commit entity and relation deltas, and
//! nothing in the graph distinguishes the two afterwards: a change with no
//! semantic deltas is exactly what a whitespace-only commit produces at either
//! depth. Depth therefore has to be *recorded* when the import runs — inferring
//! it later from "present but empty" would refuse valid refs to catch invalid
//! ones.
//!
//! This module is the persistence boundary for that record, kept out of the
//! ref-lookup answer path for the same reason the hydration checkpoint store is
//! kept out of it: reading and writing Kin's own state is an IO boundary, and an
//! answer path must not hold one. Nothing here reads repository source content,
//! and no query is ever answered from these files — they only report which
//! recorded history a graph-backed answer cannot be produced for.

use anyhow::{bail, Context, Result};
use kin_model::SemanticChangeId;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::path::{Path, PathBuf};

const RECORD_SCHEMA: &str = "kin.ref-hydration-depth.v1";
const RECORD_DEPTH: &str = "artifact-only";

/// One hydration that inserted history into the graph with no semantic replay
/// behind it.
pub(crate) struct ArtifactOnlyHydration {
    /// The Git commit whose ancestry the hydration imported. Carried as the
    /// operator-facing name of the import that produced the gap.
    pub(crate) tip: String,
    /// Every change the hydration inserted unreplayed. The whole ancestry is
    /// recorded, not just the tip: `history --ref <tip>~2` reads an ancestor's
    /// deltas, and that ancestor is exactly as unreplayed as the tip is.
    pub(crate) changes: Vec<SemanticChangeId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredRecord {
    schema: String,
    depth: String,
    tip: String,
    changes: Vec<String>,
}

/// `.kin/kindb/hydration-depth/` — one record per artifact-only hydration.
///
/// Deliberately inside the KinDB directory rather than beside it: the records
/// describe the depth of the history held in `graph.kndb`, so they are
/// discarded with the snapshot they describe. A record that outlived its graph
/// would claim a gap in history the graph no longer holds.
fn records_dir(layout: &kin_core::KinLayout) -> PathBuf {
    layout.kindb_dir().join("hydration-depth")
}

fn write_record_atomically(path: &Path, record: &StoredRecord) -> Result<()> {
    use std::io::Write;

    let json = serde_json::to_vec_pretty(record)
        .with_context(|| format!("serialize hydration-depth record {}", path.display()))?;
    let temp_path = path.with_extension(format!("json.{}.tmp", std::process::id()));
    {
        let mut file = std::fs::File::create(&temp_path)
            .with_context(|| format!("create hydration-depth record {}", temp_path.display()))?;
        file.write_all(&json)
            .with_context(|| format!("write hydration-depth record {}", temp_path.display()))?;
        // Durable before it is visible: this record is what stops a later
        // semantic caller from answering out of an unreplayed ancestry, so it
        // has to survive the same crash the graph write it guards survives.
        file.sync_all()
            .with_context(|| format!("flush hydration-depth record {}", temp_path.display()))?;
    }
    std::fs::rename(&temp_path, path).with_context(|| {
        format!(
            "publish hydration-depth record {} as {}",
            temp_path.display(),
            path.display()
        )
    })
}

fn read_stored_records(layout: &kin_core::KinLayout) -> Result<Vec<(PathBuf, StoredRecord)>> {
    let dir = records_dir(layout);
    let entries = match std::fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => {
            return Err(err)
                .with_context(|| format!("read hydration-depth records in {}", dir.display()))
        }
    };

    let mut paths = Vec::new();
    for entry in entries {
        let entry =
            entry.with_context(|| format!("read hydration-depth records in {}", dir.display()))?;
        let path = entry.path();
        if path.extension().and_then(|extension| extension.to_str()) == Some("json") {
            paths.push(path);
        }
    }
    // Directory order is not stable across platforms; reading in sorted order
    // keeps repeated calls reporting the same gap first.
    paths.sort();

    let mut records = Vec::new();
    for path in paths {
        let bytes = std::fs::read(&path)
            .with_context(|| format!("read hydration-depth record {}", path.display()))?;
        let record: StoredRecord = serde_json::from_slice(&bytes)
            .with_context(|| format!("parse hydration-depth record {}", path.display()))?;
        // Unreadable or unrecognized state is reported, never assumed away: it
        // means the depth of the history in this graph cannot be established.
        if record.schema != RECORD_SCHEMA || record.depth != RECORD_DEPTH {
            bail!(
                "hydration-depth record {} declares unsupported schema '{}' depth '{}'",
                path.display(),
                record.schema,
                record.depth
            );
        }
        records.push((path, record));
    }
    Ok(records)
}

fn parse_recorded_change(record: &StoredRecord, change: &str) -> Result<SemanticChangeId> {
    crate::commands::ref_lookup::parse_change_id(change).with_context(|| {
        format!(
            "hydration-depth record for Git commit {} names unparseable change '{}'",
            record.tip, change
        )
    })
}

/// Every artifact-only hydration this repository has recorded.
pub(crate) fn artifact_only_hydrations(
    layout: &kin_core::KinLayout,
) -> Result<Vec<ArtifactOnlyHydration>> {
    let mut hydrations = Vec::new();
    for (_, record) in read_stored_records(layout)? {
        let mut changes = Vec::with_capacity(record.changes.len());
        for change in &record.changes {
            changes.push(parse_recorded_change(&record, change)?);
        }
        hydrations.push(ArtifactOnlyHydration {
            tip: record.tip.clone(),
            changes,
        });
    }
    Ok(hydrations)
}

/// Every change recorded as imported without its semantic replay, whether or
/// not a graph still holds it.
///
/// The hydration owner uses this to find history it can upgrade. Readers must
/// additionally confirm the graph still holds what a record describes.
pub(crate) fn recorded_change_ids(
    layout: &kin_core::KinLayout,
) -> Result<HashSet<SemanticChangeId>> {
    let mut recorded = HashSet::new();
    for hydration in artifact_only_hydrations(layout)? {
        recorded.extend(hydration.changes);
    }
    Ok(recorded)
}

/// Record that `changes` were inserted for `git_oid`'s ancestry unreplayed.
///
/// Written before the graph write, never after. A record without the matching
/// graph state is inert — every reader confirms presence in the graph before
/// treating a recorded change as a gap — whereas graph state without its record
/// is exactly the silent wrong answer this exists to prevent.
pub(crate) fn record_artifact_only(
    layout: &kin_core::KinLayout,
    tip: SemanticChangeId,
    git_oid: &str,
    changes: &[SemanticChangeId],
) -> Result<()> {
    if changes.is_empty() {
        return Ok(());
    }
    let dir = records_dir(layout);
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("create hydration-depth directory {}", dir.display()))?;
    let record = StoredRecord {
        schema: RECORD_SCHEMA.to_string(),
        depth: RECORD_DEPTH.to_string(),
        tip: git_oid.to_string(),
        changes: changes.iter().map(ToString::to_string).collect(),
    };
    // Named by the tip's change id, which is hex by construction. The Git oid
    // it was derived from arrives as caller text and never becomes a path
    // component.
    write_record_atomically(&dir.join(format!("{tip}.json")), &record)
}

/// Drop `changes` from every record: they now carry semantic deltas, so nothing
/// about them is a gap any more. A record left describing nothing is removed.
pub(crate) fn forget_replayed(
    layout: &kin_core::KinLayout,
    changes: &[SemanticChangeId],
) -> Result<()> {
    if changes.is_empty() {
        return Ok(());
    }
    let replayed: HashSet<String> = changes.iter().map(ToString::to_string).collect();
    for (path, mut record) in read_stored_records(layout)? {
        let before = record.changes.len();
        record.changes.retain(|change| !replayed.contains(change));
        if record.changes.len() == before {
            continue;
        }
        if record.changes.is_empty() {
            std::fs::remove_file(&path).with_context(|| {
                format!("remove satisfied hydration-depth record {}", path.display())
            })?;
        } else {
            write_record_atomically(&path, &record)?;
        }
    }
    Ok(())
}
