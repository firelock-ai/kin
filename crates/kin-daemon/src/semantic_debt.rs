//! Paths whose exact bytes reached authority without their semantics, recorded
//! against the body identity the parse is owed for.
//!
//! # Why this exists
//!
//! A disposable session publishes a complete exact tree of its own. The bytes
//! become graph authority, and nothing parses them, so the derived graph keeps
//! answering about those files at the positions the previous parse recorded.
//! The commit that follows cannot notice: it forces one complete admission,
//! that admission plans its transition from a working copy the publication has
//! already made current, finds it empty, and returns before its own enrichment
//! half ever runs. On a converted `psf/requests` an edit that prepended
//! seventeen lines left the whole file answering seventeen lines short, under an
//! envelope with nothing to report.
//!
//! The publication re-derives the semantics on the spot, which fixes the live
//! daemon. It does not survive a restart. Entities reach durable authority only
//! inside a semantic change, a session reconcile deliberately publishes the
//! workspace tree with no history and no ref move, and a derived-graph mutation
//! that no change carries is gone when the next daemon replays that history.
//! Measured rather than assumed: a daemon reopened between the session's edit
//! and its commit read the pre-edit span back, and a synchronous
//! `save_snapshot` immediately after the re-derivation did not change that.
//!
//! So something has to outlive the daemon and tell the next commit it owes a
//! parse. That is what this file records.
//!
//! # Why it is bound to a hash
//!
//! A path alone cannot say whether the debt is still real. The working copy
//! moves on, other writers publish over the same path, and a commit lands. A
//! path plus the body the parse is owed for answers all three: an entry whose
//! tree entry no longer names that body has been overtaken by a later
//! transition, and the admission that observed that transition already enriched
//! it. Settling those costs nothing and re-parsing them would be waste that
//! grows with the age of the store.
//!
//! # Why a file under the store root
//!
//! Every read and write here is ingestion IO at an explicit boundary, never a
//! semantic answer: the record says which paths are owed a parse, and the parse
//! itself reads graph-owned CAS. The two durable markers that already serve this
//! path, `unpublished-enrichment.json` and the LSP-enriched marker, are sidecar
//! JSON under the same root, and the graph exposes no general metadata surface
//! to hang a third one from.
//!
//! # Who settles it
//!
//! The commit that publishes, and only after its transaction reaches authority.
//! A commit derives its change from the live graph, so everything the drain put
//! back into that graph reaches history with it. Settling at the drain instead
//! would clear the record for a parse the next crash could still lose.

use std::collections::BTreeSet;
use std::path::PathBuf;

use kin_model::{RepoPath, TreeEntry};
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::state::DaemonState;

/// One path owed a parse, and the body it is owed for.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct SemanticDebt {
    /// The repository path, in its UTF-8 rendering. A path with no UTF-8
    /// rendering carries no semantic identity and is never recorded.
    pub(crate) path: String,
    /// Hex of the body hash the parse is owed for.
    pub(crate) body: String,
}

/// Ingestion IO: the record of what is owed, under the store root.
///
/// The root is read from the daemon's own layout here rather than taken as a
/// parameter, the way the sibling markers in `loop_runner` and `daemon` read
/// it, so the only path this module ever opens is a constant join under a root
/// the daemon bound at open and nothing a caller passes can reach the join.
fn marker_path(state: &DaemonState) -> PathBuf {
    state.layout.root().join("semantic-debt.json")
}

/// Every path one publication moved, paired with the body it published there.
///
/// Removals and the vacated half of a rename carry no body to parse and are
/// skipped, as are symlinks and Gitlinks, which are never source owned by the
/// link path.
pub(crate) fn owed_by(deltas: &[kin_model::TreeDelta]) -> Vec<SemanticDebt> {
    let mut owed = Vec::new();
    for delta in deltas {
        let Some(new) = delta.new_state() else {
            continue;
        };
        let TreeEntry::Blob { hash, .. } = new.entry else {
            continue;
        };
        let Some(path) = new.path.as_utf8() else {
            continue;
        };
        owed.push(SemanticDebt {
            path: path.to_string(),
            body: hash.to_string(),
        });
    }
    owed
}

/// Merge `owed` into the record, replacing any earlier entry for the same path.
///
/// A failed write is reported and never fatal. The record makes a loss
/// recoverable; a store that cannot write it is no worse off than one built
/// before this existed, and refusing a durable publication over it would trade a
/// recoverable gap for an unrecoverable refusal.
pub(crate) fn record(state: &DaemonState, owed: &[SemanticDebt]) {
    if owed.is_empty() {
        return;
    }
    let mut entries = outstanding(state);
    entries.retain(|entry| !owed.iter().any(|fresh| fresh.path == entry.path));
    entries.extend_from_slice(owed);
    write(state, &entries);
}

/// Read the record. An unreadable or unparseable one is treated as empty and
/// said out loud, because the alternative is refusing every commit on the store.
pub(crate) fn outstanding(state: &DaemonState) -> Vec<SemanticDebt> {
    let marker = marker_path(state);
    let Ok(bytes) = std::fs::read(&marker) else {
        return Vec::new();
    };
    match serde_json::from_slice::<Vec<SemanticDebt>>(&bytes) {
        Ok(entries) => entries,
        Err(error) => {
            warn!(
                marker = %marker.display(),
                error = %error,
                "the semantic-debt record will not parse, so a path whose bytes moved without \
                 their semantics stays stale until it is edited again"
            );
            Vec::new()
        }
    }
}

/// Split a record into what is still owed and what a later transition overtook.
///
/// Owed means the tree still names the exact body the debt was recorded for. A
/// path the tree no longer carries, or carries at a different body, has been
/// through an admission that enriched it, and the entry is spent.
pub(crate) fn partition_against_tree(
    state: &DaemonState,
    entries: &[SemanticDebt],
) -> (BTreeSet<RepoPath>, Vec<String>) {
    let tree = state.graph.resolved_tree();
    let mut owed = BTreeSet::new();
    let mut spent = Vec::new();
    for entry in entries {
        let Ok(repo_path) = RepoPath::from_utf8(entry.path.clone()) else {
            spent.push(entry.path.clone());
            continue;
        };
        let still_owed =
            tree.artifact_at_path(&repo_path)
                .is_some_and(|artifact| match artifact.entry {
                    TreeEntry::Blob { hash, .. } => hash.to_string() == entry.body,
                    _ => false,
                });
        if still_owed {
            owed.insert(repo_path);
        } else {
            spent.push(entry.path.clone());
        }
    }
    (owed, spent)
}

/// Drop the named paths from the record and rewrite it.
pub(crate) fn settle(state: &DaemonState, paths: &[String]) {
    if paths.is_empty() {
        return;
    }
    let mut entries = outstanding(state);
    let before = entries.len();
    entries.retain(|entry| !paths.contains(&entry.path));
    if entries.len() == before {
        return;
    }
    write(state, &entries);
}

/// Clear the whole record.
///
/// Called once a commit's transaction reaches authority. A commit derives its
/// change from the live graph, so every parse the drain put back into that graph
/// is in history by the time this runs, and nothing the record named is still
/// owed. The coordination gate spans both the publication that records a debt
/// and the commit that clears it, so nothing can be recorded in between and lost
/// here.
pub(crate) fn settle_all(state: &DaemonState) {
    let marker = marker_path(state);
    match std::fs::remove_file(&marker) {
        Ok(()) => debug!(
            marker = %marker.display(),
            "a commit published every re-derived parse, so the semantic-debt record is spent"
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => warn!(
            marker = %marker.display(),
            error = %error,
            "could not clear the semantic-debt record; the next commit re-parses paths that are \
             already published, which costs time and loses nothing"
        ),
    }
}

fn write(state: &DaemonState, entries: &[SemanticDebt]) {
    if entries.is_empty() {
        settle_all(state);
        return;
    }
    let marker = marker_path(state);
    match serde_json::to_vec(entries) {
        Ok(bytes) => {
            if let Err(error) = std::fs::write(&marker, bytes) {
                warn!(
                    marker = %marker.display(),
                    error = %error,
                    "could not persist the semantic-debt record, so a daemon restart before the \
                     next commit would leave these paths answering at their previous positions"
                );
            }
        }
        Err(error) => warn!(error = %error, "could not encode the semantic-debt record"),
    }
}
