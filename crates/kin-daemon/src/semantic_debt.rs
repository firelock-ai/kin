//! Paths whose exact bytes reached authority without their semantics, and the
//! body each one's parse is owed for.
//!
//! # Why this exists
//!
//! A standalone tree publication moves a workspace's exact bytes into
//! authority, and nothing parses them there, so the derived graph keeps
//! answering about those files at the positions the previous parse recorded.
//! The commit that follows cannot notice: it forces one complete admission,
//! that admission plans its transition from a working copy the publication has
//! already made current, finds it empty, and returns before its own enrichment
//! half ever runs. On a converted `psf/requests` an edit that prepended
//! seventeen lines left the whole file answering seventeen lines short, under an
//! envelope with nothing to report.
//!
//! The daemon re-derives the semantics on the spot, which fixes the live graph.
//! It does not survive a restart: entities reach durable authority only inside
//! a semantic change, and a derived-graph mutation that no change carries is
//! gone when the next daemon replays that history. So something has to outlive
//! the daemon and tell the next one, and the next commit, which parse is owed.
//!
//! # Where the record lives
//!
//! In repository authority, as the workspace's owed derivation ledger. The
//! standalone publication records what it owes inside its own compare-and-swap,
//! so a record is durable exactly when the bytes it describes are, and a
//! refused publication records nothing. A daemon commit pays the workspace's
//! records inside its own commit, because a commit derives its change from the
//! live graph the drain brought current. Every other transaction that moves a
//! path off an owed body overtakes that record in storage. Nothing here writes
//! a file or decides anything by a file's identity.
//!
//! # Why it is bound to a body
//!
//! A path alone cannot say whether the debt is still real. The working copy
//! moves on, other writers publish over the same path, and a commit lands. The
//! ledger binds each record to the exact body its parse is owed for, and a
//! record drives re-derivation only while the answering graph lacks a
//! parse-coverage certificate bound to that body.
//!
//! # The records earlier builds kept
//!
//! A daemon from an earlier build kept these records in `semantic-debt.json`
//! and the paths it derived entities for in `unpublished-enrichment.json`,
//! beside the store. They are migration inputs and nothing more. This build's
//! first start judges each entry against authority and the answering graph,
//! re-derives what is still owed in that start's pass, carries it into the
//! ledger on this daemon's next authority transaction, and removes both files
//! once that transaction is durable. A crash before then repeats the judgment,
//! which only reads authority and adds.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use kin_index::{FileClassification, FileClassifier};
use kin_model::{Hash256, RepoPath, TreeEntry};
use serde::Deserialize;
use tracing::{debug, warn};

use crate::state::DaemonState;

/// One path owed a parse, and the body it is owed for, as this daemon reads it
/// out of its workspace's owed derivation ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SemanticDebt {
    /// The repository path, in its UTF-8 rendering. A path with no UTF-8
    /// rendering carries no semantic identity and is never recorded.
    pub(crate) path: String,
    /// Hex of the body hash the parse is owed for.
    pub(crate) body: String,
}

impl SemanticDebt {
    fn from_record(record: &kin_db::OwedDerivation) -> Option<Self> {
        Some(Self {
            path: record.path().as_utf8()?.to_string(),
            body: record.body().to_string(),
        })
    }
}

/// Every path one publication moved, paired with the body it published there,
/// in the form the publication's own commit records them.
///
/// Removals and the vacated half of a rename carry no body to parse and are
/// skipped, as are symlinks and Gitlinks, which are never source owned by the
/// link path.
pub(crate) fn owed_by(deltas: &[kin_model::TreeDelta]) -> Vec<(RepoPath, Hash256)> {
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
        // Only a path that owes a PARSE belongs in this record. A file that is
        // not entity source owes none: its shallow, structured or opaque record
        // is written by the same admission that publishes its bytes, so there is
        // no deferred derivation for a later drain to perform.
        //
        // Recording one anyway is not merely waste. Nothing but a commit pays a
        // record, and the install proof never commits, so such an entry is owed
        // on every later reconcile tick. Each drain hands the path to
        // `readmit_semantics_for_paths`, whose non-source branch re-persists the
        // facet, and kin-db's artifact upsert calls `invalidate_artifact_for_embedding`,
        // which REMOVES the artifact's vector and re-queues it. The store then
        // holds an artifact key that is counted in embedding coverage and can
        // never keep a vector, and the counters sit still while it happens.
        //
        // Classification is by name here rather than by content, because a tree
        // delta carries no body. That admits a source-named path whose bytes are
        // opaque, which the drain then re-enriches; `readmit_semantics_for_paths`
        // refuses to rewrite an unchanged non-source record for that reason.
        if !matches!(
            FileClassifier::classify(Path::new(path)),
            FileClassification::EntitySource
        ) {
            continue;
        }
        #[cfg(test)]
        if RECORD_NOTHING_FOR_TEST.get() {
            continue;
        }
        owed.push((new.path.clone(), hash));
    }
    owed
}

#[cfg(test)]
thread_local! {
    /// Set by a test that stands in for a build from before the ledger, whose
    /// standalone publications recorded nothing in authority.
    static RECORD_NOTHING_FOR_TEST: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Run `work` as a build from before the ledger would: every standalone
/// publication it makes on this thread records no owed parse.
#[cfg(test)]
pub(crate) fn recording_nothing<T>(work: impl FnOnce() -> T) -> T {
    RECORD_NOTHING_FOR_TEST.set(true);
    let outcome = work();
    RECORD_NOTHING_FOR_TEST.set(false);
    outcome
}

/// Every record this daemon's workspace owes, read from the current authority
/// through its per-publication cache.
///
/// For a caller that must not act on an absence it could not read: an
/// authority that will not open is an error here, never an empty record.
///
/// The first read after a publication this daemon has not loaded opens the
/// whole store, so it never holds a runtime worker while it does. The
/// admission that plans the next transition shares that load.
pub(crate) fn outstanding_checked(state: &DaemonState) -> crate::error::Result<Vec<SemanticDebt>> {
    let records =
        crate::loop_runner::off_the_runtime_worker(|| crate::api::cached_owed_derivations(state))
            .map_err(|(_status, message)| {
            crate::error::DaemonError::Io(std::io::Error::other(format!(
                "could not read the owed derivation ledger from repository authority: {message}"
            )))
        })?;
    Ok(records
        .iter()
        .filter_map(SemanticDebt::from_record)
        .collect())
}

/// [`outstanding_checked`] for a caller that has nothing better to do with an
/// unreadable authority than say so: the failure is logged and read as empty.
pub(crate) fn outstanding(state: &DaemonState) -> Vec<SemanticDebt> {
    match outstanding_checked(state) {
        Ok(records) => records,
        Err(error) => {
            warn!(
                error = %error,
                "could not read the owed derivation ledger, so a path whose bytes moved without \
                 their semantics is not named from it"
            );
            Vec::new()
        }
    }
}

/// The paths among `entries` whose parse is still owed to the graph that
/// answers.
///
/// Owed means the tree still names the exact body the record was made for and
/// the answering graph holds no clean parse of that body. The ledger drops a
/// record whose body the authority tree no longer names, so a record whose body
/// this graph's tree does not name describes a transition the graph is ahead of
/// authority on; this graph parses its own bytes, and that record is not owed
/// here.
///
/// A record whose body the answering graph already parsed is not re-derived.
/// It is not paid either, because only a commit pays: after `kin upgrade`
/// every body the upgrade derived carries a certificate bound to it, so a
/// daemon start no longer re-derives what the store already holds, and the same
/// bytes published again over a later commit's parse are owed again.
pub(crate) fn owed_against_tree(
    state: &DaemonState,
    entries: &[SemanticDebt],
) -> BTreeSet<RepoPath> {
    let tree = state.graph.resolved_tree();
    let mut owed = BTreeSet::new();
    for entry in entries {
        let Ok(repo_path) = RepoPath::from_utf8(entry.path.clone()) else {
            continue;
        };
        let names_body =
            tree.artifact_at_path(&repo_path)
                .is_some_and(|artifact| match artifact.entry {
                    TreeEntry::Blob { hash, .. } => hash.to_string() == entry.body,
                    _ => false,
                });
        if names_body && !answering_graph_parsed(state, &tree, &repo_path) {
            owed.insert(repo_path);
        }
    }
    owed
}

/// Whether the owed derivation ledger this daemon already holds names no path
/// the answering graph still has to parse.
///
/// Read from the records the daemon holds, never through a store open, so a
/// caller on the reconcile tick pays nothing for asking. `false` when the
/// daemon holds no ledger yet: a ledger nobody has read is not an empty one.
pub(crate) fn nothing_owed_in_held_ledger(state: &DaemonState) -> bool {
    let Some(records) = crate::api::held_owed_derivations(state) else {
        return false;
    };
    let recorded: Vec<SemanticDebt> = records
        .iter()
        .filter_map(SemanticDebt::from_record)
        .collect();
    owed_against_tree(state, &recorded).is_empty()
}

/// Name source whose bytes reached authority and whose parse is still owed.
///
/// A complete admission records untracked host paths as empty once the tree
/// holds them. That zero is stamped, so a later reading is not due, and the
/// durability block then compares entity counts that cannot see a file nobody
/// has parsed. The result is `recorded` over a module the working copy holds.
///
/// These paths are already in the tree, so they are not in the untracked scan
/// and they do not belong in its count either. The first cut of this
/// disclosure added them to `untracked_path_count`, which reaches the agent as
/// paths that "have never been admitted" with `kin admit` as the remedy: the
/// gap was real and both the label and the lever were wrong. They get their
/// own count, and the surfaces that read it say what actually clears it.
///
/// A record the answering graph has already parsed is not one of them. The
/// ambient admission that records it re-derives the file into the live graph
/// on the spot, so its entities are in the counts the durability block
/// compares, and a surplus there already reads `live_uncommitted`. Counting
/// that path as well withdrew the reading to `unknown`, over the very write the
/// block exists to disclose. What the record says of such a path is that the
/// next commit owes its parse to durable authority, which is the same fact.
///
/// Read from the records this daemon already holds, never through a store
/// open: `/health` answers inside a two-second probe budget. They are the
/// newest the daemon has loaded or written, and every standalone publication
/// it makes writes its own, so what a publication owes is disclosed from the
/// moment it lands. Records a later commit paid or overtook can still be held
/// for a moment; the tree and certificate checks below drop them.
///
/// The sample cap matches the untracked probe. The count is the full set.
pub(crate) fn disclose_underived_source(
    state: &DaemonState,
    report: &mut kin_cli::commands::resources::ReconcileHealth,
) {
    let Some(records) = crate::api::held_owed_derivations(state) else {
        return;
    };
    let recorded: Vec<SemanticDebt> = records
        .iter()
        .filter_map(SemanticDebt::from_record)
        .collect();
    let owed = owed_against_tree(state, &recorded);
    if owed.is_empty() {
        return;
    }
    report.underived_path_count = report
        .underived_path_count
        .saturating_add(owed.len() as u64);
    const SAMPLE_LIMIT: usize = 5;
    for path in owed {
        if report.underived_paths_sample.len() >= SAMPLE_LIMIT {
            break;
        }
        let named = path.to_string();
        if !report
            .underived_paths_sample
            .iter()
            .any(|existing| existing == &named)
        {
            report.underived_paths_sample.push(named);
        }
    }
}

/// Whether the live graph holds a clean parse of the exact body the tree names
/// at `path`.
///
/// Read off the file's parse-coverage certificate, which is the graph's own
/// record of the bytes a file's semantics came from. The live reconcile binds it
/// to the blob it parsed, writes it for a file that declares nothing as much as
/// for one that declares plenty, and writes none for a parse that did not read
/// the file cleanly. A certificate bound to an earlier body, or none at all,
/// leaves the path owed.
pub(crate) fn answering_graph_parsed(
    state: &DaemonState,
    tree: &kin_model::ResolvedTree,
    path: &RepoPath,
) -> bool {
    let Some(artifact) = tree.artifact_at_path(path) else {
        return false;
    };
    let TreeEntry::Blob { hash, .. } = artifact.entry else {
        return false;
    };
    let Some(file) = path.as_utf8() else {
        return false;
    };
    // The certificate's identity depends on the artifact alone, so building an
    // empty one is how its id is named without restating the factory's rule.
    let certificate = kin_index::build_parse_coverage_relation(
        &kin_index::FileParseData {
            file_path: file.to_string(),
            entities: Vec::new(),
            relations: Vec::new(),
            imports: Vec::new(),
        },
        artifact.artifact_id,
        &kin_model::ParseCompleteness::Full,
        &std::collections::HashSet::<String>::new(),
    )
    .id;
    state
        .graph
        .get_relation_by_id(&certificate)
        .is_some_and(|relation| {
            kin_index::is_parse_coverage_relation(&relation, file, artifact.artifact_id)
                && kin_index::parse_coverage_source_digest(&relation) == Some(hash)
        })
}

/// Where a daemon from an earlier build kept the parses it owed.
///
/// A constant join under the root the daemon bound at open, so nothing a
/// caller passes can reach it.
fn legacy_debt_path(state: &DaemonState) -> PathBuf {
    state.layout.root().join("semantic-debt.json")
}

/// Where a daemon from an earlier build kept the paths it derived entities
/// for and could not have published.
fn legacy_enrichment_path(state: &DaemonState) -> PathBuf {
    state.layout.root().join("unpublished-enrichment.json")
}

/// What one legacy record file held when this build read it.
pub(crate) enum LegacyRecord<T> {
    /// No earlier build left the file.
    Absent,
    /// Every entry the file held.
    Entries(Vec<T>),
    /// The file is there and does not read as the record it names, so which
    /// work it held is unknown. Treated as owing everything it could name,
    /// never as owing nothing.
    Unknown(String),
}

impl<T> LegacyRecord<T> {
    pub(crate) fn is_present(&self) -> bool {
        !matches!(self, Self::Absent)
    }
}

#[derive(Deserialize)]
struct LegacyDebtEntry {
    path: String,
    body: String,
}

/// Ingestion IO at the migration boundary: the owed parses an earlier build's
/// daemon recorded beside the store.
pub(crate) fn read_legacy_debt(state: &DaemonState) -> LegacyRecord<SemanticDebt> {
    let marker = legacy_debt_path(state);
    let bytes = match std::fs::read(&marker) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return LegacyRecord::Absent;
        }
        Err(error) => return LegacyRecord::Unknown(format!("{}: {error}", marker.display())),
    };
    match serde_json::from_slice::<Vec<LegacyDebtEntry>>(&bytes) {
        Ok(entries) => LegacyRecord::Entries(
            entries
                .into_iter()
                .map(|entry| SemanticDebt {
                    path: entry.path,
                    body: entry.body,
                })
                .collect(),
        ),
        Err(error) => LegacyRecord::Unknown(format!("{}: {error}", marker.display())),
    }
}

/// Ingestion IO at the migration boundary: the paths an earlier build's daemon
/// derived entities for and no commit had published when it stopped.
///
/// Judged against graph truth by the startup planner, never trusted as it
/// stands, and never written by this build.
pub(crate) fn read_legacy_enrichment(state: &DaemonState) -> LegacyRecord<String> {
    let marker = legacy_enrichment_path(state);
    let bytes = match std::fs::read(&marker) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return LegacyRecord::Absent;
        }
        Err(error) => return LegacyRecord::Unknown(format!("{}: {error}", marker.display())),
    };
    match serde_json::from_slice::<Vec<String>>(&bytes) {
        Ok(paths) => LegacyRecord::Entries(paths),
        Err(error) => LegacyRecord::Unknown(format!("{}: {error}", marker.display())),
    }
}

/// Judge the owed parses an earlier build recorded against this daemon's
/// graph, which at startup is the durable authority's.
///
/// An entry survives while the tree names its exact body and the graph holds
/// no certificate bound to that body. A file that will not read owes, for all
/// this build can tell, every entity-source body the graph has no certificate
/// for, so that is what it is judged to owe.
pub(crate) fn judge_legacy_debt(
    state: &DaemonState,
    record: &LegacyRecord<SemanticDebt>,
) -> Vec<(RepoPath, Hash256)> {
    let tree = state.graph.resolved_tree();
    let candidates: Vec<(RepoPath, Hash256)> = match record {
        LegacyRecord::Absent => return Vec::new(),
        LegacyRecord::Entries(entries) => entries
            .iter()
            .filter_map(|entry| {
                let path = RepoPath::from_utf8(entry.path.clone()).ok()?;
                let body = Hash256::from_hex(&entry.body).ok()?;
                Some((path, body))
            })
            .collect(),
        LegacyRecord::Unknown(why) => {
            warn!(
                record = %why,
                "an earlier build's owed-parse record will not read, so every source body this \
                 graph holds no parse certificate for is treated as owed"
            );
            tree.artifacts_by_path()
                .filter_map(|artifact| {
                    let TreeEntry::Blob { hash, .. } = artifact.entry else {
                        return None;
                    };
                    let path = artifact.path.as_utf8()?;
                    matches!(
                        FileClassifier::classify(Path::new(path)),
                        FileClassification::EntitySource
                    )
                    .then(|| (artifact.path.clone(), hash))
                })
                .collect()
        }
    };
    candidates
        .into_iter()
        .filter(|(path, body)| {
            tree.artifact_at_path(path).is_some_and(
                |artifact| matches!(artifact.entry, TreeEntry::Blob { hash, .. } if hash == *body),
            ) && !answering_graph_parsed(state, &tree, path)
        })
        .collect()
}

/// Hold what the legacy records still owe until an authority transaction of
/// this daemon carries it, or remove the records now when they owe nothing.
///
/// `found` says whether either legacy file was there. A file whose every entry
/// authority or the graph already accounts for carries no obligation this build
/// lacks, so it goes at once.
pub(crate) fn hold_legacy_carry(state: &DaemonState, found: bool, owed: Vec<(RepoPath, Hash256)>) {
    if !found {
        return;
    }
    if owed.is_empty() {
        remove_legacy_records(state);
        return;
    }
    debug!(
        paths = owed.len(),
        "holding what an earlier build's records still owe for this daemon's next authority \
         transaction"
    );
    if let Ok(mut carry) = state.legacy_owed_derivations.lock() {
        *carry = Some(owed);
    }
}

/// What the legacy records still owe, for the next authority transaction to
/// carry into the ledger.
pub(crate) fn legacy_carry(state: &DaemonState) -> Vec<(RepoPath, Hash256)> {
    state
        .legacy_owed_derivations
        .lock()
        .ok()
        .and_then(|carry| carry.clone())
        .unwrap_or_default()
}

/// An authority transaction that carried or paid what the legacy records owed
/// is durable, so the records themselves have nothing left to say.
///
/// Called only after that transaction's receipt, never before: a daemon that
/// stops earlier leaves the files for the next start to judge again.
pub(crate) fn legacy_carried(state: &DaemonState) {
    let pending = state
        .legacy_owed_derivations
        .lock()
        .ok()
        .and_then(|mut carry| carry.take());
    if pending.is_some() {
        remove_legacy_records(state);
    }
}

/// Ingestion IO at the migration boundary: remove both legacy record files.
///
/// A removal that fails is reported and not retried here. The next start
/// judges the file again against an authority that already holds what it
/// carried, and adds nothing twice.
fn remove_legacy_records(state: &DaemonState) {
    for marker in [legacy_debt_path(state), legacy_enrichment_path(state)] {
        match std::fs::remove_file(&marker) {
            Ok(()) => debug!(
                marker = %marker.display(),
                "removed an earlier build's owed-work record, whose work authority now holds"
            ),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => warn!(
                marker = %marker.display(),
                error = %error,
                "could not remove an earlier build's owed-work record; the next start judges it \
                 again against authority, which already holds what it carried"
            ),
        }
    }
}
