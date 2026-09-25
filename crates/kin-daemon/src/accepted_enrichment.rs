// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Durable record of accepted language-server evidence repository authority has
//! not committed yet.
//!
//! An accepted language-server answer is installed into the live graph at once,
//! and repository authority only learns about it when some later publication
//! commits the graph. Until then the evidence lived in one process and nowhere
//! else, so a restart returned the committed authority graph: the accepted
//! relation was gone, and with it the reason the runtime binding-history
//! capability had been withdrawn, so the reopened daemon answered as compiler
//! checked over an interval it had itself qualified Unknown. The completion
//! marker beside this record made that worse rather than better, because it
//! survived and told the next sweep the file was already done.
//!
//! So the evidence is recorded where the marker is, retired with the marker,
//! and replayed into the graph before any reader can be served. Replay is not a
//! second opinion about the repository: it reinstalls the exact relations this
//! store accepted, through the same admission the live path uses, and an entry
//! authority has since committed or the graph now refuses is dropped.
//!
//! This is a crash record of accepted input, never an answer authority. Nothing
//! is served from it, every entry must pass ordinary graph admission to reach
//! the graph, and an absent or unreadable record degrades to exactly what this
//! daemon did before it existed.
//!
//! # Size
//!
//! The record has no size limit, on purpose. It used to refuse new evidence at
//! 16 MiB, and a cold sweep of a mid-size Go repository crosses that on its
//! own: the whole sweep is accepted before its one publication at the end, and
//! the GitHub CLI's 708 files accept about 50,000 relations, tens of megabytes
//! of record. Every relation after the limit was refused with a warning, so the
//! durability this record exists for ended part way through exactly the pass
//! that needs it most.
//!
//! What bounds the record instead is its lifecycle. Every local authority
//! commit empties it ([`clear`], from `record_repository_authority_commit`),
//! so it holds only what was accepted since the last commit, and the largest
//! that gets is one sweep's evidence: relations the live graph already holds
//! in memory and the sweep's own publication writes into authority moments
//! later. Recording and retiring append, costing what they add rather than
//! what the record holds. Replay streams it twice, holding one id and one
//! sequence number per recorded relation rather than the relations, and
//! streams the survivors into their replacement.
//!
//! # Format
//!
//! One line of JSON per relation, appended as it is accepted, so a process that
//! dies mid-write loses only the partial tail and every complete line before it
//! still parses. A retirement is a line of its own naming the files whose
//! recorded evidence it drops, applied in order at replay. Rewriting the whole
//! record for every retirement cost a full read and write of it per edited
//! file, and a crash mid-rewrite lost the record entirely.

use std::collections::HashMap;
use std::io::Write as _;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

use kin_core::KinLayout;
use kin_db::InMemoryGraph;
use kin_model::{EntityStore as _, Relation, RelationId};
use tracing::{debug, info, warn};

/// Serializes every operation on a record in this process.
///
/// A replay reads the record and then replaces it with what survived, so an
/// append landing between the two would be lost. Appends are small and a
/// replay happens once per open, so one lock for every store costs nothing
/// measurable.
static RECORD_IO: Mutex<()> = Mutex::new(());

fn record_io() -> MutexGuard<'static, ()> {
    RECORD_IO
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Where accepted, uncommitted language-server evidence is recorded.
fn path(layout: &KinLayout) -> PathBuf {
    layout.root().join("lsp-accepted-evidence.jsonl")
}

/// A line that retires the recorded evidence of these files.
#[derive(serde::Serialize, serde::Deserialize)]
struct Retirement {
    retired_files: Vec<String>,
}

/// How every retirement line starts. A relation line starts with its own
/// first field, so the two can be told apart without parsing a line twice.
const RETIREMENT_PREFIX: &[u8] = b"{\"retired_files\":";

fn encode_lines(relations: &[Relation]) -> serde_json::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    for relation in relations {
        serde_json::to_writer(
            &mut bytes,
            &kin_core::lsp_scope::AcceptedRelation {
                relation: relation.clone(),
                python_workspace_scope: Some(kin_core::lsp_scope::WORKSPACE_SCOPE),
            },
        )?;
        bytes.push(b'\n');
    }
    Ok(bytes)
}

/// One recorded line, as replay reads it.
enum Line {
    Relation(Relation),
    Retirement(Vec<String>),
    Blank,
    Unparsed,
}

fn parse_line(line: &[u8]) -> Line {
    if line.iter().all(u8::is_ascii_whitespace) {
        return Line::Blank;
    }
    if line.starts_with(RETIREMENT_PREFIX) {
        return serde_json::from_slice::<Retirement>(line).map_or(Line::Unparsed, |retirement| {
            Line::Retirement(retirement.retired_files)
        });
    }
    serde_json::from_slice::<Relation>(line).map_or(Line::Unparsed, Line::Relation)
}

/// What the first of replay's two readings learned: which line holds each
/// relation's latest version, and when each file was last retired.
#[derive(Default)]
struct Index {
    latest: HashMap<RelationId, usize>,
    retired_at: HashMap<String, usize>,
    lines: usize,
    unparsed: usize,
}

impl Index {
    /// Whether the relation recorded on line `sequence` is the one replay
    /// reinstalls: its latest version, and not retired after it was recorded.
    fn keeps(&self, sequence: usize, relation: &Relation) -> bool {
        self.latest.get(&relation.id) == Some(&sequence)
            && !relation.evidence.iter().any(|evidence| {
                evidence.source_span.as_ref().is_some_and(|span| {
                    self.retired_at
                        .get(span.file.0.as_str())
                        .is_some_and(|retired| *retired > sequence)
                })
            })
    }
}

/// Stream every line of the record to `visit`, in order.
///
/// `Ok(false)` when there is no record. An IO error part way through is an
/// error, so no caller rewrites a record it has not read to the end.
fn read(layout: &KinLayout, mut visit: impl FnMut(usize, &[u8])) -> std::io::Result<bool> {
    let file = match std::fs::File::open(path(layout)) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error),
    };
    read_lines(std::io::BufReader::new(file), &mut visit)
}

fn read_lines(
    reader: impl std::io::BufRead,
    mut visit: impl FnMut(usize, &[u8]),
) -> std::io::Result<bool> {
    for (sequence, line) in reader.split(b'\n').enumerate() {
        visit(sequence, &line?);
    }
    Ok(true)
}

/// Replace the record, atomically and durably, with the lines `write` emits.
///
/// Staged beside the record, synced, renamed over it, and the directory
/// synced, so a crash leaves the old record or the new one and never a
/// truncated file, and the rename itself survives a power loss.
fn rewrite(
    layout: &KinLayout,
    write: impl FnOnce(&mut std::io::BufWriter<std::fs::File>) -> std::io::Result<()>,
) -> std::io::Result<()> {
    let target = path(layout);
    let staged = target.with_extension(format!("jsonl.compact-{}", std::process::id()));
    let replaced = (|| {
        let mut writer = std::io::BufWriter::new(std::fs::File::create(&staged)?);
        write(&mut writer)?;
        let file = writer.into_inner().map_err(|error| error.into_error())?;
        file.sync_all()?;
        std::fs::rename(&staged, &target)
    })();
    if replaced.is_err() {
        let _ = std::fs::remove_file(&staged);
    }
    replaced?;
    if let Some(parent) = target.parent() {
        crate::state::sync_directory_metadata(parent)?;
    }
    Ok(())
}

/// Append complete lines to the record, creating it only when `create` says to.
///
/// A process that died mid-write leaves a torn last line with no newline. The
/// next append starts a line of its own first, or its first line would be
/// glued onto the torn one and lost with it, and a lost retirement brings back
/// the relations it retired.
fn append(layout: &KinLayout, bytes: &[u8], create: bool) -> std::io::Result<()> {
    use std::io::{Read as _, Seek as _};
    let opened = std::fs::OpenOptions::new()
        .create(create)
        .read(true)
        .append(true)
        .open(path(layout));
    match opened {
        Ok(mut handle) => {
            let len = handle.metadata()?.len();
            if len > 0 {
                let mut last = [0u8; 1];
                handle.seek(std::io::SeekFrom::Start(len - 1))?;
                handle.read_exact(&mut last)?;
                if last[0] != b'\n' {
                    handle.write_all(b"\n")?;
                }
            }
            handle.write_all(bytes)
        }
        // Nothing recorded, so nothing to retire.
        Err(error) if !create && error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

/// Record evidence this store has just accepted into its live graph.
///
/// Called with the relations the graph actually holds after the install, not
/// the ones that were offered: a relation the graph refused is not evidence
/// this store accepted and must not come back on the next start.
///
/// Answers whether the relations were recorded. One that was not is still in
/// the live graph and reaches authority at the next publication, but a crash
/// before then loses it. The warning names every one, so the affected subset
/// can be found in the daemon log after that crash.
pub(crate) fn record(layout: &KinLayout, accepted: &[Relation]) -> bool {
    if accepted.is_empty() {
        return true;
    }
    let bytes = match encode_lines(accepted) {
        Ok(bytes) => bytes,
        Err(error) => {
            warn!(
                %error,
                relations = accepted.len(),
                unrecorded = %unrecorded_names(accepted),
                "could not encode accepted language-server evidence; these relations are not \
                 recorded and a crash before the next publication loses them"
            );
            return false;
        }
    };
    let _io = record_io();
    match append(layout, &bytes, true) {
        Ok(()) => true,
        Err(error) => {
            warn!(
                %error,
                relations = accepted.len(),
                unrecorded = %unrecorded_names(accepted),
                "could not record accepted language-server evidence; these relations are not \
                 recorded and a crash before the next publication loses them"
            );
            false
        }
    }
}

/// Every relation a failed write leaves unrecorded, each as `id src->dst`.
fn unrecorded_names(relations: &[Relation]) -> String {
    relations
        .iter()
        .map(|relation| format!("{} {}->{}", relation.id, relation.src, relation.dst))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Reinstall accepted evidence authority has not committed, before this graph
/// answers anything.
///
/// Returns the number of relations reinstalled. Each one goes through ordinary
/// graph admission, so an entry whose endpoints no longer exist is refused here
/// exactly as it would be on the live path, and dropped rather than retried
/// forever. An entry the graph already holds was committed by some publication
/// since it was recorded, so it is dropped too and the record shrinks back to
/// the evidence that is still only accepted.
///
/// Two streaming readings: the first learns each relation's latest line and
/// each file's last retirement, the second reinstalls what survives and writes
/// it into the replacement as it goes. If indexing cannot read the record to
/// its end, nothing is replayed: the unread suffix may retire or supersede a
/// relation in the prefix. The record stays intact for the next start.
pub(crate) fn replay(layout: &KinLayout, graph: &InMemoryGraph) -> usize {
    replay_with_read(layout, graph, |visit| read(layout, visit))
}

fn replay_with_read(
    layout: &KinLayout,
    graph: &InMemoryGraph,
    mut read_record: impl FnMut(&mut dyn FnMut(usize, &[u8])) -> std::io::Result<bool>,
) -> usize {
    let _io = record_io();
    let mut index = Index::default();
    let indexed = read_record(&mut |sequence, line| match parse_line(line) {
        Line::Relation(relation) => {
            index.lines += 1;
            index.latest.insert(relation.id, sequence);
        }
        Line::Retirement(files) => {
            index.lines += 1;
            for file in files {
                index.retired_at.insert(file, sequence);
            }
        }
        Line::Unparsed => index.unparsed += 1,
        Line::Blank => {}
    });
    match indexed {
        Ok(false) => return 0,
        Ok(true) => {}
        Err(error) => {
            warn!(
                %error,
                "the accepted language-server evidence record could not be read to its end; \
                 replaying nothing and leaving the record for the next start"
            );
            return 0;
        }
    };
    if index.unparsed > 0 {
        debug!(
            unparsed = index.unparsed,
            "skipped unparsable accepted-evidence lines; a torn tail is the expected case"
        );
    }
    if index.lines == 0 {
        return 0;
    }

    let mut replayed = 0usize;
    let mut refused = 0usize;
    let mut committed = 0usize;
    let mut reinstall = |sequence: usize, line: &[u8], out: &mut dyn std::io::Write| {
        let Line::Relation(relation) = parse_line(line) else {
            return Ok(());
        };
        if !index.keeps(sequence, &relation) {
            return Ok(());
        }
        // This also fences a crash after the upgrade committed its removals
        // but before it cleaned the journal. Spanless old records are classified
        // by admitted endpoint language, not by a filename or a guessed name.
        let scope = serde_json::from_slice::<kin_core::lsp_scope::AcceptedRelation>(line)
            .ok()
            .and_then(|record| record.python_workspace_scope);
        if scope != Some(kin_core::lsp_scope::WORKSPACE_SCOPE)
            && kin_core::lsp_scope::is_python_relation(&relation, |id| {
                graph
                    .get_entity(id)
                    .ok()
                    .flatten()
                    .map(|entity| entity.language)
            })
        {
            refused += 1;
            return Ok(());
        }
        if graph.get_relation_by_id(&relation.id).is_some() {
            committed += 1;
            return Ok(());
        }
        let endpoints_present = [relation.src, relation.dst]
            .into_iter()
            .all(|node| match node {
                kin_model::GraphNodeId::Entity(id) => {
                    graph.get_entity(&id).ok().flatten().is_some()
                }
                kin_model::GraphNodeId::Artifact(id) => graph.resolved_tree().get(&id).is_some(),
                kin_model::GraphNodeId::ExternalReference(id) => {
                    graph.get_external_reference(&id).is_some()
                }
                _ => false,
            });
        if !endpoints_present {
            refused += 1;
            debug!(
                relation = %relation.id,
                "this graph refuses a recorded language-server relation with unadmitted endpoint; dropping it"
            );
            return Ok(());
        }
        match graph.upsert_relation(&relation) {
            Ok(_) => {
                replayed += 1;
                out.write_all(line)?;
                out.write_all(b"\n")
            }
            Err(error) => {
                refused += 1;
                debug!(
                    relation = %relation.id,
                    %error,
                    "this graph refuses a recorded language-server relation; dropping it"
                );
                Ok(())
            }
        }
    };

    let rewritten = rewrite(layout, |out| {
        let mut failed = None;
        read_record(&mut |sequence, line| {
            if failed.is_none() {
                failed = reinstall(sequence, line, out).err();
            }
        })?;
        failed.map_or(Ok(()), Err)
    });
    if let Err(error) = rewritten {
        warn!(
            %error,
            "could not rewrite the accepted language-server evidence record; the next start \
             replays it again"
        );
    }
    // No binding-history re-qualification here, deliberately. Replaying an
    // accepted language-server edge installs unverified input, and putting the
    // checked witness back over it restored a checked capability inside an
    // interval a crash prefix has to leave unknown. Two crash-prefix controls
    // grade that directly.
    if replayed > 0 || refused > 0 || committed > 0 {
        info!(
            replayed,
            committed,
            refused,
            "restored language-server evidence this store accepted and authority has not \
             committed"
        );
    }
    replayed
}

/// Drop the recorded evidence for files whose enrichment marker is being
/// retired, so the record and the marker say the same thing about a file.
///
/// Appended rather than rewritten: the retirement applies to every line
/// written before it and to none written after, which is the evidence accepted
/// for the file's new bytes.
pub(crate) fn retire(layout: &KinLayout, files: &[String]) {
    if files.is_empty() {
        return;
    }
    let mut line = match serde_json::to_vec(&Retirement {
        retired_files: files.to_vec(),
    }) {
        Ok(line) => line,
        Err(error) => {
            warn!(%error, "could not encode an accepted-evidence retirement");
            return;
        }
    };
    line.push(b'\n');
    let _io = record_io();
    if let Err(error) = append(layout, &line, false) {
        warn!(
            %error,
            files = files.len(),
            "could not retire accepted language-server evidence; the next start may replay \
             relations for files that have since changed"
        );
    }
}

/// Drop every recorded entry, for the case where the whole marker set goes and
/// for every authority commit.
pub(crate) fn clear(layout: &KinLayout) {
    let _io = record_io();
    let emptied = std::fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path(layout));
    match emptied {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => warn!(%error, "could not clear the accepted language-server evidence record"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{
        EntityId, FilePathId, GraphNodeId, RelationEvidence, RelationKind, RelationOrigin,
        SourceSpan,
    };

    fn layout() -> (tempfile::TempDir, KinLayout) {
        let root = tempfile::tempdir().unwrap();
        let layout = kin_core::init(root.path()).unwrap().layout;
        (root, layout)
    }

    fn relation(file: &str) -> Relation {
        Relation {
            id: RelationId::new(),
            kind: RelationKind::References,
            src: GraphNodeId::Entity(EntityId::new()),
            dst: GraphNodeId::Entity(EntityId::new()),
            confidence: 0.95,
            origin: RelationOrigin::Lsp,
            created_in: None,
            import_source: None,
            evidence: vec![RelationEvidence {
                source_span: Some(SourceSpan {
                    file: FilePathId::new(file),
                    start_byte: 0,
                    end_byte: 1,
                    start_line: 0,
                    start_col: 0,
                    end_line: 0,
                    end_col: 1,
                }),
                parser_rule: Some("lsp_references".to_string()),
                occurrence_count: 1,
                ..Default::default()
            }],
        }
    }

    /// The relation ids replay would reinstall, sorted.
    fn surviving(layout: &KinLayout) -> Vec<RelationId> {
        let mut index = Index::default();
        read(layout, |sequence, line| match parse_line(line) {
            Line::Relation(relation) => {
                index.latest.insert(relation.id, sequence);
            }
            Line::Retirement(files) => {
                for file in files {
                    index.retired_at.insert(file, sequence);
                }
            }
            _ => {}
        })
        .unwrap();
        let mut kept = Vec::new();
        read(layout, |sequence, line| {
            if let Line::Relation(relation) = parse_line(line) {
                if index.keeps(sequence, &relation) {
                    kept.push(relation.id);
                }
            }
        })
        .unwrap();
        kept.sort();
        kept
    }

    fn ids(relations: &[Relation]) -> Vec<RelationId> {
        let mut ids: Vec<_> = relations.iter().map(|relation| relation.id).collect();
        ids.sort();
        ids
    }

    /// Recording keeps going past the size the record used to refuse at, and
    /// every relation recorded reads back.
    #[test]
    fn a_record_larger_than_the_old_limit_keeps_every_relation() {
        const OLD_LIMIT: u64 = 16 * 1024 * 1024;
        let (_root, layout) = layout();
        let batch: Vec<Relation> = (0..512).map(|_| relation("pkg/a.go")).collect();
        let line_bytes = encode_lines(&batch).unwrap().len() as u64;
        let batches = OLD_LIMIT / line_bytes + 2;
        let mut recorded = Vec::new();
        for _ in 0..batches {
            let batch: Vec<Relation> = (0..512).map(|_| relation("pkg/a.go")).collect();
            assert!(record(&layout, &batch));
            recorded.extend(batch);
        }
        assert!(std::fs::metadata(path(&layout)).unwrap().len() > OLD_LIMIT);
        assert_eq!(surviving(&layout), ids(&recorded));
    }

    /// A retirement drops what was recorded for its files before it, keeps
    /// what was recorded after it, and leaves other files alone.
    #[test]
    fn a_retirement_applies_to_earlier_lines_only() {
        let (_root, layout) = layout();
        let before = relation("pkg/changed.go");
        let untouched = relation("pkg/other.go");
        assert!(record(&layout, &[before.clone(), untouched.clone()]));
        retire(&layout, &["pkg/changed.go".to_string()]);
        let after = relation("pkg/changed.go");
        assert!(record(&layout, std::slice::from_ref(&after)));
        assert_eq!(surviving(&layout), ids(&[untouched, after]));
    }

    fn admit_endpoints(
        graph: &InMemoryGraph,
        relation: &Relation,
        language: kin_model::LanguageId,
    ) {
        for node in [relation.src, relation.dst] {
            let GraphNodeId::Entity(id) = node else {
                unreachable!()
            };
            graph
                .upsert_entity(&kin_model::Entity {
                    id,
                    kind: kin_model::EntityKind::Function,
                    name: id.to_string(),
                    language,
                    fingerprint: kin_model::SemanticFingerprint {
                        algorithm: kin_model::FingerprintAlgorithm::V1TreeSitter,
                        ast_hash: kin_model::Hash256::from_bytes([1; 32]),
                        signature_hash: kin_model::Hash256::from_bytes([2; 32]),
                        behavior_hash: kin_model::Hash256::from_bytes([3; 32]),
                        equivalence_hash: kin_model::Hash256::from_bytes([4; 32]),
                        stability_score: 1.0,
                    },
                    file_origin: None,
                    span: None,
                    signature: String::new(),
                    visibility: kin_model::Visibility::Public,
                    role: kin_model::EntityRole::Source,
                    doc_summary: None,
                    metadata: kin_model::EntityMetadata::default(),
                    lineage_parent: None,
                    created_in: None,
                    superseded_by: None,
                })
                .unwrap();
        }
    }

    #[test]
    fn python_scope_upgrade_never_replays_old_target_but_keeps_new_and_other_evidence() {
        let (_root, layout) = layout();
        let graph = InMemoryGraph::new();
        let mut old = relation("source.py");
        old.evidence.clear(); // A legacy record with no source span still has owned endpoints.
        admit_endpoints(&graph, &old, kin_model::LanguageId::Python);
        let mut current = relation("source.py");
        current.src = old.src;
        admit_endpoints(&graph, &current, kin_model::LanguageId::Python);
        let other = relation("other.go");
        admit_endpoints(&graph, &other, kin_model::LanguageId::Go);
        let mut manual = old.clone();
        manual.id = RelationId::new();
        manual.origin = RelationOrigin::Manual;
        // These are pre-scope journal bytes, including an unrelated old-format row.
        let mut legacy = Vec::new();
        for relation in [&old, &other, &manual] {
            serde_json::to_writer(&mut legacy, relation).unwrap();
            legacy.push(b'\n');
        }
        std::fs::write(path(&layout), &legacy).unwrap();
        assert!(record(&layout, std::slice::from_ref(&current)));
        assert_eq!(replay(&layout, &graph), 3);
        assert!(graph.get_relation_by_id(&old.id).is_none());
        for relation in [&current, &other, &manual] {
            assert_eq!(
                graph.get_relation_by_id(&relation.id).as_ref(),
                Some(relation)
            );
        }
        // Repeating the crash-prefix open cannot resurrect the retired target.
        assert_eq!(replay(&layout, &graph), 0);
        assert!(graph.get_relation_by_id(&old.id).is_none());
    }

    /// A real read failure after the first complete relation, before a later
    /// retirement or update, must not give that prefix replay authority.
    fn assert_incomplete_index_refuses_replay(retired: bool) {
        let (_root, layout) = layout();
        let graph = InMemoryGraph::new();
        let first = relation("pkg/a.go");
        for (node, name) in [(first.src, "caller"), (first.dst, "callee")] {
            let GraphNodeId::Entity(id) = node else {
                unreachable!()
            };
            graph
                .upsert_entity(&kin_model::Entity {
                    id,
                    kind: kin_model::EntityKind::Function,
                    name: name.to_string(),
                    language: kin_model::LanguageId::Go,
                    fingerprint: kin_model::SemanticFingerprint {
                        algorithm: kin_model::FingerprintAlgorithm::V1TreeSitter,
                        ast_hash: kin_model::Hash256::from_bytes([1; 32]),
                        signature_hash: kin_model::Hash256::from_bytes([2; 32]),
                        behavior_hash: kin_model::Hash256::from_bytes([3; 32]),
                        equivalence_hash: kin_model::Hash256::from_bytes([4; 32]),
                        stability_score: 1.0,
                    },
                    file_origin: Some(FilePathId::new("pkg/a.go")),
                    span: None,
                    signature: format!("func {name}()"),
                    visibility: kin_model::Visibility::Public,
                    role: kin_model::EntityRole::Source,
                    doc_summary: None,
                    metadata: kin_model::EntityMetadata::default(),
                    lineage_parent: None,
                    created_in: None,
                    superseded_by: None,
                })
                .unwrap();
        }
        assert!(record(&layout, std::slice::from_ref(&first)));
        if retired {
            retire(&layout, &["pkg/a.go".to_string()]);
        } else {
            let mut newer = first.clone();
            newer.confidence = 0.5;
            assert!(record(&layout, &[newer]));
        }
        let original = std::fs::read(path(&layout)).unwrap();
        let prefix = encode_lines(std::slice::from_ref(&first)).unwrap();
        assert!(original.starts_with(&prefix));
        assert!(
            original.len() > prefix.len(),
            "the authoritative suffix must exist"
        );

        struct FailAfterPrefix(std::io::Cursor<Vec<u8>>);
        impl std::io::Read for FailAfterPrefix {
            fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
                if self.0.position() == self.0.get_ref().len() as u64 {
                    return Err(std::io::Error::other("injected record read failure"));
                }
                std::io::Read::read(&mut self.0, out)
            }
        }
        let mut reads = 0;
        let mut indexed_lines = 0;
        let installed = replay_with_read(&layout, &graph, |visit| {
            reads += 1;
            if reads == 1 {
                read_lines(
                    std::io::BufReader::new(FailAfterPrefix(std::io::Cursor::new(prefix.clone()))),
                    |sequence, line| {
                        indexed_lines += 1;
                        visit(sequence, line);
                    },
                )
            } else {
                read(&layout, visit)
            }
        });
        assert_eq!(
            indexed_lines, 1,
            "failure follows one complete indexed relation"
        );
        assert_eq!(
            installed, 0,
            "an incomplete index cannot authorize any replay"
        );
        assert!(graph.get_relation_by_id(&first.id).is_none());
        assert_eq!(
            std::fs::read(path(&layout)).unwrap(),
            original,
            "retain all original evidence"
        );
        assert_eq!(reads, 1, "do not reread using a partial index");

        // A later healthy replay must still observe the previously unread suffix.
        assert_eq!(replay(&layout, &graph), usize::from(!retired));
        if retired {
            assert!(graph.get_relation_by_id(&first.id).is_none());
        } else {
            assert_eq!(graph.get_relation_by_id(&first.id).unwrap().confidence, 0.5);
        }
    }

    #[test]
    fn an_index_read_error_before_a_retirement_installs_nothing() {
        assert_incomplete_index_refuses_replay(true);
    }

    #[test]
    fn an_index_read_error_before_a_newer_version_installs_nothing() {
        assert_incomplete_index_refuses_replay(false);
    }

    /// A relation recorded twice is replayed at its latest version only.
    #[test]
    fn the_latest_line_for_a_relation_wins() {
        let (_root, layout) = layout();
        let first = relation("pkg/a.go");
        let mut again = first.clone();
        again.confidence = 0.5;
        assert!(record(&layout, std::slice::from_ref(&first)));
        assert!(record(&layout, std::slice::from_ref(&again)));
        let mut latest = HashMap::new();
        read(&layout, |sequence, line| {
            if let Line::Relation(relation) = parse_line(line) {
                latest.insert(relation.id, (sequence, relation.confidence));
            }
        })
        .unwrap();
        assert_eq!(latest[&first.id], (1, 0.5));
        assert_eq!(surviving(&layout), vec![first.id]);
    }

    /// Retiring a store that recorded nothing writes nothing.
    #[test]
    fn retiring_without_a_record_creates_none() {
        let (_root, layout) = layout();
        retire(&layout, &["pkg/a.go".to_string()]);
        assert!(!path(&layout).exists());
    }

    /// A torn last line costs that line only, and what is appended after it
    /// starts a line of its own, so a retirement written next is not lost with
    /// the torn tail.
    #[test]
    fn a_torn_tail_loses_only_the_partial_line() {
        let (_root, layout) = layout();
        let kept = relation("pkg/a.go");
        assert!(record(&layout, std::slice::from_ref(&kept)));
        append(&layout, b"{\"id\":\"torn", true).unwrap();
        assert_eq!(surviving(&layout), ids(std::slice::from_ref(&kept)));
        retire(&layout, &["pkg/a.go".to_string()]);
        let after = relation("pkg/a.go");
        assert!(record(&layout, std::slice::from_ref(&after)));
        assert_eq!(surviving(&layout), ids(&[after]));
    }

    /// A failed write names every relation it left unrecorded.
    #[test]
    fn an_unrecorded_warning_names_every_relation_it_lost() {
        let relations: Vec<Relation> = (0..40).map(|_| relation("pkg/a.go")).collect();
        let names = unrecorded_names(&relations);
        for relation in &relations {
            assert!(names.contains(&format!(
                "{} {}->{}",
                relation.id, relation.src, relation.dst
            )));
        }
    }

    /// Clearing empties the record, and an absent record stays absent.
    #[test]
    fn clearing_empties_the_record() {
        let (_root, layout) = layout();
        clear(&layout);
        assert!(!path(&layout).exists());
        assert!(record(&layout, &[relation("pkg/a.go")]));
        clear(&layout);
        assert_eq!(std::fs::metadata(path(&layout)).unwrap().len(), 0);
        assert!(surviving(&layout).is_empty());
    }
}
