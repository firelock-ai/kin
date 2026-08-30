// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use hashbrown::HashMap as FastHashMap;
use serde::de::{IgnoredAny, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fmt;

use crate::storage::change_validation::{validate_semantic_change_entries, AdmittedChangeMap};
use crate::storage::repository::{GitProjectionTreeReplay, PersistedRepositoryAuthority};
use crate::types::*;

/// Statistics from a snapshot compaction pass.
///
/// Reports what was removed during garbage collection so callers can
/// log or surface compaction results.
#[derive(Debug, Clone, Default)]
pub struct CompactionStats {
    /// Relations removed because src or dst entity no longer exists.
    pub orphaned_relations_removed: usize,
    /// Outgoing edge-list entries cleaned (non-existent entities or relations).
    pub orphaned_outgoing_cleaned: usize,
    /// Incoming edge-list entries cleaned (non-existent entities or relations).
    pub orphaned_incoming_cleaned: usize,
    /// Mock hints removed (non-existent test).
    pub orphaned_mock_hints_removed: usize,
    /// Downstream warnings removed (non-existent intent or entity).
    pub orphaned_downstream_warnings_removed: usize,
    /// Approvals removed (non-existent change).
    pub orphaned_approvals_removed: usize,
    /// Delegations removed (non-existent actor).
    pub orphaned_delegations_removed: usize,
    /// Entity count before compaction.
    pub entities_before: usize,
    /// Relation count before compaction.
    pub relations_before: usize,
    /// Relation count after compaction.
    pub relations_after: usize,
}

impl CompactionStats {
    /// Total number of orphaned items removed across all collections.
    pub fn total_removed(&self) -> usize {
        self.orphaned_relations_removed
            + self.orphaned_outgoing_cleaned
            + self.orphaned_incoming_cleaned
            + self.orphaned_mock_hints_removed
            + self.orphaned_downstream_warnings_removed
            + self.orphaned_approvals_removed
            + self.orphaned_delegations_removed
    }

    /// True if compaction removed nothing (graph was already clean).
    pub fn is_clean(&self) -> bool {
        self.total_removed() == 0
    }
}

/// A writer that counts bytes and keeps none of them.
///
/// The snapshot frame carries its body's length in a header that sits ahead of
/// the body, so the length has to be known before the first body byte is
/// written. Serializing into a throwaway `Vec` to learn it costs one whole copy
/// of the repository; counting costs nothing.
#[derive(Default)]
pub(crate) struct CountingWriter {
    written: usize,
}

impl CountingWriter {
    /// Bytes this writer was handed.
    pub(crate) fn written(&self) -> usize {
        self.written
    }
}

impl std::io::Write for CountingWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.written += buf.len();
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Assemble one `KNDB` frame around a serializable snapshot body, in one buffer.
///
/// This used to serialize the body into its own `Vec` and then copy it into a
/// second, exactly-sized frame buffer, so both existed at once. The body of a
/// converted repository IS the repository: on psf/requests at full history it
/// is about a gigabyte, and that copy is what made
/// `kindb.commit.persist_successor` the moment a conversion reaches its
/// whole-run peak.
///
/// The body's length goes in the header, which sits AHEAD of the body, so one
/// streaming pass cannot know what to write there. It is counted first, over
/// the same walk that produces the bytes second, by a writer that allocates
/// nothing. Two passes of CPU buys one copy of the repository, and the buffer
/// is then exactly sized, so the writing pass never reallocates and never holds
/// a half-grown copy beside a growing one.
fn assemble_snapshot_frame<T: Serialize + ?Sized>(
    body: &T,
    persisted_root_hash: Option<[u8; 32]>,
    trailer_len: usize,
) -> Result<Vec<u8>, crate::error::KinDbError> {
    let mut counter = CountingWriter::default();
    write_snapshot_body(&mut counter, body)?;
    let body_len = counter.written();

    let mut buf = Vec::with_capacity(16 + body_len + GraphSnapshot::CHECKSUM_LEN + trailer_len);
    buf.extend_from_slice(&GraphSnapshot::MAGIC);
    buf.extend_from_slice(&GraphSnapshot::CURRENT_VERSION.to_le_bytes());
    buf.extend_from_slice(&(body_len as u64).to_le_bytes());
    write_snapshot_body(&mut buf, body)?;

    // The two passes have to agree. A writing pass that produced a different
    // number of bytes than the counting pass declared would mint a well-formed
    // header describing a body nobody wrote, and every reader would slice the
    // frame at the wrong offset. It fails loud instead.
    let written = buf.len() - 16;
    if written != body_len {
        return Err(crate::error::KinDbError::StorageError(format!(
            "snapshot body length pass counted {body_len} bytes and the writing pass produced \
             {written}; refusing to frame a body the header does not describe"
        )));
    }

    let body_checksum: [u8; 32] = Sha256::digest(&buf[16..]).into();
    buf.extend_from_slice(&body_checksum);
    if let Some(root_hash) = persisted_root_hash {
        GraphSnapshot::append_root_hash_trailer(&mut buf, body_checksum, root_hash);
    }

    Ok(buf)
}

/// One definition of the MessagePack body, used by the counting pass and the
/// writing pass, so the length in the header and the bytes it describes can
/// never come from two different encoders.
fn write_snapshot_body<W: std::io::Write, T: Serialize + ?Sized>(
    out: &mut W,
    body: &T,
) -> Result<(), crate::error::KinDbError> {
    rmp_serde::encode::write(out, body)
        .map_err(|e| crate::error::KinDbError::StorageError(format!("serialization failed: {e}")))
}

/// Whether a snapshot's authority envelope takes part in its storage admission.
///
/// A stored snapshot validates its envelope against itself. A history replay
/// deliberately does not: it proves the authority-free payload, because the
/// envelope belongs to the caller that is publishing it and the replay is
/// checking the payload underneath. The distinction used to be carried by
/// cloning the whole snapshot and nulling one field, which on a full-history
/// conversion allocated a second copy of the repository to express one bit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthorityEnvelope {
    /// Validate the envelope against the snapshot it is stored with.
    Validated,
    /// Skip the envelope, exactly as a snapshot carrying none would.
    Ignored,
}

/// Deserialize every entry of a map with its real key and value types, and keep
/// none of them.
///
/// The write path proves a snapshot round-trips before it writes the bytes, and
/// on a converted repository that proof was the single largest allocation a
/// conversion made: `rmp_serde::from_slice::<GraphSnapshot>` materialized the
/// whole graph, about 855 MiB, purely to drop it (FIR-2654). What the proof
/// needs is that every element PARSES as the type it was written from, not that
/// the collections are assembled.
///
/// `serde::de::IgnoredAny` would be far cheaper and would prove nothing: it
/// accepts any well-formed MessagePack, so a map of the wrong element type
/// passes. This visits each entry with the declared `K` and `V`, so custom
/// `Deserialize` impls and `deserialize_with` hooks still run, and the entry is
/// dropped as soon as it has been proved.
pub(crate) struct DrainMap<K, V> {
    pub(crate) len: usize,
    _marker: std::marker::PhantomData<(K, V)>,
}

impl<'de, K, V> serde::Deserialize<'de> for DrainMap<K, V>
where
    K: serde::Deserialize<'de>,
    V: serde::Deserialize<'de>,
{
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor<K, V>(std::marker::PhantomData<(K, V)>);
        impl<'de, K, V> serde::de::Visitor<'de> for Visitor<K, V>
        where
            K: serde::Deserialize<'de>,
            V: serde::Deserialize<'de>,
        {
            type Value = DrainMap<K, V>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a map whose entries parse as their declared types")
            }
            fn visit_map<A: serde::de::MapAccess<'de>>(
                self,
                mut access: A,
            ) -> Result<Self::Value, A::Error> {
                let mut len = 0usize;
                // The entry is bound and dropped inside the loop: peak is one
                // entry, not the whole map.
                while access.next_entry::<K, V>()?.is_some() {
                    len += 1;
                }
                Ok(DrainMap {
                    len,
                    _marker: std::marker::PhantomData,
                })
            }
        }
        deserializer.deserialize_map(Visitor(std::marker::PhantomData))
    }
}

/// The sequence form of [`DrainMap`], with the same contract.
pub(crate) struct DrainSeq<T> {
    pub(crate) len: usize,
    _marker: std::marker::PhantomData<T>,
}

impl<'de, T> serde::Deserialize<'de> for DrainSeq<T>
where
    T: serde::Deserialize<'de>,
{
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Visitor<T>(std::marker::PhantomData<T>);
        impl<'de, T> serde::de::Visitor<'de> for Visitor<T>
        where
            T: serde::Deserialize<'de>,
        {
            type Value = DrainSeq<T>;
            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a sequence whose elements parse as their declared type")
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut access: A,
            ) -> Result<Self::Value, A::Error> {
                let mut len = 0usize;
                while access.next_element::<T>()?.is_some() {
                    len += 1;
                }
                Ok(DrainSeq {
                    len,
                    _marker: std::marker::PhantomData,
                })
            }
        }
        deserializer.deserialize_seq(Visitor(std::marker::PhantomData))
    }
}

/// [`GraphSnapshot`]'s shape, for proving bytes round-trip without keeping them.
///
/// Every field appears here, in `GraphSnapshot`'s order, because the on-disk
/// body is compact MessagePack: a struct is a positional ARRAY, so this type's
/// field count is part of the format it decodes. A field added to
/// `GraphSnapshot` and not to this mirror therefore fails LOUDLY, with
/// `array had incorrect length`, rather than silently proving less than it
/// claims. That property is what makes a hand-maintained mirror safe, and
/// `round_trip_proof_notices_a_field_added_to_the_snapshot` holds it.
///
/// The large collections are drained; everything else keeps its real type, so
/// the authority envelope's `deserialize_with` hook still runs here exactly as
/// it does in a full decode.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub(crate) struct GraphSnapshotRoundTripProof {
    pub(crate) version: u32,
    pub(crate) entities: DrainMap<EntityId, Entity>,
    pub(crate) relations: DrainMap<RelationId, Relation>,
    pub(crate) outgoing: DrainMap<EntityId, Vec<RelationId>>,
    pub(crate) incoming: DrainMap<EntityId, Vec<RelationId>>,
    pub(crate) changes: DrainMap<SemanticChangeId, SemanticChange>,
    pub(crate) change_children: DrainMap<SemanticChangeId, Vec<SemanticChangeId>>,
    pub(crate) work_items: DrainMap<WorkId, WorkItem>,
    pub(crate) annotations: DrainMap<AnnotationId, Annotation>,
    pub(crate) work_links: DrainSeq<WorkLink>,
    pub(crate) reviews: DrainMap<ReviewId, Review>,
    pub(crate) review_decisions: DrainMap<ReviewId, Vec<ReviewDecision>>,
    pub(crate) review_notes: DrainSeq<ReviewNote>,
    pub(crate) review_discussions: DrainSeq<ReviewDiscussion>,
    pub(crate) review_assignments: DrainMap<ReviewId, Vec<ReviewAssignment>>,
    pub(crate) test_cases: DrainMap<TestId, TestCase>,
    pub(crate) assertions: DrainMap<AssertionId, Assertion>,
    pub(crate) verification_runs: DrainMap<VerificationRunId, VerificationRun>,
    pub(crate) mock_hints: DrainSeq<MockHint>,
    pub(crate) contracts: DrainMap<ContractId, Contract>,
    pub(crate) actors: DrainMap<ActorId, Actor>,
    pub(crate) delegations: DrainSeq<Delegation>,
    pub(crate) approvals: DrainSeq<Approval>,
    pub(crate) audit_events: DrainSeq<AuditEvent>,
    pub(crate) shallow_files: DrainSeq<ShallowTrackedFile>,
    pub(crate) file_layouts: DrainSeq<FileLayout>,
    pub(crate) structured_artifacts: DrainSeq<StructuredArtifact>,
    pub(crate) opaque_artifacts: DrainSeq<OpaqueArtifact>,
    pub(crate) resolved_tree: ResolvedTree,
    pub(crate) sessions: DrainMap<SessionId, AgentSession>,
    pub(crate) intents: DrainMap<IntentId, Intent>,
    pub(crate) downstream_warnings: DrainSeq<(IntentId, EntityId, String)>,
    pub(crate) entity_revisions: DrainMap<EntityId, Vec<EntityRevision>>,
    pub(crate) repository_authority: Option<PersistedRepositoryAuthority>,
    pub(crate) external_references: DrainMap<ExternalReferenceId, ExternalReference>,
    /// Mirrors the appended v14 field, with the same `default` so this proof
    /// reads a v13 body exactly as the real decoder does.
    #[serde(default)]
    pub(crate) materialized_graph: Option<MaterializedGraphSection>,
}

/// Schema of [`MaterializedGraphSection`] itself.
///
/// Separate from the snapshot format version because the two move for
/// different reasons. The snapshot version changes when the positional body
/// changes width; this changes when what a field inside the section MEANS
/// moves. A section whose schema this binary does not know is ignored and the
/// graph is replayed, which is always available, so an unknown schema costs
/// time and never correctness.
pub const MATERIALIZED_GRAPH_SCHEMA_VERSION: u32 = 1;

/// The resolved graph at one change, persisted beside the history it was
/// folded from.
///
/// A converted repository's snapshot IS its history: the `changes` map is
/// most of the body, while the entities and relations a daemon actually serves
/// are absent from the file and folded out of that history at every open by
/// `ChangeStore::resolve_graph_at`. This section is that fold, written once by
/// the publish that produced it and read directly afterwards.
///
/// It is derived state, not authority, and the distinction is load-bearing.
/// Nothing here is hashed into any authority root, because the authority over a
/// graph is the change it resolves at; adding a section therefore leaves a
/// repository's roots, and so its replicated identity, byte for byte what they
/// were. Every read checks the section against the change the caller wants
/// before trusting it, so a section that is not this caller's answer is ignored
/// rather than served.
///
/// `outgoing` and `incoming` are deliberately absent. Workspace
/// materialization rebuilds adjacency from `relations` already, so persisting
/// them would enlarge the section for no reader.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MaterializedGraphSection {
    /// Schema of this section. See [`MATERIALIZED_GRAPH_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// The change this graph is the resolution AT, and the whole binding.
    ///
    /// `kin_model::compute_semantic_change_id` hashes every immutable field of
    /// a change except `id` itself, and `parents` is one of them, so the change
    /// DAG is a Merkle DAG and an id determines its complete ancestry together
    /// with every delta in it. `resolve_graph_at` folds exactly that ancestry
    /// and reads nothing else. So naming the change names the graph: no other
    /// history can produce this id, and a reader that matches this against the
    /// target it wants has matched the content.
    ///
    /// An earlier draft also carried `RootBundle::history`, a hash over the
    /// WHOLE change map. It was dropped rather than kept as defence in depth,
    /// because it is not a weaker version of this check, it is a wrong one: a
    /// change appended anywhere moves that root while leaving the graph at this
    /// change identical, so a section that is still exactly correct would be
    /// refused after every commit and after every authority frame. A check that
    /// refuses correct answers is worse than no check when the remaining check
    /// is complete.
    ///
    /// Not an `Option`. A repository with no base target resolves to five
    /// empty maps and a default tree, which costs nothing to compute, so there
    /// is nothing there worth memoizing and no case where an absent section
    /// and an empty one have to be told apart.
    pub resolved_at: SemanticChangeId,
    /// Exactly what `ChangeStore::resolve_graph_at(resolved_at)` returns.
    ///
    /// Held whole rather than field by field so that the read path is a
    /// substitution rather than a reconstruction: whatever that call produces
    /// is what this carries, and a domain added to `ResolvedGraphState` later
    /// is carried here without anyone remembering to add it. Tombstones and
    /// entity revisions come along for the same reason, and the revisions
    /// matter on their own, since a graph built over a base with none re-derives
    /// a revision timeline across the whole history.
    pub state: ResolvedGraphState,
}

/// Why a persisted section was not used, named one reason at a time.
///
/// A refusal is a diagnosis rather than a shrug, in the shape
/// `PreparedWorkspaceGraphCache` already uses for the same class of decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MaterializedGraphRefusal {
    /// The snapshot carries no section. Every v13 store lands here.
    Absent,
    /// The section names a schema this binary does not know.
    Schema { held: u32, found: u32 },
    /// The section resolves at a different change than the caller asked for.
    Target,
}

impl std::fmt::Display for MaterializedGraphRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Absent => formatter.write_str("absent"),
            Self::Schema { held, found } => {
                write!(formatter, "schema (holding {held}, section names {found})")
            }
            Self::Target => formatter.write_str("resolved_at"),
        }
    }
}

/// The serializable snapshot of the entire graph state.
///
/// This is the on-disk format. We use std::collections::HashMap here
/// (not hashbrown) for stable serde compatibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GraphSnapshot {
    pub version: u32,
    pub entities: HashMap<EntityId, Entity>,
    pub relations: HashMap<RelationId, Relation>,
    pub outgoing: HashMap<EntityId, Vec<RelationId>>,
    pub incoming: HashMap<EntityId, Vec<RelationId>>,
    pub changes: HashMap<SemanticChangeId, SemanticChange>,
    pub change_children: HashMap<SemanticChangeId, Vec<SemanticChangeId>>,
    pub work_items: HashMap<WorkId, WorkItem>,
    pub annotations: HashMap<AnnotationId, Annotation>,
    pub work_links: Vec<WorkLink>,
    pub reviews: HashMap<ReviewId, Review>,
    pub review_decisions: HashMap<ReviewId, Vec<ReviewDecision>>,
    pub review_notes: Vec<ReviewNote>,
    pub review_discussions: Vec<ReviewDiscussion>,
    pub review_assignments: HashMap<ReviewId, Vec<ReviewAssignment>>,
    pub test_cases: HashMap<TestId, TestCase>,
    pub assertions: HashMap<AssertionId, Assertion>,
    pub verification_runs: HashMap<VerificationRunId, VerificationRun>,
    pub mock_hints: Vec<MockHint>,
    pub contracts: HashMap<ContractId, Contract>,
    pub actors: HashMap<ActorId, Actor>,
    pub delegations: Vec<Delegation>,
    pub approvals: Vec<Approval>,
    pub audit_events: Vec<AuditEvent>,
    pub shallow_files: Vec<ShallowTrackedFile>,
    pub file_layouts: Vec<FileLayout>,
    pub structured_artifacts: Vec<StructuredArtifact>,
    pub opaque_artifacts: Vec<OpaqueArtifact>,
    /// Exact graph-owned repository tree. Artifact identity, byte-exact path,
    /// content identity, and materialization kind are one validated authority.
    pub resolved_tree: ResolvedTree,
    pub sessions: HashMap<SessionId, AgentSession>,
    pub intents: HashMap<IntentId, Intent>,
    pub downstream_warnings: Vec<(IntentId, EntityId, String)>,
    pub entity_revisions: HashMap<EntityId, Vec<EntityRevision>>,
    /// One immutable, repository-scoped authority envelope.
    ///
    /// Legacy graph mutation paths leave this absent. Once present, refs,
    /// operation receipts, workspaces, aliases, admission state, and every
    /// root move only through a full repository transaction and full-snapshot
    /// CAS; incremental graph deltas are forbidden.
    #[serde(deserialize_with = "deserialize_required_repository_authority")]
    pub repository_authority: Option<PersistedRepositoryAuthority>,
    /// Resolved symbols owned outside this repository.
    ///
    /// Deliberately appended after every v12 field because MessagePack encodes
    /// this struct positionally. Reordering an existing field would reinterpret
    /// persisted bytes instead of failing closed at the v13 format boundary.
    pub external_references: HashMap<ExternalReferenceId, ExternalReference>,
    /// The resolved graph at one change, or `None` to derive it by replay.
    ///
    /// Appended after every v13 field, for the reason the field above records:
    /// MessagePack encodes this struct positionally, so appending fails closed
    /// at a format boundary while reordering would reinterpret persisted bytes.
    ///
    /// `serde(default)` is what lets ONE decoder read a v13 body and a v14
    /// body: the v13 array runs out of elements here and the field takes
    /// `None`. Nothing is skipped on serialize, so a v14 body is always 36
    /// elements wide and width stays a function of version alone, which is the
    /// property both partial decoders below use as their discriminator.
    #[serde(default)]
    pub materialized_graph: Option<MaterializedGraphSection>,
}

fn deserialize_required_repository_authority<'de, D>(
    deserializer: D,
) -> Result<Option<PersistedRepositoryAuthority>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Option::deserialize(deserializer)
}

/// The four graph domains a workspace mutation ever compares.
///
/// Deriving a workspace's cumulative semantic overlay and proving that overlay
/// reproduces the desired graph read entities, relations, external references
/// and the resolved tree, and read nothing else. Carrying those two steps on
/// whole `GraphSnapshot`s meant each of them also held a copy of every change
/// in the repository with its full entity, relation and tree delta payload,
/// plus change children, work items, annotations, reviews, verification runs,
/// provenance and sessions, none of which any comparison consults. On a
/// full-history conversion the change map IS the repository, so a snapshot
/// kept for four fields was a whole extra history.
///
/// This is a projection of a `GraphSnapshot`, never a substitute for one:
/// nothing is validated through it, and every value in it is the value the
/// snapshot's own field carried.
#[derive(Debug)]
pub struct WorkspaceGraphFacts {
    pub entities: HashMap<EntityId, Entity>,
    pub relations: HashMap<RelationId, Relation>,
    pub external_references: HashMap<ExternalReferenceId, ExternalReference>,
    pub resolved_tree: ResolvedTree,
}

impl WorkspaceGraphFacts {
    /// Take the compared domains out of a snapshot and drop the rest.
    ///
    /// Consuming rather than borrowing is the point: the domains move out and
    /// everything else is freed at the call, instead of staying alive beside
    /// the four fields a caller went on to read.
    pub fn from_snapshot(snapshot: GraphSnapshot) -> Self {
        Self {
            entities: snapshot.entities,
            relations: snapshot.relations,
            external_references: snapshot.external_references,
            resolved_tree: snapshot.resolved_tree,
        }
    }
}

/// Lightweight snapshot view for locate-only cold starts.
///
/// This intentionally decodes only the graph domains that `kin locate`
/// actually reads at query time:
/// - entities and relations
/// - semantic changes (for co-change time decay)
/// - file/artifact metadata
///
/// Large persisted adjacency lists (`outgoing`, `incoming`) are skipped here
/// because `InMemoryGraph::from_snapshot_*` rebuilds them from `relations`
/// anyway, so decoding them only adds cold-start cost.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct LocateGraphSnapshot {
    pub version: u32,
    pub entities: FastHashMap<EntityId, Entity>,
    pub relations: FastHashMap<RelationId, Relation>,
    pub changes: FastHashMap<SemanticChangeId, SemanticChange>,
    pub entity_revisions: FastHashMap<EntityId, Vec<EntityRevision>>,
    pub shallow_files: Vec<ShallowTrackedFile>,
    pub file_layouts: Vec<FileLayout>,
    pub structured_artifacts: Vec<StructuredArtifact>,
    pub opaque_artifacts: Vec<OpaqueArtifact>,
    pub resolved_tree: ResolvedTree,
    pub external_references: FastHashMap<ExternalReferenceId, ExternalReference>,
}

impl GraphSnapshot {
    /// Current format version.
    ///
    /// v14 APPENDS one element to the positional body, `materialized_graph`,
    /// and moves nothing. That is the whole reason the bump is cheap: a v13
    /// body is a v14 body with its last element missing, and the field's
    /// `serde(default)` supplies it, so one decoder reads both widths and no
    /// second copy of the field list exists to drift.
    pub const CURRENT_VERSION: u32 = 14;

    /// The oldest on-disk format version this binary opens.
    ///
    /// Deliberately a literal rather than `Self::CURRENT_VERSION`. While the
    /// two were one constant, every bump made every existing store unopenable
    /// on the same commit, which is the wrong price for a change that only
    /// appends a field. A store any shipped version wrote still opens here and
    /// still derives its graph by replay.
    pub const MIN_SUPPORTED_VERSION: u32 = 13;

    /// Magic bytes for the file header: "KNDB"
    pub const MAGIC: [u8; 4] = *b"KNDB";

    /// Size of the checksum appended to every current snapshot.
    pub const CHECKSUM_LEN: usize = 32;

    /// Optional trailer magic that binds a persisted graph-root cache value to
    /// the already-verified snapshot body checksum.
    const ROOT_HASH_TRAILER_MAGIC: [u8; 4] = *b"KRTH";
    const ROOT_HASH_TRAILER_LEN: usize = 4 + 32 + 32;

    pub fn empty() -> Self {
        Self {
            materialized_graph: None,
            version: Self::CURRENT_VERSION,
            entities: HashMap::new(),
            relations: HashMap::new(),
            outgoing: HashMap::new(),
            incoming: HashMap::new(),
            changes: HashMap::new(),
            change_children: HashMap::new(),
            work_items: HashMap::new(),
            annotations: HashMap::new(),
            work_links: Vec::new(),
            reviews: HashMap::new(),
            review_decisions: HashMap::new(),
            review_notes: Vec::new(),
            review_discussions: Vec::new(),
            review_assignments: HashMap::new(),
            test_cases: HashMap::new(),
            assertions: HashMap::new(),
            verification_runs: HashMap::new(),
            mock_hints: Vec::new(),
            contracts: HashMap::new(),
            actors: HashMap::new(),
            delegations: Vec::new(),
            approvals: Vec::new(),
            audit_events: Vec::new(),
            shallow_files: Vec::new(),
            file_layouts: Vec::new(),
            structured_artifacts: Vec::new(),
            opaque_artifacts: Vec::new(),
            resolved_tree: ResolvedTree::default(),
            sessions: HashMap::new(),
            intents: HashMap::new(),
            downstream_warnings: Vec::new(),
            entity_revisions: HashMap::new(),
            repository_authority: None,
            external_references: HashMap::new(),
        }
    }

    #[cfg(test)]
    pub(crate) fn admit_artifact_for_test(&mut self, path: String, entry: TreeEntry) -> ArtifactId {
        let path = RepoPath::from_utf8(&path).expect("valid test repository path");
        let existing = self.resolved_tree.artifact_at_path(&path).cloned();
        let artifact_id = existing
            .as_ref()
            .map(|artifact| artifact.artifact_id)
            .unwrap_or_else(ArtifactId::new);
        let mut artifacts: Vec<_> = self.resolved_tree.clone().into_artifacts().collect();
        artifacts.retain(|artifact| artifact.artifact_id != artifact_id);
        artifacts.push(ResolvedArtifact::new(artifact_id, path, entry));
        self.resolved_tree =
            ResolvedTree::from_artifacts(artifacts).expect("valid test repository tree");
        artifact_id
    }

    #[cfg(test)]
    pub(crate) fn tree_entry_for_test(&self, path: &str) -> Option<TreeEntry> {
        let path = RepoPath::from_utf8(path).ok()?;
        self.resolved_tree
            .artifact_at_path(&path)
            .map(|artifact| artifact.entry)
    }

    #[cfg(test)]
    pub(crate) fn has_artifact_path_for_test(&self, path: &str) -> bool {
        self.tree_entry_for_test(path).is_some()
    }

    /// Compact the snapshot by removing orphaned data.
    ///
    /// Performs garbage collection across all cross-referenced collections:
    /// - Relations whose src or dst entity no longer exists
    /// - Outgoing/incoming edge lists referencing non-existent entities or relations
    /// - Mock hints for non-existent tests
    /// - Downstream warnings for non-existent intents or entities
    /// - Approvals for non-existent changes
    /// - Delegations for non-existent actors
    ///
    /// For graphs with >500K entities, orphaned data can accumulate significantly
    /// after bulk deletions or re-indexes. This method ensures the snapshot
    /// contains only reachable, consistent data before serialization.
    pub fn compact(&mut self) -> CompactionStats {
        let mut stats = CompactionStats::default();
        stats.entities_before = self.entities.len();
        stats.relations_before = self.relations.len();

        // Build reference sets once — these are the "live" IDs.
        let entity_ids: HashSet<EntityId> = self.entities.keys().copied().collect();
        let test_ids: HashSet<TestId> = self.test_cases.keys().copied().collect();
        let contract_ids: HashSet<ContractId> = self.contracts.keys().copied().collect();
        let work_ids: HashSet<WorkId> = self.work_items.keys().copied().collect();
        let run_ids: HashSet<VerificationRunId> = self.verification_runs.keys().copied().collect();
        let external_reference_ids: HashSet<ExternalReferenceId> =
            self.external_references.keys().copied().collect();

        // 1. Remove orphaned relations (missing node on either endpoint)
        let before = self.relations.len();
        let artifact_ids: HashSet<ArtifactId> = self
            .resolved_tree
            .artifacts()
            .map(|artifact| artifact.artifact_id)
            .collect();
        let graph_node_ids = GraphNodeIds {
            entities: &entity_ids,
            artifacts: &artifact_ids,
            tests: &test_ids,
            contracts: &contract_ids,
            work_items: &work_ids,
            verification_runs: &run_ids,
            external_references: &external_reference_ids,
        };
        self.relations
            .retain(|_, rel| graph_node_ids.contains(rel.src) && graph_node_ids.contains(rel.dst));
        stats.orphaned_relations_removed = before - self.relations.len();

        // 2. Clean outgoing edge lists
        let live_relations: HashSet<RelationId> = self.relations.keys().copied().collect();
        let before = self.outgoing.len();
        self.outgoing.retain(|eid, _| entity_ids.contains(eid));
        for rels in self.outgoing.values_mut() {
            rels.retain(|rid| live_relations.contains(rid));
        }
        self.outgoing.retain(|_, rels| !rels.is_empty());
        stats.orphaned_outgoing_cleaned = before.saturating_sub(self.outgoing.len());

        // 3. Clean incoming edge lists
        let before = self.incoming.len();
        self.incoming.retain(|eid, _| entity_ids.contains(eid));
        for rels in self.incoming.values_mut() {
            rels.retain(|rid| live_relations.contains(rid));
        }
        self.incoming.retain(|_, rels| !rels.is_empty());
        stats.orphaned_incoming_cleaned = before.saturating_sub(self.incoming.len());

        // 4. Clean mock hints for non-existent tests
        let before = self.mock_hints.len();
        self.mock_hints
            .retain(|hint| test_ids.contains(&hint.test_id));
        stats.orphaned_mock_hints_removed = before - self.mock_hints.len();

        // 5. Clean downstream warnings for non-existent intents or entities
        let intent_ids: HashSet<IntentId> = self.intents.keys().copied().collect();
        let before = self.downstream_warnings.len();
        self.downstream_warnings
            .retain(|(iid, eid, _)| intent_ids.contains(iid) && entity_ids.contains(eid));
        stats.orphaned_downstream_warnings_removed = before - self.downstream_warnings.len();

        // 6. Clean approvals for non-existent changes
        let change_ids: HashSet<SemanticChangeId> = self.changes.keys().copied().collect();
        let before = self.approvals.len();
        self.approvals.retain(|a| change_ids.contains(&a.change_id));
        stats.orphaned_approvals_removed = before - self.approvals.len();

        // 7. Clean delegations for non-existent actors
        let actor_ids: HashSet<ActorId> = self.actors.keys().copied().collect();
        let before = self.delegations.len();
        self.delegations
            .retain(|d| actor_ids.contains(&d.principal) && actor_ids.contains(&d.delegate));
        stats.orphaned_delegations_removed = before - self.delegations.len();

        stats.relations_after = self.relations.len();
        stats
    }

    /// Serialize the snapshot to bytes with a header and checksum.
    ///
    /// Wire format:
    ///   [4B magic] [4B version LE] [8B body_len LE] [body ...] [32B checksum]
    ///
    /// The checksum is computed over the msgpack body only.
    ///
    /// For large graphs (>500K entities), this avoids cloning the entire
    /// snapshot by serializing directly when the version already matches.
    pub fn to_bytes(&self) -> Result<Vec<u8>, crate::error::KinDbError> {
        self.to_bytes_inner(None, true)
    }

    /// Serialize a snapshot whose storage admission the caller has already
    /// validated on this exact object.
    ///
    /// [`to_bytes`] revalidates storage admission before serializing, which is
    /// right for callers handing over a snapshot of unknown provenance. The
    /// repository publication path validates the exact successor under the
    /// single-writer permit immediately before persisting it, and nothing can
    /// mutate the candidate between that gate and this serialization, so the
    /// second full-snapshot walk proved nothing. The version gate still runs.
    pub(crate) fn to_bytes_pre_validated(&self) -> Result<Vec<u8>, crate::error::KinDbError> {
        self.to_bytes_inner(None, false)
    }

    /// Like [`to_bytes`] but appends a verified root-hash trailer so open
    /// paths can reuse the persisted Merkle root without recomputing it from
    /// the decoded snapshot.
    pub fn to_bytes_with_persisted_root_hash(
        &self,
        root_hash: [u8; 32],
    ) -> Result<Vec<u8>, crate::error::KinDbError> {
        self.to_bytes_inner(Some(root_hash), true)
    }

    fn to_bytes_inner(
        &self,
        persisted_root_hash: Option<[u8; 32]>,
        validate_admission: bool,
    ) -> Result<Vec<u8>, crate::error::KinDbError> {
        if self.version != Self::CURRENT_VERSION {
            return Err(crate::error::KinDbError::StorageError(format!(
                "refusing to serialize snapshot body version {}; current schema is exactly v{}",
                self.version,
                Self::CURRENT_VERSION
            )));
        }
        if validate_admission {
            self.validate_storage_admission()?;
        }
        let trailer_len = persisted_root_hash
            .map(|_| Self::ROOT_HASH_TRAILER_LEN)
            .unwrap_or(0);

        // The frame is assembled in ONE buffer, and that is the whole point of
        // the two passes below.
        //
        // This used to serialize the body into its own `Vec` and then copy it
        // into a second, exactly-sized frame buffer, so both existed at once.
        // The body of a converted repository IS the repository: on psf/requests
        // at full history it is about a gigabyte, and the copy made
        // `kindb.commit.persist_successor` the moment a conversion reaches its
        // whole-run peak. Every other cut in that phase was rearranging memory
        // underneath this one.
        //
        // The body's length has to be in the header, which sits AHEAD of the
        // body, so a single streaming pass cannot know what to write there. It
        // is counted first over the same walk that produces the bytes second,
        // by a writer that allocates nothing. Two passes of CPU buys one copy
        // of the repository, and the buffer is then exactly sized, so the write
        // pass never reallocates and never holds a half-grown copy beside a
        // growing one.
        assemble_snapshot_frame(self, persisted_root_hash, trailer_len)
    }

    /// Deserialize a snapshot from bytes (with header validation).
    ///
    /// The pre-release v13 format persists complete base-relative semantic
    /// workspace overlays alongside exact trees. Earlier snapshots fail closed
    /// because tree-only dirty workspace authority cannot be reconstructed.
    pub fn from_bytes(data: &[u8]) -> Result<Self, crate::error::KinDbError> {
        Self::from_bytes_with_persisted_root_hash(data).map(|(snapshot, _)| snapshot)
    }

    pub(crate) fn from_bytes_with_persisted_root_hash(
        data: &[u8],
    ) -> Result<(Self, Option<[u8; 32]>), crate::error::KinDbError> {
        Self::from_bytes_with_persisted_root_hash_inner(data, true, true)
    }

    pub(crate) fn from_bytes_with_persisted_root_hash_unverified(
        data: &[u8],
    ) -> Result<(Self, Option<[u8; 32]>), crate::error::KinDbError> {
        Self::from_bytes_with_persisted_root_hash_inner(data, false, true)
    }

    /// Decode exact snapshot bytes that already carry a matching durable
    /// complete-validation proof.
    ///
    /// This remains a checksum-verifying decoder. It skips only the semantic
    /// storage-admission pass whose result is already bound to these exact
    /// bytes by
    /// [`HistoryValidationProof`](crate::storage::backend::HistoryValidationProof).
    /// Callers must establish that proof against a freshly recomputed digest,
    /// repository identity, generation, validator version, and a journal-free
    /// authority before entering this boundary.
    pub(crate) fn from_bytes_reusing_exact_validation(
        data: &[u8],
    ) -> Result<Self, crate::error::KinDbError> {
        Self::from_bytes_with_persisted_root_hash_inner(data, true, false)
            .map(|(snapshot, _)| snapshot)
    }

    /// Decode exact snapshot bytes whose writer already proved admission.
    ///
    /// This stays a checksum-verifying decoder and still refuses a malformed
    /// frame, an unsupported version, a corrupt body, or a bad root-hash
    /// trailer. It skips only the semantic storage-admission pass, whose cost on
    /// a repository imported from Git is one full recursive Git tree walk per
    /// projected commit.
    ///
    /// The obligation is the mirror of [`Self::to_bytes_pre_validated`]: a
    /// caller may enter this boundary only for bytes serialized from a state
    /// that passed the admission gate and could not change between that gate and
    /// this decode.
    ///
    /// Retained under `cfg(test)` only. `prove_pre_validated_round_trip`
    /// replaced its one caller on the write path, and it stays as the reference
    /// decoder that path is checked against: a cheap proof is only trustworthy
    /// while something asserts it accepts exactly what the full decode accepts.
    #[cfg(test)]
    pub(crate) fn decode_pre_validated(data: &[u8]) -> Result<Self, crate::error::KinDbError> {
        Self::from_bytes_with_persisted_root_hash_inner(data, true, false)
            .map(|(snapshot, _)| snapshot)
    }

    /// Prove pre-validated bytes round-trip, without keeping what they decode to.
    ///
    /// Exactly the obligations [`Self::decode_pre_validated`] discharges, in the
    /// same order: the frame and its checksum, every element parsed as its
    /// declared type, and the root-hash trailer. It differs only in what it
    /// retains, which is nothing.
    ///
    /// The write path called `decode_pre_validated` and dropped the result on
    /// the next line. On a converted repository that discarded value was about
    /// 855 MiB, allocated while the caller still held the encoded frame and the
    /// whole retained import ladder, which made it the ceiling of a conversion's
    /// peak (FIR-2654).
    ///
    /// Deliberately NOT used for the admission-validating path: that one needs
    /// the assembled snapshot to walk, and it is a different obligation than
    /// round-tripping.
    pub fn prove_pre_validated_round_trip(data: &[u8]) -> Result<(), crate::error::KinDbError> {
        let _span = tracing::info_span!("kindb.snapshot.prove_round_trip").entered();
        let frame = Self::decode_frame(data, true)?;
        match frame.version {
            Self::MIN_SUPPORTED_VERSION..=Self::CURRENT_VERSION => {
                let _span = tracing::info_span!("kindb.snapshot.decode_round_trip_proof").entered();
                let proof: GraphSnapshotRoundTripProof = rmp_serde::from_slice(frame.body)
                    .map_err(|e| {
                        crate::error::KinDbError::StorageError(format!(
                            "deserialization failed: {e}"
                        ))
                    })?;
                // Report what was actually proved. Without this the counts are
                // dead weight and the log says only that a proof ran, which is
                // the same thing a proof that walked nothing would say.
                tracing::debug!(
                    entities = proof.entities.len,
                    relations = proof.relations.len,
                    changes = proof.changes.len,
                    entity_revisions = proof.entity_revisions.len,
                    audit_events = proof.audit_events.len,
                    "snapshot round-trip proved without retaining the snapshot"
                );
                drop(proof);
            }
            _ => unreachable!("decode_frame validates supported versions"),
        }
        Self::decode_root_hash_trailer(data, &frame)?;
        Ok(())
    }

    fn from_bytes_with_persisted_root_hash_inner(
        data: &[u8],
        verify_checksum: bool,
        validate_storage_admission: bool,
    ) -> Result<(Self, Option<[u8; 32]>), crate::error::KinDbError> {
        let frame = {
            let _span = tracing::info_span!("kindb.snapshot.decode_frame").entered();
            Self::decode_frame(data, verify_checksum)?
        };
        let mut snapshot = match frame.version {
            Self::MIN_SUPPORTED_VERSION..=Self::CURRENT_VERSION => {
                Self::decode_current_snapshot(frame.body)?
            }
            _ => unreachable!("decode_frame validates supported versions"),
        };
        // The header and the body both carry a version and nothing made them
        // agree. While there was one supported version the question could not
        // arise; with two it can, and a decoder that dispatches on the header
        // while trusting the body's own claim is a check that cannot fail.
        if snapshot.version != frame.version {
            return Err(crate::error::KinDbError::StorageError(format!(
                "snapshot header declares v{} but its body declares v{}",
                frame.version, snapshot.version
            )));
        }
        // An older body decodes into the current in-memory shape with its
        // appended field defaulted, so the value this returns IS a v14
        // snapshot and says so. Leaving 13 here would make the very next
        // `to_bytes` refuse its own decoded object. No root hashes the version,
        // so raising it moves no authority: checked against every one of the
        // six root functions, none reads `snapshot.version`.
        snapshot.version = Self::CURRENT_VERSION;
        if validate_storage_admission {
            snapshot.validate_storage_admission()?;
        }
        let persisted_root_hash = if verify_checksum {
            Self::decode_root_hash_trailer(data, &frame)?
        } else {
            let _span = tracing::info_span!("kindb.snapshot.skip_checksum_verification").entered();
            Self::decode_root_hash_trailer_unverified(data, frame.checksum_end)?
        };
        Ok((snapshot, persisted_root_hash))
    }

    fn decode_frame(
        data: &[u8],
        verify_checksum: bool,
    ) -> Result<SnapshotFrame<'_>, crate::error::KinDbError> {
        if data.len() < 16 {
            return Err(crate::error::KinDbError::StorageError(
                "file too small for header".to_string(),
            ));
        }

        let magic = &data[0..4];
        if magic != Self::MAGIC {
            return Err(crate::error::KinDbError::StorageError(format!(
                "invalid magic bytes: expected KNDB, got {:?}",
                magic
            )));
        }

        let version = u32::from_le_bytes(data[4..8].try_into().map_err(|_| {
            crate::error::KinDbError::SliceConversionError(
                "version bytes: expected 4-byte slice".to_string(),
            )
        })?);
        let body_len = u64::from_le_bytes(data[8..16].try_into().map_err(|_| {
            crate::error::KinDbError::SliceConversionError(
                "body_len bytes: expected 8-byte slice".to_string(),
            )
        })?) as usize;
        // Checked add: an adversarial body_len near usize::MAX would otherwise
        // wrap `16 + body_len`, defeating the bounds check and panicking on the
        // `data[16..16 + body_len]` slice below (found by fuzzing).
        let body_end = 16usize.checked_add(body_len).ok_or_else(|| {
            crate::error::KinDbError::StorageError(
                "snapshot header body length overflows usize".to_string(),
            )
        })?;
        if data.len() < body_end {
            return Err(crate::error::KinDbError::StorageError(
                "snapshot file truncated: body extends past end of data".to_string(),
            ));
        }
        let body = &data[16..body_end];

        match version {
            // Every version in the supported range shares one frame layout;
            // they differ only in how wide the MessagePack body array is. The
            // label is derived from the version rather than written as a
            // literal, because a hardcoded "v13" in a v14 refusal names the
            // wrong format at exactly the moment a reader needs the right one.
            Self::MIN_SUPPORTED_VERSION..=Self::CURRENT_VERSION => {
                let label = format!("v{version}");
                let checksum_end = Self::require_checksum_slot(data, body_len, &label)?;
                let body_checksum = if verify_checksum {
                    Some(Self::verify_checksum(data, body_len, &label)?)
                } else {
                    None
                };
                Ok(SnapshotFrame {
                    version,
                    body,
                    body_checksum,
                    checksum_end,
                })
            }
            version if version < Self::MIN_SUPPORTED_VERSION => {
                Err(crate::error::KinDbError::snapshot_schema_too_old(
                    version,
                    Self::MIN_SUPPORTED_VERSION,
                    Self::CURRENT_VERSION,
                ))
            }
            _ => Err(crate::error::KinDbError::snapshot_schema_too_new(
                version,
                Self::MIN_SUPPORTED_VERSION,
                Self::CURRENT_VERSION,
            )),
        }
    }

    fn decode_current_snapshot(body: &[u8]) -> Result<Self, crate::error::KinDbError> {
        let _span = tracing::info_span!("kindb.snapshot.decode_current_snapshot").entered();
        rmp_serde::from_slice(body).map_err(|e| {
            crate::error::KinDbError::StorageError(format!("deserialization failed: {e}"))
        })
    }

    pub(crate) fn validate_storage_admission(&self) -> Result<(), crate::error::KinDbError> {
        self.validate_storage_admission_with(GitProjectionTreeReplay::Required)
    }

    pub(crate) fn validate_storage_admission_with(
        &self,
        replay: GitProjectionTreeReplay,
    ) -> Result<(), crate::error::KinDbError> {
        self.validate_admission_with_envelope(replay, AuthorityEnvelope::Validated)
    }

    /// The same storage admission a snapshot carrying no authority envelope
    /// would pass.
    ///
    /// A history replay proves the authority-free payload on purpose: the
    /// envelope is the caller's to publish, and the replay is checking the
    /// payload it would be published over. Reaching that used to mean cloning
    /// the whole snapshot in order to null one field, which on a full-history
    /// conversion is a second copy of the repository. Ignoring the field costs
    /// nothing and asserts exactly what nulling it asserted.
    pub(crate) fn validate_authority_free_storage_admission(
        &self,
    ) -> Result<(), crate::error::KinDbError> {
        self.validate_admission_with_envelope(
            GitProjectionTreeReplay::Required,
            AuthorityEnvelope::Ignored,
        )
    }

    fn validate_admission_with_envelope(
        &self,
        replay: GitProjectionTreeReplay,
        envelope: AuthorityEnvelope,
    ) -> Result<(), crate::error::KinDbError> {
        let mut timer = crate::storage::repository::PublicationPhaseTimer::start();
        let admitted = AdmittedChangeMap::admit(&self.changes, "snapshot")?;
        let changes_ms = timer.lap_ms();
        self.validate_storage_admission_after_changes(
            replay, &admitted, envelope, changes_ms, timer,
        )
    }

    /// The same storage admission, minus the change-map pass `admitted`
    /// already ran over this snapshot's own map.
    ///
    /// The witness cannot be forged and cannot be built from a map nobody
    /// admitted, and the correspondence check below is by pointer identity, so
    /// a witness for some other map refuses rather than licensing a skip. Every
    /// other check runs exactly as it does above.
    pub(crate) fn validate_storage_admission_carrying(
        &self,
        replay: GitProjectionTreeReplay,
        admitted: &AdmittedChangeMap<'_>,
    ) -> Result<(), crate::error::KinDbError> {
        self.validate_admission_carrying_with_envelope(
            replay,
            admitted,
            AuthorityEnvelope::Validated,
        )
    }

    /// [`validate_authority_free_storage_admission`], minus the change-map pass
    /// `admitted` already ran over this snapshot's own map.
    ///
    /// The witness is checked by pointer identity exactly as it is above, so
    /// this carries a pass and never a trust extension.
    ///
    /// [`validate_authority_free_storage_admission`]: Self::validate_authority_free_storage_admission
    pub(crate) fn validate_authority_free_storage_admission_carrying(
        &self,
        replay: GitProjectionTreeReplay,
        admitted: &AdmittedChangeMap<'_>,
    ) -> Result<(), crate::error::KinDbError> {
        self.validate_admission_carrying_with_envelope(replay, admitted, AuthorityEnvelope::Ignored)
    }

    fn validate_admission_carrying_with_envelope(
        &self,
        replay: GitProjectionTreeReplay,
        admitted: &AdmittedChangeMap<'_>,
        envelope: AuthorityEnvelope,
    ) -> Result<(), crate::error::KinDbError> {
        if !admitted.describes(&self.changes) {
            return Err(crate::error::KinDbError::StorageError(
                "admitted change map does not describe this snapshot's change map".to_string(),
            ));
        }
        let timer = crate::storage::repository::PublicationPhaseTimer::start();
        self.validate_storage_admission_after_changes(replay, admitted, envelope, 0, timer)
    }

    fn validate_storage_admission_after_changes(
        &self,
        replay: GitProjectionTreeReplay,
        admitted: &AdmittedChangeMap<'_>,
        envelope: AuthorityEnvelope,
        changes_ms: u128,
        mut timer: crate::storage::repository::PublicationPhaseTimer,
    ) -> Result<(), crate::error::KinDbError> {
        for (id, reference) in &self.external_references {
            validate_external_reference_entry(id, reference, "snapshot")?;
        }
        let external_references_ms = timer.lap_ms();
        self.validate_enrichment_admission()?;
        let enrichment_ms = timer.lap_ms();
        let entity_ids: HashSet<_> = self.entities.keys().copied().collect();
        let artifact_ids: HashSet<_> = self
            .resolved_tree
            .artifacts()
            .map(|artifact| artifact.artifact_id)
            .collect();
        let test_ids: HashSet<_> = self.test_cases.keys().copied().collect();
        let contract_ids: HashSet<_> = self.contracts.keys().copied().collect();
        let work_ids: HashSet<_> = self.work_items.keys().copied().collect();
        let run_ids: HashSet<_> = self.verification_runs.keys().copied().collect();
        let external_reference_ids: HashSet<_> = self.external_references.keys().copied().collect();
        let graph_node_ids = GraphNodeIds {
            entities: &entity_ids,
            artifacts: &artifact_ids,
            tests: &test_ids,
            contracts: &contract_ids,
            work_items: &work_ids,
            verification_runs: &run_ids,
            external_references: &external_reference_ids,
        };
        let node_id_sets_ms = timer.lap_ms();
        for relation in self.relations.values() {
            for (side, node) in [("source", relation.src), ("destination", relation.dst)] {
                if !graph_node_ids.contains(node) {
                    return Err(crate::error::KinDbError::StorageError(format!(
                        "snapshot relation {} has unadmitted {side} endpoint {node}",
                        relation.id
                    )));
                }
            }
        }
        let relation_endpoints_ms = timer.lap_ms();
        let envelope_to_validate = match envelope {
            AuthorityEnvelope::Validated => self.repository_authority.as_ref(),
            AuthorityEnvelope::Ignored => None,
        };
        if let Some(authority) = envelope_to_validate {
            authority.validate_against_snapshot_with(self, replay, admitted)?;
        }
        let repository_authority_ms = timer.lap_ms();
        tracing::debug!(
            target: "kin_db::admission",
            changes_ms,
            external_references_ms,
            enrichment_ms,
            node_id_sets_ms,
            relation_endpoints_ms,
            repository_authority_ms,
            changes = self.changes.len(),
            entities = self.entities.len(),
            relations = self.relations.len(),
            shallow_files = self.shallow_files.len(),
            "snapshot storage admission validation"
        );
        #[cfg(test)]
        crate::storage::repository::record_preparation_phase(
            "storage_admission",
            vec![
                ("changes_ms", changes_ms),
                ("external_references_ms", external_references_ms),
                ("enrichment_ms", enrichment_ms),
                ("node_id_sets_ms", node_id_sets_ms),
                ("relation_endpoints_ms", relation_endpoints_ms),
                ("repository_authority_ms", repository_authority_ms),
            ],
        );
        Ok(())
    }

    fn validate_enrichment_admission(&self) -> Result<(), crate::error::KinDbError> {
        let file_ids = self
            .shallow_files
            .iter()
            .map(|file| &file.file_id)
            .chain(self.file_layouts.iter().map(|layout| &layout.file_id))
            .chain(
                self.structured_artifacts
                    .iter()
                    .map(|artifact| &artifact.file_id),
            )
            .chain(
                self.opaque_artifacts
                    .iter()
                    .map(|artifact| &artifact.file_id),
            );
        for file_id in file_ids {
            let path = RepoPath::from_utf8(&file_id.0).map_err(|error| {
                crate::error::KinDbError::StorageError(format!(
                    "semantic enrichment has invalid repository path {}: {error}",
                    file_id.0
                ))
            })?;
            if self.resolved_tree.artifact_id_at_path(&path).is_none() {
                return Err(crate::error::KinDbError::StorageError(format!(
                    "semantic enrichment exists without admitted repository identity at {}",
                    file_id.0
                )));
            }
        }
        Ok(())
    }

    fn verify_checksum(
        data: &[u8],
        body_len: usize,
        version_label: &str,
    ) -> Result<[u8; 32], crate::error::KinDbError> {
        let _span = tracing::info_span!("kindb.snapshot.verify_checksum", version = version_label)
            .entered();
        let checksum_end = Self::require_checksum_slot(data, body_len, version_label)?;
        let checksum_start = checksum_end - Self::CHECKSUM_LEN;
        let body = &data[16..16 + body_len];
        let stored_hash = &data[checksum_start..checksum_start + Self::CHECKSUM_LEN];
        let computed_hash: [u8; 32] = Sha256::digest(body).into();

        if stored_hash != computed_hash.as_slice() {
            return Err(crate::error::KinDbError::StorageError(
                "snapshot checksum mismatch: file is corrupted".to_string(),
            ));
        }

        Ok(computed_hash)
    }

    fn require_checksum_slot(
        data: &[u8],
        body_len: usize,
        version_label: &str,
    ) -> Result<usize, crate::error::KinDbError> {
        // Checked add to avoid wrapping on an adversarial body_len.
        let checksum_end = 16usize
            .checked_add(body_len)
            .and_then(|start| start.checked_add(Self::CHECKSUM_LEN))
            .ok_or_else(|| {
                crate::error::KinDbError::StorageError(format!(
                    "{version_label} snapshot body length overflows usize"
                ))
            })?;
        if data.len() < checksum_end {
            return Err(crate::error::KinDbError::StorageError(format!(
                "{version_label} snapshot missing checksum"
            )));
        }
        Ok(checksum_end)
    }

    fn append_root_hash_trailer(buf: &mut Vec<u8>, body_checksum: [u8; 32], root_hash: [u8; 32]) {
        buf.extend_from_slice(&Self::ROOT_HASH_TRAILER_MAGIC);
        buf.extend_from_slice(&root_hash);
        buf.extend_from_slice(&Self::root_hash_trailer_digest(body_checksum, root_hash));
    }

    fn decode_root_hash_trailer(
        data: &[u8],
        frame: &SnapshotFrame<'_>,
    ) -> Result<Option<[u8; 32]>, crate::error::KinDbError> {
        let Some(body_checksum) = frame.body_checksum else {
            return Ok(None);
        };

        let extra = &data[frame.checksum_end..];
        if extra.len() < 4 {
            return Ok(None);
        }
        if extra[..4] != Self::ROOT_HASH_TRAILER_MAGIC {
            return Ok(None);
        }
        if extra.len() < Self::ROOT_HASH_TRAILER_LEN {
            return Err(crate::error::KinDbError::StorageError(
                "snapshot root-hash trailer is truncated".to_string(),
            ));
        }

        let root_hash = extra[4..36].try_into().map_err(|_| {
            crate::error::KinDbError::SliceConversionError(
                "root-hash trailer root bytes: expected 32-byte slice".to_string(),
            )
        })?;
        let stored_digest: [u8; 32] = extra[36..68].try_into().map_err(|_| {
            crate::error::KinDbError::SliceConversionError(
                "root-hash trailer digest bytes: expected 32-byte slice".to_string(),
            )
        })?;
        let expected_digest = Self::root_hash_trailer_digest(body_checksum, root_hash);
        if stored_digest != expected_digest {
            return Err(crate::error::KinDbError::StorageError(
                "snapshot root-hash trailer mismatch: file is corrupted".to_string(),
            ));
        }

        Ok(Some(root_hash))
    }

    fn decode_root_hash_trailer_unverified(
        data: &[u8],
        checksum_end: usize,
    ) -> Result<Option<[u8; 32]>, crate::error::KinDbError> {
        let extra = &data[checksum_end..];
        if extra.len() < 4 {
            return Ok(None);
        }
        if extra[..4] != Self::ROOT_HASH_TRAILER_MAGIC {
            return Ok(None);
        }
        if extra.len() < Self::ROOT_HASH_TRAILER_LEN {
            return Err(crate::error::KinDbError::StorageError(
                "snapshot root-hash trailer is truncated".to_string(),
            ));
        }

        let root_hash = extra[4..36].try_into().map_err(|_| {
            crate::error::KinDbError::SliceConversionError(
                "root-hash trailer root bytes: expected 32-byte slice".to_string(),
            )
        })?;
        Ok(Some(root_hash))
    }

    fn root_hash_trailer_digest(body_checksum: [u8; 32], root_hash: [u8; 32]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(Self::ROOT_HASH_TRAILER_MAGIC);
        hasher.update(body_checksum);
        hasher.update(root_hash);
        hasher.finalize().into()
    }
}

impl LocateGraphSnapshot {
    pub(crate) fn from_bytes_with_persisted_root_hash(
        data: &[u8],
    ) -> Result<(Self, Option<[u8; 32]>), crate::error::KinDbError> {
        Self::from_bytes_with_persisted_root_hash_inner(data, true)
    }

    pub(crate) fn from_bytes_with_persisted_root_hash_unverified(
        data: &[u8],
    ) -> Result<(Self, Option<[u8; 32]>), crate::error::KinDbError> {
        Self::from_bytes_with_persisted_root_hash_inner(data, false)
    }

    fn from_bytes_with_persisted_root_hash_inner(
        data: &[u8],
        verify_checksum: bool,
    ) -> Result<(Self, Option<[u8; 32]>), crate::error::KinDbError> {
        let frame = {
            let _span = tracing::info_span!("kindb.snapshot.decode_locate_frame").entered();
            GraphSnapshot::decode_frame(data, verify_checksum)?
        };
        let snapshot = match frame.version {
            GraphSnapshot::MIN_SUPPORTED_VERSION..=GraphSnapshot::CURRENT_VERSION => {
                Self::decode_current_snapshot(frame.body)?
            }
            _ => unreachable!("decode_frame validates supported versions"),
        };
        snapshot.validate_storage_admission()?;
        let persisted_root_hash = if verify_checksum {
            GraphSnapshot::decode_root_hash_trailer(data, &frame)?
        } else {
            let _span = tracing::info_span!("kindb.snapshot.skip_locate_checksum").entered();
            GraphSnapshot::decode_root_hash_trailer_unverified(data, frame.checksum_end)?
        };
        Ok((snapshot, persisted_root_hash))
    }

    fn decode_current_snapshot(body: &[u8]) -> Result<Self, crate::error::KinDbError> {
        rmp_serde::from_slice(body).map_err(|e| {
            crate::error::KinDbError::StorageError(format!("deserialization failed: {e}"))
        })
    }

    pub(crate) fn validate_storage_admission(&self) -> Result<(), crate::error::KinDbError> {
        validate_semantic_change_entries(self.changes.iter(), "locate snapshot")?;
        for (id, reference) in &self.external_references {
            validate_external_reference_entry(id, reference, "locate snapshot")?;
        }
        let artifact_ids: HashSet<_> = self
            .resolved_tree
            .artifacts()
            .map(|artifact| artifact.artifact_id)
            .collect();
        for relation in self.relations.values() {
            for (side, node) in [("source", relation.src), ("destination", relation.dst)] {
                let admitted = match node {
                    GraphNodeId::Entity(id) => self.entities.contains_key(&id),
                    GraphNodeId::Artifact(id) => artifact_ids.contains(&id),
                    GraphNodeId::ExternalReference(id) => {
                        self.external_references.contains_key(&id)
                    }
                    // Locate snapshots intentionally omit these domains. Their
                    // authority was checked when the canonical snapshot was
                    // admitted; absence from this projection is not deletion.
                    GraphNodeId::Test(_)
                    | GraphNodeId::Contract(_)
                    | GraphNodeId::Work(_)
                    | GraphNodeId::VerificationRun(_) => true,
                };
                if !admitted {
                    return Err(crate::error::KinDbError::StorageError(format!(
                        "locate snapshot relation {} has unadmitted {side} endpoint {node}",
                        relation.id
                    )));
                }
            }
        }
        self.validate_enrichment_admission()
    }

    fn validate_enrichment_admission(&self) -> Result<(), crate::error::KinDbError> {
        let file_ids = self
            .shallow_files
            .iter()
            .map(|file| &file.file_id)
            .chain(self.file_layouts.iter().map(|layout| &layout.file_id))
            .chain(
                self.structured_artifacts
                    .iter()
                    .map(|artifact| &artifact.file_id),
            )
            .chain(
                self.opaque_artifacts
                    .iter()
                    .map(|artifact| &artifact.file_id),
            );
        for file_id in file_ids {
            let path = RepoPath::from_utf8(&file_id.0).map_err(|error| {
                crate::error::KinDbError::StorageError(format!(
                    "semantic enrichment has invalid repository path {}: {error}",
                    file_id.0
                ))
            })?;
            if self.resolved_tree.artifact_id_at_path(&path).is_none() {
                return Err(crate::error::KinDbError::StorageError(format!(
                    "semantic enrichment exists without admitted repository identity at {}",
                    file_id.0
                )));
            }
        }
        Ok(())
    }
}

impl GraphSnapshot {
    pub(crate) fn persisted_root_hash_from_bytes_unverified(
        data: &[u8],
    ) -> Result<Option<[u8; 32]>, crate::error::KinDbError> {
        let frame = Self::decode_frame(data, false)?;
        Self::decode_root_hash_trailer_unverified(data, frame.checksum_end)
    }
}

impl From<GraphSnapshot> for LocateGraphSnapshot {
    fn from(value: GraphSnapshot) -> Self {
        Self {
            version: value.version,
            entities: value.entities.into_iter().collect(),
            relations: value.relations.into_iter().collect(),
            changes: value.changes.into_iter().collect(),
            entity_revisions: value.entity_revisions.into_iter().collect(),
            shallow_files: value.shallow_files,
            file_layouts: value.file_layouts,
            structured_artifacts: value.structured_artifacts,
            opaque_artifacts: value.opaque_artifacts,
            resolved_tree: value.resolved_tree,
            external_references: value.external_references.into_iter().collect(),
        }
    }
}

impl From<LocateGraphSnapshot> for GraphSnapshot {
    fn from(value: LocateGraphSnapshot) -> Self {
        let mut snapshot = GraphSnapshot::empty();
        snapshot.version = value.version;
        snapshot.entities = value.entities.into_iter().collect();
        snapshot.relations = value.relations.into_iter().collect();
        snapshot.changes = value.changes.into_iter().collect();
        snapshot.entity_revisions = value.entity_revisions.into_iter().collect();
        snapshot.shallow_files = value.shallow_files;
        snapshot.file_layouts = value.file_layouts;
        snapshot.structured_artifacts = value.structured_artifacts;
        snapshot.opaque_artifacts = value.opaque_artifacts;
        snapshot.resolved_tree = value.resolved_tree;
        snapshot.external_references = value.external_references.into_iter().collect();
        snapshot
    }
}

impl<'de> Deserialize<'de> for LocateGraphSnapshot {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct LocateGraphSnapshotVisitor;

        impl<'de> Visitor<'de> for LocateGraphSnapshotVisitor {
            type Value = LocateGraphSnapshot;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("GraphSnapshot sequence")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                // The locate cache persists the compact eleven-field projection,
                // while mmap cold-open decodes the canonical 35-field graph
                // snapshot directly. Both are current formats; distinguish
                // them by their explicit MessagePack sequence width.
                if seq.size_hint() == Some(11) {
                    let version = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                    let entities = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                    let relations = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(2, &self))?;
                    let changes = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(3, &self))?;
                    let entity_revisions = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(4, &self))?;
                    let shallow_files = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(5, &self))?;
                    let file_layouts = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(6, &self))?;
                    let structured_artifacts = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(7, &self))?;
                    let opaque_artifacts = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(8, &self))?;
                    let resolved_tree = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(9, &self))?;
                    let external_references = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(10, &self))?;
                    return Ok(LocateGraphSnapshot {
                        version,
                        entities,
                        relations,
                        changes,
                        entity_revisions,
                        shallow_files,
                        file_layouts,
                        structured_artifacts,
                        opaque_artifacts,
                        resolved_tree,
                        external_references,
                    });
                }

                // The canonical body is 35 elements at v13 and 36 at v14; the
                // appended element is the materialized graph, which locate does
                // not read. This used to be a bare `35`, which would have made
                // every v14 store fail here with `invalid_length` while the
                // named constant one screen up said 36.
                let width = match seq.size_hint() {
                    Some(width @ GRAPH_SNAPSHOT_V13_FIELD_COUNT)
                    | Some(width @ GRAPH_SNAPSHOT_FIELD_COUNT) => width,
                    other => {
                        return Err(serde::de::Error::invalid_length(
                            other.unwrap_or_default(),
                            &self,
                        ))
                    }
                };

                let version = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                let entities = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(1, &self))?;
                let relations = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(2, &self))?;

                let _: IgnoredAny = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(3, &self))?;
                let _: IgnoredAny = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(4, &self))?;

                let changes = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(5, &self))?;

                for index in 6..24 {
                    let _: IgnoredAny = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(index, &self))?;
                }

                let shallow_files = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(24, &self))?;
                let file_layouts = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(25, &self))?;
                let structured_artifacts = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(26, &self))?;
                let opaque_artifacts = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(27, &self))?;

                let resolved_tree = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(28, &self))?;

                for index in 29..32 {
                    let _: IgnoredAny = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(index, &self))?;
                }
                let entity_revisions = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(32, &self))?;
                let _: IgnoredAny = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(33, &self))?;
                let external_references = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(34, &self))?;
                if width == GRAPH_SNAPSHOT_FIELD_COUNT {
                    let _: IgnoredAny = seq.next_element()?.ok_or_else(|| {
                        serde::de::Error::invalid_length(MATERIALIZED_GRAPH_FIELD_INDEX, &self)
                    })?;
                }

                Ok(LocateGraphSnapshot {
                    version,
                    entities,
                    relations,
                    changes,
                    entity_revisions,
                    shallow_files,
                    file_layouts,
                    structured_artifacts,
                    opaque_artifacts,
                    resolved_tree,
                    external_references,
                })
            }
        }

        deserializer.deserialize_seq(LocateGraphSnapshotVisitor)
    }
}

/// The repository-authority envelope alone, decoded without materializing the
/// history the same bytes carry.
///
/// A converted repository's snapshot IS its history: on psf/requests at 6493
/// commits the `changes` map dominates a 1051 MiB body, and decoding it costs
/// gigabytes of resident set. A caller that only needs the envelope, which is
/// where refs, workspaces, admission state and the roots live, was paying all
/// of it. `kin graph status` is such a caller: it opens the whole authority to
/// read one workspace tree and then load a handful of bodies by content
/// address.
///
/// The body is compact MessagePack, so a struct is a positional ARRAY and the
/// only way to reach field 33 is to walk the thirty-three ahead of it. Walking
/// them as [`IgnoredAny`] parses the bytes and allocates nothing, which is the
/// same trade [`LocateGraphSnapshot`] already makes for cold-start locate.
///
/// This is a projection, never a substitute for an authority open. It proves
/// the frame and its checksum exactly as a full decode does, so tampered bytes
/// still refuse, and every body it later hands a caller is verified against its
/// own content address by the backend that returns it. What it deliberately
/// does not do is re-verify bodies nobody asked for.
#[derive(Debug, Clone)]
pub struct AuthorityEnvelopeSnapshot {
    /// The on-disk format version these bytes declared.
    pub version: u32,
    /// The envelope. `None` is a legacy graph-only snapshot with no authority.
    pub repository_authority: Option<PersistedRepositoryAuthority>,
    /// The resolved graph these bytes carry, if any.
    ///
    /// Read here rather than through a third partial decoder on purpose. A
    /// second copy of a 36-element field list is only ever wrong in a way that
    /// looks like a passing run, and this reader already walks past the section
    /// to reach the envelope, so keeping it costs one more element.
    pub materialized_graph: Option<MaterializedGraphSection>,
}

impl AuthorityEnvelopeSnapshot {
    /// The section this envelope carries, or the reason it cannot be used.
    ///
    /// `resolved_at` is the change the caller intends to resolve the graph at,
    /// which for a workspace is its `base_target`. Matching it is what makes
    /// the answer this section's own, and the Merkle change id is what makes
    /// matching it sufficient.
    pub fn materialized_graph_for(
        &self,
        resolved_at: &SemanticChangeId,
    ) -> Result<&MaterializedGraphSection, MaterializedGraphRefusal> {
        let section = self
            .materialized_graph
            .as_ref()
            .ok_or(MaterializedGraphRefusal::Absent)?;
        section.validate_for(resolved_at)?;
        Ok(section)
    }
}

impl MaterializedGraphSection {
    /// Whether this section may answer for the graph at `resolved_at`.
    ///
    /// Every arm returns a DIFFERENT refusal, so a falsification can read which
    /// check answered rather than only that one did.
    pub fn validate_for(
        &self,
        resolved_at: &SemanticChangeId,
    ) -> Result<(), MaterializedGraphRefusal> {
        if self.schema_version != MATERIALIZED_GRAPH_SCHEMA_VERSION {
            return Err(MaterializedGraphRefusal::Schema {
                held: MATERIALIZED_GRAPH_SCHEMA_VERSION,
                found: self.schema_version,
            });
        }
        if &self.resolved_at != resolved_at {
            return Err(MaterializedGraphRefusal::Target);
        }
        Ok(())
    }
}

impl AuthorityEnvelopeSnapshot {
    /// Decode the envelope from a checksum-verified snapshot frame.
    pub fn from_bytes(data: &[u8]) -> Result<Self, crate::error::KinDbError> {
        let frame = {
            let _span = tracing::info_span!("kindb.snapshot.decode_envelope_frame").entered();
            GraphSnapshot::decode_frame(data, true)?
        };
        match frame.version {
            GraphSnapshot::MIN_SUPPORTED_VERSION..=GraphSnapshot::CURRENT_VERSION => {
                let _span = tracing::info_span!("kindb.snapshot.decode_envelope").entered();
                rmp_serde::from_slice(frame.body).map_err(|e| {
                    crate::error::KinDbError::StorageError(format!(
                        "authority envelope decode failed: {e}"
                    ))
                })
            }
            _ => unreachable!("decode_frame validates supported versions"),
        }
    }
}

impl<'de> Deserialize<'de> for AuthorityEnvelopeSnapshot {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct AuthorityEnvelopeVisitor;

        impl<'de> Visitor<'de> for AuthorityEnvelopeVisitor {
            type Value = AuthorityEnvelopeSnapshot;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("GraphSnapshot sequence")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                // Width is the format discriminator, exactly as it is for
                // `LocateGraphSnapshot`. The eleven-field locate projection
                // carries no envelope at all, so it is refused by name here
                // rather than silently decoding as an absent authority.
                // Width is the format discriminator and it is a function of
                // the snapshot version alone: v13 bodies are 35 elements, v14
                // bodies are 36, and nothing is skipped on serialize so the
                // width never varies within a version. The eleven-field locate
                // projection carries no envelope at all, so it is refused by
                // width here rather than silently decoding as an absent
                // authority.
                let width = match seq.size_hint() {
                    Some(width @ GRAPH_SNAPSHOT_V13_FIELD_COUNT)
                    | Some(width @ GRAPH_SNAPSHOT_FIELD_COUNT) => width,
                    other => {
                        return Err(serde::de::Error::invalid_length(
                            other.unwrap_or_default(),
                            &self,
                        ))
                    }
                };

                let version = seq
                    .next_element()?
                    .ok_or_else(|| serde::de::Error::invalid_length(0, &self))?;
                for index in 1..REPOSITORY_AUTHORITY_FIELD_INDEX {
                    let _: IgnoredAny = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(index, &self))?;
                }
                let repository_authority = seq.next_element()?.ok_or_else(|| {
                    serde::de::Error::invalid_length(REPOSITORY_AUTHORITY_FIELD_INDEX, &self)
                })?;
                let _: IgnoredAny = seq.next_element()?.ok_or_else(|| {
                    serde::de::Error::invalid_length(REPOSITORY_AUTHORITY_FIELD_INDEX + 1, &self)
                })?;
                let materialized_graph = if width == GRAPH_SNAPSHOT_FIELD_COUNT {
                    seq.next_element()?.ok_or_else(|| {
                        serde::de::Error::invalid_length(MATERIALIZED_GRAPH_FIELD_INDEX, &self)
                    })?
                } else {
                    None
                };

                Ok(AuthorityEnvelopeSnapshot {
                    version,
                    repository_authority,
                    materialized_graph,
                })
            }
        }

        deserializer.deserialize_seq(AuthorityEnvelopeVisitor)
    }
}

/// Fields in the v13 positional body, and where the envelope sits in it.
///
/// Named constants rather than literals because two decoders and one
/// round-trip proof have to agree about the same array, and a field appended to
/// `GraphSnapshot` moves the envelope. `the_envelope_index_names_the_authority`
/// pins both against the struct itself.
pub(crate) const GRAPH_SNAPSHOT_FIELD_COUNT: usize = 36;
/// The v13 body's width, which is the current width minus the appended field.
///
/// Kept as its own constant rather than as `FIELD_COUNT - 1` so that a future
/// append has to state what the older widths were instead of silently
/// redefining one of them.
pub(crate) const GRAPH_SNAPSHOT_V13_FIELD_COUNT: usize = 35;
pub(crate) const REPOSITORY_AUTHORITY_FIELD_INDEX: usize = 33;
pub(crate) const MATERIALIZED_GRAPH_FIELD_INDEX: usize = 35;

struct SnapshotFrame<'a> {
    version: u32,
    body: &'a [u8],
    body_checksum: Option<[u8; 32]>,
    checksum_end: usize,
}

// ---------------------------------------------------------------------------
// BorrowedGraphSnapshot — zero-clone serializable view over live graph stores
// ---------------------------------------------------------------------------

/// A borrowed view over live graph stores that serializes identically to
/// [`GraphSnapshot`].  By holding references to the existing in-memory data
/// (hashbrown maps + vecs), we avoid the ~18 GB clone that `to_snapshot()`
/// materialises for large graphs.
///
/// The `Serialize` impl manually writes 35 fields in the same positional
/// order as the derive(Serialize) on `GraphSnapshot`, so the resulting
/// msgpack is byte-for-byte compatible with the owned version.
pub struct BorrowedGraphSnapshot<'a> {
    // EntityData fields
    pub entities: &'a hashbrown::HashMap<EntityId, Entity>,
    pub relations: &'a hashbrown::HashMap<RelationId, Relation>,
    pub outgoing: &'a hashbrown::HashMap<EntityId, Vec<RelationId>>,
    pub incoming: &'a hashbrown::HashMap<EntityId, Vec<RelationId>>,
    pub resolved_tree: &'a ResolvedTree,
    pub shallow_files: &'a hashbrown::HashMap<FilePathId, ShallowTrackedFile>,
    pub file_layouts: &'a hashbrown::HashMap<FilePathId, FileLayout>,
    pub structured_artifacts: &'a hashbrown::HashMap<FilePathId, StructuredArtifact>,
    pub opaque_artifacts: &'a hashbrown::HashMap<FilePathId, OpaqueArtifact>,
    pub external_references: &'a hashbrown::HashMap<ExternalReferenceId, ExternalReference>,
    // ChangeData fields
    pub changes: &'a hashbrown::HashMap<SemanticChangeId, SemanticChange>,
    pub change_children: &'a hashbrown::HashMap<SemanticChangeId, Vec<SemanticChangeId>>,
    // WorkData fields
    pub work_items: &'a hashbrown::HashMap<WorkId, WorkItem>,
    pub annotations: &'a hashbrown::HashMap<AnnotationId, Annotation>,
    pub work_links: &'a Vec<WorkLink>,
    // ReviewData fields
    pub reviews: &'a hashbrown::HashMap<ReviewId, Review>,
    pub review_decisions: &'a hashbrown::HashMap<ReviewId, Vec<ReviewDecision>>,
    pub review_notes: &'a hashbrown::HashMap<ReviewNoteId, ReviewNote>,
    pub review_discussions: &'a hashbrown::HashMap<ReviewDiscussionId, ReviewDiscussion>,
    pub review_assignments: &'a hashbrown::HashMap<ReviewId, Vec<ReviewAssignment>>,
    // VerificationData fields
    pub test_cases: &'a hashbrown::HashMap<TestId, TestCase>,
    pub assertions: &'a hashbrown::HashMap<AssertionId, Assertion>,
    pub verification_runs: &'a hashbrown::HashMap<VerificationRunId, VerificationRun>,
    pub mock_hints: &'a Vec<MockHint>,
    pub contracts: &'a hashbrown::HashMap<ContractId, Contract>,
    // ProvenanceData fields
    pub actors: &'a hashbrown::HashMap<ActorId, Actor>,
    pub delegations: &'a Vec<Delegation>,
    pub approvals: &'a Vec<Approval>,
    pub audit_events: &'a Vec<AuditEvent>,
    // SessionData fields
    pub sessions: &'a hashbrown::HashMap<SessionId, AgentSession>,
    pub intents: &'a hashbrown::HashMap<IntentId, Intent>,
    pub downstream_warnings: &'a Vec<(IntentId, EntityId, String)>,
    pub entity_revisions: &'a hashbrown::HashMap<EntityId, Vec<EntityRevision>>,
}

impl<'a> Serialize for BorrowedGraphSnapshot<'a> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        // Must produce exactly GRAPH_SNAPSHOT_FIELD_COUNT fields in the same
        // order as GraphSnapshot's derive(Serialize).  rmp_serde serializes
        // structs as arrays, so position (not name) determines the mapping.
        let mut state = serializer.serialize_struct("GraphSnapshot", GRAPH_SNAPSHOT_FIELD_COUNT)?;

        // 1. version
        state.serialize_field("version", &GraphSnapshot::CURRENT_VERSION)?;
        // 2. entities  (hashbrown::HashMap → map)
        state.serialize_field("entities", self.entities)?;
        // 3. relations
        state.serialize_field("relations", self.relations)?;
        // 4. outgoing
        state.serialize_field("outgoing", self.outgoing)?;
        // 5. incoming
        state.serialize_field("incoming", self.incoming)?;
        // 6. changes
        state.serialize_field("changes", self.changes)?;
        // 7. change_children
        state.serialize_field("change_children", self.change_children)?;
        // 8. work_items
        state.serialize_field("work_items", self.work_items)?;
        // 9. annotations
        state.serialize_field("annotations", self.annotations)?;
        // 10. work_links
        state.serialize_field("work_links", self.work_links)?;
        // 11. reviews
        state.serialize_field("reviews", self.reviews)?;
        // 12. review_decisions
        state.serialize_field("review_decisions", self.review_decisions)?;
        // 13. review_notes  (HashMap values → seq)
        state.serialize_field("review_notes", &HashMapValuesAsSeq(self.review_notes))?;
        // 14. review_discussions  (HashMap values → seq)
        state.serialize_field(
            "review_discussions",
            &HashMapValuesAsSeq(self.review_discussions),
        )?;
        // 15. review_assignments
        state.serialize_field("review_assignments", self.review_assignments)?;
        // 16. test_cases
        state.serialize_field("test_cases", self.test_cases)?;
        // 17. assertions
        state.serialize_field("assertions", self.assertions)?;
        // 18. verification_runs
        state.serialize_field("verification_runs", self.verification_runs)?;
        // 19. mock_hints
        state.serialize_field("mock_hints", self.mock_hints)?;
        // 20. contracts
        state.serialize_field("contracts", self.contracts)?;
        // 21. actors
        state.serialize_field("actors", self.actors)?;
        // 22. delegations
        state.serialize_field("delegations", self.delegations)?;
        // 23. approvals
        state.serialize_field("approvals", self.approvals)?;
        // 24. audit_events
        state.serialize_field("audit_events", self.audit_events)?;
        // 25. shallow_files  (HashMap values → seq)
        state.serialize_field("shallow_files", &HashMapValuesAsSeq(self.shallow_files))?;
        // 26. file_layouts  (HashMap values → seq)
        state.serialize_field("file_layouts", &HashMapValuesAsSeq(self.file_layouts))?;
        // 27. structured_artifacts  (HashMap values → seq)
        state.serialize_field(
            "structured_artifacts",
            &HashMapValuesAsSeq(self.structured_artifacts),
        )?;
        // 28. opaque_artifacts  (HashMap values → seq)
        state.serialize_field(
            "opaque_artifacts",
            &HashMapValuesAsSeq(self.opaque_artifacts),
        )?;
        // 29. resolved_tree
        state.serialize_field("resolved_tree", self.resolved_tree)?;
        // 30. sessions
        state.serialize_field("sessions", self.sessions)?;
        // 31. intents
        state.serialize_field("intents", self.intents)?;
        // 32. downstream_warnings
        state.serialize_field("downstream_warnings", self.downstream_warnings)?;
        // 33. entity_revisions
        state.serialize_field("entity_revisions", self.entity_revisions)?;
        // 34. Mutable live graphs are not repository transaction authority.
        state.serialize_field(
            "repository_authority",
            &Option::<PersistedRepositoryAuthority>::None,
        )?;
        // 35. Resolved external symbols (append-only v13 field).
        state.serialize_field("external_references", self.external_references)?;
        // 36. A live mutable graph is not a published repository authority, so
        // it has no history root to bind a section to and never carries one.
        state.serialize_field(
            "materialized_graph",
            &Option::<MaterializedGraphSection>::None,
        )?;
        state.end()
    }
}

impl<'a> BorrowedGraphSnapshot<'a> {
    /// Serialize to the on-disk binary format (KNDB header + msgpack body + checksum).
    ///
    /// Produces bytes identical in structure to [`GraphSnapshot::to_bytes`] but
    /// without ever materialising an owned [`GraphSnapshot`].
    pub fn to_bytes(&self) -> Result<Vec<u8>, crate::error::KinDbError> {
        self.to_bytes_inner(None)
    }

    pub fn to_bytes_with_persisted_root_hash(
        &self,
        root_hash: [u8; 32],
    ) -> Result<Vec<u8>, crate::error::KinDbError> {
        self.to_bytes_inner(Some(root_hash))
    }

    fn to_bytes_inner(
        &self,
        persisted_root_hash: Option<[u8; 32]>,
    ) -> Result<Vec<u8>, crate::error::KinDbError> {
        self.validate_storage_admission()?;
        let trailer_len = persisted_root_hash
            .map(|_| GraphSnapshot::ROOT_HASH_TRAILER_LEN)
            .unwrap_or(0);
        // The same one-buffer assembly the owned snapshot uses, for the same
        // reason: this is the daemon's own save path over a live graph, and it
        // held two whole encodings of the store at once.
        assemble_snapshot_frame(self, persisted_root_hash, trailer_len)
    }

    fn validate_storage_admission(&self) -> Result<(), crate::error::KinDbError> {
        validate_semantic_change_entries(self.changes.iter(), "borrowed snapshot")?;
        for (id, reference) in self.external_references {
            validate_external_reference_entry(id, reference, "borrowed snapshot")?;
        }
        for file_id in self
            .shallow_files
            .keys()
            .chain(self.file_layouts.keys())
            .chain(self.structured_artifacts.keys())
            .chain(self.opaque_artifacts.keys())
        {
            let path = RepoPath::from_utf8(&file_id.0).map_err(|error| {
                crate::error::KinDbError::StorageError(format!(
                    "semantic enrichment has invalid repository path {}: {error}",
                    file_id.0
                ))
            })?;
            if self.resolved_tree.artifact_id_at_path(&path).is_none() {
                return Err(crate::error::KinDbError::StorageError(format!(
                    "semantic enrichment exists without admitted repository identity at {}",
                    file_id.0
                )));
            }
        }
        let entity_ids: HashSet<_> = self.entities.keys().copied().collect();
        let artifact_ids: HashSet<_> = self
            .resolved_tree
            .artifacts()
            .map(|artifact| artifact.artifact_id)
            .collect();
        let test_ids: HashSet<_> = self.test_cases.keys().copied().collect();
        let contract_ids: HashSet<_> = self.contracts.keys().copied().collect();
        let work_ids: HashSet<_> = self.work_items.keys().copied().collect();
        let run_ids: HashSet<_> = self.verification_runs.keys().copied().collect();
        let external_reference_ids: HashSet<_> = self.external_references.keys().copied().collect();
        let graph_node_ids = GraphNodeIds {
            entities: &entity_ids,
            artifacts: &artifact_ids,
            tests: &test_ids,
            contracts: &contract_ids,
            work_items: &work_ids,
            verification_runs: &run_ids,
            external_references: &external_reference_ids,
        };
        for relation in self.relations.values() {
            for (side, node) in [("source", relation.src), ("destination", relation.dst)] {
                if !graph_node_ids.contains(node) {
                    return Err(crate::error::KinDbError::StorageError(format!(
                        "borrowed snapshot relation {} has unadmitted {side} endpoint {node}",
                        relation.id
                    )));
                }
            }
        }
        Ok(())
    }
}

/// Helper that serializes a `hashbrown::HashMap`'s values as a sequence
/// (matching the `Vec<V>` fields in [`GraphSnapshot`]'s on-disk format).
struct HashMapValuesAsSeq<'a, K, V>(&'a hashbrown::HashMap<K, V>);

impl<K, V: Serialize> Serialize for HashMapValuesAsSeq<'_, K, V> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.0.values())
    }
}

struct GraphNodeIds<'a> {
    entities: &'a HashSet<EntityId>,
    artifacts: &'a HashSet<ArtifactId>,
    tests: &'a HashSet<TestId>,
    contracts: &'a HashSet<ContractId>,
    work_items: &'a HashSet<WorkId>,
    verification_runs: &'a HashSet<VerificationRunId>,
    external_references: &'a HashSet<ExternalReferenceId>,
}

impl GraphNodeIds<'_> {
    fn contains(&self, node: GraphNodeId) -> bool {
        match node {
            GraphNodeId::Entity(id) => self.entities.contains(&id),
            GraphNodeId::Artifact(id) => self.artifacts.contains(&id),
            GraphNodeId::Test(id) => self.tests.contains(&id),
            GraphNodeId::Contract(id) => self.contracts.contains(&id),
            GraphNodeId::Work(id) => self.work_items.contains(&id),
            GraphNodeId::VerificationRun(id) => self.verification_runs.contains(&id),
            GraphNodeId::ExternalReference(id) => self.external_references.contains(&id),
        }
    }
}

fn validate_external_reference_entry(
    id: &ExternalReferenceId,
    reference: &ExternalReference,
    context: &str,
) -> Result<(), crate::error::KinDbError> {
    if *id != reference.id {
        return Err(crate::error::KinDbError::StorageError(format!(
            "{context} external-reference key {id} does not match record identity {}",
            reference.id
        )));
    }
    reference.validate().map_err(|error| {
        crate::error::KinDbError::StorageError(format!(
            "{context} external reference {id} is invalid: {error}"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Regression (found by fuzzing): a snapshot header whose body_len is near
    /// usize::MAX must be rejected with an error, never wrap `16 + body_len`
    /// and panic on the body slice.
    #[test]
    fn from_bytes_rejects_overflowing_body_len_without_panic() {
        let mut data = Vec::new();
        data.extend_from_slice(&GraphSnapshot::MAGIC);
        data.extend_from_slice(&GraphSnapshot::CURRENT_VERSION.to_le_bytes());
        data.extend_from_slice(&u64::MAX.to_le_bytes()); // absurd body_len
        data.extend_from_slice(&[0u8; 16]); // some trailing bytes
        let result = GraphSnapshot::from_bytes(&data);
        assert!(
            result.is_err(),
            "overflowing body_len must error, not panic"
        );
    }

    fn test_entity(name: &str) -> Entity {
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0; 32]),
                signature_hash: Hash256::from_bytes([0; 32]),
                behavior_hash: Hash256::from_bytes([0; 32]),
                equivalence_hash: Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new("src/main.rs")),
            span: None,
            signature: format!("fn {name}()"),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    fn seal_change(mut change: SemanticChange) -> SemanticChange {
        change.id =
            kin_model::compute_semantic_change_id(&change).expect("valid semantic change fixture");
        change
    }

    fn encode_snapshot_without_admission_validation(snapshot: &GraphSnapshot) -> Vec<u8> {
        let body = rmp_serde::to_vec(snapshot).unwrap();
        let mut bytes = Vec::with_capacity(16 + body.len() + GraphSnapshot::CHECKSUM_LEN);
        bytes.extend_from_slice(&GraphSnapshot::MAGIC);
        bytes.extend_from_slice(&GraphSnapshot::CURRENT_VERSION.to_le_bytes());
        bytes.extend_from_slice(&(body.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&body);
        bytes.extend_from_slice(&Sha256::digest(&body));
        bytes
    }

    fn test_relation(src: EntityId, dst: EntityId) -> Relation {
        Relation {
            id: RelationId::new(),
            kind: RelationKind::Calls,
            src: GraphNodeId::Entity(src),
            dst: GraphNodeId::Entity(dst),
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
            evidence: Vec::new(),
        }
    }

    #[test]
    fn locate_snapshot_decode_preserves_locate_domains_only() {
        let caller = test_entity("caller");
        let callee = test_entity("callee");
        let relation = test_relation(caller.id, callee.id);
        let non_legacy_locate_relation = Relation {
            id: RelationId::new(),
            kind: RelationKind::SendsMessage,
            src: GraphNodeId::Entity(callee.id),
            dst: GraphNodeId::Entity(caller.id),
            confidence: 0.75,
            origin: RelationOrigin::Inferred,
            created_in: None,
            import_source: None,
            evidence: Vec::new(),
        };
        let external_reference =
            ExternalReference::new_resolved("python-module-v1", "requests", "get").unwrap();
        let external_relation = Relation {
            id: RelationId::new(),
            kind: RelationKind::Imports,
            src: GraphNodeId::Entity(caller.id),
            dst: GraphNodeId::ExternalReference(external_reference.id),
            confidence: 1.0,
            origin: RelationOrigin::Lsp,
            created_in: None,
            import_source: None,
            evidence: Vec::new(),
        };
        let change = seal_change(SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([9; 32])),
            parents: Vec::new(),
            timestamp: Timestamp::now(),
            author: AuthorId::new("tester"),
            message: "cochange".into(),
            entity_deltas: vec![EntityDelta::Added {
                new: caller.clone(),
            }],
            relation_deltas: Vec::new(),
            tree_deltas: Vec::new(),
            projected_files: vec![FilePathId::new("src/main.rs")],
            spec_link: None,
            evidence: Vec::new(),
            risk_summary: None,
            origin: kin_model::ChangeOrigin::Native,
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
        });

        let mut snapshot = GraphSnapshot::empty();
        snapshot.entities.insert(caller.id, caller.clone());
        snapshot.entities.insert(callee.id, callee.clone());
        snapshot.relations.insert(relation.id, relation.clone());
        snapshot.relations.insert(
            non_legacy_locate_relation.id,
            non_legacy_locate_relation.clone(),
        );
        snapshot
            .relations
            .insert(external_relation.id, external_relation);
        snapshot
            .external_references
            .insert(external_reference.id, external_reference.clone());
        snapshot.outgoing.insert(caller.id, vec![relation.id]);
        snapshot.incoming.insert(callee.id, vec![relation.id]);
        snapshot.changes.insert(change.id, change.clone());
        snapshot.entity_revisions =
            kin_model::graph::derive_entity_revisions_from_changes(vec![change.clone()]).unwrap();
        let file_id = FilePathId::new("src/main.rs");
        let assigned_artifact_id = ArtifactId::new();
        snapshot.shallow_files.push(ShallowTrackedFile {
            file_id: file_id.clone(),
            language_hint: "rust".into(),
            declaration_count: 2,
            import_count: 0,
            syntax_hash: Hash256::from_bytes([1; 32]),
            signature_hash: Some(Hash256::from_bytes([2; 32])),
            declaration_names: vec!["caller".into(), "callee".into()],
            import_paths: Vec::new(),
        });
        snapshot.resolved_tree = ResolvedTree::from_artifacts([ResolvedArtifact::new(
            assigned_artifact_id,
            RepoPath::from_utf8(&file_id.0).unwrap(),
            TreeEntry::blob(Hash256::from_bytes([1; 32]), false),
        )])
        .unwrap();

        let persisted_root_hash = [7; 32];
        let bytes = snapshot
            .to_bytes_with_persisted_root_hash(persisted_root_hash)
            .unwrap();
        let (locate_snapshot, decoded_root_hash) =
            LocateGraphSnapshot::from_bytes_with_persisted_root_hash(&bytes).unwrap();

        assert_eq!(decoded_root_hash, Some(persisted_root_hash));
        assert_eq!(locate_snapshot.entities.len(), 2);
        assert_eq!(locate_snapshot.relations.len(), 3);
        assert_eq!(
            locate_snapshot
                .relations
                .get(&non_legacy_locate_relation.id)
                .map(|relation| relation.kind),
            Some(RelationKind::SendsMessage)
        );
        assert_eq!(locate_snapshot.changes.len(), 1);
        assert_eq!(
            locate_snapshot
                .external_references
                .get(&external_reference.id),
            Some(&external_reference)
        );
        assert!(!locate_snapshot.entity_revisions.is_empty());
        assert_eq!(locate_snapshot.shallow_files.len(), 1);
        assert_eq!(
            locate_snapshot
                .resolved_tree
                .artifact_id_at_path(&RepoPath::from_utf8(&file_id.0).unwrap()),
            Some(assigned_artifact_id)
        );

        let decoded: GraphSnapshot = locate_snapshot.into();
        assert_eq!(
            decoded.external_references.get(&external_reference.id),
            Some(&external_reference)
        );
        assert_eq!(decoded.entities.len(), 2);
        assert_eq!(decoded.relations.len(), 3);
        assert_eq!(decoded.changes.len(), 1);
        assert!(!decoded.entity_revisions.is_empty());
        assert_eq!(
            decoded
                .resolved_tree
                .artifact_id_at_path(&RepoPath::from_utf8(&file_id.0).unwrap()),
            Some(assigned_artifact_id)
        );
        assert!(decoded.outgoing.is_empty());
        assert!(decoded.incoming.is_empty());
        assert!(decoded.work_items.is_empty());
        assert!(decoded.reviews.is_empty());
    }

    #[test]
    fn compact_empty_snapshot_is_clean() {
        let mut snap = GraphSnapshot::empty();
        let stats = snap.compact();
        assert!(stats.is_clean());
        assert_eq!(stats.total_removed(), 0);
        assert_eq!(stats.entities_before, 0);
        assert_eq!(stats.relations_before, 0);
    }

    // ── FIR-2654: the write path's round-trip proof stopped keeping the graph ──

    /// The number of fields the on-disk body carries, read off the MessagePack
    /// array header. Compact MessagePack encodes a struct positionally, so this
    /// is the format's own field count rather than a restatement of the source.
    fn encoded_field_count(body: &[u8]) -> usize {
        match body[0] {
            b @ 0x90..=0x9f => (b & 0x0f) as usize,
            0xdc => u16::from_be_bytes([body[1], body[2]]) as usize,
            0xdd => u32::from_be_bytes([body[1], body[2], body[3], body[4]]) as usize,
            other => panic!("snapshot body is not a MessagePack array: first byte {other:#x}"),
        }
    }

    #[test]
    fn round_trip_proof_lists_every_field_the_snapshot_encodes() {
        // The tripwire that makes a hand-maintained mirror safe. A field added
        // to GraphSnapshot changes the encoded array's arity, and the proof
        // type then refuses the bytes with `array had incorrect length` rather
        // than proving less than it claims. This test names the drift directly
        // so the next reader does not have to decode that error first.
        let snapshot = GraphSnapshot::empty();
        let body = rmp_serde::to_vec(&snapshot).expect("empty snapshot serializes");
        let encoded = encoded_field_count(&body);
        let proof: GraphSnapshotRoundTripProof = rmp_serde::from_slice(&body).unwrap_or_else(|e| {
            panic!(
                "GraphSnapshotRoundTripProof no longer matches GraphSnapshot's {encoded} encoded \
                 fields: {e}. Add the new field to the mirror, in the same position."
            )
        });
        assert_eq!(proof.version, snapshot.version);
    }

    #[test]
    fn the_envelope_decode_reads_the_same_authority_the_full_decode_reads() {
        // This is what pins REPOSITORY_AUTHORITY_FIELD_INDEX to the struct
        // rather than to a comment. The envelope decoder walks thirty-three
        // fields as IgnoredAny and then parses the thirty-fourth as an
        // `Option<PersistedRepositoryAuthority>`. Pointed one field either way
        // it would be parsing `entity_revisions` or `external_references`,
        // which are maps, and a struct is a positional array, so the decode
        // fails loudly instead of returning a wrong envelope.
        let mut snapshot = GraphSnapshot::empty();
        let repository_id = RepositoryId::new("envelope-index-test").expect("repository id");
        snapshot.repository_authority = Some(
            PersistedRepositoryAuthority::empty(repository_id.clone(), &snapshot)
                .expect("an empty authority is constructible"),
        );
        let bytes = snapshot.to_bytes().expect("serializes");

        let envelope = AuthorityEnvelopeSnapshot::from_bytes(&bytes).expect("the envelope decodes");
        assert_eq!(envelope.version, snapshot.version);
        assert_eq!(
            envelope.repository_authority, snapshot.repository_authority,
            "the envelope must be the authority the full decode reads, field for field"
        );

        let full = GraphSnapshot::from_bytes(&bytes).expect("the full decode accepts these bytes");
        assert_eq!(envelope.repository_authority, full.repository_authority);
    }

    #[test]
    fn the_envelope_constants_match_the_encoded_snapshot() {
        // The arity half of the same tripwire. A field appended to
        // GraphSnapshot moves the envelope, and this fails on the count before
        // anyone debugs a decode error.
        let snapshot = GraphSnapshot::empty();
        let body = rmp_serde::to_vec(&snapshot).expect("empty snapshot serializes");
        assert_eq!(
            encoded_field_count(&body),
            GRAPH_SNAPSHOT_FIELD_COUNT,
            "GraphSnapshot's encoded arity moved; the envelope decoder's field \
             indices are stale"
        );
        assert!(
            REPOSITORY_AUTHORITY_FIELD_INDEX < GRAPH_SNAPSHOT_FIELD_COUNT,
            "the envelope index must name a field that exists"
        );
    }

    #[test]
    fn the_envelope_decode_reports_an_absent_authority_as_absent() {
        // The negative arm. A legacy graph-only snapshot has no envelope, and
        // that has to read as None rather than as an error or as an empty
        // authority. Without this the test above passes with a decoder that
        // returns whatever it finds.
        let snapshot = GraphSnapshot::empty();
        assert!(snapshot.repository_authority.is_none());
        let bytes = snapshot
            .to_bytes_pre_validated()
            .expect("an authority-free snapshot serializes");
        let envelope = AuthorityEnvelopeSnapshot::from_bytes(&bytes).expect("the envelope decodes");
        assert!(
            envelope.repository_authority.is_none(),
            "an absent authority must read as absent"
        );
    }

    #[test]
    fn the_envelope_decode_refuses_a_locate_projection() {
        // The eleven-field locate cache is a current format that carries no
        // envelope. Decoding it as one would report every locate cache as an
        // authority-free repository, so the width is checked by name.
        let locate = LocateGraphSnapshot {
            version: GraphSnapshot::CURRENT_VERSION,
            entities: Default::default(),
            relations: Default::default(),
            changes: Default::default(),
            entity_revisions: Default::default(),
            shallow_files: Vec::new(),
            file_layouts: Vec::new(),
            structured_artifacts: Vec::new(),
            opaque_artifacts: Vec::new(),
            resolved_tree: ResolvedTree::default(),
            external_references: Default::default(),
        };
        let body = rmp_serde::to_vec(&locate).expect("the locate projection serializes");
        assert_eq!(encoded_field_count(&body), 11);
        assert!(
            rmp_serde::from_slice::<AuthorityEnvelopeSnapshot>(&body).is_err(),
            "an eleven-field locate body is not an authority envelope"
        );
    }

    #[test]
    fn the_envelope_decode_still_verifies_the_checksum() {
        // Named the same way its sibling above is named, and for the same
        // reason: a corrupted body also breaks the decode, so `is_err()` alone
        // would pass with checksum verification switched off and prove nothing.
        let snapshot = GraphSnapshot::empty();
        let bytes = snapshot.to_bytes_pre_validated().expect("serializes");
        let mut corrupt = bytes.clone();
        let body_start = 16;
        assert!(corrupt.len() > body_start, "body must exist to corrupt");
        corrupt[body_start] ^= 0xff;
        let error = AuthorityEnvelopeSnapshot::from_bytes(&corrupt)
            .expect_err("a corrupted body must be refused");
        assert!(
            error.to_string().contains("checksum"),
            "the refusal must be the checksum's, not the decoder's: {error}"
        );
    }

    #[test]
    fn drain_map_parses_every_entry_with_its_declared_type() {
        // The control that makes the proof worth running, and it has to test the
        // wrapper directly. Routing it through the whole snapshot did not work:
        // a short body fails on the array's ARITY before any element type is
        // examined, so that version of this test passed with the wrappers
        // swapped for `serde::de::IgnoredAny`, which proves nothing.
        let body = rmp_serde::to_vec(&HashMap::from([("k".to_string(), 7u32)]))
            .expect("a map of integers serializes");

        let matching: DrainMap<String, u32> =
            rmp_serde::from_slice(&body).expect("the declared types match these bytes");
        assert_eq!(
            matching.len, 1,
            "the entry must be counted as it is drained"
        );

        // An Entity is not a u32. `IgnoredAny` would accept this.
        assert!(
            rmp_serde::from_slice::<DrainMap<String, Entity>>(&body).is_err(),
            "a map whose values are integers is not a map of Entity"
        );
    }

    #[test]
    fn drain_seq_parses_every_element_with_its_declared_type() {
        let body = rmp_serde::to_vec(&vec![1u32, 2, 3]).expect("serializes");
        let matching: DrainSeq<u32> = rmp_serde::from_slice(&body).expect("types match");
        assert_eq!(matching.len, 3);
        assert!(
            rmp_serde::from_slice::<DrainSeq<Entity>>(&body).is_err(),
            "a sequence of integers is not a sequence of Entity"
        );
    }

    #[test]
    fn prove_pre_validated_round_trip_accepts_what_decode_pre_validated_accepts() {
        // Same bytes, same verdict: the cheap proof must not be more permissive
        // than the decode it replaces.
        let snapshot = GraphSnapshot::empty();
        let bytes = snapshot.to_bytes_pre_validated().expect("serializes");
        GraphSnapshot::decode_pre_validated(&bytes).expect("the full decode accepts these bytes");
        GraphSnapshot::prove_pre_validated_round_trip(&bytes)
            .expect("the non-retaining proof must accept them too");
    }

    #[test]
    fn prove_pre_validated_round_trip_still_verifies_the_checksum() {
        // Naming the checksum is the point. Asserting only `is_err()` passed
        // with checksum verification switched OFF, because a corrupted body also
        // breaks the decode: the test could not tell the two apart and so did
        // not hold the obligation it claimed.
        let snapshot = GraphSnapshot::empty();
        let bytes = snapshot.to_bytes_pre_validated().expect("serializes");
        let mut corrupt = bytes.clone();
        let body_start = 16;
        assert!(corrupt.len() > body_start, "body must exist to corrupt");
        corrupt[body_start] ^= 0xff;
        let error = GraphSnapshot::prove_pre_validated_round_trip(&corrupt)
            .expect_err("a corrupted body must be refused");
        assert!(
            error.to_string().contains("checksum mismatch"),
            "the checksum must be what refuses a corrupted body, not the decode: {error}"
        );
    }

    #[test]
    fn snapshot_deserialization_rejects_duplicate_artifact_identity_assignments() {
        let snapshot = GraphSnapshot::empty();
        let artifact_id = ArtifactId::new();
        let mut encoded = serde_json::to_value(snapshot).unwrap();
        encoded["resolved_tree"] = serde_json::json!({
            "artifacts": [
                ResolvedArtifact::new(
                    artifact_id,
                    RepoPath::from_utf8("compose.yaml").unwrap(),
                    TreeEntry::blob(Hash256::from_bytes([1; 32]), false),
                ),
                ResolvedArtifact::new(
                    artifact_id,
                    RepoPath::from_utf8("Cargo.lock").unwrap(),
                    TreeEntry::blob(Hash256::from_bytes([2; 32]), false),
                ),
            ]
        });

        let error = serde_json::from_value::<GraphSnapshot>(encoded).unwrap_err();
        assert!(error.to_string().contains("more than once"));
    }

    #[test]
    fn snapshot_rejects_semantic_enrichment_without_tree_admission() {
        let mut snapshot = GraphSnapshot::empty();
        snapshot.structured_artifacts.push(StructuredArtifact {
            file_id: FilePathId::new("compose.yaml"),
            kind: ArtifactKind::ComposeFile,
            content_hash: Hash256::from_bytes([7; 32]),
            text_preview: Some("services:".into()),
        });

        let error = snapshot.to_bytes().unwrap_err();

        assert!(error
            .to_string()
            .contains("without admitted repository identity"));
    }

    #[test]
    fn compact_removes_orphaned_relations() {
        let mut snap = GraphSnapshot::empty();

        let e1 = test_entity("alive");
        let e2 = test_entity("dead"); // will not be in entities
        let rel = test_relation(e1.id, e2.id);

        snap.entities.insert(e1.id, e1.clone());
        // e2 is NOT inserted — making the relation orphaned
        snap.relations.insert(rel.id, rel.clone());
        snap.outgoing.insert(e1.id, vec![rel.id]);
        snap.incoming.insert(e2.id, vec![rel.id]);

        let stats = snap.compact();
        assert_eq!(stats.orphaned_relations_removed, 1);
        assert!(snap.relations.is_empty());
        assert!(snap.outgoing.is_empty()); // cleaned because relation was removed
        assert!(snap.incoming.is_empty()); // cleaned because e2 doesn't exist
        assert!(!stats.is_clean());
    }

    #[test]
    fn compact_preserves_valid_relations() {
        let mut snap = GraphSnapshot::empty();

        let e1 = test_entity("caller");
        let e2 = test_entity("callee");
        let rel = test_relation(e1.id, e2.id);

        snap.entities.insert(e1.id, e1.clone());
        snap.entities.insert(e2.id, e2.clone());
        snap.relations.insert(rel.id, rel.clone());
        snap.outgoing.insert(e1.id, vec![rel.id]);
        snap.incoming.insert(e2.id, vec![rel.id]);

        let stats = snap.compact();
        assert!(stats.is_clean());
        assert_eq!(snap.relations.len(), 1);
        assert_eq!(snap.outgoing.len(), 1);
        assert_eq!(snap.incoming.len(), 1);
    }

    #[test]
    fn compact_preserves_artifact_relations_with_persisted_artifact_ids() {
        let mut snap = GraphSnapshot::empty();
        let generated_path = FilePathId::new("single_include/nlohmann/json.hpp");
        let source_path = FilePathId::new("include/nlohmann/detail/exceptions.hpp");
        let generated_id = ArtifactId::new();
        let source_id = ArtifactId::new();

        for file_id in [&generated_path, &source_path] {
            snap.file_layouts.push(FileLayout {
                file_id: file_id.clone(),
                imports: ImportSection {
                    byte_range: 0..0,
                    items: Vec::new(),
                },
                regions: Vec::new(),
                parse_completeness: ParseCompleteness::Full,
            });
        }
        snap.resolved_tree = ResolvedTree::from_artifacts([
            ResolvedArtifact::new(
                generated_id,
                RepoPath::from_utf8(&generated_path.0).unwrap(),
                TreeEntry::blob(Hash256::from_bytes([1; 32]), false),
            ),
            ResolvedArtifact::new(
                source_id,
                RepoPath::from_utf8(&source_path.0).unwrap(),
                TreeEntry::blob(Hash256::from_bytes([2; 32]), false),
            ),
        ])
        .unwrap();

        let relation = Relation {
            id: RelationId::new(),
            kind: RelationKind::DerivedFrom,
            src: GraphNodeId::Artifact(generated_id),
            dst: GraphNodeId::Artifact(source_id),
            confidence: 0.9,
            origin: RelationOrigin::Inferred,
            created_in: None,
            import_source: None,
            evidence: Vec::new(),
        };
        snap.relations.insert(relation.id, relation);

        let stats = snap.compact();
        assert_eq!(stats.orphaned_relations_removed, 0);
        assert_eq!(snap.relations.len(), 1);
    }

    #[test]
    fn compact_removes_orphaned_mock_hints() {
        let mut snap = GraphSnapshot::empty();

        let e1 = test_entity("target");
        snap.entities.insert(e1.id, e1.clone());

        let dead_test = TestId::new();
        snap.mock_hints.push(MockHint {
            hint_id: MockHintId::new(),
            test_id: dead_test,
            dependency_scope: WorkScope::Entity(e1.id),
            strategy: MockStrategy::Stub,
        });

        let stats = snap.compact();
        assert_eq!(stats.orphaned_mock_hints_removed, 1);
        assert!(snap.mock_hints.is_empty());
    }

    #[test]
    fn compact_removes_orphaned_downstream_warnings() {
        let mut snap = GraphSnapshot::empty();

        let e1 = test_entity("warned");
        snap.entities.insert(e1.id, e1.clone());
        let dead_intent = IntentId::new();

        snap.downstream_warnings
            .push((dead_intent, e1.id, "stale warning".into()));

        let stats = snap.compact();
        assert_eq!(stats.orphaned_downstream_warnings_removed, 1);
        assert!(snap.downstream_warnings.is_empty());
    }

    #[test]
    fn compact_removes_orphaned_approvals() {
        let mut snap = GraphSnapshot::empty();

        let dead_change = SemanticChangeId::from_hash(Hash256::from_bytes([99; 32]));
        let actor = Actor {
            actor_id: ActorId::new(),
            kind: ActorKind::Human,
            display_name: "tester".into(),
            external_refs: vec![],
        };
        snap.actors.insert(actor.actor_id, actor.clone());

        snap.approvals.push(Approval {
            approval_id: ApprovalId::new(),
            change_id: dead_change,
            approver: actor.actor_id,
            decision: ApprovalDecision::Approved,
            reason: "looks good".into(),
            timestamp: Timestamp::now(),
        });

        let stats = snap.compact();
        assert_eq!(stats.orphaned_approvals_removed, 1);
        assert!(snap.approvals.is_empty());
    }

    #[test]
    fn compact_removes_orphaned_delegations() {
        let mut snap = GraphSnapshot::empty();

        let dead_actor = ActorId::new();
        let live_actor = ActorId::new();
        snap.actors.insert(
            live_actor,
            Actor {
                actor_id: live_actor,
                kind: ActorKind::Human,
                display_name: "live".into(),
                external_refs: vec![],
            },
        );

        snap.delegations.push(Delegation {
            delegation_id: DelegationId::new(),
            principal: live_actor,
            delegate: dead_actor, // doesn't exist
            scope: vec![],
            started_at: Timestamp::now(),
            ended_at: None,
        });

        let stats = snap.compact();
        assert_eq!(stats.orphaned_delegations_removed, 1);
        assert!(snap.delegations.is_empty());
    }

    #[test]
    fn compact_stats_total_removed() {
        let mut snap = GraphSnapshot::empty();

        let e1 = test_entity("live");
        snap.entities.insert(e1.id, e1.clone());
        let dead_entity = EntityId::new();

        // Add multiple types of orphaned data
        let rel = test_relation(e1.id, dead_entity);
        snap.relations.insert(rel.id, rel);

        let dead_intent = IntentId::new();
        snap.downstream_warnings
            .push((dead_intent, e1.id, "orphan".into()));

        let stats = snap.compact();
        assert!(stats.total_removed() >= 2);
        assert!(!stats.is_clean());
    }

    /// The frame the two-buffer assembly produced, kept as a reference.
    ///
    /// This is the code that wrote every snapshot on disk today: serialize the
    /// body into its own `Vec`, then copy it into an exactly-sized frame
    /// buffer. It is retained here and nowhere else, so the one-buffer
    /// assembly is compared against the implementation the stores were written
    /// under rather than against itself.
    fn reference_two_buffer_frame(
        snapshot: &GraphSnapshot,
        persisted_root_hash: Option<[u8; 32]>,
    ) -> Vec<u8> {
        let body = rmp_serde::to_vec(snapshot).expect("reference body serializes");
        let trailer_len = persisted_root_hash
            .map(|_| GraphSnapshot::ROOT_HASH_TRAILER_LEN)
            .unwrap_or(0);
        let mut buf =
            Vec::with_capacity(16 + body.len() + GraphSnapshot::CHECKSUM_LEN + trailer_len);
        buf.extend_from_slice(&GraphSnapshot::MAGIC);
        buf.extend_from_slice(&GraphSnapshot::CURRENT_VERSION.to_le_bytes());
        buf.extend_from_slice(&(body.len() as u64).to_le_bytes());
        buf.extend(&body);
        let body_checksum: [u8; 32] = Sha256::digest(&body).into();
        buf.extend_from_slice(&body_checksum);
        if let Some(root_hash) = persisted_root_hash {
            GraphSnapshot::append_root_hash_trailer(&mut buf, body_checksum, root_hash);
        }
        buf
    }

    /// Snapshot shapes that exercise every branch the frame assembly takes.
    fn frame_corpus() -> Vec<(&'static str, GraphSnapshot)> {
        let empty = GraphSnapshot::empty();

        let mut one_entity = GraphSnapshot::empty();
        let solo = test_entity("solo");
        one_entity.entities.insert(solo.id, solo);

        let mut related = GraphSnapshot::empty();
        let left = test_entity("left");
        let right = test_entity("right");
        let edge = test_relation(left.id, right.id);
        related.entities.insert(left.id, left.clone());
        related.entities.insert(right.id, right.clone());
        related.relations.insert(edge.id, edge.clone());
        related.outgoing.insert(left.id, vec![edge.id]);
        related.incoming.insert(right.id, vec![edge.id]);

        // Large enough that the writing pass crosses whatever buffer boundary
        // an encoder might choose, which is the case a small fixture cannot
        // reach and the one a real repository always does.
        let mut many = GraphSnapshot::empty();
        for index in 0..512 {
            let entity = test_entity(&format!("bulk_{index}"));
            many.entities.insert(entity.id, entity);
        }

        // Non-ASCII text through the encoder: combining marks, an
        // astral-plane character and a bidi mark.
        let mut unicode = GraphSnapshot::empty();
        let mut marked = test_entity("uni");
        marked.signature = "fn e\u{0301}\u{1F4A1}\u{200F}()".to_string();
        unicode.entities.insert(marked.id, marked);

        vec![
            ("empty", empty),
            ("one_entity", one_entity),
            ("related", related),
            ("five_hundred_entities", many),
            ("unicode_signature", unicode),
        ]
    }

    /// The frame assembled in one buffer must be byte-identical to the frame
    /// assembled in two, for every shape.
    ///
    /// A changed snapshot frame makes every store on disk unreadable, so this
    /// is the bar the one-buffer assembly has to clear, and it is compared
    /// against the retained original rather than against itself.
    #[test]
    fn the_one_buffer_frame_is_the_two_buffer_frame_for_every_corpus_shape() {
        let root_hash = [7u8; 32];
        for (name, snapshot) in frame_corpus() {
            let reference = reference_two_buffer_frame(&snapshot, None);
            let shipped = snapshot.to_bytes().expect("shipped assembly serializes");
            assert_eq!(
                reference,
                shipped,
                "`{name}` frames differently in one buffer than in two, over its {} byte frame",
                reference.len()
            );
            assert_eq!(
                reference,
                snapshot
                    .to_bytes_pre_validated()
                    .expect("pre-validated assembly serializes"),
                "`{name}` frames differently on the pre-validated path"
            );

            let reference_with_trailer = reference_two_buffer_frame(&snapshot, Some(root_hash));
            let shipped_with_trailer = snapshot
                .to_bytes_with_persisted_root_hash(root_hash)
                .expect("trailer assembly serializes");
            assert_eq!(
                reference_with_trailer, shipped_with_trailer,
                "`{name}` frames differently with a persisted root-hash trailer"
            );

            // The frame still decodes to the snapshot it was made from, which
            // is the property a byte comparison alone would not catch if BOTH
            // implementations were wrong in the same way.
            let decoded = GraphSnapshot::from_bytes(&shipped).expect("frame decodes");
            assert_eq!(
                decoded.entities.len(),
                snapshot.entities.len(),
                "`{name}` decoded to a different entity count"
            );
            assert_eq!(
                decoded.relations.len(),
                snapshot.relations.len(),
                "`{name}` decoded to a different relation count"
            );
        }
    }

    /// The header must describe the body it is stapled to.
    ///
    /// Every assertion above proves sameness, and an assembly that emitted a
    /// constant frame would satisfy all of them. This reads the declared body
    /// length out of the header and checks it against where the checksum
    /// actually starts, per shape.
    #[test]
    fn the_frame_header_declares_the_body_length_it_actually_wrote() {
        for (name, snapshot) in frame_corpus() {
            let frame = snapshot.to_bytes().expect("frame serializes");
            let declared = u64::from_le_bytes(
                frame[8..16]
                    .try_into()
                    .expect("the header carries eight length bytes"),
            ) as usize;
            assert_eq!(
                declared,
                frame.len() - 16 - GraphSnapshot::CHECKSUM_LEN,
                "`{name}` declares a body length its frame does not carry"
            );
            let checksum: [u8; 32] = Sha256::digest(&frame[16..16 + declared]).into();
            assert_eq!(
                &checksum[..],
                &frame[16 + declared..16 + declared + GraphSnapshot::CHECKSUM_LEN],
                "`{name}` carries a checksum of bytes other than its own body"
            );
        }
    }

    #[test]
    fn compact_roundtrip_produces_identical_bytes() {
        let mut snap = GraphSnapshot::empty();

        let e1 = test_entity("a");
        let e2 = test_entity("b");
        let rel = test_relation(e1.id, e2.id);

        snap.entities.insert(e1.id, e1.clone());
        snap.entities.insert(e2.id, e2.clone());
        snap.relations.insert(rel.id, rel.clone());
        snap.outgoing.insert(e1.id, vec![rel.id]);
        snap.incoming.insert(e2.id, vec![rel.id]);

        // Compact a clean snapshot — should be idempotent
        snap.compact();
        let bytes1 = snap.to_bytes().unwrap();

        snap.compact();
        let bytes2 = snap.to_bytes().unwrap();

        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn to_bytes_rejects_noncurrent_body_version() {
        let mut snap = GraphSnapshot::empty();
        let e = test_entity("fast_path");
        snap.entities.insert(e.id, e);

        assert_eq!(snap.version, GraphSnapshot::CURRENT_VERSION);
        assert!(snap.to_bytes().is_ok());

        snap.version = 1;
        let error = snap.to_bytes().unwrap_err();
        // Derived from the constant rather than typed, because a hardcoded
        // version in an assertion goes stale on exactly the commit that most
        // needs the assertion to still mean something.
        assert!(error
            .to_string()
            .contains(&format!("exactly v{}", GraphSnapshot::CURRENT_VERSION)));
    }

    #[test]
    fn roundtrip_empty_snapshot() {
        let snap = GraphSnapshot::empty();

        let bytes = snap.to_bytes().unwrap();
        let loaded = GraphSnapshot::from_bytes(&bytes).unwrap();
        assert_eq!(loaded.version, GraphSnapshot::CURRENT_VERSION);
        assert!(loaded.entities.is_empty());
    }

    #[test]
    fn pre_validated_serialization_matches_validated_bytes_exactly() {
        let mut snap = GraphSnapshot::empty();
        let e = test_entity("shared_prevalidated");
        snap.entities.insert(e.id, e);

        assert_eq!(
            snap.to_bytes().unwrap(),
            snap.to_bytes_pre_validated().unwrap(),
            "skipping the redundant admission walk must not change one byte"
        );
    }

    #[test]
    fn pre_validated_serialization_skips_only_the_admission_walk() {
        let mut snap = GraphSnapshot::empty();
        let dangling = test_relation(EntityId::new(), EntityId::new());
        snap.relations.insert(dangling.id, dangling);

        let error = snap.to_bytes().unwrap_err();
        assert!(error.to_string().contains("unadmitted"));
        snap.to_bytes_pre_validated()
            .expect("pre-validated serialization trusts the caller's admission gate");

        snap.version = 1;
        let error = snap.to_bytes_pre_validated().unwrap_err();
        assert!(
            error.to_string().contains("exactly v"),
            "the version gate must keep running on the pre-validated path"
        );
    }

    #[test]
    fn roundtrip_preserves_executable_symlink_and_unsupported_paths() {
        let mut snapshot = GraphSnapshot::empty();
        let executable = TreeEntry::blob(Hash256::from_bytes([0x41; 32]), true);
        let symlink = TreeEntry::symlink(Hash256::from_bytes([0x42; 32]));
        let opaque = TreeEntry::blob(Hash256::from_bytes([0x43; 32]), false);
        snapshot.resolved_tree = ResolvedTree::from_artifacts([
            ResolvedArtifact::new(
                ArtifactId::new(),
                RepoPath::from_utf8("scripts/deploy").unwrap(),
                executable,
            ),
            ResolvedArtifact::new(
                ArtifactId::new(),
                RepoPath::from_utf8("current-config").unwrap(),
                symlink,
            ),
            ResolvedArtifact::new(
                ArtifactId::new(),
                RepoPath::from_utf8("assets/model.unsupported").unwrap(),
                opaque,
            ),
        ])
        .unwrap();

        let loaded = GraphSnapshot::from_bytes(&snapshot.to_bytes().unwrap()).unwrap();

        assert_eq!(
            loaded
                .resolved_tree
                .artifact_at_path(&RepoPath::from_utf8("scripts/deploy").unwrap())
                .map(|artifact| artifact.entry),
            Some(executable)
        );
        assert_eq!(
            loaded
                .resolved_tree
                .artifact_at_path(&RepoPath::from_utf8("current-config").unwrap())
                .map(|artifact| artifact.entry),
            Some(symlink)
        );
        assert_eq!(
            loaded
                .resolved_tree
                .artifact_at_path(&RepoPath::from_utf8("assets/model.unsupported").unwrap())
                .map(|artifact| artifact.entry),
            Some(opaque)
        );
    }

    /// The one field a v14 body may be missing, because a v13 body IS one.
    ///
    /// Named as a list rather than skipped inside the loop so that a second
    /// defaulted field has to be added here deliberately. A `continue` on a
    /// condition would have let the next one in silently.
    const DELIBERATELY_DEFAULTED_FIELDS: [&str; 1] = ["materialized_graph"];

    #[test]
    fn current_snapshot_requires_every_persisted_field() {
        let encoded = serde_json::to_value(GraphSnapshot::empty()).unwrap();
        let fields: Vec<String> = encoded
            .as_object()
            .expect("snapshot serializes as a map")
            .keys()
            .cloned()
            .collect();

        let mut required = 0;
        for field in fields {
            let mut missing = encoded.clone();
            missing
                .as_object_mut()
                .expect("snapshot serializes as a map")
                .remove(&field);

            if DELIBERATELY_DEFAULTED_FIELDS.contains(&field.as_str()) {
                serde_json::from_value::<GraphSnapshot>(missing).unwrap_or_else(|error| {
                    panic!(
                        "{field} is documented as defaulted and must decode when absent: {error}"
                    )
                });
                continue;
            }

            let error = serde_json::from_value::<GraphSnapshot>(missing).unwrap_err();
            assert!(
                error.to_string().contains(&field),
                "missing {field} should fail explicitly: {error}"
            );
            required += 1;
        }
        assert_eq!(
            required,
            GRAPH_SNAPSHOT_FIELD_COUNT - DELIBERATELY_DEFAULTED_FIELDS.len(),
            "every field except the documented exemptions must be required, and the count is \
             asserted so a field that stops being checked cannot pass as one that was exempt"
        );
    }

    #[test]
    fn current_snapshot_rejects_unknown_persisted_fields() {
        let mut encoded = serde_json::to_value(GraphSnapshot::empty()).unwrap();
        encoded
            .as_object_mut()
            .expect("snapshot serializes as a map")
            .insert("working_tree".to_string(), serde_json::json!([]));

        let error = serde_json::from_value::<GraphSnapshot>(encoded).unwrap_err();
        assert!(
            error.to_string().contains("unknown field `working_tree`"),
            "unexpected error: {error}"
        );
    }

    #[test]
    fn current_version_checksum_is_appended() {
        let snap = GraphSnapshot::empty();
        let bytes = snap.to_bytes().unwrap();

        // Header: 4 magic + 4 version + 8 body_len = 16
        let body_len = u64::from_le_bytes(bytes[8..16].try_into().unwrap()) as usize;
        // Total should be header + body + 32-byte checksum
        assert_eq!(bytes.len(), 16 + body_len + GraphSnapshot::CHECKSUM_LEN);

        // Version in header should match the current format version.
        let version = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        assert_eq!(version, GraphSnapshot::CURRENT_VERSION);
    }

    #[test]
    fn snapshot_decode_rejects_corrupted_semantic_change_identity() {
        let mut snapshot = GraphSnapshot::empty();
        let change = seal_change(SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0x91; 32])),
            parents: Vec::new(),
            timestamp: Timestamp::now(),
            author: AuthorId::new("tester"),
            message: "valid before corruption".into(),
            entity_deltas: Vec::new(),
            relation_deltas: Vec::new(),
            tree_deltas: Vec::new(),
            projected_files: Vec::new(),
            spec_link: None,
            evidence: Vec::new(),
            risk_summary: None,
            origin: kin_model::ChangeOrigin::Native,
            admission_policy_delta: None,
            external_reference_deltas: Vec::new(),
        });
        snapshot.changes.insert(change.id, change.clone());
        snapshot
            .changes
            .get_mut(&change.id)
            .unwrap()
            .message
            .push_str(" after id was sealed");

        let bytes = encode_snapshot_without_admission_validation(&snapshot);
        let error = GraphSnapshot::from_bytes(&bytes)
            .expect_err("checksum-valid snapshot corruption must fail identity validation");
        assert!(error.to_string().contains("recomputes to"));

        let error = GraphSnapshot::from_bytes_with_persisted_root_hash_unverified(&bytes)
            .expect_err("the mmap checksum shortcut must still validate change identity");
        assert!(error.to_string().contains("recomputes to"));
    }

    #[test]
    fn current_version_roundtrips_persisted_root_hash_trailer() {
        let mut snap = GraphSnapshot::empty();
        let entity = test_entity("persisted-root");
        snap.entities.insert(entity.id, entity);
        let root_hash = crate::storage::merkle::compute_graph_root_hash(&snap);

        let bytes = snap.to_bytes_with_persisted_root_hash(root_hash).unwrap();
        let body_len = u64::from_le_bytes(bytes[8..16].try_into().unwrap()) as usize;
        assert_eq!(
            bytes.len(),
            16 + body_len + GraphSnapshot::CHECKSUM_LEN + GraphSnapshot::ROOT_HASH_TRAILER_LEN
        );

        let (loaded, persisted_root_hash) =
            GraphSnapshot::from_bytes_with_persisted_root_hash(&bytes).unwrap();
        assert_eq!(persisted_root_hash, Some(root_hash));
        assert_eq!(loaded.entities.len(), 1);
    }

    #[test]
    fn current_version_unverified_load_reads_persisted_root_hash_trailer() {
        let mut snap = GraphSnapshot::empty();
        let entity = test_entity("persisted-root-unverified");
        snap.entities.insert(entity.id, entity);
        let root_hash = crate::storage::merkle::compute_graph_root_hash(&snap);

        let (loaded, persisted_root_hash) =
            GraphSnapshot::from_bytes_with_persisted_root_hash_unverified(
                &snap.to_bytes_with_persisted_root_hash(root_hash).unwrap(),
            )
            .unwrap();
        assert_eq!(persisted_root_hash, Some(root_hash));
        assert_eq!(loaded.entities.len(), 1);
    }

    #[test]
    fn corrupted_persisted_root_hash_trailer_is_rejected() {
        let snap = GraphSnapshot::empty();
        let root_hash = crate::storage::merkle::compute_graph_root_hash(&snap);
        let mut bytes = snap.to_bytes_with_persisted_root_hash(root_hash).unwrap();
        let trailer_digest_offset = bytes.len() - 1;
        bytes[trailer_digest_offset] ^= 0xFF;

        let err = GraphSnapshot::from_bytes_with_persisted_root_hash(&bytes).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("root-hash trailer mismatch") || msg.contains("corrupted"),
            "expected root-hash trailer error, got: {msg}"
        );
    }

    #[test]
    fn current_version_corrupted_body_detected() {
        let snap = GraphSnapshot::empty();
        let mut bytes = snap.to_bytes().unwrap();

        // Corrupt a byte in the body (after the 16-byte header)
        if bytes.len() > 20 {
            bytes[20] ^= 0xFF;
        }

        let err = GraphSnapshot::from_bytes(&bytes).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("checksum mismatch") || msg.contains("corrupted"),
            "expected checksum error, got: {msg}"
        );
    }

    #[test]
    fn snapshot_rejects_external_reference_key_and_endpoint_corruption() {
        let admitted =
            ExternalReference::new_resolved("python-module-v1", "requests", "get").unwrap();
        let missing =
            ExternalReference::new_resolved("python-module-v1", "urllib", "open").unwrap();

        let mut key_mismatch = GraphSnapshot::empty();
        key_mismatch
            .external_references
            .insert(missing.id, admitted.clone());
        let error = key_mismatch
            .to_bytes()
            .expect_err("map keys must bind the external record identity");
        assert!(error.to_string().contains("does not match record identity"));

        let mut dangling = GraphSnapshot::empty();
        dangling
            .external_references
            .insert(admitted.id, admitted.clone());
        let relation = Relation {
            id: RelationId::new(),
            kind: RelationKind::Imports,
            src: GraphNodeId::ExternalReference(admitted.id),
            dst: GraphNodeId::ExternalReference(missing.id),
            confidence: 1.0,
            origin: RelationOrigin::Lsp,
            created_in: None,
            import_source: None,
            evidence: Vec::new(),
        };
        dangling.relations.insert(relation.id, relation);
        let error = dangling
            .to_bytes()
            .expect_err("relations cannot target an unadmitted external reference");
        assert!(error
            .to_string()
            .contains("unadmitted destination endpoint"));
    }

    #[test]
    fn current_version_truncated_checksum_detected() {
        let snap = GraphSnapshot::empty();
        let bytes = snap.to_bytes().unwrap();

        // Truncate the last 10 bytes (partial checksum)
        let truncated = &bytes[..bytes.len() - 10];

        let err = GraphSnapshot::from_bytes(truncated).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("missing checksum"),
            "expected missing checksum error, got: {msg}"
        );
    }

    #[test]
    fn rejects_v2_snapshot_without_inventing_tree_modes() {
        let snap = GraphSnapshot::empty();
        let mut snapshot = snap.clone();
        snapshot.version = 2;
        let body = rmp_serde::to_vec(&snapshot).unwrap();

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&GraphSnapshot::MAGIC);
        bytes.extend_from_slice(&2u32.to_le_bytes());
        bytes.extend_from_slice(&(body.len() as u64).to_le_bytes());
        bytes.extend(body);

        let error = GraphSnapshot::from_bytes(&bytes).unwrap_err();
        assert!(matches!(
            error,
            crate::KinDbError::IncompatibleSnapshotVersion { found: 2, .. }
        ));
    }

    /// A v11 snapshot can persist an exact dirty workspace tree without its
    /// semantic overlay. It must never masquerade as current authority.
    #[test]
    fn v11_tree_only_workspace_snapshot_fails_fast_with_actionable_error() {
        let stale_version = 11u32;
        assert_eq!(GraphSnapshot::MIN_SUPPORTED_VERSION, 13);
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&GraphSnapshot::MAGIC);
        bytes.extend_from_slice(&stale_version.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes()); // empty body

        let err = GraphSnapshot::from_bytes(&bytes).unwrap_err();
        assert!(
            matches!(
                err,
                crate::error::KinDbError::IncompatibleSnapshotVersion { found, .. }
                    if found == stale_version
            ),
            "expected IncompatibleSnapshotVersion, got: {err:?}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("older than"),
            "missing version-gap wording: {msg}"
        );
        assert!(
            msg.contains(&format!(
                "versions {} through {}",
                GraphSnapshot::MIN_SUPPORTED_VERSION,
                GraphSnapshot::CURRENT_VERSION
            )),
            "missing supported-range wording: {msg}"
        );
        assert!(
            msg.contains("reinitialize")
                && msg.contains("workspace semantics")
                && msg.contains("file modes"),
            "missing exact-workspace remediation: {msg}"
        );
    }

    /// A snapshot written by a newer Kin must also fail fast with a typed,
    /// actionable error (upgrade guidance) rather than crashing.
    #[test]
    fn future_schema_snapshot_fails_fast_with_actionable_error() {
        let future_version = GraphSnapshot::CURRENT_VERSION + 1;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&GraphSnapshot::MAGIC);
        bytes.extend_from_slice(&future_version.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());

        let err = GraphSnapshot::from_bytes(&bytes).unwrap_err();
        assert!(
            matches!(
                err,
                crate::error::KinDbError::IncompatibleSnapshotVersion { found, .. }
                    if found == future_version
            ),
            "expected IncompatibleSnapshotVersion, got: {err:?}"
        );
        let msg = err.to_string();
        assert!(
            msg.contains("newer than"),
            "missing version-gap wording: {msg}"
        );
        assert!(
            msg.contains("upgrade Kin"),
            "missing upgrade remediation: {msg}"
        );
    }

    #[test]
    fn rejects_current_layout_body_with_v3_envelope() {
        let mut snapshot = GraphSnapshot::empty();
        snapshot.version = 3;
        let body = rmp_serde::to_vec(&snapshot).unwrap();

        let mut bytes = Vec::new();
        bytes.extend_from_slice(&GraphSnapshot::MAGIC);
        bytes.extend_from_slice(&3u32.to_le_bytes());
        bytes.extend_from_slice(&(body.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&body);
        bytes.extend_from_slice(&Sha256::digest(&body));

        let error = GraphSnapshot::from_bytes(&bytes).unwrap_err();
        assert!(matches!(
            error,
            crate::KinDbError::IncompatibleSnapshotVersion { found: 3, .. }
        ));
    }

    #[test]
    fn snapshot_roundtrips_file_layouts() {
        let mut snapshot = GraphSnapshot::empty();
        snapshot.admit_artifact_for_test(
            "src/lib.rs".to_string(),
            crate::types::regular_tree_entry(1),
        );
        snapshot.file_layouts.push(FileLayout {
            file_id: FilePathId::new("src/lib.rs"),
            parse_completeness: ParseCompleteness::Partial("1 parse error range(s)".into()),
            imports: ImportSection {
                byte_range: 0..0,
                items: vec![],
            },
            regions: vec![SourceRegion::Trivia { byte_range: 0..42 }],
        });

        let bytes = snapshot.to_bytes().unwrap();
        let loaded = GraphSnapshot::from_bytes(&bytes).unwrap();
        assert_eq!(loaded.file_layouts.len(), 1);
        assert_eq!(
            loaded.file_layouts[0].parse_completeness,
            ParseCompleteness::Partial("1 parse error range(s)".into())
        );
    }

    #[test]
    fn invalid_magic_rejected() {
        let mut data = vec![0u8; 64];
        data[0..4].copy_from_slice(b"XXXX");
        assert!(GraphSnapshot::from_bytes(&data).is_err());
    }

    // ---- the materialized graph section -----------------------------------

    fn a_change_id(byte: u8) -> SemanticChangeId {
        SemanticChangeId::from_hash(Hash256::from_bytes([byte; 32]))
    }

    /// A section resolving at `resolved_at` and carrying one named entity.
    ///
    /// The entity is not decoration. A section of empty maps round-trips
    /// through a decoder that drops every domain, so the codec tests below
    /// would pass on a reader that returned `ResolvedGraphState::default()`.
    fn a_section(resolved_at: SemanticChangeId, entity_name: &str) -> MaterializedGraphSection {
        let entity = test_entity(entity_name);
        let mut state = ResolvedGraphState::default();
        state.entities.insert(entity.id, entity);
        MaterializedGraphSection {
            schema_version: MATERIALIZED_GRAPH_SCHEMA_VERSION,
            resolved_at,
            state,
        }
    }

    fn only_entity_name(section: &MaterializedGraphSection) -> &str {
        let mut names: Vec<&str> = section
            .state
            .entities
            .values()
            .map(|entity| entity.name.as_str())
            .collect();
        names.sort_unstable();
        assert_eq!(names.len(), 1, "the fixture carries exactly one entity");
        names[0]
    }

    /// The exact bytes a v13 writer produced for `snapshot`.
    ///
    /// Built by editing the real encoding rather than by mirroring the v13
    /// field list in a second struct. A second copy of a field list is only
    /// ever wrong in a way that looks like a passing run, and the difference
    /// between the two formats is precisely one array element, so that is the
    /// one edit made here: the header loses a field and the trailing nil the
    /// appended field encoded as goes with it. Every step asserts what it
    /// found before changing it.
    fn v13_frame(mut snapshot: GraphSnapshot) -> Vec<u8> {
        assert!(
            snapshot.materialized_graph.is_none(),
            "a v13 body has no section, so there is none to drop"
        );
        snapshot.version = GraphSnapshot::MIN_SUPPORTED_VERSION;
        let mut body = rmp_serde::to_vec(&snapshot).expect("a snapshot serializes");
        assert_eq!(
            encoded_field_count(&body),
            GRAPH_SNAPSHOT_FIELD_COUNT,
            "the current encoding is what this edits down from"
        );
        assert_eq!(
            body[0], 0xdc,
            "both widths use the array16 header, so only its count changes"
        );
        assert_eq!(
            body.pop(),
            Some(0xc0),
            "the appended field is absent and encodes as nil"
        );
        let v13 = u16::try_from(GRAPH_SNAPSHOT_V13_FIELD_COUNT).expect("a width fits u16");
        body[1..3].copy_from_slice(&v13.to_be_bytes());
        assert_eq!(encoded_field_count(&body), GRAPH_SNAPSHOT_V13_FIELD_COUNT);

        let mut frame = Vec::new();
        frame.extend_from_slice(&GraphSnapshot::MAGIC);
        frame.extend_from_slice(&GraphSnapshot::MIN_SUPPORTED_VERSION.to_le_bytes());
        frame.extend_from_slice(&(body.len() as u64).to_le_bytes());
        frame.extend_from_slice(&body);
        let checksum: [u8; 32] = Sha256::digest(&body).into();
        frame.extend_from_slice(&checksum);
        frame
    }

    #[test]
    fn a_v13_store_still_opens_and_carries_no_section() {
        // The compatibility row that matters most: every store any shipped
        // version wrote must still open. Its section reads absent, which is
        // what routes it to replay.
        let bytes = v13_frame(GraphSnapshot::empty());

        let snapshot = GraphSnapshot::from_bytes(&bytes).expect("a v13 body still decodes");
        assert!(
            snapshot.materialized_graph.is_none(),
            "a v13 body has no section and must not invent one"
        );
        assert_eq!(
            snapshot.version,
            GraphSnapshot::CURRENT_VERSION,
            "an older body decodes into the current in-memory shape and says so, or the very \
             next to_bytes refuses its own decoded object"
        );

        // The negative control for the width edit above: without it, this
        // whole test would be reading a v14 body and proving nothing about v13.
        let current = GraphSnapshot::empty().to_bytes().expect("serializes");
        assert_eq!(
            encoded_field_count(&current[16..]),
            GRAPH_SNAPSHOT_FIELD_COUNT
        );
    }

    #[test]
    fn the_envelope_decode_reads_a_v13_body_too() {
        // The partial decoder keys on width, so it needs both widths named or
        // it refuses every store written before this change.
        let bytes = v13_frame(GraphSnapshot::empty());
        let envelope =
            AuthorityEnvelopeSnapshot::from_bytes(&bytes).expect("the envelope decodes a v13 body");
        assert!(envelope.materialized_graph.is_none());
    }

    #[test]
    fn the_envelope_decode_reads_the_same_section_the_full_decode_reads() {
        // The section sits one element past the envelope, so this pins
        // MATERIALIZED_GRAPH_FIELD_INDEX to the struct the same way the
        // envelope test above pins the authority index. Pointed one field
        // earlier it would parse `external_references`, a map, as a struct.
        let mut snapshot = GraphSnapshot::empty();
        snapshot.materialized_graph = Some(a_section(a_change_id(0x11), "served"));
        let bytes = snapshot
            .to_bytes_pre_validated()
            .expect("a snapshot with a section serializes");

        let envelope = AuthorityEnvelopeSnapshot::from_bytes(&bytes).expect("the envelope decodes");
        let from_envelope = envelope
            .materialized_graph
            .as_ref()
            .expect("the envelope reads the section");
        let full = GraphSnapshot::from_bytes(&bytes).expect("the full decode accepts these bytes");
        let from_full = full
            .materialized_graph
            .as_ref()
            .expect("the full decode reads the section");

        assert_eq!(from_envelope.resolved_at, from_full.resolved_at);
        assert_eq!(only_entity_name(from_envelope), only_entity_name(from_full));
        assert_eq!(only_entity_name(from_envelope), "served");
    }

    #[test]
    fn a_section_answers_only_for_the_change_it_resolves_at() {
        // The whole binding. A change id is a Merkle hash over its own deltas
        // and its parents, so matching it matches the content; NOT matching it
        // must refuse, or the section answers one workspace's graph to another
        // workspace at a different head.
        let section = a_section(a_change_id(0x11), "served");
        assert!(section.validate_for(&a_change_id(0x11)).is_ok());
        assert_eq!(
            section.validate_for(&a_change_id(0x22)),
            Err(MaterializedGraphRefusal::Target),
            "a section must refuse a change it is not the resolution at"
        );
    }

    #[test]
    fn a_section_of_an_unknown_schema_is_refused_by_schema() {
        // Separated from the target arm because the two can hide each other:
        // a test that only ever varies the target would pass against a
        // validator that dropped the schema check entirely.
        let mut section = a_section(a_change_id(0x11), "served");
        section.schema_version = MATERIALIZED_GRAPH_SCHEMA_VERSION + 1;
        assert_eq!(
            section.validate_for(&a_change_id(0x11)),
            Err(MaterializedGraphRefusal::Schema {
                held: MATERIALIZED_GRAPH_SCHEMA_VERSION,
                found: MATERIALIZED_GRAPH_SCHEMA_VERSION + 1,
            }),
            "an unknown schema must refuse by name, not fall through to the target check"
        );
    }

    #[test]
    fn an_envelope_with_no_section_refuses_as_absent() {
        // The ordinary case, and it must be distinguishable from the two
        // refusals above so a log can tell an old store from a stale section.
        let snapshot = GraphSnapshot::empty();
        let bytes = snapshot.to_bytes_pre_validated().expect("serializes");
        let envelope = AuthorityEnvelopeSnapshot::from_bytes(&bytes).expect("the envelope decodes");
        assert_eq!(
            envelope
                .materialized_graph_for(&a_change_id(0x11))
                .expect_err("no section means a refusal"),
            MaterializedGraphRefusal::Absent
        );
    }

    #[test]
    fn a_section_does_not_weaken_tamper_detection() {
        // The asymmetry the design rests on: a stale section falls back, but
        // bytes that are not what the writer wrote still refuse the whole
        // snapshot. Flip one byte INSIDE the section and the frame checksum
        // must catch it, with an untampered decode as the control.
        let mut snapshot = GraphSnapshot::empty();
        snapshot.materialized_graph = Some(a_section(a_change_id(0x11), "served"));
        let bytes = snapshot.to_bytes_pre_validated().expect("serializes");
        assert!(
            GraphSnapshot::from_bytes(&bytes).is_ok(),
            "the control must decode, or the tampered arm proves nothing"
        );

        // The section is the last thing in the body, and the body ends 32 bytes
        // before the frame does.
        let mut tampered = bytes.clone();
        let last_body_byte = tampered.len() - GraphSnapshot::CHECKSUM_LEN - 1;
        tampered[last_body_byte] ^= 0xff;
        let error = GraphSnapshot::from_bytes(&tampered)
            .expect_err("a tampered body must refuse")
            .to_string();
        assert!(
            error.contains("checksum mismatch"),
            "the frame checksum must be what refuses, got: {error}"
        );
    }

    #[test]
    fn a_body_whose_version_contradicts_its_frame_is_refused() {
        // With one supported version this could not arise. With two it can,
        // and a decoder that dispatches on the header while trusting the body
        // is a check that cannot fail.
        let mut snapshot = GraphSnapshot::empty();
        snapshot.version = GraphSnapshot::MIN_SUPPORTED_VERSION;
        let body = rmp_serde::to_vec(&snapshot).expect("serializes");
        let mut frame = Vec::new();
        frame.extend_from_slice(&GraphSnapshot::MAGIC);
        // The header says v14 while the body says v13.
        frame.extend_from_slice(&GraphSnapshot::CURRENT_VERSION.to_le_bytes());
        frame.extend_from_slice(&(body.len() as u64).to_le_bytes());
        frame.extend_from_slice(&body);
        let checksum: [u8; 32] = Sha256::digest(&body).into();
        frame.extend_from_slice(&checksum);

        let error = GraphSnapshot::from_bytes(&frame)
            .expect_err("a contradicting version must refuse")
            .to_string();
        assert!(
            error.contains("header declares v14 but its body declares v13"),
            "the refusal must name both versions, got: {error}"
        );
    }

    #[test]
    fn every_decoder_accepts_a_v13_body() {
        // Five decode entry points share one frame reader, and on this change
        // four of them were left keyed on CURRENT_VERSION alone while one was
        // fixed. Counting `unreachable!` arms would not have caught that; each
        // decoder has to be asked with the input only a two-version reader can
        // answer. A v13 body is exactly that input.
        let bytes = v13_frame(GraphSnapshot::empty());

        GraphSnapshot::from_bytes(&bytes).expect("the full decode accepts a v13 body");
        GraphSnapshot::from_bytes_reusing_exact_validation(&bytes)
            .expect("the validation-reusing decode accepts a v13 body");
        GraphSnapshot::prove_pre_validated_round_trip(&bytes)
            .expect("the round-trip proof accepts a v13 body");
        AuthorityEnvelopeSnapshot::from_bytes(&bytes)
            .expect("the envelope decode accepts a v13 body");
        LocateGraphSnapshot::from_bytes_with_persisted_root_hash(&bytes)
            .expect("the locate decode accepts a v13 body");

        // The control. A version outside the supported range must still be
        // refused by every one of them, or "accepts a v13 body" would be
        // satisfied by a reader that accepts anything.
        let mut too_old = bytes.clone();
        too_old[4..8].copy_from_slice(&12u32.to_le_bytes());
        assert!(GraphSnapshot::from_bytes(&too_old).is_err());
        assert!(AuthorityEnvelopeSnapshot::from_bytes(&too_old).is_err());
    }

    #[test]
    fn the_section_index_and_both_widths_match_the_encoded_snapshot() {
        // The arity tripwire, extended. A field appended after the section
        // moves it, and this fails on the count before anyone debugs a decode
        // error. The v13 width is asserted as a relation to the current one so
        // it cannot drift into naming a width that never existed.
        let snapshot = GraphSnapshot::empty();
        let body = rmp_serde::to_vec(&snapshot).expect("empty snapshot serializes");
        assert_eq!(encoded_field_count(&body), GRAPH_SNAPSHOT_FIELD_COUNT);
        assert_eq!(
            MATERIALIZED_GRAPH_FIELD_INDEX,
            GRAPH_SNAPSHOT_FIELD_COUNT - 1,
            "the section is the last element of the current body"
        );
        assert_eq!(
            GRAPH_SNAPSHOT_V13_FIELD_COUNT,
            GRAPH_SNAPSHOT_FIELD_COUNT - 1,
            "v14 appends exactly one element to v13"
        );
        assert_eq!(
            GraphSnapshot::MIN_SUPPORTED_VERSION + 1,
            GraphSnapshot::CURRENT_VERSION,
            "the two supported versions are adjacent, which is what makes one \
             decoder with one defaulted field enough"
        );
    }
}
