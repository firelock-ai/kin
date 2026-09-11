// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Canonical identities for immutable repository objects.
//!
//! Change identity belongs in the shared model boundary, not in one producer.
//! Every store and transport can therefore recompute an incoming
//! [`SemanticChange`](crate::SemanticChange) before admitting it.

use std::collections::BTreeSet;

use sha2::{Digest, Sha256};

use crate::admission::AdmissionPolicyDelta;
use crate::{
    Entity, EntityDelta, ExternalReferenceDelta, Hash256, ModelError, Relation, RelationDelta,
    Result, SemanticChange, SemanticChangeId, TransactionDelta, TreeDelta,
};

/// Domain separator hashed ahead of a semantic change's canonical preimage.
///
/// Named because the streaming derivation writes it through the same sink as
/// the payload, and the reference walk the tests keep must write the identical
/// bytes for the comparison to mean anything.
const SEMANTIC_CHANGE_HASH_DOMAIN: &[u8] = b"kin-semantic-change-v6\0";

/// Compute the immutable v6 identity of a complete semantic change.
///
/// The existing `id` field is excluded to avoid self-reference. Independent
/// deltas are sorted by stable target identity, so producer iteration order is
/// irrelevant. All remaining immutable fields participate, including exact
/// change origin and admission-policy transitions.
///
/// The preimage is streamed one field and one delta at a time through the
/// sinks [`crate::RepositoryTransaction::transaction_hash`] uses, so deriving
/// an identity holds no copy of the change. The implementation this replaced
/// copied the change's deltas once to validate them and the whole change again
/// to sort it, built a `serde_json::Value` tree of that copy in order to delete
/// `id` from it, and held the encoding as one buffer. A change that carries a
/// whole tree pays that on every derivation, and an admission derives the same
/// change's identity a dozen times: on a one-commit import of an 18,508-file
/// repository the tree alone took resident memory from 1.2 GiB to 13.7 GiB in
/// twelve seconds.
pub fn compute_semantic_change_id(change: &SemanticChange) -> Result<SemanticChangeId> {
    validate_change_deltas(change)?;
    let view = CanonicalChangeIdentity::new(change);

    // Two passes over the same walk, because the preimage carries its byte
    // length ahead of its payload and a hasher cannot be told the length
    // afterwards. The first pass counts and keeps nothing; the second hashes
    // and keeps nothing.
    let mut counter = CountingSink::default();
    view.write_canonical_preimage(&mut counter)?;
    let payload_len = counter.len();

    let mut sink = HashingSink::new();
    sink.write_bytes(SEMANTIC_CHANGE_HASH_DOMAIN);
    sink.write_bytes(&payload_len.to_le_bytes());
    let header_len = sink.written();
    view.write_canonical_preimage(&mut sink)?;

    // The two passes walk the same immutable view, so they agree or something
    // under them is not deterministic. Refuse rather than return a well-formed
    // hash of a preimage whose length prefix contradicts its payload, because
    // every change in every store on disk is named by this value.
    let hashed_payload = sink.written() - header_len;
    if hashed_payload != payload_len {
        return Err(ModelError::InvalidOperation(format!(
            "semantic change identity preimage counted {payload_len} bytes and hashed \
             {hashed_payload}"
        )));
    }
    Ok(SemanticChangeId::from_hash(Hash256::from_bytes(
        sink.finish(),
    )))
}

/// Fields of a [`SemanticChange`] that reach its identity preimage whatever
/// the change carries.
///
/// Every field but `id`, which the preimage derives, and
/// `external_reference_deltas`, which the derive skips when empty and the
/// walk below therefore skips too. Hoisted so the count the object header
/// carries and the fields the walk writes come from one constant rather than
/// from a copy that can drift.
const CHANGE_IDENTITY_FIELD_COUNT: usize = 13;

/// The identity-bearing fields of one [`SemanticChange`], borrowed and in
/// canonical order.
///
/// The preimage is the change's derived serialization with `id` removed and
/// the four independent delta collections sorted by target. Neither can be had
/// by streaming the derive: a serializer emits fields as `Serialize` delivers
/// them and has nothing to delete or reorder. The implementation this replaced
/// got a mutable object by building a `serde_json::Value` tree of a clone,
/// which is the cost named on [`compute_semantic_change_id`].
///
/// This view writes the object by hand instead, in the byte-wise key order the
/// tree walk sorted the derive's fields into, and hands each delta collection
/// to [`append_canonical_seq`] so one delta's encoding is resident at a time.
/// It is the shape of `CanonicalTransaction` in `repository.rs` with one
/// difference: it is a walk rather than a `Serialize` impl, so no serializer
/// ever sees it and the positional-differential rule for hand-written
/// serializations does not apply. What guards it instead is
/// `the_identity_preimage_matches_the_tree_walk`, which diffs these bytes
/// against the retained tree walk over the derive, offset by offset, on every
/// field a change can carry, and the pinned identities beneath it.
struct CanonicalChangeIdentity<'a> {
    source: &'a SemanticChange,
    entity_deltas: Vec<&'a EntityDelta>,
    relation_deltas: Vec<&'a RelationDelta>,
    tree_deltas: Vec<&'a TreeDelta>,
    external_reference_deltas: Vec<&'a ExternalReferenceDelta>,
}

impl<'a> CanonicalChangeIdentity<'a> {
    fn new(source: &'a SemanticChange) -> Self {
        let mut entity_deltas: Vec<&'a EntityDelta> = source.entity_deltas.iter().collect();
        entity_deltas.sort_by_key(|delta| EntityDelta::target_id(delta));

        let mut relation_deltas: Vec<&'a RelationDelta> = source.relation_deltas.iter().collect();
        relation_deltas.sort_by_key(|delta| RelationDelta::target_id(delta));

        let mut tree_deltas: Vec<&'a TreeDelta> = source.tree_deltas.iter().collect();
        tree_deltas.sort_by_key(|delta| TreeDelta::artifact_id(delta));

        let mut external_reference_deltas: Vec<&'a ExternalReferenceDelta> =
            source.external_reference_deltas.iter().collect();
        external_reference_deltas.sort_by_key(|delta| ExternalReferenceDelta::target_id(delta));

        Self {
            source,
            entity_deltas,
            relation_deltas,
            tree_deltas,
            external_reference_deltas,
        }
    }

    /// The preimage, written one field at a time into any sink.
    ///
    /// Byte for byte what the tree walk emits for the derive with `id`
    /// removed. The keys are in BYTE-WISE order rather than declaration order,
    /// because that is the order the walk sorts a `serde_json::Map` into, and
    /// `external_reference_deltas` is written only when it is non-empty,
    /// because the derive skips it then and the count in the header has to
    /// say what follows.
    fn write_canonical_preimage<S: CanonicalSink>(&self, out: &mut S) -> Result<()> {
        let source = self.source;
        let field_count =
            CHANGE_IDENTITY_FIELD_COUNT + usize::from(!self.external_reference_deltas.is_empty());

        append_canonical_object_header(out, field_count)?;

        append_canonical_key(out, "admission_policy_delta")?;
        append_canonical_value(out, &source.admission_policy_delta)?;
        append_canonical_key(out, "author")?;
        append_canonical_value(out, &source.author)?;
        append_canonical_key(out, "entity_deltas")?;
        append_canonical_seq(out, &self.entity_deltas)?;
        append_canonical_key(out, "evidence")?;
        append_canonical_value(out, &source.evidence)?;
        if !self.external_reference_deltas.is_empty() {
            append_canonical_key(out, "external_reference_deltas")?;
            append_canonical_seq(out, &self.external_reference_deltas)?;
        }
        append_canonical_key(out, "message")?;
        append_canonical_value(out, &source.message)?;
        append_canonical_key(out, "origin")?;
        append_canonical_value(out, &source.origin)?;
        append_canonical_key(out, "parents")?;
        append_canonical_value(out, &source.parents)?;
        append_canonical_key(out, "projected_files")?;
        append_canonical_value(out, &source.projected_files)?;
        append_canonical_key(out, "relation_deltas")?;
        append_canonical_seq(out, &self.relation_deltas)?;
        append_canonical_key(out, "risk_summary")?;
        append_canonical_value(out, &source.risk_summary)?;
        append_canonical_key(out, "spec_link")?;
        append_canonical_value(out, &source.spec_link)?;
        append_canonical_key(out, "timestamp")?;
        append_canonical_value(out, &source.timestamp)?;
        append_canonical_key(out, "tree_deltas")?;
        append_canonical_seq(out, &self.tree_deltas)?;

        Ok(())
    }

    /// The whole preimage in one buffer.
    ///
    /// Only the tests want this. They compare it byte for byte and pin it by
    /// digest; production hashes it as it is produced and never holds it.
    #[cfg(test)]
    fn canonical_preimage(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        self.write_canonical_preimage(&mut out)?;
        Ok(out)
    }
}

/// The streamed identity preimage of `change`, collected into one buffer.
#[cfg(test)]
pub(crate) fn change_identity_preimage(change: &SemanticChange) -> Result<Vec<u8>> {
    CanonicalChangeIdentity::new(change).canonical_preimage()
}

/// The identity preimage as the implementation this crate replaced produced
/// it: the derive as a `serde_json::Value` tree with `id` removed, walked by
/// the encoder that defines the format.
///
/// Kept as the oracle the streaming walk is checked against. Keeping it is the
/// point: a differential in which both sides go through the same new code
/// proves nothing.
#[cfg(test)]
pub(crate) fn change_identity_preimage_via_tree(change: &SemanticChange) -> Result<Vec<u8>> {
    let mut canonical_change = change.clone();
    canonical_change
        .entity_deltas
        .sort_by_key(EntityDelta::target_id);
    canonical_change
        .relation_deltas
        .sort_by_key(RelationDelta::target_id);
    canonical_change
        .tree_deltas
        .sort_by_key(TreeDelta::artifact_id);
    canonical_change
        .external_reference_deltas
        .sort_by_key(ExternalReferenceDelta::target_id);

    let mut payload = serde_json::to_value(&canonical_change).map_err(serialization)?;
    let fields = payload.as_object_mut().ok_or_else(|| {
        ModelError::InvalidOperation(
            "semantic change identity payload is not an object".to_string(),
        )
    })?;
    if fields.remove("id").is_none() {
        return Err(ModelError::InvalidOperation(
            "semantic change identity payload has no id field".to_string(),
        ));
    }
    let mut canonical = Vec::new();
    append_canonical_json(&mut canonical, &payload)?;
    Ok(canonical)
}

/// The identity as the implementation this crate replaced derived it, kept
/// verbatim so the streaming derivation can be measured against it.
#[cfg(test)]
pub(crate) fn reference_semantic_change_id(change: &SemanticChange) -> Result<SemanticChangeId> {
    let delta = change.transaction_delta();
    validate_transaction_delta(&delta)?;
    let canonical = change_identity_preimage_via_tree(change)?;

    let mut hasher = Sha256::new();
    hasher.update(SEMANTIC_CHANGE_HASH_DOMAIN);
    append_len_prefixed_hash_field(&mut hasher, &canonical)?;
    let result = hasher.finalize();
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(&result);
    Ok(SemanticChangeId::from_hash(Hash256::from_bytes(bytes)))
}

/// Reject an incoming change whose declared identity does not match its
/// complete immutable payload.
pub fn validate_semantic_change_id(change: &SemanticChange) -> Result<()> {
    if change.parents.contains(&change.id) {
        return Err(ModelError::InvalidOperation(format!(
            "semantic change {} cannot name itself as a parent",
            change.id
        )));
    }
    let computed = compute_semantic_change_id(change)?;
    if computed == change.id {
        return Ok(());
    }
    Err(ModelError::InvalidOperation(format!(
        "semantic change {} declares an identity that recomputes to {}",
        change.id, computed
    )))
}

/// Validate exact, self-inverting deltas before replay or identity derivation.
///
/// One transaction may target each entity, relation, or artifact at most once.
/// Modified deltas preserve identity and carry two different complete states.
pub fn validate_transaction_delta(delta: &TransactionDelta) -> Result<()> {
    validate_deltas(
        &delta.entity_deltas,
        &delta.relation_deltas,
        &delta.tree_deltas,
        delta.admission_policy_delta.as_ref(),
        &delta.external_reference_deltas,
    )
}

/// [`validate_transaction_delta`] over a change's own deltas, where they are.
///
/// `SemanticChange::transaction_delta` copies every delta into a
/// `TransactionDelta`, and identity derivation used to call it for no reason
/// but to hand the copy to the validator. On a change that carries a whole
/// tree, that copy is the whole tree.
fn validate_change_deltas(change: &SemanticChange) -> Result<()> {
    validate_deltas(
        &change.entity_deltas,
        &change.relation_deltas,
        &change.tree_deltas,
        change.admission_policy_delta.as_ref(),
        &change.external_reference_deltas,
    )
}

fn validate_deltas(
    entity_deltas: &[EntityDelta],
    relation_deltas: &[RelationDelta],
    tree_deltas: &[TreeDelta],
    admission_policy_delta: Option<&AdmissionPolicyDelta>,
    external_reference_deltas: &[ExternalReferenceDelta],
) -> Result<()> {
    let mut entity_targets = BTreeSet::new();
    for entity_delta in entity_deltas {
        let target = entity_delta.target_id();
        if !entity_targets.insert(target) {
            return Err(ModelError::InvalidOperation(format!(
                "transaction contains more than one delta for entity {target}"
            )));
        }
        match entity_delta {
            EntityDelta::Added { new } => validate_entity_numbers(new)?,
            EntityDelta::Modified { old, new } => {
                validate_entity_numbers(old)?;
                validate_entity_numbers(new)?;
                if old.id != new.id {
                    return Err(ModelError::InvalidOperation(format!(
                        "entity modification changes identity from {} to {}",
                        old.id, new.id
                    )));
                }
                if old == new {
                    return Err(ModelError::InvalidOperation(format!(
                        "entity {} modification is a no-op",
                        old.id
                    )));
                }
            }
            EntityDelta::Removed { old } => validate_entity_numbers(old)?,
        }
    }

    let mut relation_targets = BTreeSet::new();
    for relation_delta in relation_deltas {
        let target = relation_delta.target_id();
        if !relation_targets.insert(target) {
            return Err(ModelError::InvalidOperation(format!(
                "transaction contains more than one delta for relation {target}"
            )));
        }
        match relation_delta {
            RelationDelta::Added { new } => validate_relation_numbers(new)?,
            RelationDelta::Modified { old, new } => {
                validate_relation_numbers(old)?;
                validate_relation_numbers(new)?;
                if old.id != new.id {
                    return Err(ModelError::InvalidOperation(format!(
                        "relation modification changes identity from {} to {}",
                        old.id, new.id
                    )));
                }
                if old == new {
                    return Err(ModelError::InvalidOperation(format!(
                        "relation {} modification is a no-op",
                        old.id
                    )));
                }
            }
            RelationDelta::Removed { old } => validate_relation_numbers(old)?,
        }
    }

    let mut external_reference_targets = BTreeSet::new();
    for reference_delta in external_reference_deltas {
        let target = reference_delta.target_id();
        if !external_reference_targets.insert(target) {
            return Err(ModelError::InvalidOperation(format!(
                "transaction contains more than one delta for external reference {target}"
            )));
        }
        match reference_delta {
            ExternalReferenceDelta::Added { new } => new.validate()?,
            ExternalReferenceDelta::Removed { old } => old.validate()?,
        }
    }

    let mut tree_targets = BTreeSet::new();
    for tree_delta in tree_deltas {
        let target = tree_delta.artifact_id();
        if !tree_targets.insert(target) {
            return Err(ModelError::InvalidOperation(format!(
                "transaction contains more than one delta for artifact {target:?}"
            )));
        }
        if let TreeDelta::Updated { old, new, .. } = tree_delta {
            if old == new {
                return Err(ModelError::InvalidOperation(format!(
                    "artifact {target:?} update is a no-op"
                )));
            }
        }
    }

    if let Some(policy_delta) = admission_policy_delta {
        policy_delta.validate()?;
    }
    Ok(())
}

/// Derive a deterministic content fingerprint from a complete transaction.
pub fn content_identity_from_deltas(delta: &TransactionDelta) -> Result<[u8; 32]> {
    validate_transaction_delta(delta)?;

    let mut canonical = delta.clone();
    canonical.entity_deltas.sort_by_key(EntityDelta::target_id);
    canonical
        .relation_deltas
        .sort_by_key(RelationDelta::target_id);
    canonical.tree_deltas.sort_by_key(TreeDelta::artifact_id);
    canonical
        .external_reference_deltas
        .sort_by_key(ExternalReferenceDelta::target_id);

    let encoded = canonical_json_bytes(&canonical)?;

    let mut hasher = Sha256::new();
    hasher.update(b"kin-content-v5\0");
    append_len_prefixed_hash_field(&mut hasher, &encoded)?;
    let result = hasher.finalize();
    let mut bytes = [0_u8; 32];
    bytes.copy_from_slice(&result);
    Ok(bytes)
}

fn validate_entity_numbers(entity: &Entity) -> Result<()> {
    let score = entity.fingerprint.stability_score;
    if score.is_finite() && (0.0..=1.0).contains(&score) {
        return Ok(());
    }
    Err(ModelError::InvalidOperation(format!(
        "entity {} has invalid fingerprint stability score {score}",
        entity.id
    )))
}

fn validate_relation_numbers(relation: &Relation) -> Result<()> {
    if relation.confidence.is_finite() && (0.0..=1.0).contains(&relation.confidence) {
        return Ok(());
    }
    Err(ModelError::InvalidOperation(format!(
        "relation {} has invalid confidence score {}",
        relation.id, relation.confidence
    )))
}

fn append_len_prefixed_hash_field(hasher: &mut Sha256, value: &[u8]) -> Result<()> {
    hasher.update(
        u64::try_from(value.len())
            .map_err(|_| {
                ModelError::InvalidOperation("canonical change field exceeds u64".to_string())
            })?
            .to_le_bytes(),
    );
    hasher.update(value);
    Ok(())
}

/// Encode a value into the canonical byte string every identity in this crate
/// hashes.
///
/// # Object key order is deliberately not part of this contract
///
/// Two serializations that emit the same fields under the same names in
/// different orders produce identical bytes here, so every identity derived
/// through this function is blind to field order. That is a decision, and the
/// reason lives in where the order is lost rather than in where it is sorted.
/// `serde_json::to_value` builds a `serde_json::Map`, which is a `BTreeMap` in
/// the default feature configuration, so the declaration order is already gone
/// before the `Value::Object` arm of [`append_canonical_json`] ever runs.
///
/// That makes the `sort_by` in that arm a no-op in the default build, and it is
/// kept anyway. `serde_json`'s `preserve_order` feature swaps the map for an
/// `IndexMap`, Cargo unifies features across a whole build graph, and any crate
/// in any consumer's dependency tree can turn it on. Without the sort, every
/// identity this crate derives would then depend on which unrelated crates a
/// consumer happens to build. Note what follows: the sort cannot be exercised
/// in the default configuration, because a `BTreeMap` cannot present its keys
/// out of order, so deleting it fails no test here. It is insurance, not
/// covered behavior, and it is written down as such so it does not read as dead
/// code to whoever finds it next.
///
/// Preserving order instead was considered and rejected. No format this crate
/// persists reads these payloads back by name from this encoding, so order
/// would buy nothing a positional differential does not buy better, and turning
/// it on would rewrite every identity already on disk.
///
/// # What that costs, and who owes the difference
///
/// A differential that compares HASHES cannot see anything the hash
/// deliberately normalizes away, and this one normalizes away field order. So a
/// serialization written or mirrored by hand cannot be guarded by a hash
/// comparison alone: swap two fields in a mirror type and every hash
/// differential over it stays green. That was demonstrated by sabotage on
/// [`crate::RepositoryTransaction`]'s canonicalization rather than reasoned
/// about, and it is why FIR-2549 exists.
///
/// Every payload reaching this function whose serialization is hand-written, or
/// mirrored field for field against another type, therefore owes a POSITIONAL
/// differential in addition to its hash test: encode it through a
/// non-human-readable serializer, where a struct is an ordered array and the
/// element count is load-bearing, and diff those bytes against a reference
/// built the other way. `rmp-serde` is what this crate uses for that.
/// `tests/persisted_schema.rs` carries the registry that refuses a new
/// hand-written serialization arriving without one.
///
/// Sequence order is a different question and IS preserved: the `Value::Array`
/// arm encodes elements in the order it receives them. Collections whose order
/// must not affect identity are sorted by their callers before they arrive.
/// Where the canonical encoder puts the bytes it produces.
///
/// The encoder used to write only into a `Vec<u8>`, which meant every caller
/// held the whole encoding before doing anything with it. The bytes are
/// unchanged and the walk that produces them is unchanged; only the destination
/// is now a choice, so a caller that just wants a digest never has to hold the
/// document it is digesting.
pub(crate) trait CanonicalSink {
    fn push_byte(&mut self, byte: u8);
    fn write_bytes(&mut self, bytes: &[u8]);
}

impl CanonicalSink for Vec<u8> {
    fn push_byte(&mut self, byte: u8) {
        self.push(byte);
    }

    fn write_bytes(&mut self, bytes: &[u8]) {
        self.extend_from_slice(bytes);
    }
}

/// Counts what the encoder would write and keeps none of it.
///
/// The length pass of a two-pass hash. The preimage carries its own byte length
/// ahead of its payload, and a hasher cannot be fed the length after the fact,
/// so the length is counted first over the same walk that will produce the
/// bytes second.
#[derive(Debug, Default)]
pub(crate) struct CountingSink {
    len: u64,
}

impl CountingSink {
    pub(crate) fn len(&self) -> u64 {
        self.len
    }
}

impl CanonicalSink for CountingSink {
    fn push_byte(&mut self, _byte: u8) {
        self.len += 1;
    }

    fn write_bytes(&mut self, bytes: &[u8]) {
        self.len += bytes.len() as u64;
    }
}

/// Feeds the encoder's bytes into a hasher as they are produced.
///
/// Tracks how many bytes it has taken so the caller can prove the hashing pass
/// wrote exactly what the counting pass promised. That check is not decoration:
/// the length is hashed before the payload, so a second pass that disagreed
/// with the first would produce a well-formed hash of a preimage nothing ever
/// held, and every transaction identity in every store derives from it.
pub(crate) struct HashingSink {
    hasher: Sha256,
    written: u64,
}

impl HashingSink {
    pub(crate) fn new() -> Self {
        Self {
            hasher: Sha256::new(),
            written: 0,
        }
    }

    pub(crate) fn written(&self) -> u64 {
        self.written
    }

    pub(crate) fn finish(self) -> [u8; 32] {
        let digest = self.hasher.finalize();
        let mut bytes = [0_u8; 32];
        bytes.copy_from_slice(&digest);
        bytes
    }
}

impl CanonicalSink for HashingSink {
    fn push_byte(&mut self, byte: u8) {
        self.hasher.update([byte]);
        self.written += 1;
    }

    fn write_bytes(&mut self, bytes: &[u8]) {
        self.hasher.update(bytes);
        self.written += bytes.len() as u64;
    }
}

pub(crate) fn canonical_json_bytes(value: &impl serde::Serialize) -> Result<Vec<u8>> {
    crate::canonical_ser::canonical_streamed_bytes(value)
}

/// The same bytes, produced by walking a `serde_json::Value` tree of the whole
/// value.
///
/// This is what every identity in this crate was built from before
/// [`crate::canonical_ser`] existed, so it defines the encoding rather than
/// merely agreeing with it, and it is kept as the oracle the streaming encoder
/// is checked against. Keeping it is the point: a differential in which both
/// sides go through the same new code proves nothing.
#[cfg(test)]
pub(crate) fn canonical_json_bytes_via_tree(value: &impl serde::Serialize) -> Result<Vec<u8>> {
    let value = serde_json::to_value(value).map_err(serialization)?;
    let mut encoded = Vec::new();
    append_canonical_json(&mut encoded, &value)?;
    Ok(encoded)
}

/// The canonical encoding of one value, appended to `output`.
///
/// Same bytes as [`canonical_json_bytes`] produces for that value, because it
/// is the same walk over the same `serde_json::Value`. What differs is scope:
/// the tree built here covers this value alone, so a caller assembling a large
/// container can build and drop one element's tree at a time instead of holding
/// the whole document's.
pub(crate) fn append_canonical_value<S: CanonicalSink>(
    output: &mut S,
    value: &impl serde::Serialize,
) -> Result<()> {
    crate::canonical_ser::append_canonical_streamed(output, value)
}

/// The canonical encoding of an array, materializing one element at a time.
///
/// This is the whole point of the incremental path. `canonical_json_bytes` over
/// a whole transaction builds a `serde_json::Value` tree eleven times the size
/// of the transaction, and the arrays of changes are nearly all of it. Encoding
/// element by element bounds the tree to one element while emitting byte-for-byte
/// what the whole-tree walk emits, because the framing below is copied from
/// [`append_canonical_json`]'s array arm and each element goes through the same
/// walk.
pub(crate) fn append_canonical_seq<S: CanonicalSink, T: serde::Serialize>(
    output: &mut S,
    items: &[T],
) -> Result<()> {
    output.push_byte(4);
    output.write_bytes(
        &u64::try_from(items.len())
            .map_err(|_| ModelError::InvalidOperation("canonical array exceeds u64".to_string()))?
            .to_le_bytes(),
    );
    for item in items {
        append_canonical_value(output, item)?;
    }
    Ok(())
}

/// The header of a canonical object with a known field count.
///
/// Copied from [`append_canonical_json`]'s object arm. A caller that emits its
/// own fields is responsible for emitting exactly `fields` of them, in
/// byte-wise key order, because that is what the whole-tree walk does when it
/// sorts a `serde_json::Map`.
pub(crate) fn append_canonical_object_header<S: CanonicalSink>(
    output: &mut S,
    fields: usize,
) -> Result<()> {
    output.push_byte(5);
    output.write_bytes(
        &u64::try_from(fields)
            .map_err(|_| ModelError::InvalidOperation("canonical object exceeds u64".to_string()))?
            .to_le_bytes(),
    );
    Ok(())
}

/// One object field's key, length-prefixed as the whole-tree walk writes it.
pub(crate) fn append_canonical_key<S: CanonicalSink>(output: &mut S, key: &str) -> Result<()> {
    append_len_prefixed_vec_field(output, key.as_bytes())
}

#[cfg(test)]
fn append_canonical_json<S: CanonicalSink>(
    output: &mut S,
    value: &serde_json::Value,
) -> Result<()> {
    match value {
        serde_json::Value::Null => output.push_byte(0),
        serde_json::Value::Bool(value) => {
            output.push_byte(1);
            output.push_byte(u8::from(*value));
        }
        serde_json::Value::Number(value) => {
            output.push_byte(2);
            append_len_prefixed_vec_field(output, value.to_string().as_bytes())?;
        }
        serde_json::Value::String(value) => {
            output.push_byte(3);
            append_len_prefixed_vec_field(output, value.as_bytes())?;
        }
        serde_json::Value::Array(values) => {
            output.push_byte(4);
            output.write_bytes(
                &u64::try_from(values.len())
                    .map_err(|_| {
                        ModelError::InvalidOperation("canonical array exceeds u64".to_string())
                    })?
                    .to_le_bytes(),
            );
            for value in values {
                append_canonical_json(output, value)?;
            }
        }
        serde_json::Value::Object(values) => {
            output.push_byte(5);
            output.write_bytes(
                &u64::try_from(values.len())
                    .map_err(|_| {
                        ModelError::InvalidOperation("canonical object exceeds u64".to_string())
                    })?
                    .to_le_bytes(),
            );
            let mut values: Vec<_> = values.iter().collect();
            values.sort_by(|left, right| left.0.cmp(right.0));
            for (key, value) in values {
                append_len_prefixed_vec_field(output, key.as_bytes())?;
                append_canonical_json(output, value)?;
            }
        }
    }
    Ok(())
}

/// The canonical encoding with exactly ONE byte of its framing changed.
///
/// Only reachable from tests, and only for one job: proving that the pinned
/// preimage digests can actually fail. A corpus of pins is worth nothing until
/// something shows the pins move when the encoder moves, and the cheapest
/// honest demonstration is an encoder that differs from the real one by a single
/// byte, here the object tag.
///
/// Deliberately a separate walk rather than a flag threaded through
/// [`append_canonical_json`]. A flag inside the real encoder is a branch that
/// ships, and a mis-set one would corrupt every identity this crate derives.
#[cfg(test)]
pub(crate) fn canonical_json_bytes_with_one_byte_of_framing_changed(
    value: &impl serde::Serialize,
) -> Result<Vec<u8>> {
    fn append(output: &mut Vec<u8>, value: &serde_json::Value) -> Result<()> {
        match value {
            serde_json::Value::Object(values) => {
                // The real encoder writes 5 here. This is the whole mutation.
                output.push(6);
                output.extend_from_slice(
                    &u64::try_from(values.len())
                        .map_err(|_| {
                            ModelError::InvalidOperation("canonical object exceeds u64".to_string())
                        })?
                        .to_le_bytes(),
                );
                let mut values: Vec<_> = values.iter().collect();
                values.sort_by(|left, right| left.0.cmp(right.0));
                for (key, value) in values {
                    append_len_prefixed_vec_field(output, key.as_bytes())?;
                    append(output, value)?;
                }
                Ok(())
            }
            serde_json::Value::Array(values) => {
                output.push(4);
                output.extend_from_slice(
                    &u64::try_from(values.len())
                        .map_err(|_| {
                            ModelError::InvalidOperation("canonical array exceeds u64".to_string())
                        })?
                        .to_le_bytes(),
                );
                for value in values {
                    append(output, value)?;
                }
                Ok(())
            }
            other => append_canonical_json(output, other),
        }
    }

    let value = serde_json::to_value(value).map_err(serialization)?;
    let mut encoded = Vec::new();
    append(&mut encoded, &value)?;
    Ok(encoded)
}

fn append_len_prefixed_vec_field<S: CanonicalSink>(output: &mut S, value: &[u8]) -> Result<()> {
    output.write_bytes(
        &u64::try_from(value.len())
            .map_err(|_| ModelError::InvalidOperation("canonical value exceeds u64".to_string()))?
            .to_le_bytes(),
    );
    output.write_bytes(value);
    Ok(())
}

#[cfg(test)]
fn serialization(error: serde_json::Error) -> ModelError {
    ModelError::Serialization(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relation::{RelationEvidence, RelationOrigin};
    use crate::{
        alloc_probe, AdmissionPolicyDelta, ArtifactId, AuthorId, ChangeOrigin, EntityId,
        EntityKind, EntityMetadata, EntityRole, EvidenceId, ExternalReference, FilePathId,
        FingerprintAlgorithm, GitObjectId, GraphNodeId, LanguageId, LocatedEntry, RelationId,
        RelationKind, RepoPath, RiskLevel, RiskSummary, SemanticFingerprint, SharedAdmissionPolicy,
        SourceSpan, SpecId, Timestamp, TreeEntry, Visibility,
    };
    use chrono::{TimeZone, Utc};

    fn empty_change() -> SemanticChange {
        SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
            origin: ChangeOrigin::Native,
            parents: Vec::new(),
            timestamp: Timestamp::from(
                Utc.timestamp_millis_opt(1_700_000_000_000)
                    .single()
                    .unwrap(),
            ),
            author: AuthorId::new("identity-test"),
            message: "identity-bearing change".to_string(),
            entity_deltas: Vec::new(),
            relation_deltas: Vec::new(),
            tree_deltas: Vec::new(),
            admission_policy_delta: None,
            projected_files: Vec::new(),
            spec_link: None,
            evidence: Vec::new(),
            risk_summary: None,
            external_reference_deltas: Vec::new(),
        }
    }

    fn tree_delta(id: u128, path: &str, byte: u8) -> TreeDelta {
        TreeDelta::Added {
            artifact_id: crate::ArtifactId(uuid::Uuid::from_u128(id)),
            new: LocatedEntry::new(
                RepoPath::from_utf8(path).unwrap(),
                TreeEntry::blob(Hash256::from_bytes([byte; 32]), false),
            ),
        }
    }

    #[test]
    fn declared_id_is_excluded_but_every_payload_field_participates() {
        let original = empty_change();
        let expected = compute_semantic_change_id(&original).unwrap();

        let mut different_declared_id = original.clone();
        different_declared_id.id = SemanticChangeId::from_hash(Hash256::from_bytes([9; 32]));
        assert_eq!(
            compute_semantic_change_id(&different_declared_id).unwrap(),
            expected
        );

        let mut different_message = original;
        different_message.message.push('!');
        assert_ne!(
            compute_semantic_change_id(&different_message).unwrap(),
            expected
        );
    }

    #[test]
    fn change_origin_participates_in_v6_identity() {
        let native = empty_change();
        let mut imported = native.clone();
        imported.origin = ChangeOrigin::GitCommit {
            oid: GitObjectId::sha1([0x91; 20]),
        };

        assert_ne!(
            compute_semantic_change_id(&native).unwrap(),
            compute_semantic_change_id(&imported).unwrap()
        );
    }

    #[test]
    fn octopus_and_repeated_git_parents_preserve_exact_order() {
        let first = SemanticChangeId::from_hash(Hash256::from_bytes([0x31; 32]));
        let second = SemanticChangeId::from_hash(Hash256::from_bytes([0x32; 32]));
        let third = SemanticChangeId::from_hash(Hash256::from_bytes([0x33; 32]));
        let mut change = empty_change();
        change.parents = vec![first, second, first, third];

        let identity = compute_semantic_change_id(&change).unwrap();
        change.id = identity;
        validate_semantic_change_id(&change).unwrap();

        let encoded = serde_json::to_vec(&change).unwrap();
        let decoded: SemanticChange = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded.parents, vec![first, second, first, third]);

        let mut reordered = decoded;
        reordered.parents.swap(0, 1);
        assert_ne!(
            compute_semantic_change_id(&reordered).unwrap(),
            identity,
            "parent order participates in identity"
        );
    }

    #[test]
    fn independent_delta_order_is_canonical_but_duplicate_targets_are_rejected() {
        let first = tree_delta(1, "Dockerfile", 0x11);
        let second = tree_delta(2, "compose.yaml", 0x22);
        let left = TransactionDelta {
            tree_deltas: vec![first.clone(), second.clone()],
            ..TransactionDelta::default()
        };
        let right = TransactionDelta {
            tree_deltas: vec![second, first.clone()],
            ..TransactionDelta::default()
        };
        assert_eq!(
            content_identity_from_deltas(&left).unwrap(),
            content_identity_from_deltas(&right).unwrap()
        );

        let duplicate = TransactionDelta {
            tree_deltas: vec![
                first.clone(),
                TreeDelta::Removed {
                    artifact_id: first.artifact_id(),
                    old: first.new_state().unwrap().clone(),
                },
            ],
            ..TransactionDelta::default()
        };
        assert!(validate_transaction_delta(&duplicate).is_err());
    }

    #[test]
    fn validation_rejects_spoofed_and_accepts_recomputed_identity() {
        let mut change = empty_change();
        let error = validate_semantic_change_id(&change).unwrap_err();
        assert!(error.to_string().contains("recomputes to"));

        change.id = compute_semantic_change_id(&change).unwrap();
        validate_semantic_change_id(&change).unwrap();
    }

    #[test]
    fn semantic_change_v6_hash_domain_has_a_pinned_fixture() {
        let mut fixture = empty_change();
        fixture.id = SemanticChangeId::from_hash(Hash256::from_bytes([0x55; 32]));
        fixture.timestamp = Timestamp::from(
            chrono::DateTime::parse_from_rfc3339("2026-01-02T03:04:05Z")
                .unwrap()
                .with_timezone(&Utc),
        );
        fixture.author = AuthorId::new("fixture");
        fixture.message = "phase two".to_string();
        fixture.origin = ChangeOrigin::GitCommit {
            oid: GitObjectId::sha1([0x66; 20]),
        };

        assert_eq!(
            compute_semantic_change_id(&fixture).unwrap().to_string(),
            "f455b244cffbf4eee002e607b19926cefb575e2549fdc21ecbbb956a2eed9fad",
            "changing the kin-semantic-change-v6 domain or canonical fixture is a wire break"
        );
        assert!(
            !serde_json::to_string(&fixture)
                .unwrap()
                .contains("external_reference_deltas"),
            "an empty appended delta class must not move the legacy JSON fixture"
        );
        let messagepack = rmp_serde::to_vec(&fixture).unwrap();
        let decoded: SemanticChange = rmp_serde::from_slice(&messagepack).unwrap();
        assert!(decoded.external_reference_deltas.is_empty());
        assert_eq!(
            compute_semantic_change_id(&decoded).unwrap(),
            compute_semantic_change_id(&fixture).unwrap(),
            "an older positional change payload must keep its identity"
        );
    }

    /// The canonical encoder cannot see the order of an object's fields.
    ///
    /// This is the contract stated on [`canonical_json_bytes`], made
    /// falsifiable. Every identity in this crate is derived from these bytes,
    /// so anyone who makes the encoder order-preserving moves every identity
    /// already on disk, and this is the test that stops them silently.
    ///
    /// It is also the reason a hash differential is not enough for a
    /// hand-written or mirrored serialization: the two structs below emit the
    /// same field names in opposite orders and are byte-identical here, which
    /// is exactly what a field swapped in a mirror type looks like to every
    /// hash comparison in the crate.
    ///
    /// The three `assert_ne!` cases are the controls. Without them a broken
    /// encoder that returned a constant, or ignored its input, would satisfy
    /// the equality above and read as a pass.
    #[test]
    fn the_canonical_encoder_is_blind_to_object_field_order_and_to_nothing_else() {
        #[derive(serde::Serialize)]
        struct Declared {
            alpha: u8,
            beta: &'static str,
        }
        #[derive(serde::Serialize)]
        struct Reordered {
            beta: &'static str,
            alpha: u8,
        }
        #[derive(serde::Serialize)]
        struct Renamed {
            alpha: u8,
            gamma: &'static str,
        }

        let declared = canonical_json_bytes(&Declared {
            alpha: 7,
            beta: "value",
        })
        .unwrap();
        let reordered = canonical_json_bytes(&Reordered {
            beta: "value",
            alpha: 7,
        })
        .unwrap();
        assert_eq!(
            declared, reordered,
            "the canonical encoder started distinguishing field order, which rewrites every \
             identity in this crate; read the contract on canonical_json_bytes before changing it"
        );

        assert_ne!(
            declared,
            canonical_json_bytes(&Declared {
                alpha: 8,
                beta: "value",
            })
            .unwrap(),
            "the encoder ignored a field value"
        );
        assert_ne!(
            declared,
            canonical_json_bytes(&Renamed {
                alpha: 7,
                gamma: "value",
            })
            .unwrap(),
            "the encoder ignored a field name"
        );
        assert_ne!(
            canonical_json_bytes(&["first", "second"]).unwrap(),
            canonical_json_bytes(&["second", "first"]).unwrap(),
            "sequence order is part of the contract and must survive the encoder"
        );

        // The equality above cannot fail in the default feature
        // configuration, because `serde_json::Map` is a `BTreeMap` there and
        // cannot present its keys out of order in the first place. This is the
        // arm that can: the exact bytes, built here by hand from the format
        // `append_canonical_json` defines. Any change to that format fails
        // here, including one that stopped sorting under `preserve_order`,
        // where the map does keep insertion order.
        let mut expected = vec![5_u8];
        expected.extend_from_slice(&2_u64.to_le_bytes());
        expected.extend_from_slice(&5_u64.to_le_bytes());
        expected.extend_from_slice(b"alpha");
        expected.push(2);
        expected.extend_from_slice(&1_u64.to_le_bytes());
        expected.extend_from_slice(b"7");
        expected.extend_from_slice(&4_u64.to_le_bytes());
        expected.extend_from_slice(b"beta");
        expected.push(3);
        expected.extend_from_slice(&5_u64.to_le_bytes());
        expected.extend_from_slice(b"value");
        assert_eq!(
            declared, expected,
            "the canonical byte format moved, which rewrites every identity this crate has ever \
             written; `alpha` precedes `beta` here because keys are sorted, not because the \
             struct declares them that way"
        );
    }

    #[test]
    fn external_reference_deltas_are_canonical_identity_bearing_and_unique() {
        let first =
            crate::ExternalReference::new_resolved("python-module-v1", "requests", "get").unwrap();
        let second =
            crate::ExternalReference::new_resolved("npm-package-v1", "@mui/utils", "merge")
                .unwrap();
        let left = TransactionDelta {
            external_reference_deltas: vec![
                ExternalReferenceDelta::Added { new: first.clone() },
                ExternalReferenceDelta::Added {
                    new: second.clone(),
                },
            ],
            ..TransactionDelta::default()
        };
        let right = TransactionDelta {
            external_reference_deltas: vec![
                ExternalReferenceDelta::Added {
                    new: second.clone(),
                },
                ExternalReferenceDelta::Added { new: first.clone() },
            ],
            ..TransactionDelta::default()
        };
        assert_eq!(
            content_identity_from_deltas(&left).unwrap(),
            content_identity_from_deltas(&right).unwrap()
        );
        assert_eq!(left.inverse().inverse(), left);

        let duplicate = TransactionDelta {
            external_reference_deltas: vec![
                ExternalReferenceDelta::Added { new: first.clone() },
                ExternalReferenceDelta::Removed { old: first.clone() },
            ],
            ..TransactionDelta::default()
        };
        assert!(validate_transaction_delta(&duplicate)
            .unwrap_err()
            .to_string()
            .contains("more than one delta for external reference"));

        let mut change = empty_change();
        let baseline = compute_semantic_change_id(&change).unwrap();
        change.external_reference_deltas = vec![ExternalReferenceDelta::Added { new: first }];
        assert_ne!(compute_semantic_change_id(&change).unwrap(), baseline);
    }

    fn span(path: &str, start: usize) -> SourceSpan {
        SourceSpan {
            file: FilePathId::new(path),
            start_byte: start,
            end_byte: start + 240,
            start_line: 2,
            start_col: 0,
            end_line: 14,
            end_col: 1,
        }
    }

    /// An entity with every optional field present and a metadata bag that
    /// nests every JSON shape, so the flattened map path is anchored too.
    fn wide_entity(seed: u128, name: &str) -> Entity {
        let byte = seed as u8;
        let mut metadata = EntityMetadata::default();
        metadata.extra.insert(
            "decorators".to_string(),
            serde_json::json!(["route", { "path": "/v1", "methods": ["GET", "POST"] }]),
        );
        metadata
            .extra
            .insert("complexity".to_string(), serde_json::json!(seed as u64 % 7));
        metadata
            .extra
            .insert("ratio".to_string(), serde_json::json!(0.5));
        metadata
            .extra
            .insert("negative".to_string(), serde_json::json!(-3));
        metadata.extra.insert(
            "async".to_string(),
            serde_json::json!(seed.is_multiple_of(2)),
        );
        metadata
            .extra
            .insert("deprecated".to_string(), serde_json::Value::Null);
        Entity {
            id: EntityId(uuid::Uuid::from_u128(seed)),
            kind: EntityKind::Method,
            name: name.to_string(),
            language: LanguageId::Python,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([byte; 32]),
                signature_hash: Hash256::from_bytes([byte ^ 0x11; 32]),
                behavior_hash: Hash256::from_bytes([byte ^ 0x22; 32]),
                equivalence_hash: Hash256::from_bytes([byte ^ 0x33; 32]),
                stability_score: 0.875,
            },
            file_origin: Some(FilePathId::new(format!("src/{name}.py"))),
            span: Some(span(&format!("src/{name}.py"), 10)),
            signature: format!("def {name}(self, value: int) -> str"),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: Some(format!("{name} re\u{0301}sume\u{0301} \u{1F9EA}")),
            metadata,
            lineage_parent: Some(EntityId(uuid::Uuid::from_u128(seed + 1_000_000))),
            created_in: Some(SemanticChangeId::from_hash(Hash256::from_bytes([0x77; 32]))),
            superseded_by: None,
        }
    }

    fn wide_relation(seed: u128, src: EntityId, dst: GraphNodeId, confidence: f32) -> Relation {
        Relation {
            id: RelationId(uuid::Uuid::from_u128(seed)),
            kind: RelationKind::Calls,
            src: GraphNodeId::Entity(src),
            dst,
            confidence,
            origin: RelationOrigin::Lsp,
            created_in: Some(SemanticChangeId::from_hash(Hash256::from_bytes([0x78; 32]))),
            import_source: Some("requests".to_string()),
            evidence: vec![RelationEvidence {
                source_span: Some(span("src/caller.py", 300)),
                parser_rule: Some("call_expression".to_string()),
                token: Some("get".to_string()),
                source_path: Some("requests".to_string()),
                resolved_path: None,
                occurrence_count: 2,
                ..RelationEvidence::default()
            }],
        }
    }

    fn located(path: &str, entry: TreeEntry) -> LocatedEntry {
        LocatedEntry::new(RepoPath::from_utf8(path).unwrap(), entry)
    }

    /// A change that carries every field an identity can see, `width` deltas
    /// of every variant in every collection, and every collection out of
    /// canonical order.
    fn wide_change(width: u128) -> SemanticChange {
        let mut change = empty_change();
        change.origin = ChangeOrigin::GitCommit {
            oid: GitObjectId::sha1([0x42; 20]),
        };
        change.parents = vec![
            SemanticChangeId::from_hash(Hash256::from_bytes([0x31; 32])),
            SemanticChangeId::from_hash(Hash256::from_bytes([0x32; 32])),
        ];
        change.message = "wide change: re\u{0301}sume\u{0301} \u{1F9EA} \u{200F}bidi".to_string();
        let external =
            ExternalReference::new_resolved("python-module-v1", "requests", "get").unwrap();
        for index in (0..width).rev() {
            let byte = index as u8;
            let entity = wide_entity(1_000 + index, &format!("entity_{index}"));
            let entity_id = entity.id;
            let earlier = wide_entity(1_000 + index, &format!("entity_{index}_before"));
            change.entity_deltas.push(match index % 3 {
                0 => EntityDelta::Added { new: entity },
                1 => EntityDelta::Modified {
                    old: earlier,
                    new: entity,
                },
                _ => EntityDelta::Removed { old: entity },
            });

            let target = if index.is_multiple_of(2) {
                GraphNodeId::Entity(EntityId(uuid::Uuid::from_u128(2_000 + index)))
            } else {
                GraphNodeId::ExternalReference(external.id)
            };
            let relation = wide_relation(5_000 + index, entity_id, target, 0.75);
            let weaker = wide_relation(5_000 + index, entity_id, target, 0.5);
            change.relation_deltas.push(match index % 3 {
                0 => RelationDelta::Added { new: relation },
                1 => RelationDelta::Modified {
                    old: weaker,
                    new: relation,
                },
                _ => RelationDelta::Removed { old: relation },
            });

            let artifact_id = ArtifactId(uuid::Uuid::from_u128(9_000 + index));
            let blob = located(
                &format!("src/file_{index}.py"),
                TreeEntry::blob(Hash256::from_bytes([byte; 32]), index.is_multiple_of(2)),
            );
            change.tree_deltas.push(match index % 3 {
                0 => TreeDelta::Added {
                    artifact_id,
                    new: blob,
                },
                1 => TreeDelta::Updated {
                    artifact_id,
                    old: located(
                        &format!("src/link_{index}"),
                        TreeEntry::symlink(Hash256::from_bytes([byte ^ 0x44; 32])),
                    ),
                    new: located(
                        &format!("vendor/module_{index}"),
                        TreeEntry::gitlink(GitObjectId::sha1([byte; 20])),
                    ),
                },
                _ => TreeDelta::Removed {
                    artifact_id,
                    old: blob,
                },
            });
        }
        change.external_reference_deltas = vec![
            ExternalReferenceDelta::Added {
                new: ExternalReference::new_resolved("python-module-v1", "zzz-later", "sym")
                    .unwrap(),
            },
            ExternalReferenceDelta::Removed {
                old: ExternalReference::new_resolved("npm-package-v1", "@mui/utils", "merge")
                    .unwrap(),
            },
            ExternalReferenceDelta::Added { new: external },
        ];
        change.admission_policy_delta = Some(AdmissionPolicyDelta::initialize(
            SharedAdmissionPolicy::empty(0),
        ));
        change.projected_files = vec![FilePathId::new("src/b.py"), FilePathId::new("src/a.py")];
        change.spec_link = Some(SpecId(uuid::Uuid::from_u128(0x5bec)));
        change.evidence = vec![
            EvidenceId(uuid::Uuid::from_u128(0xe2)),
            EvidenceId(uuid::Uuid::from_u128(0xe1)),
        ];
        change.risk_summary = Some(RiskSummary {
            overall_risk: RiskLevel::High,
            breaking_changes: vec!["drops `get`".to_string()],
            test_coverage_gaps: Vec::new(),
            contract_violations: vec!["contract-1".to_string()],
            work_risks: vec!["an in-progress work item".to_string()],
            notes: vec!["note".to_string()],
        });
        change
    }

    /// Reorder every independent collection of `change` by `seed`.
    fn permute(change: &mut SemanticChange, seed: u64) {
        fn shuffle<T>(items: &mut [T], seed: u64) {
            if items.len() < 2 {
                return;
            }
            let rotate = usize::try_from(seed).unwrap_or(0) % items.len();
            items.rotate_left(rotate);
            if seed % 2 == 1 {
                items.reverse();
            }
            if seed % 3 == 2 {
                let middle = items.len() / 2;
                items.swap(0, middle);
            }
        }
        shuffle(&mut change.entity_deltas, seed);
        shuffle(&mut change.relation_deltas, seed.wrapping_add(1));
        shuffle(&mut change.tree_deltas, seed.wrapping_add(2));
        shuffle(&mut change.external_reference_deltas, seed.wrapping_add(3));
    }

    fn pinned_fixture() -> SemanticChange {
        let mut fixture = empty_change();
        fixture.id = SemanticChangeId::from_hash(Hash256::from_bytes([0x55; 32]));
        fixture.timestamp = Timestamp::from(
            chrono::DateTime::parse_from_rfc3339("2026-01-02T03:04:05Z")
                .unwrap()
                .with_timezone(&Utc),
        );
        fixture.author = AuthorId::new("fixture");
        fixture.message = "phase two".to_string();
        fixture.origin = ChangeOrigin::GitCommit {
            oid: GitObjectId::sha1([0x66; 20]),
        };
        fixture
    }

    /// The streamed identity preimage is the tree walk's, byte for byte, on
    /// every field a change can carry and every order its collections can
    /// arrive in.
    ///
    /// BYTES, not hashes, because a divergence then names the offset and the
    /// bytes on both sides rather than two digests that differ. Both sides
    /// must not go through the streaming walk, or the differential proves
    /// nothing, which is why `change_identity_preimage_via_tree` is kept.
    ///
    /// The shapes are the empty change, the pinned fixture, a wide change with
    /// every optional field present and every delta variant in every
    /// collection, eight reorderings of that change, and the same change with
    /// its skipped tail absent, so both branches of the header's field count
    /// are reached. The controls at the end make sure the comparison sees
    /// content: the reorderings share one identity and the other shapes each
    /// have their own.
    #[test]
    fn the_identity_preimage_matches_the_tree_walk() {
        let mut shapes: Vec<(String, SemanticChange)> = vec![
            ("empty change".to_string(), empty_change()),
            ("pinned fixture".to_string(), pinned_fixture()),
            ("wide change".to_string(), wide_change(9)),
        ];
        for seed in 0..8_u64 {
            let mut permuted = wide_change(9);
            permute(&mut permuted, seed);
            shapes.push((format!("wide change, reordering {seed}"), permuted));
        }
        let mut without_references = wide_change(5);
        without_references.external_reference_deltas.clear();
        shapes.push((
            "wide change without external references".to_string(),
            without_references,
        ));

        for (name, change) in &shapes {
            let streamed = change_identity_preimage(change).unwrap();
            let walked = change_identity_preimage_via_tree(change).unwrap();
            if streamed != walked {
                let offset = streamed
                    .iter()
                    .zip(walked.iter())
                    .position(|(left, right)| left != right)
                    .unwrap_or_else(|| streamed.len().min(walked.len()));
                let window = |bytes: &[u8]| {
                    bytes[offset.min(bytes.len())..(offset + 24).min(bytes.len())].to_vec()
                };
                panic!(
                    "{name}: the identity preimage walk diverges from the tree walk at offset \
                     {offset} (streamed {} bytes, tree walk {}); streamed {:?}, tree walk {:?}",
                    streamed.len(),
                    walked.len(),
                    window(&streamed),
                    window(&walked)
                );
            }
            assert!(
                !streamed.is_empty(),
                "{name}: encoded to nothing, so this comparison cannot fail"
            );
            assert_eq!(
                compute_semantic_change_id(change).unwrap(),
                reference_semantic_change_id(change).unwrap(),
                "{name}: the streamed identity differs from the one it replaced"
            );
        }

        let wide = compute_semantic_change_id(&shapes[2].1).unwrap();
        for (name, change) in &shapes[3..11] {
            assert_eq!(
                compute_semantic_change_id(change).unwrap(),
                wide,
                "{name}: delta order reached the identity"
            );
        }
        let distinct: BTreeSet<SemanticChangeId> = [0, 1, 2, 11]
            .into_iter()
            .map(|index| compute_semantic_change_id(&shapes[index].1).unwrap())
            .collect();
        assert_eq!(
            distinct.len(),
            4,
            "four different changes produced fewer than four identities, so the comparison \
             above is not seeing content"
        );
    }

    /// Deriving an identity still validates the deltas it hashes.
    ///
    /// The validation moved from a copy of the deltas to the deltas
    /// themselves, and a derivation that skipped it would mint an identity for
    /// a change no replay can apply.
    #[test]
    fn deriving_an_identity_refuses_an_invalid_delta_set() {
        let mut duplicated = wide_change(3);
        let repeated = duplicated.entity_deltas[0].clone();
        duplicated.entity_deltas.push(repeated);
        let error = compute_semantic_change_id(&duplicated).unwrap_err();
        assert!(
            error.to_string().contains("more than one delta for entity"),
            "{error}"
        );

        let mut unstable = wide_change(3);
        let entity = match &mut unstable.entity_deltas[0] {
            EntityDelta::Added { new } | EntityDelta::Modified { new, .. } => new,
            EntityDelta::Removed { old } => old,
        };
        entity.fingerprint.stability_score = f32::NAN;
        let error = compute_semantic_change_id(&unstable).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("invalid fingerprint stability score"),
            "{error}"
        );

        // The control: the same change validates and derives once repaired.
        compute_semantic_change_id(&wide_change(3)).unwrap();
    }

    /// A populated change's identity is pinned, and the pin is anchored to the
    /// retained tree walk as well as to the streaming derivation.
    ///
    /// The empty fixture in `semantic_change_v6_hash_domain_has_a_pinned_fixture`
    /// reaches none of the collections. This one reaches every field and every
    /// delta variant, so a change to how any of them is framed moves it. It was
    /// measured through `reference_semantic_change_id`, the implementation the
    /// streaming walk replaced, on the commit that introduced the walk.
    #[test]
    fn a_populated_change_has_a_pinned_identity() {
        const PINNED: &str = "0c62d43eca6530d579900e459b2dcc2385cf483bcebea896cb02c0eb4c43085e";
        let change = wide_change(9);
        let reference = reference_semantic_change_id(&change).unwrap().to_string();
        let streamed = compute_semantic_change_id(&change).unwrap().to_string();
        println!("WIDE_CHANGE_IDENTITY reference {reference} streamed {streamed}");
        assert_eq!(
            reference, PINNED,
            "the tree walk this pin was measured from no longer produces it, so the pin \
             anchors nothing"
        );
        assert_eq!(
            streamed, PINNED,
            "changing the kin-semantic-change-v6 preimage of a populated change is a wire break"
        );
    }

    /// Deriving an identity holds one delta at a time, never a copy of the
    /// change.
    ///
    /// Priced against the change's own clone so there is no constant to
    /// drift. The retained implementation is the control: it must show the
    /// probe at least two copies of the change, or a probe that cannot see a
    /// whole-change materialization proves nothing about the streaming walk.
    #[test]
    fn deriving_an_identity_holds_one_delta_at_a_time() {
        let change = wide_change(1_024);

        // Warm any lazily-initialized state so it is not charged to one arm.
        compute_semantic_change_id(&change).unwrap();
        reference_semantic_change_id(&change).unwrap();

        let clone_cost = alloc_probe::measure(|| {
            let copy = change.clone();
            std::hint::black_box(&copy);
        })
        .peak_live;
        let reference = alloc_probe::measure(|| {
            reference_semantic_change_id(&change).unwrap();
        })
        .peak_live;
        let streamed = alloc_probe::measure(|| {
            compute_semantic_change_id(&change).unwrap();
        })
        .peak_live;
        println!("clone {clone_cost} reference {reference} streamed {streamed}");

        assert!(
            clone_cost > 0 && reference > 0 && streamed > 0,
            "the allocation probe measured nothing, so it cannot fail: clone {clone_cost}, \
             reference {reference}, streamed {streamed}"
        );
        assert!(
            reference >= clone_cost * 2,
            "the retained derivation peaked at {reference} bytes against a clone's \
             {clone_cost}, so the probe is not seeing the copies it exists to price"
        );
        assert!(
            streamed * 8 <= clone_cost,
            "deriving an identity peaked at {streamed} bytes against a clone's {clone_cost}; \
             the derivation is holding a copy of the change again"
        );
    }
}
