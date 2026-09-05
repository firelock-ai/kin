// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use crate::error::KinDbError;
use crate::types::{SemanticChange, SemanticChangeId};

/// Validate one immutable semantic change before it crosses an authoritative
/// storage boundary.
pub(crate) fn validate_semantic_change(change: &SemanticChange) -> Result<(), KinDbError> {
    kin_model::validate_semantic_change_id(change)?;
    Ok(())
}

/// Validate both the collection key and the full-payload identity of one
/// semantic change.
pub(crate) fn validate_semantic_change_entry(
    key: &SemanticChangeId,
    change: &SemanticChange,
    boundary: &str,
) -> Result<(), KinDbError> {
    if key != &change.id {
        return Err(KinDbError::StorageError(format!(
            "{boundary} semantic change map key {key} does not match declared id {}",
            change.id
        )));
    }
    validate_semantic_change(change)
}

/// Validate every keyed semantic change in an authoritative collection.
pub(crate) fn validate_semantic_change_entries<'a>(
    entries: impl IntoIterator<Item = (&'a SemanticChangeId, &'a SemanticChange)>,
    boundary: &str,
) -> Result<(), KinDbError> {
    for (key, change) in entries {
        validate_semantic_change_entry(key, change, boundary)?;
    }
    Ok(())
}

/// Proof that one exact semantic change map has passed the admission pass.
///
/// Re-deriving the content-addressed id of every semantic change is O(history),
/// and one successor preparation ran that pass five times over a single map,
/// because every derived snapshot on the workspace path carries the authority's
/// change map verbatim and every consumer of a derived snapshot validates it
/// again. This witness carries the first pass's result to the others.
///
/// The proof is carried by the type rather than by a flag. The field is private
/// and the map is borrowed, so a witness cannot be forged, cannot be built from
/// a map nobody admitted, and cannot have an entry added to it after the fact:
/// a shared borrow makes post-construction insertion impossible by Rust's own
/// rules rather than by convention.
///
/// Correspondence is checked, not assumed. [`describes`](Self::describes)
/// compares by pointer identity, which is exact and O(1), so a witness for one
/// map can never license skipping the pass on a different map.
#[derive(Clone, Copy)]
pub(crate) enum AdmittedChangeMap<'a> {
    /// The pass ran in this process over exactly the borrowed map.
    Derived(&'a std::collections::HashMap<SemanticChangeId, SemanticChange>),
    /// The map is still on disk, and that IS the pass.
    ///
    /// An encoded map is built in exactly one place, by
    /// `GraphSnapshot::from_bytes_with_encoded_history`, which recovery reaches
    /// only when a durable validation record names these exact snapshot bytes
    /// at this validator version. That record is the whole validator's verdict
    /// on those bytes, admission included, so a map that is still encoded is a
    /// map that record already admitted. Mutating one decodes it first
    /// (`DerefMut` forces), so an encoded map is also provably the map the open
    /// verified rather than a descendant of it.
    OnDisk(&'a crate::storage::change_map::ChangeMap),
}

impl<'a> AdmittedChangeMap<'a> {
    /// Run the admission pass and witness the map that passed it.
    ///
    /// This is the trust anchor and the only way to admit a map that no other
    /// witness already covers.
    pub(crate) fn admit(
        changes: &'a std::collections::HashMap<SemanticChangeId, SemanticChange>,
        boundary: &str,
    ) -> Result<Self, KinDbError> {
        validate_semantic_change_entries(changes.iter(), boundary)?;
        Ok(Self::Derived(changes))
    }

    /// Witness a map an open left on disk, or `None` for one in memory.
    ///
    /// `None` is the whole safety property of this constructor: a decoded map
    /// carries no record of where it came from, so it gets the ordinary pass
    /// and nothing here can hand it a free one. Only the encoded state, which
    /// the variant above shows can be reached only under a durable validation
    /// record, is witnessed.
    ///
    /// This exists because re-deriving the id of every change would decode the
    /// history the open deliberately left on disk: measured on a full VS Code
    /// store, 1,418,929,338 bytes retained for the life of the daemon to reach
    /// a conclusion the record already carried.
    pub(crate) fn on_disk(changes: &'a crate::storage::change_map::ChangeMap) -> Option<Self> {
        (!changes.is_decoded()).then_some(Self::OnDisk(changes))
    }

    /// Carry an existing admission onto a map the caller just cloned from the
    /// admitted one.
    ///
    /// Holding an `AdmittedChangeMap` is the only way to reach this, so an
    /// unadmitted map cannot enter through it. What this constructor cannot
    /// check is that `clone` really is a clone of `admitted`'s map, so every
    /// call site places it beside the clone that justifies it, and
    /// `carry_sites_stay_enumerated` fails if a new call site appears.
    pub(crate) fn carried_from_clone(
        clone: &'a std::collections::HashMap<SemanticChangeId, SemanticChange>,
        admitted: &AdmittedChangeMap<'_>,
    ) -> Self {
        let _ = admitted;
        Self::Derived(clone)
    }

    /// Whether this witness describes exactly `changes`, by pointer identity.
    ///
    /// Takes the map in its own type rather than its decoded entries, so that
    /// asking the question does not decode the answer. A `Derived` witness
    /// borrows entries, so it can only describe a map that already holds them;
    /// against one still on disk it reports false without decoding it, which
    /// is the same verdict a decode would have reached, since a fresh decode
    /// is a fresh allocation and never the map the witness borrowed.
    pub(crate) fn describes(&self, changes: &crate::storage::change_map::ChangeMap) -> bool {
        match self {
            Self::Derived(admitted) => changes
                .decoded_if_present()
                .is_some_and(|decoded| std::ptr::eq(*admitted, decoded)),
            Self::OnDisk(admitted) => std::ptr::eq(*admitted, changes),
        }
    }
}

#[cfg(test)]
mod admitted_change_map_tests {
    use super::*;
    use crate::storage::change_map::{ChangeMap, EncodedChanges, HistorySource};
    use crate::storage::format::GraphSnapshot;
    use crate::storage::repository::GitProjectionTreeReplay;

    /// The carrying path must refuse a witness that was minted for some other
    /// map. Without this, holding any witness at all would license skipping the
    /// pass on any snapshot, which is the trust extension this design exists to
    /// avoid.
    #[test]
    fn carrying_refuses_a_witness_minted_for_a_different_map() {
        let subject = GraphSnapshot::empty();
        let other = GraphSnapshot::empty();
        let witness = AdmittedChangeMap::admit(&other.changes, "other snapshot")
            .expect("an empty map is admissible");
        let error = subject
            .validate_storage_admission_carrying(GitProjectionTreeReplay::Required, &witness)
            .expect_err("a witness for another map must not license a skip");
        assert!(
            error
                .to_string()
                .contains("does not describe this snapshot's change map"),
            "a witness for a different map must be refused by name, got: {error}"
        );
    }

    /// The other direction, so the refusal above is discrimination rather than
    /// a path that always refuses.
    #[test]
    fn carrying_accepts_the_map_its_witness_admitted() {
        let subject = GraphSnapshot::empty();
        let witness = AdmittedChangeMap::admit(&subject.changes, "subject snapshot")
            .expect("an empty map is admissible");
        subject
            .validate_storage_admission_carrying(GitProjectionTreeReplay::Required, &witness)
            .expect("a snapshot's own witness must be accepted");
    }

    /// `describes` is pointer identity, so an equal-but-distinct map is not the
    /// admitted one. Two maps with identical contents must not be
    /// interchangeable, or the check would degrade to a contents comparison
    /// that proves nothing about which map was actually admitted.
    #[test]
    fn an_equal_but_distinct_map_is_not_the_admitted_one() {
        let admitted_map = ChangeMap::new();
        let twin = ChangeMap::from(admitted_map.decoded().unwrap().clone());
        assert_eq!(
            *admitted_map, *twin,
            "the two maps must be equal for this test to mean anything"
        );
        let witness = AdmittedChangeMap::admit(&admitted_map, "admitted")
            .expect("an empty map is admissible");
        assert!(
            witness.describes(&admitted_map),
            "a witness must describe the map it admitted"
        );
        assert!(
            !witness.describes(&twin),
            "an equal but distinct map must not be treated as the admitted one"
        );
    }

    #[test]
    fn a_shared_history_witness_stops_at_mutable_access() {
        let admitted_map = ChangeMap::new();
        let mut shared = admitted_map.clone();
        let witness = AdmittedChangeMap::admit(&admitted_map, "admitted")
            .expect("an empty map is admissible");
        assert!(
            witness.describes(&shared),
            "both readers hold the admitted history"
        );

        // Even a mutable operation that leaves the contents equal detaches
        // the map. A later write cannot borrow the original map's admission.
        shared.reserve(1);
        assert_eq!(*admitted_map, *shared);
        assert!(witness.describes(&admitted_map));
        assert!(!witness.describes(&shared));
    }

    /// A map in memory carries no record of where it came from, so it must not
    /// be witnessable this way. This is the one check standing between the
    /// on-disk witness and a free pass for any map at all.
    #[test]
    fn a_decoded_map_cannot_be_witnessed_as_being_on_disk() {
        let decoded = ChangeMap::new();
        assert!(decoded.is_decoded(), "the control: this map is in memory");
        assert!(
            AdmittedChangeMap::on_disk(&decoded).is_none(),
            "a map in memory must take the ordinary admission pass"
        );
    }

    /// The other direction, so the refusal above is discrimination rather than
    /// a constructor that never returns a witness. An encoded map is witnessed,
    /// it describes itself, and it describes nothing else, all without decoding.
    #[test]
    fn an_on_disk_map_is_witnessed_and_describes_only_itself() {
        let encoded = encoded_change_map();
        let other = encoded_change_map();
        assert!(
            !encoded.is_decoded(),
            "the control: this map is still on disk"
        );
        let witness =
            AdmittedChangeMap::on_disk(&encoded).expect("an encoded map is witnessed on disk");
        assert!(witness.describes(&encoded));
        assert!(
            !witness.describes(&other),
            "a witness for one on-disk map must not describe another"
        );
        assert!(
            !encoded.is_decoded() && !other.is_decoded(),
            "asking the question must not decode either map"
        );
    }

    /// A witness minted over decoded entries must not describe a map that is
    /// still on disk, and asking must not decode it. Without this, the identity
    /// check would pay the very decode the witness exists to avoid.
    #[test]
    fn a_derived_witness_does_not_describe_an_on_disk_map() {
        let decoded = ChangeMap::new();
        let witness =
            AdmittedChangeMap::admit(&decoded, "admitted").expect("an empty map is admissible");
        let encoded = encoded_change_map();
        assert!(!witness.describes(&encoded));
        assert!(
            !encoded.is_decoded(),
            "the identity check must not have decoded it"
        );
    }

    /// A map that reports itself as on disk. Its source is never read here:
    /// every assertion above is about identity, and decoding is exactly what
    /// these tests prove does not happen.
    fn encoded_change_map() -> ChangeMap {
        ChangeMap::encoded(EncodedChanges::new(
            HistorySource::Memory(std::sync::Arc::from(Vec::new().into_boxed_slice())),
            0..0,
            1,
            [0u8; 32],
        ))
    }

    /// Every place that carries an admission onto a map it did not itself
    /// admit is a trust point, because the clone relationship cannot be checked
    /// without re-deriving the digests the carry exists to avoid. They are
    /// enumerated here so a new one cannot appear silently.
    ///
    /// If this fails, a call site was added or removed. Confirm the new site
    /// genuinely clones the witnessed map beside it, then update the count and
    /// say so in the change that does it.
    #[test]
    fn carry_sites_stay_enumerated() {
        const NEEDLE: &str = "AdmittedChangeMap::carried_from_clone(";
        let repository = include_str!("repository.rs").matches(NEEDLE).count();
        let graph = include_str!("../engine/graph.rs").matches(NEEDLE).count();
        assert_eq!(
            (repository, graph),
            (2, 1),
            "the carry sites moved: repository.rs has {repository} and graph.rs has {graph}"
        );
    }
}
