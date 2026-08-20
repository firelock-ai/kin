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
pub(crate) struct AdmittedChangeMap<'a> {
    changes: &'a std::collections::HashMap<SemanticChangeId, SemanticChange>,
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
        Ok(Self { changes })
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
        Self { changes: clone }
    }

    /// Whether this witness describes exactly `changes`, by pointer identity.
    pub(crate) fn describes(
        &self,
        changes: &std::collections::HashMap<SemanticChangeId, SemanticChange>,
    ) -> bool {
        std::ptr::eq(self.changes, changes)
    }
}

#[cfg(test)]
mod admitted_change_map_tests {
    use super::*;
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
        let admitted_map = std::collections::HashMap::new();
        let twin = admitted_map.clone();
        assert_eq!(
            admitted_map, twin,
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
