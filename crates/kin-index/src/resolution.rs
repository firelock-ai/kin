// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! How strongly a graph edge's destination was proven.
//!
//! A call edge resolved from a bare method name is a candidate, not a fact.
//! Before this marker existed, an edge the linker had proven through an import
//! and an edge it had guessed from a repo-wide same-name match were
//! indistinguishable in every response, so `impact_analysis`, `find_references`,
//! `trace_data_flow`, `graph_neighborhood` and dead-code all consumed guesses as
//! facts.
//!
//! The marker is derived from what the graph already persists rather than added
//! as a new stored field, so every store that already exists classifies without
//! a migration and no relation schema changes. The derivation is exact rather
//! than a heuristic: each linker resolution tier stamps its own distinct
//! `confidence`, that value is persisted and merkle-bound, and
//! [`RelationResolution::of`] inverts the tier ladder. `resolution_tier_ladder`
//! in this module's tests asserts the two stay in step.

use kin_model::{Relation, RelationOrigin};

/// Field name this marker is published under on every agent-facing response
/// that returns edges. Downstream consumers that must count only proven edges
/// (dead-code analysis, "is this unused" claims) key on this name.
pub const RESOLUTION_FIELD: &str = "resolution";

/// How the destination of a relation was established.
///
/// Ordered weakest to strongest so `>=` comparisons read naturally: a consumer
/// that may only count proven edges writes
/// `resolution >= RelationResolution::ImportScoped`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RelationResolution {
    /// The target was chosen by matching a bare name across the repository.
    /// Nothing about the call site proves this destination: a same-named
    /// method on an unrelated type, a test double, or an overload would match
    /// equally well. Treat as a candidate.
    NameOnly,
    /// The target module or directory scope was known — the receiver is bound
    /// by an import in this file, the callee was pinned to a module by the
    /// parser, or the caller's own imports/include closure singled the file out
    /// — and the symbol was then selected inside that scope.
    ImportScoped,
    /// The destination entity itself is proven: it is defined in this file, it
    /// is the symbol a declared import names, it is the ancestor a pinned
    /// dispatch class resolves to, or a language server reported it.
    TypeResolved,
}

impl RelationResolution {
    /// Stable wire name. These strings are the published contract; they are
    /// what a reader and any downstream filter match on, so they must not
    /// change with refactors.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TypeResolved => "type_resolved",
            Self::ImportScoped => "import_scoped",
            Self::NameOnly => "name_only",
        }
    }

    /// Whether an edge at this resolution may be counted as evidence that a
    /// destination is genuinely used. `name_only` may not: it is exactly the
    /// class of edge that made `Session.request` appear to call
    /// `RequestsCookieJar.update`.
    pub fn is_proven(self) -> bool {
        self >= Self::ImportScoped
    }

    /// Classify a stored relation.
    ///
    /// Exact tier constants are matched first so the classification cannot
    /// drift with a threshold. A confidence from outside the ladder (a
    /// hand-authored edge, a future tier, an older store) falls back to a
    /// monotone reading of the same scale, which is conservative: an unknown
    /// value never classifies stronger than the tier band it lands in.
    pub fn of(relation: &Relation) -> Self {
        if matches!(
            relation.origin,
            RelationOrigin::Lsp | RelationOrigin::Manual
        ) {
            return Self::TypeResolved;
        }
        Self::from_confidence(relation.confidence)
    }

    /// Classify from a persisted tier confidence alone.
    ///
    /// Used where only the confidence survived the boundary — a cross-repo
    /// spine edge carries its confidence but not the relation record the other
    /// repository resolved.
    pub fn from_confidence(confidence: f32) -> Self {
        for &(tier, resolution) in RESOLUTION_TIER_LADDER {
            if confidence.to_bits() == tier.to_bits() {
                return resolution;
            }
        }
        if confidence >= 0.95 {
            Self::TypeResolved
        } else if confidence >= 0.8 {
            Self::ImportScoped
        } else {
            Self::NameOnly
        }
    }
}

/// Confidence the receiver-method fan-out tier persists.
///
/// The tier resolves `x.m(...)` where nothing settles the receiver's type, so
/// its destination is the weakest thing the linker emits: a method that shares
/// the leaf name. It is named here rather than written as a literal because
/// [`is_receiver_name_guess`] recovers the tier from it, and a second copy of
/// the number is how the two would come apart.
pub const RECEIVER_NAME_FANOUT_CONFIDENCE: f32 = 0.3;

/// Whether this edge is a receiver-method call the linker matched on the bare
/// leaf name alone.
///
/// `name_only` covers four tiers, and they are not equally weak. A callee
/// written `Error::msg` that matches exactly one entity in the repository is
/// stamped `name_only` too, and demoting it would take ordinary cross-file
/// calls out of every count that reads this. What FIR-1552 is about is
/// narrower: the tier that answered `find_references(HTTPAdapter.send)` with 33
/// rows for a method two lines call. This predicate names that tier and nothing
/// else.
///
/// A language server or a hand-authored edge is proven whatever its confidence,
/// matching [`RelationResolution::of`], so neither can be read as a guess here.
pub fn is_receiver_name_guess(relation: &Relation) -> bool {
    !matches!(
        relation.origin,
        RelationOrigin::Lsp | RelationOrigin::Manual
    ) && relation.confidence.to_bits() == RECEIVER_NAME_FANOUT_CONFIDENCE.to_bits()
}

/// The linker's resolution tiers, as (persisted confidence, what that tier
/// proved). Kept beside the enum so a new tier has one obvious place to
/// declare what it proved, and tested in `linker.rs` against the constants the
/// tiers actually emit.
pub const RESOLUTION_TIER_LADDER: &[(f32, RelationResolution)] = &[
    // Parser-certain: the destination is defined in the calling file, or the
    // macro use reaches its definition through the include closure.
    (1.0, RelationResolution::TypeResolved),
    (0.95, RelationResolution::TypeResolved),
    // A pinned dispatch class walked its Extends chain to the defining
    // ancestor: the receiver type is known, so the destination is proven.
    (0.85, RelationResolution::TypeResolved),
    // Module known, symbol selected inside it.
    (0.9, RelationResolution::ImportScoped),
    // Ambiguous same-name bucket settled by the caller's own directory,
    // imports, or include closure.
    (0.8, RelationResolution::ImportScoped),
    // Same name somewhere else in the repo, with nothing to say it is this one.
    (0.7, RelationResolution::NameOnly),
    // A path-qualified callee reduced by dropping its module prefix.
    (0.6, RelationResolution::NameOnly),
    // Receiver-method fan-out: every same-named method in the repo.
    (
        RECEIVER_NAME_FANOUT_CONFIDENCE,
        RelationResolution::NameOnly,
    ),
    // Cross-repo placeholder: the destination is not in this repo at all.
    (0.2, RelationResolution::NameOnly),
];

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{EntityId, GraphNodeId, RelationId, RelationKind};

    fn relation(confidence: f32, origin: RelationOrigin) -> Relation {
        let src = EntityId::from_content("a.py", "A", "Function", 1);
        let dst = EntityId::from_content("b.py", "B", "Function", 1);
        Relation {
            id: RelationId::from_content("a", "b", "Calls"),
            kind: RelationKind::Calls,
            src: GraphNodeId::Entity(src),
            dst: GraphNodeId::Entity(dst),
            confidence,
            origin,
            created_in: None,
            import_source: None,
            evidence: Vec::new(),
        }
    }

    #[test]
    fn every_ladder_entry_classifies_as_declared() {
        for &(confidence, expected) in RESOLUTION_TIER_LADDER {
            assert_eq!(
                RelationResolution::of(&relation(confidence, RelationOrigin::Inferred)),
                expected,
                "tier at confidence {confidence} classified against its declaration"
            );
        }
    }

    #[test]
    fn a_language_server_edge_is_type_resolved_whatever_its_confidence() {
        assert_eq!(
            RelationResolution::of(&relation(0.3, RelationOrigin::Lsp)),
            RelationResolution::TypeResolved
        );
        assert_eq!(
            RelationResolution::of(&relation(0.3, RelationOrigin::Manual)),
            RelationResolution::TypeResolved
        );
    }

    #[test]
    fn an_off_ladder_confidence_falls_back_monotonically() {
        // Values no tier emits, so only the fallback can answer.
        assert_eq!(
            RelationResolution::of(&relation(0.97, RelationOrigin::Inferred)),
            RelationResolution::TypeResolved
        );
        assert_eq!(
            RelationResolution::of(&relation(0.83, RelationOrigin::Inferred)),
            RelationResolution::ImportScoped
        );
        assert_eq!(
            RelationResolution::of(&relation(0.5, RelationOrigin::Inferred)),
            RelationResolution::NameOnly
        );
    }

    #[test]
    fn only_proven_resolutions_may_be_counted_as_use() {
        assert!(!RelationResolution::NameOnly.is_proven());
        assert!(RelationResolution::ImportScoped.is_proven());
        assert!(RelationResolution::TypeResolved.is_proven());
    }

    #[test]
    fn only_the_receiver_fanout_tier_reads_as_a_receiver_name_guess() {
        assert!(is_receiver_name_guess(&relation(
            RECEIVER_NAME_FANOUT_CONFIDENCE,
            RelationOrigin::Inferred
        )));
        // The other three `name_only` tiers are not this one. An exact-name
        // match with a single candidate in particular is an ordinary cross-file
        // call, and counting it as a guess would empty every reference headline.
        for confidence in [0.7, 0.6, 0.2] {
            assert_eq!(
                RelationResolution::of(&relation(confidence, RelationOrigin::Inferred)),
                RelationResolution::NameOnly,
                "tier {confidence} is name_only"
            );
            assert!(
                !is_receiver_name_guess(&relation(confidence, RelationOrigin::Inferred)),
                "but tier {confidence} is not the receiver fan-out"
            );
        }
    }

    #[test]
    fn a_language_server_edge_is_never_a_receiver_name_guess() {
        for origin in [RelationOrigin::Lsp, RelationOrigin::Manual] {
            assert!(!is_receiver_name_guess(&relation(
                RECEIVER_NAME_FANOUT_CONFIDENCE,
                origin
            )));
        }
    }

    #[test]
    fn wire_names_are_the_published_contract() {
        assert_eq!(RelationResolution::TypeResolved.as_str(), "type_resolved");
        assert_eq!(RelationResolution::ImportScoped.as_str(), "import_scoped");
        assert_eq!(RelationResolution::NameOnly.as_str(), "name_only");
        assert_eq!(RESOLUTION_FIELD, "resolution");
    }
}
