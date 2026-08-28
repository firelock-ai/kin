//! Numerical-producer policy shared by every Kin surface that persists or
//! ranks against a vector index.
//!
//! KinDB attests which runtime actually returned each embedding vector, and
//! that attestation is the only trustworthy statement about a stored index's
//! numerics: the configured route is what a process asked for, while the
//! producer set is what the process got after memory guards, out-of-memory
//! retries and CPU-twin fallbacks have had their say.
//!
//! Two decisions read that attestation, and both live here so they cannot
//! drift apart. A hosted artifact may only be attached when every producer
//! bound into its bytes is one this process is willing to serve. A fresh query
//! vector may only be trusted against a persisted index when the runtime that
//! produced the query is one the index itself was built from. CPU and Metal
//! are close, but they are not proved rank-stable across persisted document
//! vectors and fresh query vectors, so they stay separate identities until a
//! dedicated cross-backend conformance proof admits a wider numeric profile.

use kin_db::{EmbeddingProducer, EmbeddingProducerSet};

/// Stable lowercase label for one producer.
///
/// Profile identities and operator-facing text both render through this, so a
/// producer never carries one spelling in a persisted identity and another in
/// the message that explains a refusal.
pub fn producer_label(producer: EmbeddingProducer) -> &'static str {
    match producer {
        EmbeddingProducer::Cpu => "cpu",
        EmbeddingProducer::Metal => "metal",
        EmbeddingProducer::Cuda => "cuda",
        EmbeddingProducer::Remote => "remote",
        EmbeddingProducer::Unspecified => "unspecified",
    }
}

/// Render a producer set in its canonical order as a comma-separated label.
///
/// An empty set renders as `none` rather than an empty string, because an
/// empty field in a log line reads as a formatting bug rather than as the fact
/// that no runtime was attested.
pub fn describe_producers(producers: &EmbeddingProducerSet) -> String {
    if producers.is_empty() {
        return "none".to_string();
    }
    producers
        .iter()
        .map(producer_label)
        .collect::<Vec<_>>()
        .join(",")
}

/// The exact producer set a hosted vector artifact may carry when this process
/// resolved `producer` as its single numerical route.
///
/// Hosted artifacts move between hosts, so the fence is one producer wide.
/// A producer this process cannot name is refused rather than widened: an
/// unproven numeric profile that fails closed costs a backfill, while one that
/// fails open silently ranks against vectors nothing ever compared.
pub fn hosted_allowed_producers(
    producer: EmbeddingProducer,
) -> std::result::Result<EmbeddingProducerSet, String> {
    match producer {
        EmbeddingProducer::Unspecified => Err(
            "hosted vector persistence requires an attributable producer, and this process \
             resolved none"
                .to_string(),
        ),
        attributed => Ok(EmbeddingProducerSet::singleton(attributed)),
    }
}

/// Whether a fresh query vector may be ranked against a persisted index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryProducerVerdict {
    /// No vector ranking happened, so there is nothing to attest. KinDB
    /// returns an empty producer set when the index is missing or empty.
    NotRanked,
    /// Every runtime that produced the query also produced part of the index.
    Attributed,
    /// The persisted index carries vectors written without producer evidence.
    IndexUnattributed { index: String },
    /// The query vector came back without producer evidence.
    QueryUnattributed { query: String },
    /// The query was produced by a runtime the index was never built from.
    Mismatched { query: String, index: String },
}

impl QueryProducerVerdict {
    /// Whether ranking on this result is backed by matching producer evidence.
    ///
    /// `NotRanked` is clean because no vector influenced the answer.
    pub fn is_clean(&self) -> bool {
        matches!(self, Self::NotRanked | Self::Attributed)
    }

    /// Stable machine-readable reason, for degradation records and metrics.
    pub fn reason(&self) -> Option<&'static str> {
        match self {
            Self::NotRanked | Self::Attributed => None,
            Self::IndexUnattributed { .. } => Some("vector_index_unattributed"),
            Self::QueryUnattributed { .. } => Some("query_vector_unattributed"),
            Self::Mismatched { .. } => Some("query_producer_mismatch"),
        }
    }

    /// Operator-facing sentence naming both sides of the disagreement.
    pub fn detail(&self) -> Option<String> {
        match self {
            Self::NotRanked | Self::Attributed => None,
            Self::IndexUnattributed { index } => Some(format!(
                "the persisted vector index carries producers {index}, so its numerics are not \
                 attributable and ranking against it is unproven"
            )),
            Self::QueryUnattributed { query } => Some(format!(
                "the query vector carries producers {query}, so the runtime that produced it is \
                 not attributable"
            )),
            Self::Mismatched { query, index } => Some(format!(
                "the query vector was produced by {query} while the persisted index was built by \
                 {index}, and those numerics are not proved rank-stable against each other"
            )),
        }
    }

    /// What an operator should do about it.
    pub fn remediation(&self) -> Option<&'static str> {
        match self {
            Self::NotRanked | Self::Attributed => None,
            Self::IndexUnattributed { .. } | Self::Mismatched { .. } => Some(
                "re-embed this repository on the runtime that serves queries (kin embed), or \
                 pin KIN_EMBED_BACKEND to the runtime that built the index",
            ),
            Self::QueryUnattributed { .. } => {
                Some("check daemon embed worker health (kin status), then retry")
            }
        }
    }
}

/// Compare the runtimes that produced a query vector with the lineage of the
/// index it was ranked against.
///
/// `index_lineage` is the conservative monotonic union KinDB keeps on the
/// persisted index; `query_producers` is the exact set that returned this
/// query's vectors. A query is admitted when its producers are a subset of the
/// lineage, because the index then already contains vectors from that runtime.
pub fn evaluate_query_producers(
    index_lineage: Option<&EmbeddingProducerSet>,
    query_producers: &EmbeddingProducerSet,
) -> QueryProducerVerdict {
    // KinDB returns an empty query producer set exactly when no query
    // embedding ran, which is the missing-or-empty index case. Nothing was
    // ranked on a vector, so there is no numeric claim to qualify.
    if query_producers.is_empty() {
        return QueryProducerVerdict::NotRanked;
    }
    let Some(index) = index_lineage.filter(|lineage| !lineage.is_empty()) else {
        return QueryProducerVerdict::IndexUnattributed {
            index: describe_producers(&EmbeddingProducerSet::new()),
        };
    };
    if !index.is_fully_attributed() {
        return QueryProducerVerdict::IndexUnattributed {
            index: describe_producers(index),
        };
    }
    if !query_producers.is_fully_attributed() {
        return QueryProducerVerdict::QueryUnattributed {
            query: describe_producers(query_producers),
        };
    }
    if query_producers.is_subset(index) {
        return QueryProducerVerdict::Attributed;
    }
    QueryProducerVerdict::Mismatched {
        query: describe_producers(query_producers),
        index: describe_producers(index),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(producers: &[EmbeddingProducer]) -> EmbeddingProducerSet {
        let mut out = EmbeddingProducerSet::new();
        for producer in producers {
            out.insert(*producer);
        }
        out
    }

    /// Every producer the enum can carry has exactly one label, and no two
    /// producers share one. A label collision would make a refusal message
    /// name a runtime that is not the one being refused.
    #[test]
    fn every_producer_has_one_distinct_label() {
        let all = [
            EmbeddingProducer::Cpu,
            EmbeddingProducer::Metal,
            EmbeddingProducer::Cuda,
            EmbeddingProducer::Remote,
            EmbeddingProducer::Unspecified,
        ];
        let mut labels: Vec<&str> = all.iter().map(|p| producer_label(*p)).collect();
        labels.sort_unstable();
        let distinct = labels.len();
        labels.dedup();
        assert_eq!(
            labels.len(),
            distinct,
            "two producers share one label: {labels:?}"
        );
        assert!(
            labels.iter().all(|label| !label.is_empty()),
            "a producer rendered as an empty label"
        );
    }

    #[test]
    fn an_empty_set_describes_as_none_rather_than_empty_text() {
        assert_eq!(describe_producers(&EmbeddingProducerSet::new()), "none");
    }

    #[test]
    fn a_set_describes_in_canonical_order() {
        assert_eq!(
            describe_producers(&set(&[EmbeddingProducer::Metal, EmbeddingProducer::Cpu])),
            "cpu,metal"
        );
    }

    /// The hosted fence is exactly one attributed producer wide, and the
    /// unattributed producer is refused rather than admitted as a fifth value.
    #[test]
    fn hosted_allowlist_is_one_attributed_producer_and_refuses_unspecified() {
        for producer in [
            EmbeddingProducer::Cpu,
            EmbeddingProducer::Metal,
            EmbeddingProducer::Cuda,
            EmbeddingProducer::Remote,
        ] {
            let allowed = hosted_allowed_producers(producer)
                .unwrap_or_else(|error| panic!("{producer:?} must be admissible: {error}"));
            assert_eq!(allowed.len(), 1, "{producer:?} widened the hosted fence");
            assert!(allowed.contains(producer));
        }
        let refused = hosted_allowed_producers(EmbeddingProducer::Unspecified)
            .expect_err("an unattributed producer must not open the hosted fence");
        assert!(
            refused.contains("attributable"),
            "the refusal must say why: {refused}"
        );
    }

    /// A CPU-built index queried by a CPU runtime is the healthy path, and it
    /// must report no reason at all. A counter that never reads zero cannot
    /// tell a caller that anything is well.
    #[test]
    fn a_matching_runtime_is_attributed_and_carries_no_reason() {
        let index = set(&[EmbeddingProducer::Cpu]);
        let verdict = evaluate_query_producers(Some(&index), &set(&[EmbeddingProducer::Cpu]));
        assert_eq!(verdict, QueryProducerVerdict::Attributed);
        assert!(verdict.is_clean());
        assert_eq!(verdict.reason(), None);
        assert_eq!(verdict.detail(), None);
        assert_eq!(verdict.remediation(), None);
    }

    #[test]
    fn an_empty_query_set_is_not_ranked_rather_than_mismatched() {
        let index = set(&[EmbeddingProducer::Metal]);
        let verdict = evaluate_query_producers(Some(&index), &EmbeddingProducerSet::new());
        assert_eq!(verdict, QueryProducerVerdict::NotRanked);
        assert!(verdict.is_clean());
        // And it stays NotRanked with no index at all, because nothing ranked.
        assert_eq!(
            evaluate_query_producers(None, &EmbeddingProducerSet::new()),
            QueryProducerVerdict::NotRanked
        );
    }

    /// The external P1-2 case: a Metal query against a CPU-built index.
    #[test]
    fn a_metal_query_against_a_cpu_index_is_mismatched_and_names_both_sides() {
        let index = set(&[EmbeddingProducer::Cpu]);
        let verdict = evaluate_query_producers(Some(&index), &set(&[EmbeddingProducer::Metal]));
        assert!(!verdict.is_clean());
        assert_eq!(verdict.reason(), Some("query_producer_mismatch"));
        let detail = verdict.detail().expect("a mismatch must explain itself");
        assert!(detail.contains("metal"), "query side missing: {detail}");
        assert!(detail.contains("cpu"), "index side missing: {detail}");
        assert!(verdict.remediation().is_some());
    }

    /// The OOM-fallback case runs the other way: a Metal-built index queried
    /// by the CPU twin after a memory guard fired.
    #[test]
    fn a_cpu_fallback_query_against_a_metal_index_is_mismatched() {
        let index = set(&[EmbeddingProducer::Metal]);
        let verdict = evaluate_query_producers(Some(&index), &set(&[EmbeddingProducer::Cpu]));
        assert_eq!(verdict.reason(), Some("query_producer_mismatch"));
    }

    #[test]
    fn a_remote_query_against_a_local_index_is_mismatched() {
        let index = set(&[EmbeddingProducer::Cpu]);
        let verdict = evaluate_query_producers(Some(&index), &set(&[EmbeddingProducer::Remote]));
        assert_eq!(verdict.reason(), Some("query_producer_mismatch"));
    }

    /// A mixed query batch is admitted only when the index carries BOTH
    /// runtimes. The subset rule is the whole point: one arm being present is
    /// not enough.
    #[test]
    fn a_mixed_query_batch_needs_the_whole_lineage_not_one_arm() {
        let mixed = set(&[EmbeddingProducer::Cpu, EmbeddingProducer::Metal]);
        assert_eq!(
            evaluate_query_producers(Some(&set(&[EmbeddingProducer::Cpu])), &mixed).reason(),
            Some("query_producer_mismatch")
        );
        assert_eq!(
            evaluate_query_producers(Some(&mixed), &mixed),
            QueryProducerVerdict::Attributed
        );
        // A single-arm query against a mixed index is a subset, so it ranks.
        assert_eq!(
            evaluate_query_producers(Some(&mixed), &set(&[EmbeddingProducer::Metal])),
            QueryProducerVerdict::Attributed
        );
    }

    /// An index built by raw insertion carries `Unspecified`, and that is
    /// reported as the index's fault rather than blamed on the query, even
    /// when the query is itself unattributed.
    #[test]
    fn an_unattributed_index_is_reported_before_the_query_is_blamed() {
        let index = set(&[EmbeddingProducer::Cpu, EmbeddingProducer::Unspecified]);
        let verdict = evaluate_query_producers(Some(&index), &set(&[EmbeddingProducer::Cpu]));
        assert_eq!(verdict.reason(), Some("vector_index_unattributed"));
        let detail = verdict.detail().expect("must explain itself");
        assert!(detail.contains("unspecified"), "{detail}");

        let both_unattributed = evaluate_query_producers(
            Some(&index),
            &set(&[EmbeddingProducer::Unspecified]),
        );
        assert_eq!(both_unattributed.reason(), Some("vector_index_unattributed"));
    }

    /// An attributed index queried by an unattributed vector blames the query.
    #[test]
    fn an_unattributed_query_against_an_attributed_index_blames_the_query() {
        let index = set(&[EmbeddingProducer::Cpu]);
        let verdict =
            evaluate_query_producers(Some(&index), &set(&[EmbeddingProducer::Unspecified]));
        assert_eq!(verdict.reason(), Some("query_vector_unattributed"));
    }

    /// A query that ranked against an index with no lineage at all is not
    /// silently admitted. This is the state a pre-provenance index reaches.
    #[test]
    fn a_ranked_query_against_a_lineage_free_index_is_unattributed() {
        let verdict = evaluate_query_producers(None, &set(&[EmbeddingProducer::Cpu]));
        assert_eq!(verdict.reason(), Some("vector_index_unattributed"));
        assert_eq!(
            evaluate_query_producers(
                Some(&EmbeddingProducerSet::new()),
                &set(&[EmbeddingProducer::Cpu])
            )
            .reason(),
            Some("vector_index_unattributed")
        );
    }

    /// Every non-clean verdict carries all three of reason, detail and
    /// remediation, and every clean one carries none. Asserting the join over
    /// the real set stops a new variant from shipping with a reason nothing
    /// can explain.
    #[test]
    fn every_verdict_variant_is_complete_in_both_directions() {
        let cases = [
            QueryProducerVerdict::NotRanked,
            QueryProducerVerdict::Attributed,
            QueryProducerVerdict::IndexUnattributed {
                index: "unspecified".to_string(),
            },
            QueryProducerVerdict::QueryUnattributed {
                query: "unspecified".to_string(),
            },
            QueryProducerVerdict::Mismatched {
                query: "metal".to_string(),
                index: "cpu".to_string(),
            },
        ];
        for verdict in cases {
            if verdict.is_clean() {
                assert_eq!(verdict.reason(), None, "{verdict:?}");
                assert_eq!(verdict.detail(), None, "{verdict:?}");
                assert_eq!(verdict.remediation(), None, "{verdict:?}");
            } else {
                assert!(verdict.reason().is_some(), "{verdict:?}");
                assert!(verdict.detail().is_some(), "{verdict:?}");
                assert!(verdict.remediation().is_some(), "{verdict:?}");
            }
        }
    }
}
