#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchQuery {
    pub text: String,
    pub require_proof: bool,
    pub limit: usize,
}

impl SearchQuery {
    pub fn new(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            require_proof: false,
            limit: 20,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct CandidateSignals {
    pub lexical: f32,
    pub semantic: f32,
    pub graph: f32,
    pub proof: f32,
    pub provenance: f32,
}

impl CandidateSignals {
    pub const fn new(
        lexical: f32,
        semantic: f32,
        graph: f32,
        proof: f32,
        provenance: f32,
    ) -> Self {
        Self {
            lexical,
            semantic,
            graph,
            proof,
            provenance,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct SearchCandidate {
    pub id: String,
    pub title: String,
    pub signals: CandidateSignals,
}

#[derive(Debug, Clone, PartialEq)]
pub struct RankedResult {
    pub id: String,
    pub title: String,
    pub score: f32,
    pub explanation: String,
}

pub fn rank_candidates(query: &SearchQuery, candidates: &[SearchCandidate]) -> Vec<RankedResult> {
    let mut ranked: Vec<_> = candidates
        .iter()
        .filter(|candidate| !query.require_proof || candidate.signals.proof > 0.0)
        .map(|candidate| RankedResult {
            id: candidate.id.clone(),
            title: candidate.title.clone(),
            score: candidate_score(query, &candidate.signals),
            explanation: explanation_for(&candidate.signals),
        })
        .collect();

    ranked.sort_by(|left, right| right.score.total_cmp(&left.score));
    ranked.truncate(query.limit);
    ranked
}

fn candidate_score(query: &SearchQuery, signals: &CandidateSignals) -> f32 {
    let proof_bias = if query.require_proof { 1.35 } else { 1.0 };
    signals.lexical * 0.30
        + signals.semantic * 0.28
        + signals.graph * 0.18
        + signals.proof * 0.16 * proof_bias
        + signals.provenance * 0.08
}

fn explanation_for(signals: &CandidateSignals) -> String {
    let mut parts = Vec::new();
    if signals.lexical > 0.0 {
        parts.push("lexical");
    }
    if signals.semantic > 0.0 {
        parts.push("semantic");
    }
    if signals.graph > 0.0 {
        parts.push("graph");
    }
    if signals.proof > 0.0 {
        parts.push("proof");
    }
    if signals.provenance > 0.0 {
        parts.push("provenance");
    }
    if parts.is_empty() {
        "unranked".to_string()
    } else {
        format!("ranked via {}", parts.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::{rank_candidates, CandidateSignals, SearchCandidate, SearchQuery};

    #[test]
    fn proof_requirement_filters_unproven_results() {
        let mut query = SearchQuery::new("queue");
        query.require_proof = true;

        let ranked = rank_candidates(
            &query,
            &[
                SearchCandidate {
                    id: "entity:1".into(),
                    title: "QueueRuntime".into(),
                    signals: CandidateSignals::new(0.7, 0.8, 0.6, 0.0, 0.4),
                },
                SearchCandidate {
                    id: "entity:2".into(),
                    title: "QueueProof".into(),
                    signals: CandidateSignals::new(0.6, 0.7, 0.5, 0.8, 0.4),
                },
            ],
        );

        assert_eq!(ranked.len(), 1);
        assert_eq!(ranked[0].id, "entity:2");
    }

    #[test]
    fn ranking_prefers_balanced_high_signal_candidates() {
        let query = SearchQuery::new("runtime");

        let ranked = rank_candidates(
            &query,
            &[
                SearchCandidate {
                    id: "entity:weak-proof".into(),
                    title: "RuntimeNotes".into(),
                    signals: CandidateSignals::new(0.9, 0.7, 0.2, 0.0, 0.2),
                },
                SearchCandidate {
                    id: "entity:balanced".into(),
                    title: "RuntimeController".into(),
                    signals: CandidateSignals::new(0.7, 0.8, 0.8, 0.8, 0.6),
                },
            ],
        );

        assert_eq!(ranked[0].id, "entity:balanced");
        assert!(ranked[0].explanation.contains("proof"));
    }
}
