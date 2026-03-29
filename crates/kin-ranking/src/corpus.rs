// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Curated benchmark corpus for evaluating search ranking quality.
//!
//! Each benchmark query includes synthetic candidates with pre-assigned signals
//! and human-graded relevance judgments. This enables offline evaluation of
//! ranking algorithms without requiring a live graph.

use crate::relevance::RelevanceJudgment;
use crate::{CandidateSignals, SearchCandidate, SearchQuery};

/// A single benchmark query with candidates and relevance judgments.
pub struct BenchmarkQuery {
    /// Short identifier for this query.
    pub name: String,
    /// Human description of what this query tests.
    pub description: String,
    /// The search query.
    pub query: SearchQuery,
    /// Candidate entities with pre-computed signals.
    pub candidates: Vec<SearchCandidate>,
    /// Ground-truth relevance judgments.
    pub judgments: Vec<RelevanceJudgment>,
}

/// Complete benchmark corpus for search relevance evaluation.
pub struct SearchBenchmarkCorpus {
    pub queries: Vec<BenchmarkQuery>,
}

impl SearchBenchmarkCorpus {
    /// Returns the built-in benchmark corpus with 8 curated queries spanning
    /// different search scenarios: exact match, partial match, semantic concept,
    /// proof-required, multi-signal fusion, type disambiguation, broad vs narrow,
    /// and provenance-weighted.
    pub fn default_corpus() -> Self {
        Self {
            queries: vec![
                exact_name_match(),
                partial_prefix(),
                semantic_concept(),
                proof_required(),
                multi_signal_fusion(),
                type_disambiguation(),
                broad_query(),
                provenance_weighted(),
            ],
        }
    }

    pub fn len(&self) -> usize {
        self.queries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.queries.is_empty()
    }
}

fn candidate(id: &str, title: &str, signals: CandidateSignals) -> SearchCandidate {
    SearchCandidate {
        id: id.to_string(),
        title: title.to_string(),
        signals,
    }
}

fn judgment(id: &str, grade: u8) -> RelevanceJudgment {
    RelevanceJudgment {
        id: id.to_string(),
        grade,
    }
}

/// Query "handleRequest" — tests lexical dominance.
fn exact_name_match() -> BenchmarkQuery {
    BenchmarkQuery {
        name: "exact_name_match".into(),
        description: "Tests that exact name matches rank first via lexical signal".into(),
        query: SearchQuery::new("handleRequest"),
        candidates: vec![
            candidate(
                "e:1",
                "handleRequest",
                CandidateSignals::new(0.95, 0.7, 0.5, 0.3, 0.6),
            ),
            candidate(
                "e:2",
                "handleResponse",
                CandidateSignals::new(0.55, 0.65, 0.4, 0.2, 0.5),
            ),
            candidate(
                "e:3",
                "RequestParser",
                CandidateSignals::new(0.40, 0.50, 0.3, 0.1, 0.3),
            ),
            candidate(
                "e:4",
                "routeMiddleware",
                CandidateSignals::new(0.15, 0.45, 0.6, 0.0, 0.4),
            ),
            candidate(
                "e:5",
                "DatabasePool",
                CandidateSignals::new(0.05, 0.10, 0.2, 0.0, 0.2),
            ),
        ],
        judgments: vec![
            judgment("e:1", 3),
            judgment("e:2", 2),
            judgment("e:3", 1),
            judgment("e:4", 1),
            judgment("e:5", 0),
        ],
    }
}

/// Query "parse" — tests prefix matching across multiple relevant entities.
fn partial_prefix() -> BenchmarkQuery {
    BenchmarkQuery {
        name: "partial_prefix".into(),
        description: "Tests prefix matching: multiple entities share a common prefix".into(),
        query: SearchQuery::new("parse"),
        candidates: vec![
            candidate(
                "e:10",
                "ParseConfig",
                CandidateSignals::new(0.85, 0.60, 0.4, 0.5, 0.5),
            ),
            candidate(
                "e:11",
                "ParseArgs",
                CandidateSignals::new(0.80, 0.55, 0.3, 0.4, 0.4),
            ),
            candidate(
                "e:12",
                "TokenParser",
                CandidateSignals::new(0.70, 0.65, 0.5, 0.3, 0.3),
            ),
            candidate(
                "e:13",
                "Validator",
                CandidateSignals::new(0.20, 0.35, 0.3, 0.2, 0.2),
            ),
            candidate(
                "e:14",
                "Logger",
                CandidateSignals::new(0.05, 0.10, 0.1, 0.0, 0.1),
            ),
        ],
        judgments: vec![
            judgment("e:10", 3),
            judgment("e:11", 2),
            judgment("e:12", 2),
            judgment("e:13", 1),
            judgment("e:14", 0),
        ],
    }
}

/// Query "authentication" — tests semantic signal dominance.
fn semantic_concept() -> BenchmarkQuery {
    BenchmarkQuery {
        name: "semantic_concept".into(),
        description: "Tests that semantic signal can elevate entities with low lexical match"
            .into(),
        query: SearchQuery::new("authentication"),
        candidates: vec![
            candidate(
                "e:20",
                "AuthMiddleware",
                CandidateSignals::new(0.20, 0.90, 0.7, 0.5, 0.6),
            ),
            candidate(
                "e:21",
                "SessionValidator",
                CandidateSignals::new(0.10, 0.75, 0.5, 0.4, 0.5),
            ),
            candidate(
                "e:22",
                "UserModel",
                CandidateSignals::new(0.15, 0.50, 0.4, 0.2, 0.4),
            ),
            candidate(
                "e:23",
                "DatabasePool",
                CandidateSignals::new(0.05, 0.15, 0.2, 0.1, 0.2),
            ),
            candidate(
                "e:24",
                "LogFormatter",
                CandidateSignals::new(0.02, 0.05, 0.1, 0.0, 0.1),
            ),
        ],
        judgments: vec![
            judgment("e:20", 3),
            judgment("e:21", 2),
            judgment("e:22", 1),
            judgment("e:23", 0),
            judgment("e:24", 0),
        ],
    }
}

/// Query "validate" with require_proof=true — tests proof filtering.
fn proof_required() -> BenchmarkQuery {
    let mut query = SearchQuery::new("validate");
    query.require_proof = true;
    BenchmarkQuery {
        name: "proof_required".into(),
        description: "Tests that require_proof filters out unproven candidates".into(),
        query,
        candidates: vec![
            candidate(
                "e:30",
                "ValidateInput",
                CandidateSignals::new(0.80, 0.60, 0.4, 0.80, 0.5),
            ),
            candidate(
                "e:31",
                "SchemaChecker",
                CandidateSignals::new(0.50, 0.55, 0.5, 0.60, 0.4),
            ),
            candidate(
                "e:32",
                "QuickCheck",
                CandidateSignals::new(0.70, 0.50, 0.3, 0.00, 0.3),
            ),
            candidate(
                "e:33",
                "TypeGuard",
                CandidateSignals::new(0.40, 0.45, 0.3, 0.40, 0.3),
            ),
            candidate(
                "e:34",
                "FormatHelper",
                CandidateSignals::new(0.30, 0.20, 0.1, 0.00, 0.1),
            ),
        ],
        judgments: vec![
            judgment("e:30", 3),
            judgment("e:31", 2),
            judgment("e:32", 0), // filtered by proof requirement
            judgment("e:33", 1),
            judgment("e:34", 0), // filtered by proof requirement
        ],
    }
}

/// Query "router" — tests that balanced signals beat single-strong.
fn multi_signal_fusion() -> BenchmarkQuery {
    BenchmarkQuery {
        name: "multi_signal_fusion".into(),
        description: "Tests that balanced multi-signal candidates outrank single-signal ones"
            .into(),
        query: SearchQuery::new("router"),
        candidates: vec![
            candidate(
                "e:40",
                "RouterImpl",
                CandidateSignals::new(0.70, 0.65, 0.60, 0.55, 0.50),
            ),
            candidate(
                "e:41",
                "RouteHelper",
                CandidateSignals::new(0.90, 0.15, 0.10, 0.05, 0.05),
            ),
            candidate(
                "e:42",
                "PathMatcher",
                CandidateSignals::new(0.30, 0.70, 0.40, 0.30, 0.20),
            ),
            candidate(
                "e:43",
                "MiddlewareChain",
                CandidateSignals::new(0.15, 0.40, 0.65, 0.20, 0.30),
            ),
            candidate(
                "e:44",
                "ErrorHandler",
                CandidateSignals::new(0.10, 0.20, 0.25, 0.10, 0.15),
            ),
            candidate(
                "e:45",
                "StaticServer",
                CandidateSignals::new(0.05, 0.10, 0.15, 0.05, 0.10),
            ),
        ],
        judgments: vec![
            judgment("e:40", 3),
            judgment("e:41", 2),
            judgment("e:42", 2),
            judgment("e:43", 1),
            judgment("e:44", 0),
            judgment("e:45", 0),
        ],
    }
}

/// Query "Config" — common name, tests disambiguation among similar entities.
fn type_disambiguation() -> BenchmarkQuery {
    BenchmarkQuery {
        name: "type_disambiguation".into(),
        description: "Tests ranking among many similarly-named entities".into(),
        query: SearchQuery::new("Config"),
        candidates: vec![
            candidate(
                "e:50",
                "AppConfig",
                CandidateSignals::new(0.80, 0.70, 0.65, 0.50, 0.70),
            ),
            candidate(
                "e:51",
                "DbConfig",
                CandidateSignals::new(0.75, 0.60, 0.50, 0.40, 0.50),
            ),
            candidate(
                "e:52",
                "TestConfig",
                CandidateSignals::new(0.75, 0.50, 0.30, 0.20, 0.30),
            ),
            candidate(
                "e:53",
                "ConfigParser",
                CandidateSignals::new(0.60, 0.45, 0.25, 0.15, 0.25),
            ),
            candidate(
                "e:54",
                "RuntimeFlags",
                CandidateSignals::new(0.20, 0.35, 0.20, 0.10, 0.20),
            ),
            candidate(
                "e:55",
                "EnvLoader",
                CandidateSignals::new(0.10, 0.30, 0.15, 0.05, 0.15),
            ),
        ],
        judgments: vec![
            judgment("e:50", 3),
            judgment("e:51", 2),
            judgment("e:52", 1),
            judgment("e:53", 1),
            judgment("e:54", 0),
            judgment("e:55", 0),
        ],
    }
}

/// Query "get" — very broad, tests ranking quality in noisy results.
fn broad_query() -> BenchmarkQuery {
    BenchmarkQuery {
        name: "broad_query".into(),
        description: "Tests ranking with a very broad query producing many low-quality matches"
            .into(),
        query: SearchQuery::new("get"),
        candidates: vec![
            candidate(
                "e:60",
                "getUser",
                CandidateSignals::new(0.85, 0.50, 0.60, 0.40, 0.55),
            ),
            candidate(
                "e:61",
                "getConfig",
                CandidateSignals::new(0.80, 0.45, 0.50, 0.35, 0.45),
            ),
            candidate(
                "e:62",
                "getter",
                CandidateSignals::new(0.75, 0.30, 0.20, 0.10, 0.20),
            ),
            candidate(
                "e:63",
                "Widget",
                CandidateSignals::new(0.10, 0.15, 0.10, 0.05, 0.10),
            ),
            candidate(
                "e:64",
                "setUser",
                CandidateSignals::new(0.40, 0.40, 0.55, 0.30, 0.40),
            ),
            candidate(
                "e:65",
                "fetchData",
                CandidateSignals::new(0.25, 0.50, 0.35, 0.20, 0.30),
            ),
            candidate(
                "e:66",
                "deleteRecord",
                CandidateSignals::new(0.10, 0.10, 0.10, 0.05, 0.05),
            ),
        ],
        judgments: vec![
            judgment("e:60", 3),
            judgment("e:61", 2),
            judgment("e:62", 1),
            judgment("e:63", 0),
            judgment("e:64", 1),
            judgment("e:65", 1),
            judgment("e:66", 0),
        ],
    }
}

/// Query "migrate" — tests provenance signal contribution.
fn provenance_weighted() -> BenchmarkQuery {
    BenchmarkQuery {
        name: "provenance_weighted".into(),
        description: "Tests that provenance signal helps distinguish production vs test code"
            .into(),
        query: SearchQuery::new("migrate"),
        candidates: vec![
            candidate(
                "e:70",
                "MigrateDatabase",
                CandidateSignals::new(0.80, 0.65, 0.50, 0.40, 0.90),
            ),
            candidate(
                "e:71",
                "MigrateSchema",
                CandidateSignals::new(0.75, 0.60, 0.45, 0.35, 0.70),
            ),
            candidate(
                "e:72",
                "MigrateTest",
                CandidateSignals::new(0.70, 0.55, 0.30, 0.20, 0.15),
            ),
            candidate(
                "e:73",
                "SeedData",
                CandidateSignals::new(0.25, 0.40, 0.35, 0.15, 0.50),
            ),
            candidate(
                "e:74",
                "DropTable",
                CandidateSignals::new(0.15, 0.30, 0.20, 0.10, 0.30),
            ),
        ],
        judgments: vec![
            judgment("e:70", 3),
            judgment("e:71", 2),
            judgment("e:72", 1),
            judgment("e:73", 1),
            judgment("e:74", 0),
        ],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn corpus_loads_with_eight_queries() {
        let corpus = SearchBenchmarkCorpus::default_corpus();
        assert_eq!(corpus.len(), 8);
        assert!(!corpus.is_empty());
    }

    #[test]
    fn each_query_has_candidates_and_judgments() {
        let corpus = SearchBenchmarkCorpus::default_corpus();
        for query in &corpus.queries {
            assert!(
                !query.candidates.is_empty(),
                "Query '{}' has no candidates",
                query.name,
            );
            assert!(
                !query.judgments.is_empty(),
                "Query '{}' has no judgments",
                query.name,
            );
        }
    }

    #[test]
    fn all_judgment_ids_match_candidate_ids() {
        let corpus = SearchBenchmarkCorpus::default_corpus();
        for bq in &corpus.queries {
            let candidate_ids: Vec<&str> = bq.candidates.iter().map(|c| c.id.as_str()).collect();
            for j in &bq.judgments {
                assert!(
                    candidate_ids.contains(&j.id.as_str()),
                    "Query '{}': judgment ID '{}' not found in candidates",
                    bq.name,
                    j.id,
                );
            }
        }
    }

    #[test]
    fn query_names_are_unique() {
        let corpus = SearchBenchmarkCorpus::default_corpus();
        let mut names: Vec<&str> = corpus.queries.iter().map(|q| q.name.as_str()).collect();
        names.sort();
        names.dedup();
        assert_eq!(names.len(), 8);
    }

    #[test]
    fn each_query_has_at_least_one_relevant_judgment() {
        let corpus = SearchBenchmarkCorpus::default_corpus();
        for bq in &corpus.queries {
            let has_relevant = bq.judgments.iter().any(|j| j.grade >= 2);
            assert!(
                has_relevant,
                "Query '{}' has no relevant judgments (grade >= 2)",
                bq.name,
            );
        }
    }

    #[test]
    fn exact_name_match_query_text_correct() {
        let corpus = SearchBenchmarkCorpus::default_corpus();
        let q = corpus
            .queries
            .iter()
            .find(|q| q.name == "exact_name_match")
            .unwrap();
        assert_eq!(q.query.text, "handleRequest");
    }

    #[test]
    fn proof_required_query_has_flag_set() {
        let corpus = SearchBenchmarkCorpus::default_corpus();
        let q = corpus
            .queries
            .iter()
            .find(|q| q.name == "proof_required")
            .unwrap();
        assert!(q.query.require_proof);
    }
}
