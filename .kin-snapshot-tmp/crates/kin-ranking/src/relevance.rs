// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Information retrieval evaluation metrics for search relevance benchmarking.
//!
//! Implements NDCG@K, MRR, Precision@K, and Recall@K using graded relevance
//! judgments (0–3 scale: irrelevant, somewhat, highly, perfect).

use crate::RankedResult;

/// A human relevance judgment for a single entity in a query.
#[derive(Debug, Clone, PartialEq)]
pub struct RelevanceJudgment {
    /// Entity ID that this judgment applies to.
    pub id: String,
    /// Relevance grade: 0 = irrelevant, 1 = somewhat, 2 = highly, 3 = perfect.
    pub grade: u8,
}

/// Aggregated relevance metrics for a single query or averaged across a corpus.
#[derive(Debug, Clone, PartialEq)]
pub struct RelevanceReport {
    pub ndcg_5: f64,
    pub ndcg_10: f64,
    pub mrr: f64,
    pub precision_5: f64,
    pub precision_10: f64,
    pub recall_10: f64,
}

/// Normalized Discounted Cumulative Gain at position K.
///
/// DCG = sum_{i=1}^{k} (2^rel_i - 1) / log2(i + 1)
/// IDCG = DCG of the ideal ranking (sorted by grade descending)
/// NDCG = DCG / IDCG
pub fn ndcg_at_k(results: &[RankedResult], judgments: &[RelevanceJudgment], k: usize) -> f64 {
    if k == 0 || results.is_empty() {
        return 0.0;
    }

    let k = k.min(results.len());

    // Compute DCG for the actual ranking.
    let dcg: f64 = results[..k]
        .iter()
        .enumerate()
        .map(|(i, result)| {
            let grade = grade_for(&result.id, judgments) as f64;
            (2.0_f64.powf(grade) - 1.0) / (i as f64 + 2.0).log2()
        })
        .sum();

    // Compute IDCG: sort all judgment grades descending, take top k.
    let mut ideal_grades: Vec<f64> = judgments.iter().map(|j| j.grade as f64).collect();
    ideal_grades.sort_by(|a, b| b.total_cmp(a));
    ideal_grades.truncate(k);

    let idcg: f64 = ideal_grades
        .iter()
        .enumerate()
        .map(|(i, &grade)| (2.0_f64.powf(grade) - 1.0) / (i as f64 + 2.0).log2())
        .sum();

    if idcg == 0.0 {
        return 0.0;
    }

    dcg / idcg
}

/// Mean Reciprocal Rank.
///
/// Finds the rank of the first result with grade >= 2 (highly relevant).
/// Returns 1.0 / rank, or 0.0 if no highly relevant result appears.
pub fn mrr(results: &[RankedResult], judgments: &[RelevanceJudgment]) -> f64 {
    for (i, result) in results.iter().enumerate() {
        if grade_for(&result.id, judgments) >= 2 {
            return 1.0 / (i as f64 + 1.0);
        }
    }
    0.0
}

/// Fraction of top-K results that have grade >= threshold.
pub fn precision_at_k(
    results: &[RankedResult],
    judgments: &[RelevanceJudgment],
    k: usize,
    threshold: u8,
) -> f64 {
    if k == 0 {
        return 0.0;
    }
    let k = k.min(results.len());
    if k == 0 {
        return 0.0;
    }

    let relevant_count = results[..k]
        .iter()
        .filter(|r| grade_for(&r.id, judgments) >= threshold)
        .count();

    relevant_count as f64 / k as f64
}

/// Fraction of all relevant items (grade >= threshold in judgments) that appear
/// in the top-K results.
pub fn recall_at_k(
    results: &[RankedResult],
    judgments: &[RelevanceJudgment],
    k: usize,
    threshold: u8,
) -> f64 {
    let total_relevant = judgments.iter().filter(|j| j.grade >= threshold).count();
    if total_relevant == 0 {
        return 0.0;
    }

    let k = k.min(results.len());
    let found_relevant = results[..k]
        .iter()
        .filter(|r| grade_for(&r.id, judgments) >= threshold)
        .count();

    found_relevant as f64 / total_relevant as f64
}

/// Computes all standard relevance metrics and returns a [`RelevanceReport`].
pub fn evaluate_relevance(
    results: &[RankedResult],
    judgments: &[RelevanceJudgment],
) -> RelevanceReport {
    RelevanceReport {
        ndcg_5: ndcg_at_k(results, judgments, 5),
        ndcg_10: ndcg_at_k(results, judgments, 10),
        mrr: mrr(results, judgments),
        precision_5: precision_at_k(results, judgments, 5, 2),
        precision_10: precision_at_k(results, judgments, 10, 2),
        recall_10: recall_at_k(results, judgments, 10, 2),
    }
}

/// Looks up the relevance grade for a given entity ID. Returns 0 if not found.
fn grade_for(id: &str, judgments: &[RelevanceJudgment]) -> u8 {
    judgments
        .iter()
        .find(|j| j.id == id)
        .map(|j| j.grade)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RankedResult;

    fn make_result(id: &str, score: f32) -> RankedResult {
        RankedResult {
            id: id.to_string(),
            title: id.to_string(),
            score,
            explanation: String::new(),
        }
    }

    fn make_judgment(id: &str, grade: u8) -> RelevanceJudgment {
        RelevanceJudgment {
            id: id.to_string(),
            grade,
        }
    }

    // -----------------------------------------------------------------------
    // NDCG tests
    // -----------------------------------------------------------------------

    #[test]
    fn perfect_ranking_produces_ndcg_one() {
        // Results already in ideal order: grade 3, 2, 1, 0
        let results = vec![
            make_result("a", 1.0),
            make_result("b", 0.8),
            make_result("c", 0.5),
            make_result("d", 0.2),
        ];
        let judgments = vec![
            make_judgment("a", 3),
            make_judgment("b", 2),
            make_judgment("c", 1),
            make_judgment("d", 0),
        ];
        let ndcg = ndcg_at_k(&results, &judgments, 4);
        assert!((ndcg - 1.0).abs() < 1e-10, "Expected 1.0, got {ndcg}");
    }

    #[test]
    fn worst_ranking_produces_low_ndcg() {
        // Reversed order: worst first
        let results = vec![
            make_result("d", 1.0),
            make_result("c", 0.8),
            make_result("b", 0.5),
            make_result("a", 0.2),
        ];
        let judgments = vec![
            make_judgment("a", 3),
            make_judgment("b", 2),
            make_judgment("c", 1),
            make_judgment("d", 0),
        ];
        let ndcg = ndcg_at_k(&results, &judgments, 4);
        assert!(ndcg < 0.7, "Expected low NDCG, got {ndcg}");
    }

    #[test]
    fn ndcg_empty_results_returns_zero() {
        let judgments = vec![make_judgment("a", 3)];
        assert_eq!(ndcg_at_k(&[], &judgments, 5), 0.0);
    }

    #[test]
    fn ndcg_k_zero_returns_zero() {
        let results = vec![make_result("a", 1.0)];
        let judgments = vec![make_judgment("a", 3)];
        assert_eq!(ndcg_at_k(&results, &judgments, 0), 0.0);
    }

    #[test]
    fn ndcg_no_relevant_judgments_returns_zero() {
        let results = vec![make_result("a", 1.0)];
        let judgments = vec![make_judgment("a", 0)];
        assert_eq!(ndcg_at_k(&results, &judgments, 5), 0.0);
    }

    #[test]
    fn ndcg_k_larger_than_results_uses_result_count() {
        let results = vec![make_result("a", 1.0), make_result("b", 0.5)];
        let judgments = vec![make_judgment("a", 3), make_judgment("b", 2)];
        let ndcg = ndcg_at_k(&results, &judgments, 100);
        assert!((ndcg - 1.0).abs() < 1e-10);
    }

    // -----------------------------------------------------------------------
    // MRR tests
    // -----------------------------------------------------------------------

    #[test]
    fn mrr_first_result_highly_relevant() {
        let results = vec![make_result("a", 1.0), make_result("b", 0.5)];
        let judgments = vec![make_judgment("a", 3), make_judgment("b", 1)];
        assert!((mrr(&results, &judgments) - 1.0).abs() < 1e-10);
    }

    #[test]
    fn mrr_second_result_highly_relevant() {
        let results = vec![make_result("b", 1.0), make_result("a", 0.5)];
        let judgments = vec![make_judgment("a", 2), make_judgment("b", 1)];
        assert!((mrr(&results, &judgments) - 0.5).abs() < 1e-10);
    }

    #[test]
    fn mrr_no_relevant_returns_zero() {
        let results = vec![make_result("a", 1.0)];
        let judgments = vec![make_judgment("a", 1)];
        assert_eq!(mrr(&results, &judgments), 0.0);
    }

    #[test]
    fn mrr_empty_results_returns_zero() {
        let judgments = vec![make_judgment("a", 3)];
        assert_eq!(mrr(&[], &judgments), 0.0);
    }

    // -----------------------------------------------------------------------
    // Precision tests
    // -----------------------------------------------------------------------

    #[test]
    fn precision_all_relevant() {
        let results = vec![make_result("a", 1.0), make_result("b", 0.8)];
        let judgments = vec![make_judgment("a", 3), make_judgment("b", 2)];
        assert!((precision_at_k(&results, &judgments, 2, 2) - 1.0).abs() < 1e-10);
    }

    #[test]
    fn precision_half_relevant() {
        let results = vec![make_result("a", 1.0), make_result("b", 0.8)];
        let judgments = vec![make_judgment("a", 3), make_judgment("b", 0)];
        assert!((precision_at_k(&results, &judgments, 2, 2) - 0.5).abs() < 1e-10);
    }

    #[test]
    fn precision_k_zero_returns_zero() {
        let results = vec![make_result("a", 1.0)];
        let judgments = vec![make_judgment("a", 3)];
        assert_eq!(precision_at_k(&results, &judgments, 0, 2), 0.0);
    }

    #[test]
    fn precision_threshold_behavior() {
        let results = vec![make_result("a", 1.0)];
        let judgments = vec![make_judgment("a", 1)];
        // grade 1 < threshold 2
        assert_eq!(precision_at_k(&results, &judgments, 1, 2), 0.0);
        // grade 1 >= threshold 1
        assert!((precision_at_k(&results, &judgments, 1, 1) - 1.0).abs() < 1e-10);
    }

    // -----------------------------------------------------------------------
    // Recall tests
    // -----------------------------------------------------------------------

    #[test]
    fn recall_all_found() {
        let results = vec![make_result("a", 1.0), make_result("b", 0.8)];
        let judgments = vec![make_judgment("a", 3), make_judgment("b", 2)];
        assert!((recall_at_k(&results, &judgments, 2, 2) - 1.0).abs() < 1e-10);
    }

    #[test]
    fn recall_partial() {
        let results = vec![make_result("a", 1.0)];
        let judgments = vec![make_judgment("a", 3), make_judgment("b", 2)];
        assert!((recall_at_k(&results, &judgments, 1, 2) - 0.5).abs() < 1e-10);
    }

    #[test]
    fn recall_no_relevant_in_judgments_returns_zero() {
        let results = vec![make_result("a", 1.0)];
        let judgments = vec![make_judgment("a", 0)];
        assert_eq!(recall_at_k(&results, &judgments, 1, 2), 0.0);
    }

    // -----------------------------------------------------------------------
    // evaluate_relevance integration test
    // -----------------------------------------------------------------------

    #[test]
    fn evaluate_relevance_returns_all_metrics() {
        let results = vec![
            make_result("a", 1.0),
            make_result("b", 0.8),
            make_result("c", 0.5),
        ];
        let judgments = vec![
            make_judgment("a", 3),
            make_judgment("b", 2),
            make_judgment("c", 1),
        ];
        let report = evaluate_relevance(&results, &judgments);
        assert!(report.ndcg_5 > 0.0);
        assert!(report.ndcg_10 > 0.0);
        assert!(report.mrr > 0.0);
        assert!(report.precision_5 > 0.0);
        assert!(report.recall_10 > 0.0);
    }

    #[test]
    fn evaluate_relevance_empty_returns_zeros() {
        let report = evaluate_relevance(&[], &[]);
        assert_eq!(report.ndcg_5, 0.0);
        assert_eq!(report.ndcg_10, 0.0);
        assert_eq!(report.mrr, 0.0);
        assert_eq!(report.precision_5, 0.0);
        assert_eq!(report.precision_10, 0.0);
        assert_eq!(report.recall_10, 0.0);
    }

    #[test]
    fn unknown_result_ids_treated_as_grade_zero() {
        let results = vec![make_result("unknown", 1.0)];
        let judgments = vec![make_judgment("a", 3)];
        assert_eq!(ndcg_at_k(&results, &judgments, 1), 0.0);
        assert_eq!(mrr(&results, &judgments), 0.0);
    }
}
