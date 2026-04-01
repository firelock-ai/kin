// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Feature vector definitions for the learning-to-rank pipeline.
//!
//! [`LocateFeatureVector`] captures the 33-dimensional feature space used by
//! [`crate::ltr::GradientBoostedRanker`] to rerank locate-pipeline candidates.

use serde::{Deserialize, Serialize};

/// Feature vector for a single candidate file in the locate pipeline.
/// Each feature is an `f32` that the LTR model can use for ranking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocateFeatureVector {
    // -- Per-signal RRF scores (10 features) --
    pub traceback_score: f32,
    pub search_score: f32,
    pub multihop_score: f32,
    pub test_score: f32,
    pub snippet_score: f32,
    pub import_score: f32,
    pub error_score: f32,
    pub embedding_score: f32,
    pub cochange_score: f32,
    pub projection_score: f32,

    // -- Signal presence (10 features) --
    pub traceback_present: f32,
    pub search_present: f32,
    pub multihop_present: f32,
    pub test_present: f32,
    pub snippet_present: f32,
    pub import_present: f32,
    pub error_present: f32,
    pub embedding_present: f32,
    pub cochange_present: f32,
    pub projection_present: f32,

    // -- Aggregate features --
    pub signal_count: f32,
    pub fused_rrf_score: f32,
    pub rrf_rank: f32,

    // -- File features --
    pub path_depth: f32,
    pub is_test: f32,
    pub is_source: f32,
    pub is_external: f32,
    pub file_tier: f32,

    // -- Query features --
    pub query_term_count: f32,
    pub query_has_traceback: f32,
    pub query_has_path: f32,
    pub query_length: f32,
}

impl LocateFeatureVector {
    pub const FEATURE_COUNT: usize = 32;

    const NAMES: [&'static str; Self::FEATURE_COUNT] = [
        "traceback_score",
        "search_score",
        "multihop_score",
        "test_score",
        "snippet_score",
        "import_score",
        "error_score",
        "embedding_score",
        "cochange_score",
        "projection_score",
        "traceback_present",
        "search_present",
        "multihop_present",
        "test_present",
        "snippet_present",
        "import_present",
        "error_present",
        "embedding_present",
        "cochange_present",
        "projection_present",
        "signal_count",
        "fused_rrf_score",
        "rrf_rank",
        "path_depth",
        "is_test",
        "is_source",
        "is_external",
        "file_tier",
        "query_term_count",
        "query_has_traceback",
        "query_has_path",
        "query_length",
    ];

    /// Convert to a flat `f32` array for model input.
    pub fn to_array(&self) -> [f32; Self::FEATURE_COUNT] {
        [
            self.traceback_score,
            self.search_score,
            self.multihop_score,
            self.test_score,
            self.snippet_score,
            self.import_score,
            self.error_score,
            self.embedding_score,
            self.cochange_score,
            self.projection_score,
            self.traceback_present,
            self.search_present,
            self.multihop_present,
            self.test_present,
            self.snippet_present,
            self.import_present,
            self.error_present,
            self.embedding_present,
            self.cochange_present,
            self.projection_present,
            self.signal_count,
            self.fused_rrf_score,
            self.rrf_rank,
            self.path_depth,
            self.is_test,
            self.is_source,
            self.is_external,
            self.file_tier,
            self.query_term_count,
            self.query_has_traceback,
            self.query_has_path,
            self.query_length,
        ]
    }

    /// Create from a flat `f32` array (model output parsing).
    pub fn from_array(arr: &[f32; Self::FEATURE_COUNT]) -> Self {
        Self {
            traceback_score: arr[0],
            search_score: arr[1],
            multihop_score: arr[2],
            test_score: arr[3],
            snippet_score: arr[4],
            import_score: arr[5],
            error_score: arr[6],
            embedding_score: arr[7],
            cochange_score: arr[8],
            projection_score: arr[9],
            traceback_present: arr[10],
            search_present: arr[11],
            multihop_present: arr[12],
            test_present: arr[13],
            snippet_present: arr[14],
            import_present: arr[15],
            error_present: arr[16],
            embedding_present: arr[17],
            cochange_present: arr[18],
            projection_present: arr[19],
            signal_count: arr[20],
            fused_rrf_score: arr[21],
            rrf_rank: arr[22],
            path_depth: arr[23],
            is_test: arr[24],
            is_source: arr[25],
            is_external: arr[26],
            file_tier: arr[27],
            query_term_count: arr[28],
            query_has_traceback: arr[29],
            query_has_path: arr[30],
            query_length: arr[31],
        }
    }

    /// Feature names for debugging/logging.
    pub fn feature_names() -> Vec<&'static str> {
        Self::NAMES.to_vec()
    }

    /// Return a zeroed feature vector.
    pub fn zeros() -> Self {
        Self::from_array(&[0.0; Self::FEATURE_COUNT])
    }
}

/// Training example: feature vector + binary label (1.0 = gold file, 0.0 = not gold).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingExample {
    pub task_id: String,
    pub file_path: String,
    pub features: LocateFeatureVector,
    pub label: f32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feature_count_matches_array_length() {
        let fv = LocateFeatureVector::zeros();
        let arr = fv.to_array();
        assert_eq!(arr.len(), LocateFeatureVector::FEATURE_COUNT);
    }

    #[test]
    fn roundtrip_array_conversion() {
        let mut arr = [0.0_f32; LocateFeatureVector::FEATURE_COUNT];
        for (i, v) in arr.iter_mut().enumerate() {
            *v = i as f32 * 0.1;
        }
        let fv = LocateFeatureVector::from_array(&arr);
        let back = fv.to_array();
        for (a, b) in arr.iter().zip(back.iter()) {
            assert!((a - b).abs() < 1e-7);
        }
    }

    #[test]
    fn feature_names_count() {
        let names = LocateFeatureVector::feature_names();
        assert_eq!(names.len(), LocateFeatureVector::FEATURE_COUNT);
    }

    #[test]
    fn feature_names_unique() {
        let names = LocateFeatureVector::feature_names();
        let mut deduped = names.clone();
        deduped.sort();
        deduped.dedup();
        assert_eq!(names.len(), deduped.len());
    }

    #[test]
    fn zeros_all_zero() {
        let fv = LocateFeatureVector::zeros();
        for v in fv.to_array() {
            assert_eq!(v, 0.0);
        }
    }

    #[test]
    fn serde_roundtrip() {
        let mut arr = [0.0_f32; LocateFeatureVector::FEATURE_COUNT];
        for (i, v) in arr.iter_mut().enumerate() {
            *v = (i as f32 + 1.0) / 100.0;
        }
        let fv = LocateFeatureVector::from_array(&arr);
        let json = serde_json::to_string(&fv).unwrap();
        let restored: LocateFeatureVector = serde_json::from_str(&json).unwrap();
        let orig = fv.to_array();
        let rest = restored.to_array();
        for (a, b) in orig.iter().zip(rest.iter()) {
            assert!((a - b).abs() < 1e-7);
        }
    }

    #[test]
    fn training_example_serde_roundtrip() {
        let ex = TrainingExample {
            task_id: "task-001".into(),
            file_path: "src/main.rs".into(),
            features: LocateFeatureVector::zeros(),
            label: 1.0,
        };
        let json = serde_json::to_string(&ex).unwrap();
        let restored: TrainingExample = serde_json::from_str(&json).unwrap();
        assert_eq!(restored.task_id, "task-001");
        assert_eq!(restored.label, 1.0);
    }
}
