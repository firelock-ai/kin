// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Gradient-boosted tree ensemble for learning-to-rank in the locate pipeline.
//!
//! Provides a pure-Rust CART-style gradient boosting implementation that can
//! train on [`crate::features::TrainingExample`]s and rerank candidates by
//! predicted relevance score.

use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::features::{LocateFeatureVector, TrainingExample};

/// A single decision tree node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TreeNode {
    Leaf {
        value: f32,
    },
    Split {
        feature_index: usize,
        threshold: f32,
        left: Box<TreeNode>,
        right: Box<TreeNode>,
    },
}

/// Gradient-boosted tree ensemble for learning-to-rank.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GradientBoostedRanker {
    pub trees: Vec<TreeNode>,
    pub learning_rate: f32,
    pub base_score: f32,
}

impl GradientBoostedRanker {
    /// Load a trained model from JSON.
    pub fn load(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let data = std::fs::read_to_string(path)?;
        let model: Self = serde_json::from_str(&data)?;
        Ok(model)
    }

    /// Save model to JSON.
    pub fn save(&self, path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let json = serde_json::to_string_pretty(self)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// Score a single candidate.
    pub fn predict(&self, features: &LocateFeatureVector) -> f32 {
        let arr = features.to_array();
        let mut score = self.base_score;
        for tree in &self.trees {
            score += self.learning_rate * tree_predict(tree, &arr);
        }
        score
    }

    /// Rerank candidates by LTR score.
    ///
    /// Each tuple is `(file_path, score, features)`. After reranking the score
    /// field is replaced with the LTR prediction and the vec is sorted
    /// descending.
    pub fn rerank(&self, candidates: &mut [(String, f32, LocateFeatureVector)]) {
        for (_, score, features) in candidates.iter_mut() {
            *score = self.predict(features);
        }
        candidates.sort_by(|a, b| {
            b.1.partial_cmp(&a.1)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| a.0.cmp(&b.0))
        });
    }

    /// Train a new model from labelled examples using gradient boosting.
    ///
    /// * `max_depth` — tree depth (3–5 typical)
    /// * `n_trees` — number of boosting rounds (50–200)
    /// * `learning_rate` — shrinkage factor (0.1 typical)
    pub fn train(
        examples: &[TrainingExample],
        max_depth: usize,
        n_trees: usize,
        learning_rate: f32,
    ) -> Self {
        let n = examples.len();
        if n == 0 {
            return Self {
                trees: Vec::new(),
                learning_rate,
                base_score: 0.0,
            };
        }

        // Materialise feature arrays and labels.
        let feature_arrays: Vec<[f32; LocateFeatureVector::FEATURE_COUNT]> =
            examples.iter().map(|e| e.features.to_array()).collect();
        let labels: Vec<f32> = examples.iter().map(|e| e.label).collect();

        // Initial base score: log-odds of the positive rate.
        let pos_count = labels.iter().filter(|&&l| l > 0.5).count() as f32;
        let neg_count = n as f32 - pos_count;
        let base_score = if pos_count > 0.0 && neg_count > 0.0 {
            (pos_count / neg_count).ln()
        } else {
            0.0
        };

        let mut predictions = vec![base_score; n];
        let mut trees = Vec::with_capacity(n_trees);

        for _ in 0..n_trees {
            // Compute residuals: label - sigmoid(prediction).
            let residuals: Vec<f32> = predictions
                .iter()
                .zip(labels.iter())
                .map(|(&pred, &label)| label - sigmoid(pred))
                .collect();

            // Fit a tree to the residuals.
            let indices: Vec<usize> = (0..n).collect();
            let tree = build_tree(&feature_arrays, &residuals, &indices, 0, max_depth);

            // Update predictions.
            for (i, arr) in feature_arrays.iter().enumerate() {
                predictions[i] += learning_rate * tree_predict(&tree, arr);
            }

            trees.push(tree);
        }

        Self {
            trees,
            learning_rate,
            base_score,
        }
    }
}

fn sigmoid(x: f32) -> f32 {
    1.0 / (1.0 + (-x).exp())
}

fn tree_predict(node: &TreeNode, features: &[f32]) -> f32 {
    match node {
        TreeNode::Leaf { value } => *value,
        TreeNode::Split {
            feature_index,
            threshold,
            left,
            right,
        } => {
            if features[*feature_index] <= *threshold {
                tree_predict(left, features)
            } else {
                tree_predict(right, features)
            }
        }
    }
}

/// Build a CART regression tree on `residuals` using greedy MSE splits.
fn build_tree(
    features: &[[f32; LocateFeatureVector::FEATURE_COUNT]],
    residuals: &[f32],
    indices: &[usize],
    depth: usize,
    max_depth: usize,
) -> TreeNode {
    // Leaf conditions: max depth reached or too few samples.
    if depth >= max_depth || indices.len() <= 1 {
        return TreeNode::Leaf {
            value: leaf_value(residuals, indices),
        };
    }

    let (best_feature, best_threshold, best_mse) = find_best_split(features, residuals, indices);

    // No useful split found.
    if best_mse.is_nan() || best_feature >= LocateFeatureVector::FEATURE_COUNT {
        return TreeNode::Leaf {
            value: leaf_value(residuals, indices),
        };
    }

    let (left_idx, right_idx): (Vec<usize>, Vec<usize>) = indices
        .iter()
        .partition(|&&i| features[i][best_feature] <= best_threshold);

    // If the split produces an empty side, return a leaf.
    if left_idx.is_empty() || right_idx.is_empty() {
        return TreeNode::Leaf {
            value: leaf_value(residuals, indices),
        };
    }

    let left = build_tree(features, residuals, &left_idx, depth + 1, max_depth);
    let right = build_tree(features, residuals, &right_idx, depth + 1, max_depth);

    TreeNode::Split {
        feature_index: best_feature,
        threshold: best_threshold,
        left: Box::new(left),
        right: Box::new(right),
    }
}

/// Mean residual — the optimal constant prediction for a leaf.
fn leaf_value(residuals: &[f32], indices: &[usize]) -> f32 {
    if indices.is_empty() {
        return 0.0;
    }
    let sum: f32 = indices.iter().map(|&i| residuals[i]).sum();
    sum / indices.len() as f32
}

/// Find the best (feature, threshold) split that minimises weighted MSE.
///
/// For each feature we try up to 10 quantile thresholds computed from the
/// values present in `indices`.
fn find_best_split(
    features: &[[f32; LocateFeatureVector::FEATURE_COUNT]],
    residuals: &[f32],
    indices: &[usize],
) -> (usize, f32, f32) {
    let n = indices.len();
    let mut best_feature = LocateFeatureVector::FEATURE_COUNT; // sentinel
    let mut best_threshold = 0.0_f32;
    let mut best_mse = f32::INFINITY;

    let total_sum: f32 = indices.iter().map(|&i| residuals[i]).sum();

    for feat in 0..LocateFeatureVector::FEATURE_COUNT {
        // Collect and sort feature values.
        let mut vals: Vec<(f32, usize)> = indices.iter().map(|&i| (features[i][feat], i)).collect();
        vals.sort_by(|a, b| a.0.total_cmp(&b.0));

        // Skip constant features.
        if vals.first().map(|v| v.0) == vals.last().map(|v| v.0) {
            continue;
        }

        // Try up to 10 quantile thresholds.
        let n_thresholds = 10.min(n - 1);
        let mut tried_thresholds = Vec::with_capacity(n_thresholds);

        for t in 1..=n_thresholds {
            let idx = t * n / (n_thresholds + 1);
            if idx == 0 || idx >= n {
                continue;
            }
            let threshold = (vals[idx - 1].0 + vals[idx].0) / 2.0;

            // Deduplicate thresholds.
            if tried_thresholds
                .iter()
                .any(|&prev: &f32| (prev - threshold).abs() < 1e-9)
            {
                continue;
            }
            tried_thresholds.push(threshold);

            // Compute MSE for this split using the sorted order.
            let mut left_sum = 0.0_f32;
            let mut left_count = 0_usize;
            for &(val, sample_idx) in &vals {
                if val <= threshold {
                    left_sum += residuals[sample_idx];
                    left_count += 1;
                } else {
                    break;
                }
            }
            let right_count = n - left_count;
            if left_count == 0 || right_count == 0 {
                continue;
            }

            let right_sum = total_sum - left_sum;
            let left_mean = left_sum / left_count as f32;
            let right_mean = right_sum / right_count as f32;

            // Weighted MSE reduction: we minimise the total MSE after split.
            // MSE_left = sum((r - left_mean)^2) / n  (weighted by left_count/n)
            // Rather than computing full MSE, we use the variance-reduction
            // criterion: -left_count * left_mean^2 - right_count * right_mean^2
            // (negated because we want to maximise reduction).
            let mse = -(left_count as f32 * left_mean * left_mean
                + right_count as f32 * right_mean * right_mean);

            if mse < best_mse {
                best_mse = mse;
                best_feature = feat;
                best_threshold = threshold;
            }
        }
    }

    (best_feature, best_threshold, best_mse)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::features::LocateFeatureVector;

    fn make_example(score: f32, label: f32) -> TrainingExample {
        let mut fv = LocateFeatureVector::zeros();
        fv.search_score = score;
        fv.search_present = if score > 0.0 { 1.0 } else { 0.0 };
        fv.signal_count = if score > 0.0 { 1.0 } else { 0.0 };
        TrainingExample {
            task_id: "t".into(),
            file_path: "f".into(),
            features: fv,
            label,
        }
    }

    #[test]
    fn predict_leaf_only() {
        let ranker = GradientBoostedRanker {
            trees: vec![TreeNode::Leaf { value: 0.5 }],
            learning_rate: 1.0,
            base_score: 0.0,
        };
        let fv = LocateFeatureVector::zeros();
        assert!((ranker.predict(&fv) - 0.5).abs() < 1e-5);
    }

    #[test]
    fn predict_single_split() {
        let ranker = GradientBoostedRanker {
            trees: vec![TreeNode::Split {
                feature_index: 1, // search_score
                threshold: 0.5,
                left: Box::new(TreeNode::Leaf { value: -1.0 }),
                right: Box::new(TreeNode::Leaf { value: 1.0 }),
            }],
            learning_rate: 1.0,
            base_score: 0.0,
        };

        let mut low = LocateFeatureVector::zeros();
        low.search_score = 0.3;
        assert!((ranker.predict(&low) - (-1.0)).abs() < 1e-5);

        let mut high = LocateFeatureVector::zeros();
        high.search_score = 0.8;
        assert!((ranker.predict(&high) - 1.0).abs() < 1e-5);
    }

    #[test]
    fn learning_rate_scales_predictions() {
        let ranker = GradientBoostedRanker {
            trees: vec![TreeNode::Leaf { value: 2.0 }],
            learning_rate: 0.1,
            base_score: 1.0,
        };
        let fv = LocateFeatureVector::zeros();
        // 1.0 + 0.1 * 2.0 = 1.2
        assert!((ranker.predict(&fv) - 1.2).abs() < 1e-5);
    }

    #[test]
    fn rerank_sorts_descending() {
        let ranker = GradientBoostedRanker {
            trees: vec![TreeNode::Split {
                feature_index: 1,
                threshold: 0.5,
                left: Box::new(TreeNode::Leaf { value: -1.0 }),
                right: Box::new(TreeNode::Leaf { value: 1.0 }),
            }],
            learning_rate: 1.0,
            base_score: 0.0,
        };

        let mut low = LocateFeatureVector::zeros();
        low.search_score = 0.2;
        let mut high = LocateFeatureVector::zeros();
        high.search_score = 0.9;

        let mut candidates = vec![("low.rs".into(), 0.0, low), ("high.rs".into(), 0.0, high)];

        ranker.rerank(&mut candidates);
        assert_eq!(candidates[0].0, "high.rs");
        assert_eq!(candidates[1].0, "low.rs");
    }

    #[test]
    fn train_empty_returns_no_trees() {
        let ranker = GradientBoostedRanker::train(&[], 3, 10, 0.1);
        assert!(ranker.trees.is_empty());
        assert_eq!(ranker.base_score, 0.0);
    }

    #[test]
    fn train_separable_data_learns_ranking() {
        // Create clearly separable data: high search_score → label 1, low → label 0.
        let mut examples = Vec::new();
        for i in 0..20 {
            let score = i as f32 / 20.0;
            let label = if score > 0.5 { 1.0 } else { 0.0 };
            examples.push(make_example(score, label));
        }

        let ranker = GradientBoostedRanker::train(&examples, 3, 50, 0.1);

        // High-score candidate should get a higher prediction than low-score.
        let high_pred = ranker.predict(&make_example(0.9, 0.0).features);
        let low_pred = ranker.predict(&make_example(0.1, 0.0).features);
        assert!(
            high_pred > low_pred,
            "Expected high ({high_pred}) > low ({low_pred})"
        );
    }

    #[test]
    fn train_produces_expected_tree_count() {
        let examples = vec![make_example(0.8, 1.0), make_example(0.2, 0.0)];
        let ranker = GradientBoostedRanker::train(&examples, 2, 10, 0.1);
        assert_eq!(ranker.trees.len(), 10);
    }

    #[test]
    fn serde_roundtrip() {
        let ranker = GradientBoostedRanker {
            trees: vec![
                TreeNode::Split {
                    feature_index: 0,
                    threshold: 0.5,
                    left: Box::new(TreeNode::Leaf { value: -0.3 }),
                    right: Box::new(TreeNode::Leaf { value: 0.7 }),
                },
                TreeNode::Leaf { value: 0.1 },
            ],
            learning_rate: 0.1,
            base_score: 0.0,
        };

        let json = serde_json::to_string(&ranker).unwrap();
        let restored: GradientBoostedRanker = serde_json::from_str(&json).unwrap();

        let fv = LocateFeatureVector::zeros();
        assert!((ranker.predict(&fv) - restored.predict(&fv)).abs() < 1e-7);
    }

    #[test]
    fn save_and_load_roundtrip() {
        let ranker = GradientBoostedRanker {
            trees: vec![TreeNode::Leaf { value: 0.42 }],
            learning_rate: 0.1,
            base_score: 0.5,
        };

        let dir = std::env::temp_dir().join("kin_ltr_test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("model.json");

        ranker.save(&path).unwrap();
        let loaded = GradientBoostedRanker::load(&path).unwrap();

        assert_eq!(loaded.trees.len(), 1);
        assert!((loaded.base_score - 0.5).abs() < 1e-7);
        assert!((loaded.learning_rate - 0.1).abs() < 1e-7);

        // Cleanup.
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sigmoid_boundaries() {
        assert!((sigmoid(0.0) - 0.5).abs() < 1e-5);
        assert!(sigmoid(10.0) > 0.99);
        assert!(sigmoid(-10.0) < 0.01);
    }
}
