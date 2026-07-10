// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Per-query result sizing over a rank-ordered fused score vector.
//!
//! `kin locate` fuses several retrieval signals into one score per file, sorted
//! highest first. How many of those files to declare is a precision/recall
//! trade: a fixed cap over-declares on a decisive query and under-declares on an
//! ambiguous one. The fused score distribution carries the signal — a confident
//! query separates a small head from the rest with a sharp score drop (a
//! "knee"), while an ambiguous query decays smoothly with no clean break.
//!
//! This module turns that observation into a pure, deterministic sizing
//! function. The knee position is corpus- and query-dependent — one corpus
//! separates its head at rank ~10, another decays flat — so the cut is computed
//! per query from the actual score vector rather than pinned to a global
//! constant. When no decisive knee exists the sizing declines to cut and the
//! caller keeps its incumbent size, so a flat tail is never truncated on a weak
//! signal (recall-safe).
//!
//! [`score_gap_ratio`] is the shared gap primitive: the relative separation of
//! an adjacent rank pair. Both the knee detector here and the declaration cutoff
//! in `locate.rs` measure a gap the same way, so the two suffix trims stay
//! consistent instead of encoding two different notions of "separated".

/// Relative separation of an adjacent, sorted-descending rank pair
/// (`cur >= next`), used to locate the sharpest drop in a score vector.
///
/// Returns `cur / next`: a value at or near `1.0` is a flat, tied step, while a
/// large value is a sharp drop. A non-positive `next` is treated as an infinite
/// separation — a zero/negative-scored file is never a real declaration, so the
/// boundary just above it is a maximal knee. A non-positive `cur` (which, in a
/// descending list, forces `next <= 0` too, but is guarded independently)
/// yields `1.0`: no positive-scored head remains to separate from.
pub fn score_gap_ratio(cur: f32, next: f32) -> f32 {
    if next <= 0.0 {
        return f32::INFINITY;
    }
    if cur <= 0.0 {
        return 1.0;
    }
    cur / next
}

/// Knee-detecting dynamic result size over a rank-ordered fused score vector
/// (`scores`, highest confidence first).
///
/// Returns `Some(k)` — keep the leading `k` results — when the sharpest relative
/// score drop whose kept prefix falls in the `[k_min, k_max]` window is a
/// decisive separation (its [`score_gap_ratio`] exceeds `gap_min`). Returns
/// `None` when the window holds no decisive knee — a flat, score-tied tail — so
/// the caller keeps its incumbent size. `None` is the recall-safe outcome: the
/// sizing only ever cuts on a clear break, never on a weak one.
///
/// Bounds and clamping:
/// * `k_min` is clamped up to `1` (a keep of zero is never returned) and is the
///   smallest prefix that may be kept.
/// * `k_max` is clamped down to the last internal boundary (`scores.len() - 1`)
///   and up to `k_min`, so the window is always non-empty and in range.
/// * A list no longer than the floor, or a `gap_min` that is not a finite value
///   above `1.0` (a ratio of one would fire on any strictly-decreasing pair,
///   which is not a *separation*), disables the cut and returns `None`.
///
/// Determinism: a pure function of `scores`. Boundaries are scanned low to high
/// and ties in the relative gap keep the earliest (smallest-`k`, higher
/// precision) boundary. The result only ever selects a leading prefix; the list
/// order is never changed.
pub fn dynamic_k_len(scores: &[f32], k_min: usize, k_max: usize, gap_min: f32) -> Option<usize> {
    let n = scores.len();
    let floor = k_min.max(1);
    if n <= floor || !gap_min.is_finite() || gap_min <= 1.0 {
        return None;
    }
    // `n > floor >= 1` guarantees `n >= 2`, so `n - 1 >= floor` and the window
    // `[floor, ceiling]` is a non-empty range of internal boundaries. Boundary
    // `b` keeps `b` results and cuts between index `b - 1` and `b`.
    let ceiling = k_max.max(floor).min(n - 1);
    let mut best_k = 0usize;
    let mut best_ratio = f32::NEG_INFINITY;
    for b in floor..=ceiling {
        let ratio = score_gap_ratio(scores[b - 1], scores[b]);
        if ratio > best_ratio {
            best_ratio = ratio;
            best_k = b;
        }
    }
    if best_k > 0 && best_ratio > gap_min {
        Some(best_k)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn score_gap_ratio_plain_ratio_for_positive_pair() {
        assert_eq!(score_gap_ratio(10.0, 2.0), 5.0);
        assert_eq!(score_gap_ratio(3.0, 3.0), 1.0);
    }

    #[test]
    fn score_gap_ratio_nonpositive_next_is_infinite() {
        assert_eq!(score_gap_ratio(1.0, 0.0), f32::INFINITY);
        assert_eq!(score_gap_ratio(1.0, -0.5), f32::INFINITY);
    }

    #[test]
    fn score_gap_ratio_nonpositive_cur_has_no_head_to_separate() {
        // A non-positive current score means no positive head remains; report a
        // flat step so it is never chosen as a knee.
        assert_eq!(score_gap_ratio(0.0, 5.0), 1.0);
        assert_eq!(score_gap_ratio(-1.0, 5.0), 1.0);
    }

    #[test]
    fn sharp_knee_cuts_at_the_drop() {
        // Three confident files, then a tied tail: the knee is after rank 3.
        let scores = [9.0, 8.5, 8.0, 0.4, 0.39, 0.38, 0.37];
        assert_eq!(dynamic_k_len(&scores, 1, 20, 2.0), Some(3));
    }

    #[test]
    fn flat_tail_declines_to_cut() {
        // A smoothly decaying, score-tied list has no decisive knee: fall back to
        // the incumbent size (None), never an aggressive cut.
        let scores = [1.00, 0.99, 0.985, 0.98, 0.976, 0.97, 0.965];
        assert_eq!(dynamic_k_len(&scores, 1, 20, 2.0), None);
    }

    #[test]
    fn largest_gap_wins_within_window() {
        // Two drops: 2x after rank 2 and 4x after rank 4. The sharper (4x) wins
        // even though the 2x break comes first.
        let scores = [10.0, 9.0, 4.5, 4.0, 1.0, 0.9];
        assert_eq!(dynamic_k_len(&scores, 1, 20, 1.5), Some(4));
    }

    #[test]
    fn tie_in_gap_keeps_the_earliest_boundary() {
        // Identical 3x drops after rank 1 and rank 2: the earliest (higher
        // precision) boundary wins deterministically.
        let scores = [9.0, 3.0, 1.0, 0.9, 0.8];
        assert_eq!(dynamic_k_len(&scores, 1, 20, 2.0), Some(1));
    }

    #[test]
    fn k_min_floor_protects_the_head() {
        // The sharpest drop is after rank 1, but k_min=3 forbids cutting that
        // shallow; the next in-window knee (after rank 3) is taken instead.
        let scores = [50.0, 5.0, 4.8, 0.2, 0.19];
        assert_eq!(dynamic_k_len(&scores, 3, 20, 2.0), Some(3));
    }

    #[test]
    fn k_max_ceiling_bounds_the_search() {
        // The only decisive drop sits after rank 5, past a k_max of 3: no
        // in-window knee, so no cut.
        let scores = [1.0, 0.99, 0.98, 0.97, 0.96, 0.1, 0.09];
        assert_eq!(dynamic_k_len(&scores, 1, 3, 2.0), None);
    }

    #[test]
    fn k_max_past_end_clamps_to_last_boundary() {
        let scores = [9.0, 8.0, 7.0, 0.1];
        // k_max far past the end still finds the tail knee after rank 3.
        assert_eq!(dynamic_k_len(&scores, 1, 999, 2.0), Some(3));
    }

    #[test]
    fn short_list_at_or_below_floor_never_cuts() {
        assert_eq!(dynamic_k_len(&[], 1, 20, 2.0), None);
        assert_eq!(dynamic_k_len(&[5.0], 1, 20, 2.0), None);
        assert_eq!(dynamic_k_len(&[9.0, 0.1], 3, 20, 2.0), None);
    }

    #[test]
    fn disabled_or_degenerate_threshold_never_cuts() {
        let scores = [9.0, 0.1, 0.09, 0.08];
        assert_eq!(dynamic_k_len(&scores, 1, 20, 1.0), None);
        assert_eq!(dynamic_k_len(&scores, 1, 20, 0.5), None);
        assert_eq!(dynamic_k_len(&scores, 1, 20, f32::NAN), None);
        assert_eq!(dynamic_k_len(&scores, 1, 20, f32::INFINITY), None);
    }

    #[test]
    fn zero_scored_tail_is_a_maximal_knee() {
        // A file scoring exactly zero (or below) is never a real declaration:
        // the boundary just above it is an infinite-separation knee.
        let scores = [4.0, 3.5, 0.0, 0.0];
        assert_eq!(dynamic_k_len(&scores, 1, 20, 2.0), Some(2));
    }

    #[test]
    fn deterministic_across_repeated_calls() {
        let scores = [9.0, 8.5, 8.0, 0.4, 0.39, 0.38];
        let first = dynamic_k_len(&scores, 2, 20, 2.0);
        for _ in 0..64 {
            assert_eq!(dynamic_k_len(&scores, 2, 20, 2.0), first);
        }
    }
}
