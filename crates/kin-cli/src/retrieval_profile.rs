// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Versioned retrieval quality profiles.
//!
//! A profile supplies the DEFAULT for each retrieval quality lever; an explicit
//! `KIN_LOCATE_*` / `KIN_SEMLOC_*` env var always wins over the profile default.
//! Profiles are versioned so a proof run can pin exact serving behavior with a
//! single value (`KIN_PROFILE=accuracy-v1`) instead of juggling individual
//! lever exports, and so future lever flips land as a new version rather than
//! silently changing what an existing pin means.
//!
//! - `compat-v0` (default): byte-identical to the pre-profile serving
//!   behavior. The MCP `semantic_locate` tool keeps the single-vector cosine
//!   ranking, and every lever keeps its historical default. It is the default
//!   because a paired A/B on the frozen multi-file diagnostic measured the
//!   accuracy-v1 candidate REGRESSING the CLI agent arm on every localization
//!   metric; accuracy-v1 stays opt-in until its levers are tuned and graduate
//!   on measurement.
//! - `accuracy-v1` (opt-in): the candidate serving shape. The MCP
//!   `semantic_locate` tool routes through the full fused locate pipeline,
//!   entity-granularity fusion and the lexical parity floor are on, the
//!   cross-encoder reranker runs in promotion-only blend mode under a latency
//!   budget when its model is already cached locally, and the embedding
//!   seed floor actually rejects near-orthogonal noise.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

/// Set once by the daemon's serving entrypoint. The cross-encoder's
/// profile-driven default only applies in a live daemon process: a resident
/// server amortizes model residency across queries, while one-shot library
/// callers (tests, tooling) must not pay — or nondeterministically trigger —
/// a model load unless they opt in explicitly via env.
static DAEMON_SERVING: AtomicBool = AtomicBool::new(false);

/// Mark this process as a resident daemon serving retrieval queries.
pub fn mark_daemon_serving() {
    DAEMON_SERVING.store(true, Ordering::Relaxed);
}

/// True when this process declared itself a resident serving daemon.
pub fn daemon_serving() -> bool {
    DAEMON_SERVING.load(Ordering::Relaxed)
}

/// Reset the daemon-serving mark. Test-only: the flag is process-global and
/// tests covering both sides of the gate share one process.
#[doc(hidden)]
pub fn reset_daemon_serving_for_tests() {
    DAEMON_SERVING.store(false, Ordering::Relaxed);
}

/// Versioned retrieval quality profile. Selected via `KIN_PROFILE`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetrievalProfile {
    /// Measured-accuracy defaults (current version).
    AccuracyV1,
    /// Pre-profile behavior: cosine-only `semantic_locate`, historical lever
    /// defaults. Kept for A/B comparison and as an escape hatch.
    CompatV0,
}

impl RetrievalProfile {
    /// Resolve the active profile from `KIN_PROFILE`.
    ///
    /// Accepts the canonical versioned names (`accuracy-v1`, `compat-v0`) plus
    /// unversioned aliases (`accuracy`, `compat`, `legacy`) that track the
    /// latest version of each family. Unknown values warn loudly and fall back
    /// to the default so a typo cannot silently select an unintended serving
    /// shape without a trace.
    pub fn from_env() -> Self {
        match std::env::var("KIN_PROFILE") {
            Ok(value) => {
                let normalized = value.trim().to_ascii_lowercase();
                match normalized.as_str() {
                    "" => Self::default(),
                    "accuracy-v1" | "accuracy" => Self::AccuracyV1,
                    "compat-v0" | "compat" | "legacy" => Self::CompatV0,
                    other => {
                        tracing::warn!(
                            profile = other,
                            "unknown KIN_PROFILE value; using default profile {}",
                            Self::default().name()
                        );
                        Self::default()
                    }
                }
            }
            Err(_) => Self::default(),
        }
    }

    /// Stable identifier recorded in explain output, daemon logs, and agent
    /// payloads so every result is attributable to the serving profile that
    /// produced it.
    pub fn name(self) -> &'static str {
        match self {
            Self::AccuracyV1 => "accuracy-v1",
            Self::CompatV0 => "compat-v0",
        }
    }

    /// Whether the MCP `semantic_locate` tool routes through the full fused
    /// locate pipeline (true) or the legacy single-vector cosine ranking
    /// (false).
    pub fn semantic_locate_fused(self) -> bool {
        matches!(self, Self::AccuracyV1)
    }

    /// Default for `KIN_LOCATE_ENTITY_FUSION` (fuse at entity granularity
    /// before collapsing to files).
    pub fn entity_fusion_default(self) -> bool {
        matches!(self, Self::AccuracyV1)
    }

    /// Default for `KIN_LOCATE_LEXICAL_FLOOR_READMIT` (readmit strong lexical
    /// candidates the fused ranking dropped, subsuming grep on keyword
    /// queries).
    pub fn lexical_floor_readmit_default(self) -> bool {
        matches!(self, Self::AccuracyV1)
    }

    /// Default for `KIN_LOCATE_CROSS_ENCODER_ENABLED`.
    ///
    /// Accuracy profile: on, but only when BOTH hold —
    /// - the reranker model is already cached locally (the constructor
    ///   otherwise downloads from the network, which a default must never do
    ///   mid-query), and
    /// - this process is a resident serving daemon (`mark_daemon_serving`),
    ///   so one-shot library callers and test binaries never pay a model load
    ///   by default.
    ///
    /// The missing-model state is reported as a structured degradation
    /// instead of silently skipping. An explicit
    /// `KIN_LOCATE_CROSS_ENCODER_ENABLED=1` still forces the attempt (and
    /// with it the download) regardless of cache state or process kind.
    pub fn cross_encoder_default(self, model_cached: bool) -> bool {
        match self {
            Self::AccuracyV1 => model_cached && daemon_serving(),
            Self::CompatV0 => false,
        }
    }

    /// Default for `KIN_LOCATE_RERANK_BLEND`: promotion-only additive blending
    /// of cross-encoder scores. The legacy overwrite mode substitutes raw
    /// logits for fused scores and can evict multi-signal-corroborated files,
    /// so any profile that enables the cross-encoder must also default to the
    /// blend.
    pub fn rerank_blend_default(self) -> bool {
        matches!(self, Self::AccuracyV1)
    }

    /// Default for `KIN_LOCATE_RERANK_LATENCY_BUDGET_MS`. The accuracy profile
    /// bounds the reranker so an over-budget rerank falls back to the fused
    /// order; compat keeps the historical unbounded behavior (0).
    pub fn rerank_latency_budget_ms_default(self) -> usize {
        match self {
            Self::AccuracyV1 => 1_500,
            Self::CompatV0 => 0,
        }
    }

    /// Default for `KIN_LOCATE_EMBEDDING_MIN_SIMILARITY`, in RELEVANCE units.
    ///
    /// The embedding seed floor compares against `relevance = (1 + cos) / 2`,
    /// not raw cosine. The historical default of 0.25 therefore only rejects
    /// cosine < -0.5 — near-orthogonal noise (cos ≈ 0) passes straight into
    /// the seed pool at full signal weight. The documented intent is to drop
    /// cosine < 0.25, which in relevance units is (1 + 0.25) / 2 = 0.625.
    pub fn embedding_min_relevance_default(self) -> f32 {
        match self {
            Self::AccuracyV1 => 0.625,
            Self::CompatV0 => 0.25,
        }
    }
}

impl Default for RetrievalProfile {
    fn default() -> Self {
        Self::CompatV0
    }
}

/// Convert a raw embedding cosine similarity to the relevance scale the
/// embedding seed floor is expressed in (`(1 + cos) / 2`). Single source for
/// the unit remap so the floor default and its tests cannot drift apart.
pub fn cosine_to_relevance(cosine: f32) -> f32 {
    ((1.0 + cosine) / 2.0).max(0.0)
}

/// True when the cross-encoder model is already present in the local
/// Hugging Face hub cache, so constructing it cannot trigger a network
/// download. Mirrors the `hf-hub` cache layout (`$HF_HOME` or
/// `~/.cache/huggingface`, `hub/models--{org}--{name}`) without taking the
/// dependency; a false negative merely means the reranker stays off by
/// default until the model is fetched explicitly.
pub fn cross_encoder_model_cached(model_id: &str) -> bool {
    let base = std::env::var_os("HF_HOME").map(PathBuf::from).or_else(|| {
        std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache/huggingface"))
    });
    let Some(base) = base else {
        return false;
    };
    let model_dir = base
        .join("hub")
        .join(format!("models--{}", model_id.replace('/', "--")));
    // A usable cache entry has at least one resolved snapshot directory.
    let snapshots = model_dir.join("snapshots");
    match std::fs::read_dir(&snapshots) {
        Ok(mut entries) => entries.any(|entry| entry.is_ok()),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[serial_test::serial]
    fn profile_resolves_from_env_with_aliases_and_default() {
        std::env::remove_var("KIN_PROFILE");
        assert_eq!(RetrievalProfile::from_env(), RetrievalProfile::CompatV0);

        std::env::set_var("KIN_PROFILE", "compat-v0");
        assert_eq!(RetrievalProfile::from_env(), RetrievalProfile::CompatV0);

        std::env::set_var("KIN_PROFILE", "compat");
        assert_eq!(RetrievalProfile::from_env(), RetrievalProfile::CompatV0);

        std::env::set_var("KIN_PROFILE", "ACCURACY-V1");
        assert_eq!(RetrievalProfile::from_env(), RetrievalProfile::AccuracyV1);

        // Unknown values must not silently select a different serving shape.
        std::env::set_var("KIN_PROFILE", "warp-speed");
        assert_eq!(RetrievalProfile::from_env(), RetrievalProfile::CompatV0);

        std::env::remove_var("KIN_PROFILE");
    }

    #[test]
    fn accuracy_profile_floor_rejects_near_orthogonal_noise() {
        let accuracy = RetrievalProfile::AccuracyV1.embedding_min_relevance_default();
        let compat = RetrievalProfile::CompatV0.embedding_min_relevance_default();

        // cos ≈ 0 (orthogonal, i.e. unrelated content) must be rejected by the
        // accuracy floor. The historical floor admitted it — that is the
        // mis-scaling this default fixes.
        let orthogonal = cosine_to_relevance(0.0);
        assert!(
            orthogonal < accuracy,
            "cos=0 noise must fall below the floor"
        );
        assert!(
            orthogonal >= compat,
            "compat keeps the historical (mis-scaled) admit behavior"
        );

        // The documented intent: cosine below 0.25 is noise, at-or-above 0.25
        // is signal. The accuracy floor is exactly that boundary.
        assert!(cosine_to_relevance(0.24) < accuracy);
        assert!(cosine_to_relevance(0.25) >= accuracy);

        // Sanity on the remap itself.
        assert_eq!(cosine_to_relevance(1.0), 1.0);
        assert_eq!(cosine_to_relevance(-1.0), 0.0);
    }

    #[test]
    fn compat_profile_preserves_historical_defaults() {
        let compat = RetrievalProfile::CompatV0;
        assert!(!compat.semantic_locate_fused());
        assert!(!compat.entity_fusion_default());
        assert!(!compat.lexical_floor_readmit_default());
        assert!(!compat.cross_encoder_default(true));
        assert!(!compat.rerank_blend_default());
        assert_eq!(compat.rerank_latency_budget_ms_default(), 0);
        assert_eq!(compat.embedding_min_relevance_default(), 0.25);
    }

    #[test]
    #[serial_test::serial]
    fn accuracy_profile_gates_cross_encoder_on_cached_model_and_daemon_context() {
        let accuracy = RetrievalProfile::AccuracyV1;

        // Outside a serving daemon the default never turns the reranker on,
        // cached model or not — a test binary or one-shot library caller must
        // not pay a model load without an explicit env opt-in.
        reset_daemon_serving_for_tests();
        assert!(!accuracy.cross_encoder_default(true));
        assert!(!accuracy.cross_encoder_default(false));

        mark_daemon_serving();
        assert!(accuracy.cross_encoder_default(true));
        assert!(
            !accuracy.cross_encoder_default(false),
            "an unset default must never trigger a mid-query model download"
        );
        reset_daemon_serving_for_tests();
    }
}
