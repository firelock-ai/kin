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
//! - `accuracy-v2` (default): the measured-accuracy serving shape.
//!   Entity-granularity fusion, the lexical parity floor, and the calibrated
//!   embedding seed floor are on; the cross-encoder reranker is off
//!   unconditionally. The reranker's standing do-not-flip verdict held when
//!   the accuracy levers graduated to default, so the flip minted this new
//!   version instead of editing `accuracy-v1` in place, and an existing
//!   `accuracy-v1` pin keeps the conditional reranker it always had.
//! - `accuracy-v1` (opt-in): the previous accuracy candidate. Same levers as
//!   `accuracy-v2` plus the cross-encoder reranker in promotion-only blend
//!   mode under a latency budget, when its model is already cached locally
//!   and the process is a resident daemon.
//! - `compat-v0` (opt-in): the historical lever defaults, kept for A/B
//!   comparison and as an escape hatch. It was the shipped default until the
//!   accuracy levers graduated on measurement: bare-name symbol lookup
//!   through MCP `semantic_locate` scored 0 of 23 at rank one under cosine
//!   serving against 20 of 23 under the fused pipeline.
//!
//! The MCP `semantic_locate` routing is not a profile lever: every profile
//! routes the full fused locate pipeline, exactly like `POST /locate` always
//! has, and the legacy cosine ranking stays reachable per call via
//! `pipeline: "cosine"`.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
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
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum RetrievalProfile {
    /// Measured-accuracy defaults (current version): the `accuracy-v1` lever
    /// set with the cross-encoder reranker off unconditionally.
    #[default]
    AccuracyV2,
    /// Previous accuracy candidate: `accuracy-v2` plus the conditional
    /// budget-gated cross-encoder. Kept addressable so an existing pin keeps
    /// meaning exactly what it meant.
    AccuracyV1,
    /// Historical lever defaults. Kept for A/B comparison and as an escape
    /// hatch.
    CompatV0,
}

impl RetrievalProfile {
    /// Resolve the active profile from `KIN_PROFILE`.
    ///
    /// Accepts the canonical versioned names (`accuracy-v2`, `accuracy-v1`,
    /// `compat-v0`) plus unversioned aliases (`accuracy`, `compat`, `legacy`)
    /// that track the latest version of each family. Unknown values warn
    /// loudly and fall back to the default so a typo cannot silently select an
    /// unintended serving shape without a trace.
    pub fn from_env() -> Self {
        match std::env::var("KIN_PROFILE") {
            Ok(value) => {
                let normalized = value.trim().to_ascii_lowercase();
                match normalized.as_str() {
                    "" => Self::default(),
                    "accuracy-v2" | "accuracy" => Self::AccuracyV2,
                    "accuracy-v1" => Self::AccuracyV1,
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
            Self::AccuracyV2 => "accuracy-v2",
            Self::AccuracyV1 => "accuracy-v1",
            Self::CompatV0 => "compat-v0",
        }
    }

    /// Whether the MCP `semantic_locate` tool routes through the full fused
    /// locate pipeline by default. True for every profile: routing is not a
    /// profile lever. The daemon's `semantic_locate` arm routes fused
    /// unconditionally, exactly like `POST /locate`, and the legacy cosine
    /// ranking stays reachable per call via `pipeline: "cosine"`. Kept as an
    /// accessor so health reporting reads one authority and a new variant has
    /// to state its routing explicitly.
    pub fn semantic_locate_fused(self) -> bool {
        match self {
            Self::AccuracyV2 | Self::AccuracyV1 | Self::CompatV0 => true,
        }
    }

    /// Default for `KIN_LOCATE_ENTITY_FUSION` (fuse at entity granularity
    /// before collapsing to files).
    pub fn entity_fusion_default(self) -> bool {
        matches!(self, Self::AccuracyV2 | Self::AccuracyV1)
    }

    /// Default for `KIN_LOCATE_DECLARATION_CUTOFF` (confidence-calibrated
    /// declaration cutoff: trim the low-confidence tail of the located file list
    /// when the fused score distribution shows a decisive separation, and keep
    /// the full list when scores are flat / genuinely ambiguous).
    ///
    /// Dark for every profile today: the lever ships without changing any
    /// profile's serving behavior. It graduates to a profile default (e.g.
    /// `accuracy-v1`) only through the paired-A/B measurement gate — split this
    /// arm to `Self::AccuracyV1 => true` at graduation. Until then the A/B itself
    /// runs via an explicit `KIN_LOCATE_DECLARATION_CUTOFF=1`, which always wins
    /// over this default at the read site, so no serving default silently flips.
    pub fn declaration_cutoff_default(self) -> bool {
        match self {
            Self::AccuracyV2 | Self::AccuracyV1 | Self::CompatV0 => false,
        }
    }

    /// Default for `KIN_LOCATE_LEXICAL_FLOOR_READMIT` (readmit strong lexical
    /// candidates the fused ranking dropped, subsuming grep on keyword
    /// queries).
    pub fn lexical_floor_readmit_default(self) -> bool {
        matches!(self, Self::AccuracyV2 | Self::AccuracyV1)
    }

    /// The cross-encoder default a RESIDENT SERVING DAEMON applies for this
    /// profile, given whether the model is already cached locally. One-shot
    /// reporters (`kin doctor`, `kin setup status`) read this instead of
    /// [`Self::cross_encoder_default`] because the state their user cares
    /// about is the daemon's, not the reporting process's own serving gate.
    ///
    /// `accuracy-v2` answers false even with the model cached: the reranker's
    /// do-not-flip verdict stands, and an install that prefetched the model
    /// under earlier advice must not silently start paying for it when the
    /// default profile changes. An explicit
    /// `KIN_LOCATE_CROSS_ENCODER_ENABLED=1` still wins at the read site.
    pub fn cross_encoder_daemon_default(self, model_cached: bool) -> bool {
        match self {
            Self::AccuracyV1 => model_cached,
            Self::AccuracyV2 | Self::CompatV0 => false,
        }
    }

    /// Default for `KIN_LOCATE_CROSS_ENCODER_ENABLED`.
    ///
    /// `accuracy-v1`: on, but only when BOTH hold —
    /// - the reranker model is already cached locally (the constructor
    ///   otherwise downloads from the network, which a default must never do
    ///   mid-query), and
    /// - this process is a resident serving daemon (`mark_daemon_serving`),
    ///   so one-shot library callers and test binaries never pay a model load
    ///   by default.
    ///
    /// `accuracy-v2` and `compat-v0` keep the reranker off unconditionally.
    /// The missing-model state is reported as a structured degradation
    /// instead of silently skipping. An explicit
    /// `KIN_LOCATE_CROSS_ENCODER_ENABLED=1` still forces the attempt (and
    /// with it the download) regardless of cache state or process kind.
    pub fn cross_encoder_default(self, model_cached: bool) -> bool {
        self.cross_encoder_daemon_default(model_cached) && daemon_serving()
    }

    /// Default for `KIN_LOCATE_RERANK_BLEND`: promotion-only additive blending
    /// of cross-encoder scores. The legacy overwrite mode substitutes raw
    /// logits for fused scores and can evict multi-signal-corroborated files,
    /// so any profile that could serve the cross-encoder, including one whose
    /// user enables it explicitly over a default of off, must also default to
    /// the blend.
    pub fn rerank_blend_default(self) -> bool {
        matches!(self, Self::AccuracyV2 | Self::AccuracyV1)
    }

    /// Default for `KIN_LOCATE_RERANK_LATENCY_BUDGET_MS`. The accuracy
    /// profiles bound the reranker so an over-budget rerank falls back to the
    /// fused order; compat keeps the historical unbounded behavior (0).
    pub fn rerank_latency_budget_ms_default(self) -> usize {
        match self {
            Self::AccuracyV2 | Self::AccuracyV1 => 1_500,
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
            Self::AccuracyV2 | Self::AccuracyV1 => 0.625,
            Self::CompatV0 => 0.25,
        }
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
    cached_under_base(resolved_hf_cache_base().as_deref(), model_id)
}

/// True when this install has ever fetched `model_id` into the local Hugging
/// Face hub cache, whether or not a usable snapshot is there now.
///
/// `hf-hub` creates `hub/models--{org}--{name}` the first time it downloads a
/// model and leaves that directory behind (with its `blobs`, `refs`, and
/// `snapshots` children) when a snapshot is pruned or a download is
/// interrupted. So its existence is the coarser fact that this machine has
/// fetched the model at some point, and [`cross_encoder_model_cached`] is the
/// finer one that a resolved snapshot is usable right now. The pair separates
/// a lever that has never been available here from one that was and is not.
///
/// A cache root deleted wholesale reads as never fetched. That is the side to
/// err on: it treats the install as one nobody has configured yet rather than
/// one that lost a capability, which understates rather than invents.
pub fn cross_encoder_model_ever_fetched(model_id: &str) -> bool {
    let Some(base) = resolved_hf_cache_base() else {
        return false;
    };
    model_cache_dir(&base, model_id).is_dir()
}

/// The cache root for this process, with the platform and home resolvers the
/// two probes above both need bound once.
fn resolved_hf_cache_base() -> Option<PathBuf> {
    hf_cache_base(
        cfg!(windows),
        |key| std::env::var_os(key),
        || directories::UserDirs::new().map(|dirs| dirs.home_dir().to_path_buf()),
        || directories::BaseDirs::new().map(|dirs| dirs.home_dir().to_path_buf()),
    )
}

/// The root `hf-hub` would resolve its cache under, given the platform and the
/// environment.
///
/// `hf-hub` reads `HF_HOME` first and otherwise falls back to
/// `dirs::home_dir()/.cache/huggingface` (`hf-hub-0.5.0/src/lib.rs:42-54`), so
/// this mirrors that shape and defers the home itself to the one resolver the
/// crate already has.
///
/// Taken as arguments rather than gated behind `cfg` for the reason
/// [`crate::commands::setup::resolve_home_dir`] spells out: a `cfg`-gated
/// Windows arm is compiled, and therefore tested, only on the platform this
/// fleet has no host for. That is precisely how the `HOME`-only lookup this
/// replaces survived — `HOME` is not a Windows name, so the probe answered
/// "absent" on Windows even with the model fully downloaded, and the reranker
/// silently stayed off instead of failing.
///
/// One divergence is deliberate and worth naming: on Windows `dirs::home_dir()`
/// is `FOLDERID_Profile` (`dirs-6.0.0/src/win.rs:5`) while `resolve_home_dir`
/// prefers a non-empty `USERPROFILE`. They agree unless `USERPROFILE` has been
/// redirected away from the known-folder profile, and following the redirect is
/// what keeps an isolated home isolated. When they do disagree the probe under-
/// reports, which this function's contract already permits: a false negative
/// only leaves the reranker off until the model is fetched explicitly.
///
/// That divergence is measured, not inferred. On a native Windows host with
/// both `HOME` and `USERPROFILE` pointed at an isolated directory, `hf-hub`
/// still wrote its 522 MB cache under the known-folder profile and left the
/// isolated home empty. Preferring `USERPROFILE` is still the right side to err
/// on: reporting a model cached that `hf-hub` would not find there is a false
/// POSITIVE, and that costs a download in the middle of a query.
fn hf_cache_base(
    windows: bool,
    var_os: impl Fn(&str) -> Option<OsString>,
    known_profile_root: impl FnOnce() -> Option<PathBuf>,
    base_dirs_home: impl FnOnce() -> Option<PathBuf>,
) -> Option<PathBuf> {
    // An empty value is not a path; treat it the same as unset rather than
    // resolving the cache relative to the working directory.
    if let Some(hf_home) = var_os("HF_HOME").filter(|value| !value.is_empty()) {
        return Some(PathBuf::from(hf_home));
    }
    crate::commands::setup::resolve_home_dir(windows, var_os, known_profile_root, base_dirs_home)
        .map(|home| home.join(".cache").join("huggingface"))
}

/// Whether `model_id` has a resolved snapshot under an already-resolved cache
/// root. Split from the root lookup so the layout and the home policy fail
/// independently.
fn cached_under_base(base: Option<&Path>, model_id: &str) -> bool {
    let Some(base) = base else {
        return false;
    };
    snapshot_present(&model_cache_dir(base, model_id))
}

/// Whether a model cache directory holds a usable entry, which is at least one
/// resolved snapshot directory.
pub(crate) fn snapshot_present(model_dir: &Path) -> bool {
    match std::fs::read_dir(model_dir.join("snapshots")) {
        Ok(mut entries) => entries.any(|entry| entry.is_ok()),
        Err(_) => false,
    }
}

/// Where `hf-hub` keeps everything it has fetched for `model_id`. Expressed
/// once so the has-ever-been-fetched and is-usable-now probes cannot drift onto
/// different layouts.
pub(crate) fn model_cache_dir(base: &Path, model_id: &str) -> PathBuf {
    base.join("hub")
        .join(format!("models--{}", model_id.replace('/', "--")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[serial_test::serial]
    fn profile_resolves_from_env_with_aliases_and_default() {
        let mut profile = kin_core::test_env::EnvVarGuard::unset("KIN_PROFILE");
        assert_eq!(RetrievalProfile::from_env(), RetrievalProfile::AccuracyV2);

        profile.apply("KIN_PROFILE", Some("compat-v0"));
        assert_eq!(RetrievalProfile::from_env(), RetrievalProfile::CompatV0);

        profile.apply("KIN_PROFILE", Some("compat"));
        assert_eq!(RetrievalProfile::from_env(), RetrievalProfile::CompatV0);

        // A versioned pin keeps meaning exactly the version it names.
        profile.apply("KIN_PROFILE", Some("ACCURACY-V1"));
        assert_eq!(RetrievalProfile::from_env(), RetrievalProfile::AccuracyV1);

        profile.apply("KIN_PROFILE", Some("accuracy-v2"));
        assert_eq!(RetrievalProfile::from_env(), RetrievalProfile::AccuracyV2);

        // The unversioned alias tracks the latest version of its family.
        profile.apply("KIN_PROFILE", Some("accuracy"));
        assert_eq!(RetrievalProfile::from_env(), RetrievalProfile::AccuracyV2);

        // Unknown values must not silently select a different serving shape.
        profile.apply("KIN_PROFILE", Some("warp-speed"));
        assert_eq!(RetrievalProfile::from_env(), RetrievalProfile::AccuracyV2);

        profile.apply::<_, &str>("KIN_PROFILE", None);
        assert_eq!(RetrievalProfile::from_env(), RetrievalProfile::AccuracyV2);
    }

    /// The shipped default: the accuracy lever set with the reranker off.
    /// Pins the default variant, its name, and every lever value, so a future
    /// edit cannot move the default without this test naming the change.
    #[test]
    #[serial_test::serial]
    fn default_profile_is_accuracy_v2_with_the_reranker_off() {
        let _profile = kin_core::test_env::EnvVarGuard::unset("KIN_PROFILE");
        let default = RetrievalProfile::from_env();
        assert_eq!(default, RetrievalProfile::AccuracyV2);
        assert_eq!(default, RetrievalProfile::default());
        assert_eq!(default.name(), "accuracy-v2");

        assert!(default.semantic_locate_fused());
        assert!(default.entity_fusion_default());
        assert!(default.lexical_floor_readmit_default());
        assert_eq!(default.rerank_latency_budget_ms_default(), 1_500);
        assert_eq!(default.embedding_min_relevance_default(), 0.625);
        // Blend stays the default so an explicit env enable of the
        // cross-encoder still gets promotion-only blending.
        assert!(default.rerank_blend_default());
        assert!(!default.declaration_cutoff_default());

        // The reranker stays off on the strongest form of its old
        // on-condition: model cached AND resident daemon. An install that
        // prefetched the model under earlier doctor advice must not silently
        // start reranking when the default profile changes.
        let _mark = DaemonServingMark;
        mark_daemon_serving();
        assert!(!default.cross_encoder_default(true));
        assert!(!default.cross_encoder_daemon_default(true));
        // ...while an accuracy-v1 pin keeps the conditional it always had.
        assert!(RetrievalProfile::AccuracyV1.cross_encoder_default(true));
        assert!(RetrievalProfile::AccuracyV1.cross_encoder_daemon_default(true));
    }

    /// Routing is not a profile lever: every profile, the compat escape hatch
    /// included, routes the MCP tool through the fused pipeline.
    #[test]
    fn every_profile_routes_semantic_locate_fused() {
        for profile in [
            RetrievalProfile::AccuracyV2,
            RetrievalProfile::AccuracyV1,
            RetrievalProfile::CompatV0,
        ] {
            assert!(
                profile.semantic_locate_fused(),
                "{} must route semantic_locate fused",
                profile.name()
            );
        }
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
        // The one deliberate exception: routing is profile-independent, so
        // the compat pin preserves the historical LEVER defaults while the
        // MCP tool routes fused like every other profile. The cosine ranking
        // stays reachable per call via `pipeline: "cosine"`.
        assert!(compat.semantic_locate_fused());
        assert!(!compat.entity_fusion_default());
        assert!(!compat.lexical_floor_readmit_default());
        assert!(!compat.cross_encoder_default(true));
        assert!(!compat.rerank_blend_default());
        assert_eq!(compat.rerank_latency_budget_ms_default(), 0);
        assert_eq!(compat.embedding_min_relevance_default(), 0.25);
        // The declaration cutoff ships dark: unset + compat is byte-identical to
        // the pre-lever file list (no truncation applied at the read site).
        assert!(!compat.declaration_cutoff_default());
    }

    #[test]
    fn declaration_cutoff_is_dark_for_every_profile() {
        // The confidence cutoff is a graduation-gated lever: it must not be a
        // silent default under ANY profile, so that shipping it changes nothing
        // until a paired A/B flips it on. An explicit env override drives the A/B.
        for profile in [
            RetrievalProfile::AccuracyV2,
            RetrievalProfile::AccuracyV1,
            RetrievalProfile::CompatV0,
        ] {
            assert!(
                !profile.declaration_cutoff_default(),
                "{} must not enable the declaration cutoff by default",
                profile.name()
            );
        }
    }

    /// Clears the process-global serving mark on the way out, including when
    /// the test unwinds.
    ///
    /// The mark gates the cross-encoder default, and a cross-encoder default
    /// left switched on makes unrelated `locate` tests fetch reranker weights
    /// over the network. Restoring it only on the success path means one failed
    /// assertion here turns into a download — and an unbounded one — somewhere
    /// else in the binary.
    struct DaemonServingMark;

    impl Drop for DaemonServingMark {
        fn drop(&mut self) {
            reset_daemon_serving_for_tests();
        }
    }

    #[test]
    #[serial_test::serial]
    fn accuracy_profile_gates_cross_encoder_on_cached_model_and_daemon_context() {
        let accuracy = RetrievalProfile::AccuracyV1;
        let _mark = DaemonServingMark;

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
    }

    /// Reads only the names it is given, so a test states the whole environment
    /// it is asserting against and nothing ambient can leak in.
    fn env_of(pairs: &[(&str, &Path)]) -> impl Fn(&str) -> Option<OsString> + use<> {
        let pairs: Vec<(String, OsString)> = pairs
            .iter()
            .map(|(key, value)| ((*key).to_string(), value.as_os_str().to_os_string()))
            .collect();
        move |key| {
            pairs
                .iter()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value.clone())
        }
    }

    fn stage_cached_model(home: &Path, model_id: &str) {
        let dir = home
            .join(".cache")
            .join("huggingface")
            .join("hub")
            .join(format!("models--{}", model_id.replace('/', "--")))
            .join("snapshots")
            .join("0123456789abcdef");
        std::fs::create_dir_all(&dir).unwrap();
    }

    const CE_MODEL: &str = "cross-encoder/ms-marco-MiniLM-L-6-v2";

    /// Windows names the profile root `USERPROFILE` and does not set `HOME`, so
    /// a `HOME`-only lookup reports every model absent no matter what is on
    /// disk. This is the regression: it fails against the previous lookup and
    /// passes against the shared resolver.
    #[test]
    fn probe_finds_a_cached_model_under_a_windows_shaped_home() {
        let temp = tempfile::tempdir().unwrap();
        let profile = temp.path();
        stage_cached_model(profile, CE_MODEL);

        let base = hf_cache_base(true, env_of(&[("USERPROFILE", profile)]), || None, || None);

        assert_eq!(
            base,
            Some(profile.join(".cache").join("huggingface")),
            "a Windows home must resolve from USERPROFILE"
        );
        assert!(
            cached_under_base(base.as_deref(), CE_MODEL),
            "a fully downloaded model under a Windows profile must read as cached"
        );
    }

    /// The negative arm, so the positive above cannot pass by answering `true`
    /// unconditionally.
    #[test]
    fn probe_reports_absent_when_no_model_is_cached() {
        let temp = tempfile::tempdir().unwrap();
        let profile = temp.path();

        let base = hf_cache_base(true, env_of(&[("USERPROFILE", profile)]), || None, || None);

        assert_eq!(base, Some(profile.join(".cache").join("huggingface")));
        assert!(
            !cached_under_base(base.as_deref(), CE_MODEL),
            "an empty cache must report absent"
        );
    }

    /// A model directory left behind with no resolved snapshot is what a pruned
    /// cache or an interrupted download leaves. The two probes have to disagree
    /// there: that disagreement is the whole of what separates a lever this
    /// install has never had from one it had and lost. Walked as three states
    /// on one fixture, so each assertion falsifies the one before it.
    #[test]
    #[serial_test::serial]
    fn a_pruned_model_reads_as_fetched_but_not_cached() {
        let temp = tempfile::tempdir().unwrap();
        let _hf = kin_core::test_env::EnvVarGuard::set("HF_HOME", temp.path());
        let model_dir = model_cache_dir(temp.path(), CE_MODEL);

        assert!(
            !cross_encoder_model_ever_fetched(CE_MODEL),
            "an untouched cache root must read as never fetched"
        );
        assert!(!cross_encoder_model_cached(CE_MODEL));

        std::fs::create_dir_all(model_dir.join("blobs")).unwrap();
        assert!(
            cross_encoder_model_ever_fetched(CE_MODEL),
            "a model directory left behind means this install fetched the model once"
        );
        assert!(
            !cross_encoder_model_cached(CE_MODEL),
            "with no resolved snapshot the model is not usable now"
        );

        std::fs::create_dir_all(model_dir.join("snapshots").join("0123456789abcdef")).unwrap();
        assert!(
            cross_encoder_model_ever_fetched(CE_MODEL) && cross_encoder_model_cached(CE_MODEL),
            "a resolved snapshot is both fetched and usable"
        );
    }

    /// A profile root that exists but holds no `AppData` subtree collapses the
    /// `BaseDirs` constructor to `None`. `USERPROFILE` must still win, which is
    /// the same failure mode the setup resolver was hardened against.
    #[test]
    fn windows_probe_prefers_the_named_profile_over_both_lookups() {
        let temp = tempfile::tempdir().unwrap();
        let named = temp.path().join("named");
        let known = temp.path().join("known-folder");
        std::fs::create_dir_all(&named).unwrap();
        stage_cached_model(&named, CE_MODEL);

        let base = hf_cache_base(
            true,
            env_of(&[("USERPROFILE", &named)]),
            || Some(known.clone()),
            || Some(known.clone()),
        );

        assert_eq!(base, Some(named.join(".cache").join("huggingface")));
        assert!(cached_under_base(base.as_deref(), CE_MODEL));
    }

    /// With `USERPROFILE` unset or empty the known-folder profile answers, so an
    /// environment that names nothing still resolves.
    #[test]
    fn windows_probe_falls_back_to_the_known_folder_profile() {
        let temp = tempfile::tempdir().unwrap();
        let known = temp.path();
        stage_cached_model(known, CE_MODEL);

        for env in [env_of(&[]), env_of(&[("USERPROFILE", Path::new(""))])] {
            let base = hf_cache_base(true, env, || Some(known.to_path_buf()), || None);
            assert_eq!(base, Some(known.join(".cache").join("huggingface")));
            assert!(cached_under_base(base.as_deref(), CE_MODEL));
        }
    }

    /// Unix keeps resolving through `BaseDirs`, which reads `HOME` first and
    /// otherwise falls back to the passwd database, and must never consult
    /// `USERPROFILE`.
    #[test]
    fn unix_probe_resolves_through_base_dirs_and_ignores_userprofile() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("home");
        let windows_only = temp.path().join("windows-only");
        std::fs::create_dir_all(&home).unwrap();
        stage_cached_model(&home, CE_MODEL);

        let base = hf_cache_base(
            false,
            env_of(&[("USERPROFILE", &windows_only)]),
            || Some(windows_only.clone()),
            || Some(home.clone()),
        );

        assert_eq!(base, Some(home.join(".cache").join("huggingface")));
        assert!(cached_under_base(base.as_deref(), CE_MODEL));
    }

    /// `HF_HOME` is the cache root itself, not a home, and outranks every home
    /// lookup on both platforms. An empty value is not a path and must read as
    /// unset rather than resolving relative to the working directory.
    #[test]
    fn hf_home_outranks_the_resolved_home_and_ignores_empty() {
        let temp = tempfile::tempdir().unwrap();
        let hf_home = temp.path().join("hf");
        let profile = temp.path().join("profile");
        std::fs::create_dir_all(&profile).unwrap();
        std::fs::create_dir_all(
            hf_home
                .join("hub")
                .join(format!("models--{}", CE_MODEL.replace('/', "--")))
                .join("snapshots")
                .join("0123456789abcdef"),
        )
        .unwrap();

        for windows in [true, false] {
            let base = hf_cache_base(
                windows,
                env_of(&[("HF_HOME", &hf_home), ("USERPROFILE", &profile)]),
                || Some(profile.clone()),
                || Some(profile.clone()),
            );
            assert_eq!(base, Some(hf_home.clone()), "HF_HOME is the cache root");
            assert!(cached_under_base(base.as_deref(), CE_MODEL));

            let empty = hf_cache_base(
                windows,
                env_of(&[("HF_HOME", Path::new("")), ("USERPROFILE", &profile)]),
                || Some(profile.clone()),
                || Some(profile.clone()),
            );
            assert_eq!(
                empty,
                Some(profile.join(".cache").join("huggingface")),
                "an empty HF_HOME must read as unset"
            );
        }
    }

    /// No resolvable home at all is the one case that legitimately answers
    /// `None`, and it must report absent rather than probing a relative path.
    #[test]
    fn probe_reports_absent_without_any_resolvable_home() {
        for windows in [true, false] {
            let base = hf_cache_base(windows, env_of(&[]), || None, || None);
            assert_eq!(base, None);
            assert!(!cached_under_base(base.as_deref(), CE_MODEL));
        }
    }
}
