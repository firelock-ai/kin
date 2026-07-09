// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

#[cfg(feature = "embeddings")]
pub mod cache_admin;
#[cfg(feature = "embeddings")]
mod inference;
#[cfg(feature = "embeddings")]
pub mod rerank;

#[cfg(feature = "embeddings")]
use hf_hub::{api::sync::Api, Repo, RepoType};
#[cfg(feature = "embeddings")]
use kin_infer::gpu::GpuBackend;
#[cfg(feature = "embeddings")]
use rayon::prelude::*;
#[cfg(feature = "embeddings")]
use reqwest::blocking::Client as BlockingHttpClient;
#[cfg(feature = "embeddings")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "embeddings")]
use sha2::{Digest, Sha256};
#[cfg(feature = "embeddings")]
use std::borrow::Cow;
#[cfg(feature = "embeddings")]
use std::collections::HashMap;
#[cfg(feature = "embeddings")]
use std::path::{Path, PathBuf};
#[cfg(feature = "embeddings")]
use tokenizers::tokenizer::{
    PaddingDirection, PaddingParams, PaddingStrategy, TruncationDirection, TruncationParams,
    TruncationStrategy,
};
#[cfg(feature = "embeddings")]
use tokenizers::Tokenizer;

#[cfg(feature = "embeddings")]
use self::inference::{BertConfig, BertModel};

use crate::error::KinDbError;
use kin_model::{
    ArtifactKind, Entity, EntityKind, OpaqueArtifact, ShallowTrackedFile, StructuredArtifact,
};

// ---------------------------------------------------------------------------
// Embed stage timing
// ---------------------------------------------------------------------------

/// The stages of the entity embed hot path, in pipeline order.
///
/// The forward stage is GPU-bound; drain, prep, persist, and prune run on the
/// CPU around it. [`EmbedStageTimings`] accumulates per-stage wall time and call
/// counts so a `RUST_LOG=kin_db=info` embed run reports where CPU time actually
/// goes — without per-batch span spam — and so a snapshot can be surfaced through
/// operator tooling (e.g. `kin resources inspect`).
#[cfg(feature = "vector")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EmbedStage {
    /// Drain + deterministic priority selection of the next batch from the queue.
    Drain,
    /// Format each drained entity's embed text under the graph read lock.
    Prep,
    /// Run model inference for the prepared batch (the GPU forward).
    Forward,
    /// Upsert embedded vectors into the index.
    Persist,
    /// Reconcile the index against graph truth (orphaned-vector eviction).
    Prune,
}

#[cfg(feature = "vector")]
impl EmbedStage {
    /// Every stage, in pipeline order. Array indices match [`EmbedStage::index`].
    pub const ALL: [EmbedStage; 5] = [
        EmbedStage::Drain,
        EmbedStage::Prep,
        EmbedStage::Forward,
        EmbedStage::Persist,
        EmbedStage::Prune,
    ];

    const fn index(self) -> usize {
        match self {
            EmbedStage::Drain => 0,
            EmbedStage::Prep => 1,
            EmbedStage::Forward => 2,
            EmbedStage::Persist => 3,
            EmbedStage::Prune => 4,
        }
    }

    /// Short lower-case label used in log lines and inspect output.
    pub const fn label(self) -> &'static str {
        match self {
            EmbedStage::Drain => "drain",
            EmbedStage::Prep => "prep",
            EmbedStage::Forward => "forward",
            EmbedStage::Persist => "persist",
            EmbedStage::Prune => "prune",
        }
    }
}

/// Per-stage wall-clock + call-count accumulator for the embed hot path. One
/// instance lives on each `InMemoryGraph`; the staged embed methods record into
/// it. Recording a stage is two `Instant` reads plus two relaxed atomic adds —
/// negligible against a ~128-entity batch — so it is always on.
#[cfg(feature = "vector")]
pub struct EmbedStageTimings {
    nanos: [std::sync::atomic::AtomicU64; 5],
    calls: [std::sync::atomic::AtomicU64; 5],
}

#[cfg(feature = "vector")]
impl Default for EmbedStageTimings {
    fn default() -> Self {
        Self {
            nanos: std::array::from_fn(|_| std::sync::atomic::AtomicU64::new(0)),
            calls: std::array::from_fn(|_| std::sync::atomic::AtomicU64::new(0)),
        }
    }
}

#[cfg(feature = "vector")]
impl EmbedStageTimings {
    /// Record one stage observation.
    pub fn record(&self, stage: EmbedStage, elapsed: std::time::Duration) {
        let i = stage.index();
        // Saturate rather than wrap; nanos for any realistic embed run stay far
        // below u64::MAX (~584 years).
        let add = elapsed.as_nanos().min(u64::MAX as u128) as u64;
        self.nanos[i].fetch_add(add, std::sync::atomic::Ordering::Relaxed);
        self.calls[i].fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    /// Time `body`, record its wall time against `stage`, and return its value.
    pub fn time<T>(&self, stage: EmbedStage, body: impl FnOnce() -> T) -> T {
        let start = std::time::Instant::now();
        let out = body();
        self.record(stage, start.elapsed());
        out
    }

    /// Start a scoped timer that records `stage` when dropped — for stages whose
    /// function returns from several places.
    pub fn scope(&self, stage: EmbedStage) -> EmbedStageScope<'_> {
        EmbedStageScope {
            timings: self,
            stage,
            start: std::time::Instant::now(),
        }
    }

    /// Take a point-in-time snapshot of the cumulative totals.
    pub fn snapshot(&self) -> EmbedStageSnapshot {
        let mut stages = [EmbedStageCount::default(); 5];
        for (i, slot) in stages.iter_mut().enumerate() {
            *slot = EmbedStageCount {
                nanos: self.nanos[i].load(std::sync::atomic::Ordering::Relaxed),
                calls: self.calls[i].load(std::sync::atomic::Ordering::Relaxed),
            };
        }
        EmbedStageSnapshot { stages }
    }
}

/// RAII guard recording its stage's elapsed time when dropped.
#[cfg(feature = "vector")]
pub struct EmbedStageScope<'a> {
    timings: &'a EmbedStageTimings,
    stage: EmbedStage,
    start: std::time::Instant,
}

#[cfg(feature = "vector")]
impl Drop for EmbedStageScope<'_> {
    fn drop(&mut self) {
        self.timings.record(self.stage, self.start.elapsed());
    }
}

/// Cumulative wall time + call count for a single stage.
#[cfg(feature = "vector")]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EmbedStageCount {
    /// Total nanoseconds spent in the stage.
    pub nanos: u64,
    /// Number of times the stage ran.
    pub calls: u64,
}

/// An immutable snapshot of [`EmbedStageTimings`], indexed by [`EmbedStage`].
#[cfg(feature = "vector")]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EmbedStageSnapshot {
    stages: [EmbedStageCount; 5],
}

#[cfg(feature = "vector")]
impl EmbedStageSnapshot {
    /// Per-stage totals accrued between `base` and `self` — one run's slice of a
    /// cumulative per-graph accumulator. Saturating so a reset base never
    /// underflows.
    pub fn since(&self, base: &EmbedStageSnapshot) -> EmbedStageSnapshot {
        let mut stages = [EmbedStageCount::default(); 5];
        for (i, slot) in stages.iter_mut().enumerate() {
            *slot = EmbedStageCount {
                nanos: self.stages[i].nanos.saturating_sub(base.stages[i].nanos),
                calls: self.stages[i].calls.saturating_sub(base.stages[i].calls),
            };
        }
        EmbedStageSnapshot { stages }
    }

    /// The cumulative total for one stage.
    pub fn stage(&self, stage: EmbedStage) -> EmbedStageCount {
        self.stages[stage.index()]
    }

    /// Total wall time across all stages.
    pub fn total_nanos(&self) -> u64 {
        self.stages.iter().map(|s| s.nanos).sum()
    }

    /// Whether any stage ran at all.
    pub fn is_empty(&self) -> bool {
        self.stages.iter().all(|s| s.calls == 0)
    }

    /// Emit a single `info`-level line summarizing every stage. `context` labels
    /// the run (e.g. "serial" / "pipelined"). No-op when nothing ran.
    pub fn log_summary(&self, context: &str) {
        if self.is_empty() {
            return;
        }
        let ms = |n: u64| n as f64 / 1.0e6;
        let drain = self.stage(EmbedStage::Drain);
        let prep = self.stage(EmbedStage::Prep);
        let forward = self.stage(EmbedStage::Forward);
        let persist = self.stage(EmbedStage::Persist);
        let prune = self.stage(EmbedStage::Prune);
        tracing::info!(
            target: "kin_db",
            "embed stage timing [{context}] total={:.1}ms | drain={:.1}ms/{} prep={:.1}ms/{} \
             forward={:.1}ms/{} persist={:.1}ms/{} prune={:.1}ms/{}",
            ms(self.total_nanos()),
            ms(drain.nanos),
            drain.calls,
            ms(prep.nanos),
            prep.calls,
            ms(forward.nanos),
            forward.calls,
            ms(persist.nanos),
            persist.calls,
            ms(prune.nanos),
            prune.calls,
        );
    }
}

/// Parse a HuggingFace `config.json` into the target config type, dropping a
/// serde-alias key whenever its canonical counterpart is also present. Some
/// published configs (nomic-bert) ship both `layer_norm_eps` and
/// `layer_norm_epsilon`, which `#[serde(alias)]` otherwise rejects as a
/// duplicate field — so the parse must tolerate the canonical+alias pair.
#[cfg(feature = "embeddings")]
fn parse_model_config<T: serde::de::DeserializeOwned>(data: &str) -> serde_json::Result<T> {
    let mut value: serde_json::Value = serde_json::from_str(data)?;
    if let Some(obj) = value.as_object_mut() {
        const ALIAS_PAIRS: &[(&str, &str)] = &[
            ("hidden_size", "n_embd"),
            ("num_hidden_layers", "n_layer"),
            ("num_attention_heads", "n_head"),
            ("intermediate_size", "n_inner"),
            ("max_position_embeddings", "n_positions"),
            ("layer_norm_eps", "layer_norm_epsilon"),
            ("rope_theta", "rotary_emb_base"),
        ];
        for (canonical, alias) in ALIAS_PAIRS {
            if obj.contains_key(*canonical) {
                obj.remove(*alias);
            }
        }
    }
    serde_json::from_value(value)
}

/// Load a `BertModel`, optionally pinned to the CPU backend.
///
/// The compute backend is passed explicitly to kin-infer via
/// `BertModel::load_with_backend`. The effective backend is CPU when either the
/// caller's `force_cpu` argument is set or the process-global
/// `KIN_INFER_FORCE_CPU` env override is active (`gpu::force_cpu_from_env`);
/// otherwise the normal Metal > CUDA > CPU auto ladder runs. This preserves the
/// env-honoring semantics of `BertModel::load` (which a forced-CPU determinism
/// proof relies on) while selecting per-load: the load never mutates the
/// environment, so a concurrent load can no longer observe a transient toggle
/// and pick the wrong backend.
#[cfg(feature = "embeddings")]
fn load_bert_model(
    weights_path: &Path,
    config: BertConfig,
    force_cpu: bool,
) -> Result<BertModel, kin_infer::InferError> {
    BertModel::load_with_backend(
        weights_path,
        config,
        force_cpu || kin_infer::gpu::force_cpu_from_env(),
    )
}

/// Process-global counters that record how the throughput-profile hybrid split
/// actually routed embedding work.
///
/// These make the CPU twin's contribution observable and provable: after an
/// index run, `snapshot().cpu_twin_entities > 0` is positive evidence that the
/// idle cores ran a real share of the batch (rather than the GPU silently
/// absorbing all of it). Counters are best-effort relaxed atomics — they are an
/// observability surface, never a control input.
#[cfg(feature = "embeddings")]
pub mod hybrid_metrics {
    use std::sync::atomic::{AtomicU64, Ordering};

    static GPU_ENTITIES: AtomicU64 = AtomicU64::new(0);
    static GPU_TOKENS: AtomicU64 = AtomicU64::new(0);
    static CPU_TWIN_ENTITIES: AtomicU64 = AtomicU64::new(0);
    static CPU_TWIN_TOKENS: AtomicU64 = AtomicU64::new(0);
    static HYBRID_BATCHES: AtomicU64 = AtomicU64::new(0);
    static SINGLE_SIDE_BATCHES: AtomicU64 = AtomicU64::new(0);
    static TWIN_UNAVAILABLE_BATCHES: AtomicU64 = AtomicU64::new(0);
    static CPU_PARALLEL_BATCHES: AtomicU64 = AtomicU64::new(0);
    static SEQFLOOR_DEGENERATE_BATCHES: AtomicU64 = AtomicU64::new(0);

    /// A point-in-time read of the hybrid dispatch counters.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
    pub struct HybridDispatchStats {
        /// Entities embedded on the GPU (Metal) arm.
        pub gpu_entities: u64,
        /// Padded tokens embedded on the GPU arm.
        pub gpu_tokens: u64,
        /// Entities embedded on the CPU twin — non-zero proves the twin ran.
        pub cpu_twin_entities: u64,
        /// Padded tokens embedded on the CPU twin.
        pub cpu_twin_tokens: u64,
        /// Batches that ran both arms concurrently.
        pub hybrid_batches: u64,
        /// Batches where the balanced split placed all work on one arm.
        pub single_side_batches: u64,
        /// Batches that fell back to serial primary-model dispatch because the
        /// CPU twin could not be built.
        pub twin_unavailable_batches: u64,
        /// CPU subsets embedded with their sub-batches spread concurrently across
        /// cores — non-zero proves the idle cores ran in parallel.
        pub cpu_parallel_batches: u64,
        /// SeqFloor batches whose sequence-length split was structurally
        /// degenerate (no entity exceeded the truncation cap, so the criterion
        /// could route nothing to the CPU twin). Non-zero proves the dispatcher
        /// recognized the degenerate split and deferred to the adaptive
        /// throughput decision rather than silently collapsing to a single GPU
        /// arm.
        pub seqfloor_degenerate_batches: u64,
    }

    pub(crate) fn record_gpu(entities: u64, tokens: u64) {
        GPU_ENTITIES.fetch_add(entities, Ordering::Relaxed);
        GPU_TOKENS.fetch_add(tokens, Ordering::Relaxed);
    }

    pub(crate) fn record_cpu_twin(entities: u64, tokens: u64) {
        CPU_TWIN_ENTITIES.fetch_add(entities, Ordering::Relaxed);
        CPU_TWIN_TOKENS.fetch_add(tokens, Ordering::Relaxed);
    }

    pub(crate) fn record_hybrid_batch() {
        HYBRID_BATCHES.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_single_side_batch() {
        SINGLE_SIDE_BATCHES.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_twin_unavailable_batch() {
        TWIN_UNAVAILABLE_BATCHES.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_cpu_parallel_batch() {
        CPU_PARALLEL_BATCHES.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn record_seqfloor_degenerate_batch() {
        SEQFLOOR_DEGENERATE_BATCHES.fetch_add(1, Ordering::Relaxed);
    }

    /// Read the current counters.
    pub fn snapshot() -> HybridDispatchStats {
        HybridDispatchStats {
            gpu_entities: GPU_ENTITIES.load(Ordering::Relaxed),
            gpu_tokens: GPU_TOKENS.load(Ordering::Relaxed),
            cpu_twin_entities: CPU_TWIN_ENTITIES.load(Ordering::Relaxed),
            cpu_twin_tokens: CPU_TWIN_TOKENS.load(Ordering::Relaxed),
            hybrid_batches: HYBRID_BATCHES.load(Ordering::Relaxed),
            single_side_batches: SINGLE_SIDE_BATCHES.load(Ordering::Relaxed),
            twin_unavailable_batches: TWIN_UNAVAILABLE_BATCHES.load(Ordering::Relaxed),
            cpu_parallel_batches: CPU_PARALLEL_BATCHES.load(Ordering::Relaxed),
            seqfloor_degenerate_batches: SEQFLOOR_DEGENERATE_BATCHES.load(Ordering::Relaxed),
        }
    }

    /// Reset all counters to zero (test/diagnostic harnesses).
    pub fn reset() {
        for counter in [
            &GPU_ENTITIES,
            &GPU_TOKENS,
            &CPU_TWIN_ENTITIES,
            &CPU_TWIN_TOKENS,
            &HYBRID_BATCHES,
            &SINGLE_SIDE_BATCHES,
            &TWIN_UNAVAILABLE_BATCHES,
            &CPU_PARALLEL_BATCHES,
            &SEQFLOOR_DEGENERATE_BATCHES,
        ] {
            counter.store(0, Ordering::Relaxed);
        }
    }
}

/// Adaptive GPU/CPU split ratio for the throughput-profile hybrid.
///
/// The right CPU-twin share depends on the GPU's per-entity speed advantage at
/// the batch's sequence length, which varies (the GPU pulls far ahead on long
/// sequences). A hardcoded ratio over-feeds the slow CPU arm on long code
/// entities, so the GPU finishes early and idles waiting for the twin — net
/// slower than GPU-only. This measures the actual GPU-vs-CPU token throughput
/// from each concurrent dispatch and steers the ratio toward the value that
/// balances the two arms. It bootstraps GPU-heavy (never over-feed the twin
/// before measuring), rides UP toward GPU-only when the twin can't keep up
/// (long sequences), and DOWN toward a real split when it can (short sequences).
/// An explicit `KIN_EMBED_HYBRID_GPU_TPUT_RATIO` disables adaptation.
#[cfg(feature = "embeddings")]
pub mod adaptive_split {
    use std::sync::Mutex;

    /// Ratio used before any measurement, when the twin is engaged.
    const BOOTSTRAP_RATIO: f64 = 16.0;
    const RATIO_MIN: f64 = 1.0;
    const RATIO_MAX: f64 = 4096.0;
    const EWMA_ALPHA: f64 = 0.4;
    /// Probe the twin on the first few batches (to seed a measurement) and then
    /// every `PROBE_INTERVAL` batches (to track sequence-length drift), forcing it
    /// a small share even while the steady decision is GPU-only.
    const PROBE_EARLY: u64 = 3;
    const PROBE_INTERVAL: u64 = 48;
    /// Entities handed to the twin on a probe batch (the shortest available).
    pub(crate) const PROBE_CPU_ENTITIES: usize = 2;

    /// What the next throughput-hybrid batch should do.
    pub(crate) enum SplitPlan {
        /// Embed the whole batch on the GPU — at this sequence length the twin's
        /// per-entity latency exceeds the GPU's batch time, so any CPU share only
        /// makes the GPU wait. This is the explicit "hybrid not beneficial" record.
        GpuOnly,
        /// Split GPU/CPU at `ratio`; `min_cpu_probe > 0` forces a measurement.
        Balanced { ratio: f64, min_cpu_probe: usize },
    }

    struct State {
        ratio: f64,
        /// Last measurement showed the CPU arm finishing within the GPU arm's time
        /// (so engaging the twin speeds the batch up rather than stalling the GPU).
        cpu_beneficial: bool,
        samples: u64,
        batches: u64,
        last_gpu_tokens_per_sec: f64,
        last_cpu_tokens_per_sec: f64,
    }

    static STATE: Mutex<State> = Mutex::new(State {
        ratio: BOOTSTRAP_RATIO,
        cpu_beneficial: false,
        samples: 0,
        batches: 0,
        last_gpu_tokens_per_sec: 0.0,
        last_cpu_tokens_per_sec: 0.0,
    });

    fn lock() -> std::sync::MutexGuard<'static, State> {
        STATE.lock().unwrap_or_else(|poison| poison.into_inner())
    }

    /// Plan the next adaptive dispatch. Defaults to GPU-only; engages the twin
    /// only when the latest probe showed it keeps up, and periodically probes to
    /// re-check as sequence lengths drift.
    pub(crate) fn plan() -> SplitPlan {
        let mut s = lock();
        s.batches += 1;
        let probe = s.batches <= PROBE_EARLY || s.batches.is_multiple_of(PROBE_INTERVAL);
        if probe {
            SplitPlan::Balanced {
                ratio: s.ratio,
                min_cpu_probe: PROBE_CPU_ENTITIES,
            }
        } else if s.cpu_beneficial {
            SplitPlan::Balanced {
                ratio: s.ratio,
                min_cpu_probe: 0,
            }
        } else {
            SplitPlan::GpuOnly
        }
    }

    /// Fold one concurrent dispatch's measured arm throughput into the ratio and
    /// the beneficial decision.
    pub(crate) fn record(gpu_tokens: u64, gpu_secs: f64, cpu_tokens: u64, cpu_secs: f64) {
        if gpu_tokens == 0 || cpu_tokens == 0 || gpu_secs <= 0.0 || cpu_secs <= 0.0 {
            return;
        }
        let gpu_tps = gpu_tokens as f64 / gpu_secs;
        let cpu_tps = cpu_tokens as f64 / cpu_secs;
        if !gpu_tps.is_finite() || !cpu_tps.is_finite() || cpu_tps <= 0.0 {
            return;
        }
        let measured = (gpu_tps / cpu_tps).clamp(RATIO_MIN, RATIO_MAX);
        let mut s = lock();
        s.ratio = if s.samples == 0 {
            measured
        } else {
            ((1.0 - EWMA_ALPHA) * s.ratio + EWMA_ALPHA * measured).clamp(RATIO_MIN, RATIO_MAX)
        };
        // The CPU arm is worth running only if it finished within the GPU arm's
        // wall time — otherwise it is the batch's bottleneck and the GPU idled.
        s.cpu_beneficial = cpu_secs <= gpu_secs;
        s.samples += 1;
        s.last_gpu_tokens_per_sec = gpu_tps;
        s.last_cpu_tokens_per_sec = cpu_tps;
    }

    /// Current `(ratio, gpu_tokens_per_sec, cpu_tokens_per_sec, cpu_beneficial, samples)`.
    pub fn snapshot() -> (f64, f64, f64, bool, u64) {
        let s = lock();
        (
            s.ratio,
            s.last_gpu_tokens_per_sec,
            s.last_cpu_tokens_per_sec,
            s.cpu_beneficial,
            s.samples,
        )
    }

    /// Reset to the bootstrap state (test/diagnostic harnesses).
    pub fn reset() {
        let mut s = lock();
        *s = State {
            ratio: BOOTSTRAP_RATIO,
            cpu_beneficial: false,
            samples: 0,
            batches: 0,
            last_gpu_tokens_per_sec: 0.0,
            last_cpu_tokens_per_sec: 0.0,
        };
    }
}

/// Default HuggingFace model ID.
///
/// The default nomic-embed-text-v1.5 keeps semantic search local while bringing
/// embedding build time down enough for repo-scale indexing to stay practical on
/// developer machines.
const DEFAULT_MODEL_ID: &str = "nomic-ai/nomic-embed-text-v1.5";
/// Asymmetric query instruction for SweRankEmbed / nomic_bert code retrievers.
///
/// SweRankEmbed-Small prepends this exact string (trailing space included) to
/// queries and encodes documents raw. BGE stays symmetric, so this only fires
/// when the loaded model reports a nomic_bert architecture.
#[cfg(feature = "embeddings")]
const SWERANK_QUERY_PREFIX: &str = "Represent this query for searching relevant code: ";
#[cfg(feature = "embeddings")]
const DEFAULT_LMSTUDIO_EMBED_MODEL_ID: &str = "text-embedding-nomic-embed-text-v1.5";
#[cfg(feature = "embeddings")]
const DEFAULT_OPENAI_EMBED_MODEL_ID: &str = "text-embedding-3-small";

/// Default model revision.
const DEFAULT_REVISION: &str = "main";

/// Serializes `--lib` unit tests that build a real [`CodeEmbedder`] against
/// the shared on-disk HuggingFace Hub cache
/// (`default_dimensions_match_default_model` here and
/// `test_vector_index_dimension_mismatch_auto_recovery` in `engine::graph`;
/// both resolve `DEFAULT_MODEL_ID`/`DEFAULT_REVISION`). `cargo test` runs
/// unit tests from one binary concurrently by default, and two threads
/// racing `hf_hub`'s first-time blob download for the same repo+revision
/// can corrupt the shared cache directory. Holding this lock around
/// embedder construction means the first test performs the real download
/// and every later test observes an already-warm cache: no network race,
/// and the model is fetched once per test run instead of once per test.
#[cfg(all(test, feature = "embeddings"))]
pub(crate) static EMBED_MODEL_DOWNLOAD_LOCK: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

#[cfg(feature = "embeddings")]
const DEFAULT_MAX_BATCH_TOKENS: usize = 32_768;
#[cfg(feature = "embeddings")]
const CUDA_MAX_BATCH_TOKENS: usize = 65_536;
// Metal attention is O(seq²): a GPU dispatch packed to 65_536 tokens of long
// (≈2048-token) entities allocates a multi-GB attention buffer that blows the
// GPU and gets the daemon SIGKILLed by the watchdog (no panic/OOM trace —
// observed live on a long-body repo: dies at batch=256, survives at batch=32).
// The token *sum* alone doesn't bound attention memory, which scales with
// (tokens × max_seq); with the 2048 seq cap, 16_384 tokens/dispatch keeps the
// worst-case attention buffer ~1.6GB — safe — while staying well-batched for
// the common short-entity case. Tune up via KIN_EMBED_MAX_BATCH_TOKENS.
#[cfg(feature = "embeddings")]
const METAL_MAX_BATCH_TOKENS: usize = 16_384;
// The real GPU cost of a Metal attention dispatch is the score buffer, sized
// `count × max_seq²` (= padded-tokens × max_seq). The token budget above bounds
// padded-tokens but NOT that product: at a fixed token budget, attention memory
// still grows linearly with max_seq, so a dispatch packed with long entities
// allocates a far larger buffer than one packed with short ones — and trips the
// macOS GPU watchdog (silent SIGKILL). `METAL_MAX_ATTENTION_AREA` bounds that
// product directly, so a dispatch is safe at ANY entity length: long entities
// pack fewer-per-dispatch, short entities still pack many. 8_388_608 = 2 × 2048²
// (two entities at the EMBED_MAX_SEQ_LEN cap) — the largest worst-case dispatch
// verified to survive the watchdog live on a long-body repo; 4 × that died.
// KIN_EMBED_MAX_ATTENTION_AREA may lower this cap, but must not raise the
// Metal hard guard until the inference engine has a real allocator-level bound.
#[cfg(feature = "embeddings")]
const METAL_MAX_ATTENTION_AREA: usize = 8_388_608;
#[cfg(feature = "embeddings")]
const EMBEDDING_CACHE_SCHEMA_VERSION: &str = "v2";
#[cfg(feature = "embeddings")]
const EMBEDDING_CACHE_PIPELINE_EPOCH: &str = "embed-pipeline-2026-05-31-swerank";
pub const EMBEDDING_BODY_PREVIEW_KEY: &str = "embedding_body_preview";
const FILE_IMPORT_CONTEXT_KEY: &str = "file_import_context";
const FILE_SURFACE_CONTEXT_KEY: &str = "file_surface_context";

/// Practical per-entity tokenization ceiling for embeddings. Bounded *well below*
/// the model's trained range so a single entity can never dominate GPU cost — and,
/// critically, so no single Metal embed command runs long enough to trip the macOS
/// GPU watchdog, which SIGKILLs the daemon with no panic/OOM trace (observed live:
/// a long-body repo's ~8k-token entity wedged the embed pass, the watchdog reaped
/// the process, retries then stacked on the dead daemon). The naive scalar Metal
/// attention is O(seq²): a 2982-token entity costs ~30× a typical ~500-token one,
/// and an 8192-token entity ~270× (~13s on one command — over the watchdog limit).
/// The entity embed text is front-loaded with the discriminating signal (kind,
/// path, name, signature, doc summary, body preview), so right-truncation past this
/// length drops boilerplate (Parameters/Examples/References prose), not semantics —
/// while keeping every embed command sub-second and the daemon alive at scale.
const EMBED_MAX_SEQ_LEN: usize = 2048;

/// Maximum characters of an entity's docstring (`doc_summary`) folded into its
/// embedding text. NumPy/PEP-257 docstrings are front-loaded — the summary line
/// and first paragraph carry the semantics; the long Parameters/Attributes/
/// Examples/References sections add tokens (and O(seq²) GPU cost) without
/// retrieval signal. The full docstring stays in graph truth for display/blame;
/// only the embed projection is bounded. Mirrors the 800-char body preview.
const EMBED_DOC_SUMMARY_MAX_CHARS: usize = 8000;

#[cfg(feature = "embeddings")]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EmbeddingRuntimeConfig {
    pub provider: String,
    pub model_id: String,
    pub revision: String,
    pub dimensions: Option<usize>,
    pub pipeline_epoch: String,
}

/// Generates code embeddings using a local BERT model via a custom inference
/// runtime. Pure Rust, zero framework dependencies (ndarray + safetensors).
///
/// Uses nomic-embed-text-v1.5 by default (768 dimensions; override via KIN_EMBED_MODEL_ID).
/// The model is downloaded from HuggingFace Hub on first use and cached locally.
pub struct CodeEmbedder {
    #[cfg(feature = "embeddings")]
    backend: CodeEmbedderBackend,
    #[cfg(feature = "embeddings")]
    dimensions: usize,
    #[cfg(feature = "embeddings")]
    cache: Option<EmbeddingCache>,
}

#[cfg(feature = "embeddings")]
enum CodeEmbedderBackend {
    Bert(BertEmbedder),
    OpenAiCompat(OpenAiCompatEmbedder),
}

#[cfg(feature = "embeddings")]
struct BertEmbedder {
    model: BertModel,
    /// CPU-only BertModel, loaded lazily the first time the dispatcher
    /// routes a batch through the CPU path. Held behind a Mutex + OnceLock
    /// pattern because BertModel is `!Sync` for `forward` (mutable buffers
    /// internally) and we only need one-time construction. Heap-weighted:
    /// holding two models doubles resident weights (~260MB for BGE-small).
    #[cfg(feature = "embeddings")]
    cpu_model: std::sync::OnceLock<BertModel>,
    /// Captured arguments needed to build `cpu_model` on demand.
    #[cfg(feature = "embeddings")]
    cpu_model_source: std::sync::Mutex<Option<CpuModelSource>>,
    tokenizer: Tokenizer,
    /// Instruction prepended to queries for asymmetric retrievers (SweRank /
    /// nomic_bert). Empty for symmetric models like BGE.
    query_prefix: String,
}

#[cfg(feature = "embeddings")]
struct OpenAiCompatEmbedder {
    client: BlockingHttpClient,
    endpoint: String,
    model_id: String,
    api_key: Option<String>,
    dimensions: usize,
    request_overrides: serde_json::Map<String, serde_json::Value>,
    query_prefix: String,
    document_prefix: String,
}

#[cfg(feature = "embeddings")]
#[derive(Debug, Clone, PartialEq, Eq)]
enum EmbeddingInputRole {
    Query,
    Document,
}

/// Paths captured at model load time so the CPU twin can be constructed
/// lazily without re-downloading weights from HuggingFace. Config is stored
/// as the original JSON bytes because `BertConfig` is not `Clone`.
#[cfg(feature = "embeddings")]
#[derive(Debug)]
struct CpuModelSource {
    weights_path: PathBuf,
    config_json: String,
}

impl std::fmt::Debug for CodeEmbedder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CodeEmbedder")
            .field("dimensions", {
                #[cfg(feature = "embeddings")]
                {
                    &self.dimensions
                }
                #[cfg(not(feature = "embeddings"))]
                {
                    &0usize
                }
            })
            .finish()
    }
}

impl CodeEmbedder {
    /// Create a new embedder with the default code model.
    pub fn new() -> Result<Self, KinDbError> {
        let _span = tracing::info_span!("kindb.embedder.new").entered();
        #[cfg(feature = "embeddings")]
        kin_infer::init_performance_threads();
        #[cfg(feature = "embeddings")]
        {
            let provider = configured_embedding_provider();
            return match provider {
                EmbeddingProvider::Local => {
                    let model_id = env_nonempty("KIN_EMBED_MODEL_ID")
                        .unwrap_or_else(|| DEFAULT_MODEL_ID.to_string());
                    let revision = env_nonempty("KIN_EMBED_MODEL_REVISION")
                        .unwrap_or_else(|| DEFAULT_REVISION.to_string());
                    Self::with_model(&model_id, &revision)
                }
                EmbeddingProvider::OpenAiCompat { profile } => {
                    Self::with_openai_compat(OpenAiCompatConfig::from_profile(profile)?)
                }
            };
        }

        #[cfg(not(feature = "embeddings"))]
        {
            Err(disabled_error())
        }
    }

    /// Create with a specific HuggingFace model.
    #[cfg(feature = "embeddings")]
    pub fn with_model(model_id: &str, revision: &str) -> Result<Self, KinDbError> {
        let _span = tracing::info_span!(
            "kindb.embedder.with_model",
            model_id = %model_id,
            revision = %revision
        )
        .entered();
        let (config_path, tokenizer_path, weights_path) = if let Some(dir) =
            local_model_dir(model_id)
        {
            resolve_local_model_artifacts(&dir)?
        } else {
            let repo =
                Repo::with_revision(model_id.to_string(), RepoType::Model, revision.to_string());
            let api = Api::new().map_err(|e| {
                KinDbError::IndexError(format!("failed to initialise HuggingFace API: {e}"))
            })?;
            let api = api.repo(repo);

            let config_path = api.get("config.json").map_err(|e| {
                KinDbError::IndexError(format!("failed to download model config: {e}"))
            })?;
            let tokenizer_path = api.get("tokenizer.json").map_err(|e| {
                KinDbError::IndexError(format!("failed to download tokenizer: {e}"))
            })?;
            let weights_path = api.get("model.safetensors").map_err(|e| {
                KinDbError::IndexError(format!("failed to download model weights: {e}"))
            })?;
            (config_path, tokenizer_path, weights_path)
        };

        let config_data = std::fs::read_to_string(&config_path)
            .map_err(|e| KinDbError::IndexError(format!("failed to read config: {e}")))?;
        let config: BertConfig = parse_model_config(&config_data)
            .map_err(|e| KinDbError::IndexError(format!("failed to parse model config: {e}")))?;

        let dimensions = config.hidden_size;
        let query_prefix = local_query_prefix(model_id, config.model_type.as_deref());

        let mut tokenizer = Tokenizer::from_file(&tokenizer_path)
            .map_err(|e| KinDbError::IndexError(format!("failed to load tokenizer: {e}")))?;

        let pad_id = tokenizer
            .token_to_id("<pad>")
            .or_else(|| tokenizer.get_padding().map(|padding| padding.pad_id))
            .or(config.pad_token_id)
            .unwrap_or(0);
        let pad_token = tokenizer
            .id_to_token(pad_id)
            .unwrap_or_else(|| "<pad>".to_string());

        let max_length = config.effective_max_seq_len().min(EMBED_MAX_SEQ_LEN);
        tokenizer
            .with_truncation(Some(TruncationParams {
                direction: TruncationDirection::Right,
                max_length,
                strategy: TruncationStrategy::LongestFirst,
                stride: 0,
            }))
            .map_err(|e| KinDbError::IndexError(format!("failed to configure truncation: {e}")))?;
        tokenizer.with_padding(Some(PaddingParams {
            strategy: PaddingStrategy::BatchLongest,
            direction: PaddingDirection::Right,
            pad_to_multiple_of: None,
            pad_id,
            pad_type_id: 0,
            pad_token,
        }));

        let model = load_bert_model(&weights_path, config, false)
            .map_err(|e| KinDbError::IndexError(format!("failed to load BERT model: {e}")))?;

        let cache_namespace = model_namespace(
            model_id,
            revision,
            dimensions,
            [&config_path, &tokenizer_path, &weights_path],
        );

        let backend = BertEmbedder {
            model,
            cpu_model: std::sync::OnceLock::new(),
            cpu_model_source: std::sync::Mutex::new(Some(CpuModelSource {
                weights_path: weights_path.clone(),
                config_json: config_data,
            })),
            tokenizer,
            query_prefix,
        };

        Ok(Self {
            backend: CodeEmbedderBackend::Bert(backend),
            dimensions,
            cache: EmbeddingCache::new(cache_namespace, dimensions),
        })
    }

    /// Create with a specific HuggingFace model.
    #[cfg(not(feature = "embeddings"))]
    pub fn with_model(_model_id: &str, _revision: &str) -> Result<Self, KinDbError> {
        Err(disabled_error())
    }

    /// Create with an OpenAI-compatible embeddings endpoint.
    #[cfg(feature = "embeddings")]
    fn with_openai_compat(config: OpenAiCompatConfig) -> Result<Self, KinDbError> {
        let embedder = OpenAiCompatEmbedder::new(config)?;
        let dimensions = embedder.dimensions;
        let cache_namespace = embedder.cache_namespace();
        Ok(Self {
            backend: CodeEmbedderBackend::OpenAiCompat(embedder),
            dimensions,
            cache: EmbeddingCache::new(cache_namespace, dimensions),
        })
    }

    /// Generate an embedding for a single entity.
    ///
    /// The input text is composed as `"{name} {signature} {body_preview}"`.
    #[cfg(feature = "embeddings")]
    pub fn embed_entity(
        &self,
        name: &str,
        signature: &str,
        body: &str,
    ) -> Result<Vec<f32>, KinDbError> {
        let _span = tracing::info_span!(
            "kindb.embedder.embed_entity",
            name = %name
        )
        .entered();
        let text = format_entity_text(name, signature, body);
        let mut vecs = self.embed_batch(&[text])?;
        vecs.pop()
            .ok_or_else(|| KinDbError::IndexError("embedding returned empty result".into()))
    }

    /// Generate an embedding for a single entity.
    ///
    /// The input text is composed as `"{name} {signature} {body_preview}"`.
    #[cfg(not(feature = "embeddings"))]
    pub fn embed_entity(
        &self,
        _name: &str,
        _signature: &str,
        _body: &str,
    ) -> Result<Vec<f32>, KinDbError> {
        Err(disabled_error())
    }

    /// Embed a raw query string (for semantic search).
    #[cfg(feature = "embeddings")]
    pub fn embed_text(&self, text: &str) -> Result<Vec<f32>, KinDbError> {
        let _span =
            tracing::info_span!("kindb.embedder.embed_text", text_len = text.len()).entered();
        let mut vecs = self.embed_batch_for_role(&[text.to_string()], EmbeddingInputRole::Query)?;
        vecs.pop()
            .ok_or_else(|| KinDbError::IndexError("embedding returned empty result".into()))
    }

    /// Embed a raw query string (for semantic search).
    #[cfg(not(feature = "embeddings"))]
    pub fn embed_text(&self, _text: &str) -> Result<Vec<f32>, KinDbError> {
        Err(disabled_error())
    }

    /// Batch-embed multiple pre-formatted text strings as document roles.
    #[cfg(feature = "embeddings")]
    pub fn embed_batch(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, KinDbError> {
        let _span =
            tracing::info_span!("kindb.embedder.embed_batch", texts = texts.len()).entered();
        self.embed_batch_for_role(texts, EmbeddingInputRole::Document)
    }

    /// Batch-embed multiple raw queries as query roles.
    #[cfg(feature = "embeddings")]
    pub fn embed_query_batch(&self, queries: &[String]) -> Result<Vec<Vec<f32>>, KinDbError> {
        let _span =
            tracing::info_span!("kindb.embedder.embed_query_batch", queries = queries.len())
                .entered();
        self.embed_batch_for_role(queries, EmbeddingInputRole::Query)
    }

    #[cfg(feature = "embeddings")]
    fn embed_batch_for_role(
        &self,
        texts: &[String],
        role: EmbeddingInputRole,
    ) -> Result<Vec<Vec<f32>>, KinDbError> {
        if texts.is_empty() {
            return Ok(Vec::new());
        }

        let prepared_texts = self.prepare_inputs(texts, role);
        let mut cached_results: Vec<Option<Vec<f32>>> = vec![None; texts.len()];
        // Cache-missing inputs are borrowed from `prepared_texts`, never copied —
        // the inference backend only needs to read them.
        let mut missing_texts: Vec<&str> = Vec::new();
        let mut missing_slots: Vec<Vec<usize>> = Vec::new();
        let mut missing_keys = Vec::new();

        if let Some(cache) = self.cache.as_ref() {
            let mut missing_by_key: HashMap<String, usize> = HashMap::new();
            for (idx, text) in prepared_texts.iter().enumerate() {
                let key = cache.key_for_text(text);
                if let Some(vector) = cache.get_by_key(&key) {
                    cached_results[idx] = Some(vector);
                    continue;
                }

                match missing_by_key.get(&key).copied() {
                    Some(miss_idx) => missing_slots[miss_idx].push(idx),
                    None => {
                        missing_by_key.insert(key.clone(), missing_texts.len());
                        missing_keys.push(key);
                        missing_texts.push(text.as_str());
                        missing_slots.push(vec![idx]);
                    }
                }
            }
        } else {
            for (idx, text) in prepared_texts.iter().enumerate() {
                missing_texts.push(text.as_str());
                missing_slots.push(vec![idx]);
            }
        }

        if missing_texts.is_empty() {
            return cached_results
                .into_iter()
                .map(|vector| {
                    vector.ok_or_else(|| {
                        KinDbError::IndexError("embedding cache returned incomplete batch".into())
                    })
                })
                .collect();
        }

        let missing_results = self.embed_uncached_batch(&missing_texts)?;
        if missing_results.len() != missing_texts.len() {
            return Err(KinDbError::IndexError(format!(
                "embedding endpoint returned {} vectors for {} inputs",
                missing_results.len(),
                missing_texts.len()
            )));
        }

        for (miss_idx, vector) in missing_results.into_iter().enumerate() {
            let vector = sanitize_embedding(vector, self.dimensions, || {
                missing_texts.get(miss_idx).copied().unwrap_or("")
            });
            if let Some(cache) = self.cache.as_ref() {
                if let Some(key) = missing_keys.get(miss_idx) {
                    cache.put_by_key(key, &vector);
                }
            }

            for original_idx in &missing_slots[miss_idx] {
                cached_results[*original_idx] = Some(vector.clone());
            }
        }

        cached_results
            .into_iter()
            .map(|vector| {
                vector.ok_or_else(|| {
                    KinDbError::IndexError("embedding batch result order mismatch".into())
                })
            })
            .collect()
    }

    #[cfg(feature = "embeddings")]
    fn prepare_inputs<'a>(
        &self,
        texts: &'a [String],
        role: EmbeddingInputRole,
    ) -> Cow<'a, [String]> {
        match &self.backend {
            CodeEmbedderBackend::Bert(embedder) => embedder.prepare_inputs(texts, role),
            CodeEmbedderBackend::OpenAiCompat(embedder) => embedder.prepare_inputs(texts, role),
        }
    }

    #[cfg(feature = "embeddings")]
    fn embed_uncached_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, KinDbError> {
        match &self.backend {
            CodeEmbedderBackend::Bert(embedder) => {
                embedder.embed_uncached_batch(texts, self.dimensions)
            }
            CodeEmbedderBackend::OpenAiCompat(embedder) => embedder.embed_batch(texts),
        }
    }

    /// Batch-embed multiple pre-formatted text strings.
    #[cfg(not(feature = "embeddings"))]
    pub fn embed_batch(&self, _texts: &[String]) -> Result<Vec<Vec<f32>>, KinDbError> {
        Err(disabled_error())
    }

    /// Batch-embed multiple raw queries as query roles.
    #[cfg(not(feature = "embeddings"))]
    pub fn embed_query_batch(&self, _queries: &[String]) -> Result<Vec<Vec<f32>>, KinDbError> {
        Err(disabled_error())
    }

    /// The number of dimensions produced by this model.
    #[cfg(feature = "embeddings")]
    pub fn dimensions(&self) -> usize {
        self.dimensions
    }

    /// Local inference backend used by the embedder, when this is a local model.
    #[cfg(feature = "embeddings")]
    pub fn local_backend(&self) -> Option<GpuBackend> {
        match &self.backend {
            CodeEmbedderBackend::Bert(embedder) => Some(embedder.model.backend()),
            CodeEmbedderBackend::OpenAiCompat(_) => None,
        }
    }

    /// Whether the local embedder is actually using an accelerator.
    #[cfg(feature = "embeddings")]
    pub fn uses_local_accelerator(&self) -> bool {
        self.local_backend()
            .is_some_and(|backend| backend != GpuBackend::Cpu)
    }
}

#[cfg(feature = "embeddings")]
impl BertEmbedder {
    fn prepare_inputs<'a>(
        &self,
        texts: &'a [String],
        role: EmbeddingInputRole,
    ) -> Cow<'a, [String]> {
        if self.query_prefix.is_empty() || role != EmbeddingInputRole::Query {
            return Cow::Borrowed(texts);
        }
        Cow::Owned(
            texts
                .iter()
                .map(|text| format!("{}{}", self.query_prefix, text))
                .collect(),
        )
    }

    fn embed_uncached_batch(
        &self,
        texts: &[&str],
        dimensions: usize,
    ) -> Result<Vec<Vec<f32>>, KinDbError> {
        let encodings = {
            let _span =
                tracing::info_span!("kindb.embedder.tokenize_batch", texts = texts.len()).entered();
            self.tokenizer
                .encode_batch(texts.to_vec(), true)
                .map_err(|e| KinDbError::IndexError(format!("tokenization failed: {e}")))?
        };

        // Extract token ids + masks in parallel, then trim tokenizer right-padding
        // and length-sort so the budget packs by real tokenized length. The
        // parallel collect preserves input order and the sort is stable, so
        // equal-length entities keep their ascending original index — ordering is
        // identical to the prior serial extraction.
        let order: Vec<(usize, Vec<u32>, Vec<u32>)> = encodings
            .into_par_iter()
            .enumerate()
            .map(|(idx, encoding)| {
                (
                    idx,
                    encoding.get_ids().to_vec(),
                    encoding.get_attention_mask().to_vec(),
                )
            })
            .collect();
        let batch = encoded_batch_from_tokenized(order);

        let budget = BatchBudget::from_env(self.model.backend());

        let mode = hybrid_mode(self.model.backend());
        if mode != HybridMode::Off {
            return self.embed_hybrid(batch, dimensions, budget, texts.len(), mode);
        }

        let placed = self.process_encoded_subset(batch.as_slice(), dimensions, budget, None)?;
        scatter_placed(placed, texts.len())
    }

    fn embed_hybrid(
        &self,
        batch: EncodedBatch,
        dimensions: usize,
        budget: BatchBudget,
        total: usize,
        mode: HybridMode,
    ) -> Result<Vec<Vec<f32>>, KinDbError> {
        let placed = match mode {
            HybridMode::Off => unreachable!("embed_hybrid is only called for enabled modes"),
            HybridMode::SeqFloor => match plan_seqfloor_route(&batch.ids) {
                SeqFloorRoute::SplitByLength { cpu_from } => {
                    // A sequence longer than the truncation cap is present: keep
                    // the over-cap entities on the CPU twin and the rest on the GPU.
                    let (short, long) = batch.as_slice().split_at(cpu_from);
                    self.dispatch_concurrent(short, long, dimensions, budget, false)?
                }
                SeqFloorRoute::Degenerate => {
                    // Every entity sits at or under the truncation cap, so the
                    // sequence-length criterion can route nothing to the CPU twin.
                    // Record the degenerate split explicitly and make a real
                    // per-batch decision with the adaptive throughput split, which
                    // engages the twin with non-zero work when it measurably keeps
                    // up and records an explicit GPU-only ("hybrid not beneficial")
                    // decision when it does not — instead of silently collapsing to
                    // a single GPU arm that looks like a balanced hybrid.
                    hybrid_metrics::record_seqfloor_degenerate_batch();
                    self.dispatch_adaptive_balanced(batch.as_slice(), dimensions, budget, None)?
                }
            },
            HybridMode::Balanced { gpu_tput_ratio } => self.dispatch_adaptive_balanced(
                batch.as_slice(),
                dimensions,
                budget,
                gpu_tput_ratio,
            )?,
        };

        scatter_placed(placed, total)
    }

    /// Dispatch a batch through the adaptive throughput split.
    ///
    /// An explicit `gpu_tput_ratio` pins a fixed balanced split; otherwise the
    /// plan is adaptive — GPU-only unless a probe shows the CPU twin keeps up.
    /// Either way the per-batch decision is recorded through `hybrid_metrics` (a
    /// GPU-only decision bumps `single_side_batches` and the GPU counters; a real
    /// split bumps `hybrid_batches` and the CPU-twin counters), so the routing is
    /// provable after the fact rather than silently collapsing to one arm.
    fn dispatch_adaptive_balanced(
        &self,
        batch: EncodedSlice<'_>,
        dimensions: usize,
        budget: BatchBudget,
        gpu_tput_ratio: Option<f64>,
    ) -> Result<Vec<(usize, Vec<f32>)>, KinDbError> {
        let (plan, adaptive) = match gpu_tput_ratio {
            Some(fixed) => (
                adaptive_split::SplitPlan::Balanced {
                    ratio: fixed,
                    min_cpu_probe: 0,
                },
                false,
            ),
            None => (adaptive_split::plan(), true),
        };
        match plan {
            adaptive_split::SplitPlan::GpuOnly => {
                // The twin is not pulling its weight at this sequence length: embed
                // the whole batch on the GPU and record the decision rather than
                // fake-balancing a dragging split.
                let entities = batch.len() as u64;
                let tokens: u64 = batch.ids.iter().map(|ids| ids.len() as u64).sum();
                hybrid_metrics::record_single_side_batch();
                hybrid_metrics::record_gpu(entities, tokens);
                tracing::info!(
                    target: "kindb.embed.dispatch",
                    routing = "gpu_only_adaptive",
                    gpu_entities = entities,
                    gpu_tokens = tokens,
                    cpu_twin_used = false,
                    "embed_hybrid_dispatch"
                );
                self.process_encoded_subset(batch, dimensions, budget, None)
            }
            adaptive_split::SplitPlan::Balanced {
                ratio,
                min_cpu_probe,
            } => {
                let (metal_subset, cpu_subset) = balanced_partition(batch, ratio, min_cpu_probe);
                let metal_tokens: usize = metal_subset.ids.iter().map(|ids| ids.len()).sum();
                let cpu_tokens: usize = cpu_subset.ids.iter().map(|ids| ids.len()).sum();
                tracing::info!(
                    target: "kindb.embed.dispatch",
                    metal_entities = metal_subset.len(),
                    cpu_entities = cpu_subset.len(),
                    metal_tokens = metal_tokens,
                    cpu_tokens = cpu_tokens,
                    gpu_tput_ratio = ratio,
                    adaptive = adaptive,
                    cpu_threads = rayon::current_num_threads(),
                    "embed_hybrid_balance"
                );
                self.dispatch_concurrent(
                    metal_subset.as_slice(),
                    cpu_subset.as_slice(),
                    dimensions,
                    budget,
                    adaptive,
                )
            }
        }
    }

    fn process_encoded_subset(
        &self,
        batch: EncodedSlice<'_>,
        dimensions: usize,
        budget: BatchBudget,
        backend_override: Option<EmbedBackendChoice>,
    ) -> Result<Vec<(usize, Vec<f32>)>, KinDbError> {
        // Pack the length-sorted run into sub-batch ranges up front.
        let mut ranges: Vec<(usize, usize, usize)> = Vec::new();
        let mut start = 0usize;
        while start < batch.len() {
            let (end, longest) = budget.next_batch(batch.ids, start);
            ranges.push((start, end, longest));
            start = end;
        }

        // Parallel CPU dispatch: when the work is pinned to the CPU twin under the
        // throughput profile, embed the sub-batches concurrently across the idle
        // cores rather than one at a time on a single thread (the case that pegs a
        // single core on all-long code corpora). Each sub-batch forward is
        // independent and deterministic, and results are scattered by original
        // index, so the output is identical to the serial path. Requires the twin
        // to be available so every forward runs on the CPU model — never a
        // concurrent submission to the shared Metal model. Width is the ambient
        // rayon pool (sized to the resource plan's rayon_threads by the host
        // binary), so this does not oversubscribe and is not hardcoded.
        let parallel_cpu = ranges.len() > 1
            && matches!(backend_override, Some(EmbedBackendChoice::Cpu { .. }))
            && resource_profile_is_throughput()
            && self.cpu_model().is_ok();

        if parallel_cpu {
            hybrid_metrics::record_cpu_parallel_batch();
            tracing::info!(
                target: "kindb.embed.dispatch",
                routing = "cpu_parallel",
                sub_batches = ranges.len(),
                entities = batch.len(),
                rayon_threads = rayon::current_num_threads(),
                "embed_cpu_parallel"
            );
            let backend_choice = EmbedBackendChoice::Cpu {
                reason: "hybrid_cpu_parallel",
            };
            let chunks = ranges
                .par_iter()
                .map(|&(s, e, longest)| {
                    self.process_chunk(
                        backend_choice,
                        &batch.ids[s..e],
                        &batch.masks[s..e],
                        &batch.idx[s..e],
                        longest,
                        dimensions,
                    )
                })
                .collect::<Result<Vec<_>, KinDbError>>()?;
            let mut placed: Vec<(usize, Vec<f32>)> = Vec::with_capacity(batch.len());
            for chunk in chunks {
                placed.extend(chunk);
            }
            return Ok(placed);
        }

        let mut placed: Vec<(usize, Vec<f32>)> = Vec::with_capacity(batch.len());
        for &(s, e, longest) in &ranges {
            let backend_choice = backend_override.unwrap_or_else(|| resolve_embed_backend(longest));
            placed.extend(self.process_chunk(
                backend_choice,
                &batch.ids[s..e],
                &batch.masks[s..e],
                &batch.idx[s..e],
                longest,
                dimensions,
            )?);
        }
        Ok(placed)
    }

    /// Embed one sub-batch on the chosen backend and return its `(original_idx,
    /// vector)` pairs.
    ///
    /// The non-finite retry runs on the SAME model that produced the batch, so a
    /// CPU-twin sub-batch never falls back onto the shared Metal model — which is
    /// what makes concurrent dispatch of CPU sub-batches safe.
    fn process_chunk(
        &self,
        backend_choice: EmbedBackendChoice,
        token_ids: &[Vec<u32>],
        attention_masks: &[Vec<u32>],
        indices: &[usize],
        longest: usize,
        dimensions: usize,
    ) -> Result<Vec<(usize, Vec<f32>)>, KinDbError> {
        let count = token_ids.len();
        let trace_start = batch_trace::enabled().then(std::time::Instant::now);
        let (vectors, forward_model): (Vec<Vec<f32>>, &BertModel) = match backend_choice {
            EmbedBackendChoice::Metal { reason } => {
                if let Some((attention_area, attention_area_cap)) =
                    metal_hard_guard_rejection(count, longest)
                {
                    let guard_reason = match reason {
                        "env_forced" => "env_forced_memory_guard",
                        "hybrid_metal" => "hybrid_metal_memory_guard",
                        "hybrid_serial_primary" => "hybrid_serial_memory_guard",
                        _ => "metal_memory_guard_cpu",
                    };
                    tracing::warn!(
                        target: "kindb.embed.dispatch",
                        batch_size = count,
                        max_seq = longest,
                        attention_area = attention_area,
                        attention_area_cap = attention_area_cap,
                        backend = "cpu",
                        reason = guard_reason,
                        "embed_metal_memory_guard"
                    );
                    let model = self.cpu_model().map_err(|e| {
                        KinDbError::IndexError(format!(
                            "Metal memory guard declined unsafe batch \
                             (batch_size={count}, max_seq={longest}, \
                             attention_area={attention_area}, cap={attention_area_cap}) \
                             but CPU twin is unavailable: {e}"
                        ))
                    })?;
                    let vectors =
                        model
                            .forward_batched(token_ids, attention_masks)
                            .map_err(|e| {
                                KinDbError::IndexError(format!(
                                    "inference failed (CPU retry after Metal memory guard): {e}"
                                ))
                            })?;
                    (vectors, model)
                } else {
                    tracing::info!(
                        target: "kindb.embed.dispatch",
                        batch_size = count,
                        max_seq = longest,
                        backend = "metal",
                        reason = reason,
                        "embed_dispatch"
                    );
                    let _span = tracing::info_span!(
                        "kindb.embedder.forward_batch",
                        batch = count,
                        longest = longest
                    )
                    .entered();
                    let metal_forward = if metal_oom_injection_armed() {
                        Err(kin_infer::InferError::OutOfMemory(
                            "synthetic Metal OOM (KIN_EMBED_TEST_FORCE_METAL_OOM)".to_string(),
                        ))
                    } else {
                        self.model.forward_batched(token_ids, attention_masks)
                    };
                    let vectors = match metal_forward {
                        Ok(v) => v,
                        Err(kin_infer::InferError::OutOfMemory(msg)) => {
                            // Metal ran out of device memory mid-forward. Rather
                            // than failing the index, degrade this batch to the CPU
                            // twin and retry once. If the twin is unavailable, fail
                            // loud instead of submitting the same unsafe batch back
                            // to the primary Metal model.
                            tracing::warn!(
                                target: "kindb.embed.dispatch",
                                error = %msg,
                                batch_size = count,
                                max_seq = longest,
                                "metal embed out-of-memory; retrying batch on CPU"
                            );
                            let model = self.cpu_model().map_err(|e| {
                                KinDbError::IndexError(format!(
                                    "Metal OOM for batch \
                                     (batch_size={count}, max_seq={longest}) \
                                     and CPU twin is unavailable: {e}"
                                ))
                            })?;
                            model
                                .forward_batched(token_ids, attention_masks)
                                .map_err(|e| {
                                    KinDbError::IndexError(format!(
                                        "inference failed (CPU retry after Metal OOM): {e}"
                                    ))
                                })?
                        }
                        Err(e) => {
                            return Err(KinDbError::IndexError(format!("inference failed: {e}")));
                        }
                    };
                    (vectors, &self.model)
                }
            }
            EmbedBackendChoice::Cpu { reason } => {
                tracing::info!(
                    target: "kindb.embed.dispatch",
                    batch_size = count,
                    max_seq = longest,
                    backend = "cpu",
                    reason = reason,
                    "embed_dispatch"
                );
                let _span = tracing::info_span!(
                    "kindb.embedder.forward_cpu_path",
                    batch = count,
                    longest = longest
                )
                .entered();
                let cpu_model = match self.cpu_model() {
                    Ok(m) => Some(m),
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "cpu_model unavailable; falling back to primary model for this chunk"
                        );
                        None
                    }
                };
                let model = cpu_model.unwrap_or(&self.model);
                let vectors = model
                    .forward_batched(token_ids, attention_masks)
                    .map_err(|e| KinDbError::IndexError(format!("inference failed: {e}")))?;
                (vectors, model)
            }
        };

        if let Some(start) = trace_start {
            batch_trace::record_batch(count, longest, token_ids, start.elapsed());
        }

        // Defense in depth: if the dispatched path still returned any non-finite
        // vectors, retry per-sample through the single-input forward path of the
        // SAME model before the outer sanitizer handles any remaining bad vectors.
        let vectors = if vectors.iter().any(|v| !v.iter().all(|x| x.is_finite())) {
            tracing::warn!(
                batch = count,
                longest = longest,
                "dispatched path produced non-finite vectors; retrying via single-input forward path"
            );
            let mut retried = Vec::with_capacity(count);
            for (ids, mask) in token_ids.iter().zip(attention_masks.iter()) {
                let out = forward_model
                    .forward(std::slice::from_ref(ids), std::slice::from_ref(mask))
                    .map_err(|e| KinDbError::IndexError(format!("inference failed: {e}")))?;
                retried.push(out.into_iter().next().ok_or_else(|| {
                    KinDbError::IndexError("forward returned empty batch".into())
                })?);
            }
            retried
        } else {
            vectors
        };

        let mut chunk: Vec<(usize, Vec<f32>)> = Vec::with_capacity(count);
        for (original_idx, vector) in indices.iter().zip(vectors) {
            if vector.len() != dimensions {
                return Err(KinDbError::IndexError(format!(
                    "embedding returned {} dimensions, expected {}",
                    vector.len(),
                    dimensions
                )));
            }
            chunk.push((*original_idx, vector));
        }
        Ok(chunk)
    }

    fn dispatch_concurrent(
        &self,
        metal_side: EncodedSlice<'_>,
        cpu_side: EncodedSlice<'_>,
        dimensions: usize,
        budget: BatchBudget,
        record_adaptive: bool,
    ) -> Result<Vec<(usize, Vec<f32>)>, KinDbError> {
        let tokens =
            |side: EncodedSlice<'_>| -> u64 { side.ids.iter().map(|ids| ids.len() as u64).sum() };
        let metal_entities = metal_side.len() as u64;
        let cpu_entities = cpu_side.len() as u64;
        let metal_tokens = tokens(metal_side);
        let cpu_tokens = tokens(cpu_side);

        if metal_side.is_empty() {
            // The balanced split placed the whole batch on the CPU side — record
            // that decision explicitly rather than silently re-routing it. Run it
            // on the CPU twin (the otherwise-idle cores); passing `None` would
            // defer to the auto resolver, which routes to Metal and would send a
            // CPU-destined subset back to the GPU. There is no concurrency in this
            // branch, so deferring to the auto resolver when the twin is missing
            // is still safe.
            let twin_available = self.cpu_model().is_ok();
            hybrid_metrics::record_single_side_batch();
            if twin_available {
                hybrid_metrics::record_cpu_twin(cpu_entities, cpu_tokens);
            } else {
                hybrid_metrics::record_twin_unavailable_batch();
                hybrid_metrics::record_gpu(cpu_entities, cpu_tokens);
            }
            tracing::info!(
                target: "kindb.embed.dispatch",
                routing = "cpu_only",
                cpu_entities = cpu_entities,
                cpu_tokens = cpu_tokens,
                cpu_twin_used = twin_available,
                "embed_hybrid_dispatch"
            );
            let cpu_override = twin_available.then_some(EmbedBackendChoice::Cpu {
                reason: "hybrid_cpu_only",
            });
            return self.process_encoded_subset(cpu_side, dimensions, budget, cpu_override);
        }
        if cpu_side.is_empty() {
            // Whole batch is short enough to stay on the GPU — record the
            // single-arm decision and run it there.
            hybrid_metrics::record_single_side_batch();
            hybrid_metrics::record_gpu(metal_entities, metal_tokens);
            tracing::info!(
                target: "kindb.embed.dispatch",
                routing = "gpu_only",
                gpu_entities = metal_entities,
                gpu_tokens = metal_tokens,
                cpu_twin_used = false,
                "embed_hybrid_dispatch"
            );
            return self.process_encoded_subset(metal_side, dimensions, budget, None);
        }

        // Hybrid concurrency is only safe when the CPU arm runs on its OWN model
        // (the CPU twin) — a different backend than the primary Metal model. If the
        // twin is unavailable, process_encoded_subset's CPU path falls back to
        // &self.model, so BOTH rayon::join arms would submit to the single Metal
        // model concurrently; on unified memory that races the shared command queue
        // and buffer pool and corrupts embeddings. In that case process the whole
        // set SERIALLY on the primary model instead (slower, but correct).
        if let Err(e) = self.cpu_model() {
            hybrid_metrics::record_twin_unavailable_batch();
            hybrid_metrics::record_gpu(metal_entities + cpu_entities, metal_tokens + cpu_tokens);
            tracing::warn!(
                target: "kindb.embed.dispatch",
                routing = "serial_primary",
                error = %e,
                gpu_entities = metal_entities + cpu_entities,
                cpu_twin_used = false,
                fallback_reason = "cpu_twin_unavailable",
                "cpu twin unavailable; processing hybrid set serially on the primary model to avoid concurrent shared-model submission"
            );
            let mut merged = self.process_encoded_subset(
                metal_side,
                dimensions,
                budget,
                Some(EmbedBackendChoice::Metal {
                    reason: "hybrid_serial_primary",
                }),
            )?;
            merged.extend(self.process_encoded_subset(
                cpu_side,
                dimensions,
                budget,
                Some(EmbedBackendChoice::Metal {
                    reason: "hybrid_serial_primary",
                }),
            )?);
            return Ok(merged);
        }

        // Both arms run concurrently: GPU on the primary Metal model, CPU twin on
        // the idle cores. Record the actual per-arm work so the twin's share is
        // provable after the fact.
        hybrid_metrics::record_hybrid_batch();
        hybrid_metrics::record_gpu(metal_entities, metal_tokens);
        hybrid_metrics::record_cpu_twin(cpu_entities, cpu_tokens);
        tracing::info!(
            target: "kindb.embed.dispatch",
            routing = "concurrent",
            gpu_entities = metal_entities,
            gpu_tokens = metal_tokens,
            cpu_entities = cpu_entities,
            cpu_tokens = cpu_tokens,
            cpu_twin_used = true,
            "embed_hybrid_dispatch"
        );
        let (metal_timed, cpu_timed) = rayon::join(
            || {
                let started = std::time::Instant::now();
                let result = self.process_encoded_subset(
                    metal_side,
                    dimensions,
                    budget,
                    Some(EmbedBackendChoice::Metal {
                        reason: "hybrid_metal",
                    }),
                );
                (result, started.elapsed())
            },
            || {
                let started = std::time::Instant::now();
                let result = self.process_encoded_subset(
                    cpu_side,
                    dimensions,
                    budget,
                    Some(EmbedBackendChoice::Cpu {
                        reason: "hybrid_cpu",
                    }),
                );
                (result, started.elapsed())
            },
        );
        let (metal_res, metal_secs) = metal_timed;
        let (cpu_res, cpu_secs) = cpu_timed;

        // Feed the measured per-arm throughput back into the adaptive ratio so the
        // next split tracks the real GPU-vs-CPU speed at this sequence length.
        if record_adaptive {
            adaptive_split::record(
                metal_tokens,
                metal_secs.as_secs_f64(),
                cpu_tokens,
                cpu_secs.as_secs_f64(),
            );
            let (ratio, gpu_tps, cpu_tps, cpu_beneficial, samples) = adaptive_split::snapshot();
            tracing::info!(
                target: "kindb.embed.dispatch",
                gpu_tokens_per_sec = gpu_tps,
                cpu_tokens_per_sec = cpu_tps,
                adaptive_ratio = ratio,
                cpu_beneficial = cpu_beneficial,
                samples = samples,
                "embed_hybrid_adaptive"
            );
        }

        let mut merged = metal_res?;
        merged.extend(cpu_res?);
        Ok(merged)
    }

    /// Lazily construct (or return) the CPU-only BertModel twin.
    ///
    /// Construction goes through `load_bert_model(.., force_cpu = true)`, which
    /// pins this one load to `CpuCompute` via an explicit kin-infer backend
    /// argument, so the primary (GPU) model and any concurrent load are
    /// unaffected. The twin runs the CPU arm of the throughput-profile hybrid
    /// split.
    #[cfg(feature = "embeddings")]
    fn cpu_model(&self) -> Result<&BertModel, KinDbError> {
        if let Some(model) = self.cpu_model.get() {
            return Ok(model);
        }

        // Take the source out of the Mutex; we only need it once. After
        // successful init, the OnceLock holds the model and the source is
        // dropped.
        let source = {
            let mut guard = self
                .cpu_model_source
                .lock()
                .map_err(|_| KinDbError::IndexError("cpu_model_source mutex poisoned".into()))?;
            guard.take()
        };

        let built = if let Some(source) = source {
            let config: BertConfig = parse_model_config(&source.config_json).map_err(|e| {
                KinDbError::IndexError(format!("cpu twin config parse failed: {e}"))
            })?;

            // Pin this single load to the CPU backend. load_bert_model passes
            // the backend explicitly to kin-infer, so the primary (GPU) model
            // and any concurrent load are unaffected.
            let cpu_model = load_bert_model(&source.weights_path, config, true).map_err(|e| {
                KinDbError::IndexError(format!("failed to load CPU BERT twin: {e}"))
            })?;
            tracing::info!(
                backend = %cpu_model.backend(),
                "kindb.embed: CPU BertModel twin loaded for long-sequence fallback"
            );
            cpu_model
        } else {
            return Err(KinDbError::IndexError(
                "cpu_model_source already consumed without a successful init".into(),
            ));
        };

        // Race: another thread may have beaten us; `set` will return Err on
        // that second attempt. Either way, `get` afterward yields the
        // winning instance.
        let _ = self.cpu_model.set(built);
        self.cpu_model
            .get()
            .ok_or_else(|| KinDbError::IndexError("cpu_model init failed".into()))
    }
}

#[cfg(feature = "embeddings")]
#[derive(Debug, Clone, PartialEq, Eq)]
enum EmbeddingProvider {
    Local,
    OpenAiCompat { profile: OpenAiCompatProfile },
}

#[cfg(feature = "embeddings")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OpenAiCompatProfile {
    OpenAi,
    LmStudio,
    Compatible,
}

#[cfg(feature = "embeddings")]
#[derive(Debug, Clone)]
struct OpenAiCompatConfig {
    provider_label: String,
    base_url: String,
    model_id: String,
    api_key: Option<String>,
    dimensions: Option<usize>,
    send_dimensions: bool,
    timeout_secs: u64,
    request_overrides: serde_json::Map<String, serde_json::Value>,
    query_prefix: String,
    document_prefix: String,
}

#[cfg(feature = "embeddings")]
impl OpenAiCompatConfig {
    fn from_profile(profile: OpenAiCompatProfile) -> Result<Self, KinDbError> {
        let provider_label = match profile {
            OpenAiCompatProfile::OpenAi => "openai",
            OpenAiCompatProfile::LmStudio => "lmstudio",
            OpenAiCompatProfile::Compatible => "openai-compatible",
        }
        .to_string();

        let default_base_url = match profile {
            OpenAiCompatProfile::OpenAi => "https://api.openai.com/v1",
            OpenAiCompatProfile::LmStudio | OpenAiCompatProfile::Compatible => {
                "http://localhost:1234/v1"
            }
        };
        let default_model = match profile {
            OpenAiCompatProfile::OpenAi => DEFAULT_OPENAI_EMBED_MODEL_ID,
            OpenAiCompatProfile::LmStudio | OpenAiCompatProfile::Compatible => {
                DEFAULT_LMSTUDIO_EMBED_MODEL_ID
            }
        };
        let base_url = env_nonempty("KIN_EMBED_OPENAI_BASE_URL")
            .or_else(|| env_nonempty("KIN_EMBED_BASE_URL"))
            .unwrap_or_else(|| default_base_url.to_string());
        let model_id = env_nonempty("KIN_EMBED_OPENAI_MODEL")
            .or_else(|| env_nonempty("KIN_EMBED_MODEL_ID"))
            .unwrap_or_else(|| default_model.to_string());
        let api_key = env_nonempty("KIN_EMBED_OPENAI_API_KEY").or_else(|| {
            if matches!(profile, OpenAiCompatProfile::OpenAi) {
                env_nonempty("OPENAI_API_KEY")
            } else {
                None
            }
        });
        let dimensions = env_nonempty("KIN_EMBED_OPENAI_DIMENSIONS")
            .map(|value| parse_positive_usize("KIN_EMBED_OPENAI_DIMENSIONS", &value))
            .transpose()?;
        let timeout_secs = env_nonempty("KIN_EMBED_OPENAI_TIMEOUT_SECS")
            .map(|value| parse_positive_u64("KIN_EMBED_OPENAI_TIMEOUT_SECS", &value))
            .transpose()?
            .unwrap_or(120);
        let send_dimensions = env_flag("KIN_EMBED_OPENAI_SEND_DIMENSIONS");
        let request_overrides = match env_nonempty("KIN_EMBED_OPENAI_REQUEST_JSON") {
            Some(value) => parse_json_object_env("KIN_EMBED_OPENAI_REQUEST_JSON", &value)?,
            None => serde_json::Map::new(),
        };
        let (default_query_prefix, default_document_prefix) =
            default_openai_embedding_prefixes(&model_id);
        let query_prefix =
            env_nonempty("KIN_EMBED_OPENAI_QUERY_PREFIX").unwrap_or(default_query_prefix);
        let document_prefix =
            env_nonempty("KIN_EMBED_OPENAI_DOCUMENT_PREFIX").unwrap_or(default_document_prefix);

        Ok(Self {
            provider_label,
            base_url,
            model_id,
            api_key,
            dimensions,
            send_dimensions,
            timeout_secs,
            request_overrides,
            query_prefix,
            document_prefix,
        })
    }

    fn endpoint(&self) -> String {
        let trimmed = self.base_url.trim_end_matches('/');
        if trimmed.ends_with("/embeddings") {
            trimmed.to_string()
        } else {
            format!("{trimmed}/embeddings")
        }
    }

    fn provider_identity(&self) -> String {
        format!(
            "{}:{}",
            self.provider_label,
            self.base_url.trim_end_matches('/')
        )
    }

    fn request_overrides_fingerprint(&self) -> String {
        let mut hasher = Sha256::new();
        if let Ok(encoded) = serde_json::to_vec(&self.request_overrides) {
            hasher.update(encoded);
        }
        let digest = hex::encode(hasher.finalize());
        digest[..16].to_string()
    }

    fn runtime_revision(&self) -> String {
        format!(
            "openai-compatible;query_prefix={};document_prefix={};send_dimensions={};request={}",
            self.query_prefix,
            self.document_prefix,
            self.send_dimensions,
            self.request_overrides_fingerprint()
        )
    }
}

#[cfg(feature = "embeddings")]
impl OpenAiCompatEmbedder {
    fn new(config: OpenAiCompatConfig) -> Result<Self, KinDbError> {
        let client = BlockingHttpClient::builder()
            .timeout(std::time::Duration::from_secs(config.timeout_secs))
            .build()
            .map_err(|e| {
                KinDbError::IndexError(format!("failed to build embeddings HTTP client: {e}"))
            })?;
        let mut embedder = Self {
            client,
            endpoint: config.endpoint(),
            model_id: config.model_id,
            api_key: config.api_key,
            dimensions: config.dimensions.unwrap_or(0),
            request_overrides: config.request_overrides,
            query_prefix: config.query_prefix,
            document_prefix: config.document_prefix,
        };
        if config.send_dimensions {
            if let Some(dimensions) = config.dimensions {
                embedder
                    .request_overrides
                    .insert("dimensions".to_string(), serde_json::json!(dimensions));
            }
        }
        if embedder.dimensions == 0 {
            let probe = embedder.embed_batch_raw(&["kin embedding dimension probe"])?;
            embedder.dimensions = probe.first().map(Vec::len).ok_or_else(|| {
                KinDbError::IndexError("embedding probe returned no vectors".into())
            })?;
        }
        Ok(embedder)
    }

    fn prepare_inputs<'a>(
        &self,
        texts: &'a [String],
        role: EmbeddingInputRole,
    ) -> Cow<'a, [String]> {
        let prefix = match role {
            EmbeddingInputRole::Query => &self.query_prefix,
            EmbeddingInputRole::Document => &self.document_prefix,
        };
        if prefix.is_empty() {
            return Cow::Borrowed(texts);
        }
        Cow::Owned(texts.iter().map(|text| format!("{prefix}{text}")).collect())
    }

    fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, KinDbError> {
        let vectors = self.embed_batch_raw(texts)?;
        for vector in &vectors {
            if vector.len() != self.dimensions {
                return Err(KinDbError::IndexError(format!(
                    "embedding endpoint returned {} dimensions, expected {}",
                    vector.len(),
                    self.dimensions
                )));
            }
        }
        Ok(vectors)
    }

    fn embed_batch_raw(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, KinDbError> {
        let mut body = serde_json::Map::new();
        body.insert(
            "model".to_string(),
            serde_json::Value::String(self.model_id.clone()),
        );
        body.insert("input".to_string(), serde_json::json!(texts));
        for (key, value) in &self.request_overrides {
            if matches!(key.as_str(), "model" | "input") {
                return Err(KinDbError::IndexError(format!(
                    "KIN_EMBED_OPENAI_REQUEST_JSON cannot override reserved embeddings field '{key}'"
                )));
            }
            body.insert(key.clone(), value.clone());
        }

        let mut req = self
            .client
            .post(&self.endpoint)
            .json(&serde_json::Value::Object(body));
        if let Some(api_key) = self.api_key.as_ref() {
            req = req.bearer_auth(api_key);
        }

        let resp = req
            .send()
            .map_err(|e| KinDbError::IndexError(format!("embedding request failed: {e}")))?;
        let status = resp.status();
        let text = resp
            .text()
            .map_err(|e| KinDbError::IndexError(format!("embedding response read failed: {e}")))?;
        if !status.is_success() {
            return Err(KinDbError::IndexError(format!(
                "embedding endpoint error (HTTP {status}): {text}"
            )));
        }
        parse_openai_embedding_response(&text, texts.len())
    }

    fn cache_namespace(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(EMBEDDING_CACHE_PIPELINE_EPOCH.as_bytes());
        hasher.update([0]);
        hasher.update(self.endpoint.as_bytes());
        hasher.update([0]);
        hasher.update(self.model_id.as_bytes());
        hasher.update([0]);
        hasher.update(self.dimensions.to_le_bytes());
        hasher.update([0]);
        hasher.update(self.query_prefix.as_bytes());
        hasher.update([0]);
        hasher.update(self.document_prefix.as_bytes());
        hasher.update([0]);
        if !self.request_overrides.is_empty() {
            if let Ok(encoded) = serde_json::to_vec(&self.request_overrides) {
                hasher.update(encoded);
            }
        }
        let digest = hex::encode(hasher.finalize());
        format!(
            "{}-{}",
            sanitize_component(&format!("{}-{}", self.endpoint, self.model_id)),
            &digest[..16]
        )
    }
}

#[cfg(feature = "embeddings")]
#[derive(Debug, Deserialize)]
struct OpenAiEmbeddingResponse {
    data: Vec<OpenAiEmbeddingData>,
}

#[cfg(feature = "embeddings")]
#[derive(Debug, Deserialize)]
struct OpenAiEmbeddingData {
    embedding: Vec<f32>,
    #[serde(default)]
    index: Option<usize>,
}

#[cfg(feature = "embeddings")]
fn parse_openai_embedding_response(
    text: &str,
    expected: usize,
) -> Result<Vec<Vec<f32>>, KinDbError> {
    let response: OpenAiEmbeddingResponse = serde_json::from_str(text)
        .map_err(|e| KinDbError::IndexError(format!("invalid embeddings JSON: {e}")))?;
    if response.data.len() != expected {
        return Err(KinDbError::IndexError(format!(
            "embedding endpoint returned {} vectors for {} inputs",
            response.data.len(),
            expected
        )));
    }
    let mut ordered: Vec<Option<Vec<f32>>> = vec![None; expected];
    for (fallback_idx, item) in response.data.into_iter().enumerate() {
        let index = item.index.unwrap_or(fallback_idx);
        if index >= expected {
            return Err(KinDbError::IndexError(format!(
                "embedding response index {index} out of range for {expected} inputs"
            )));
        }
        if ordered[index].replace(item.embedding).is_some() {
            return Err(KinDbError::IndexError(format!(
                "embedding response duplicated index {index}"
            )));
        }
    }
    ordered
        .into_iter()
        .enumerate()
        .map(|(index, vector)| {
            vector.ok_or_else(|| {
                KinDbError::IndexError(format!("embedding response missing index {index}"))
            })
        })
        .collect()
}

#[cfg(feature = "embeddings")]
fn configured_embedding_provider() -> EmbeddingProvider {
    match env_nonempty("KIN_EMBED_PROVIDER")
        .unwrap_or_else(|| "local".to_string())
        .trim()
        .to_ascii_lowercase()
        .as_str()
    {
        "local" | "hf" | "huggingface" | "bge" => EmbeddingProvider::Local,
        "openai" => EmbeddingProvider::OpenAiCompat {
            profile: OpenAiCompatProfile::OpenAi,
        },
        "lmstudio" | "lm-studio" => EmbeddingProvider::OpenAiCompat {
            profile: OpenAiCompatProfile::LmStudio,
        },
        "openai-compat" | "openai-compatible" | "compatible" => EmbeddingProvider::OpenAiCompat {
            profile: OpenAiCompatProfile::Compatible,
        },
        other => {
            tracing::warn!(
                provider = %other,
                "unknown KIN_EMBED_PROVIDER value, falling back to local embeddings"
            );
            EmbeddingProvider::Local
        }
    }
}

#[cfg(feature = "embeddings")]
fn env_nonempty(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[cfg(feature = "embeddings")]
fn env_flag(name: &str) -> bool {
    env_nonempty(name)
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

#[cfg(feature = "embeddings")]
fn parse_positive_usize(name: &str, value: &str) -> Result<usize, KinDbError> {
    let parsed = value
        .parse::<usize>()
        .map_err(|e| KinDbError::IndexError(format!("{name} must be a positive integer: {e}")))?;
    if parsed == 0 {
        return Err(KinDbError::IndexError(format!(
            "{name} must be a positive integer"
        )));
    }
    Ok(parsed)
}

#[cfg(feature = "embeddings")]
fn parse_positive_u64(name: &str, value: &str) -> Result<u64, KinDbError> {
    let parsed = value
        .parse::<u64>()
        .map_err(|e| KinDbError::IndexError(format!("{name} must be a positive integer: {e}")))?;
    if parsed == 0 {
        return Err(KinDbError::IndexError(format!(
            "{name} must be a positive integer"
        )));
    }
    Ok(parsed)
}

#[cfg(feature = "embeddings")]
fn parse_json_object_env(
    name: &str,
    value: &str,
) -> Result<serde_json::Map<String, serde_json::Value>, KinDbError> {
    let parsed: serde_json::Value = serde_json::from_str(value)
        .map_err(|e| KinDbError::IndexError(format!("{name} must be JSON: {e}")))?;
    parsed
        .as_object()
        .cloned()
        .ok_or_else(|| KinDbError::IndexError(format!("{name} must be a JSON object")))
}

/// When `model_id` resolves to an existing local directory, return it so model
/// artifacts load from disk instead of HuggingFace Hub. Lets the bench point at
/// a local SweRank checkout via `KIN_EMBED_MODEL_ID=/path/to/model` while a bare
/// repo id (e.g. `BAAI/bge-small-en-v1.5`) still downloads as before.
#[cfg(feature = "embeddings")]
pub(crate) fn local_model_dir(model_id: &str) -> Option<PathBuf> {
    let path = Path::new(model_id);
    if path.is_dir() {
        Some(path.to_path_buf())
    } else {
        None
    }
}

#[cfg(feature = "embeddings")]
pub(crate) fn resolve_local_model_artifacts(
    dir: &Path,
) -> Result<(PathBuf, PathBuf, PathBuf), KinDbError> {
    let require = |name: &str| -> Result<PathBuf, KinDbError> {
        let candidate = dir.join(name);
        if candidate.is_file() {
            Ok(candidate)
        } else {
            Err(KinDbError::IndexError(format!(
                "local model directory {} is missing {name}",
                dir.display()
            )))
        }
    };
    Ok((
        require("config.json")?,
        require("tokenizer.json")?,
        require("model.safetensors")?,
    ))
}

#[cfg(feature = "embeddings")]
fn local_query_prefix(model_id: &str, model_type: Option<&str>) -> String {
    let lower_id = model_id.to_ascii_lowercase();
    if lower_id.contains("swerank") {
        SWERANK_QUERY_PREFIX.to_string()
    } else {
        match model_type.map(str::trim) {
            Some("nomic_bert") | Some("nomic-bert") => SWERANK_QUERY_PREFIX.to_string(),
            _ => String::new(),
        }
    }
}

#[cfg(feature = "embeddings")]
fn default_openai_embedding_prefixes(model_id: &str) -> (String, String) {
    let lower = model_id.to_ascii_lowercase();
    if lower.contains("nomic-embed") || lower.contains("nomic_embed") {
        (
            "search_query: ".to_string(),
            "search_document: ".to_string(),
        )
    } else {
        (String::new(), String::new())
    }
}

#[cfg(feature = "embeddings")]
pub fn configured_embedding_runtime() -> EmbeddingRuntimeConfig {
    match configured_embedding_provider() {
        EmbeddingProvider::Local => EmbeddingRuntimeConfig {
            provider: "local".to_string(),
            model_id: env_nonempty("KIN_EMBED_MODEL_ID")
                .unwrap_or_else(|| DEFAULT_MODEL_ID.to_string()),
            revision: env_nonempty("KIN_EMBED_MODEL_REVISION")
                .unwrap_or_else(|| DEFAULT_REVISION.to_string()),
            dimensions: None,
            pipeline_epoch: EMBEDDING_CACHE_PIPELINE_EPOCH.to_string(),
        },
        EmbeddingProvider::OpenAiCompat { profile } => {
            let config =
                OpenAiCompatConfig::from_profile(profile).unwrap_or_else(|_| OpenAiCompatConfig {
                    provider_label: "openai-compatible".to_string(),
                    base_url: env_nonempty("KIN_EMBED_OPENAI_BASE_URL")
                        .unwrap_or_else(|| "http://localhost:1234/v1".to_string()),
                    model_id: env_nonempty("KIN_EMBED_OPENAI_MODEL")
                        .or_else(|| env_nonempty("KIN_EMBED_MODEL_ID"))
                        .unwrap_or_else(|| DEFAULT_LMSTUDIO_EMBED_MODEL_ID.to_string()),
                    api_key: None,
                    dimensions: None,
                    send_dimensions: false,
                    timeout_secs: 120,
                    request_overrides: serde_json::Map::new(),
                    query_prefix: String::new(),
                    document_prefix: String::new(),
                });
            let revision = config.runtime_revision();
            EmbeddingRuntimeConfig {
                provider: config.provider_identity(),
                model_id: config.model_id,
                revision,
                dimensions: config.dimensions,
                pipeline_epoch: EMBEDDING_CACHE_PIPELINE_EPOCH.to_string(),
            }
        }
    }
}

#[cfg(feature = "embeddings")]
fn default_max_batch_tokens(backend: GpuBackend) -> usize {
    match backend {
        GpuBackend::Metal => METAL_MAX_BATCH_TOKENS,
        GpuBackend::Cuda => CUDA_MAX_BATCH_TOKENS,
        GpuBackend::Cpu => DEFAULT_MAX_BATCH_TOKENS,
    }
}

#[cfg(feature = "embeddings")]
fn default_max_attention_area(backend: GpuBackend) -> usize {
    match backend {
        GpuBackend::Metal => METAL_MAX_ATTENTION_AREA,
        // CUDA (flash-attention, large VRAM) is not bounded by the host attention
        // ceiling. CPU IS bounded by the same area ceiling: host attention scratch
        // is count*seq^2*heads bytes, and the hybrid CPU twin runs many sub-batches
        // concurrently (rayon), so an unbounded CPU area lets parallel host
        // allocations OOM-kill the daemon on high-RAM machines.
        GpuBackend::Cuda => usize::MAX,
        GpuBackend::Cpu => METAL_MAX_ATTENTION_AREA,
    }
}

#[cfg(feature = "embeddings")]
fn cap_attention_area_for_backend(backend: GpuBackend, area: usize) -> usize {
    match backend {
        GpuBackend::Metal | GpuBackend::Cpu => area.min(METAL_MAX_ATTENTION_AREA),
        GpuBackend::Cuda => area,
    }
}

#[cfg(feature = "embeddings")]
fn metal_attention_area(count: usize, max_seq: usize) -> usize {
    max_seq
        .max(1)
        .saturating_mul(max_seq.max(1))
        .saturating_mul(count.max(1))
}

#[cfg(feature = "embeddings")]
fn metal_hard_guard_rejection(count: usize, max_seq: usize) -> Option<(usize, usize)> {
    let area = metal_attention_area(count, max_seq);
    let cap = METAL_MAX_ATTENTION_AREA;
    (area > cap).then_some((area, cap))
}

/// True only when `KIN_RESOURCE_PROFILE` is explicitly set to `throughput`.
/// Read live (never cached) so behavior tracks the current environment.
#[cfg(feature = "embeddings")]
pub(crate) fn resource_profile_is_throughput() -> bool {
    std::env::var("KIN_RESOURCE_PROFILE")
        .map(|value| value.trim().eq_ignore_ascii_case("throughput"))
        .unwrap_or(false)
}

/// Throughput-profile embedding plan for `backend`, detected once per backend.
/// Host detection is cached; the plan is otherwise deterministic for a backend.
#[cfg(feature = "embeddings")]
fn throughput_embedding_plan(backend: GpuBackend) -> &'static kin_infer::resource::EmbeddingPlan {
    use kin_infer::resource::{
        detect_host, detect_memory, AcceleratorBackend, AcceleratorInfo, Profile, ResourcePlan,
    };
    use std::sync::OnceLock;

    static METAL: OnceLock<kin_infer::resource::EmbeddingPlan> = OnceLock::new();
    static CUDA: OnceLock<kin_infer::resource::EmbeddingPlan> = OnceLock::new();
    static CPU: OnceLock<kin_infer::resource::EmbeddingPlan> = OnceLock::new();

    let (cell, accel_backend, unified_memory) = match backend {
        GpuBackend::Metal => (&METAL, AcceleratorBackend::Metal, true),
        GpuBackend::Cuda => (&CUDA, AcceleratorBackend::Cuda, false),
        GpuBackend::Cpu => (&CPU, AcceleratorBackend::Cpu, false),
    };

    cell.get_or_init(|| {
        let memory = detect_memory();
        // On unified-memory accelerators (Apple Silicon) the GPU shares system
        // RAM, so surface the detected memory as the device budget too. This lets
        // ResourcePlan size its hardware-scaled caps from real memory regardless
        // of which accelerator field its heuristics read, so the plan tracks the
        // host (e.g. a 128 GB box) rather than a hardcoded default.
        let (device_total_bytes, device_available_bytes) = if unified_memory {
            (memory.system_total_bytes, memory.system_available_bytes)
        } else {
            (None, None)
        };
        let accel = AcceleratorInfo {
            backend: accel_backend,
            device_index: 0,
            unified_memory,
            device_total_bytes,
            device_available_bytes,
            recommended_working_set_bytes: None,
            max_single_buffer_bytes: None,
            max_inflight_command_buffers: 1,
            reserve_device_bytes: None,
            allow_cpu_fallback: true,
        };
        ResourcePlan::for_profile(Profile::Throughput, &detect_host(), &accel, &memory).embedding
    })
}

/// Throughput-profile graph entity-chunk size (backend-independent).
#[cfg(all(feature = "embeddings", feature = "vector"))]
pub(crate) fn throughput_graph_chunk_size() -> usize {
    throughput_embedding_plan(GpuBackend::Cpu).max_entities_per_graph_chunk
}

/// Per-sub-batch embed shape + forward-timing trace (`KIN_EMBED_BATCH_TRACE`).
///
/// The finer-grained companion to [`EmbedStageTimings`]: that accumulator records
/// the whole `Forward` stage per drained batch, while this records each GPU
/// dispatch the [`BatchBudget`] actually packs — its padded vs real tokens and
/// attention area (`longest² × count`) alongside the forward wall. It surfaces the
/// *effective* batch budget (which the `resources inspect` report does not reflect)
/// and the padding waste a wide token budget introduces.
///
/// Off by default and zero-cost when off: gated by a cached env flag, the atomics
/// and the per-dispatch line are only touched on the trace path.
#[cfg(feature = "embeddings")]
pub mod batch_trace {
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::sync::OnceLock;
    use std::time::Duration;

    pub(crate) fn enabled() -> bool {
        static ENABLED: OnceLock<bool> = OnceLock::new();
        *ENABLED.get_or_init(|| {
            std::env::var("KIN_EMBED_BATCH_TRACE")
                .map(|value| !value.is_empty() && value != "0")
                .unwrap_or(false)
        })
    }

    static MAX_TOKENS: AtomicUsize = AtomicUsize::new(0);
    static MAX_AREA: AtomicUsize = AtomicUsize::new(0);
    static BATCHES: AtomicU64 = AtomicU64::new(0);
    static ENTITIES: AtomicU64 = AtomicU64::new(0);
    static REAL_TOKENS: AtomicU64 = AtomicU64::new(0);
    static PADDED_TOKENS: AtomicU64 = AtomicU64::new(0);
    static REAL_AREA: AtomicU64 = AtomicU64::new(0);
    static PADDED_AREA: AtomicU64 = AtomicU64::new(0);
    static FORWARD_NANOS: AtomicU64 = AtomicU64::new(0);
    static MAX_COUNT: AtomicU64 = AtomicU64::new(0);
    static MAX_LONGEST: AtomicU64 = AtomicU64::new(0);

    /// Record the effective budget resolved for the run (set once by `from_env`).
    pub(crate) fn record_budget(max_tokens: usize, max_attention_area: usize) {
        MAX_TOKENS.store(max_tokens, Ordering::Relaxed);
        MAX_AREA.store(max_attention_area, Ordering::Relaxed);
    }

    /// Record one dispatched sub-batch: its shape, its padded vs real work, and
    /// the wall time of the forward that embedded it.
    pub(crate) fn record_batch(count: usize, longest: usize, ids: &[Vec<u32>], forward: Duration) {
        let real_tokens: u64 = ids.iter().map(|v| v.len() as u64).sum();
        let real_area: u64 = ids
            .iter()
            .map(|v| {
                let len = v.len() as u64;
                len.saturating_mul(len)
            })
            .sum();
        let count = count as u64;
        let longest = longest as u64;
        let padded_tokens = longest.saturating_mul(count);
        let padded_area = longest.saturating_mul(longest).saturating_mul(count);
        let forward_nanos = forward.as_nanos().min(u64::MAX as u128) as u64;
        BATCHES.fetch_add(1, Ordering::Relaxed);
        ENTITIES.fetch_add(count, Ordering::Relaxed);
        REAL_TOKENS.fetch_add(real_tokens, Ordering::Relaxed);
        PADDED_TOKENS.fetch_add(padded_tokens, Ordering::Relaxed);
        REAL_AREA.fetch_add(real_area, Ordering::Relaxed);
        PADDED_AREA.fetch_add(padded_area, Ordering::Relaxed);
        FORWARD_NANOS.fetch_add(forward_nanos, Ordering::Relaxed);
        MAX_COUNT.fetch_max(count, Ordering::Relaxed);
        MAX_LONGEST.fetch_max(longest, Ordering::Relaxed);
        eprintln!(
            "[embed_batch_trace] count={count} longest={longest} real_tok={real_tokens} \
             padded_tok={padded_tokens} pad_tok_x={:.2} real_area={real_area} \
             padded_area={padded_area} pad_area_x={:.2} forward_us={}",
            padded_tokens as f64 / real_tokens.max(1) as f64,
            padded_area as f64 / real_area.max(1) as f64,
            forward.as_micros(),
        );
    }

    /// Cumulative totals for the trace, since the last [`reset`].
    #[derive(Debug, Clone, Copy, Default)]
    pub struct Summary {
        pub max_tokens: usize,
        pub max_attention_area: usize,
        pub batches: u64,
        pub entities: u64,
        pub real_tokens: u64,
        pub padded_tokens: u64,
        pub real_area: u64,
        pub padded_area: u64,
        pub forward_nanos: u64,
        pub max_count: u64,
        pub max_longest: u64,
    }

    impl Summary {
        /// Padded ÷ real token ratio: linear-buffer (FFN/projection) waste.
        pub fn token_waste(&self) -> f64 {
            self.padded_tokens as f64 / self.real_tokens.max(1) as f64
        }
        /// Padded ÷ real attention-area ratio: O(seq²) attention waste.
        pub fn area_waste(&self) -> f64 {
            self.padded_area as f64 / self.real_area.max(1) as f64
        }
        pub fn mean_count(&self) -> f64 {
            self.entities as f64 / self.batches.max(1) as f64
        }
        pub fn forward_secs(&self) -> f64 {
            self.forward_nanos as f64 / 1.0e9
        }
    }

    /// Point-in-time snapshot of the cumulative totals.
    pub fn snapshot() -> Summary {
        Summary {
            max_tokens: MAX_TOKENS.load(Ordering::Relaxed),
            max_attention_area: MAX_AREA.load(Ordering::Relaxed),
            batches: BATCHES.load(Ordering::Relaxed),
            entities: ENTITIES.load(Ordering::Relaxed),
            real_tokens: REAL_TOKENS.load(Ordering::Relaxed),
            padded_tokens: PADDED_TOKENS.load(Ordering::Relaxed),
            real_area: REAL_AREA.load(Ordering::Relaxed),
            padded_area: PADDED_AREA.load(Ordering::Relaxed),
            forward_nanos: FORWARD_NANOS.load(Ordering::Relaxed),
            max_count: MAX_COUNT.load(Ordering::Relaxed),
            max_longest: MAX_LONGEST.load(Ordering::Relaxed),
        }
    }

    /// Zero the per-dispatch accumulators (the resolved budget is retained).
    pub fn reset() {
        for counter in [
            &BATCHES,
            &ENTITIES,
            &REAL_TOKENS,
            &PADDED_TOKENS,
            &REAL_AREA,
            &PADDED_AREA,
            &FORWARD_NANOS,
            &MAX_COUNT,
            &MAX_LONGEST,
        ] {
            counter.store(0, Ordering::Relaxed);
        }
    }
}

/// The two budgets that bound a single embed GPU dispatch, and the rule that packs
/// a length-sorted run of entities into one.
///
/// Entities are sorted by token length, then greedily packed into a dispatch until
/// EITHER budget would be exceeded:
/// - `max_tokens` bounds padded tokens (`max_seq × count`) → the linear buffers
///   (token ids, FFN activations, output embeddings).
/// - `max_attention_area` bounds attention area (`max_seq² × count`) → the O(seq²)
///   Metal attention score buffer. The token budget alone does NOT bound this (see
///   `METAL_MAX_ATTENTION_AREA`), so without it a dispatch of long entities trips
///   the macOS GPU watchdog even while its token count is in budget.
#[cfg(feature = "embeddings")]
#[derive(Clone, Copy)]
struct BatchBudget {
    max_tokens: usize,
    max_attention_area: usize,
}

#[cfg(feature = "embeddings")]
impl BatchBudget {
    /// Resolve both budgets for `backend`, honoring the `KIN_EMBED_MAX_BATCH_TOKENS`
    /// and `KIN_EMBED_MAX_ATTENTION_AREA` overrides (each ignored unless it parses to
    /// a value > 0).
    fn from_env(backend: GpuBackend) -> Self {
        let env_usize = |key: &str, fallback: usize| {
            std::env::var(key)
                .ok()
                .and_then(|value| value.parse::<usize>().ok())
                .filter(|value| *value > 0)
                .unwrap_or(fallback)
        };
        // Fallbacks default to today's hardcoded budgets; under the throughput
        // profile they become the throughput plan's budgets. An explicit
        // KIN_EMBED_* override still wins over both.
        let (default_tokens, default_area) = if resource_profile_is_throughput() {
            let plan = throughput_embedding_plan(backend);
            let area = match plan.max_attention_area {
                Some(value) => value as usize,
                None => usize::MAX,
            };
            (plan.max_batch_tokens, area)
        } else {
            (
                default_max_batch_tokens(backend),
                default_max_attention_area(backend),
            )
        };
        let requested_area = env_usize("KIN_EMBED_MAX_ATTENTION_AREA", default_area);
        let max_tokens = env_usize("KIN_EMBED_MAX_BATCH_TOKENS", default_tokens);
        let max_attention_area = cap_attention_area_for_backend(backend, requested_area);
        if batch_trace::enabled() {
            batch_trace::record_budget(max_tokens, max_attention_area);
        }
        Self {
            max_tokens,
            max_attention_area,
        }
    }

    /// Greedily extend a batch from `start` over length-sorted token `ids`, stopping
    /// before either budget would be exceeded. A single entity is always admitted
    /// (the `end > start` guard) so an over-budget lone entity still gets embedded.
    /// Returns `(end, longest)`; the batch is `ids[start..end]` padded to
    /// `longest` tokens.
    fn next_batch(self, ids: &[Vec<u32>], start: usize) -> (usize, usize) {
        let mut end = start;
        let mut longest = 0usize;
        while end < ids.len() {
            let candidate_len = ids[end].len().max(1);
            let projected_longest = longest.max(candidate_len);
            let projected_tokens = projected_longest * (end - start + 1);
            let projected_area = projected_longest * projected_tokens;
            if end > start
                && (projected_tokens > self.max_tokens || projected_area > self.max_attention_area)
            {
                break;
            }
            longest = projected_longest;
            end += 1;
        }
        (end, longest)
    }
}

/// Sequence-length ceiling above which the hybrid split keeps an entity on the
/// CPU twin instead of the GPU.
///
/// Set to `EMBED_MAX_SEQ_LEN` — the tokenizer's hard truncation cap and the
/// embedder's max trained sequence — so no real entity is forced to the slow CPU
/// path. The Metal embedder produces finite, CPU-identical embeddings across the
/// full `0..=EMBED_MAX_SEQ_LEN` range (the long-sequence NaN was a norm-dispatch
/// bug in the inference engine, since fixed and validated batch-parity against
/// the CPU twin up to 2048), so long code entities ride the GPU and the
/// throughput hybrid splits work purely by the GPU/CPU throughput ratio rather
/// than by sequence length. The `> threshold` arm remains a defensive guard for
/// any future sequence longer than the cap.
#[cfg(feature = "embeddings")]
const EMBED_CPU_SEQ_THRESHOLD: usize = EMBED_MAX_SEQ_LEN;

/// The pre-inference routing decision for one SeqFloor-profile batch.
///
/// `EMBED_CPU_SEQ_THRESHOLD` equals the tokenizer's hard truncation cap
/// (`EMBED_MAX_SEQ_LEN`), so no tokenized entity can exceed it. The
/// sequence-length split therefore routes every real batch entirely to the GPU
/// arm and nothing to the CPU twin — the `> threshold` partition is always empty.
/// Running such a batch through the raw `split_at` collapses it to a single
/// GPU-only arm with no record of WHY the twin never engaged, so it is
/// indistinguishable from a balanced hybrid that legitimately chose the GPU. This
/// decision makes the degeneracy explicit instead.
#[cfg(feature = "embeddings")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SeqFloorRoute {
    /// At least one entity exceeds the truncation cap, so the sequence-length
    /// split routes real work to the CPU twin. `cpu_from` is the first index of
    /// the CPU (over-cap) side within the length-sorted batch. This remains a
    /// defensive guard for any future sequence longer than the cap.
    SplitByLength { cpu_from: usize },
    /// No entity exceeds the cap: the sequence-length criterion can never move
    /// work to the CPU twin. Defer the per-batch GPU/CPU decision to the adaptive
    /// throughput split instead of silently collapsing to a single GPU arm.
    Degenerate,
}

/// Decide how a SeqFloor batch routes, purely from tokenized lengths.
///
/// Pure and side-effect-free (no timing, no global state) so the routing
/// decision is deterministic and unit-testable without a GPU or daemon.
#[cfg(feature = "embeddings")]
fn plan_seqfloor_route(ids: &[Vec<u32>]) -> SeqFloorRoute {
    let cpu_from = ids.partition_point(|entity| entity.len() <= EMBED_CPU_SEQ_THRESHOLD);
    if !ids.is_empty() && cpu_from >= ids.len() {
        SeqFloorRoute::Degenerate
    } else {
        SeqFloorRoute::SplitByLength { cpu_from }
    }
}

/// Default Balanced-hybrid CPU lane cutoff. Tokenized entities at or below this
/// length are cheap enough for the CPU twin; heavier under-cap entities stay on
/// Metal. Tune with `KIN_EMBED_HYBRID_CPU_MAX_SEQ_LEN`.
#[cfg(feature = "embeddings")]
const BALANCED_CPU_MAX_SEQ_LEN: usize = 256;

#[cfg(feature = "embeddings")]
fn balanced_cpu_max_seq_len() -> usize {
    std::env::var("KIN_EMBED_HYBRID_CPU_MAX_SEQ_LEN")
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(BALANCED_CPU_MAX_SEQ_LEN)
        .min(EMBED_MAX_SEQ_LEN.saturating_sub(1))
        .max(1)
}

/// When auto dispatch resolves, should it prefer CPU unconditionally?
///
/// The Metal BERT NaN was root-caused to GELU's tanh argument overflowing
/// (`sinh/cosh` → inf → NaN) at long sequences; the fix clamps the argument
/// in `gelu_activation` (kin-infer commit d8df3cc). With that landed, the
/// `metal_seq_len_regression` suite is green end-to-end (BGE-small Metal-vs-CPU
/// parity, cosine ≈ 1.0, zero NaN from seq_len 7..1024), the SwiGLU/SiLU path is
/// verified clean by `swerank_self_retrieval` (top-1 correct, margin 0.19), and
/// the ContextBench nlohmann/json backfill probe validated max_seq=2048 forced
/// Metal batches. Auto dispatch should therefore stay on Metal by default; CPU
/// remains available through `KIN_EMBED_BACKEND=cpu`.
#[cfg(feature = "embeddings")]
const EMBED_AUTO_PREFERS_CPU: bool = false;

#[cfg(feature = "embeddings")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EmbedBackendChoice {
    Metal { reason: &'static str },
    Cpu { reason: &'static str },
}

#[cfg(feature = "embeddings")]
#[derive(Debug, Clone, Copy, PartialEq)]
enum HybridMode {
    Off,
    SeqFloor,
    /// `gpu_tput_ratio` is `Some` only when `KIN_EMBED_HYBRID_GPU_TPUT_RATIO`
    /// pins it explicitly; otherwise it is `None` and the split ratio is measured
    /// adaptively per batch (see [`adaptive_split`]).
    Balanced {
        gpu_tput_ratio: Option<f64>,
    },
}

#[cfg(feature = "embeddings")]
fn balanced_from_ratio_env() -> HybridMode {
    let gpu_tput_ratio = std::env::var("KIN_EMBED_HYBRID_GPU_TPUT_RATIO")
        .ok()
        .and_then(|v| v.trim().parse::<f64>().ok())
        .filter(|v| v.is_finite() && *v > 0.0);
    HybridMode::Balanced { gpu_tput_ratio }
}

/// Resolve the hybrid CPU/GPU split for `backend`.
///
/// Precedence mirrors `BatchBudget::from_env`: an explicit `KIN_EMBED_HYBRID`
/// value wins; otherwise the throughput resource profile derives the mode from
/// `ResourcePlan`; otherwise hybrid stays `Off`. The unset/non-throughput path
/// is byte-identical to the prior default (`Off`), so proof embeddings are
/// unchanged — only `KIN_RESOURCE_PROFILE=throughput` (a non-citable mode) may
/// engage the CPU twin. The `EMBED_AUTO_PREFERS_CPU` and `KIN_EMBED_BACKEND`
/// guards apply to whichever path produced a non-`Off` mode.
#[cfg(feature = "embeddings")]
fn hybrid_mode(backend: GpuBackend) -> HybridMode {
    let desired = match std::env::var("KIN_EMBED_HYBRID") {
        Ok(value) => {
            let raw = value.trim().to_ascii_lowercase();
            if matches!(raw.as_str(), "" | "0" | "false" | "off" | "no") {
                return HybridMode::Off;
            }
            if matches!(raw.as_str(), "seq" | "floor" | "seqfloor" | "seq_floor") {
                HybridMode::SeqFloor
            } else {
                balanced_from_ratio_env()
            }
        }
        Err(_) => {
            if !resource_profile_is_throughput() {
                return HybridMode::Off;
            }
            match throughput_embedding_plan(backend).hybrid_mode {
                kin_infer::resource::HybridMode::Off => return HybridMode::Off,
                kin_infer::resource::HybridMode::SequentialFloor => HybridMode::SeqFloor,
                kin_infer::resource::HybridMode::Balanced => balanced_from_ratio_env(),
            }
        }
    };

    if EMBED_AUTO_PREFERS_CPU {
        return HybridMode::Off;
    }
    let backend_env = std::env::var("KIN_EMBED_BACKEND")
        .ok()
        .map(|v| v.trim().to_ascii_lowercase())
        .unwrap_or_else(|| "auto".to_string());
    if !matches!(backend_env.as_str(), "auto" | "") {
        return HybridMode::Off;
    }
    desired
}

/// A tokenized batch held as parallel, length-sorted arrays. Keeping ids and masks
/// contiguous (rather than a `Vec` of per-entity tuples) lets each GPU dispatch
/// borrow a sub-range directly, so the hot loop never re-clones token buffers.
/// `idx[k]` is the original input position of the k-th entity, so results can be
/// scattered back into input order regardless of how the batch was split.
#[cfg(feature = "embeddings")]
struct EncodedBatch {
    idx: Vec<usize>,
    ids: Vec<Vec<u32>>,
    masks: Vec<Vec<u32>>,
}

#[cfg(feature = "embeddings")]
impl EncodedBatch {
    fn len(&self) -> usize {
        self.idx.len()
    }

    fn as_slice(&self) -> EncodedSlice<'_> {
        EncodedSlice {
            idx: &self.idx,
            ids: &self.ids,
            masks: &self.masks,
        }
    }
}

#[cfg(feature = "embeddings")]
fn trim_tokenized_right_padding(ids: &mut Vec<u32>, mask: &mut Vec<u32>) {
    let requested_keep = mask
        .iter()
        .rposition(|&value| value != 0)
        .map(|idx| idx + 1)
        .unwrap_or(1);
    let max_keep = ids.len().min(mask.len());
    let keep = if max_keep == 0 {
        0
    } else {
        requested_keep.min(max_keep).max(1)
    };
    ids.truncate(keep);
    mask.truncate(keep);
}

#[cfg(feature = "embeddings")]
fn encoded_batch_from_tokenized(mut order: Vec<(usize, Vec<u32>, Vec<u32>)>) -> EncodedBatch {
    for (_, ids, mask) in &mut order {
        trim_tokenized_right_padding(ids, mask);
    }
    order.sort_by_key(|(_, ids, _)| ids.len());

    // Move (not clone) the sorted tuples into parallel arrays. Holding ids and
    // masks contiguously lets every GPU dispatch borrow a sub-range directly,
    // so the hot loop never re-clones token buffers per sub-batch.
    let mut batch = EncodedBatch {
        idx: Vec::with_capacity(order.len()),
        ids: Vec::with_capacity(order.len()),
        masks: Vec::with_capacity(order.len()),
    };
    for (idx, ids, mask) in order {
        batch.idx.push(idx);
        batch.ids.push(ids);
        batch.masks.push(mask);
    }
    batch
}

/// Borrowed view over a contiguous run of an [`EncodedBatch`]. `Copy` so the two
/// hybrid arms can each capture a disjoint view inside `rayon::join` without
/// cloning the underlying token buffers.
#[cfg(feature = "embeddings")]
#[derive(Clone, Copy)]
struct EncodedSlice<'a> {
    idx: &'a [usize],
    ids: &'a [Vec<u32>],
    masks: &'a [Vec<u32>],
}

#[cfg(feature = "embeddings")]
impl<'a> EncodedSlice<'a> {
    fn len(&self) -> usize {
        self.idx.len()
    }

    fn is_empty(&self) -> bool {
        self.idx.is_empty()
    }

    fn split_at(&self, mid: usize) -> (EncodedSlice<'a>, EncodedSlice<'a>) {
        let (idx_l, idx_r) = self.idx.split_at(mid);
        let (ids_l, ids_r) = self.ids.split_at(mid);
        let (masks_l, masks_r) = self.masks.split_at(mid);
        (
            EncodedSlice {
                idx: idx_l,
                ids: ids_l,
                masks: masks_l,
            },
            EncodedSlice {
                idx: idx_r,
                ids: ids_r,
                masks: masks_r,
            },
        )
    }
}

/// Split a length-sorted batch into a Metal (GPU) subset and a CPU-twin subset
/// for the Balanced hybrid mode.
///
/// Tokenized entities at or below `KIN_EMBED_HYBRID_CPU_MAX_SEQ_LEN` are
/// CPU-eligible because they are cheap enough for the CPU twin. Heavier
/// under-`EMBED_MAX_SEQ_LEN` entities stay on the GPU, where Metal's batch
/// throughput is strongest. The CPU-eligible entities are then split so the two
/// arms finish at roughly the same time: the GPU clears work `gpu_tput_ratio`×
/// faster per unit while also carrying the heavier entities. Balancing GPU time
/// `(heavy + eligible - cpu) / ratio` against CPU time `cpu` gives
///
/// ```text
/// cpu = (eligible + heavy) / (ratio + 1)
/// ```
///
/// clamped to `[0, eligible]`. When heavy work dominates this gives the CPU twin
/// all cheap entities while the GPU carries the expensive ones; with no heavy
/// work it reduces to the CPU taking `1 / (ratio + 1)` of uniform short work.
///
/// `min_cpu_probe` forces the twin at least that many of the shortest entities
/// even when the ratio would give it none — used by the adaptive probe to take a
/// fresh throughput measurement (shortest entities minimize the probe's cost).
#[cfg(feature = "embeddings")]
fn balanced_partition(
    batch: EncodedSlice<'_>,
    gpu_tput_ratio: f64,
    min_cpu_probe: usize,
) -> (EncodedBatch, EncodedBatch) {
    balanced_partition_with_cpu_max_seq_len(
        batch,
        gpu_tput_ratio,
        min_cpu_probe,
        balanced_cpu_max_seq_len(),
    )
}

#[cfg(feature = "embeddings")]
fn balanced_partition_with_cpu_max_seq_len(
    batch: EncodedSlice<'_>,
    gpu_tput_ratio: f64,
    min_cpu_probe: usize,
    cpu_max_seq_len: usize,
) -> (EncodedBatch, EncodedBatch) {
    let cpu_max_seq_len = cpu_max_seq_len
        .min(EMBED_MAX_SEQ_LEN.saturating_sub(1))
        .max(1);
    let cpu_candidate_split = batch
        .ids
        .partition_point(|ids| ids.len() <= cpu_max_seq_len);

    let work = |ids: &[u32]| ids.len().max(1) as f64;
    let w_cpu_candidates: f64 = batch.ids[..cpu_candidate_split]
        .iter()
        .map(|ids| work(ids))
        .sum();
    let w_gpu_forced: f64 = batch.ids[cpu_candidate_split..]
        .iter()
        .map(|ids| work(ids))
        .sum();

    let target_cpu =
        ((w_cpu_candidates + w_gpu_forced) / (gpu_tput_ratio + 1.0)).clamp(0.0, w_cpu_candidates);

    // Fill the CPU side from the shortest eligible entities up; the tie-break on
    // original index keeps the selection deterministic regardless of sort impl.
    let mut order: Vec<usize> = (0..cpu_candidate_split).collect();
    order.sort_by(|&a, &b| {
        batch.ids[a]
            .len()
            .cmp(&batch.ids[b].len())
            .then(batch.idx[a].cmp(&batch.idx[b]))
    });

    let mut to_cpu = vec![false; batch.len()];
    let mut cpu_work = 0.0;
    let mut cpu_count = 0usize;
    for pos in order {
        let w = work(&batch.ids[pos]);
        if target_cpu > 0.0 && (cpu_work + w <= target_cpu || cpu_count == 0) {
            cpu_work += w;
            cpu_count += 1;
            to_cpu[pos] = true;
        }
    }

    // Adaptive probe: ensure the twin gets at least `min_cpu_probe` entities by
    // moving the shortest GPU-assigned entities over (the batch is length-sorted
    // ascending, so low positions are cheapest to run on the CPU).
    if min_cpu_probe > 0 {
        for on_cpu in to_cpu.iter_mut() {
            if cpu_count >= min_cpu_probe {
                break;
            }
            if !*on_cpu {
                *on_cpu = true;
                cpu_count += 1;
            }
        }
    }

    let metal_count = batch.len() - cpu_count;
    let mut metal = EncodedBatch {
        idx: Vec::with_capacity(metal_count),
        ids: Vec::with_capacity(metal_count),
        masks: Vec::with_capacity(metal_count),
    };
    let mut cpu = EncodedBatch {
        idx: Vec::with_capacity(cpu_count),
        ids: Vec::with_capacity(cpu_count),
        masks: Vec::with_capacity(cpu_count),
    };
    let push_into = |dst: &mut EncodedBatch, pos: usize| {
        dst.idx.push(batch.idx[pos]);
        dst.ids.push(batch.ids[pos].clone());
        dst.masks.push(batch.masks[pos].clone());
    };
    for (pos, &on_cpu) in to_cpu.iter().enumerate() {
        if on_cpu {
            push_into(&mut cpu, pos);
        } else {
            push_into(&mut metal, pos);
        }
    }

    (metal, cpu)
}

/// Scatter `(original_idx, vector)` placements back into input order, failing if
/// any slot is missing.
#[cfg(feature = "embeddings")]
fn scatter_placed(
    placed: Vec<(usize, Vec<f32>)>,
    total: usize,
) -> Result<Vec<Vec<f32>>, KinDbError> {
    let mut results: Vec<Option<Vec<f32>>> = vec![None; total];
    for (original_idx, vector) in placed {
        results[original_idx] = Some(vector);
    }
    results
        .into_iter()
        .map(|vector| {
            vector.ok_or_else(|| {
                KinDbError::IndexError("embedding batch result order mismatch".into())
            })
        })
        .collect()
}

/// Pick the inference path for a chunk based on `KIN_EMBED_BACKEND` and the
/// chunk's longest sequence length.
///
/// - `metal` (forced): always route through `forward_batched`. Useful to
///   verify the Metal kernel fix once it lands.
/// - `cpu` (forced): always route through per-sample `forward`, which on
///   Metal uses the non-broken fused_attention kernel and on pure-CPU builds
///   is the SIMD path. Debug escape hatch.
/// - `auto` (default): use batched Metal. CPU is an explicit escape hatch via
///   `KIN_EMBED_BACKEND=cpu`, not a hidden fallback for long code entities.
#[cfg(feature = "embeddings")]
fn resolve_embed_backend(max_seq: usize) -> EmbedBackendChoice {
    let mode = std::env::var("KIN_EMBED_BACKEND")
        .ok()
        .map(|v| v.trim().to_ascii_lowercase())
        .unwrap_or_else(|| "auto".to_string());

    match mode.as_str() {
        "metal" | "gpu" => EmbedBackendChoice::Metal {
            reason: "env_forced",
        },
        "cpu" => EmbedBackendChoice::Cpu {
            reason: "env_forced",
        },
        "auto" | "" => auto_choice(max_seq),
        other => {
            tracing::warn!(
                backend = %other,
                "unknown KIN_EMBED_BACKEND value, falling back to auto"
            );
            auto_choice(max_seq)
        }
    }
}

#[cfg(feature = "embeddings")]
fn auto_choice(_max_seq: usize) -> EmbedBackendChoice {
    if EMBED_AUTO_PREFERS_CPU {
        EmbedBackendChoice::Cpu {
            reason: "auto_metal_unreliable",
        }
    } else {
        EmbedBackendChoice::Metal {
            reason: "auto_metal_default",
        }
    }
}

/// Test-only fault injection for the Metal embedding dispatch arm.
///
/// When `KIN_EMBED_TEST_FORCE_METAL_OOM` is set to a positive integer `N`, the
/// first `N` Metal `forward_batched` dispatches in this process are replaced
/// with a synthetic `kin_infer::InferError::OutOfMemory`, so the CPU-degrade
/// retry path can be exercised end-to-end without putting the device under real
/// memory pressure. The kin-infer side already proves `try_new_buffer` surfaces
/// a real `OutOfMemory`; this lets the kin-db side prove the dispatcher handles
/// that error value by retrying the batch on the CPU twin.
///
/// In production the variable is unset: the budget initializes to `0` exactly
/// once and every subsequent check is a single relaxed atomic load that returns
/// `false`, so the embedding hot path is unaffected.
#[cfg(feature = "embeddings")]
fn metal_oom_injection_armed() -> bool {
    use std::sync::atomic::{AtomicI64, Ordering};
    use std::sync::OnceLock;

    static BUDGET: OnceLock<AtomicI64> = OnceLock::new();
    let budget = BUDGET.get_or_init(|| {
        let remaining = std::env::var("KIN_EMBED_TEST_FORCE_METAL_OOM")
            .ok()
            .and_then(|value| value.trim().parse::<i64>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(0);
        AtomicI64::new(remaining)
    });

    if budget.load(Ordering::Relaxed) <= 0 {
        return false;
    }
    // fetch_sub returns the PREVIOUS value; inject while it was still positive.
    budget.fetch_sub(1, Ordering::Relaxed) > 0
}

/// Build the text representation fed to the embedding model.
pub fn format_entity_text(name: &str, signature: &str, body: &str) -> String {
    let mut parts = Vec::with_capacity(3);
    if !name.is_empty() {
        parts.push(name);
    }
    if !signature.is_empty() {
        parts.push(signature);
    }
    if !body.is_empty() {
        parts.push(body);
    }
    parts.join(" ")
}

/// Build the text representation for a persisted graph entity.
pub fn format_graph_entity_text(entity: &Entity) -> String {
    format_graph_entity_text_with_context(entity, &[])
}

/// Append `text` to `out`, bounded to `max_chars` on a UTF-8 char boundary.
/// Right-truncation keeps the front of the field, which for docstrings is the
/// summary line and first paragraph (the discriminating signal); the trailing
/// boilerplate that is dropped carries little retrieval value but heavy cost.
///
/// Writes straight into the embed-text buffer instead of allocating an
/// intermediate `String` for every capped field.
fn push_bounded_embed_field(out: &mut String, text: &str, max_chars: usize) {
    if text.chars().count() <= max_chars {
        out.push_str(text);
    } else {
        out.extend(text.chars().take(max_chars));
    }
}

/// Allocating twin of [`push_bounded_embed_field`], kept for the unit tests that
/// assert the truncation contract directly.
#[cfg(test)]
fn bounded_embed_field(text: &str, max_chars: usize) -> String {
    let mut out = String::new();
    push_bounded_embed_field(&mut out, text, max_chars);
    out
}

/// Build the text representation for a persisted graph entity with additional
/// graph-derived neighborhood context lines.
///
/// The fields are emitted in a fixed order and joined with `\n`. Output is built
/// directly into one pre-sized `String` — no intermediate `Vec<String>` and no
/// per-field clones — so the common entity formats in a single allocation. The
/// byte layout is identical to the prior `parts.join("\n")` form; embed
/// determinism depends on that, so it is locked by
/// `format_graph_entity_text_byte_identical_to_joined_parts`.
pub fn format_graph_entity_text_with_context(entity: &Entity, context_lines: &[String]) -> String {
    let kind_label = entity_kind_label(entity.kind);

    let file_origin = entity.file_origin.as_ref().map(|origin| origin.0.as_str());
    if let Some(path) = file_origin {
        // Machine-absolute paths must never enter embed text — they bake
        // machine-specific prefixes into vectors, breaking cross-host
        // reproducibility. The parser layer is responsible for storing
        // repo-relative paths; this guard catches regressions at the embed
        // boundary where the damage would be silent.
        debug_assert!(
            !path.starts_with('/'),
            "absolute path in embed text: '{path}' — store repo-relative paths only"
        );
        if path.starts_with('/') {
            tracing::warn!(
                path = %path,
                "machine-absolute path detected in embedding input (entity file_origin); \
                 vectors may not be reproducible across machines — store repo-relative paths"
            );
        }
    }

    let doc_summary = entity
        .doc_summary
        .as_deref()
        .map(str::trim)
        .filter(|summary| !summary.is_empty());
    let metadata_field = |key: &str| {
        entity
            .metadata
            .extra
            .get(key)
            .and_then(|value| value.as_str())
            .filter(|text| !text.is_empty())
    };
    let body_preview = metadata_field(EMBEDDING_BODY_PREVIEW_KEY);
    let file_import_context = metadata_field(FILE_IMPORT_CONTEXT_KEY);
    let file_surface_context = metadata_field(FILE_SURFACE_CONTEXT_KEY);

    // Pre-size for every field that will be emitted (each preceded by one
    // `\n` joiner), so the buffer is allocated once. The doc-summary estimate
    // uses its untruncated byte length — a harmless slight over-reserve when the
    // field is capped.
    let mut capacity = kind_label.len();
    if let Some(path) = file_origin {
        capacity += 1 + path.len();
    }
    if !entity.name.is_empty() {
        capacity += 1 + entity.name.len();
    }
    if !entity.signature.is_empty() {
        capacity += 1 + entity.signature.len();
    }
    if let Some(summary) = doc_summary {
        capacity += 1 + summary.len();
    }
    for field in [body_preview, file_import_context, file_surface_context]
        .into_iter()
        .flatten()
    {
        capacity += 1 + field.len();
    }
    for line in context_lines {
        capacity += 1 + line.len();
    }

    let mut out = String::with_capacity(capacity);
    out.push_str(kind_label);
    if let Some(path) = file_origin {
        out.push('\n');
        out.push_str(path);
    }
    if !entity.name.is_empty() {
        out.push('\n');
        out.push_str(&entity.name);
    }
    if !entity.signature.is_empty() {
        out.push('\n');
        out.push_str(&entity.signature);
    }
    if let Some(summary) = doc_summary {
        out.push('\n');
        push_bounded_embed_field(&mut out, summary, EMBED_DOC_SUMMARY_MAX_CHARS);
    }
    for field in [body_preview, file_import_context, file_surface_context]
        .into_iter()
        .flatten()
    {
        out.push('\n');
        out.push_str(field);
    }
    for line in context_lines {
        out.push('\n');
        out.push_str(line);
    }
    out
}

/// Build the text representation for a structured artifact.
pub fn format_artifact_text(artifact: &StructuredArtifact) -> String {
    let mut parts = Vec::with_capacity(4);
    parts.push("structured_artifact".to_string());
    parts.push(format!("kind={}", artifact_kind_label(artifact.kind)));
    parts.push(format!("file={}", artifact.file_id.0));
    if let Some(text_preview) = artifact.text_preview.as_deref() {
        let text_preview = text_preview.trim();
        if !text_preview.is_empty() {
            parts.push(text_preview.to_string());
        }
    }
    parts.join("\n")
}

/// Build the text representation for an opaque artifact.
pub fn format_opaque_text(artifact: &OpaqueArtifact) -> String {
    let mut parts = Vec::with_capacity(4);
    parts.push("opaque_artifact".to_string());
    parts.push(format!("file={}", artifact.file_id.0));
    if let Some(mime_type) = artifact.mime_type.as_deref() {
        let mime_type = mime_type.trim();
        if !mime_type.is_empty() {
            parts.push(format!("mime_type={mime_type}"));
        }
    }
    if let Some(text_preview) = artifact.text_preview.as_deref() {
        let text_preview = text_preview.trim();
        if !text_preview.is_empty() {
            parts.push(text_preview.to_string());
        }
    }
    parts.join("\n")
}

/// Build the text representation for a shallow-tracked file.
pub fn format_shallow_text(file: &ShallowTrackedFile) -> String {
    let mut parts = Vec::with_capacity(8);
    parts.push("shallow_file".to_string());
    parts.push(format!("file={}", file.file_id.0));
    parts.push(format!("language_hint={}", file.language_hint));
    parts.push(format!("declaration_count={}", file.declaration_count));
    parts.push(format!("import_count={}", file.import_count));
    if let Some(signature_hash) = file.signature_hash.as_ref() {
        parts.push(format!("signature_hash={signature_hash:?}"));
    }
    if !file.declaration_names.is_empty() {
        parts.push(format!("declarations={}", file.declaration_names.join(" ")));
    }
    if !file.import_paths.is_empty() {
        parts.push(format!("imports={}", file.import_paths.join(" ")));
    }
    parts.join("\n")
}

fn artifact_kind_label(kind: ArtifactKind) -> &'static str {
    match kind {
        ArtifactKind::PackageManifest => "package_manifest",
        ArtifactKind::SqlMigration => "sql_migration",
        ArtifactKind::CiConfig => "ci_config",
        ArtifactKind::Dockerfile => "dockerfile",
        ArtifactKind::ComposeFile => "compose_file",
        ArtifactKind::Makefile => "makefile",
    }
}

fn entity_kind_label(kind: EntityKind) -> &'static str {
    match kind {
        EntityKind::Function => "function",
        EntityKind::Class => "class",
        EntityKind::Interface => "interface",
        EntityKind::TraitDef => "trait",
        EntityKind::TypeAlias => "type_alias",
        EntityKind::Module => "module",
        EntityKind::Package => "package",
        EntityKind::Test => "test",
        EntityKind::Schema => "schema",
        EntityKind::ApiEndpoint => "api_endpoint",
        EntityKind::EventContract => "event_contract",
        EntityKind::File => "file",
        EntityKind::DocumentNode => "document_node",
        EntityKind::Method => "method",
        EntityKind::EnumDef => "enum",
        EntityKind::EnumVariant => "enum_variant",
        EntityKind::Constant => "constant",
        EntityKind::StaticVar => "static_var",
        EntityKind::Macro => "macro",
    }
}

#[cfg(not(feature = "embeddings"))]
fn disabled_error() -> KinDbError {
    KinDbError::IndexError(
        "embeddings support is disabled in this build. Rebuild with `--features embeddings`."
            .into(),
    )
}

/// Capacity of the in-memory LRU in front of the on-disk embedding vector
/// cache: ~1024 vectors (≈3 MB at 768-dim f32) bounds resident memory while
/// keeping the hot working set warm.
#[cfg(feature = "embeddings")]
const EMBED_MEMORY_CACHE_CAPACITY: usize = 1024;

/// Bounded least-recently-used cache for embedding vectors held in memory in
/// front of the on-disk vector cache. When full, it evicts only the single
/// least-recently-used entry, keeping the hottest working set resident.
///
/// It governs only which vectors are resident in RAM, never the bytes returned:
/// a value served from this cache is byte-for-byte identical to what the
/// on-disk read would return, so embedding determinism and cache provenance are
/// unchanged. Recency uses a monotonic counter; eviction scans for the minimum,
/// which is cheap because the cache is small and eviction is rare relative to
/// embedding cost.
#[cfg(feature = "embeddings")]
#[derive(Debug)]
struct VectorLruCache {
    capacity: usize,
    tick: u64,
    entries: std::collections::HashMap<String, LruEntry>,
}

#[cfg(feature = "embeddings")]
#[derive(Debug)]
struct LruEntry {
    vector: Vec<f32>,
    last_used: u64,
}

#[cfg(feature = "embeddings")]
impl VectorLruCache {
    fn with_capacity(capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            capacity,
            tick: 0,
            entries: std::collections::HashMap::with_capacity(capacity),
        }
    }

    fn next_tick(&mut self) -> u64 {
        self.tick = self.tick.wrapping_add(1);
        self.tick
    }

    /// Return a clone of the cached vector and mark it most-recently-used.
    fn get(&mut self, key: &str) -> Option<Vec<f32>> {
        let tick = self.next_tick();
        let entry = self.entries.get_mut(key)?;
        entry.last_used = tick;
        Some(entry.vector.clone())
    }

    /// Insert or refresh `key`, evicting the least-recently-used entry first
    /// when a new key would exceed capacity.
    fn put(&mut self, key: &str, vector: Vec<f32>) {
        let tick = self.next_tick();
        if let Some(entry) = self.entries.get_mut(key) {
            entry.vector = vector;
            entry.last_used = tick;
            return;
        }
        if self.entries.len() >= self.capacity {
            self.evict_least_recently_used();
        }
        self.entries.insert(
            key.to_string(),
            LruEntry {
                vector,
                last_used: tick,
            },
        );
    }

    fn evict_least_recently_used(&mut self) {
        if let Some(victim) = self
            .entries
            .iter()
            .min_by_key(|(_, entry)| entry.last_used)
            .map(|(key, _)| key.clone())
        {
            self.entries.remove(&victim);
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    fn contains_key(&self, key: &str) -> bool {
        self.entries.contains_key(key)
    }
}

#[cfg(feature = "embeddings")]
#[derive(Debug, Clone)]
struct EmbeddingCache {
    root: PathBuf,
    dimensions: usize,
    memory_cache: std::sync::Arc<std::sync::Mutex<VectorLruCache>>,
}

#[cfg(feature = "embeddings")]
impl EmbeddingCache {
    fn new(namespace: String, dimensions: usize) -> Option<Self> {
        if std::env::var("KIN_EMBED_CACHE")
            .ok()
            .is_some_and(|value| value == "0")
        {
            return None;
        }

        let base_dir = cache_admin::embedding_cache_base_dir()?;
        Self::new_in(base_dir, namespace, dimensions)
    }

    fn new_in(base_dir: PathBuf, namespace: String, dimensions: usize) -> Option<Self> {
        let root = base_dir
            .join(EMBEDDING_CACHE_SCHEMA_VERSION)
            .join(namespace);
        std::fs::create_dir_all(&root).ok()?;
        Some(Self {
            root,
            dimensions,
            memory_cache: std::sync::Arc::new(std::sync::Mutex::new(
                VectorLruCache::with_capacity(EMBED_MEMORY_CACHE_CAPACITY),
            )),
        })
    }

    fn key_for_text(&self, text: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(text.as_bytes());
        hex::encode(hasher.finalize())
    }

    fn get_by_key(&self, key: &str) -> Option<Vec<f32>> {
        if let Some(cached) = self.memory_cache.lock().unwrap().get(key) {
            return Some(cached);
        }

        if let Some(vector) = read_cached_vector(&self.path_for_key(key), self.dimensions) {
            self.memory_cache.lock().unwrap().put(key, vector.clone());
            Some(vector)
        } else {
            None
        }
    }

    fn put_by_key(&self, key: &str, vector: &[f32]) {
        if vector.len() != self.dimensions {
            return;
        }
        if !vector.iter().all(|v| v.is_finite()) {
            return;
        }
        // Zero vectors are what `sanitize_embedding` emits in place of NaN;
        // persisting them would poison future runs the same way the prior
        // NaN cache did. A genuine embedding from BGE is L2-normalized so
        // its norm is ~1.0 — a zero vector is always sentinel output.
        if vector.iter().all(|v| *v == 0.0) {
            return;
        }

        {
            let mut cache = self.memory_cache.lock().unwrap();
            cache.put(key, vector.to_vec());
        }

        let _ = write_cached_vector(&self.path_for_key(key), vector);
    }

    fn path_for_key(&self, key: &str) -> PathBuf {
        let prefix = &key[..2];
        self.root.join(prefix).join(format!("{key}.bin"))
    }
}

#[cfg(feature = "embeddings")]
fn model_namespace<const N: usize>(
    model_id: &str,
    revision: &str,
    dimensions: usize,
    artifact_paths: [&Path; N],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(EMBEDDING_CACHE_PIPELINE_EPOCH.as_bytes());
    hasher.update([0]);
    hasher.update(model_id.as_bytes());
    hasher.update([0]);
    hasher.update(revision.as_bytes());
    hasher.update([0]);
    hasher.update(dimensions.to_le_bytes());
    hasher.update([0]);
    for path in artifact_paths {
        hasher.update(path.to_string_lossy().as_bytes());
        hasher.update([0]);
    }
    let digest = hex::encode(hasher.finalize());
    format!("{}-{}", sanitize_component(model_id), &digest[..16])
}

#[cfg(feature = "embeddings")]
fn sanitize_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_') {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    out
}

#[cfg(feature = "embeddings")]
fn read_cached_vector(path: &Path, dimensions: usize) -> Option<Vec<f32>> {
    let bytes = std::fs::read(path).ok()?;
    if bytes.len() != dimensions * std::mem::size_of::<f32>() {
        return None;
    }

    let mut values = Vec::with_capacity(dimensions);
    for chunk in bytes.chunks_exact(std::mem::size_of::<f32>()) {
        values.push(f32::from_le_bytes(chunk.try_into().ok()?));
    }
    // Poisoned cache entries from prior builds must not be returned: treat them
    // as a miss so the caller re-embeds with current defensive guards in place.
    if !values.iter().all(|v| v.is_finite()) {
        let _ = std::fs::remove_file(path);
        return None;
    }
    // Zero vectors in the cache are the sentinel emitted by `sanitize_embedding`
    // when the inference kernel produced NaN. A real BGE embedding is
    // L2-normalized (norm ~1.0), so a zero vector is never a legitimate
    // cache hit — evict and re-embed.
    if values.iter().all(|v| *v == 0.0) {
        let _ = std::fs::remove_file(path);
        return None;
    }
    Some(values)
}

/// Replace non-finite embeddings with a zero vector of the correct dimension.
/// Cosine distance's zero-norm guard then produces a sentinel distance of 1.0
/// rather than propagating NaN through the search index.
#[cfg(feature = "embeddings")]
fn sanitize_embedding<'a, F>(vector: Vec<f32>, dimensions: usize, describe: F) -> Vec<f32>
where
    F: FnOnce() -> &'a str,
{
    let needs_fix = vector.len() != dimensions || !vector.iter().all(|v| v.is_finite());
    if !needs_fix {
        return vector;
    }
    let text = describe();
    let preview: String = text.chars().take(64).collect();
    tracing::error!(
        dims = vector.len(),
        expected_dims = dimensions,
        nan_count = vector.iter().filter(|v| v.is_nan()).count(),
        inf_count = vector.iter().filter(|v| v.is_infinite()).count(),
        text_len = text.len(),
        text_preview = %preview,
        "embedder produced non-finite vector; substituting zero vector"
    );
    vec![0.0f32; dimensions]
}

#[cfg(feature = "embeddings")]
fn write_cached_vector(path: &Path, vector: &[f32]) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut bytes = Vec::with_capacity(std::mem::size_of_val(vector));
    for value in vector {
        bytes.extend_from_slice(&value.to_le_bytes());
    }

    let tmp = path.with_extension(format!("tmp-{}", std::process::id()));
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{
        EntityId, EntityMetadata, EntityRole, FilePathId, FingerprintAlgorithm, Hash256,
        LanguageId, SemanticFingerprint, Visibility,
    };

    /// Default embedding dimensions (768, nomic-embed-text-v1.5).
    const DEFAULT_EMBED_DIMS: usize = 768;

    #[test]
    fn format_entity_text_joins_parts() {
        assert_eq!(
            format_entity_text("foo", "fn foo()", "{ 1 }"),
            "foo fn foo() { 1 }"
        );
        assert_eq!(format_entity_text("foo", "", ""), "foo");
        assert_eq!(format_entity_text("", "", ""), "");
    }

    #[test]
    fn format_graph_entity_text_includes_semantic_context() {
        let mut entity = Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: "parse_config".into(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256([0; 32]),
                signature_hash: Hash256([0; 32]),
                behavior_hash: Hash256([0; 32]),
                equivalence_hash: Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new("src/config.rs")),
            span: None,
            signature: "fn parse_config(path: &str) -> Config".into(),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: Some("Parse a config file".into()),
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        };
        entity.metadata.extra.insert(
            EMBEDDING_BODY_PREVIEW_KEY.into(),
            serde_json::Value::String("fn parse_config(path: &str) -> Config { ... }".into()),
        );
        entity.metadata.extra.insert(
            FILE_IMPORT_CONTEXT_KEY.into(),
            serde_json::Value::String(
                "module @vue/runtime-core names createRenderer hydrate".into(),
            ),
        );
        entity.metadata.extra.insert(
            FILE_SURFACE_CONTEXT_KEY.into(),
            serde_json::Value::String("surface runtime-dom surface runtime dom".into()),
        );

        let formatted = format_graph_entity_text(&entity);
        assert!(formatted.contains("function"));
        assert!(formatted.contains("src/config.rs"));
        assert!(formatted.contains("parse_config"));
        assert!(formatted.contains("fn parse_config(path: &str) -> Config"));
        assert!(formatted.contains("Parse a config file"));
        assert!(formatted.contains("fn parse_config(path: &str) -> Config { ... }"));
        assert!(formatted.contains("@vue/runtime-core"));
        assert!(formatted.contains("runtime dom"));
    }

    #[test]
    fn format_graph_entity_text_caps_long_doc_summary() {
        // A numpy-style docstring far exceeds the embed cap (cf. scikit-learn's
        // RandomForestClassifier, whose docstring alone is ~3700 tokens). Only
        // the front — the semantic summary — should be folded into embed text;
        // the trailing Parameters/Examples prose is dropped.
        let head = "A random forest classifier. ";
        let long_doc = format!(
            "{head}{}",
            "Parameters ---------- n_estimators int default 100. ".repeat(200)
        );
        assert!(long_doc.chars().count() > EMBED_DOC_SUMMARY_MAX_CHARS);

        let entity = Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: "RandomForestClassifier".into(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256([0; 32]),
                signature_hash: Hash256([0; 32]),
                behavior_hash: Hash256([0; 32]),
                equivalence_hash: Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new("sklearn/ensemble/_forest.py")),
            span: None,
            signature: "class RandomForestClassifier".into(),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: Some(long_doc.clone()),
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        };

        let formatted = format_graph_entity_text(&entity);
        // The summary head is retained.
        assert!(formatted.contains("A random forest classifier."));
        // The full docstring is NOT folded in verbatim.
        assert!(!formatted.contains(&long_doc));
        // Total embed text stays within the cap plus the short header fields
        // (kind/path/name/signature), proving the docstring no longer dominates.
        assert!(
            formatted.chars().count() <= EMBED_DOC_SUMMARY_MAX_CHARS + 256,
            "doc summary not capped: {} chars",
            formatted.chars().count()
        );
    }

    #[test]
    fn bounded_embed_field_passes_through_short_text() {
        assert_eq!(bounded_embed_field("short text", 100), "short text");
    }

    #[test]
    fn bounded_embed_field_truncates_on_char_boundary() {
        // Multi-byte chars must not panic at the truncation boundary.
        let text: String = "é".repeat(50);
        let bounded = bounded_embed_field(&text, 10);
        assert_eq!(bounded.chars().count(), 10);
        assert!(bounded.chars().all(|c| c == 'é'));
    }

    #[test]
    fn format_graph_entity_text_with_context_appends_graph_neighborhood() {
        let entity = Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: "load_registry".into(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256([0; 32]),
                signature_hash: Hash256([0; 32]),
                behavior_hash: Hash256([0; 32]),
                equivalence_hash: Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new("src/registry.rs")),
            span: None,
            signature: "fn load_registry() -> Registry".into(),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        };

        let formatted = format_graph_entity_text_with_context(
            &entity,
            &[
                "calls parse_manifest".into(),
                "import_source serde_json".into(),
            ],
        );

        assert!(formatted.contains("load_registry"));
        assert!(formatted.contains("calls parse_manifest"));
        assert!(formatted.contains("import_source serde_json"));
    }

    #[test]
    fn format_graph_entity_text_byte_identical_to_joined_parts() {
        // The direct-build rewrite of `format_graph_entity_text_with_context`
        // must be byte-for-byte identical to the prior `Vec<String>` +
        // `join("\n")` construction, or persisted embed vectors would shift.
        // This reproduces that prior algorithm and asserts equality across the
        // field-presence and truncation permutations the embed path exercises.
        fn joined_reference(entity: &Entity, context_lines: &[String]) -> String {
            fn bounded(text: &str, max_chars: usize) -> String {
                if text.chars().count() <= max_chars {
                    text.to_string()
                } else {
                    text.chars().take(max_chars).collect()
                }
            }
            let mut parts: Vec<String> = Vec::new();
            parts.push(entity_kind_label(entity.kind).to_string());
            if let Some(file_origin) = &entity.file_origin {
                parts.push(file_origin.0.clone());
            }
            if !entity.name.is_empty() {
                parts.push(entity.name.clone());
            }
            if !entity.signature.is_empty() {
                parts.push(entity.signature.clone());
            }
            if let Some(doc_summary) = entity.doc_summary.as_deref() {
                let doc_summary = doc_summary.trim();
                if !doc_summary.is_empty() {
                    parts.push(bounded(doc_summary, EMBED_DOC_SUMMARY_MAX_CHARS));
                }
            }
            for key in [
                EMBEDDING_BODY_PREVIEW_KEY,
                FILE_IMPORT_CONTEXT_KEY,
                FILE_SURFACE_CONTEXT_KEY,
            ] {
                if let Some(text) = entity.metadata.extra.get(key).and_then(|v| v.as_str()) {
                    if !text.is_empty() {
                        parts.push(text.to_string());
                    }
                }
            }
            parts.extend(context_lines.iter().cloned());
            parts.join("\n")
        }

        let sample_entity = || Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: "load_registry".into(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256([0; 32]),
                signature_hash: Hash256([0; 32]),
                behavior_hash: Hash256([0; 32]),
                equivalence_hash: Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            // Repo-relative path: the new formatter's absolute-path guard must
            // stay a no-op so its push matches the reference exactly.
            file_origin: Some(FilePathId::new("src/registry.rs")),
            span: None,
            signature: "fn load_registry() -> Registry".into(),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: Some("Load the registry".into()),
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        };

        // Case 1: every field populated, including all three metadata contexts.
        let mut full = sample_entity();
        full.metadata.extra.insert(
            EMBEDDING_BODY_PREVIEW_KEY.into(),
            serde_json::Value::String("fn load_registry() -> Registry { .. }".into()),
        );
        full.metadata.extra.insert(
            FILE_IMPORT_CONTEXT_KEY.into(),
            serde_json::Value::String("module serde names Deserialize".into()),
        );
        full.metadata.extra.insert(
            FILE_SURFACE_CONTEXT_KEY.into(),
            serde_json::Value::String("surface registry".into()),
        );

        // Case 2: doc summary far over the cap → ASCII truncation path.
        let mut capped = sample_entity();
        capped.doc_summary = Some("word ".repeat(EMBED_DOC_SUMMARY_MAX_CHARS));

        // Case 3: minimal — no file, empty name + signature, no doc/metadata.
        let mut minimal = sample_entity();
        minimal.file_origin = None;
        minimal.name = String::new();
        minimal.signature = String::new();
        minimal.doc_summary = None;

        // Case 4: multibyte doc summary truncation on a char boundary.
        let mut multibyte = sample_entity();
        multibyte.doc_summary = Some("é".repeat(EMBED_DOC_SUMMARY_MAX_CHARS + 50));

        let cases: Vec<(Entity, Vec<String>)> = vec![
            (
                full,
                vec!["calls parse_manifest".into(), "import_source serde".into()],
            ),
            (capped, Vec::new()),
            (minimal, Vec::new()),
            (multibyte, vec!["neighbor load_other".into()]),
        ];

        for (entity, ctx) in cases {
            assert_eq!(
                format_graph_entity_text_with_context(&entity, &ctx),
                joined_reference(&entity, &ctx),
                "direct-build embed text diverged from the joined-parts reference",
            );
        }
    }

    #[cfg(feature = "vector")]
    #[test]
    fn embed_stage_timings_accumulate_and_delta() {
        let timings = EmbedStageTimings::default();
        let base = timings.snapshot();
        assert!(base.is_empty(), "a fresh accumulator records nothing");

        timings.record(EmbedStage::Drain, std::time::Duration::from_millis(2));
        timings.record(EmbedStage::Drain, std::time::Duration::from_millis(3));
        let out = timings.time(EmbedStage::Prep, || 7);
        assert_eq!(out, 7, "time() returns the closure's value");
        {
            // A scoped timer counts as one call even at ~zero duration.
            let _scope = timings.scope(EmbedStage::Forward);
        }

        let snap = timings.snapshot();
        assert_eq!(snap.stage(EmbedStage::Drain).calls, 2);
        assert_eq!(snap.stage(EmbedStage::Drain).nanos, 5_000_000);
        assert_eq!(snap.stage(EmbedStage::Prep).calls, 1);
        assert_eq!(snap.stage(EmbedStage::Forward).calls, 1);
        assert_eq!(snap.stage(EmbedStage::Persist).calls, 0);
        assert_eq!(snap.stage(EmbedStage::Prune).calls, 0);
        assert!(!snap.is_empty());
        assert!(snap.total_nanos() >= 5_000_000);

        let delta = snap.since(&base);
        assert_eq!(delta.stage(EmbedStage::Drain).calls, 2);
        assert_eq!(delta.stage(EmbedStage::Drain).nanos, 5_000_000);
        // A later baseline yields a zero (saturating, never underflowing) delta.
        assert!(snap.since(&snap).is_empty());
        // Smoke: summarizing must not panic with no subscriber installed.
        delta.log_summary("unit");
    }

    #[test]
    fn format_artifact_text_includes_kind_path_and_preview() {
        let artifact = StructuredArtifact {
            file_id: FilePathId::new("Makefile"),
            kind: ArtifactKind::Makefile,
            content_hash: Hash256([1; 32]),
            text_preview: Some("build target install test".into()),
        };

        let formatted = format_artifact_text(&artifact);
        assert_eq!(
            formatted,
            "structured_artifact\nkind=makefile\nfile=Makefile\nbuild target install test"
        );
    }

    #[test]
    fn format_opaque_text_includes_mime_and_preview() {
        let artifact = OpaqueArtifact {
            file_id: FilePathId::new("assets/logo.svg"),
            content_hash: Hash256([2; 32]),
            mime_type: Some("image/svg+xml".into()),
            text_preview: Some("svg logo icon".into()),
        };

        let formatted = format_opaque_text(&artifact);
        assert_eq!(
            formatted,
            "opaque_artifact\nfile=assets/logo.svg\nmime_type=image/svg+xml\nsvg logo icon"
        );
    }

    #[test]
    fn format_shallow_text_includes_surface_context() {
        let file = ShallowTrackedFile {
            file_id: FilePathId::new("src/lib.rs"),
            language_hint: "rust".into(),
            declaration_count: 2,
            import_count: 1,
            syntax_hash: Hash256([3; 32]),
            signature_hash: Some(Hash256([4; 32])),
            declaration_names: vec!["parse_config".into(), "load_registry".into()],
            import_paths: vec!["crate::config".into()],
        };

        let formatted = format_shallow_text(&file);
        assert!(formatted.starts_with(
            "shallow_file\nfile=src/lib.rs\nlanguage_hint=rust\ndeclaration_count=2\nimport_count=1"
        ));
        assert!(formatted.contains("signature_hash=Hash256"));
        assert!(formatted.contains("declarations=parse_config load_registry"));
        assert!(formatted.contains("imports=crate::config"));
    }

    #[test]
    fn default_dimensions_match_default_model() {
        #[cfg(feature = "embeddings")]
        {
            // See `EMBED_MODEL_DOWNLOAD_LOCK`: shares the HF Hub cache
            // download with
            // `engine::graph::tests::test_vector_index_dimension_mismatch_auto_recovery`.
            let _download_guard = EMBED_MODEL_DOWNLOAD_LOCK.lock();
            let embedder = CodeEmbedder::new().unwrap();
            assert_eq!(embedder.dimensions(), DEFAULT_EMBED_DIMS);
        }
    }

    #[cfg(feature = "embeddings")]
    #[test]
    fn backend_specific_default_batch_token_budget_matches_runtime() {
        assert_eq!(
            default_max_batch_tokens(GpuBackend::Cpu),
            DEFAULT_MAX_BATCH_TOKENS
        );
        assert_eq!(
            default_max_batch_tokens(GpuBackend::Cuda),
            CUDA_MAX_BATCH_TOKENS
        );
        assert_eq!(
            default_max_batch_tokens(GpuBackend::Metal),
            METAL_MAX_BATCH_TOKENS
        );
    }

    #[cfg(feature = "embeddings")]
    #[test]
    fn backend_specific_default_attention_area_matches_runtime() {
        assert_eq!(
            default_max_attention_area(GpuBackend::Metal),
            METAL_MAX_ATTENTION_AREA
        );
        // CUDA (large VRAM, flash-attention) stays unbounded; CPU is bounded by the
        // same area ceiling so the parallel host attention scratch can't OOM the daemon.
        assert_eq!(default_max_attention_area(GpuBackend::Cuda), usize::MAX);
        assert_eq!(
            default_max_attention_area(GpuBackend::Cpu),
            METAL_MAX_ATTENTION_AREA
        );
    }

    #[cfg(feature = "embeddings")]
    #[test]
    fn batch_budget_area_cap_splits_long_entity_dispatch() {
        // Token budget effectively unbounded so ONLY the attention-area cap binds.
        let budget = BatchBudget {
            max_tokens: usize::MAX,
            max_attention_area: METAL_MAX_ATTENTION_AREA, // 8_388_608 = 2 × 2048²
        };
        // Four entities at the EMBED_MAX_SEQ_LEN cap. attention area = 2048² × count;
        // count=2 → 8_388_608 (== cap, admitted), count=3 → 12_582_912 (> cap, split).
        // This is the exact worst-case dispatch verified to survive the GPU watchdog.
        let ids: Vec<Vec<u32>> = (0..4).map(|_| vec![0u32; 2048]).collect();
        let (end, longest) = budget.next_batch(&ids, 0);
        assert_eq!(
            end, 2,
            "long-entity dispatch must cap at 2 at the 2×2048² area"
        );
        assert_eq!(longest, 2048);
        // The remaining two pack into the next dispatch the same way.
        let (end2, _) = budget.next_batch(&ids, end);
        assert_eq!(end2, 4);
    }

    #[cfg(feature = "embeddings")]
    #[test]
    fn metal_hard_guard_rejects_crash_shape() {
        let safe = metal_hard_guard_rejection(2, EMBED_MAX_SEQ_LEN);
        assert_eq!(safe, None, "2 x 2048^2 is the verified safe Metal hard cap");

        let unsafe_shape = metal_hard_guard_rejection(8, EMBED_MAX_SEQ_LEN);
        assert_eq!(
            unsafe_shape,
            Some((33_554_432, METAL_MAX_ATTENTION_AREA)),
            "the 8 x 2048 smoke-crash shape must be declined before Metal allocation"
        );
    }

    #[cfg(feature = "embeddings")]
    #[test]
    fn batch_budget_token_cap_bounds_short_entity_dispatch() {
        // Area unbounded so ONLY the token cap binds: short entities still pack many,
        // exactly as before the area guard existed (no common-case regression).
        let budget = BatchBudget {
            max_tokens: METAL_MAX_BATCH_TOKENS, // 16_384
            max_attention_area: usize::MAX,
        };
        // 256-token entities: 16_384 / 256 = 64 per dispatch.
        let ids: Vec<Vec<u32>> = (0..100).map(|_| vec![0u32; 256]).collect();
        let (end, longest) = budget.next_batch(&ids, 0);
        assert_eq!(end, 64);
        assert_eq!(longest, 256);
    }

    #[cfg(feature = "embeddings")]
    #[test]
    fn batch_budget_admits_single_oversized_entity_alone() {
        // A lone entity exceeding both budgets is still admitted (so it always gets
        // embedded), but nothing else is packed with it.
        let budget = BatchBudget {
            max_tokens: 100,
            max_attention_area: 100,
        };
        let ids: Vec<Vec<u32>> = vec![vec![0u32; 2048], vec![0u32; 2048]];
        let (end, longest) = budget.next_batch(&ids, 0);
        assert_eq!(
            end, 1,
            "over-budget lone entity admitted; next not packed with it"
        );
        assert_eq!(longest, 2048);
    }

    #[cfg(feature = "embeddings")]
    #[test]
    fn tokenized_padding_trim_removes_only_right_padding() {
        let mut ids = vec![101, 201, 0, 301, 0, 0];
        let mut mask = vec![1, 1, 0, 1, 0, 0];
        trim_tokenized_right_padding(&mut ids, &mut mask);
        assert_eq!(ids, vec![101, 201, 0, 301]);
        assert_eq!(mask, vec![1, 1, 0, 1]);

        let mut all_padding_ids = vec![0, 0, 0];
        let mut all_padding_mask = vec![0, 0, 0];
        trim_tokenized_right_padding(&mut all_padding_ids, &mut all_padding_mask);
        assert_eq!(
            all_padding_ids,
            vec![0],
            "an all-padding row still keeps one token"
        );
        assert_eq!(
            all_padding_mask,
            vec![0],
            "an all-padding row still keeps one mask entry"
        );
    }

    #[cfg(feature = "embeddings")]
    #[test]
    fn encoded_batch_sorts_and_budgets_by_unpadded_lengths() {
        fn padded_row(real_len: usize, padded_len: usize) -> (Vec<u32>, Vec<u32>) {
            let mut ids: Vec<u32> = (0..padded_len).map(|i| i as u32).collect();
            let mut mask = vec![0u32; padded_len];
            for value in mask.iter_mut().take(real_len) {
                *value = 1;
            }
            ids.truncate(padded_len);
            (ids, mask)
        }

        let padded_len = 2048;
        let tokenized = vec![
            {
                let (ids, mask) = padded_row(8, padded_len);
                (0usize, ids, mask)
            },
            {
                let (ids, mask) = padded_row(3, padded_len);
                (1usize, ids, mask)
            },
            {
                let (ids, mask) = padded_row(4, padded_len);
                (2usize, ids, mask)
            },
        ];
        assert!(tokenized
            .iter()
            .all(|(_, ids, mask)| ids.len() == padded_len && mask.len() == padded_len));

        let batch = encoded_batch_from_tokenized(tokenized);
        assert_eq!(batch.idx, vec![1, 2, 0]);
        assert_eq!(
            batch.ids.iter().map(Vec::len).collect::<Vec<_>>(),
            vec![3, 4, 8]
        );
        assert_eq!(
            batch.masks.iter().map(Vec::len).collect::<Vec<_>>(),
            vec![3, 4, 8]
        );

        let budget = BatchBudget {
            max_tokens: 24,
            max_attention_area: usize::MAX,
        };
        let (end, longest) = budget.next_batch(&batch.ids, 0);
        assert_eq!(
            (end, longest),
            (3, 8),
            "unpadded lengths should pack the whole mixed-length batch"
        );
    }

    #[cfg(feature = "embeddings")]
    static RESOURCE_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Serializes the tests that mutate the process-global `adaptive_split` state
    /// so the parallel test runner can't interleave their reset/record/plan calls.
    #[cfg(feature = "embeddings")]
    static ADAPTIVE_STATE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Serializes the tests that read/reset the process-global `hybrid_metrics`
    /// counters so a parallel reset can't clobber another test's assertion.
    #[cfg(feature = "embeddings")]
    static HYBRID_METRICS_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Serializes process-env access for the resource-profile tests and snapshots
    /// the relevant vars, restoring them on drop so the suite never leaks state.
    #[cfg(feature = "embeddings")]
    struct ResourceEnvGuard {
        _lock: std::sync::MutexGuard<'static, ()>,
        profile: Option<String>,
        max_tokens: Option<String>,
        max_area: Option<String>,
        hybrid: Option<String>,
        hybrid_ratio: Option<String>,
        hybrid_cpu_max_seq_len: Option<String>,
        backend: Option<String>,
    }

    #[cfg(feature = "embeddings")]
    impl ResourceEnvGuard {
        fn acquire() -> Self {
            let lock = RESOURCE_ENV_LOCK
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            let guard = Self {
                _lock: lock,
                profile: std::env::var("KIN_RESOURCE_PROFILE").ok(),
                max_tokens: std::env::var("KIN_EMBED_MAX_BATCH_TOKENS").ok(),
                max_area: std::env::var("KIN_EMBED_MAX_ATTENTION_AREA").ok(),
                hybrid: std::env::var("KIN_EMBED_HYBRID").ok(),
                hybrid_ratio: std::env::var("KIN_EMBED_HYBRID_GPU_TPUT_RATIO").ok(),
                hybrid_cpu_max_seq_len: std::env::var("KIN_EMBED_HYBRID_CPU_MAX_SEQ_LEN").ok(),
                backend: std::env::var("KIN_EMBED_BACKEND").ok(),
            };
            std::env::remove_var("KIN_RESOURCE_PROFILE");
            std::env::remove_var("KIN_EMBED_MAX_BATCH_TOKENS");
            std::env::remove_var("KIN_EMBED_MAX_ATTENTION_AREA");
            std::env::remove_var("KIN_EMBED_HYBRID");
            std::env::remove_var("KIN_EMBED_HYBRID_GPU_TPUT_RATIO");
            std::env::remove_var("KIN_EMBED_HYBRID_CPU_MAX_SEQ_LEN");
            std::env::remove_var("KIN_EMBED_BACKEND");
            guard
        }
    }

    #[cfg(feature = "embeddings")]
    impl Drop for ResourceEnvGuard {
        fn drop(&mut self) {
            let restore = |key: &str, prev: &Option<String>| match prev {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            };
            restore("KIN_RESOURCE_PROFILE", &self.profile);
            restore("KIN_EMBED_MAX_BATCH_TOKENS", &self.max_tokens);
            restore("KIN_EMBED_MAX_ATTENTION_AREA", &self.max_area);
            restore("KIN_EMBED_HYBRID", &self.hybrid);
            restore("KIN_EMBED_HYBRID_GPU_TPUT_RATIO", &self.hybrid_ratio);
            restore(
                "KIN_EMBED_HYBRID_CPU_MAX_SEQ_LEN",
                &self.hybrid_cpu_max_seq_len,
            );
            restore("KIN_EMBED_BACKEND", &self.backend);
        }
    }

    #[cfg(feature = "embeddings")]
    #[test]
    fn batch_budget_unset_profile_matches_today() {
        let _env = ResourceEnvGuard::acquire();
        let budget = BatchBudget::from_env(GpuBackend::Metal);
        assert_eq!(budget.max_tokens, METAL_MAX_BATCH_TOKENS);
        assert_eq!(budget.max_tokens, 16_384);
        assert_eq!(budget.max_attention_area, 8_388_608);
    }

    #[cfg(feature = "embeddings")]
    #[test]
    fn batch_budget_throughput_lifts_metal_tokens_keeps_area() {
        let _env = ResourceEnvGuard::acquire();
        std::env::set_var("KIN_RESOURCE_PROFILE", "throughput");
        // The budget mirrors whatever the resource plan resolves for this host.
        // ResourcePlan's throughput caps auto-scale with hardware (memory/cores),
        // so this asserts against the plan rather than a fixed number — it only
        // pins the invariant that throughput LIFTS the token budget above proof.
        let plan = throughput_embedding_plan(GpuBackend::Metal);
        let budget = BatchBudget::from_env(GpuBackend::Metal);
        assert_eq!(budget.max_tokens, plan.max_batch_tokens);
        assert!(
            budget.max_tokens > METAL_MAX_BATCH_TOKENS,
            "throughput must lift the token budget above the proof default"
        );
        let expected_area = plan
            .max_attention_area
            .map(|area| area as usize)
            .unwrap_or(usize::MAX)
            .min(METAL_MAX_ATTENTION_AREA);
        assert_eq!(budget.max_attention_area, expected_area);
        assert_eq!(
            budget.max_attention_area, METAL_MAX_ATTENTION_AREA,
            "throughput may lift token budget, but Metal attention area stays at the verified hard cap"
        );
    }

    #[cfg(feature = "embeddings")]
    #[test]
    fn batch_budget_env_override_wins_over_throughput() {
        let _env = ResourceEnvGuard::acquire();
        std::env::set_var("KIN_RESOURCE_PROFILE", "throughput");
        std::env::set_var("KIN_EMBED_MAX_BATCH_TOKENS", "12345");
        // The explicit token override wins; the attention area still tracks the
        // plan (auto-scaled, so not hardcoded).
        let plan = throughput_embedding_plan(GpuBackend::Metal);
        let budget = BatchBudget::from_env(GpuBackend::Metal);
        assert_eq!(budget.max_tokens, 12_345);
        let expected_area = plan
            .max_attention_area
            .map(|area| area as usize)
            .unwrap_or(usize::MAX)
            .min(METAL_MAX_ATTENTION_AREA);
        assert_eq!(budget.max_attention_area, expected_area);
    }

    #[cfg(feature = "embeddings")]
    #[test]
    fn metal_attention_area_env_override_cannot_raise_hard_cap() {
        let _env = ResourceEnvGuard::acquire();
        std::env::set_var("KIN_RESOURCE_PROFILE", "throughput");
        std::env::set_var("KIN_EMBED_MAX_ATTENTION_AREA", "33554432");

        let budget = BatchBudget::from_env(GpuBackend::Metal);
        assert_eq!(
            budget.max_attention_area, METAL_MAX_ATTENTION_AREA,
            "env override cannot raise Metal above the verified hard guard"
        );

        std::env::set_var("KIN_EMBED_MAX_ATTENTION_AREA", "4194304");
        let tightened = BatchBudget::from_env(GpuBackend::Metal);
        assert_eq!(
            tightened.max_attention_area, 4_194_304,
            "env override may still lower Metal's hard guard"
        );
    }

    #[cfg(feature = "embeddings")]
    #[test]
    fn resolve_embed_backend_honors_env_and_metal_default() {
        let _env = ResourceEnvGuard::acquire();

        std::env::set_var("KIN_EMBED_BACKEND", "auto");
        // `EMBED_AUTO_PREFERS_CPU` is `false`: auto stays on Metal. CPU is an
        // explicit debug escape hatch via KIN_EMBED_BACKEND=cpu.
        assert!(matches!(
            resolve_embed_backend(8),
            EmbedBackendChoice::Metal { .. }
        ));
        assert!(matches!(
            resolve_embed_backend(128),
            EmbedBackendChoice::Metal { .. }
        ));
        assert!(matches!(
            resolve_embed_backend(EMBED_CPU_SEQ_THRESHOLD + 1),
            EmbedBackendChoice::Metal { .. }
        ));

        std::env::set_var("KIN_EMBED_BACKEND", "cpu");
        assert!(matches!(
            resolve_embed_backend(64),
            EmbedBackendChoice::Cpu { .. }
        ));
        assert!(matches!(
            resolve_embed_backend(1024),
            EmbedBackendChoice::Cpu { .. }
        ));

        std::env::set_var("KIN_EMBED_BACKEND", "metal");
        assert!(matches!(
            resolve_embed_backend(1024),
            EmbedBackendChoice::Metal { .. }
        ));

        // An unrecognized value falls through to the auto path, which now keeps
        // long code entities on Metal.
        std::env::set_var("KIN_EMBED_BACKEND", "nonsense-value");
        assert!(matches!(
            resolve_embed_backend(EMBED_CPU_SEQ_THRESHOLD + 1),
            EmbedBackendChoice::Metal { .. }
        ));
    }

    #[cfg(feature = "embeddings")]
    #[test]
    fn hybrid_mode_default_is_off_for_proof() {
        let _env = ResourceEnvGuard::acquire();
        assert_eq!(hybrid_mode(GpuBackend::Metal), HybridMode::Off);
        assert_eq!(hybrid_mode(GpuBackend::Cpu), HybridMode::Off);
    }

    #[cfg(feature = "embeddings")]
    #[test]
    fn hybrid_mode_proof_profile_is_off() {
        let _env = ResourceEnvGuard::acquire();
        std::env::set_var("KIN_RESOURCE_PROFILE", "proof");
        assert_eq!(hybrid_mode(GpuBackend::Metal), HybridMode::Off);
    }

    #[cfg(feature = "embeddings")]
    #[test]
    fn hybrid_mode_throughput_matches_resource_plan() {
        let _env = ResourceEnvGuard::acquire();
        std::env::set_var("KIN_RESOURCE_PROFILE", "throughput");
        let expected = match throughput_embedding_plan(GpuBackend::Metal).hybrid_mode {
            kin_infer::resource::HybridMode::Off => HybridMode::Off,
            kin_infer::resource::HybridMode::SequentialFloor => HybridMode::SeqFloor,
            // No explicit ratio env, so the split is adaptive (None).
            kin_infer::resource::HybridMode::Balanced => HybridMode::Balanced {
                gpu_tput_ratio: None,
            },
        };
        assert_eq!(hybrid_mode(GpuBackend::Metal), expected);
    }

    #[cfg(feature = "embeddings")]
    #[test]
    fn hybrid_mode_explicit_off_overrides_throughput() {
        let _env = ResourceEnvGuard::acquire();
        std::env::set_var("KIN_RESOURCE_PROFILE", "throughput");
        std::env::set_var("KIN_EMBED_HYBRID", "0");
        assert_eq!(hybrid_mode(GpuBackend::Metal), HybridMode::Off);
    }

    #[cfg(feature = "embeddings")]
    #[test]
    fn hybrid_mode_explicit_balanced_wins_without_profile() {
        let _env = ResourceEnvGuard::acquire();
        std::env::set_var("KIN_EMBED_HYBRID", "1");
        // Hybrid forced on, but no explicit ratio → adaptive (None).
        assert_eq!(
            hybrid_mode(GpuBackend::Metal),
            HybridMode::Balanced {
                gpu_tput_ratio: None
            }
        );
    }

    #[cfg(feature = "embeddings")]
    #[test]
    fn hybrid_mode_non_auto_backend_disables_throughput_hybrid() {
        let _env = ResourceEnvGuard::acquire();
        std::env::set_var("KIN_RESOURCE_PROFILE", "throughput");
        std::env::set_var("KIN_EMBED_BACKEND", "cpu");
        assert_eq!(hybrid_mode(GpuBackend::Metal), HybridMode::Off);
    }

    #[cfg(feature = "embeddings")]
    #[test]
    fn balanced_cpu_max_seq_len_env_is_narrow_and_below_token_cap() {
        let _env = ResourceEnvGuard::acquire();
        assert_eq!(balanced_cpu_max_seq_len(), BALANCED_CPU_MAX_SEQ_LEN);
        assert!(balanced_cpu_max_seq_len() < EMBED_MAX_SEQ_LEN);

        std::env::set_var("KIN_EMBED_HYBRID_CPU_MAX_SEQ_LEN", "384");
        assert_eq!(balanced_cpu_max_seq_len(), 384);

        std::env::set_var("KIN_EMBED_HYBRID_CPU_MAX_SEQ_LEN", "999999");
        assert_eq!(balanced_cpu_max_seq_len(), EMBED_MAX_SEQ_LEN - 1);

        std::env::set_var("KIN_EMBED_HYBRID_CPU_MAX_SEQ_LEN", "0");
        assert_eq!(balanced_cpu_max_seq_len(), BALANCED_CPU_MAX_SEQ_LEN);
    }

    /// Build a length-sorted `EncodedBatch` from a list of input lengths, exactly
    /// as `embed_uncached_batch` does: `idx[k]` is the original (pre-sort) input
    /// position of the k-th shortest entity.
    #[cfg(feature = "embeddings")]
    fn encoded_batch_from_lengths(lengths: &[usize]) -> EncodedBatch {
        let mut order: Vec<(usize, usize)> = lengths.iter().copied().enumerate().collect();
        order.sort_by_key(|(_, len)| *len);
        let mut batch = EncodedBatch {
            idx: Vec::with_capacity(order.len()),
            ids: Vec::with_capacity(order.len()),
            masks: Vec::with_capacity(order.len()),
        };
        for (orig, len) in order {
            let len = len.max(1);
            batch.idx.push(orig);
            batch.ids.push(vec![0u32; len]);
            batch.masks.push(vec![1u32; len]);
        }
        batch
    }

    #[cfg(feature = "embeddings")]
    fn covers_all_indices(metal: &EncodedBatch, cpu: &EncodedBatch, total: usize) {
        let mut seen: Vec<usize> = metal.idx.iter().chain(cpu.idx.iter()).copied().collect();
        seen.sort_unstable();
        assert_eq!(
            seen,
            (0..total).collect::<Vec<_>>(),
            "every original index must appear exactly once across both arms"
        );
    }

    // On a realistic post-tokenization mix of many cheap entities plus under-cap
    // heavy ones, both the GPU arm and CPU twin must receive a real share.
    #[cfg(feature = "embeddings")]
    #[test]
    fn balanced_partition_engages_both_arms_on_real_mix() {
        let mut lengths: Vec<usize> = (0..160).map(|i| 64 + (i % 4) * 32).collect();
        lengths.extend((0..40).map(|i| 512 + (i % 5) * 192));
        let batch = encoded_batch_from_lengths(&lengths);
        let (metal, cpu) = balanced_partition_with_cpu_max_seq_len(batch.as_slice(), 4.0, 0, 256);

        assert!(
            metal.len() > 0,
            "GPU arm must get a real share of the batch"
        );
        assert!(cpu.len() > 0, "CPU twin must get a real share of the batch");
        assert!(
            cpu.ids.iter().all(|ids| ids.len() <= 256),
            "CPU twin should receive cheap entities"
        );
        assert!(
            metal.ids.iter().any(|ids| ids.len() > 256),
            "GPU arm should carry heavier under-cap entities"
        );
        covers_all_indices(&metal, &cpu, lengths.len());
    }

    // When under-cap heavy work dominates, the CPU twin takes all cheap entities
    // while the GPU carries the heavier tokenized entities.
    #[cfg(feature = "embeddings")]
    #[test]
    fn balanced_partition_heavy_under_cap_keeps_gpu_busy() {
        let mut lengths: Vec<usize> = (0..10).map(|_| 128).collect();
        lengths.extend((0..10).map(|_| 1200));
        let batch = encoded_batch_from_lengths(&lengths);
        let (metal, cpu) = balanced_partition_with_cpu_max_seq_len(batch.as_slice(), 4.0, 0, 256);

        assert_eq!(
            metal.len(),
            10,
            "every heavy entity should land on the GPU arm"
        );
        assert!(
            metal.ids.iter().all(|ids| ids.len() > 256),
            "GPU arm must hold the heavier under-cap sequences"
        );
        assert_eq!(
            cpu.len(),
            10,
            "every cheap entity should land on the CPU arm"
        );
        assert!(
            cpu.ids.iter().all(|ids| ids.len() <= 256),
            "CPU twin must hold the cheap sequences"
        );
        covers_all_indices(&metal, &cpu, lengths.len());
    }

    // With no heavy entities the split reduces to the GPU taking ratio/(ratio+1)
    // of uniform cheap work — ~80% at the default 4× ratio, ~20% to the CPU.
    #[cfg(feature = "embeddings")]
    #[test]
    fn balanced_partition_no_long_splits_short_by_ratio() {
        let lengths: Vec<usize> = (0..100).map(|_| 100).collect();
        let batch = encoded_batch_from_lengths(&lengths);
        let (metal, cpu) = balanced_partition_with_cpu_max_seq_len(batch.as_slice(), 4.0, 0, 256);

        assert!(metal.len() > 0 && cpu.len() > 0, "both arms must run");
        let metal_frac = metal.len() as f64 / lengths.len() as f64;
        assert!(
            (metal_frac - 0.8).abs() < 0.05,
            "GPU share {metal_frac} should be ~0.8 (= 4/(4+1)) of uniform short work"
        );
        covers_all_indices(&metal, &cpu, lengths.len());
    }

    // Determinism: the same batch partitions identically across runs, and the union
    // of both arms is exactly the input index set with no duplicates — so scattering
    // results back by original index (see `scatter_placed`) is order-stable no matter
    // how the CPU/GPU split falls. (Cross-backend fp parity of the vectors themselves
    // requires a real GPU embed on Metal hardware.)
    #[cfg(feature = "embeddings")]
    #[test]
    fn balanced_partition_is_deterministic_and_order_stable() {
        let mut lengths = Vec::new();
        for i in 0..300usize {
            // Deterministic pseudo-mix of cheap and heavier under-cap sequences.
            let len = if i % 7 == 0 {
                512 + (i % 5) * 200
            } else {
                50 + (i % 31)
            };
            lengths.push(len);
        }
        let batch = encoded_batch_from_lengths(&lengths);
        let (m1, c1) = balanced_partition_with_cpu_max_seq_len(batch.as_slice(), 3.5, 0, 256);
        let (m2, c2) = balanced_partition_with_cpu_max_seq_len(batch.as_slice(), 3.5, 0, 256);
        assert_eq!(m1.idx, m2.idx, "GPU assignment must be deterministic");
        assert_eq!(c1.idx, c2.idx, "CPU assignment must be deterministic");
        covers_all_indices(&m1, &c1, lengths.len());
    }

    // The adaptive ratio rides toward GPU-only when the CPU twin is much slower
    // (long sequences) and settles low when the CPU keeps up (short sequences) —
    // exactly what stops the twin from dragging the GPU on long code corpora.
    // (Only this test mutates the process-global adaptive state.)
    #[cfg(feature = "embeddings")]
    #[test]
    fn adaptive_ratio_tracks_measured_throughput() {
        let _guard = ADAPTIVE_STATE_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        // CPU ~100× slower: GPU 100k tok in 0.1s (1M tok/s), CPU 5k tok in 0.5s (10k tok/s).
        adaptive_split::reset();
        for _ in 0..12 {
            adaptive_split::record(100_000, 0.1, 5_000, 0.5);
        }
        let (slow_cpu_ratio, _, _, _, samples) = adaptive_split::snapshot();
        assert!(samples >= 12);
        assert!(
            slow_cpu_ratio > 40.0,
            "ratio must ride up toward GPU-only when the CPU drags, got {slow_cpu_ratio}"
        );

        // CPU keeps up: GPU 1M tok/s, CPU 900k tok/s → ratio ~1.1.
        adaptive_split::reset();
        for _ in 0..12 {
            adaptive_split::record(100_000, 0.1, 90_000, 0.1);
        }
        let (fast_cpu_ratio, _, _, _, _) = adaptive_split::snapshot();
        assert!(
            fast_cpu_ratio < 2.0,
            "ratio must settle low when the CPU keeps up, got {fast_cpu_ratio}"
        );
        adaptive_split::reset();
    }

    // A high ratio gives the twin zero, but the probe must still hand it the
    // minimum (shortest) entities so the next batch yields a fresh measurement.
    #[cfg(feature = "embeddings")]
    #[test]
    fn adaptive_probe_forces_min_cpu_share() {
        let lengths: Vec<usize> = (0..40).map(|i| 100 + i).collect();
        let batch = encoded_batch_from_lengths(&lengths);
        // Without a probe, a near-infinite ratio sends ~everything to the GPU.
        let (_, cpu_no_probe) =
            balanced_partition_with_cpu_max_seq_len(batch.as_slice(), 1.0e6, 0, 256);
        assert!(
            cpu_no_probe.len() <= 1,
            "high ratio with no probe → ~GPU-only, got {}",
            cpu_no_probe.len()
        );
        // With a probe of 2, the twin gets at least its minimum share.
        let (metal, cpu) = balanced_partition_with_cpu_max_seq_len(batch.as_slice(), 1.0e6, 2, 256);
        assert!(
            cpu.len() >= 2,
            "probe must hand the twin its minimum share, got {}",
            cpu.len()
        );
        assert!(
            cpu.ids.iter().all(|ids| ids.len() <= 102),
            "probe must pick the shortest entities (cheapest CPU cost)"
        );
        covers_all_indices(&metal, &cpu, lengths.len());
    }

    // After the early-probe window the plan engages the twin ONLY when the last
    // measurement showed it finishing within the GPU arm's time — otherwise it
    // stays GPU-only rather than fake-balancing a dragging split.
    #[cfg(feature = "embeddings")]
    #[test]
    fn adaptive_plan_engages_twin_only_when_beneficial() {
        use adaptive_split::SplitPlan;
        let _guard = ADAPTIVE_STATE_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());

        // CPU drags (cpu_secs 0.5 > gpu_secs 0.1) → GPU-only after the probe window.
        adaptive_split::reset();
        adaptive_split::record(100_000, 0.1, 5_000, 0.5);
        let mut plan = None;
        for _ in 0..5 {
            plan = Some(adaptive_split::plan());
        }
        assert!(
            matches!(plan, Some(SplitPlan::GpuOnly)),
            "a dragging CPU must yield GPU-only after the probe window"
        );

        // CPU keeps up (cpu_secs 0.1 <= gpu_secs 0.1) → engage the twin.
        adaptive_split::reset();
        adaptive_split::record(100_000, 0.1, 90_000, 0.1);
        let mut plan = None;
        for _ in 0..5 {
            plan = Some(adaptive_split::plan());
        }
        assert!(
            matches!(plan, Some(SplitPlan::Balanced { .. })),
            "a CPU that keeps up must engage a balanced split"
        );
        adaptive_split::reset();
    }

    // The SeqFloor split (slice `split_at`, zero-clone) likewise covers every index
    // exactly once.
    #[cfg(feature = "embeddings")]
    #[test]
    fn seqfloor_split_covers_all_indices() {
        let mut lengths: Vec<usize> = (0..50).map(|i| 100 + i).collect();
        lengths.extend((0..15).map(|i| EMBED_CPU_SEQ_THRESHOLD + 100 + i * 10));
        let batch = encoded_batch_from_lengths(&lengths);
        let split = batch
            .ids
            .partition_point(|ids| ids.len() <= EMBED_CPU_SEQ_THRESHOLD);
        let (short, long) = batch.as_slice().split_at(split);
        assert!(
            !short.is_empty() && !long.is_empty(),
            "both sides should be present"
        );
        let mut seen: Vec<usize> = short.idx.iter().chain(long.idx.iter()).copied().collect();
        seen.sort_unstable();
        assert_eq!(seen, (0..lengths.len()).collect::<Vec<_>>());
        assert!(short
            .ids
            .iter()
            .all(|ids| ids.len() <= EMBED_CPU_SEQ_THRESHOLD));
        assert!(long
            .ids
            .iter()
            .all(|ids| ids.len() > EMBED_CPU_SEQ_THRESHOLD));
    }

    #[cfg(feature = "embeddings")]
    fn ids_of_lengths(lengths: &[usize]) -> Vec<Vec<u32>> {
        lengths.iter().map(|&len| vec![0u32; len]).collect()
    }

    // Every tokenized entity is truncated to `EMBED_MAX_SEQ_LEN`, which equals
    // `EMBED_CPU_SEQ_THRESHOLD`, so a real post-tokenization batch never has an
    // over-cap entity: the sequence-length split is structurally degenerate and
    // the route reports it as such rather than masquerading as a balanced hybrid.
    #[cfg(feature = "embeddings")]
    #[test]
    fn plan_seqfloor_route_is_degenerate_when_all_under_cap() {
        let ids = ids_of_lengths(&(0..32).map(|i| 64 + i).collect::<Vec<_>>());
        assert_eq!(plan_seqfloor_route(&ids), SeqFloorRoute::Degenerate);
        // The boundary length (exactly at the cap) is still CPU-ineligible by the
        // `<= threshold` test, so a full-cap batch is degenerate too.
        let at_cap = ids_of_lengths(&[EMBED_CPU_SEQ_THRESHOLD; 4]);
        assert_eq!(plan_seqfloor_route(&at_cap), SeqFloorRoute::Degenerate);
    }

    // The defensive `> threshold` arm: if a future sequence ever exceeds the cap,
    // the route splits at the first over-cap (length-sorted) entity so the long
    // tail rides the CPU twin and the short head stays on the GPU.
    #[cfg(feature = "embeddings")]
    #[test]
    fn plan_seqfloor_route_splits_when_over_cap_present() {
        let mut lengths: Vec<usize> = (0..10).map(|i| 100 + i).collect();
        lengths.extend((0..5).map(|i| EMBED_CPU_SEQ_THRESHOLD + 1 + i));
        let ids = ids_of_lengths(&lengths);
        match plan_seqfloor_route(&ids) {
            SeqFloorRoute::SplitByLength { cpu_from } => {
                assert_eq!(cpu_from, 10, "split begins at the first over-cap entity");
                assert!(ids[..cpu_from]
                    .iter()
                    .all(|e| e.len() <= EMBED_CPU_SEQ_THRESHOLD));
                assert!(ids[cpu_from..]
                    .iter()
                    .all(|e| e.len() > EMBED_CPU_SEQ_THRESHOLD));
            }
            other => panic!("expected SplitByLength, got {other:?}"),
        }
    }

    // An empty batch is not "degenerate" (there is no work and nothing to record);
    // it takes the cheap split-at-zero path so no degenerate counter is bumped.
    #[cfg(feature = "embeddings")]
    #[test]
    fn plan_seqfloor_route_empty_batch_is_not_degenerate() {
        let ids: Vec<Vec<u32>> = Vec::new();
        assert_eq!(
            plan_seqfloor_route(&ids),
            SeqFloorRoute::SplitByLength { cpu_from: 0 }
        );
    }

    // The route is a pure function of the lengths: the same batch always decides
    // the same way, with no timing or global-state dependence.
    #[cfg(feature = "embeddings")]
    #[test]
    fn plan_seqfloor_route_is_deterministic() {
        let mut lengths: Vec<usize> = (0..20).map(|i| 80 + i).collect();
        lengths.extend((0..3).map(|i| EMBED_CPU_SEQ_THRESHOLD + 1 + i));
        let ids = ids_of_lengths(&lengths);
        assert_eq!(plan_seqfloor_route(&ids), plan_seqfloor_route(&ids));
    }

    // The degenerate-split counter is observable: it starts at zero, records each
    // degenerate SeqFloor batch, and clears on reset.
    #[cfg(feature = "embeddings")]
    #[test]
    fn seqfloor_degenerate_metric_records_and_resets() {
        let _guard = HYBRID_METRICS_LOCK
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        hybrid_metrics::reset();
        assert_eq!(hybrid_metrics::snapshot().seqfloor_degenerate_batches, 0);
        hybrid_metrics::record_seqfloor_degenerate_batch();
        hybrid_metrics::record_seqfloor_degenerate_batch();
        assert_eq!(hybrid_metrics::snapshot().seqfloor_degenerate_batches, 2);
        hybrid_metrics::reset();
        assert_eq!(hybrid_metrics::snapshot().seqfloor_degenerate_batches, 0);
    }

    #[cfg(feature = "embeddings")]
    #[test]
    fn embedding_cache_round_trips_vectors() {
        let dir = tempfile::tempdir().unwrap();
        let cache =
            EmbeddingCache::new_in(dir.path().to_path_buf(), "test_model-namespace".into(), 4)
                .expect("cache should initialize");
        let key = cache.key_for_text("hello");

        assert!(cache.get_by_key(&key).is_none());

        cache.put_by_key(&key, &[1.0, 2.0, 3.0, 4.0]);
        assert_eq!(cache.get_by_key(&key).unwrap(), vec![1.0, 2.0, 3.0, 4.0]);
    }

    #[cfg(feature = "embeddings")]
    #[test]
    fn openai_embedding_response_is_ordered_by_index() {
        let body = r#"{
            "object": "list",
            "data": [
                {"object": "embedding", "index": 1, "embedding": [0.0, 1.0]},
                {"object": "embedding", "index": 0, "embedding": [1.0, 0.0]}
            ],
            "model": "test"
        }"#;

        let vectors = parse_openai_embedding_response(body, 2).unwrap();
        assert_eq!(vectors, vec![vec![1.0, 0.0], vec![0.0, 1.0]]);
    }

    #[cfg(feature = "embeddings")]
    #[test]
    fn parse_model_config_tolerates_canonical_plus_alias() {
        #[derive(serde::Deserialize)]
        struct Cfg {
            #[serde(alias = "layer_norm_epsilon")]
            layer_norm_eps: f64,
        }
        let json = r#"{"layer_norm_eps":1e-12,"layer_norm_epsilon":1e-12}"#;
        assert!(serde_json::from_str::<Cfg>(json).is_err());
        let cfg: Cfg = parse_model_config(json).expect("tolerant parse drops the alias");
        assert_eq!(cfg.layer_norm_eps, 1e-12);
    }

    #[cfg(feature = "embeddings")]
    #[test]
    fn openai_embedding_response_rejects_count_mismatch() {
        let body = r#"{"data":[{"index":0,"embedding":[1.0]}]}"#;
        let err = parse_openai_embedding_response(body, 2).unwrap_err();
        assert!(err.to_string().contains("returned 1 vectors for 2 inputs"));
    }

    #[cfg(feature = "embeddings")]
    #[test]
    fn nomic_defaults_use_search_prefixes() {
        let (query, document) =
            default_openai_embedding_prefixes("text-embedding-nomic-embed-text-v1.5");
        assert_eq!(query, "search_query: ");
        assert_eq!(document, "search_document: ");

        let (query, document) = default_openai_embedding_prefixes("text-embedding-3-small");
        assert_eq!(query, "");
        assert_eq!(document, "");
    }

    #[cfg(feature = "embeddings")]
    #[test]
    fn openai_runtime_revision_includes_request_overrides() {
        let base = OpenAiCompatConfig {
            provider_label: "openai-compatible".into(),
            base_url: "http://localhost:1234/v1".into(),
            model_id: "test-embed".into(),
            api_key: None,
            dimensions: Some(3),
            send_dimensions: false,
            timeout_secs: 30,
            request_overrides: serde_json::Map::new(),
            query_prefix: String::new(),
            document_prefix: String::new(),
        };
        let mut tuned = base.clone();
        tuned.request_overrides.insert(
            "encoding_format".into(),
            serde_json::Value::String("float".into()),
        );

        assert_ne!(base.runtime_revision(), tuned.runtime_revision());
    }

    #[cfg(feature = "embeddings")]
    fn test_openai_embedder(query_prefix: &str, document_prefix: &str) -> OpenAiCompatEmbedder {
        OpenAiCompatEmbedder {
            client: BlockingHttpClient::new(),
            endpoint: "http://localhost:1234/v1/embeddings".into(),
            model_id: "test-embed".into(),
            api_key: None,
            dimensions: 2,
            request_overrides: serde_json::Map::new(),
            query_prefix: query_prefix.into(),
            document_prefix: document_prefix.into(),
        }
    }

    #[cfg(feature = "embeddings")]
    #[test]
    fn code_embedder_prepare_inputs_borrows_without_prefixes() {
        let embedder = CodeEmbedder {
            backend: CodeEmbedderBackend::OpenAiCompat(test_openai_embedder("", "")),
            dimensions: 2,
            cache: None,
        };
        let texts = vec!["alpha".to_string(), "beta".to_string()];

        let prepared = embedder.prepare_inputs(&texts, EmbeddingInputRole::Document);
        match prepared {
            Cow::Borrowed(slice) => assert!(std::ptr::eq(slice.as_ptr(), texts.as_ptr())),
            Cow::Owned(_) => panic!("unprefixed document inputs should be borrowed"),
        }
    }

    #[cfg(feature = "embeddings")]
    #[test]
    fn code_embedder_prepare_inputs_owns_prefixed_roles() {
        let embedder = CodeEmbedder {
            backend: CodeEmbedderBackend::OpenAiCompat(test_openai_embedder(
                "search_query: ",
                "search_document: ",
            )),
            dimensions: 2,
            cache: None,
        };
        let texts = vec!["alpha".to_string(), "beta".to_string()];

        let queries = embedder.prepare_inputs(&texts, EmbeddingInputRole::Query);
        assert!(matches!(queries, Cow::Owned(_)));
        assert_eq!(
            queries.as_ref(),
            &[
                "search_query: alpha".to_string(),
                "search_query: beta".to_string()
            ]
        );

        let documents = embedder.prepare_inputs(&texts, EmbeddingInputRole::Document);
        assert!(matches!(documents, Cow::Owned(_)));
        assert_eq!(
            documents.as_ref(),
            &[
                "search_document: alpha".to_string(),
                "search_document: beta".to_string()
            ]
        );
        assert_eq!(texts, vec!["alpha".to_string(), "beta".to_string()]);
    }

    // ── no-absolute-path guard ───────────────────────────────────────────────

    /// Guard test (durable artifact): a machine-absolute path in file_origin
    /// triggers the debug_assert! guard, documenting that this is a bug.
    /// In debug builds (all `cargo test` runs) this panics; a regression that
    /// introduces absolute paths will be caught immediately.
    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "absolute path in embed text")]
    fn absolute_file_origin_guard_fires() {
        let entity = Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: "absolute_path_fn".into(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256([0; 32]),
                signature_hash: Hash256([0; 32]),
                behavior_hash: Hash256([0; 32]),
                equivalence_hash: Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            // Machine-absolute path — must never enter the embedder.
            file_origin: Some(FilePathId::new("/Users/ci/myrepo/src/config.rs")),
            span: None,
            signature: "fn absolute_path_fn()".into(),
            visibility: kin_model::Visibility::Public,
            role: kin_model::EntityRole::Source,
            doc_summary: None,
            metadata: kin_model::EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        };
        // The debug_assert! inside format_graph_entity_text_with_context fires here.
        let _ = format_graph_entity_text(&entity);
    }

    #[test]
    #[cfg(feature = "embeddings")]
    fn vector_lru_hit_and_miss() {
        let mut lru = VectorLruCache::with_capacity(4);
        assert_eq!(lru.get("absent"), None);
        lru.put("k", vec![0.5, 0.25]);
        assert_eq!(lru.get("k"), Some(vec![0.5, 0.25]));
        assert_eq!(lru.len(), 1);
    }

    #[test]
    #[cfg(feature = "embeddings")]
    fn vector_lru_evicts_least_recently_used() {
        let mut lru = VectorLruCache::with_capacity(2);
        lru.put("a", vec![1.0]);
        lru.put("b", vec![2.0]);
        // Touch "a" so "b" becomes the least-recently-used entry.
        assert_eq!(lru.get("a"), Some(vec![1.0]));
        // Inserting a third key over capacity must evict "b" only.
        lru.put("c", vec![3.0]);
        assert_eq!(lru.len(), 2);
        assert!(lru.contains_key("a"));
        assert!(lru.contains_key("c"));
        assert!(!lru.contains_key("b"));
        assert_eq!(lru.get("b"), None);
    }

    #[test]
    #[cfg(feature = "embeddings")]
    fn vector_lru_refresh_existing_does_not_evict() {
        let mut lru = VectorLruCache::with_capacity(2);
        lru.put("a", vec![1.0]);
        lru.put("b", vec![2.0]);
        // Updating an existing key is not a new insertion — nothing is evicted.
        lru.put("a", vec![9.0]);
        assert_eq!(lru.len(), 2);
        assert_eq!(lru.get("a"), Some(vec![9.0]));
        assert!(lru.contains_key("b"));
    }

    /// A vector served from the in-memory LRU must be byte-for-byte identical to
    /// what a direct on-disk read returns — the LRU only changes residency, not
    /// the answer, so embed determinism and cache provenance are preserved.
    #[test]
    #[cfg(feature = "embeddings")]
    fn lru_served_vector_equals_disk_read() {
        let tmp =
            std::env::temp_dir().join(format!("kin-db-embed-lru-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let dims = 4;

        let writer = EmbeddingCache::new_in(tmp.clone(), "lru-equality".to_string(), dims)
            .expect("cache root");
        let key = writer.key_for_text("function\nsrc/lib.rs\nload_registry");
        let vector = vec![0.5_f32, -0.25, 0.125, 0.0625];
        writer.put_by_key(&key, &vector);

        // Direct disk read of the persisted vector.
        let from_disk = read_cached_vector(&writer.path_for_key(&key), dims).expect("on-disk hit");

        // A fresh cache over the same root starts with an empty LRU, so the
        // first read is served from disk (and populates the LRU); the second is
        // served from the LRU. Both must equal the disk bytes.
        let reader = EmbeddingCache::new_in(tmp.clone(), "lru-equality".to_string(), dims)
            .expect("cache root");
        let served_from_disk = reader.get_by_key(&key).expect("disk-backed hit");
        let served_from_lru = reader.get_by_key(&key).expect("memory hit");

        assert_eq!(from_disk, vector);
        assert_eq!(served_from_disk, vector);
        assert_eq!(served_from_lru, vector);
        assert_eq!(served_from_lru, from_disk);

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
