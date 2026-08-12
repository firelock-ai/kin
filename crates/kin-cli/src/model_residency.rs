// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Resident inference models for a serving process.
//!
//! Inference models here are built by reading weights off disk and
//! materializing them in memory: a 12-layer cross-encoder costs on the order of
//! a second and hundreds of megabytes to construct, and nothing about that work
//! depends on the query. The cross-encoder's own serving gate
//! ([`crate::retrieval_profile::daemon_serving`]) exists to buy that
//! amortization, so the built model has to outlive the query that first needed
//! it or the gate buys nothing.
//!
//! [`ResidentModels`] holds built models keyed on model identity plus revision,
//! so a model id change rebuilds and a repeat query does not. It is bounded:
//! each resident model is large, so the cache keeps the most recently used
//! [`ResidentModels::capacity`] entries and drops the rest.
//!
//! Concurrency has two properties worth stating, because a serving daemon hits
//! both. Building one model never blocks a lookup of another: the map lock is
//! released before a build starts. And concurrent first-callers for the SAME
//! model build it once rather than once each, which matters when the duplicate
//! is a second copy of the whole model resident at the same time.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

/// A model's cache identity: its id and the revision it was resolved at.
type ModelKey = (String, String);

/// One cache line. The outer `Arc` keeps a slot alive for a caller that is
/// building into it even if the cache evicts the line meanwhile; the `Mutex`
/// serializes builders of that one model.
type Slot<T> = Arc<Mutex<Option<Arc<T>>>>;

/// Take a lock, recovering from poisoning.
///
/// A build that panics poisons the slot it was building into. Propagating that
/// would wedge the model for the rest of the process lifetime, turning one bad
/// weights file into a permanently degraded daemon; recovering instead leaves
/// the slot empty so the next caller retries and either succeeds or reports its
/// own error.
fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// A bounded, thread-safe cache of built inference models.
pub struct ResidentModels<T> {
    entries: Mutex<Vec<(ModelKey, Slot<T>)>>,
    capacity: usize,
    builds: AtomicU64,
}

impl<T> ResidentModels<T> {
    /// A cache holding at most `capacity` models, clamped to at least one.
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
            capacity: capacity.max(1),
            builds: AtomicU64::new(0),
        }
    }

    /// The resident model for `model_id` at `revision`, building it with
    /// `build` only if this cache does not already hold it.
    ///
    /// Returns whether THIS call built the model. A caller cannot infer that
    /// from the build counter, because a concurrent build of another model
    /// moves the counter under it, and a residency signal that reports builds
    /// which did not happen is worse than none.
    ///
    /// A failed build is not cached: the slot stays empty so a later call
    /// retries. This keeps a transient failure (a partial download, a busy
    /// device) from being remembered as a permanent one.
    pub fn get_or_build<E>(
        &self,
        model_id: &str,
        revision: &str,
        build: impl FnOnce() -> Result<T, E>,
    ) -> Result<(Arc<T>, bool), E> {
        let key = (model_id.to_string(), revision.to_string());
        let slot = self.slot_for(&key);
        let mut resident = lock(&slot);
        if let Some(model) = resident.as_ref() {
            return Ok((Arc::clone(model), false));
        }
        let model = Arc::new(build()?);
        self.builds.fetch_add(1, Ordering::Relaxed);
        *resident = Some(Arc::clone(&model));
        self.reinstate(key, &slot);
        Ok((model, true))
    }

    /// How many models this cache has actually built.
    ///
    /// Residency is a claim about construction count, not about wall clock, so
    /// this is the number that proves it: a serving process that reranks many
    /// queries against one model should report one build.
    pub fn builds(&self) -> u64 {
        self.builds.load(Ordering::Relaxed)
    }

    /// The slot for `key`, inserting an empty one if absent, promoting it to
    /// most-recently-used, and evicting past capacity.
    ///
    /// Returns with the map lock released, so the caller's build does not hold
    /// up lookups of other models.
    fn slot_for(&self, key: &ModelKey) -> Slot<T> {
        let mut entries = lock(&self.entries);
        if let Some(position) = entries.iter().position(|(entry_key, _)| entry_key == key) {
            let entry = entries.remove(position);
            let slot = Arc::clone(&entry.1);
            entries.insert(0, entry);
            return slot;
        }
        let slot: Slot<T> = Arc::new(Mutex::new(None));
        entries.insert(0, (key.clone(), Arc::clone(&slot)));
        entries.truncate(self.capacity);
        slot
    }

    /// Put a freshly built model's slot back in the map if eviction removed it
    /// while the build was running.
    ///
    /// The map lock is released across a build so one model's build does not
    /// block another's lookup, which leaves a window where enough other keys
    /// arrive to evict this one. Without this the built model is unreachable,
    /// the next request for that key rebuilds, and residency silently decays to
    /// the rebuild-per-query behavior this cache exists to remove.
    fn reinstate(&self, key: ModelKey, slot: &Slot<T>) {
        let mut entries = lock(&self.entries);
        if entries.iter().any(|(entry_key, _)| *entry_key == key) {
            return;
        }
        entries.insert(0, (key, Arc::clone(slot)));
        entries.truncate(self.capacity);
    }
}

/// How many cross-encoders stay resident at once.
///
/// The reranker model id is fixed per serving process in every configuration
/// that ships, so one entry covers the steady state and the second only absorbs
/// a model id change without a rebuild-per-query flap while both are in use.
/// Each resident cross-encoder is hundreds of megabytes, which is why this is a
/// small number rather than an unbounded map.
#[cfg(feature = "embeddings")]
const CROSS_ENCODER_CAPACITY: usize = 2;

#[cfg(feature = "embeddings")]
fn cross_encoders() -> &'static ResidentModels<kin_db::embed::rerank::CrossEncoder> {
    use std::sync::OnceLock;
    static CACHE: OnceLock<ResidentModels<kin_db::embed::rerank::CrossEncoder>> = OnceLock::new();
    CACHE.get_or_init(|| ResidentModels::new(CROSS_ENCODER_CAPACITY))
}

/// The resident cross-encoder for `model_id` at `revision`, building it on
/// first use in this process.
///
/// Scoring is unchanged: [`kin_db::embed::rerank::CrossEncoder::rerank`] reads
/// the model through a shared reference and derives its scores from the query
/// and documents alone, so a shared instance returns what a per-query instance
/// returned.
#[cfg(feature = "embeddings")]
pub fn cross_encoder(
    model_id: &str,
    revision: &str,
) -> Result<Arc<kin_db::embed::rerank::CrossEncoder>, kin_db::error::KinDbError> {
    let cache = cross_encoders();
    let (model, built) = cache.get_or_build(model_id, revision, || {
        kin_db::embed::rerank::CrossEncoder::new(model_id, revision)
    })?;
    if built {
        tracing::info!(
            model_id,
            revision,
            builds = cache.builds(),
            "built resident cross-encoder"
        );
    }
    Ok(model)
}

/// How many cross-encoders this process has built.
///
/// A serving daemon that has answered many reranked queries should report one
/// per model it was asked for, which is reranker residency stated as a number
/// rather than as a latency. No daemon endpoint or CLI command reports it yet,
/// so today the live signal is the build log line above and this is the hook a
/// surface can be hung on.
#[cfg(feature = "embeddings")]
pub fn cross_encoder_builds() -> u64 {
    cross_encoders().builds()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;
    use std::sync::Barrier;

    /// A stand-in for a real model: cheap to build, and it carries the build
    /// ordinal so a test can tell two instances apart. Counting builds is what
    /// proves residency, and it proves it without a weights file, a network
    /// fetch, or a device.
    #[derive(Debug)]
    struct StubModel {
        ordinal: usize,
    }

    struct StubBuilder {
        attempts: AtomicUsize,
    }

    impl StubBuilder {
        fn new() -> Self {
            Self {
                attempts: AtomicUsize::new(0),
            }
        }

        fn build(&self) -> Result<StubModel, String> {
            let ordinal = self.attempts.fetch_add(1, Ordering::SeqCst);
            Ok(StubModel { ordinal })
        }

        fn attempts(&self) -> usize {
            self.attempts.load(Ordering::SeqCst)
        }
    }

    #[test]
    fn a_repeat_request_reuses_the_resident_model_instead_of_rebuilding() {
        let cache = ResidentModels::new(2);
        let builder = StubBuilder::new();

        let (first, first_built) = cache
            .get_or_build("model", "main", || builder.build())
            .expect("first build");
        let (second, second_built) = cache
            .get_or_build("model", "main", || builder.build())
            .expect("second build");
        assert!(first_built, "the first request builds");
        assert!(!second_built, "the second request must report no build");

        assert_eq!(
            builder.attempts(),
            1,
            "the second request must not construct a second model"
        );
        assert_eq!(cache.builds(), 1);
        assert!(
            Arc::ptr_eq(&first, &second),
            "both callers must share one resident instance"
        );
    }

    #[test]
    fn a_different_model_or_revision_is_a_different_resident_entry() {
        let cache = ResidentModels::new(4);
        let builder = StubBuilder::new();

        let (base, _) = cache
            .get_or_build("model", "main", || builder.build())
            .expect("base build");
        let (other_revision, _) = cache
            .get_or_build("model", "v2", || builder.build())
            .expect("revision build");
        let (other_model, _) = cache
            .get_or_build("other", "main", || builder.build())
            .expect("model build");

        assert_eq!(cache.builds(), 3);
        assert_ne!(base.ordinal, other_revision.ordinal);
        assert_ne!(other_revision.ordinal, other_model.ordinal);

        let (base_again, _) = cache
            .get_or_build("model", "main", || builder.build())
            .expect("base reuse");
        assert_eq!(
            cache.builds(),
            3,
            "each key stays resident alongside the others"
        );
        assert!(Arc::ptr_eq(&base, &base_again));
    }

    #[test]
    fn the_cache_is_bounded_and_evicts_least_recently_used_first() {
        let cache = ResidentModels::new(2);
        let builder = StubBuilder::new();

        cache
            .get_or_build("a", "main", || builder.build())
            .expect("a");
        cache
            .get_or_build("b", "main", || builder.build())
            .expect("b");
        cache
            .get_or_build("a", "main", || builder.build())
            .expect("a again");
        cache
            .get_or_build("c", "main", || builder.build())
            .expect("c");

        assert_eq!(
            cache.builds(),
            3,
            "a was resident when it was touched again"
        );

        cache
            .get_or_build("a", "main", || builder.build())
            .expect("a stayed");
        assert_eq!(
            cache.builds(),
            3,
            "the most recently used entry must survive an insert at capacity"
        );

        cache
            .get_or_build("b", "main", || builder.build())
            .expect("b rebuilt");
        assert_eq!(
            cache.builds(),
            4,
            "the least recently used entry is the one evicted"
        );
    }

    #[test]
    fn concurrent_first_callers_for_one_model_build_it_once() {
        let cache = Arc::new(ResidentModels::new(2));
        let builder = Arc::new(StubBuilder::new());
        let racers = 8;
        let barrier = Arc::new(Barrier::new(racers));

        let handles: Vec<_> = (0..racers)
            .map(|_| {
                let cache = Arc::clone(&cache);
                let builder = Arc::clone(&builder);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    cache
                        .get_or_build("model", "main", || builder.build())
                        .expect("raced build")
                        .0
                })
            })
            .collect();

        let models: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().expect("racer joined"))
            .collect();

        assert_eq!(
            builder.attempts(),
            1,
            "a duplicate build would hold a second whole model in memory"
        );
        assert_eq!(cache.builds(), 1);
        for model in &models {
            assert!(
                Arc::ptr_eq(model, &models[0]),
                "every racer must observe the same resident instance"
            );
        }
    }

    /// A model built while other keys evicted its slot is still resident
    /// afterwards.
    ///
    /// The map lock is released across a build, so a build long enough to be
    /// worth caching is exactly the one during which other keys can evict it.
    /// If the finished model is left unreachable, the next request for that key
    /// rebuilds and residency decays back to rebuild-per-query, which is the
    /// failure this cache exists to remove. It also puts two whole models in
    /// memory at once, which the design claims it prevents.
    #[test]
    fn a_model_evicted_while_it_was_building_is_still_resident_when_it_finishes() {
        use std::sync::mpsc;

        let cache = Arc::new(ResidentModels::new(1));
        let builder = Arc::new(StubBuilder::new());
        let (building, is_building) = mpsc::channel();
        let (finish, may_finish) = mpsc::channel();

        let slow = {
            let cache = Arc::clone(&cache);
            let builder = Arc::clone(&builder);
            std::thread::spawn(move || {
                cache
                    .get_or_build("a", "main", || {
                        building.send(()).expect("report that the build started");
                        may_finish.recv().expect("wait for release");
                        builder.build()
                    })
                    .expect("slow build")
                    .0
            })
        };

        is_building.recv().expect("the slow build started");
        cache
            .get_or_build("b", "main", || builder.build())
            .expect("second key evicts the first at capacity 1");
        finish.send(()).expect("release the slow build");
        let built = slow.join().expect("slow builder joined");

        assert_eq!(cache.builds(), 2, "one build per key so far");

        let (again, rebuilt) = cache
            .get_or_build("a", "main", || builder.build())
            .expect("request the evicted-while-building key again");
        assert!(
            !rebuilt,
            "a model that finished building must be reachable, not rebuilt"
        );
        assert_eq!(cache.builds(), 2);
        assert!(
            Arc::ptr_eq(&built, &again),
            "the resident instance must be the one that was built, not a second copy"
        );
    }

    #[test]
    fn a_build_that_fails_is_retried_rather_than_remembered() {
        let cache = ResidentModels::new(2);
        let builder = StubBuilder::new();

        let failed: Result<(Arc<StubModel>, bool), String> =
            cache.get_or_build("model", "main", || Err("weights unreadable".to_string()));
        assert_eq!(failed.unwrap_err(), "weights unreadable");
        assert_eq!(cache.builds(), 0);

        let (recovered, _) = cache
            .get_or_build("model", "main", || builder.build())
            .expect("retry after a failed build");
        assert_eq!(recovered.ordinal, 0);
        assert_eq!(cache.builds(), 1);
    }

    #[test]
    fn a_cache_holds_at_least_one_model_even_if_asked_for_none() {
        let cache = ResidentModels::new(0);
        let builder = StubBuilder::new();

        cache
            .get_or_build("model", "main", || builder.build())
            .expect("first");
        cache
            .get_or_build("model", "main", || builder.build())
            .expect("second");

        assert_eq!(cache.builds(), 1);
    }

    /// The resident cache shares one model across serving threads, so the model
    /// type has to be shareable. Asserting it here names the requirement the
    /// concrete cache depends on instead of leaving it to a distant compile
    /// error if the model type ever gains a non-shareable field.
    #[cfg(feature = "embeddings")]
    #[test]
    fn the_cross_encoder_is_shareable_across_threads() {
        fn assert_shareable<T: Send + Sync>() {}
        assert_shareable::<kin_db::embed::rerank::CrossEncoder>();
        assert_shareable::<ResidentModels<kin_db::embed::rerank::CrossEncoder>>();
    }

    /// A process that never reranks has never built a cross-encoder, which is
    /// the same counter a serving daemon is asked for and the reason it stays
    /// zero rather than being absent.
    #[cfg(feature = "embeddings")]
    #[test]
    fn a_process_that_never_reranks_reports_no_cross_encoder_builds() {
        assert_eq!(super::cross_encoder_builds(), 0);
    }
}
