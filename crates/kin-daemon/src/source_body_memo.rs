// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Process-local memo for immutable source bodies read out of hosted storage.
//!
//! A hosted daemon reads the same source bodies over and over. Nothing above
//! this layer memoizes them: `kin-mcp`'s hosted projection budget keeps a blob
//! map for the length of one request and drops it, and every other reader goes
//! straight to the backend. On GCS each of those reads costs a HEAD to learn
//! the object's size and then a bounded GET of exactly that many bytes, so one
//! body is two billed Class B operations and its bytes on the wire, every
//! time.
//!
//! Measured on `kin-ecosystem-kin-graphs-dev` over the 24 hours ending
//! 2026-09-03T20:00Z: 6,638,311 `ReadObject` and 6,624,127 `GetObjectMetadata`
//! against a bucket holding 6,834 objects, with 423 GB served. Six thousand
//! objects cannot absorb six million reads without repeating: at that ratio
//! all but a rounding error of the traffic is a re-read of a body the process
//! already had. There were no object writes at all in the same window.
//!
//! ## Why a memo is exact here and not merely cheaper
//!
//! The key is the content address. `StorageBackend` requires every
//! implementation to verify returned bytes against the digest and fail closed
//! on corruption, so a body that came back under `(repo_id, digest)` is the
//! only body that can ever come back under it. There is no invalidation to
//! keep in step and no window where a hit and a miss would answer differently.
//!
//! Three things keep that true, and each is a rule this module holds rather
//! than a property it inherits:
//!
//! * The key carries the repository. Bodies are content addressed but
//!   *admission* is per repository: `load_source_blob` answers `None` when
//!   these exact bytes were never persisted under this repository, and that
//!   answer is an authority gap a caller is required to see. Keying on the
//!   digest alone would let one repository serve bodies published under
//!   another.
//! * Absence is never memoized. `None` is the one answer that can change,
//!   because a body can be published later.
//! * A bounded read re-applies its own ceiling on a hit. `max_bytes` is the
//!   caller's response budget rather than a fact about storage, so a hit must
//!   refuse exactly what the backend would have refused.
//!
//! Nothing deletes a source body. The trait has no removal method, no backend
//! implements one, and a repository purge rewrites tree entries rather than
//! erasing bodies. So a memoized body cannot outlive its authority.

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use kin_db::storage::PreparedWorkspaceGraphArtifact;
use kin_db::{
    Generation, KinDbError, SnapshotAuthority, SnapshotCursor, SnapshotRecoveryState,
    SnapshotSaveOutcome, StorageBackend, VectorArtifact, VectorArtifactBinding,
    VectorArtifactCursor, VectorArtifactLoadOutcome, VectorArtifactSaveOutcome,
};

/// How many bytes of source bodies one process will hold.
///
/// Sized from the measurement rather than from taste. The dev fleet's whole
/// object namespace is 6,834 objects and the 24-hour reading above averages
/// about 64 KB per read, so the entire working set is roughly 440 MB. A budget
/// under the working set is worse than no budget on a pass that walks a tree
/// end to end, because least-recently-used eviction then evicts exactly the
/// entry the next walk asks for. This is a ceiling and not an allocation: a
/// small store holds a small memo.
pub const DEFAULT_RESIDENT_BYTES: u64 = 512 * 1024 * 1024;

/// The largest single body worth memoizing.
///
/// One large file must not be able to evict the whole working set behind it.
/// The bound matches the ceiling `kin-mcp` already puts on hosted semantic
/// source reads, so the bodies these surfaces can actually return are exactly
/// the bodies this admits.
pub const DEFAULT_ENTRY_BYTES: u64 = 8 * 1024 * 1024;

type MemoKey = (String, [u8; 32]);

struct MemoEntry {
    body: std::sync::Arc<Vec<u8>>,
    tick: u64,
}

/// The memo itself: bodies by key, plus a use order to evict by.
///
/// `order` maps a monotonic use tick to its key, so the least recently used
/// entry is the first key in the map. A read moves an entry to a fresh tick.
#[derive(Default)]
struct Memo {
    entries: HashMap<MemoKey, MemoEntry>,
    order: BTreeMap<u64, MemoKey>,
    next_tick: u64,
    resident_bytes: u64,
}

impl Memo {
    fn take_tick(&mut self) -> u64 {
        let tick = self.next_tick;
        self.next_tick = self.next_tick.saturating_add(1);
        tick
    }

    fn get(&mut self, key: &MemoKey) -> Option<std::sync::Arc<Vec<u8>>> {
        let old_tick = self.entries.get(key)?.tick;
        let tick = self.take_tick();
        self.order.remove(&old_tick);
        self.order.insert(tick, key.clone());
        let entry = self.entries.get_mut(key)?;
        entry.tick = tick;
        Some(std::sync::Arc::clone(&entry.body))
    }

    fn admit(&mut self, key: MemoKey, body: &[u8], budget: u64) {
        let len = body.len() as u64;
        if let Some(existing) = self.entries.remove(&key) {
            self.order.remove(&existing.tick);
            self.resident_bytes = self
                .resident_bytes
                .saturating_sub(existing.body.len() as u64);
        }
        let tick = self.take_tick();
        self.order.insert(tick, key.clone());
        self.entries.insert(
            key,
            MemoEntry {
                body: std::sync::Arc::new(body.to_vec()),
                tick,
            },
        );
        self.resident_bytes = self.resident_bytes.saturating_add(len);
        while self.resident_bytes > budget {
            let Some((&oldest, _)) = self.order.iter().next() else {
                break;
            };
            let Some(evicted_key) = self.order.remove(&oldest) else {
                break;
            };
            if let Some(evicted) = self.entries.remove(&evicted_key) {
                self.resident_bytes = self
                    .resident_bytes
                    .saturating_sub(evicted.body.len() as u64);
            }
        }
    }
}

/// A [`StorageBackend`] that answers a repeated immutable-body read from
/// memory instead of from the wire.
///
/// Install it directly above the object-store backend so every reader beneath
/// the daemon shares one memo, including the ones that reach storage through
/// `kin-mcp` and `kin-core` rather than through this crate.
pub struct SourceBodyMemoBackend {
    inner: Box<dyn StorageBackend>,
    memo: Mutex<Memo>,
    resident_budget_bytes: u64,
    max_entry_bytes: u64,
    hits: AtomicU64,
    misses: AtomicU64,
    refused_admissions: AtomicU64,
}

impl std::fmt::Debug for SourceBodyMemoBackend {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SourceBodyMemoBackend")
            .field("resident_budget_bytes", &self.resident_budget_bytes)
            .field("max_entry_bytes", &self.max_entry_bytes)
            .field("hits", &self.hits.load(Ordering::Relaxed))
            .field("misses", &self.misses.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

impl SourceBodyMemoBackend {
    pub fn new(inner: Box<dyn StorageBackend>) -> Self {
        Self::with_budget(inner, DEFAULT_RESIDENT_BYTES, DEFAULT_ENTRY_BYTES)
    }

    pub fn with_budget(
        inner: Box<dyn StorageBackend>,
        resident_budget_bytes: u64,
        max_entry_bytes: u64,
    ) -> Self {
        Self {
            inner,
            memo: Mutex::new(Memo::default()),
            resident_budget_bytes,
            max_entry_bytes,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            refused_admissions: AtomicU64::new(0),
        }
    }

    /// Reads answered from memory.
    pub fn hits(&self) -> u64 {
        self.hits.load(Ordering::Relaxed)
    }

    /// Reads that reached the backend.
    pub fn misses(&self) -> u64 {
        self.misses.load(Ordering::Relaxed)
    }

    /// Bodies the backend returned that were too large to memoize.
    pub fn refused_admissions(&self) -> u64 {
        self.refused_admissions.load(Ordering::Relaxed)
    }

    /// Bytes of source bodies this process is holding.
    pub fn resident_bytes(&self) -> u64 {
        self.locked().resident_bytes
    }

    fn locked(&self) -> std::sync::MutexGuard<'_, Memo> {
        self.memo
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn memoized(&self, repo_id: &str, digest: [u8; 32]) -> Option<std::sync::Arc<Vec<u8>>> {
        let body = self.locked().get(&(repo_id.to_string(), digest));
        if body.is_some() {
            self.hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.misses.fetch_add(1, Ordering::Relaxed);
        }
        body
    }

    fn admit(&self, repo_id: &str, digest: [u8; 32], body: &[u8]) {
        if body.len() as u64 > self.max_entry_bytes {
            self.refused_admissions.fetch_add(1, Ordering::Relaxed);
            return;
        }
        self.locked().admit(
            (repo_id.to_string(), digest),
            body,
            self.resident_budget_bytes,
        );
    }

    /// Refuse a memoized body the caller's own ceiling would not have admitted.
    ///
    /// The wording follows the backend's: a caller that sizes a response budget
    /// off this refusal has to read the same sentence whether or not the body
    /// happened to be in memory.
    fn within_ceiling(
        body: &[u8],
        max_bytes: u64,
        repo_id: &str,
        digest: [u8; 32],
    ) -> Result<(), KinDbError> {
        if body.len() as u64 > max_bytes {
            return Err(KinDbError::StorageError(format!(
                "source blob {} in repo {repo_id} is {} bytes, above the {max_bytes}-byte read boundary",
                hex_digest(digest),
                body.len()
            )));
        }
        Ok(())
    }
}

fn hex_digest(digest: [u8; 32]) -> String {
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

impl StorageBackend for SourceBodyMemoBackend {
    // --- the memoized surface -------------------------------------------------

    fn load_source_blob(
        &self,
        repo_id: &str,
        digest: [u8; 32],
    ) -> Result<Option<Vec<u8>>, KinDbError> {
        if let Some(body) = self.memoized(repo_id, digest) {
            return Ok(Some(body.as_ref().clone()));
        }
        let loaded = self.inner.load_source_blob(repo_id, digest)?;
        if let Some(body) = loaded.as_deref() {
            self.admit(repo_id, digest, body);
        }
        Ok(loaded)
    }

    fn load_source_blob_bounded(
        &self,
        repo_id: &str,
        digest: [u8; 32],
        max_bytes: u64,
    ) -> Result<Option<Vec<u8>>, KinDbError> {
        if let Some(body) = self.memoized(repo_id, digest) {
            Self::within_ceiling(&body, max_bytes, repo_id, digest)?;
            return Ok(Some(body.as_ref().clone()));
        }
        let loaded = self
            .inner
            .load_source_blob_bounded(repo_id, digest, max_bytes)?;
        if let Some(body) = loaded.as_deref() {
            self.admit(repo_id, digest, body);
        }
        Ok(loaded)
    }

    /// A length the memo already holds costs nothing. A length it does not is
    /// left to the backend's metadata-only read rather than turned into a body
    /// download, because that is the whole point of the method.
    fn source_blob_len(&self, repo_id: &str, digest: [u8; 32]) -> Result<Option<u64>, KinDbError> {
        if let Some(body) = self.memoized(repo_id, digest) {
            return u64::try_from(body.len()).map(Some).map_err(|_| {
                KinDbError::StorageError(
                    "immutable source blob length does not fit u64".to_string(),
                )
            });
        }
        self.inner.source_blob_len(repo_id, digest)
    }

    /// A write publishes the exact bytes under the exact identity, so the memo
    /// takes them rather than dropping what it was just handed.
    fn save_source_blob(
        &self,
        repo_id: &str,
        digest: [u8; 32],
        data: &[u8],
    ) -> Result<(), KinDbError> {
        self.inner.save_source_blob(repo_id, digest, data)?;
        self.admit(repo_id, digest, data);
        Ok(())
    }

    // --- everything else is forwarded ----------------------------------------
    //
    // Forwarded exhaustively, and that is a rule rather than a courtesy. Every
    // method on this trait that a decorator omits falls through to a default
    // written for a backend that cannot do better, and several of those
    // defaults are expensive or fail closed. The publication gate omitted
    // `load_snapshot_cursor` and silently turned a metadata-only probe into a
    // full authority download for every hosted request. A new method arriving
    // on the trait lands here as a default too, so keep this list complete.
    //
    // The two batch seams are the deliberate exception. Their defaults build a
    // batch over `self`, which routes every read in the batch through the memo
    // above; forwarding them to the inner backend would hand the batch a
    // reference that skips it. An object store has no repository lock for a
    // batch to amortize, so nothing is lost by taking the default.

    fn supports_incremental_deltas(&self) -> bool {
        self.inner.supports_incremental_deltas()
    }

    fn load_snapshot(&self, repo_id: &str) -> Result<Option<(Vec<u8>, Generation)>, KinDbError> {
        self.inner.load_snapshot(repo_id)
    }

    fn load_snapshot_authority(
        &self,
        repo_id: &str,
    ) -> Result<Option<SnapshotAuthority>, KinDbError> {
        self.inner.load_snapshot_authority(repo_id)
    }

    fn load_snapshot_cursor(&self, repo_id: &str) -> Result<Option<SnapshotCursor>, KinDbError> {
        self.inner.load_snapshot_cursor(repo_id)
    }

    fn load_recovery_state(&self, repo_id: &str) -> Result<SnapshotRecoveryState, KinDbError> {
        self.inner.load_recovery_state(repo_id)
    }

    fn save_snapshot(
        &self,
        repo_id: &str,
        data: &[u8],
        expected_gen: Generation,
    ) -> Result<Generation, KinDbError> {
        self.inner.save_snapshot(repo_id, data, expected_gen)
    }

    fn save_snapshot_classified(
        &self,
        repo_id: &str,
        data: &[u8],
        expected_cursor: SnapshotCursor,
    ) -> SnapshotSaveOutcome {
        self.inner
            .save_snapshot_classified(repo_id, data, expected_cursor)
    }

    fn save_snapshot_validated(
        &self,
        repo_id: &str,
        data: &[u8],
        expected: SnapshotCursor,
        history_validator_version: Option<u32>,
    ) -> SnapshotSaveOutcome {
        self.inner
            .save_snapshot_validated(repo_id, data, expected, history_validator_version)
    }

    fn save_snapshot_streamed(
        &self,
        repo_id: &str,
        produce: &mut dyn FnMut(&mut dyn std::io::Write) -> Result<(u64, [u8; 32]), KinDbError>,
        expected: SnapshotCursor,
        history_validator_version: Option<u32>,
    ) -> SnapshotSaveOutcome {
        self.inner
            .save_snapshot_streamed(repo_id, produce, expected, history_validator_version)
    }

    fn record_history_validation(
        &self,
        repo_id: &str,
        generation: Generation,
        snapshot_sha256: &str,
        validator_version: u32,
    ) -> Result<bool, KinDbError> {
        self.inner.record_history_validation(
            repo_id,
            generation,
            snapshot_sha256,
            validator_version,
        )
    }

    fn supports_authority_frames(&self) -> bool {
        self.inner.supports_authority_frames()
    }

    fn save_authority_frame(
        &self,
        repo_id: &str,
        frame: &[u8],
        expected: SnapshotCursor,
        history_validator_version: Option<u32>,
    ) -> SnapshotSaveOutcome {
        self.inner
            .save_authority_frame(repo_id, frame, expected, history_validator_version)
    }

    fn record_journal_history_validation(
        &self,
        repo_id: &str,
        head_generation: Generation,
        snapshot_sha256: &str,
        journal_sha256: &str,
        validator_version: u32,
    ) -> Result<bool, KinDbError> {
        self.inner.record_journal_history_validation(
            repo_id,
            head_generation,
            snapshot_sha256,
            journal_sha256,
            validator_version,
        )
    }

    fn load_prepared_workspace_graph_binding(
        &self,
        repo_id: &str,
        workspace_id: &str,
    ) -> Result<Option<Vec<u8>>, KinDbError> {
        self.inner
            .load_prepared_workspace_graph_binding(repo_id, workspace_id)
    }

    fn load_prepared_workspace_graph(
        &self,
        repo_id: &str,
        workspace_id: &str,
    ) -> Result<Option<PreparedWorkspaceGraphArtifact>, KinDbError> {
        self.inner
            .load_prepared_workspace_graph(repo_id, workspace_id)
    }

    fn record_prepared_workspace_graph(
        &self,
        repo_id: &str,
        workspace_id: &str,
        artifact: &PreparedWorkspaceGraphArtifact,
    ) -> Result<bool, KinDbError> {
        self.inner
            .record_prepared_workspace_graph(repo_id, workspace_id, artifact)
    }

    fn supports_vector_artifacts(&self) -> bool {
        self.inner.supports_vector_artifacts()
    }

    fn load_vector_artifact(
        &self,
        repo_id: &str,
        binding: VectorArtifactBinding,
    ) -> Result<VectorArtifactLoadOutcome, KinDbError> {
        self.inner.load_vector_artifact(repo_id, binding)
    }

    fn save_vector_artifact(
        &self,
        repo_id: &str,
        artifact: &VectorArtifact,
        expected: VectorArtifactCursor,
    ) -> VectorArtifactSaveOutcome {
        self.inner.save_vector_artifact(repo_id, artifact, expected)
    }

    fn save_delta(
        &self,
        repo_id: &str,
        delta_data: &[u8],
        base_gen: Generation,
    ) -> Result<Generation, KinDbError> {
        self.inner.save_delta(repo_id, delta_data, base_gen)
    }

    fn load_deltas_since(
        &self,
        repo_id: &str,
        since_gen: Generation,
    ) -> Result<Vec<(Vec<u8>, Generation)>, KinDbError> {
        self.inner.load_deltas_since(repo_id, since_gen)
    }

    fn compact_deltas(&self, repo_id: &str) -> Result<Generation, KinDbError> {
        self.inner.compact_deltas(repo_id)
    }

    fn clear_deltas(&self, repo_id: &str) -> Result<(), KinDbError> {
        self.inner.clear_deltas(repo_id)
    }

    fn save_overlay(&self, repo_id: &str, session_id: &str, data: &[u8]) -> Result<(), KinDbError> {
        self.inner.save_overlay(repo_id, session_id, data)
    }

    fn load_overlay(&self, repo_id: &str, session_id: &str) -> Result<Option<Vec<u8>>, KinDbError> {
        self.inner.load_overlay(repo_id, session_id)
    }

    fn delete_overlay(&self, repo_id: &str, session_id: &str) -> Result<(), KinDbError> {
        self.inner.delete_overlay(repo_id, session_id)
    }

    fn list_repos(&self) -> Result<Vec<String>, KinDbError> {
        self.inner.list_repos()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex;

    use super::*;

    /// A backend that answers from a map and counts what it was asked for, so
    /// a test can assert on requests rather than on results.
    ///
    /// Cloneable and shared, because the decorator takes ownership of the
    /// backend it wraps and the test still has to read the counters.
    #[derive(Clone, Default)]
    struct CountingBackend {
        bodies: std::sync::Arc<Mutex<HashMap<(String, [u8; 32]), Vec<u8>>>>,
        body_reads: std::sync::Arc<AtomicU64>,
        length_reads: std::sync::Arc<AtomicU64>,
        cursor_reads: std::sync::Arc<AtomicU64>,
        snapshot_reads: std::sync::Arc<AtomicU64>,
        recovery_reads: std::sync::Arc<AtomicU64>,
        prepared_bindings: std::sync::Arc<Mutex<HashMap<(String, String), Vec<u8>>>>,
        prepared_binding_reads: std::sync::Arc<AtomicU64>,
    }

    impl CountingBackend {
        fn publish(&self, repo_id: &str, digest: [u8; 32], body: &[u8]) {
            self.bodies
                .lock()
                .unwrap()
                .insert((repo_id.to_string(), digest), body.to_vec());
        }
    }

    impl StorageBackend for CountingBackend {
        fn load_prepared_workspace_graph_binding(
            &self,
            repo_id: &str,
            workspace_id: &str,
        ) -> Result<Option<Vec<u8>>, KinDbError> {
            self.prepared_binding_reads.fetch_add(1, Ordering::SeqCst);
            Ok(self
                .prepared_bindings
                .lock()
                .unwrap()
                .get(&(repo_id.to_string(), workspace_id.to_string()))
                .cloned())
        }

        fn load_snapshot(
            &self,
            _repo_id: &str,
        ) -> Result<Option<(Vec<u8>, Generation)>, KinDbError> {
            self.snapshot_reads.fetch_add(1, Ordering::SeqCst);
            Ok(None)
        }

        fn load_recovery_state(&self, _repo_id: &str) -> Result<SnapshotRecoveryState, KinDbError> {
            self.recovery_reads.fetch_add(1, Ordering::SeqCst);
            Ok((None, Vec::new()))
        }

        fn load_snapshot_cursor(
            &self,
            _repo_id: &str,
        ) -> Result<Option<SnapshotCursor>, KinDbError> {
            self.cursor_reads.fetch_add(1, Ordering::SeqCst);
            Ok(Some(SnapshotCursor::from_backend_generation(7)))
        }

        fn save_source_blob(
            &self,
            repo_id: &str,
            digest: [u8; 32],
            data: &[u8],
        ) -> Result<(), KinDbError> {
            self.publish(repo_id, digest, data);
            Ok(())
        }

        fn load_source_blob(
            &self,
            repo_id: &str,
            digest: [u8; 32],
        ) -> Result<Option<Vec<u8>>, KinDbError> {
            self.load_source_blob_bounded(repo_id, digest, u64::MAX)
        }

        fn load_source_blob_bounded(
            &self,
            repo_id: &str,
            digest: [u8; 32],
            max_bytes: u64,
        ) -> Result<Option<Vec<u8>>, KinDbError> {
            self.body_reads.fetch_add(1, Ordering::SeqCst);
            let bodies = self.bodies.lock().unwrap();
            let Some(body) = bodies.get(&(repo_id.to_string(), digest)) else {
                return Ok(None);
            };
            if body.len() as u64 > max_bytes {
                return Err(KinDbError::StorageError(format!(
                    "source blob is {} bytes, above the {max_bytes}-byte read boundary",
                    body.len()
                )));
            }
            Ok(Some(body.clone()))
        }

        fn source_blob_len(
            &self,
            repo_id: &str,
            digest: [u8; 32],
        ) -> Result<Option<u64>, KinDbError> {
            self.length_reads.fetch_add(1, Ordering::SeqCst);
            Ok(self
                .bodies
                .lock()
                .unwrap()
                .get(&(repo_id.to_string(), digest))
                .map(|body| body.len() as u64))
        }

        fn save_snapshot(
            &self,
            _repo_id: &str,
            _data: &[u8],
            _expected_gen: Generation,
        ) -> Result<Generation, KinDbError> {
            Ok(1)
        }

        fn save_delta(
            &self,
            _repo_id: &str,
            _delta_data: &[u8],
            _base_gen: Generation,
        ) -> Result<Generation, KinDbError> {
            Ok(1)
        }

        fn load_deltas_since(
            &self,
            _repo_id: &str,
            _since_gen: Generation,
        ) -> Result<Vec<(Vec<u8>, Generation)>, KinDbError> {
            Ok(Vec::new())
        }

        fn clear_deltas(&self, _repo_id: &str) -> Result<(), KinDbError> {
            Ok(())
        }

        fn save_overlay(
            &self,
            _repo_id: &str,
            _session_id: &str,
            _data: &[u8],
        ) -> Result<(), KinDbError> {
            Ok(())
        }

        fn load_overlay(
            &self,
            _repo_id: &str,
            _session_id: &str,
        ) -> Result<Option<Vec<u8>>, KinDbError> {
            Ok(None)
        }

        fn delete_overlay(&self, _repo_id: &str, _session_id: &str) -> Result<(), KinDbError> {
            Ok(())
        }

        fn list_repos(&self) -> Result<Vec<String>, KinDbError> {
            Ok(Vec::new())
        }
    }

    fn digest(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    fn fixture() -> (CountingBackend, SourceBodyMemoBackend) {
        let backend = CountingBackend::default();
        let memo = SourceBodyMemoBackend::new(Box::new(backend.clone()));
        (backend, memo)
    }

    /// The whole point, stated as a request count. A thousand reads of one
    /// immutable body reach storage once, which on GCS is one HEAD and one GET
    /// instead of a thousand of each.
    #[test]
    fn a_repeated_body_read_reaches_the_backend_once() {
        let (backend, memo) = fixture();
        backend.publish("kin", digest(1), b"fn main() {}");

        for _ in 0..1_000 {
            let body = memo
                .load_source_blob_bounded("kin", digest(1), 8 * 1024)
                .unwrap()
                .expect("published body");
            assert_eq!(body, b"fn main() {}");
        }

        assert_eq!(backend.body_reads.load(Ordering::SeqCst), 1);
        assert_eq!(memo.hits(), 999);
        assert_eq!(memo.misses(), 1);
    }

    /// The memo keys on the repository as well as the digest, so identical
    /// bytes published under one repository are not served as another
    /// repository's authority. A body absent from the second repository stays
    /// absent.
    #[test]
    fn one_repositorys_body_is_never_served_as_anothers() {
        let (backend, memo) = fixture();
        backend.publish("kin", digest(2), b"shared bytes");

        assert_eq!(
            memo.load_source_blob("kin", digest(2)).unwrap().as_deref(),
            Some(&b"shared bytes"[..])
        );
        assert_eq!(memo.load_source_blob("kinlab", digest(2)).unwrap(), None);

        backend.publish("kinlab", digest(2), b"shared bytes");
        assert_eq!(
            memo.load_source_blob("kinlab", digest(2))
                .unwrap()
                .as_deref(),
            Some(&b"shared bytes"[..])
        );
        assert_eq!(backend.body_reads.load(Ordering::SeqCst), 3);
    }

    /// Absence is the one answer that can change, so it is never memoized. A
    /// body published after a miss is visible on the next read.
    #[test]
    fn absence_is_never_memoized() {
        let (backend, memo) = fixture();

        assert_eq!(memo.load_source_blob("kin", digest(3)).unwrap(), None);
        assert_eq!(memo.load_source_blob("kin", digest(3)).unwrap(), None);
        backend.publish("kin", digest(3), b"published later");
        assert_eq!(
            memo.load_source_blob("kin", digest(3)).unwrap().as_deref(),
            Some(&b"published later"[..])
        );

        assert_eq!(backend.body_reads.load(Ordering::SeqCst), 3);
    }

    /// `max_bytes` is the caller's response budget, not a fact about storage,
    /// so a hit refuses exactly what a miss would have refused.
    #[test]
    fn a_memoized_body_still_refuses_the_callers_ceiling() {
        let (backend, memo) = fixture();
        backend.publish("kin", digest(4), b"0123456789");

        assert!(memo
            .load_source_blob_bounded("kin", digest(4), 64)
            .unwrap()
            .is_some());
        let refused = memo
            .load_source_blob_bounded("kin", digest(4), 4)
            .expect_err("a ceiling below the body must refuse");
        assert!(
            refused
                .to_string()
                .contains("above the 4-byte read boundary"),
            "{refused}"
        );
        assert_eq!(backend.body_reads.load(Ordering::SeqCst), 1);
    }

    /// A publication writes the exact bytes under the exact identity, so the
    /// read that follows it costs nothing.
    #[test]
    fn a_write_populates_the_memo() {
        let (backend, memo) = fixture();

        memo.save_source_blob("kin", digest(5), b"just written")
            .unwrap();
        assert_eq!(
            memo.load_source_blob("kin", digest(5)).unwrap().as_deref(),
            Some(&b"just written"[..])
        );
        assert_eq!(backend.body_reads.load(Ordering::SeqCst), 0);
    }

    /// A length the memo holds is free. A length it does not hold is left to
    /// the backend's metadata read and never promoted into a body download.
    #[test]
    fn a_length_read_never_becomes_a_body_download() {
        let (backend, memo) = fixture();
        backend.publish("kin", digest(6), b"0123456789");

        assert_eq!(memo.source_blob_len("kin", digest(6)).unwrap(), Some(10));
        assert_eq!(backend.body_reads.load(Ordering::SeqCst), 0);
        assert_eq!(backend.length_reads.load(Ordering::SeqCst), 1);

        memo.load_source_blob("kin", digest(6)).unwrap();
        assert_eq!(memo.source_blob_len("kin", digest(6)).unwrap(), Some(10));
        assert_eq!(backend.length_reads.load(Ordering::SeqCst), 1);
    }

    /// One large file must not be able to evict the working set behind it, so
    /// a body over the entry ceiling is served and then dropped.
    #[test]
    fn a_body_above_the_entry_ceiling_is_never_admitted() {
        let backend = CountingBackend::default();
        let memo = SourceBodyMemoBackend::with_budget(Box::new(backend.clone()), 1024, 16);
        backend.publish("kin", digest(7), &[b'x'; 64]);

        for _ in 0..3 {
            assert_eq!(
                memo.load_source_blob("kin", digest(7))
                    .unwrap()
                    .unwrap()
                    .len(),
                64
            );
        }
        assert_eq!(backend.body_reads.load(Ordering::SeqCst), 3);
        assert_eq!(memo.refused_admissions(), 3);
        assert_eq!(memo.resident_bytes(), 0);
    }

    /// The memo stays inside its byte budget, evicting least recently used
    /// first, and an evicted body is re-read rather than forgotten.
    #[test]
    fn the_memo_stays_inside_its_byte_budget() {
        let backend = CountingBackend::default();
        let memo = SourceBodyMemoBackend::with_budget(Box::new(backend.clone()), 32, 32);
        for seed in 0..4_u8 {
            backend.publish("kin", digest(seed), &[seed; 16]);
            memo.load_source_blob("kin", digest(seed)).unwrap().unwrap();
            assert!(
                memo.resident_bytes() <= 32,
                "resident {} over budget",
                memo.resident_bytes()
            );
        }

        // Two bodies of sixteen bytes fit; the first two were evicted.
        assert_eq!(memo.resident_bytes(), 32);
        assert_eq!(backend.body_reads.load(Ordering::SeqCst), 4);
        memo.load_source_blob("kin", digest(0)).unwrap().unwrap();
        assert_eq!(backend.body_reads.load(Ordering::SeqCst), 5);
        memo.load_source_blob("kin", digest(3)).unwrap().unwrap();
        assert_eq!(backend.body_reads.load(Ordering::SeqCst), 5);
    }

    #[test]
    fn prepared_binding_reads_cross_both_decorators_without_becoming_body_cache_entries() {
        use crate::storage_delegate::{DelegatingBackend, StorageBackendDelegate};

        struct PassThrough(SourceBodyMemoBackend);
        impl StorageBackendDelegate for PassThrough {
            fn delegate(&self) -> &dyn StorageBackend {
                &self.0
            }
        }

        let (backend, memo) = fixture();
        let key = ("repo-a".to_string(), "workspace-a".to_string());
        backend
            .prepared_bindings
            .lock()
            .unwrap()
            .insert(key.clone(), b"first-binding".to_vec());
        assert_eq!(
            memo.load_prepared_workspace_graph_binding("repo-a", "workspace-a")
                .unwrap(),
            Some(b"first-binding".to_vec())
        );

        let decorated = DelegatingBackend::new(PassThrough(memo));
        assert_eq!(
            decorated
                .load_prepared_workspace_graph_binding("repo-a", "workspace-a")
                .unwrap(),
            Some(b"first-binding".to_vec())
        );
        backend
            .prepared_bindings
            .lock()
            .unwrap()
            .insert(key, b"replacement-binding".to_vec());
        assert_eq!(
            decorated
                .load_prepared_workspace_graph_binding("repo-a", "workspace-a")
                .unwrap(),
            Some(b"replacement-binding".to_vec())
        );
        for (repo, workspace) in [("repo-b", "workspace-a"), ("repo-a", "workspace-b")] {
            assert_eq!(
                decorated
                    .load_prepared_workspace_graph_binding(repo, workspace)
                    .unwrap(),
                None
            );
        }
        assert_eq!(decorated.decorator().0.resident_bytes(), 0);
        assert_eq!(backend.prepared_binding_reads.load(Ordering::SeqCst), 5);
        assert_eq!(backend.body_reads.load(Ordering::SeqCst), 0);
        assert_eq!(backend.snapshot_reads.load(Ordering::SeqCst), 0);
        assert_eq!(backend.recovery_reads.load(Ordering::SeqCst), 0);
    }

    /// The regression that started this work, pinned on the new decorator.
    ///
    /// `StorageBackend::load_snapshot_cursor` has a default that recovers the
    /// whole authority. A decorator that omits the method inherits that
    /// default and turns every publication probe into a snapshot download. The
    /// probe must reach the backend's own metadata-only implementation and
    /// must load no snapshot on the way.
    #[test]
    fn the_publication_probe_reaches_the_backends_own_metadata_read() {
        let (backend, memo) = fixture();

        assert_eq!(
            memo.load_snapshot_cursor("kin").unwrap(),
            Some(SnapshotCursor::from_backend_generation(7))
        );
        assert_eq!(backend.cursor_reads.load(Ordering::SeqCst), 1);
        assert_eq!(backend.snapshot_reads.load(Ordering::SeqCst), 0);
        assert_eq!(backend.recovery_reads.load(Ordering::SeqCst), 0);
    }
}
