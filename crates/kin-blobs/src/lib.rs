// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

mod error;

pub use error::BlobError;

use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use tracing::{debug, warn};

/// Content-addressed 256-bit hash.
#[derive(
    Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
pub struct Hash256(pub [u8; 32]);

impl Hash256 {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn from_hex(s: &str) -> std::result::Result<Self, hex::FromHexError> {
        let mut buf = [0u8; 32];
        hex::decode_to_slice(s, &mut buf)?;
        Ok(Self(buf))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Display for Hash256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl std::fmt::Debug for Hash256 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Hash256({})", &hex::encode(self.0)[..12])
    }
}

/// Monotonic counter for unique temp file names within a process.
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Number of renames after which [`BlobStore::write`] drains pending
/// directory barriers on its own.
///
/// This is a backstop, not a tuning knob: it exists so a caller that never
/// calls [`BlobStore::sync`] and holds its store for the life of the process
/// still cannot accumulate an unbounded set of renames awaiting a barrier.
///
/// A drain costs one barrier per shard directory touched since the previous
/// drain, which two-hex-character sharding caps at 256. Draining every 4096
/// renames therefore holds the amortized directory cost below 0.07 barriers
/// per blob, against exactly 1.0 when every write barriered its own shard,
/// while bounding the un-barriered renames at 4096.
const PENDING_RENAME_DRAIN_THRESHOLD: usize = 4096;

pub type Result<T> = std::result::Result<T, BlobError>;

/// Compute the SHA-256 hash of the given data.
///
/// This is the primary way to produce a `Hash256` for content-addressed
/// storage. The `Hash256` type is hash-algorithm-agnostic; the SHA-256
/// dependency lives here.
pub fn digest(data: &[u8]) -> Hash256 {
    Hash256(digest_bytes(data))
}

/// Compute a SHA-256 digest of `data`, returning the raw 32 bytes.
///
/// Lower-level variant of [`digest`] for callers that need raw bytes.
pub fn digest_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    bytes
}

/// Content-addressable blob store using SHA-256 hashing and Git-style sharding.
///
/// Blobs are stored at `{root}/{hash[0..2]}/{hash[2..]}` where the hash is
/// hex-encoded. This provides directory-level sharding to avoid filesystem
/// bottlenecks with large numbers of objects.
///
/// # Durability model
///
/// A blob's *bytes* are durable when [`write`](Self::write) returns. The
/// barrier that makes the blob's *name* durable is deferred and amortized
/// across a shard directory, and is issued by [`sync`](Self::sync), by the
/// [`Drop`] drain, or by `write` itself once enough renames accumulate. See
/// [`write`](Self::write) for the crash states this does and does not admit.
pub struct BlobStore {
    root: PathBuf,
    pending: Mutex<PendingDirSyncs>,
    /// Renames after which [`BlobStore::write`] drains on its own. Always
    /// [`PENDING_RENAME_DRAIN_THRESHOLD`] outside this crate's own tests, which
    /// lower it so the drain path is exercised without writing thousands of
    /// blobs.
    drain_threshold: usize,
}

/// Directory entries this store has created but not yet made durable.
///
/// Tracked per shard rather than per blob: a shard directory needs exactly one
/// barrier no matter how many renames landed in it since the last one.
#[derive(Default)]
struct PendingDirSyncs {
    /// Two-hex-character shard directory names holding a pending rename.
    shards: BTreeSet<String>,
    /// Whether the store root holds a shard directory creation that is not yet
    /// durable. A lost shard directory loses every blob beneath it the same way
    /// a lost rename loses one, so the root drains on the same schedule.
    root: bool,
    /// Renames recorded since the last drain.
    renames: usize,
}

impl PendingDirSyncs {
    /// Record one rename into `shard`, reporting whether the caller should
    /// drain now.
    fn record(&mut self, shard: &str, created_shard_dir: bool, threshold: usize) -> bool {
        self.shards.insert(shard.to_string());
        self.root |= created_shard_dir;
        self.renames += 1;
        self.renames >= threshold
    }
}

/// Summary of a single [`gc`](BlobStore::gc) pass over the store.
///
/// All counts are over blobs enumerated at the start of the pass: `scanned` is
/// the total observed, `retained` the subset kept because it was in the
/// caller-supplied live set, and `reclaimed` the subset removed. `bytes_reclaimed`
/// is the summed on-disk size of the removed blobs (best-effort; a blob whose
/// size could not be read at sweep time contributes 0).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GcReport {
    /// Total number of stored blobs observed by the sweep.
    pub scanned: usize,
    /// Number of blobs kept because they were present in the live set.
    pub retained: usize,
    /// Number of blobs removed because they were absent from the live set.
    pub reclaimed: usize,
    /// Total on-disk bytes freed by the reclaimed blobs.
    pub bytes_reclaimed: u64,
}

impl BlobStore {
    /// Create or open a blob store at the given root directory.
    ///
    /// Creates the root directory if it does not exist.
    pub fn new(root: PathBuf) -> Result<Self> {
        Self::with_drain_threshold(root, PENDING_RENAME_DRAIN_THRESHOLD)
    }

    fn with_drain_threshold(root: PathBuf, drain_threshold: usize) -> Result<Self> {
        fs::create_dir_all(&root).map_err(|e| BlobError::io(&root, e))?;
        Ok(Self {
            root,
            pending: Mutex::new(PendingDirSyncs::default()),
            drain_threshold,
        })
    }

    /// Write data to the blob store, returning its content hash.
    ///
    /// If a blob with the same hash already exists, this is a no-op (content
    /// deduplication).
    ///
    /// # Durability
    ///
    /// Writes are atomic, and a blob's **contents** are durable when `write`
    /// returns: data goes to a unique temporary file in the shard directory,
    /// the file's bytes are `fsync`ed, and only then is it renamed into place.
    /// That ordering is what stops a power loss after `rename` from leaving a
    /// zero-length or torn object that the content address now vouches for.
    /// Because `write` dedup-skips on existence, such an object would be
    /// trusted forever.
    ///
    /// The **directory** barrier that makes the rename itself durable is
    /// deferred and amortized: `write` records the shard as pending, and
    /// [`sync`](Self::sync) issues one barrier per shard directory rather than
    /// one per blob. A store dropped without an explicit `sync` drains on
    /// `drop`, and `write` drains on its own once enough renames accumulate, so
    /// the set of renames awaiting a barrier is always bounded.
    ///
    /// The one crash state this defers into is a blob whose bytes reached the
    /// device but whose name did not: the blob is **absent**, never
    /// present-but-corrupt, because its content barrier strictly precedes the
    /// rename that publishes the name. An absent blob is what dedup already
    /// treats as "not written yet", so it is re-writable byte for byte from the
    /// same content, the property content addressing exists to provide.
    /// Callers that must know a set of names is durable before recording
    /// references that outlive a crash should call [`sync`](Self::sync) as their
    /// commit point.
    ///
    /// # Self-healing precondition for write-only callers
    ///
    /// If a corrupt blob is already present at its content-addressed path,
    /// `write` will skip writing and return `Ok(hash)` — the corrupt file stays
    /// trusted by dedup. The self-healing path is:
    ///
    /// 1. Call [`read`](Self::read): it detects the mismatch, quarantines the
    ///    corrupt file (freeing the path), and returns [`BlobError::HashMismatch`].
    /// 2. Call `write` again: dedup now sees no existing file and writes correctly.
    ///
    /// Callers that never call `read` on a written blob (bulk importers, etc.)
    /// will not trigger quarantine and a corrupt file can persist indefinitely.
    /// The safe pattern for resilient importers is to `write` then immediately
    /// `read`-verify, or to call [`read`](Self::read) instead of relying on dedup
    /// to detect prior corruption.
    pub fn write(&self, data: &[u8]) -> Result<Hash256> {
        let _span = tracing::info_span!("kin_blobs.write", bytes = data.len()).entered();
        let hash = digest(data);
        let hex = hash.to_string();
        let shard_name = &hex[..2];
        let shard_dir = self.root.join(shard_name);
        let blob_path = shard_dir.join(&hex[2..]);

        // Deduplication: if the blob already exists, skip writing.
        if blob_path.exists() {
            debug!(hash = %hash, "blob already exists, skipping write");
            return Ok(hash);
        }

        let created_shard_dir = self.ensure_shard_dir(&shard_dir)?;

        // Atomic-durable write: write to a unique temp file in the shard dir,
        // fsync its contents, then rename into place. The shard directory's own
        // barrier is deferred to `sync`.
        let seq = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let temp_path = shard_dir.join(format!(".tmp-{}-{}-{}", hash, std::process::id(), seq));
        write_file_durably(&temp_path, data).map_err(|e| BlobError::io(&temp_path, e))?;
        fs::rename(&temp_path, &blob_path).map_err(|e| {
            // Don't leave the fsynced temp file behind on a failed rename.
            let _ = fs::remove_file(&temp_path);
            BlobError::io(&blob_path, e)
        })?;

        // Bound the guard to a `let` so it is unmistakably released before the
        // drain below reacquires it.
        let drain_now =
            self.lock_pending()
                .record(shard_name, created_shard_dir, self.drain_threshold);
        if drain_now {
            // Bounded backstop only. The blob's bytes are already durable, so a
            // failed directory barrier does not make this write unsuccessful;
            // the shard stays pending and a later `sync`/`drop` retries it.
            let _ = self.sync();
        }

        debug!(hash = %hash, bytes = data.len(), "wrote blob");
        Ok(hash)
    }

    /// Issue the deferred directory barriers, making every rename and shard
    /// directory this store has created durable.
    ///
    /// This is the store's commit point. [`write`](Self::write) makes a blob's
    /// *bytes* durable before renaming the blob into place but leaves the
    /// barrier that makes the *name* durable to this call, so a bulk import
    /// pays one barrier per shard directory touched (at most 256, given
    /// two-hex-character sharding) instead of one per blob. A newly created
    /// shard directory is itself an entry in the store root, so the root is
    /// barriered here too.
    ///
    /// Calling `sync` is optional: dropping the store drains, and `write`
    /// drains on its own once enough renames accumulate. Call it explicitly
    /// when about to record blob references somewhere that outlives a crash and
    /// those names must be durable first.
    ///
    /// A directory that no longer exists, pruned by [`gc`](Self::gc)
    /// compaction or removed along with the store root, has no entry left to
    /// make durable and is not an error. Any other failure is returned, and the
    /// directories it affected stay pending so a later `sync` or the `drop`
    /// drain retries them.
    pub fn sync(&self) -> Result<()> {
        let (shards, root) = {
            let mut pending = self.lock_pending();
            pending.renames = 0;
            (
                std::mem::take(&mut pending.shards),
                std::mem::take(&mut pending.root),
            )
        };
        if shards.is_empty() && !root {
            return Ok(());
        }
        let _span = tracing::info_span!("kin_blobs.sync", shards = shards.len()).entered();

        let mut first_error: Option<BlobError> = None;
        let mut unsynced = BTreeSet::new();
        let mut root_unsynced = false;

        if root {
            if let Err(e) = sync_dir(&self.root) {
                // A removed root has no entry left to make durable.
                if e.kind() != std::io::ErrorKind::NotFound {
                    first_error = Some(BlobError::io(&self.root, e));
                    root_unsynced = true;
                }
            }
        }
        for shard in shards {
            let shard_dir = self.root.join(&shard);
            match sync_dir(&shard_dir) {
                Ok(()) => {}
                // Pruned by compaction, or removed with the store root.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    if first_error.is_none() {
                        first_error = Some(BlobError::io(&shard_dir, e));
                    }
                    unsynced.insert(shard);
                }
            }
        }

        if root_unsynced || !unsynced.is_empty() {
            let mut pending = self.lock_pending();
            pending.root |= root_unsynced;
            pending.shards.extend(unsynced);
        }
        match first_error {
            Some(e) => Err(e),
            None => Ok(()),
        }
    }

    /// Create `shard_dir` if absent, reporting whether this call created it.
    ///
    /// A newly created shard directory is a new entry in the store root, so the
    /// root needs a barrier of its own before that directory is durable.
    fn ensure_shard_dir(&self, shard_dir: &Path) -> Result<bool> {
        match fs::create_dir(shard_dir) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(false),
            // The root itself was removed underneath us: rebuild the chain.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir_all(shard_dir).map_err(|e| BlobError::io(shard_dir, e))?;
                Ok(true)
            }
            Err(e) => Err(BlobError::io(shard_dir, e)),
        }
    }

    /// Lock the pending-barrier state, recovering from poisoning.
    ///
    /// The state is a plain set of shard names and two counters: a panic
    /// elsewhere in the process cannot leave it structurally invalid, so
    /// refusing to sync after an unrelated panic would turn that panic into a
    /// durability outage for the whole store.
    fn lock_pending(&self) -> MutexGuard<'_, PendingDirSyncs> {
        self.pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Read a blob by its hash, verifying that the stored bytes still hash to
    /// the requested address.
    ///
    /// This is the honest default for a content-addressed store: a torn write or
    /// on-disk bit-rot is caught here instead of silently serving corrupt content
    /// into the graph. On a mismatch the bad object is quarantined (see
    /// [`quarantine`](Self::quarantine)) — moved aside so dedup stops trusting it
    /// and a later `write` of the correct bytes can heal the store — and a
    /// [`BlobError::HashMismatch`] is returned.
    ///
    /// Returns [`BlobError::NotFound`] if the blob does not exist. Callers on a
    /// hot path who have already established integrity may opt out of the re-hash
    /// with [`read_unverified`](Self::read_unverified).
    pub fn read(&self, hash: &Hash256) -> Result<Vec<u8>> {
        let _span = tracing::info_span!("kin_blobs.read", hash = %hash).entered();
        let data = self.read_unverified(hash)?;
        let actual = digest(&data);
        if actual != *hash {
            // Content no longer matches its address: the object is corrupt.
            // Quarantine it (preserving evidence) so dedup stops trusting it and
            // a rewrite can heal the store, then surface the mismatch.
            let quarantined = self.quarantine(hash).unwrap_or(None);
            warn!(
                expected = %hash,
                actual = %actual,
                quarantined = ?quarantined,
                "blob failed hash verification on read; quarantined corrupt object"
            );
            return Err(BlobError::HashMismatch {
                expected: hash.to_string(),
                actual: actual.to_string(),
            });
        }
        Ok(data)
    }

    /// Read a blob by its hash WITHOUT verifying its content hash.
    ///
    /// Faster than [`read`](Self::read) because it skips the re-hash, but it
    /// trusts the on-disk bytes blindly. Use only on hot paths where integrity
    /// has already been established — never as the general-purpose read.
    ///
    /// Returns [`BlobError::NotFound`] if the blob does not exist.
    ///
    /// # Warning: bypasses the quarantine-trigger
    ///
    /// Unlike [`read`](Self::read), this method does not hash-verify the content
    /// and therefore never detects corruption or triggers quarantine. If this is
    /// the only read path for a given blob, a corrupt file will never be
    /// quarantined and a subsequent `write` of the correct bytes will continue to
    /// dedup-skip past the corrupt file. Prefer `read` for correctness;
    /// reserve `read_unverified` for hot paths where prior verification is proven.
    pub fn read_unverified(&self, hash: &Hash256) -> Result<Vec<u8>> {
        let blob_path = self.blob_path(hash);
        fs::read(&blob_path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                BlobError::NotFound {
                    hash: hash.to_string(),
                }
            } else {
                BlobError::io(&blob_path, e)
            }
        })
    }

    /// Check whether a blob exists in the store.
    pub fn exists(&self, hash: &Hash256) -> Result<bool> {
        let blob_path = self.blob_path(hash);
        match blob_path.try_exists() {
            Ok(exists) => Ok(exists),
            Err(e) => Err(BlobError::io(&blob_path, e)),
        }
    }

    /// Delete a blob from the store.
    ///
    /// Returns an error if the blob does not exist.
    pub fn delete(&self, hash: &Hash256) -> Result<()> {
        let blob_path = self.blob_path(hash);
        fs::remove_file(&blob_path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                BlobError::NotFound {
                    hash: hash.to_string(),
                }
            } else {
                BlobError::io(&blob_path, e)
            }
        })?;
        debug!(hash = %hash, "deleted blob");
        Ok(())
    }

    /// Enumerate every blob hash currently stored under `root`.
    ///
    /// Walks the Git-style shard directories (`{root}/{hash[0..2]}/...`) and
    /// reconstructs each blob's [`Hash256`] from `{shard}{name}`. This is the
    /// enumeration primitive that [`gc`](Self::gc) sweeps over.
    ///
    /// Robust to a partially-populated store: the `.corrupt/` quarantine area is
    /// skipped entirely, as are leftover `.tmp-*` temp files and any other entry
    /// whose name does not parse as a valid 64-hex-char hash. Top-level entries
    /// that are not 2-hex-char shard directories are ignored, and a missing root
    /// yields an empty result rather than an error.
    pub fn list_hashes(&self) -> Result<Vec<Hash256>> {
        let entries = match fs::read_dir(&self.root) {
            Ok(entries) => entries,
            // A store that has never been written to (or whose root was reaped by
            // a prior compaction) simply holds nothing.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(BlobError::io(&self.root, e)),
        };

        let mut hashes = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| BlobError::io(&self.root, e))?;
            let shard = entry.file_name();
            let shard = shard.to_string_lossy();
            // Only real 2-hex-char shard dirs hold blobs. This skips `.corrupt`
            // (leading dot, wrong length) and any stray top-level files.
            if shard.len() != 2 || !is_hex(&shard) {
                continue;
            }
            let shard_path = entry.path();
            if !shard_path.is_dir() {
                continue;
            }
            let shard_entries =
                fs::read_dir(&shard_path).map_err(|e| BlobError::io(&shard_path, e))?;
            for shard_entry in shard_entries {
                let shard_entry = shard_entry.map_err(|e| BlobError::io(&shard_path, e))?;
                let name = shard_entry.file_name();
                let name = name.to_string_lossy();
                // Skip `.tmp-*` temp files and anything else that isn't a valid
                // remainder of a content address. `from_hex` enforces both the
                // 64-char total length and hex-only content.
                match Hash256::from_hex(&format!("{shard}{name}")) {
                    Ok(hash) => hashes.push(hash),
                    Err(_) => continue,
                }
            }
        }
        Ok(hashes)
    }

    /// Reachability-based garbage collection (mark-and-sweep) with compaction.
    ///
    /// Reclaims every stored blob whose hash is absent from the caller-supplied
    /// `live` set — the live-root set the caller has determined is still
    /// reachable from the graph. Enumeration is via [`list_hashes`](Self::list_hashes),
    /// and each unreferenced blob is removed through [`delete`](Self::delete).
    /// After sweeping, now-empty shard directories are pruned (compaction) so the
    /// on-disk layout does not accumulate empty 2-char dirs.
    ///
    /// Contract:
    /// - GC reclaims **only** blobs absent from `live`. Anything in `live` is
    ///   retained untouched.
    /// - The `.corrupt/` quarantine area is **never** touched: corrupt-object
    ///   evidence survives GC, and the `.corrupt` directory is never pruned.
    /// - Concurrency: enumeration takes a point-in-time snapshot of the store. A
    ///   blob written *after* enumeration is simply not seen and therefore never
    ///   collected — GC can never race-delete a freshly-written object it didn't
    ///   observe. Conversely, a blob deleted concurrently (its [`delete`](Self::delete)
    ///   returning [`BlobError::NotFound`]) is counted as already-reclaimed rather
    ///   than treated as an error.
    pub fn gc(&self, live: &std::collections::HashSet<Hash256>) -> Result<GcReport> {
        let _span = tracing::info_span!("kin_blobs.gc", live = live.len()).entered();

        let stored = self.list_hashes()?;
        let scanned = stored.len();
        let mut report = GcReport {
            scanned,
            ..GcReport::default()
        };

        for hash in stored {
            if live.contains(&hash) {
                report.retained += 1;
                continue;
            }
            // Record the on-disk size before removal (best-effort: a concurrent
            // delete may already have removed it).
            let blob_path = self.blob_path(&hash);
            let size = fs::metadata(&blob_path).map(|m| m.len()).unwrap_or(0);
            match self.delete(&hash) {
                Ok(()) => {
                    report.reclaimed += 1;
                    report.bytes_reclaimed += size;
                }
                // A concurrent delete already reclaimed it: count it, don't fail.
                Err(BlobError::NotFound { .. }) => {
                    report.reclaimed += 1;
                    report.bytes_reclaimed += size;
                }
                Err(e) => return Err(e),
            }
        }

        self.prune_empty_shards();

        debug!(
            scanned = report.scanned,
            retained = report.retained,
            reclaimed = report.reclaimed,
            bytes_reclaimed = report.bytes_reclaimed,
            "gc complete"
        );
        Ok(report)
    }

    /// Best-effort compaction: remove empty 2-hex-char shard directories left
    /// behind after a sweep. The `.corrupt/` area and any non-shard entry are
    /// never removed. Errors are intentionally swallowed — a non-empty or
    /// concurrently-repopulated shard simply stays, which is harmless.
    fn prune_empty_shards(&self) {
        let entries = match fs::read_dir(&self.root) {
            Ok(entries) => entries,
            Err(_) => return,
        };
        for entry in entries.flatten() {
            let shard = entry.file_name();
            let shard = shard.to_string_lossy();
            // Only ever consider real 2-hex-char shard dirs; this leaves
            // `.corrupt` and any other top-level entry untouched.
            if shard.len() != 2 || !is_hex(&shard) {
                continue;
            }
            let shard_path = entry.path();
            if shard_path.is_dir() {
                // `remove_dir` only succeeds on an empty directory, so a shard
                // that still holds (or just regained) a blob is left alone.
                let _ = fs::remove_dir(&shard_path);
            }
        }
    }

    /// Move a corrupt object aside into a `.corrupt/` area under the store root.
    ///
    /// Preserves the bad bytes as evidence (quarantine never deletes data) and,
    /// crucially, frees the object's content-addressed path so a subsequent
    /// [`write`](Self::write) of the correct content is no longer dedup-skipped —
    /// the store self-heals on the next write. This is invoked automatically by
    /// [`read`](Self::read) on a [`BlobError::HashMismatch`].
    ///
    /// Returns the path the object was moved to, or `Ok(None)` when there was
    /// nothing at the object's path to quarantine (e.g. a concurrent reader
    /// already moved it). The quarantine file is named after the object's
    /// *expected* address so an operator can trace which blob it was meant to be.
    pub fn quarantine(&self, hash: &Hash256) -> Result<Option<PathBuf>> {
        let blob_path = self.blob_path(hash);
        if !blob_path.exists() {
            return Ok(None);
        }
        let corrupt_dir = self.root.join(".corrupt");
        fs::create_dir_all(&corrupt_dir).map_err(|e| BlobError::io(&corrupt_dir, e))?;
        let seq = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
        let dest = corrupt_dir.join(format!("{}-{}-{}", hash, std::process::id(), seq));
        match fs::rename(&blob_path, &dest) {
            Ok(()) => {
                // Make the quarantine move durable so a crash can't resurrect the
                // corrupt object back into the dedup path. Unlike the write path
                // this barrier is not amortized: quarantine runs only on detected
                // corruption, so it is never hot, and deferring it would leave the
                // corrupt object dedup-trusted for the length of the deferral.
                // Failures stay swallowed: a resurrected corrupt object is
                // re-detected and re-quarantined by the next `read`.
                let _ = sync_dir(&corrupt_dir);
                if let Some(parent) = blob_path.parent() {
                    let _ = sync_dir(parent);
                }
                debug!(hash = %hash, dest = %dest.display(), "quarantined corrupt blob");
                Ok(Some(dest))
            }
            // Lost a race with another reader that already quarantined it.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(BlobError::io(&dest, e)),
        }
    }

    /// Return the root directory of the blob store.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Compute the filesystem path for a blob given its hash.
    ///
    /// Layout: `{root}/{hash[0..2]}/{hash[2..]}` (Git-style sharding).
    fn blob_path(&self, hash: &Hash256) -> PathBuf {
        let hex = hash.to_string();
        self.root.join(&hex[..2]).join(&hex[2..])
    }

    /// Directory barriers this store still owes: `(shards, root, renames)`.
    ///
    /// Test-only window onto the deferral itself, so the amortization can be
    /// asserted rather than inferred from timings.
    #[cfg(test)]
    fn pending_snapshot(&self) -> (usize, bool, usize) {
        let pending = self.lock_pending();
        (pending.shards.len(), pending.root, pending.renames)
    }
}

impl Drop for BlobStore {
    /// Drain any deferred directory barriers.
    ///
    /// Dropping the handle is the last commit point a caller that never called
    /// [`sync`](BlobStore::sync) will get. Failures are swallowed because
    /// `drop` cannot report them, which matches the best-effort directory
    /// barrier policy this store has always had.
    fn drop(&mut self) {
        let _ = self.sync();
    }
}

/// Whether every character in `s` is an ASCII hex digit (`0-9`, `a-f`, `A-F`).
///
/// Used by enumeration and compaction to recognize genuine shard directories and
/// reject stray entries (`.corrupt`, `.tmp-*`, etc.) without erroring.
fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Write `data` to `path` and `fsync` the file so its bytes are durable on disk
/// before the caller renames it into its final content-addressed location.
fn write_file_durably(path: &Path, data: &[u8]) -> std::io::Result<()> {
    let mut file = File::create(path)?;
    file.write_all(data)?;
    file.sync_all()?;
    Ok(())
}

/// `fsync` a directory so a `rename`/`create` within it is durable.
///
/// Directory fsync is not guaranteed on every platform (and is a no-op on
/// some). The error is returned rather than swallowed so [`BlobStore::sync`]
/// can distinguish "nothing left to make durable" (the directory is gone) from
/// a real failure it must keep pending and report.
fn sync_dir(dir: &Path) -> std::io::Result<()> {
    File::open(dir)?.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_store() -> (tempfile::TempDir, BlobStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = BlobStore::new(dir.path().join("objects")).unwrap();
        (dir, store)
    }

    #[test]
    fn write_and_read_round_trip() {
        let (_dir, store) = make_store();
        let data = b"hello, blob store!";
        let hash = store.write(data).unwrap();
        let retrieved = store.read(&hash).unwrap();
        assert_eq!(retrieved, data);
    }

    #[test]
    fn deduplication() {
        let (_dir, store) = make_store();
        let data = b"duplicate content";
        let hash1 = store.write(data).unwrap();
        let hash2 = store.write(data).unwrap();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn different_content_different_hash() {
        let (_dir, store) = make_store();
        let hash1 = store.write(b"content A").unwrap();
        let hash2 = store.write(b"content B").unwrap();
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn read_missing_blob_returns_not_found() {
        let (_dir, store) = make_store();
        let fake_hash = Hash256([0xab; 32]);
        let err = store.read(&fake_hash).unwrap_err();
        assert!(matches!(err, BlobError::NotFound { .. }));
    }

    #[test]
    fn exists_returns_false_for_missing() {
        let (_dir, store) = make_store();
        let fake_hash = Hash256([0xcd; 32]);
        assert!(!store.exists(&fake_hash).unwrap());
    }

    #[test]
    fn exists_returns_true_after_write() {
        let (_dir, store) = make_store();
        let hash = store.write(b"some data").unwrap();
        assert!(store.exists(&hash).unwrap());
    }

    #[test]
    fn delete_removes_blob() {
        let (_dir, store) = make_store();
        let hash = store.write(b"delete me").unwrap();
        assert!(store.exists(&hash).unwrap());
        store.delete(&hash).unwrap();
        assert!(!store.exists(&hash).unwrap());
    }

    #[test]
    fn delete_missing_blob_returns_not_found() {
        let (_dir, store) = make_store();
        let fake_hash = Hash256([0xef; 32]);
        let err = store.delete(&fake_hash).unwrap_err();
        assert!(matches!(err, BlobError::NotFound { .. }));
    }

    #[test]
    fn sharding_directory_structure() {
        let (_dir, store) = make_store();
        let data = b"sharding test";
        let hash = store.write(data).unwrap();
        let hex = hash.to_string();

        // Verify the shard directory exists
        let shard_dir = store.root().join(&hex[..2]);
        assert!(shard_dir.is_dir());

        // Verify the blob file exists with the correct name
        let blob_file = shard_dir.join(&hex[2..]);
        assert!(blob_file.is_file());

        // Verify content matches
        let content = std::fs::read(&blob_file).unwrap();
        assert_eq!(content, data);
    }

    #[test]
    fn hash256_hex_round_trip() {
        let hash = digest(b"test data");
        let hex = hash.to_string();
        let parsed = Hash256::from_hex(&hex).unwrap();
        assert_eq!(hash, parsed);
    }

    #[test]
    fn hash256_display() {
        let hash = digest(b"display test");
        let display = format!("{hash}");
        assert_eq!(display.len(), 64); // 32 bytes = 64 hex chars
        assert_eq!(display, hash.to_string());
    }

    #[test]
    fn empty_blob() {
        let (_dir, store) = make_store();
        let hash = store.write(b"").unwrap();
        let data = store.read(&hash).unwrap();
        assert!(data.is_empty());
    }

    #[test]
    fn large_blob() {
        let (_dir, store) = make_store();
        let data: Vec<u8> = (0..100_000).map(|i| (i % 256) as u8).collect();
        let hash = store.write(&data).unwrap();
        let retrieved = store.read(&hash).unwrap();
        assert_eq!(retrieved, data);
    }

    // -----------------------------------------------------------------------
    // digest / Hash256 tests
    // -----------------------------------------------------------------------

    #[test]
    fn digest_deterministic() {
        let h1 = digest(b"hello");
        let h2 = digest(b"hello");
        assert_eq!(h1, h2);
    }

    #[test]
    fn digest_different_data_different_hash() {
        let h1 = digest(b"hello");
        let h2 = digest(b"world");
        assert_ne!(h1, h2);
    }

    #[test]
    fn hash256_from_hex_invalid_length() {
        let result = Hash256::from_hex("abcd");
        assert!(result.is_err());
    }

    #[test]
    fn hash256_from_hex_invalid_chars() {
        let result =
            Hash256::from_hex("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz");
        assert!(result.is_err());
    }

    #[test]
    fn hash256_debug_format() {
        let hash = digest(b"debug");
        let debug = format!("{:?}", hash);
        assert!(debug.starts_with("Hash256("));
        assert!(debug.ends_with(")"));
    }

    #[test]
    fn digest_empty_data() {
        let hash = digest(b"");
        // SHA-256 of empty string is a known value
        assert_eq!(
            hash.to_string(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn hash256_copy_semantics() {
        let h1 = digest(b"copy");
        let h2 = h1; // Copy
        assert_eq!(h1, h2);
    }

    #[test]
    fn hash256_hash_trait() {
        use std::collections::HashSet;
        let h1 = digest(b"a");
        let h2 = digest(b"b");
        let mut set = HashSet::new();
        set.insert(h1);
        set.insert(h2);
        set.insert(h1); // duplicate
        assert_eq!(set.len(), 2);
    }

    // -----------------------------------------------------------------------
    // BlobStore advanced tests
    // -----------------------------------------------------------------------

    #[test]
    fn store_root_returns_correct_path() {
        let dir = tempfile::tempdir().unwrap();
        let objects_path = dir.path().join("my_objects");
        let store = BlobStore::new(objects_path.clone()).unwrap();
        assert_eq!(store.root(), objects_path);
    }

    #[test]
    fn write_creates_root_if_missing() {
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("a").join("b").join("c").join("objects");
        let store = BlobStore::new(nested.clone()).unwrap();
        assert!(nested.exists());
        let hash = store.write(b"test").unwrap();
        assert!(store.exists(&hash).unwrap());
    }

    #[test]
    fn one_megabyte_blob() {
        let (_dir, store) = make_store();
        let data: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();
        let hash = store.write(&data).unwrap();
        let retrieved = store.read(&hash).unwrap();
        assert_eq!(retrieved.len(), 1_000_000);
        assert_eq!(retrieved, data);
    }

    #[test]
    fn binary_content_blob() {
        let (_dir, store) = make_store();
        // All possible byte values
        let data: Vec<u8> = (0..=255).collect();
        let hash = store.write(&data).unwrap();
        let retrieved = store.read(&hash).unwrap();
        assert_eq!(retrieved, data);
    }

    #[test]
    fn write_read_delete_read_cycle() {
        let (_dir, store) = make_store();
        let hash = store.write(b"cycle test").unwrap();
        assert!(store.exists(&hash).unwrap());
        let data = store.read(&hash).unwrap();
        assert_eq!(data, b"cycle test");
        store.delete(&hash).unwrap();
        assert!(!store.exists(&hash).unwrap());
        assert!(store.read(&hash).is_err());
    }

    #[test]
    fn double_delete_fails() {
        let (_dir, store) = make_store();
        let hash = store.write(b"delete twice").unwrap();
        store.delete(&hash).unwrap();
        let err = store.delete(&hash).unwrap_err();
        assert!(matches!(err, BlobError::NotFound { .. }));
    }

    #[test]
    fn different_shards_for_different_content() {
        let (_dir, store) = make_store();
        let h1 = store.write(b"content alpha").unwrap();
        let h2 = store.write(b"content beta").unwrap();
        let hex1 = h1.to_string();
        let hex2 = h2.to_string();
        // Different content should (almost certainly) have different shard prefixes
        // or at minimum different hashes
        assert_ne!(hex1, hex2);
    }

    #[test]
    fn shard_directory_is_two_char_prefix() {
        let (_dir, store) = make_store();
        let hash = store.write(b"shard check").unwrap();
        let hex = hash.to_string();
        let shard = &hex[..2];
        let shard_dir = store.root().join(shard);
        assert!(shard_dir.is_dir());
        let blob_name = &hex[2..];
        let blob_path = shard_dir.join(blob_name);
        assert!(blob_path.is_file());
    }

    #[test]
    fn hash_verification_on_read() {
        let (_dir, store) = make_store();
        let data = b"verify me";
        let hash = store.write(data).unwrap();
        let retrieved = store.read(&hash).unwrap();
        let recomputed = digest(&retrieved);
        assert_eq!(hash, recomputed);
    }

    #[test]
    fn concurrent_writes_same_content() {
        let (_dir, store) = make_store();
        let store = std::sync::Arc::new(store);
        let mut handles = Vec::new();
        let data = b"concurrent content";

        for _ in 0..10 {
            let s = std::sync::Arc::clone(&store);
            handles.push(std::thread::spawn(move || s.write(data)));
        }

        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        // At least one write must succeed
        let successes: Vec<Hash256> = results.into_iter().filter_map(|r| r.ok()).collect();
        assert!(
            !successes.is_empty(),
            "at least one concurrent write must succeed"
        );

        // All successful writes should produce the same hash
        let first = successes[0];
        for h in &successes {
            assert_eq!(*h, first);
        }

        // Content should be readable
        let retrieved = store.read(&first).unwrap();
        assert_eq!(retrieved.as_slice(), data);
    }

    #[test]
    fn concurrent_writes_different_content() {
        let (_dir, store) = make_store();
        let store = std::sync::Arc::new(store);
        let mut handles = Vec::new();

        for i in 0..10u8 {
            let s = std::sync::Arc::clone(&store);
            handles.push(std::thread::spawn(move || {
                let data = vec![i; 100];
                let hash = s.write(&data).unwrap();
                (hash, data)
            }));
        }

        let results: Vec<(Hash256, Vec<u8>)> =
            handles.into_iter().map(|h| h.join().unwrap()).collect();

        for (hash, data) in &results {
            let retrieved = store.read(hash).unwrap();
            assert_eq!(&retrieved, data);
        }
    }

    #[test]
    fn multiple_distinct_blobs_coexist() {
        let (_dir, store) = make_store();
        let mut hashes = Vec::new();
        for i in 0..50 {
            let data = format!("blob number {i}");
            let hash = store.write(data.as_bytes()).unwrap();
            hashes.push((hash, data));
        }
        for (hash, expected) in &hashes {
            let retrieved = store.read(hash).unwrap();
            assert_eq!(retrieved, expected.as_bytes());
        }
    }

    #[test]
    fn idempotent_write_returns_same_hash() {
        let (_dir, store) = make_store();
        let data = b"idempotent";
        let h1 = store.write(data).unwrap();
        let h2 = store.write(data).unwrap();
        let h3 = store.write(data).unwrap();
        assert_eq!(h1, h2);
        assert_eq!(h2, h3);
    }

    #[test]
    fn exists_after_delete_returns_false() {
        let (_dir, store) = make_store();
        let hash = store.write(b"temp").unwrap();
        assert!(store.exists(&hash).unwrap());
        store.delete(&hash).unwrap();
        assert!(!store.exists(&hash).unwrap());
    }

    #[test]
    fn read_after_rewrite_succeeds() {
        let (_dir, store) = make_store();
        let data = b"rewrite";
        let hash = store.write(data).unwrap();
        store.delete(&hash).unwrap();
        let hash2 = store.write(data).unwrap();
        assert_eq!(hash, hash2);
        let retrieved = store.read(&hash2).unwrap();
        assert_eq!(retrieved.as_slice(), data);
    }

    #[test]
    fn whitespace_only_content() {
        let (_dir, store) = make_store();
        let data = b"   \n\t\r\n   ";
        let hash = store.write(data).unwrap();
        let retrieved = store.read(&hash).unwrap();
        assert_eq!(retrieved, data);
    }

    #[test]
    fn null_bytes_content() {
        let (_dir, store) = make_store();
        let data = vec![0u8; 1024];
        let hash = store.write(&data).unwrap();
        let retrieved = store.read(&hash).unwrap();
        assert_eq!(retrieved, data);
    }

    // -----------------------------------------------------------------------
    // Crash / corruption durability tests
    // -----------------------------------------------------------------------

    /// Reconstruct a blob's on-disk path the same way `blob_path` does, so tests
    /// can corrupt the backing file directly to simulate a torn write / bit-rot.
    fn on_disk_path(store: &BlobStore, hash: &Hash256) -> PathBuf {
        let hex = hash.to_string();
        store.root().join(&hex[..2]).join(&hex[2..])
    }

    fn corrupt_dir_entries(store: &BlobStore) -> Vec<PathBuf> {
        let corrupt = store.root().join(".corrupt");
        if !corrupt.exists() {
            return Vec::new();
        }
        std::fs::read_dir(&corrupt)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect()
    }

    /// A write must leave no temporary file behind: the temp is fsynced then
    /// renamed atomically into place, so the shard dir holds only the final blob.
    #[test]
    fn write_leaves_no_temp_file() {
        let (_dir, store) = make_store();
        let hash = store.write(b"atomic durable write").unwrap();
        let shard_dir = on_disk_path(&store, &hash).parent().unwrap().to_path_buf();
        let leftovers: Vec<_> = std::fs::read_dir(&shard_dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name.starts_with(".tmp-"))
            .collect();
        assert!(
            leftovers.is_empty(),
            "stray temp files remain: {leftovers:?}"
        );
    }

    /// A torn write (file truncated mid-content) must be caught on read as a
    /// hash mismatch rather than silently returning short content.
    #[test]
    fn torn_write_detected_on_read() {
        let (_dir, store) = make_store();
        let data: Vec<u8> = (0..2048).map(|i| (i % 256) as u8).collect();
        let hash = store.write(&data).unwrap();

        // Simulate a torn write: truncate the backing file to half its length.
        let path = on_disk_path(&store, &hash);
        let partial = &data[..data.len() / 2];
        std::fs::write(&path, partial).unwrap();

        let err = store.read(&hash).unwrap_err();
        assert!(
            matches!(err, BlobError::HashMismatch { .. }),
            "expected HashMismatch, got {err:?}"
        );
    }

    /// A single flipped byte (silent bit-rot) must be detected on read.
    #[test]
    fn bit_flip_detected_on_read() {
        let (_dir, store) = make_store();
        let data = b"the quick brown fox jumps over the lazy dog".to_vec();
        let hash = store.write(&data).unwrap();

        let path = on_disk_path(&store, &hash);
        let mut bytes = std::fs::read(&path).unwrap();
        bytes[0] ^= 0xFF; // flip the first byte
        std::fs::write(&path, &bytes).unwrap();

        let err = store.read(&hash).unwrap_err();
        assert!(
            matches!(err, BlobError::HashMismatch { .. }),
            "expected HashMismatch, got {err:?}"
        );
    }

    /// Detecting corruption on read must quarantine the bad object (preserving
    /// its exact bytes as evidence) and free its content-addressed path.
    #[test]
    fn read_quarantines_corrupt_object() {
        let (_dir, store) = make_store();
        let data = b"quarantine me when corrupt".to_vec();
        let hash = store.write(&data).unwrap();

        let path = on_disk_path(&store, &hash);
        let corrupt_bytes = b"this is not the original content at all".to_vec();
        std::fs::write(&path, &corrupt_bytes).unwrap();

        let _ = store.read(&hash).unwrap_err();

        // The content-addressed path is now free (no longer dedup-trusted)...
        assert!(
            !path.exists(),
            "corrupt object should be moved out of its path"
        );
        // ...and the bad bytes are preserved as evidence under `.corrupt/`.
        let entries = corrupt_dir_entries(&store);
        assert_eq!(entries.len(), 1, "exactly one quarantined object expected");
        let preserved = std::fs::read(&entries[0]).unwrap();
        assert_eq!(
            preserved, corrupt_bytes,
            "quarantine must preserve evidence"
        );
    }

    /// After a corrupt object is quarantined on read, re-writing the correct
    /// content must land (not be dedup-skipped) and heal the store.
    #[test]
    fn rewrite_after_quarantine_heals() {
        let (_dir, store) = make_store();
        let data = b"heal me after corruption".to_vec();
        let hash = store.write(&data).unwrap();

        // Corrupt the backing file, then read to trigger quarantine.
        let path = on_disk_path(&store, &hash);
        std::fs::write(&path, b"corrupted").unwrap();
        let _ = store.read(&hash).unwrap_err();
        assert!(!path.exists());

        // Re-writing the original content must NOT be dedup-skipped, and the
        // store is healed: the read now succeeds and verifies.
        let healed_hash = store.write(&data).unwrap();
        assert_eq!(healed_hash, hash);
        let retrieved = store.read(&hash).unwrap();
        assert_eq!(retrieved, data);
    }

    /// `read_unverified` must return the raw on-disk bytes even when corrupt,
    /// while `read` rejects them — the documented opt-out contract.
    #[test]
    fn read_unverified_bypasses_verification() {
        let (_dir, store) = make_store();
        let data = b"trust me blindly".to_vec();
        let hash = store.write(&data).unwrap();

        let path = on_disk_path(&store, &hash);
        let corrupt = b"corrupt but returned by read_unverified".to_vec();
        std::fs::write(&path, &corrupt).unwrap();

        // Unverified read returns the corrupt bytes as-is, no error.
        let raw = store.read_unverified(&hash).unwrap();
        assert_eq!(raw, corrupt);

        // Verified read rejects them (and quarantines).
        let err = store.read(&hash).unwrap_err();
        assert!(matches!(err, BlobError::HashMismatch { .. }));
    }

    /// Quarantining a hash with nothing on disk is a no-op, not an error.
    #[test]
    fn quarantine_missing_is_noop() {
        let (_dir, store) = make_store();
        let fake = Hash256([0x11; 32]);
        assert_eq!(store.quarantine(&fake).unwrap(), None);
    }

    /// A valid (uncorrupted) blob round-trips through the verifying read.
    #[test]
    fn verified_read_accepts_valid_blob() {
        let (_dir, store) = make_store();
        let data: Vec<u8> = (0..50_000).map(|i| (i % 256) as u8).collect();
        let hash = store.write(&data).unwrap();
        let retrieved = store.read(&hash).unwrap();
        assert_eq!(retrieved, data);
        // No spurious quarantine of healthy data.
        assert!(corrupt_dir_entries(&store).is_empty());
    }

    // -----------------------------------------------------------------------
    // list_hashes / GC / compaction tests
    // -----------------------------------------------------------------------

    use std::collections::HashSet;

    /// Count the 2-hex-char shard directories currently present under the root.
    fn shard_dir_count(store: &BlobStore) -> usize {
        std::fs::read_dir(store.root())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                let name = e.file_name();
                let name = name.to_string_lossy();
                name.len() == 2 && name.bytes().all(|b| b.is_ascii_hexdigit()) && e.path().is_dir()
            })
            .count()
    }

    #[test]
    fn list_hashes_roundtrips() {
        let (_dir, store) = make_store();
        let mut expected = HashSet::new();
        for i in 0..12 {
            let data = format!("list-hashes blob {i}");
            expected.insert(store.write(data.as_bytes()).unwrap());
        }
        let listed: HashSet<Hash256> = store.list_hashes().unwrap().into_iter().collect();
        assert_eq!(listed, expected);
    }

    #[test]
    fn list_hashes_empty_store_is_empty() {
        let (_dir, store) = make_store();
        assert!(store.list_hashes().unwrap().is_empty());
    }

    #[test]
    fn list_hashes_missing_root_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        // Construct a store, then remove its root entirely.
        let root = dir.path().join("gone");
        let store = BlobStore::new(root.clone()).unwrap();
        std::fs::remove_dir_all(&root).unwrap();
        assert!(store.list_hashes().unwrap().is_empty());
    }

    #[test]
    fn list_hashes_ignores_non_hash_files() {
        let (_dir, store) = make_store();
        let hash = store.write(b"real blob").unwrap();
        // Drop a stray non-hex file into the same shard dir.
        let shard_dir = on_disk_path(&store, &hash).parent().unwrap().to_path_buf();
        std::fs::write(shard_dir.join("not-a-hash.txt"), b"junk").unwrap();
        // And a leftover temp file with a `.tmp-` prefix.
        std::fs::write(shard_dir.join(".tmp-leftover"), b"abandoned").unwrap();

        let listed: Vec<Hash256> = store.list_hashes().unwrap();
        assert_eq!(listed, vec![hash], "only the real blob should be listed");

        // And GC must not choke on the stray entries.
        let report = store.gc(&HashSet::new()).unwrap();
        assert_eq!(report.scanned, 1);
        assert_eq!(report.reclaimed, 1);
    }

    #[test]
    fn list_hashes_skips_corrupt_dir() {
        let (_dir, store) = make_store();
        let data = b"corrupt-skip blob".to_vec();
        let hash = store.write(&data).unwrap();
        // Corrupt and read to trigger quarantine, populating `.corrupt/`.
        std::fs::write(on_disk_path(&store, &hash), b"corrupt").unwrap();
        let _ = store.read(&hash).unwrap_err();
        assert!(!corrupt_dir_entries(&store).is_empty());

        // The quarantined object must not appear in the listing.
        assert!(store.list_hashes().unwrap().is_empty());
    }

    #[test]
    fn gc_reclaims_unreferenced() {
        let (_dir, store) = make_store();
        let keep = store.write(b"keep this blob").unwrap();
        let drop1 = store.write(b"drop this blob one").unwrap();
        let drop2 = store.write(b"drop this blob two").unwrap();

        let mut live = HashSet::new();
        live.insert(keep);

        let report = store.gc(&live).unwrap();
        assert_eq!(report.scanned, 3);
        assert_eq!(report.retained, 1);
        assert_eq!(report.reclaimed, 2);

        // The live blob still reads back correctly.
        assert_eq!(store.read(&keep).unwrap(), b"keep this blob");
        // The unreferenced blobs are gone.
        assert!(!store.exists(&drop1).unwrap());
        assert!(!store.exists(&drop2).unwrap());
    }

    #[test]
    fn gc_empty_live_reclaims_all() {
        let (_dir, store) = make_store();
        let mut hashes = Vec::new();
        for i in 0..5 {
            hashes.push(store.write(format!("blob {i}").as_bytes()).unwrap());
        }
        let report = store.gc(&HashSet::new()).unwrap();
        assert_eq!(report.scanned, 5);
        assert_eq!(report.retained, 0);
        assert_eq!(report.reclaimed, 5);
        for h in &hashes {
            assert!(!store.exists(h).unwrap());
        }
    }

    #[test]
    fn gc_all_live_reclaims_nothing() {
        let (_dir, store) = make_store();
        let mut live = HashSet::new();
        for i in 0..5 {
            live.insert(store.write(format!("blob {i}").as_bytes()).unwrap());
        }
        let report = store.gc(&live).unwrap();
        assert_eq!(report.scanned, 5);
        assert_eq!(report.retained, 5);
        assert_eq!(report.reclaimed, 0);
        assert_eq!(report.bytes_reclaimed, 0);
        for h in &live {
            assert!(store.exists(h).unwrap());
        }
    }

    #[test]
    fn gc_reports_accurate_byte_count() {
        let (_dir, store) = make_store();
        // Distinct-length payloads so the summed byte count is unambiguous.
        let keep_data = vec![1u8; 100];
        let drop_a = vec![2u8; 250];
        let drop_b = vec![3u8; 777];
        let keep = store.write(&keep_data).unwrap();
        store.write(&drop_a).unwrap();
        store.write(&drop_b).unwrap();

        let mut live = HashSet::new();
        live.insert(keep);

        let report = store.gc(&live).unwrap();
        assert_eq!(report.reclaimed, 2);
        assert_eq!(
            report.bytes_reclaimed,
            (drop_a.len() + drop_b.len()) as u64,
            "bytes_reclaimed must equal the summed lengths of the reclaimed blobs"
        );
    }

    #[test]
    fn gc_preserves_corrupt_quarantine() {
        let (_dir, store) = make_store();
        let data = b"this blob will be corrupted".to_vec();
        let hash = store.write(&data).unwrap();

        // Corrupt the backing file, then read to trigger quarantine.
        std::fs::write(on_disk_path(&store, &hash), b"corrupted bytes").unwrap();
        let err = store.read(&hash).unwrap_err();
        assert!(matches!(err, BlobError::HashMismatch { .. }));
        let before = corrupt_dir_entries(&store);
        assert_eq!(before.len(), 1, "quarantine should hold one object");

        // GC with an empty live set must NOT touch the `.corrupt/` evidence.
        let _ = store.gc(&HashSet::new()).unwrap();

        let after = corrupt_dir_entries(&store);
        assert_eq!(after, before, "quarantine evidence must survive GC");
        assert!(
            store.root().join(".corrupt").is_dir(),
            ".corrupt directory must still exist after GC"
        );
    }

    #[test]
    fn gc_prunes_empty_shard_dirs() {
        let (_dir, store) = make_store();
        for i in 0..6 {
            store.write(format!("prune blob {i}").as_bytes()).unwrap();
        }
        assert!(shard_dir_count(&store) > 0, "expected shard dirs to exist");

        let report = store.gc(&HashSet::new()).unwrap();
        assert_eq!(report.reclaimed, 6);

        // All shard dirs should be pruned, but GC succeeds and root survives.
        assert_eq!(
            shard_dir_count(&store),
            0,
            "empty shard dirs should be pruned"
        );
        assert!(
            store.root().exists(),
            "store root must still exist after GC"
        );
    }

    #[test]
    fn gc_on_empty_store_is_noop() {
        let (_dir, store) = make_store();
        let report = store.gc(&HashSet::new()).unwrap();
        assert_eq!(report, GcReport::default());
    }

    #[test]
    fn gc_does_not_prune_shard_with_live_blob() {
        let (_dir, store) = make_store();
        let keep = store.write(b"survivor").unwrap();
        let drop = store.write(b"casualty").unwrap();

        let mut live = HashSet::new();
        live.insert(keep);
        let report = store.gc(&live).unwrap();
        assert_eq!(report.reclaimed, 1);

        // The surviving blob's shard dir must still hold it.
        assert!(store.exists(&keep).unwrap());
        assert_eq!(store.read(&keep).unwrap(), b"survivor");
        assert!(!store.exists(&drop).unwrap());
        // Its shard directory still exists.
        let keep_shard = on_disk_path(&store, &keep).parent().unwrap().to_path_buf();
        assert!(keep_shard.is_dir());
    }

    // -----------------------------------------------------------------------
    // Self-healing precondition tests
    // -----------------------------------------------------------------------

    #[test]
    fn write_dedup_skips_corrupt_blob_until_read_quarantines() {
        let (_dir, store) = make_store();

        // Write correct content; compute the hash it should live under.
        let correct = b"correct content";
        let hash = store.write(correct).unwrap();

        // Corrupt the on-disk file directly (simulating bit-rot).
        let blob_path = on_disk_path(&store, &hash);
        fs::write(&blob_path, b"corrupted!").unwrap();

        // A second write of the correct bytes dedup-skips: the corrupt file
        // stays trusted because write() only checks existence, not content.
        let hash2 = store.write(correct).unwrap();
        assert_eq!(hash, hash2);
        assert_eq!(fs::read(&blob_path).unwrap(), b"corrupted!");

        // read() detects the mismatch and quarantines the corrupt object.
        let err = store.read(&hash).unwrap_err();
        assert!(matches!(err, BlobError::HashMismatch { .. }));
        // After quarantine the path is freed, so write() now heals the store.
        let hash3 = store.write(correct).unwrap();
        assert_eq!(hash, hash3);
        assert_eq!(store.read(&hash).unwrap(), correct);
    }

    // -----------------------------------------------------------------------
    // Amortized directory-barrier tests
    // -----------------------------------------------------------------------

    /// Find `count` distinct payloads whose content addresses share one shard,
    /// so a test can drive many renames into a single directory.
    fn payloads_in_one_shard(count: usize) -> Vec<Vec<u8>> {
        let mut by_shard: std::collections::HashMap<String, Vec<Vec<u8>>> =
            std::collections::HashMap::new();
        for i in 0..1_000_000u32 {
            let payload = format!("shard-collision-{i}").into_bytes();
            let hex = digest(&payload).to_string();
            let bucket = by_shard.entry(hex[..2].to_string()).or_default();
            bucket.push(payload);
            if bucket.len() >= count {
                return std::mem::take(bucket);
            }
        }
        panic!("no shard accumulated {count} payloads within the search bound");
    }

    /// The mechanism under test: many renames into one shard leave exactly one
    /// directory barrier outstanding, not one per blob.
    #[test]
    fn renames_into_one_shard_leave_one_pending_barrier() {
        let (_dir, store) = make_store();
        let payloads = payloads_in_one_shard(16);
        for payload in &payloads {
            store.write(payload).unwrap();
        }

        let (shards, root, renames) = store.pending_snapshot();
        assert_eq!(renames, payloads.len(), "every write records a rename");
        assert_eq!(shards, 1, "16 renames into one shard owe one barrier");
        assert!(
            root,
            "the shard directory was created, so the root owes one"
        );

        // Draining clears the debt.
        store.sync().unwrap();
        assert_eq!(store.pending_snapshot(), (0, false, 0));
    }

    /// The root barrier is owed only when a write actually creates a shard
    /// directory, not on every write into an existing one.
    #[test]
    fn root_barrier_owed_only_when_a_shard_is_created() {
        let (_dir, store) = make_store();
        let payloads = payloads_in_one_shard(2);

        store.write(&payloads[0]).unwrap();
        assert!(store.pending_snapshot().1, "first write created the shard");
        store.sync().unwrap();

        store.write(&payloads[1]).unwrap();
        let (shards, root, renames) = store.pending_snapshot();
        assert_eq!((shards, renames), (1, 1));
        assert!(!root, "writing into an existing shard owes no root barrier");
    }

    /// A store's pending set can never exceed the 256 possible shards, however
    /// many blobs were written: that ceiling is the amortization.
    #[test]
    fn pending_barriers_are_bounded_by_the_shard_count() {
        let (_dir, store) = make_store();
        for i in 0..400 {
            store
                .write(format!("bounded barrier blob {i}").as_bytes())
                .unwrap();
        }
        let (shards, _, renames) = store.pending_snapshot();
        assert_eq!(renames, 400);
        assert!(
            shards <= 256 && shards < renames,
            "{shards} pending barriers for {renames} renames must be capped by the shard count"
        );
    }

    /// The auto-drain backstop trips exactly at the bound, so a caller that
    /// never syncs still cannot accumulate renames without limit.
    #[test]
    fn pending_state_drains_at_the_rename_bound() {
        let bound = PENDING_RENAME_DRAIN_THRESHOLD;
        let mut pending = PendingDirSyncs::default();
        for i in 1..bound {
            assert!(
                !pending.record("ab", false, bound),
                "rename {i} must not trip the drain"
            );
        }
        assert!(
            pending.record("ab", false, bound),
            "rename {bound} must trip the drain"
        );
        assert_eq!(pending.shards.len(), 1, "one shard, however many renames");
    }

    /// `write` must drain on its own at the bound. Exercised with a lowered
    /// threshold so the path, including releasing the pending lock before the
    /// drain reacquires it, is covered without writing thousands of blobs.
    #[test]
    fn write_drains_itself_at_the_rename_bound() {
        let dir = tempfile::tempdir().unwrap();
        let store = BlobStore::with_drain_threshold(dir.path().join("objects"), 4).unwrap();

        let mut written = Vec::new();
        for i in 0..3 {
            let data = format!("self-draining blob {i}").into_bytes();
            written.push((store.write(&data).unwrap(), data));
            assert_eq!(
                store.pending_snapshot().2,
                i + 1,
                "renames accumulate below the bound"
            );
        }

        // The 4th rename trips the drain inside `write` itself.
        let data = b"self-draining blob 3".to_vec();
        written.push((store.write(&data).unwrap(), data));
        assert_eq!(
            store.pending_snapshot(),
            (0, false, 0),
            "write must have drained at the bound"
        );

        // And it keeps draining, without losing anything, across many bounds.
        for i in 4..40 {
            let data = format!("self-draining blob {i}").into_bytes();
            written.push((store.write(&data).unwrap(), data));
        }
        assert!(
            store.pending_snapshot().2 < 4,
            "renames never exceed the bound"
        );
        for (hash, data) in &written {
            assert_eq!(&store.read(hash).unwrap(), data);
        }
    }

    #[test]
    fn sync_on_untouched_store_is_ok() {
        let (_dir, store) = make_store();
        store.sync().unwrap();
        assert_eq!(store.pending_snapshot(), (0, false, 0));
    }

    #[test]
    fn sync_is_idempotent() {
        let (_dir, store) = make_store();
        store.write(b"sync twice").unwrap();
        store.sync().unwrap();
        store.sync().unwrap();
        assert_eq!(store.pending_snapshot(), (0, false, 0));
    }

    /// GC compaction removes shard directories. A pending barrier for a
    /// directory that no longer exists has nothing to make durable and must not
    /// be reported as a failure.
    #[test]
    fn sync_after_gc_pruned_shards_is_ok() {
        let (_dir, store) = make_store();
        for i in 0..8 {
            store
                .write(format!("pruned shard blob {i}").as_bytes())
                .unwrap();
        }
        let report = store.gc(&HashSet::new()).unwrap();
        assert_eq!(report.reclaimed, 8);
        assert_eq!(shard_dir_count(&store), 0, "shards should be pruned");

        store.sync().unwrap();
        assert_eq!(store.pending_snapshot(), (0, false, 0));
    }

    /// A store whose root was removed underneath it must sync and drop cleanly:
    /// there is no directory left to barrier.
    #[test]
    fn sync_and_drop_after_root_removal_are_clean() {
        let dir = tempfile::tempdir().unwrap();
        let store = BlobStore::new(dir.path().join("objects")).unwrap();
        store.write(b"root goes away").unwrap();
        std::fs::remove_dir_all(store.root()).unwrap();

        store.sync().unwrap();
        assert_eq!(store.pending_snapshot(), (0, false, 0));
        drop(store); // must not panic
    }

    // -----------------------------------------------------------------------
    // Crash-semantics tests for the deferred directory barrier
    // -----------------------------------------------------------------------

    /// Deferring the directory barrier must not defer visibility: every blob
    /// written since the last sync reads back, hash-verified, with no sync.
    #[test]
    fn blobs_verify_before_any_sync() {
        let (_dir, store) = make_store();
        let mut written = Vec::new();
        for i in 0..64 {
            let data = format!("unsynced blob {i}").into_bytes();
            written.push((store.write(&data).unwrap(), data));
        }
        assert!(store.pending_snapshot().0 > 0, "barriers are still pending");
        for (hash, data) in &written {
            assert_eq!(&store.read(hash).unwrap(), data);
        }
    }

    /// The drop drain is the commit point for a caller that never syncs: a
    /// reopened store sees every blob, hash-verified.
    #[test]
    fn reopen_after_drop_sees_every_blob_without_explicit_sync() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("objects");
        let mut written = Vec::new();
        {
            let store = BlobStore::new(root.clone()).unwrap();
            for i in 0..32 {
                let data = format!("reopen blob {i}").into_bytes();
                written.push((store.write(&data).unwrap(), data));
            }
            assert!(store.pending_snapshot().0 > 0, "drop must do the draining");
        }

        let reopened = BlobStore::new(root).unwrap();
        for (hash, data) in &written {
            assert_eq!(&reopened.read(hash).unwrap(), data);
        }
        assert_eq!(reopened.list_hashes().unwrap().len(), written.len());
    }

    /// The crash state the deferred barrier admits: a blob whose bytes reached
    /// the device but whose name did not.
    ///
    /// Simulated by removing the directory entry after the write, then dropping
    /// and reopening the store. The blob must be **absent**, never
    /// present-but-corrupt, and re-writable byte for byte, which is exactly
    /// what dedup already treats as "not written yet".
    #[test]
    fn lost_directory_entry_is_absent_and_rewritable_with_identical_content() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("objects");
        let data = b"a name that never reached the device".to_vec();

        let hash = {
            let store = BlobStore::new(root.clone()).unwrap();
            let hash = store.write(&data).unwrap();
            // The rename is lost: the entry publishing the name never landed.
            std::fs::remove_file(on_disk_path(&store, &hash)).unwrap();
            hash
        };

        let reopened = BlobStore::new(root).unwrap();
        // Absent, and reported as absent: never silently missing while
        // enumeration or dedup claims it is there.
        assert!(!reopened.exists(&hash).unwrap());
        assert!(reopened.list_hashes().unwrap().is_empty());
        assert!(
            matches!(
                reopened.read(&hash).unwrap_err(),
                BlobError::NotFound { .. }
            ),
            "a lost name must read as absent, never as corrupt content"
        );
        // And re-writable to the identical address and bytes.
        assert_eq!(reopened.write(&data).unwrap(), hash);
        assert_eq!(reopened.read(&hash).unwrap(), data);
    }

    /// The content barrier still precedes the rename, so the dedup-corruption
    /// trap stays closed: whenever the name is present, the bytes behind it
    /// verify against it.
    #[test]
    fn a_present_name_always_verifies_against_its_content() {
        let (_dir, store) = make_store();
        let payloads = payloads_in_one_shard(12);
        for payload in &payloads {
            let hash = store.write(payload).unwrap();
            assert!(store.exists(&hash).unwrap());
            // No sync yet: the name is published, so the bytes must verify.
            assert_eq!(&store.read(&hash).unwrap(), payload);
        }
    }

    /// A lost shard directory loses everything beneath it exactly the way a
    /// lost rename loses one blob: absent, and re-writable.
    #[test]
    fn lost_shard_directory_is_absent_and_rewritable() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("objects");
        let payloads = payloads_in_one_shard(6);

        let hashes: Vec<Hash256> = {
            let store = BlobStore::new(root.clone()).unwrap();
            let hashes: Vec<Hash256> = payloads.iter().map(|p| store.write(p).unwrap()).collect();
            let shard_dir = on_disk_path(&store, &hashes[0])
                .parent()
                .unwrap()
                .to_path_buf();
            std::fs::remove_dir_all(&shard_dir).unwrap();
            hashes
        };

        let reopened = BlobStore::new(root).unwrap();
        assert!(reopened.list_hashes().unwrap().is_empty());
        for hash in &hashes {
            assert!(matches!(
                reopened.read(hash).unwrap_err(),
                BlobError::NotFound { .. }
            ));
        }
        for (payload, hash) in payloads.iter().zip(&hashes) {
            assert_eq!(&reopened.write(payload).unwrap(), hash);
            assert_eq!(&reopened.read(hash).unwrap(), payload);
        }
    }

    #[test]
    fn gc_live_set_covers_all_written_blobs() {
        let (_dir, store) = make_store();

        let hashes: Vec<Hash256> = [b"alpha" as &[u8], b"beta", b"gamma"]
            .iter()
            .map(|d| store.write(d).unwrap())
            .collect();

        // A correct live-set containing every written blob must retain all of them.
        let live: std::collections::HashSet<Hash256> = hashes.iter().copied().collect();
        let report = store.gc(&live).unwrap();
        assert_eq!(
            report.reclaimed, 0,
            "complete live set must retain every blob"
        );
        for h in &hashes {
            assert!(store.exists(h).unwrap(), "blob {h} must survive GC");
        }

        // A live-set that omits one blob must reclaim exactly that one.
        let mut partial = live.clone();
        partial.remove(&hashes[1]);
        let report2 = store.gc(&partial).unwrap();
        assert_eq!(report2.reclaimed, 1);
        assert!(!store.exists(&hashes[1]).unwrap());
        assert!(store.exists(&hashes[0]).unwrap());
        assert!(store.exists(&hashes[2]).unwrap());
    }
}
