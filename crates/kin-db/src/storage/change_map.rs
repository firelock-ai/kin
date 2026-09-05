// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The repository change map, decoded from its snapshot on first use.
//!
//! A converted repository's snapshot IS its history: on psf/requests at 6733
//! commits the `changes` map is 93.8 percent of a 1051.5 MiB body, and on the
//! kin repository's own store it is 94.8 percent of 3326 MiB, while the
//! entities and relations a daemon serves are zero bytes of either file. An
//! open that decodes the whole body therefore retains about 2.7x the file for
//! a map that the served graph reads by reference and a commit reads once.
//!
//! [`ChangeMap`] is the map's type in [`GraphSnapshot`](super::format::GraphSnapshot).
//! It dereferences to the `HashMap` every reader already expects, so a read
//! site compiles untouched and pays the decode the first time it is reached,
//! and never before. An open that leaves the map encoded holds the snapshot
//! file it came from and the byte range the map occupies in it; the first
//! history read re-reads that frame, proves it is the frame the open verified
//! by comparing the body checksum it carried then, and decodes the one
//! element. Nothing about the on-disk format moves: a MessagePack positional
//! array is self-delimiting, so one element of a body decodes exactly as it
//! decodes inside the whole.

use std::collections::HashMap;
use std::fmt;
use std::fs::File;
use std::ops::{Deref, DerefMut, Range};
use std::sync::{Arc, OnceLock};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use crate::error::KinDbError;
use crate::types::{SemanticChange, SemanticChangeId};

/// The decoded shape of the map, which is what every reader sees.
pub type ChangeMapInner = HashMap<SemanticChangeId, SemanticChange>;

#[cfg(test)]
thread_local! {
    static CHANGE_MAPS_DECODED_ON_THIS_THREAD: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

/// How many change maps this thread decoded from an encoded source.
///
/// This is the instrument behind "an open does not decode the change map":
/// a test that opens a store and then reads the counter can tell a lazy open
/// from an eager one directly, rather than inferring it from a duration or a
/// resident set. Counted at the one place a decode happens, so an eager path
/// re-enabled anywhere upstream is visible here. Per thread, because the test
/// suite runs in parallel and a decode on another thread is another test's.
#[cfg(test)]
pub(crate) fn change_maps_decoded_on_this_thread() -> usize {
    CHANGE_MAPS_DECODED_ON_THIS_THREAD.with(|count| count.get())
}

#[cfg(test)]
thread_local! {
    static LEAF_DIGESTS_COMPUTED_ON_THIS_THREAD: std::cell::Cell<usize> =
        const { std::cell::Cell::new(0) };
}

/// How many history-root leaf digests this thread computed from a change,
/// rather than reading from the memo.
///
/// This is the instrument behind "a fold hashes only the changes it has not
/// seen". It counts ONLY the compute branch: the verification recompute that
/// `cfg(test)` runs on every memo HIT deliberately does not increment it, or
/// the safety check would hide the saving it exists to protect. Per thread,
/// because the suite runs in parallel.
#[cfg(test)]
pub(crate) fn leaf_digests_computed_on_this_thread() -> usize {
    LEAF_DIGESTS_COMPUTED_ON_THIS_THREAD.with(|count| count.get())
}

/// Where an undecoded change map's frame can be read again.
pub(crate) enum HistorySource {
    /// The snapshot file the open read, held open so a superseded generation
    /// stays readable after the backend retires its name. Positional reads
    /// only, so clones of one snapshot share the handle without a seek race.
    File {
        file: Arc<File>,
        display: String,
        frame_len: u64,
    },
    /// The whole frame, held in memory, which is what the format tests decode
    /// against. No backend constructs it: one with no file to hand back
    /// decodes eagerly rather than keeping a gigabyte to avoid decoding it.
    #[cfg(test)]
    Memory(Arc<[u8]>),
}

impl fmt::Debug for HistorySource {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::File {
                display, frame_len, ..
            } => formatter
                .debug_struct("File")
                .field("display", display)
                .field("frame_len", frame_len)
                .finish(),
            #[cfg(test)]
            Self::Memory(frame) => formatter
                .debug_struct("Memory")
                .field("frame_len", &frame.len())
                .finish(),
        }
    }
}

impl HistorySource {
    fn describe(&self) -> String {
        match self {
            Self::File { display, .. } => display.clone(),
            #[cfg(test)]
            Self::Memory(frame) => format!("{} in-memory frame bytes", frame.len()),
        }
    }

    /// The frame as it stands now. Whether it is still the frame the open
    /// verified is decided by the caller against the recorded body checksum.
    fn read_frame(&self) -> Result<FrameBytes<'_>, KinDbError> {
        match self {
            Self::File {
                file,
                display,
                frame_len,
            } => {
                let len = usize::try_from(*frame_len).map_err(|_| {
                    KinDbError::StorageError(format!(
                        "snapshot {display} frame length {frame_len} does not fit in memory"
                    ))
                })?;
                let mut bytes = vec![0u8; len];
                read_exact_from_start(file, &mut bytes).map_err(|error| {
                    KinDbError::StorageError(format!(
                        "failed to re-read snapshot {display} for its change map: {error}"
                    ))
                })?;
                Ok(FrameBytes::Owned(bytes))
            }
            #[cfg(test)]
            Self::Memory(frame) => Ok(FrameBytes::Borrowed(frame)),
        }
    }
}

enum FrameBytes<'a> {
    Owned(Vec<u8>),
    /// Only an in-memory source borrows, and only tests build one.
    #[cfg_attr(not(test), allow(dead_code))]
    Borrowed(&'a [u8]),
}

impl AsRef<[u8]> for FrameBytes<'_> {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Owned(bytes) => bytes,
            Self::Borrowed(bytes) => bytes,
        }
    }
}

#[cfg(unix)]
fn read_exact_from_start(file: &File, buffer: &mut [u8]) -> std::io::Result<()> {
    use std::os::unix::fs::FileExt;
    file.read_exact_at(buffer, 0)
}

#[cfg(windows)]
fn read_exact_from_start(file: &File, buffer: &mut [u8]) -> std::io::Result<()> {
    use std::os::windows::fs::FileExt;
    let mut filled = 0usize;
    while filled < buffer.len() {
        let read = file.seek_read(&mut buffer[filled..], filled as u64)?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "snapshot file ended before its recorded frame length",
            ));
        }
        filled += read;
    }
    Ok(())
}

/// A change map that is still bytes on disk.
#[derive(Debug)]
pub(crate) struct EncodedChanges {
    source: HistorySource,
    /// The map element's byte range within the frame BODY, not the file.
    range: Range<usize>,
    /// The element count the map header declared, so `len` needs no decode.
    len: usize,
    /// The body checksum the frame carried when the open verified it. A re-read
    /// that does not carry the same checksum is not the snapshot that was
    /// opened and is refused rather than decoded.
    body_checksum: [u8; 32],
}

impl EncodedChanges {
    pub(crate) fn new(
        source: HistorySource,
        range: Range<usize>,
        len: usize,
        body_checksum: [u8; 32],
    ) -> Self {
        Self {
            source,
            range,
            len,
            body_checksum,
        }
    }

    fn decode(&self) -> Result<ChangeMapInner, KinDbError> {
        let _span = tracing::info_span!("kindb.snapshot.decode_change_map_on_first_use").entered();
        let frame = self.source.read_frame()?;
        let decoded = super::format::decode_change_map_element(
            frame.as_ref(),
            self.body_checksum,
            self.range.clone(),
            self.len,
        )
        .map_err(|error| {
            KinDbError::StorageError(format!(
                "change map of snapshot {} could not be decoded on first use: {error}",
                self.source.describe()
            ))
        })?;
        #[cfg(test)]
        CHANGE_MAPS_DECODED_ON_THIS_THREAD.with(|count| count.set(count.get() + 1));
        tracing::debug!(
            source = %self.source.describe(),
            changes = decoded.len(),
            encoded_bytes = self.range.len(),
            "decoded a change map on first use"
        );
        Ok(decoded)
    }
}

/// The repository's change map, decoded on first use.
///
/// Every read goes through [`Deref`], so the type is invisible at a read
/// site. The decode is fallible in principle, because it re-reads a file, and
/// `Deref` cannot say so; an open proves the file readable and its frame
/// intact before it hands out an encoded map, so what remains is a file that
/// changed or vanished underneath a running process, and that fails loud with
/// the snapshot named rather than serving an empty history. Callers that can
/// carry an error use [`ChangeMap::decoded`] instead.
pub struct ChangeMap {
    /// Clones share both first-use decoding and its result. Mutable access
    /// detaches the entries before handing them to the caller.
    body: Arc<ChangeMapBody>,
    /// Memoized history-root leaf digests, keyed by change identity.
    ///
    /// `history_root` folds this map through `canonical_leaf_hash`, which
    /// serializes each leaf's canonical payload in full. The map is ONE leaf
    /// per change, and on a converted Linux subtree a single change's leaf is
    /// 410,546,852 bytes, so a commit re-serialized the entire history to
    /// arrive at a 32-byte value for changes that had not moved.
    ///
    /// Sound on two facts, both of which are stated here because the memo is a
    /// persisted authority root and a stale entry would be a repository that
    /// no longer recognizes its own history:
    ///
    /// 1. **A change's identity determines its content.** `SemanticChangeId`
    ///    is a content hash, `admit_changes` refuses an id already present with
    ///    different content, and `AuthorityFrame::apply` refuses a frame that
    ///    re-adds an id the base holds. So a digest filed under an id can never
    ///    describe different bytes than the change now under that id.
    /// 2. **Production never mutates a change in place.** Searched with a
    ///    positive control over 295 `.changes` sites: the only production
    ///    writes are `insert`, at `repository.rs` in `admit_changes` and at
    ///    `authority_frame.rs` in `apply`. No `get_mut`, `iter_mut`,
    ///    `values_mut`, `entry` or `retain` on the map exists outside tests.
    ///
    /// Fact 2 is an invariant of code rather than of types, so it is checked
    /// rather than trusted: under `cfg(test)` every memo HIT is recomputed and
    /// compared, so any future in-place mutation fails the first test that
    /// folds a root rather than shipping a wrong one.
    ///
    /// Shared across clones on purpose. A successor is a clone of its base, so
    /// a per-clone memo would be empty at every commit and would never save
    /// anything. An entry for a change a given clone does not hold is never
    /// read, because the fold walks the map and looks each entry up.
    leaf_digests: Arc<Mutex<LeafDigestMemo>>,
}

/// One immutable history shared by every snapshot cloned from it.
struct ChangeMapBody {
    decoded: OnceLock<ChangeMapInner>,
    encoded: Option<EncodedChanges>,
    /// First uses across all clones take this gate before decoding, so they
    /// never allocate competing copies of the same history.
    decode_gate: Mutex<()>,
}

impl From<ChangeMapInner> for ChangeMapBody {
    fn from(inner: ChangeMapInner) -> Self {
        Self {
            decoded: OnceLock::from(inner),
            encoded: None,
            decode_gate: Mutex::new(()),
        }
    }
}

/// Memoized leaf digests and the domain they were computed under.
///
/// The domain is part of the hash (`canonical_leaf_hash` writes it before the
/// value), so a second domain folding this same map must not read digests
/// computed for the first. Recorded and compared rather than assumed, because
/// today there is exactly one such domain and a future second one would
/// otherwise silently reuse the wrong bytes.
#[derive(Default)]
pub(crate) struct LeafDigestMemo {
    domain: Option<&'static str>,
    digests: HashMap<SemanticChangeId, [u8; 32]>,
}

impl ChangeMap {
    /// An empty, decoded map.
    pub fn new() -> Self {
        Self::from(ChangeMapInner::new())
    }

    /// A map that stays on disk until a reader asks for an entry.
    pub(crate) fn encoded(encoded: EncodedChanges) -> Self {
        Self {
            body: Arc::new(ChangeMapBody {
                decoded: OnceLock::new(),
                encoded: Some(encoded),
                decode_gate: Mutex::new(()),
            }),
            leaf_digests: Arc::default(),
        }
    }

    /// Whether the entries are in memory.
    ///
    /// `false` is the state an open leaves a converted store's history in, and
    /// the state the served graph never has to leave.
    pub fn is_decoded(&self) -> bool {
        self.body.decoded.get().is_some()
    }

    /// The entries if they are already in memory, and `None` if they are
    /// still on disk.
    ///
    /// [`Deref`] is the ordinary way to reach the entries and it decodes them;
    /// this is for the one caller that has to compare map identity without
    /// paying the decode the comparison exists to avoid.
    pub(crate) fn decoded_if_present(&self) -> Option<&ChangeMapInner> {
        self.body.decoded.get()
    }

    /// Number of changes, read from the map header when the map is encoded.
    pub fn len(&self) -> usize {
        match (self.body.decoded.get(), &self.body.encoded) {
            (Some(decoded), _) => decoded.len(),
            (None, Some(encoded)) => encoded.len,
            (None, None) => 0,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The entries, decoding them first if they are still on disk.
    pub fn decoded(&self) -> Result<&ChangeMapInner, KinDbError> {
        if let Some(decoded) = self.body.decoded.get() {
            return Ok(decoded);
        }
        let _gate = self.body.decode_gate.lock();
        if let Some(decoded) = self.body.decoded.get() {
            return Ok(decoded);
        }
        let decoded = match &self.body.encoded {
            Some(encoded) => encoded.decode()?,
            None => ChangeMapInner::new(),
        };
        // The gate is held, so nobody else set it in between; a losing `set`
        // would mean a second decoder ran anyway, which the gate exists to
        // prevent, and dropping the loser keeps the map a reader already
        // borrowed.
        let _ = self.body.decoded.set(decoded);
        Ok(self
            .body
            .decoded
            .get()
            .expect("the change map was set under the decode gate"))
    }

    /// This map's history-root leaf digests, sorted, computing only the ones
    /// not already memoized.
    ///
    /// `DomainRoot::unordered` sorts its leaf digests before folding them, so
    /// the fold is a pure function of the digest MULTISET and cannot observe
    /// which of them were computed and which were remembered. That is what
    /// makes this byte-identical to folding from scratch rather than merely
    /// close to it.
    ///
    /// `domain` is compared against the domain the memo was built under and a
    /// mismatch clears it, because the domain is part of every digest.
    pub(crate) fn sorted_leaf_digests<E>(
        &self,
        domain: &'static str,
        compute: impl Fn(&SemanticChangeId, &SemanticChange) -> Result<[u8; 32], E>,
    ) -> Result<Vec<[u8; 32]>, E> {
        let entries = self.force();
        let mut memo = self.leaf_digests.lock();
        if memo.domain != Some(domain) {
            memo.domain = Some(domain);
            memo.digests.clear();
        }
        let mut digests = Vec::with_capacity(entries.len());
        for (id, change) in entries {
            match memo.digests.get(id) {
                Some(remembered) => {
                    // Fact 2 on the field is an invariant of code, so it is
                    // checked here rather than trusted. A change mutated in
                    // place would make this fire on the first test that folds
                    // a root, instead of shipping a wrong authority root.
                    #[cfg(test)]
                    {
                        let recomputed = compute(id, change)?;
                        assert_eq!(
                            recomputed, *remembered,
                            "a memoized history leaf digest no longer describes the change under \
                             its id; a change was mutated in place"
                        );
                    }
                    digests.push(*remembered);
                }
                None => {
                    let digest = compute(id, change)?;
                    #[cfg(test)]
                    LEAF_DIGESTS_COMPUTED_ON_THIS_THREAD.with(|count| count.set(count.get() + 1));
                    memo.digests.insert(*id, digest);
                    digests.push(digest);
                }
            }
        }
        digests.sort_unstable();
        Ok(digests)
    }

    fn force(&self) -> &ChangeMapInner {
        match self.decoded() {
            Ok(decoded) => decoded,
            Err(error) => panic!("{error}"),
        }
    }

    /// Take the entries out, decoding them first if needed. A unique map
    /// moves its allocation; a map another snapshot still shares is copied.
    pub fn into_inner(self) -> ChangeMapInner {
        self.force();
        match Arc::try_unwrap(self.body) {
            Ok(body) => body
                .decoded
                .into_inner()
                .expect("the change map was decoded on the line above"),
            Err(body) => body
                .decoded
                .get()
                .expect("the change map was decoded on the line above")
                .clone(),
        }
    }
}

impl Default for ChangeMap {
    fn default() -> Self {
        Self::new()
    }
}

impl From<ChangeMapInner> for ChangeMap {
    fn from(inner: ChangeMapInner) -> Self {
        Self {
            body: Arc::new(ChangeMapBody::from(inner)),
            leaf_digests: Arc::default(),
        }
    }
}

impl From<ChangeMap> for ChangeMapInner {
    fn from(map: ChangeMap) -> Self {
        map.into_inner()
    }
}

impl FromIterator<(SemanticChangeId, SemanticChange)> for ChangeMap {
    fn from_iter<I: IntoIterator<Item = (SemanticChangeId, SemanticChange)>>(iter: I) -> Self {
        Self::from(iter.into_iter().collect::<ChangeMapInner>())
    }
}

impl Extend<(SemanticChangeId, SemanticChange)> for ChangeMap {
    fn extend<I: IntoIterator<Item = (SemanticChangeId, SemanticChange)>>(&mut self, iter: I) {
        self.deref_mut().extend(iter);
    }
}

impl Deref for ChangeMap {
    type Target = ChangeMapInner;

    fn deref(&self) -> &Self::Target {
        self.force()
    }
}

impl DerefMut for ChangeMap {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.force();
        if Arc::get_mut(&mut self.body).is_none() {
            self.body = Arc::new(ChangeMapBody::from(self.force().clone()));
        }
        let body = Arc::get_mut(&mut self.body)
            .expect("mutable access detached the shared change map on the lines above");
        body.encoded = None;
        body.decoded
            .get_mut()
            .expect("the change map was decoded on the line above")
    }
}

impl Clone for ChangeMap {
    /// Share the history before or after first decode. Only mutable access
    /// needs a separate copy of the entries.
    fn clone(&self) -> Self {
        Self {
            body: Arc::clone(&self.body),
            leaf_digests: Arc::clone(&self.leaf_digests),
        }
    }
}

impl fmt::Debug for ChangeMap {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.body.decoded.get() {
            Some(decoded) => decoded.fmt(formatter),
            None => formatter
                .debug_struct("ChangeMap")
                .field("len", &self.len())
                .field("decoded", &false)
                .field("encoded", &self.body.encoded)
                .finish(),
        }
    }
}

impl PartialEq for ChangeMap {
    fn eq(&self, other: &Self) -> bool {
        self.force() == other.force()
    }
}

impl PartialEq<ChangeMapInner> for ChangeMap {
    fn eq(&self, other: &ChangeMapInner) -> bool {
        self.force() == other
    }
}

impl PartialEq<ChangeMap> for ChangeMapInner {
    fn eq(&self, other: &ChangeMap) -> bool {
        self == other.force()
    }
}

impl IntoIterator for ChangeMap {
    type Item = (SemanticChangeId, SemanticChange);
    type IntoIter = std::collections::hash_map::IntoIter<SemanticChangeId, SemanticChange>;

    fn into_iter(self) -> Self::IntoIter {
        self.into_inner().into_iter()
    }
}

impl<'a> IntoIterator for &'a ChangeMap {
    type Item = (&'a SemanticChangeId, &'a SemanticChange);
    type IntoIter = std::collections::hash_map::Iter<'a, SemanticChangeId, SemanticChange>;

    fn into_iter(self) -> Self::IntoIter {
        self.force().iter()
    }
}

impl<'a> IntoIterator for &'a mut ChangeMap {
    type Item = (&'a SemanticChangeId, &'a mut SemanticChange);
    type IntoIter = std::collections::hash_map::IterMut<'a, SemanticChangeId, SemanticChange>;

    fn into_iter(self) -> Self::IntoIter {
        self.deref_mut().iter_mut()
    }
}

impl Serialize for ChangeMap {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.force().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ChangeMap {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        ChangeMapInner::deserialize(deserializer).map(Self::from)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_decoded_map_reads_like_the_map_it_wraps() {
        let map = ChangeMap::new();
        assert!(map.is_decoded());
        assert!(map.is_empty());
        assert_eq!(map.len(), 0);
        assert_eq!(map.iter().count(), 0);
        let cloned = map.clone();
        assert!(cloned.is_decoded());
        assert_eq!(map, cloned);
    }
}
