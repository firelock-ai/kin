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
    decoded: OnceLock<ChangeMapInner>,
    encoded: Option<Arc<EncodedChanges>>,
    /// Serializes concurrent first uses so two readers do not both decode a
    /// gigabyte to keep one.
    decode_gate: Mutex<()>,
}

impl ChangeMap {
    /// An empty, decoded map.
    pub fn new() -> Self {
        Self::from(ChangeMapInner::new())
    }

    /// A map that stays on disk until a reader asks for an entry.
    pub(crate) fn encoded(encoded: EncodedChanges) -> Self {
        Self {
            decoded: OnceLock::new(),
            encoded: Some(Arc::new(encoded)),
            decode_gate: Mutex::new(()),
        }
    }

    /// Whether the entries are in memory.
    ///
    /// `false` is the state an open leaves a converted store's history in, and
    /// the state the served graph never has to leave.
    pub fn is_decoded(&self) -> bool {
        self.decoded.get().is_some()
    }

    /// Number of changes, read from the map header when the map is encoded.
    pub fn len(&self) -> usize {
        match (self.decoded.get(), &self.encoded) {
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
        if let Some(decoded) = self.decoded.get() {
            return Ok(decoded);
        }
        let _gate = self.decode_gate.lock();
        if let Some(decoded) = self.decoded.get() {
            return Ok(decoded);
        }
        let decoded = match &self.encoded {
            Some(encoded) => encoded.decode()?,
            None => ChangeMapInner::new(),
        };
        // The gate is held, so nobody else set it in between; a losing `set`
        // would mean a second decoder ran anyway, which the gate exists to
        // prevent, and dropping the loser keeps the map a reader already
        // borrowed.
        let _ = self.decoded.set(decoded);
        Ok(self
            .decoded
            .get()
            .expect("the change map was set under the decode gate"))
    }

    fn force(&self) -> &ChangeMapInner {
        match self.decoded() {
            Ok(decoded) => decoded,
            Err(error) => panic!("{error}"),
        }
    }

    /// Take the entries out, decoding them first if needed.
    pub fn into_inner(self) -> ChangeMapInner {
        self.force();
        self.decoded
            .into_inner()
            .expect("the change map was decoded on the line above")
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
            decoded: OnceLock::from(inner),
            encoded: None,
            decode_gate: Mutex::new(()),
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
        self.decoded
            .get_mut()
            .expect("the change map was decoded on the line above")
    }
}

impl Clone for ChangeMap {
    /// A decoded map clones its entries, exactly as the plain map did. An
    /// encoded map shares its source, so a workspace base cloned from a
    /// converted store's authority costs a pointer rather than a history.
    fn clone(&self) -> Self {
        match (self.decoded.get(), &self.encoded) {
            (Some(decoded), _) => Self::from(decoded.clone()),
            (None, Some(encoded)) => Self {
                decoded: OnceLock::new(),
                encoded: Some(Arc::clone(encoded)),
                decode_gate: Mutex::new(()),
            },
            (None, None) => Self::new(),
        }
    }
}

impl fmt::Debug for ChangeMap {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.decoded.get() {
            Some(decoded) => decoded.fmt(formatter),
            None => formatter
                .debug_struct("ChangeMap")
                .field("len", &self.len())
                .field("decoded", &false)
                .field("encoded", &self.encoded)
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
