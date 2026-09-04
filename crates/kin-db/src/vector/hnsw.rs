// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Vector index wrapper — delegates to kin-vector with EntityId convenience
//! APIs at the boundary while storing `RetrievalKey` natively.

use std::fs::{File, OpenOptions};
use std::io::{Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::embed::{EmbeddingProducer, EmbeddingProducerSet, VectorProducerProvenance};
use crate::error::KinDbError;
use crate::search::{resolve_roles, ScoredHit};
use crate::types::EntityId;
use kin_model::{EntityRole, RetrievalKey};
use kin_vector::IndexDescriptor;
use parking_lot::RwLock;
use sha2::{Digest, Sha256};

const PRODUCER_TRAILER_VERSION: u32 = 1;
const PRODUCER_TRAILER_START_MAGIC: [u8; 8] = *b"KINPRD01";
const PRODUCER_TRAILER_END_MAGIC: [u8; 8] = *b"KINPRE01";
const PRODUCER_TRAILER_DOMAIN: &[u8] = b"kindb-kvec-producer-trailer-v1\0";
const PRODUCER_TRAILER_FIXED_UNSIGNED_BYTES: usize = 8 + 4 + 8 + 1;
const MAX_PRODUCER_COUNT: usize = 5;
const MAX_PRODUCER_TRAILER_BYTES: usize =
    PRODUCER_TRAILER_FIXED_UNSIGNED_BYTES + MAX_PRODUCER_COUNT;
const KVEC_V2_MAGIC: [u8; 4] = *b"KVEC";
const KVEC_V1_VERSION: u8 = 1;
const KVEC_V2_VERSION: u32 = 2;
const KVEC_V3_VERSION: u32 = 3;
/// Oldest magic-prefixed container version this producer binding reads. Version
/// 1 predates the magic and is detected by its absence.
const KVEC_MIN_READABLE_VERSION: u32 = KVEC_V2_VERSION;
/// Newest container version this producer binding reads. A file above it is
/// refused by name rather than misread.
const KVEC_MAX_READABLE_VERSION: u32 = KVEC_V3_VERSION;
/// Preamble length, shared by every magic-prefixed version. kin-vector defines
/// its v3 constant as its v2 one for the same reason: the fixed fields this
/// code reads did not move.
const KVEC_PREAMBLE_LEN: usize = 64;
const STREAM_BUFFER_BYTES: usize = 64 * 1024;
/// Legacy classification is compatibility-only: an attributable index must use
/// the current streamed v2+trailer format. Bound the exact v1 schema decode so
/// inspecting an old or adversarial file cannot recreate the full-index
/// allocation class this sidecar contract removes. Larger v1 indexes fail
/// closed and are rebuilt from graph truth locally.
const MAX_LEGACY_PROVENANCE_DECODE_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug)]
struct ParsedProducerTrailer {
    base_len: u64,
    producers: EmbeddingProducerSet,
    unsigned: Vec<u8>,
    digest: [u8; 32],
}

fn producer_tag(producer: EmbeddingProducer) -> u8 {
    match producer {
        EmbeddingProducer::Cpu => 1,
        EmbeddingProducer::Metal => 2,
        EmbeddingProducer::Cuda => 3,
        EmbeddingProducer::Remote => 4,
        EmbeddingProducer::Unspecified => 255,
    }
}

fn producer_from_tag(tag: u8) -> Option<EmbeddingProducer> {
    match tag {
        1 => Some(EmbeddingProducer::Cpu),
        2 => Some(EmbeddingProducer::Metal),
        3 => Some(EmbeddingProducer::Cuda),
        4 => Some(EmbeddingProducer::Remote),
        255 => Some(EmbeddingProducer::Unspecified),
        _ => None,
    }
}

fn encode_unsigned_producer_trailer(
    base_len: u64,
    producers: &EmbeddingProducerSet,
) -> Result<Vec<u8>, KinDbError> {
    if producers.len() > MAX_PRODUCER_COUNT {
        return Err(KinDbError::StorageError(format!(
            "vector producer set has {} entries, exceeding the supported maximum {MAX_PRODUCER_COUNT}",
            producers.len()
        )));
    }
    let mut unsigned = Vec::with_capacity(PRODUCER_TRAILER_FIXED_UNSIGNED_BYTES + producers.len());
    unsigned.extend_from_slice(&PRODUCER_TRAILER_START_MAGIC);
    unsigned.extend_from_slice(&PRODUCER_TRAILER_VERSION.to_le_bytes());
    unsigned.extend_from_slice(&base_len.to_le_bytes());
    unsigned.push(producers.len() as u8);
    unsigned.extend(producers.iter().map(producer_tag));
    Ok(unsigned)
}

fn producer_binding_hasher() -> Sha256 {
    let mut hasher = Sha256::new();
    hasher.update(PRODUCER_TRAILER_DOMAIN);
    hasher
}

fn producer_binding_digest(base_index: &[u8], unsigned: &[u8]) -> [u8; 32] {
    let mut hasher = producer_binding_hasher();
    hasher.update(base_index);
    hasher.update(unsigned);
    hasher.finalize().into()
}

fn read_u64_le(bytes: &[u8], offset: usize) -> Result<u64, KinDbError> {
    let end = offset.checked_add(8).ok_or_else(|| {
        KinDbError::StorageError("kvec producer extent offset overflow".to_string())
    })?;
    let slice = bytes.get(offset..end).ok_or_else(|| {
        KinDbError::StorageError("kvec producer extent preamble is truncated".to_string())
    })?;
    let mut value = [0u8; 8];
    value.copy_from_slice(slice);
    Ok(u64::from_le_bytes(value))
}

/// Where a container version puts its fp32 payload relative to the rest of the
/// file.
///
/// This is the only reason the producer binding reads the container version at
/// all. KinDB appends its trailer directly after kin-vector's bytes, so it has
/// to know where those bytes end, and the fixed preamble is the only thing it
/// reads to find out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KvecPayloadPlacement {
    /// Version 2: the payload block is the last thing in the container, so the
    /// preamble locates the container's end exactly.
    LastInContainer,
    /// Version 3: the payload is the FIRST entry in a table of sections, and a
    /// container whose squared-norm table is whole carries a second section
    /// after it, aligned up from the payload's end. That table lives inside the
    /// MessagePack header, which this crate deliberately does not decode, so the
    /// preamble locates only a floor.
    FirstOfSections,
}

/// Classify a container version, or refuse it by name.
///
/// The accepted range and the exactness split are ONE decision here rather than
/// two, so no version can be admitted without somebody deciding what its
/// preamble proves. The const block below refuses to compile if the range ever
/// admits a version this function does not classify.
///
/// Verified against kin-vector's own encoders rather than taken from its prose.
/// `encode_v2` writes `payload_offset + slots * dimensions * 4` bytes and stops.
/// `encode_v3`, at kin-vector `f772f2cbdc847688bd27bad921c94a2320196d0d`, sizes
/// its output as the maximum end over its section table, and writes a `SqNorms`
/// section after `PayloadF32` whenever the norm table is whole. Both write the
/// same six fields into the first 40 bytes of the preamble, which is what lets
/// the reads below stay shared.
const fn kvec_payload_placement(version: u32) -> Option<KvecPayloadPlacement> {
    match version {
        KVEC_V2_VERSION => Some(KvecPayloadPlacement::LastInContainer),
        KVEC_V3_VERSION => Some(KvecPayloadPlacement::FirstOfSections),
        _ => None,
    }
}

const _: () = {
    let mut version = KVEC_MIN_READABLE_VERSION;
    while version <= KVEC_MAX_READABLE_VERSION {
        assert!(
            kvec_payload_placement(version).is_some(),
            "every kvec container version inside the readable range must declare whether its \
             preamble locates the container's end exactly or only a floor"
        );
        version += 1;
    }
};

/// What a kin-vector container's fixed preamble proves about where it ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KvecBaseExtent {
    /// The container ends exactly here.
    Exact(u64),
    /// The container ends at or after here.
    AtLeast(u64),
}

impl KvecBaseExtent {
    /// The smallest container end this preamble allows.
    fn floor(self) -> u64 {
        match self {
            Self::Exact(end) | Self::AtLeast(end) => end,
        }
    }
}

/// Read what a kin-vector container's fixed preamble proves about its extent.
fn kvec_base_extent_from_preamble(preamble: &[u8]) -> Result<Option<KvecBaseExtent>, KinDbError> {
    if !preamble.starts_with(&KVEC_V2_MAGIC) {
        return Ok(None);
    }
    if preamble.len() < KVEC_PREAMBLE_LEN {
        return Err(KinDbError::StorageError(
            "kvec preamble is truncated".to_string(),
        ));
    }
    let mut version = [0u8; 4];
    version.copy_from_slice(&preamble[4..8]);
    let version = u32::from_le_bytes(version);
    let placement = kvec_payload_placement(version).ok_or_else(|| {
        KinDbError::StorageError(format!(
            "unsupported kvec container version {version} for producer binding, which reads \
             {KVEC_MIN_READABLE_VERSION} through {KVEC_MAX_READABLE_VERSION}"
        ))
    })?;
    let header_len = read_u64_le(preamble, 8)?;
    let payload_offset = read_u64_le(preamble, 16)?;
    let slots = read_u64_le(preamble, 24)?;
    let dimensions = read_u64_le(preamble, 32)?;
    let header_end = (KVEC_PREAMBLE_LEN as u64)
        .checked_add(header_len)
        .ok_or_else(|| KinDbError::StorageError("kvec header extent overflows".to_string()))?;
    if payload_offset < header_end {
        return Err(KinDbError::StorageError(
            "kvec payload begins before the header ends".to_string(),
        ));
    }
    let payload_len = slots
        .checked_mul(dimensions)
        .and_then(|values| values.checked_mul(std::mem::size_of::<f32>() as u64))
        .ok_or_else(|| KinDbError::StorageError("kvec payload size overflows".to_string()))?;
    let payload_end = payload_offset
        .checked_add(payload_len)
        .ok_or_else(|| KinDbError::StorageError("kvec payload extent overflows".to_string()))?;
    Ok(Some(match placement {
        KvecPayloadPlacement::LastInContainer => KvecBaseExtent::Exact(payload_end),
        KvecPayloadPlacement::FirstOfSections => KvecBaseExtent::AtLeast(payload_end),
    }))
}

/// Read what complete `.kvec` bytes prove about the kin-vector container in
/// them, before KinDB's trailer.
fn kvec_base_extent(bytes: &[u8]) -> Result<Option<KvecBaseExtent>, KinDbError> {
    if !bytes.starts_with(&KVEC_V2_MAGIC) {
        return Ok(None);
    }
    let extent = kvec_base_extent_from_preamble(bytes)?.expect("kvec magic was checked");
    let floor = usize::try_from(extent.floor()).map_err(|_| {
        KinDbError::StorageError("kvec payload extent does not fit usize".to_string())
    })?;
    if floor > bytes.len() {
        return Err(KinDbError::StorageError(
            "kvec payload extends beyond available bytes".to_string(),
        ));
    }
    Ok(Some(extent))
}

/// Decide whether an artifact carries a producer trailer at all.
///
/// A v2 preamble settles it alone: the container either fills the artifact or
/// something was appended to it. A v3 preamble cannot, because the container
/// runs past its payload by a section table this crate does not decode, so the
/// trailer's own end magic is what says whether one is there.
fn artifact_carries_producer_trailer(
    extent: KvecBaseExtent,
    total_len: u64,
    ends_with_end_magic: impl FnOnce() -> Result<bool, KinDbError>,
) -> Result<bool, KinDbError> {
    match extent {
        KvecBaseExtent::Exact(end) => Ok(end != total_len),
        KvecBaseExtent::AtLeast(_) => ends_with_end_magic(),
    }
}

/// Confirm a trailer beginning at `start` agrees with what the preamble proved,
/// and return the container extent that implies.
fn producer_trailer_start_within_extent(
    extent: KvecBaseExtent,
    start: u64,
) -> Result<u64, KinDbError> {
    match extent {
        KvecBaseExtent::Exact(end) if start != end => Err(KinDbError::StorageError(
            "vector producer trailer does not begin at the exact kvec payload end".to_string(),
        )),
        KvecBaseExtent::AtLeast(floor) if start < floor => Err(KinDbError::StorageError(
            "vector producer trailer begins inside the kvec payload".to_string(),
        )),
        _ => Ok(start),
    }
}

fn validate_legacy_kvec_reader<R: Read + Seek>(
    reader: &mut R,
    exact_len: u64,
) -> Result<(), KinDbError> {
    if exact_len > MAX_LEGACY_PROVENANCE_DECODE_BYTES {
        return Err(KinDbError::StorageError(format!(
            "legacy kvec is {exact_len} bytes, above the bounded {}-byte provenance classification limit",
            MAX_LEGACY_PROVENANCE_DECODE_BYTES
        )));
    }
    reader.seek(SeekFrom::Start(0)).map_err(|error| {
        KinDbError::StorageError(format!("failed to rewind legacy vector index: {error}"))
    })?;
    let snapshot: kin_vector::HnswSnapshot<RetrievalKey> = rmp_serde::from_read(&mut *reader)
        .map_err(|error| {
            KinDbError::StorageError(format!(
                "vector index has no current container magic and is not a readable legacy container: {error}"
            ))
        })?;
    if snapshot.format_version != KVEC_V1_VERSION {
        return Err(KinDbError::StorageError(format!(
            "unsupported legacy kvec format version {}",
            snapshot.format_version
        )));
    }
    let consumed = reader.stream_position().map_err(|error| {
        KinDbError::StorageError(format!(
            "failed to confirm exact legacy vector index extent: {error}"
        ))
    })?;
    if consumed != exact_len {
        return Err(KinDbError::StorageError(format!(
            "legacy vector index has trailing bytes: decoded {consumed} of {exact_len}"
        )));
    }
    Ok(())
}

fn validate_legacy_kvec_bytes(bytes: &[u8]) -> Result<(), KinDbError> {
    let exact_len = u64::try_from(bytes.len())
        .map_err(|_| KinDbError::StorageError("legacy kvec length exceeds u64".to_string()))?;
    validate_legacy_kvec_reader(&mut Cursor::new(bytes), exact_len)
}

fn parse_producer_trailer_from_bytes(
    bytes: &[u8],
) -> Result<Option<ParsedProducerTrailer>, KinDbError> {
    let Some(extent) = kvec_base_extent(bytes)? else {
        validate_legacy_kvec_bytes(bytes)?;
        return Ok(None);
    };
    if !artifact_carries_producer_trailer(extent, bytes.len() as u64, || {
        Ok(bytes.ends_with(&PRODUCER_TRAILER_END_MAGIC))
    })? {
        return Ok(None);
    }
    let floor = usize::try_from(extent.floor()).expect("kvec_base_extent bounded the floor");
    let minimum_current_len = floor.checked_add(32 + 8 + 8).ok_or_else(|| {
        KinDbError::StorageError("vector producer trailer extent overflows".to_string())
    })?;
    if bytes.len() < minimum_current_len || !bytes.ends_with(&PRODUCER_TRAILER_END_MAGIC) {
        return Err(KinDbError::StorageError(
            "vector producer trailer is truncated or has extra trailing bytes".to_string(),
        ));
    }
    let unsigned_len_start = bytes.len() - 16;
    let unsigned_len = usize::try_from(read_u64_le(bytes, unsigned_len_start)?).map_err(|_| {
        KinDbError::StorageError("vector producer trailer length does not fit usize".to_string())
    })?;
    if !(PRODUCER_TRAILER_FIXED_UNSIGNED_BYTES..=MAX_PRODUCER_TRAILER_BYTES).contains(&unsigned_len)
    {
        return Err(KinDbError::StorageError(format!(
            "vector producer trailer length {unsigned_len} is outside the bounded current format"
        )));
    }
    let digest_start = unsigned_len_start.checked_sub(32).ok_or_else(|| {
        KinDbError::StorageError("vector producer trailer digest is truncated".to_string())
    })?;
    let unsigned_start = digest_start.checked_sub(unsigned_len).ok_or_else(|| {
        KinDbError::StorageError(
            "vector producer trailer length exceeds the index bytes".to_string(),
        )
    })?;
    let base_end = producer_trailer_start_within_extent(extent, unsigned_start as u64)?;
    let unsigned = bytes[unsigned_start..digest_start].to_vec();
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&bytes[digest_start..unsigned_len_start]);
    parse_unsigned_producer_trailer(unsigned, digest, base_end).map(Some)
}

fn parse_unsigned_producer_trailer(
    unsigned: Vec<u8>,
    digest: [u8; 32],
    expected_base_len: u64,
) -> Result<ParsedProducerTrailer, KinDbError> {
    if unsigned.len() < PRODUCER_TRAILER_FIXED_UNSIGNED_BYTES
        || unsigned[..8] != PRODUCER_TRAILER_START_MAGIC
    {
        return Err(KinDbError::StorageError(
            "vector producer trailer start magic is missing".to_string(),
        ));
    }
    let mut version = [0u8; 4];
    version.copy_from_slice(&unsigned[8..12]);
    let version = u32::from_le_bytes(version);
    if version != PRODUCER_TRAILER_VERSION {
        return Err(KinDbError::StorageError(format!(
            "unsupported vector producer trailer version {version}"
        )));
    }
    let base_len = read_u64_le(&unsigned, 12)?;
    if base_len != expected_base_len {
        return Err(KinDbError::StorageError(format!(
            "vector producer trailer base length {base_len} does not match exact kvec extent {expected_base_len}"
        )));
    }
    let producer_count = unsigned[20] as usize;
    if producer_count > MAX_PRODUCER_COUNT
        || unsigned.len() != PRODUCER_TRAILER_FIXED_UNSIGNED_BYTES + producer_count
    {
        return Err(KinDbError::StorageError(
            "vector producer trailer count does not match its bounded payload".to_string(),
        ));
    }
    let mut producers = EmbeddingProducerSet::new();
    let mut previous_tag = None;
    for &tag in &unsigned[PRODUCER_TRAILER_FIXED_UNSIGNED_BYTES..] {
        if previous_tag.is_some_and(|previous| previous >= tag) {
            return Err(KinDbError::StorageError(
                "vector producer trailer tags are not strictly canonical".to_string(),
            ));
        }
        let producer = producer_from_tag(tag).ok_or_else(|| {
            KinDbError::StorageError(format!(
                "vector producer trailer contains unknown producer tag {tag}"
            ))
        })?;
        producers.insert(producer);
        previous_tag = Some(tag);
    }
    Ok(ParsedProducerTrailer {
        base_len,
        producers,
        unsigned,
        digest,
    })
}

#[cfg(test)]
pub(crate) fn bind_vector_index_producers_to_bytes(
    base_index: &[u8],
    producers: &EmbeddingProducerSet,
) -> Result<Vec<u8>, KinDbError> {
    let base_len = u64::try_from(base_index.len())
        .map_err(|_| KinDbError::StorageError("kvec base length exceeds u64".to_string()))?;
    let acceptable = match kvec_base_extent(base_index)? {
        Some(KvecBaseExtent::Exact(end)) => end == base_len,
        Some(KvecBaseExtent::AtLeast(floor)) => {
            floor <= base_len && !base_index.ends_with(&PRODUCER_TRAILER_END_MAGIC)
        }
        None => false,
    };
    if !acceptable {
        return Err(KinDbError::StorageError(
            "producer binding requires one raw kvec base with no trailer of its own".to_string(),
        ));
    }
    let unsigned = encode_unsigned_producer_trailer(base_len, producers)?;
    let digest = producer_binding_digest(base_index, &unsigned);
    let unsigned_len = u64::try_from(unsigned.len()).expect("bounded trailer length fits u64");
    let mut bytes = Vec::with_capacity(base_index.len() + unsigned.len() + 48);
    bytes.extend_from_slice(base_index);
    bytes.extend_from_slice(&unsigned);
    bytes.extend_from_slice(&digest);
    bytes.extend_from_slice(&unsigned_len.to_le_bytes());
    bytes.extend_from_slice(&PRODUCER_TRAILER_END_MAGIC);
    Ok(bytes)
}

fn decode_current_vector_index_producer_binding(
    bytes: &[u8],
) -> Result<Option<(EmbeddingProducerSet, [u8; 32])>, KinDbError> {
    let Some(trailer) = parse_producer_trailer_from_bytes(bytes)? else {
        return Ok(None);
    };
    let base_len = usize::try_from(trailer.base_len)
        .map_err(|_| KinDbError::StorageError("kvec base length does not fit usize".to_string()))?;
    let expected = producer_binding_digest(&bytes[..base_len], &trailer.unsigned);
    if trailer.digest != expected {
        return Err(KinDbError::StorageError(
            "vector producer trailer binding checksum does not match index bytes and producer set"
                .to_string(),
        ));
    }
    Ok(Some((trailer.producers, trailer.digest)))
}

fn decode_vector_index_producers(bytes: &[u8]) -> Result<VectorProducerProvenance, KinDbError> {
    match decode_current_vector_index_producer_binding(bytes)? {
        Some((producers, _)) => Ok(VectorProducerProvenance::Known(producers)),
        None => Ok(VectorProducerProvenance::UnknownLegacy {
            metadata_version: None,
        }),
    }
}

fn read_kvec_base_extent(
    file: &mut File,
    file_len: u64,
) -> Result<Option<KvecBaseExtent>, KinDbError> {
    file.seek(SeekFrom::Start(0)).map_err(|error| {
        KinDbError::StorageError(format!("failed to seek vector index preamble: {error}"))
    })?;
    let mut magic = [0u8; 4];
    if file_len < magic.len() as u64 {
        return Ok(None);
    }
    file.read_exact(&mut magic).map_err(|error| {
        KinDbError::StorageError(format!("failed to read vector index magic: {error}"))
    })?;
    if magic != KVEC_V2_MAGIC {
        return Ok(None);
    }
    if file_len < KVEC_PREAMBLE_LEN as u64 {
        return Err(KinDbError::StorageError(
            "kvec preamble is truncated".to_string(),
        ));
    }
    let mut preamble = [0u8; KVEC_PREAMBLE_LEN];
    preamble[..4].copy_from_slice(&magic);
    file.read_exact(&mut preamble[4..]).map_err(|error| {
        KinDbError::StorageError(format!("failed to read vector index preamble: {error}"))
    })?;
    let extent = kvec_base_extent_from_preamble(&preamble)?.expect("kvec magic was checked");
    if extent.floor() > file_len {
        return Err(KinDbError::StorageError(
            "kvec payload extends beyond available bytes".to_string(),
        ));
    }
    Ok(Some(extent))
}

/// Whether the artifact's last eight bytes are the producer trailer's end magic.
fn file_ends_with_producer_end_magic(file: &mut File, file_len: u64) -> Result<bool, KinDbError> {
    let magic_len = PRODUCER_TRAILER_END_MAGIC.len() as u64;
    if file_len < magic_len {
        return Ok(false);
    }
    file.seek(SeekFrom::End(-(magic_len as i64)))
        .map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to seek vector producer trailer footer: {error}"
            ))
        })?;
    let mut magic = [0u8; 8];
    file.read_exact(&mut magic).map_err(|error| {
        KinDbError::StorageError(format!(
            "failed to read vector producer trailer footer: {error}"
        ))
    })?;
    Ok(magic == PRODUCER_TRAILER_END_MAGIC)
}

fn parse_producer_trailer_from_file(
    file: &mut File,
) -> Result<Option<ParsedProducerTrailer>, KinDbError> {
    let file_len = file
        .metadata()
        .map_err(|error| KinDbError::StorageError(format!("failed to stat vector index: {error}")))?
        .len();
    let Some(extent) = read_kvec_base_extent(file, file_len)? else {
        validate_legacy_kvec_reader(file, file_len)?;
        return Ok(None);
    };
    if !artifact_carries_producer_trailer(extent, file_len, || {
        file_ends_with_producer_end_magic(file, file_len)
    })? {
        return Ok(None);
    }
    let minimum_current_len = extent
        .floor()
        .checked_add(PRODUCER_TRAILER_FIXED_UNSIGNED_BYTES as u64)
        .and_then(|length| length.checked_add(32 + 8 + 8))
        .ok_or_else(|| {
            KinDbError::StorageError("vector producer trailer extent overflows".to_string())
        })?;
    if file_len < minimum_current_len {
        return Err(KinDbError::StorageError(
            "vector producer trailer is truncated or has extra trailing bytes".to_string(),
        ));
    }
    file.seek(SeekFrom::End(-16)).map_err(|error| {
        KinDbError::StorageError(format!(
            "failed to seek vector producer trailer footer: {error}"
        ))
    })?;
    let mut unsigned_len_bytes = [0u8; 8];
    let mut end_magic = [0u8; 8];
    file.read_exact(&mut unsigned_len_bytes).map_err(|error| {
        KinDbError::StorageError(format!(
            "failed to read vector producer trailer length: {error}"
        ))
    })?;
    file.read_exact(&mut end_magic).map_err(|error| {
        KinDbError::StorageError(format!(
            "failed to read vector producer trailer footer: {error}"
        ))
    })?;
    if end_magic != PRODUCER_TRAILER_END_MAGIC {
        return Err(KinDbError::StorageError(
            "vector producer trailer is truncated or has extra trailing bytes".to_string(),
        ));
    }
    let unsigned_len = u64::from_le_bytes(unsigned_len_bytes);
    if unsigned_len < PRODUCER_TRAILER_FIXED_UNSIGNED_BYTES as u64
        || unsigned_len > MAX_PRODUCER_TRAILER_BYTES as u64
    {
        return Err(KinDbError::StorageError(format!(
            "vector producer trailer length {unsigned_len} is outside the bounded current format"
        )));
    }
    let digest_start = file_len.checked_sub(16 + 32).ok_or_else(|| {
        KinDbError::StorageError("vector producer trailer digest is truncated".to_string())
    })?;
    let unsigned_start = digest_start.checked_sub(unsigned_len).ok_or_else(|| {
        KinDbError::StorageError(
            "vector producer trailer length exceeds the index bytes".to_string(),
        )
    })?;
    let base_end = producer_trailer_start_within_extent(extent, unsigned_start)?;
    let unsigned_len = usize::try_from(unsigned_len).expect("bounded trailer length fits usize");
    let mut unsigned = vec![0u8; unsigned_len];
    file.seek(SeekFrom::Start(unsigned_start))
        .map_err(|error| {
            KinDbError::StorageError(format!("failed to seek vector producer trailer: {error}"))
        })?;
    file.read_exact(&mut unsigned).map_err(|error| {
        KinDbError::StorageError(format!("failed to read vector producer trailer: {error}"))
    })?;
    let mut digest = [0u8; 32];
    file.read_exact(&mut digest).map_err(|error| {
        KinDbError::StorageError(format!(
            "failed to read vector producer trailer digest: {error}"
        ))
    })?;
    parse_unsigned_producer_trailer(unsigned, digest, base_end).map(Some)
}

fn stream_base_and_hash(
    source: &mut File,
    base_len: u64,
    mut destination: Option<&mut File>,
) -> Result<Sha256, KinDbError> {
    source.seek(SeekFrom::Start(0)).map_err(|error| {
        KinDbError::StorageError(format!("failed to rewind vector index: {error}"))
    })?;
    let mut hasher = producer_binding_hasher();
    let mut remaining = base_len;
    let mut buffer = [0u8; STREAM_BUFFER_BYTES];
    while remaining > 0 {
        let take = usize::try_from(remaining.min(buffer.len() as u64))
            .expect("bounded read length fits usize");
        let read = source.read(&mut buffer[..take]).map_err(|error| {
            KinDbError::StorageError(format!("failed to stream vector index base: {error}"))
        })?;
        if read == 0 {
            return Err(KinDbError::StorageError(
                "vector index base ended while streaming its producer binding".to_string(),
            ));
        }
        hasher.update(&buffer[..read]);
        if let Some(output) = destination.as_deref_mut() {
            output.write_all(&buffer[..read]).map_err(|error| {
                KinDbError::StorageError(format!(
                    "failed to stage verified vector index base: {error}"
                ))
            })?;
        }
        remaining -= read as u64;
    }
    Ok(hasher)
}

fn verify_producer_trailer_digest(
    file: &mut File,
    trailer: &ParsedProducerTrailer,
) -> Result<(), KinDbError> {
    let mut hasher = stream_base_and_hash(file, trailer.base_len, None)?;
    hasher.update(&trailer.unsigned);
    let expected: [u8; 32] = hasher.finalize().into();
    if expected != trailer.digest {
        return Err(KinDbError::StorageError(
            "vector producer trailer binding checksum does not match index bytes and producer set"
                .to_string(),
        ));
    }
    Ok(())
}

fn current_producer_binding_from_file(
    file: &mut File,
) -> Result<Option<(EmbeddingProducerSet, [u8; 32])>, KinDbError> {
    let Some(trailer) = parse_producer_trailer_from_file(file)? else {
        return Ok(None);
    };
    verify_producer_trailer_digest(file, &trailer)?;
    Ok(Some((trailer.producers, trailer.digest)))
}

fn producer_provenance_from_file(file: &mut File) -> Result<VectorProducerProvenance, KinDbError> {
    match current_producer_binding_from_file(file)? {
        Some((producers, _)) => Ok(VectorProducerProvenance::Known(producers)),
        None => Ok(VectorProducerProvenance::UnknownLegacy {
            metadata_version: None,
        }),
    }
}

fn append_vector_index_producer_trailer(
    path: &Path,
    producers: &EmbeddingProducerSet,
) -> Result<[u8; 32], KinDbError> {
    let mut file = OpenOptions::new()
        .read(true)
        .append(true)
        .open(path)
        .map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to open staged vector index {}: {error}",
                path.display()
            ))
        })?;
    let base_len = file
        .metadata()
        .map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to stat staged vector index {}: {error}",
                path.display()
            ))
        })?
        .len();
    // The staged file is exactly what kin-vector just wrote to a process-private
    // path, so its length IS the container's. What has to be refused here is a
    // truncated base, or one that already carries a trailer. A v2 preamble
    // proves both on its own, because its payload ends the container. A v3
    // preamble proves only the floor, so the trailer's own end magic answers the
    // second half.
    let acceptable = match read_kvec_base_extent(&mut file, base_len)? {
        Some(KvecBaseExtent::Exact(end)) => end == base_len,
        Some(KvecBaseExtent::AtLeast(floor)) => {
            floor <= base_len && !file_ends_with_producer_end_magic(&mut file, base_len)?
        }
        None => false,
    };
    if !acceptable {
        return Err(KinDbError::StorageError(
            "producer binding requires one raw kvec base with no trailer of its own".to_string(),
        ));
    }
    let unsigned = encode_unsigned_producer_trailer(base_len, producers)?;
    let mut hasher = stream_base_and_hash(&mut file, base_len, None)?;
    hasher.update(&unsigned);
    let digest: [u8; 32] = hasher.finalize().into();
    if file
        .metadata()
        .map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to restat staged vector index {}: {error}",
                path.display()
            ))
        })?
        .len()
        != base_len
    {
        return Err(KinDbError::StorageError(
            "staged vector index changed while binding producer evidence".to_string(),
        ));
    }
    file.write_all(&unsigned).map_err(|error| {
        KinDbError::StorageError(format!(
            "failed to append vector producer trailer {}: {error}",
            path.display()
        ))
    })?;
    file.write_all(&digest).map_err(|error| {
        KinDbError::StorageError(format!(
            "failed to append vector producer digest {}: {error}",
            path.display()
        ))
    })?;
    file.write_all(&(unsigned.len() as u64).to_le_bytes())
        .and_then(|()| file.write_all(&PRODUCER_TRAILER_END_MAGIC))
        .map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to append vector producer footer {}: {error}",
                path.display()
            ))
        })?;
    file.sync_all().map_err(|error| {
        KinDbError::StorageError(format!(
            "failed to sync complete staged vector index {}: {error}",
            path.display()
        ))
    })?;
    Ok(digest)
}

fn promote_staged_vector_index(staged: &Path, path: &Path) -> Result<(), KinDbError> {
    std::fs::rename(staged, path).map_err(|error| {
        KinDbError::StorageError(format!(
            "failed to promote complete vector index {} -> {}: {error}",
            staged.display(),
            path.display()
        ))
    })?;
    crate::storage::sync_parent_directory(path)
}

fn kin_vector_stage_companion(path: &Path, suffix: &str) -> PathBuf {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some(extension) if !extension.is_empty() => {
            path.with_extension(format!("{extension}.{suffix}"))
        }
        _ => path.with_extension(suffix),
    }
}

fn cleanup_staged_vector_index(path: &Path) {
    let candidates = [
        path.to_path_buf(),
        kin_vector_stage_companion(path, "tmp"),
        kin_vector_stage_companion(path, "tmp.meta"),
        kin_vector_stage_companion(path, "write.lock"),
    ];
    for candidate in candidates {
        if let Err(error) = std::fs::remove_file(&candidate) {
            if error.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(
                    path = %candidate.display(),
                    error = %error,
                    "failed to clean isolated vector save staging file"
                );
            }
        }
    }
}

struct VerifiedVectorBase {
    path: PathBuf,
    directory: PathBuf,
}

impl Drop for VerifiedVectorBase {
    fn drop(&mut self) {
        cleanup_staged_vector_index(&self.path);
        if let Err(error) = std::fs::remove_dir(&self.directory) {
            if error.kind() != std::io::ErrorKind::NotFound {
                tracing::warn!(
                    path = %self.directory.display(),
                    error = %error,
                    "failed to remove private verified vector staging directory"
                );
            }
        }
    }
}

fn stage_verified_vector_base(
    source_path: &Path,
) -> Result<(VerifiedVectorBase, EmbeddingProducerSet, [u8; 32]), KinDbError> {
    let mut source =
        crate::storage::open_regular_nofollow(source_path, "producer-bound vector index")?;
    let trailer = parse_producer_trailer_from_file(&mut source)?.ok_or_else(|| {
        KinDbError::StorageError("vector index has no current actual-producer binding".to_string())
    })?;

    // kin-vector's public path loader probes recovery companions beside its
    // input. Isolate the exact verified base in a process-private directory so
    // no ambient `<path>.tmp` candidate can replace the bytes whose trailer we
    // authenticated. A UUID makes the directory unguessable across processes;
    // mode 0700 prevents peers from introducing companions on Unix.
    let staged_directory = std::env::temp_dir().join(format!(
        "kin-db-verified-kvec-{}-{}",
        std::process::id(),
        uuid::Uuid::new_v4()
    ));
    let directory_builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    let mut directory_builder = directory_builder;
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        directory_builder.mode(0o700);
    }
    directory_builder
        .create(&staged_directory)
        .map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to create private verified vector directory {}: {error}",
                staged_directory.display()
            ))
        })?;
    let verified = VerifiedVectorBase {
        path: staged_directory.join("base.kvec"),
        directory: staged_directory,
    };
    let mut staged = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&verified.path)
        .map_err(|error| {
            KinDbError::StorageError(format!(
                "failed to create verified vector base {}: {error}",
                verified.path.display()
            ))
        })?;
    let mut hasher = stream_base_and_hash(&mut source, trailer.base_len, Some(&mut staged))?;
    hasher.update(&trailer.unsigned);
    let expected: [u8; 32] = hasher.finalize().into();
    if expected != trailer.digest {
        return Err(KinDbError::StorageError(
            "vector producer trailer binding checksum does not match index bytes and producer set"
                .to_string(),
        ));
    }
    if let Err(error) = staged.sync_all() {
        drop(staged);
        return Err(KinDbError::StorageError(format!(
            "failed to sync verified vector base {}: {error}",
            verified.path.display()
        )));
    }
    drop(staged);
    Ok((verified, trailer.producers, trailer.digest))
}

// ── Public API ──────────────────────────────────────────────────────────────

/// HNSW-backed vector similarity index for entity embeddings.
///
/// Thin wrapper around `kin_vector::VectorIndex<RetrievalKey>` that keeps
/// `EntityId` convenience APIs at the boundary and maps `VectorError` to
/// `KinDbError` for seamless integration with kin-db.
pub struct VectorIndex {
    inner: kin_vector::VectorIndex<RetrievalKey>,
    /// Process-unique identity for this handle, minted at construction.
    ///
    /// Paired with `generation` it names the key set an observer saw. A bare
    /// generation would not: a reset swaps in a fresh index whose generation
    /// restarts at zero, and a cache keyed on the number alone would serve the
    /// replaced index's counts for the replacement.
    id: u64,
    /// Bumped after every mutation that can change which keys the index holds.
    ///
    /// Every such mutation goes through one of this wrapper's methods, and the
    /// `kin_vector` index behind `inner` is private to it, so the counter is
    /// complete by construction rather than by review.
    generation: AtomicU64,
    /// Conservative lineage for every producer that has contributed to this
    /// handle. Removal deliberately does not subtract from the set.
    actual_producers: RwLock<EmbeddingProducerSet>,
    /// Serializes vector mutation plus provenance union against persistence, so
    /// no saved index can contain a vector whose producer has not yet landed.
    mutation_guard: RwLock<()>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VectorIndexPersistenceInfo {
    pub dimensions: usize,
    pub indexed: usize,
    pub actual_producers: EmbeddingProducerSet,
    /// Digest jointly covering the exact kin-vector base and its canonical
    /// producer trailer. Metadata must carry this value so a mixed-generation
    /// metadata/index pair cannot pass on shape and lineage alone.
    pub index_binding_sha256: [u8; 32],
}

/// Source of the process-unique handle ids described on [`VectorIndex::id`].
static NEXT_INDEX_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_PRODUCER_SAVE_ID: AtomicU64 = AtomicU64::new(1);

#[cfg(test)]
type ProducerFrontierHook = std::sync::Arc<dyn Fn() + Send + Sync>;
#[cfg(test)]
static PRODUCER_FRONTIER_HOOK: std::sync::Mutex<Option<(RetrievalKey, ProducerFrontierHook)>> =
    std::sync::Mutex::new(None);

#[cfg(test)]
fn set_producer_frontier_hook(key: Option<RetrievalKey>, hook: Option<ProducerFrontierHook>) {
    *PRODUCER_FRONTIER_HOOK
        .lock()
        .unwrap_or_else(|poison| poison.into_inner()) = key.zip(hook);
}

#[cfg(test)]
fn run_producer_frontier_hook(key: RetrievalKey) {
    let hook = PRODUCER_FRONTIER_HOOK
        .lock()
        .unwrap_or_else(|poison| poison.into_inner())
        .as_ref()
        .filter(|(expected, _)| *expected == key)
        .map(|(_, hook)| std::sync::Arc::clone(hook));
    if let Some(hook) = hook {
        hook();
    }
}

fn load_inner_from_verified_path(
    source_path: &Path,
    persistence_path: &Path,
) -> Result<
    (
        kin_vector::VectorIndex<RetrievalKey>,
        EmbeddingProducerSet,
        [u8; 32],
    ),
    KinDbError,
> {
    let (staged, producers, binding_sha256) = stage_verified_vector_base(source_path)?;
    let inner = kin_vector::VectorIndex::<RetrievalKey>::load_from_disk(&staged.path)
        .map_err(|error| KinDbError::IndexError(error.to_string()));
    let inner = inner?;
    inner.set_persistence_path(persistence_path.to_path_buf());
    Ok((inner, producers, binding_sha256))
}

impl VectorIndex {
    fn wrap(inner: kin_vector::VectorIndex<RetrievalKey>) -> Self {
        Self::wrap_with_producers(inner, EmbeddingProducerSet::new())
    }

    fn wrap_with_producers(
        inner: kin_vector::VectorIndex<RetrievalKey>,
        actual_producers: EmbeddingProducerSet,
    ) -> Self {
        Self {
            inner,
            id: NEXT_INDEX_ID.fetch_add(1, Ordering::Relaxed),
            generation: AtomicU64::new(0),
            actual_producers: RwLock::new(actual_producers),
            mutation_guard: RwLock::new(()),
        }
    }

    /// Conservative lineage of runtime producers represented by this index.
    ///
    /// Producers are unioned after successful insertion and never subtracted on
    /// removal. The result can therefore be more restrictive than the current
    /// live keys, but cannot hide a backend that contributed to the handle.
    pub fn actual_producers(&self) -> EmbeddingProducerSet {
        let _guard = self.mutation_guard.read();
        self.actual_producers.read().clone()
    }

    /// Decode and verify KinDB's producer binding from complete `.kvec` bytes.
    pub fn producer_provenance_from_bytes(
        bytes: &[u8],
    ) -> Result<VectorProducerProvenance, KinDbError> {
        decode_vector_index_producers(bytes)
    }

    /// Inspect complete `.kvec` bytes without collapsing structural corruption
    /// into an untyped error. Callers can distinguish exact legacy absence from
    /// malformed current evidence while strict attach paths continue to return
    /// an error and refuse the artifact.
    pub fn inspect_producer_provenance_from_bytes(bytes: &[u8]) -> VectorProducerProvenance {
        decode_vector_index_producers(bytes).unwrap_or_else(|error| {
            VectorProducerProvenance::Incompatible {
                reason: error.to_string(),
            }
        })
    }

    pub(crate) fn current_producer_binding_from_bytes(
        bytes: &[u8],
    ) -> Result<Option<(EmbeddingProducerSet, [u8; 32])>, KinDbError> {
        decode_current_vector_index_producer_binding(bytes)
    }

    pub(crate) fn current_producer_binding_from_path(
        path: &Path,
    ) -> Result<Option<(EmbeddingProducerSet, [u8; 32])>, KinDbError> {
        let mut file =
            crate::storage::open_regular_nofollow(path, "vector index producer binding")?;
        current_producer_binding_from_file(&mut file)
    }

    /// Decode and verify KinDB's producer binding from one `.kvec` file.
    pub fn producer_provenance_from_path(
        path: &Path,
    ) -> Result<VectorProducerProvenance, KinDbError> {
        let mut file =
            crate::storage::open_regular_nofollow(path, "vector index producer binding")?;
        producer_provenance_from_file(&mut file)
    }

    /// Path counterpart of [`Self::inspect_producer_provenance_from_bytes`].
    /// Opening failures remain I/O errors; once opened, incompatible producer
    /// evidence is returned as a typed outcome.
    pub fn inspect_producer_provenance_from_path(
        path: &Path,
    ) -> Result<VectorProducerProvenance, KinDbError> {
        let mut file =
            crate::storage::open_regular_nofollow(path, "vector index producer binding")?;
        Ok(
            producer_provenance_from_file(&mut file).unwrap_or_else(|error| {
                VectorProducerProvenance::Incompatible {
                    reason: error.to_string(),
                }
            }),
        )
    }

    /// Record that the key set just changed.
    ///
    /// Called after the mutation lands, never before: a caller that reads the
    /// token, then counts, then stores the count against that token must have
    /// any interleaved mutation invalidate the stored entry. Bumping first
    /// would let a count taken before the mutation be stored against the
    /// post-mutation token and served as current.
    fn mark_key_set_changed(&self) {
        self.generation.fetch_add(1, Ordering::Release);
    }

    /// Names the key set this index currently holds.
    ///
    /// Two reads that return the same pair observed the same keys, so a caller
    /// can cache a derived count against it instead of rescanning the index.
    pub fn key_set_token(&self) -> (u64, u64) {
        (self.id, self.generation.load(Ordering::Acquire))
    }

    /// How many of `keys` this index holds, resolved in ONE index lock
    /// acquisition.
    ///
    /// The per-key alternative is `contains_retrievable` in a loop, which takes
    /// the index lock once per key. Each of those acquisitions can be forced to
    /// wait behind an in-flight batch upsert, so a caller counting a
    /// graph-sized key set that way blocks for the embed worker's write
    /// duration once per key rather than once in total.
    pub fn count_present(&self, keys: &hashbrown::HashSet<RetrievalKey>) -> usize {
        if keys.is_empty() {
            return 0;
        }
        self.inner
            .keys()
            .into_iter()
            .filter(|key| keys.contains(key))
            .count()
    }

    /// Create a new vector index for embeddings of the given dimensionality.
    pub fn new(dimensions: usize) -> Result<Self, KinDbError> {
        let inner = kin_vector::VectorIndex::new(dimensions)
            .map_err(|e| KinDbError::IndexError(e.to_string()))?;
        Ok(Self::wrap(inner))
    }

    /// The index's self-description (embedding model identity + graph provenance)
    /// stamped into the persisted file.
    pub fn descriptor(&self) -> IndexDescriptor {
        self.inner.descriptor()
    }

    /// Stamp the index's self-description before saving, so a later load can
    /// prove the persisted vectors were produced by the expected model/graph and
    /// refuse silently-wrong neighbors.
    pub fn set_descriptor(&self, descriptor: IndexDescriptor) {
        let _guard = self.mutation_guard.write();
        self.inner.set_descriptor(descriptor);
    }

    /// The dimensionality of vectors in this index.
    pub fn dimensions(&self) -> usize {
        self.inner.dimensions()
    }

    /// Number of vectors currently indexed.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Whether the index is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Whether the index already contains a vector for this entity.
    pub fn contains(&self, entity_id: &EntityId) -> bool {
        let key = RetrievalKey::from(*entity_id);
        self.inner.contains(&key)
    }

    /// Whether the index already contains a vector for this retrieval key.
    pub fn contains_retrievable(&self, key: &RetrievalKey) -> bool {
        self.inner.contains(key)
    }

    /// All retrieval keys currently held in the index.
    pub fn retrievable_keys(&self) -> Vec<RetrievalKey> {
        self.inner.keys()
    }

    /// Get the embedding vector for this entity if present.
    pub fn get(&self, entity_id: &EntityId) -> Option<Vec<f32>> {
        let key = RetrievalKey::from(*entity_id);
        self.inner.get(&key)
    }

    /// Get the embedding vector for this retrieval key if present.
    pub fn get_retrievable(&self, key: &RetrievalKey) -> Option<Vec<f32>> {
        self.inner.get(key)
    }

    /// Add or update the embedding for an entity.
    ///
    /// The embedding slice must have exactly `dimensions` elements.
    pub fn upsert(&self, entity_id: EntityId, embedding: &[f32]) -> Result<(), KinDbError> {
        self.upsert_retrievable(entity_id.into(), embedding)
    }

    /// Add or update the embedding for any retrieval key.
    ///
    /// The embedding slice must have exactly `dimensions` elements.
    pub fn upsert_retrievable(
        &self,
        key: RetrievalKey,
        embedding: &[f32],
    ) -> Result<(), KinDbError> {
        self.upsert_retrievable_with_producers(
            key,
            embedding,
            &EmbeddingProducerSet::singleton(EmbeddingProducer::Unspecified),
        )
    }

    /// Add or update one embedding and bind the actual producer evidence that
    /// arrived with its bytes.
    pub fn upsert_retrievable_with_producers(
        &self,
        key: RetrievalKey,
        embedding: &[f32],
        producers: &EmbeddingProducerSet,
    ) -> Result<(), KinDbError> {
        if producers.is_empty() {
            return Err(KinDbError::IndexError(
                "producer-aware vector upsert requires a non-empty producer set".to_string(),
            ));
        }
        let _span =
            tracing::info_span!("kindb.vector_index.upsert", dims = embedding.len()).entered();
        let _guard = self.mutation_guard.write();
        #[cfg(test)]
        let hook_key = key;
        self.inner
            .upsert(key, embedding)
            .map_err(|e| KinDbError::IndexError(e.to_string()))?;
        #[cfg(test)]
        run_producer_frontier_hook(hook_key);
        self.actual_producers.write().extend(producers);
        self.mark_key_set_changed();
        Ok(())
    }

    /// Add or update the embeddings for a batch of retrieval keys.
    pub fn upsert_retrievable_batch(
        &self,
        items: Vec<(RetrievalKey, Vec<f32>)>,
    ) -> Result<(), KinDbError> {
        self.upsert_retrievable_batch_with_producers(
            items,
            &EmbeddingProducerSet::singleton(EmbeddingProducer::Unspecified),
        )
    }

    /// Add or update a batch and atomically union its actual producer evidence
    /// before persistence can observe the new vectors.
    pub fn upsert_retrievable_batch_with_producers(
        &self,
        items: Vec<(RetrievalKey, Vec<f32>)>,
        producers: &EmbeddingProducerSet,
    ) -> Result<(), KinDbError> {
        if items.is_empty() {
            return Ok(());
        }
        if producers.is_empty() {
            return Err(KinDbError::IndexError(
                "producer-aware vector batch requires a non-empty producer set".to_string(),
            ));
        }
        let _span =
            tracing::info_span!("kindb.vector_index.upsert_batch", batch_size = items.len())
                .entered();
        let _guard = self.mutation_guard.write();
        self.inner
            .upsert_batch(items)
            .map_err(|e| KinDbError::IndexError(e.to_string()))?;
        self.actual_producers.write().extend(producers);
        self.mark_key_set_changed();
        Ok(())
    }

    /// Remove the embedding for an entity.
    pub fn remove(&self, entity_id: &EntityId) -> Result<(), KinDbError> {
        let _span = tracing::info_span!("kindb.vector_index.remove").entered();
        let key = RetrievalKey::from(*entity_id);
        self.remove_retrievable(&key)
    }

    /// Remove the embedding for any retrieval key.
    pub fn remove_retrievable(&self, key: &RetrievalKey) -> Result<(), KinDbError> {
        let _guard = self.mutation_guard.write();
        self.inner
            .remove(key)
            .map_err(|e| KinDbError::IndexError(e.to_string()))?;
        self.mark_key_set_changed();
        Ok(())
    }

    /// Remove a batch of entity embeddings from the index.
    pub fn remove_batch(&self, entity_ids: &[EntityId]) -> Result<(), KinDbError> {
        let _span =
            tracing::info_span!("kindb.vector_index.remove_batch", count = entity_ids.len())
                .entered();
        let _guard = self.mutation_guard.write();
        for id in entity_ids {
            let key = RetrievalKey::from(*id);
            self.inner
                .remove(&key)
                .map_err(|e| KinDbError::IndexError(e.to_string()))?;
            self.mark_key_set_changed();
        }
        Ok(())
    }

    /// Search for the `limit` most similar entities to the given embedding.
    ///
    /// Returns pairs of (RetrievalKey, distance_score) sorted by similarity.
    pub fn search_similar(
        &self,
        embedding: &[f32],
        limit: usize,
    ) -> Result<Vec<(RetrievalKey, f32)>, KinDbError> {
        let _span = tracing::info_span!(
            "kindb.vector_index.search_similar",
            dims = embedding.len(),
            limit = limit
        )
        .entered();
        let results = self
            .inner
            .search_similar(embedding, limit)
            .map_err(|e| KinDbError::IndexError(e.to_string()))?;
        Ok(results)
    }

    /// Search for the `limit` most similar entities, filtering by a predicate.
    pub fn search_similar_filtered(
        &self,
        embedding: &[f32],
        limit: usize,
        predicate: impl Fn(&RetrievalKey) -> bool,
    ) -> Result<Vec<(RetrievalKey, f32)>, KinDbError> {
        let _span = tracing::info_span!(
            "kindb.vector_index.search_similar_filtered",
            dims = embedding.len(),
            limit = limit
        )
        .entered();
        let results = self
            .inner
            .search_similar_filtered(embedding, limit, predicate)
            .map_err(|e| KinDbError::IndexError(e.to_string()))?;
        Ok(results)
    }

    /// Search with role enrichment: returns `ScoredHit` results with entity roles attached.
    ///
    /// The `role_lookup` closure resolves an `EntityId` to its `EntityRole`.
    /// Non-entity keys get `role: None`. This follows the grouping-over-penalizing
    /// design — roles are metadata for downstream ranking, not score modifiers.
    pub fn search_similar_with_roles<F>(
        &self,
        embedding: &[f32],
        limit: usize,
        role_lookup: F,
    ) -> Result<Vec<ScoredHit>, KinDbError>
    where
        F: Fn(&EntityId) -> Option<EntityRole>,
    {
        let raw = self.search_similar(embedding, limit)?;
        Ok(resolve_roles(raw, role_lookup))
    }

    /// Search with role enrichment, filtering by a predicate.
    pub fn search_similar_filtered_with_roles<F, P>(
        &self,
        embedding: &[f32],
        limit: usize,
        predicate: P,
        role_lookup: F,
    ) -> Result<Vec<ScoredHit>, KinDbError>
    where
        F: Fn(&EntityId) -> Option<EntityRole>,
        P: Fn(&RetrievalKey) -> bool,
    {
        let raw = self.search_similar_filtered(embedding, limit, predicate)?;
        Ok(resolve_roles(raw, role_lookup))
    }

    /// Set the persistence path for this index.
    pub fn set_persistence_path(&self, path: impl Into<std::path::PathBuf>) {
        self.inner.set_persistence_path(path);
    }

    /// Save the HNSW index to disk.
    ///
    /// Persists the full HNSW graph as a single MessagePack file with atomic
    /// write semantics (write-to-tmp then rename).
    pub fn save(&self, path: &Path) -> Result<(), KinDbError> {
        self.save_with_provenance(path, None, |_| Ok(()))
            .map(|_| ())
    }

    pub(crate) fn save_with_provenance<F>(
        &self,
        path: &Path,
        descriptor: Option<IndexDescriptor>,
        before_index_promote: F,
    ) -> Result<VectorIndexPersistenceInfo, KinDbError>
    where
        F: FnOnce(&VectorIndexPersistenceInfo) -> Result<(), KinDbError>,
    {
        let _span = tracing::info_span!(
            "kindb.vector_index.save",
            path = %path.display()
        )
        .entered();
        let _guard = self.mutation_guard.write();
        if let Some(descriptor) = descriptor {
            self.inner.set_descriptor(descriptor);
        }
        let producers = self.actual_producers.read().clone();
        let dimensions = self.inner.dimensions();
        let indexed = self.inner.len();
        if indexed > 0 && producers.is_empty() {
            return Err(KinDbError::StorageError(
                "non-empty vector index has no actual-producer evidence".to_string(),
            ));
        }

        // kin-vector owns the base encoding. Save it to an isolated staging
        // path and append KinDB's small producer trailer without copying the
        // base into RAM. The callback promotes v4 metadata from this exact
        // receipt first. Only then is the complete staged index renamed into
        // place, so every crash window is a fail-closed mixed pair rather than
        // a falsely accepted legacy pair.
        let save_id = NEXT_PRODUCER_SAVE_ID.fetch_add(1, Ordering::Relaxed);
        let staged = path.with_extension(format!(
            "kvec.producer-base-{}-{save_id}",
            std::process::id()
        ));
        let outcome = (|| {
            self.inner
                .save(&staged)
                .map_err(|e| KinDbError::IndexError(e.to_string()))?;
            let index_binding_sha256 = append_vector_index_producer_trailer(&staged, &producers)?;
            let info = VectorIndexPersistenceInfo {
                dimensions,
                indexed,
                actual_producers: producers,
                index_binding_sha256,
            };
            before_index_promote(&info)?;
            promote_staged_vector_index(&staged, path)?;
            Ok(info)
        })();
        cleanup_staged_vector_index(&staged);
        outcome
    }

    /// Decode persisted index bytes for internal inspection and strict
    /// descriptor validation.
    #[cfg(test)]
    pub(crate) fn load_from_disk(path: &Path) -> Result<Self, KinDbError> {
        let _span = tracing::info_span!(
            "kindb.vector_index.load_from_disk",
            path = %path.display()
        )
        .entered();
        let (inner, producers, _) = load_inner_from_verified_path(path, path)?;
        if !inner.is_empty() && producers.is_empty() {
            return Err(KinDbError::StorageError(
                "non-empty vector index producer binding is empty".to_string(),
            ));
        }
        Ok(Self::wrap_with_producers(inner, producers))
    }

    /// Load the index at `path` and verify its self-description against
    /// `expected`, returning [`IndexLoadOutcome`].
    ///
    /// This NEVER returns an error for an incompatible or unreadable index:
    /// a model/graph mismatch (kin-vector's typed `ModelMismatch`) or a corrupt
    /// file both resolve to [`IndexLoadOutcome::Incompatible`] so the caller can
    /// archive-and-rebuild rather than crash-loop or serve silently-wrong
    /// neighbors. Both expected model and graph identities are required; an
    /// unstamped or partially bound descriptor is incompatible.
    pub fn load_compatible(path: &Path, expected: &IndexDescriptor) -> IndexLoadOutcome {
        Self::load_compatible_with_producers(path, expected, None)
    }

    /// Load an index from the exact bytes whose descriptor and producer binding
    /// were validated, optionally pinning the metadata's expected producer set.
    pub fn load_compatible_with_producers(
        path: &Path,
        expected: &IndexDescriptor,
        expected_producers: Option<&EmbeddingProducerSet>,
    ) -> IndexLoadOutcome {
        Self::load_compatible_with_evidence(path, expected, expected_producers, None)
    }

    pub(crate) fn load_compatible_with_producer_binding(
        path: &Path,
        expected: &IndexDescriptor,
        expected_producers: &EmbeddingProducerSet,
        expected_index_binding_sha256: [u8; 32],
    ) -> IndexLoadOutcome {
        Self::load_compatible_with_evidence(
            path,
            expected,
            Some(expected_producers),
            Some(expected_index_binding_sha256),
        )
    }

    fn load_compatible_with_evidence(
        path: &Path,
        expected: &IndexDescriptor,
        expected_producers: Option<&EmbeddingProducerSet>,
        expected_index_binding_sha256: Option<[u8; 32]>,
    ) -> IndexLoadOutcome {
        if expected.model_id.as_deref().is_none_or(str::is_empty)
            || expected.graph_root.as_deref().is_none_or(str::is_empty)
        {
            return IndexLoadOutcome::Incompatible(
                "expected vector descriptor must bind model_id and graph_root".to_string(),
            );
        }
        let (inner, producers, index_binding_sha256) =
            match load_inner_from_verified_path(path, path) {
                Ok(loaded) => loaded,
                Err(error) => {
                    return IndexLoadOutcome::Incompatible(format!(
                        "unreadable or invalid vector index: {error}"
                    ))
                }
            };
        if expected_producers.is_some_and(|expected| expected != &producers) {
            return IndexLoadOutcome::Incompatible(format!(
                "vector index actual producers {:?} do not match expected {:?}",
                producers, expected_producers
            ));
        }
        if let Some(expected) = expected_index_binding_sha256 {
            if expected != index_binding_sha256 {
                return IndexLoadOutcome::Incompatible(format!(
                    "vector index binding {} does not match metadata binding {}",
                    hex::encode(index_binding_sha256),
                    hex::encode(expected)
                ));
            }
        }
        if !inner.is_empty() && producers.is_empty() {
            return IndexLoadOutcome::Incompatible(
                "non-empty vector index producer binding is empty".to_string(),
            );
        }
        match inner.descriptor().verify_compatible(expected) {
            Ok(()) => IndexLoadOutcome::Loaded(Self::wrap_with_producers(inner, producers)),
            Err(e) => IndexLoadOutcome::Incompatible(e.to_string()),
        }
    }
}

/// Outcome of [`VectorIndex::load_compatible`].
pub enum IndexLoadOutcome {
    /// The on-disk index loaded and proved compatible with the expected
    /// model/graph self-description.
    Loaded(VectorIndex),
    /// The index exists but is incompatible (model/graph mismatch) or unreadable
    /// and must be archived + rebuilt rather than served. Carries a
    /// human-readable reason for the LOUD recovery notice.
    Incompatible(String),
}

impl std::fmt::Debug for VectorIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.inner)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bind_test_unsigned_trailer(base: &[u8], unsigned: &[u8]) -> Vec<u8> {
        let digest = producer_binding_digest(base, unsigned);
        let mut bytes = Vec::with_capacity(base.len() + unsigned.len() + 48);
        bytes.extend_from_slice(base);
        bytes.extend_from_slice(unsigned);
        bytes.extend_from_slice(&digest);
        bytes.extend_from_slice(&(unsigned.len() as u64).to_le_bytes());
        bytes.extend_from_slice(&PRODUCER_TRAILER_END_MAGIC);
        bytes
    }

    /// The exact end of a version 2 container, asserting on the way through
    /// that v2 still claims exactness.
    ///
    /// The split between an exact extent and a floor is the whole subject of the
    /// version 3 tests below, so every version 2 fixture in this module pins its
    /// own side of it rather than reading a bare number.
    fn exact_v2_base_end(bytes: &[u8]) -> usize {
        match kvec_base_extent(bytes).unwrap().unwrap() {
            KvecBaseExtent::Exact(end) => usize::try_from(end).unwrap(),
            KvecBaseExtent::AtLeast(floor) => {
                panic!("a v2 preamble must locate the container end exactly, got a floor {floor}")
            }
        }
    }

    fn align_up_u64(value: u64, align: u64) -> u64 {
        value.div_ceil(align) * align
    }

    /// Bytes shaped exactly like a kin-vector version 3 container.
    ///
    /// kin-db pins kin-vector 0.1.12, which has no version 3 writer, so a
    /// synthetic container is the only way this repo can exercise the shape its
    /// own producer binding has to survive. That is the point of the fixture
    /// rather than a weakness of it: two repos each hold half of this invariant
    /// and neither builds against the other's change, so the half that lives
    /// here gets a guard here.
    ///
    /// The layout is taken from kin-vector's `encode_v3` at
    /// `f772f2cbdc847688bd27bad921c94a2320196d0d`, read rather than assumed: a
    /// 64-byte preamble whose first 40 bytes mean what version 2's mean, an
    /// opaque MessagePack header, then a table of sections of which the fp32
    /// payload is the FIRST and a whole squared-norm table is the last, each
    /// section starting on a 64-byte boundary. Nothing in KinDB's producer
    /// binding decodes that header, so filler bytes are the same input to this
    /// code as a real header.
    ///
    /// A `norm_nodes` of zero writes no norm section, which is what `encode_v3`
    /// does when the norm table is not whole.
    fn synthetic_v3_container(slots: u64, dimensions: u64, norm_nodes: u64) -> Vec<u8> {
        const SECTION_ALIGN: u64 = 64;
        let header_len: u64 = 96;
        let first_offset = align_up_u64(KVEC_PREAMBLE_LEN as u64 + header_len, SECTION_ALIGN);
        let payload_end = first_offset + slots * dimensions * 4;
        let total = if norm_nodes > 0 {
            align_up_u64(payload_end, SECTION_ALIGN) + norm_nodes * 4
        } else {
            payload_end
        };

        let mut bytes = vec![0u8; usize::try_from(total).unwrap()];
        // Everything past the preamble gets a ramp rather than zeroes, so a
        // reader that lands on the wrong offset reads visibly wrong bytes
        // instead of a plausible run of nulls. Consecutive ramp bytes differ by
        // one, so no run of it can spell the trailer's end magic.
        for (index, byte) in bytes.iter_mut().enumerate().skip(KVEC_PREAMBLE_LEN) {
            *byte = (index % 251) as u8;
        }
        bytes[0..4].copy_from_slice(&KVEC_V2_MAGIC);
        bytes[4..8].copy_from_slice(&KVEC_V3_VERSION.to_le_bytes());
        bytes[8..16].copy_from_slice(&header_len.to_le_bytes());
        bytes[16..24].copy_from_slice(&first_offset.to_le_bytes());
        bytes[24..32].copy_from_slice(&slots.to_le_bytes());
        bytes[32..40].copy_from_slice(&dimensions.to_le_bytes());
        bytes
    }

    fn every_producer() -> EmbeddingProducerSet {
        let mut set = EmbeddingProducerSet::new();
        for producer in [
            EmbeddingProducer::Cpu,
            EmbeddingProducer::Metal,
            EmbeddingProducer::Cuda,
            EmbeddingProducer::Remote,
            EmbeddingProducer::Unspecified,
        ] {
            set.insert(producer);
        }
        set
    }

    /// A version 3 container binds and reads its producer trailer, through both
    /// the byte path and the file path.
    ///
    /// This is the half of FIR-3150's invariant that lives in kin-db. The
    /// observed production failure was `unsupported kvec container version 3 for
    /// producer binding` on an ordinary embed against a store a `save()` had
    /// promoted to version 3, and widening the version alone would not have
    /// fixed it: the container runs past its payload, so every caller that read
    /// the payload end as the container end would have refused the same file
    /// with a different message.
    #[test]
    fn a_version_three_container_binds_and_reads_its_producer_trailer() {
        let container = synthetic_v3_container(3, 4, 3);
        let extent = kvec_base_extent(&container).unwrap().unwrap();
        let floor = match extent {
            KvecBaseExtent::AtLeast(floor) => floor,
            KvecBaseExtent::Exact(end) => {
                panic!("a v3 preamble cannot locate the container end exactly, got {end}")
            }
        };
        assert!(
            floor < container.len() as u64,
            "the fixture must carry a section after its payload or this proves nothing about v3: \
             floor {floor}, length {}",
            container.len()
        );

        // A bare version 3 container carries no producer evidence and has to say
        // so, rather than reading its own norm section as a truncated trailer.
        assert!(matches!(
            VectorIndex::producer_provenance_from_bytes(&container).unwrap(),
            VectorProducerProvenance::UnknownLegacy { .. }
        ));

        let mut producers = EmbeddingProducerSet::singleton(EmbeddingProducer::Cpu);
        producers.insert(EmbeddingProducer::Metal);
        let bound = bind_vector_index_producers_to_bytes(&container, &producers).unwrap();
        assert_eq!(
            VectorIndex::producer_provenance_from_bytes(&bound).unwrap(),
            VectorProducerProvenance::Known(producers.clone())
        );

        // The same shape through the file path, which is the caller that
        // produced the observed failure.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("v3-container.kvec");
        std::fs::write(&path, &container).unwrap();
        assert!(matches!(
            VectorIndex::producer_provenance_from_path(&path).unwrap(),
            VectorProducerProvenance::UnknownLegacy { .. }
        ));
        append_vector_index_producer_trailer(&path, &producers).unwrap();
        assert_eq!(
            std::fs::read(&path).unwrap(),
            bound,
            "the file binder and the byte binder must agree on a v3 base"
        );
        assert_eq!(
            VectorIndex::producer_provenance_from_path(&path).unwrap(),
            VectorProducerProvenance::Known(producers.clone())
        );

        // Binding again must refuse rather than stack a second trailer on the
        // first. A version 2 base proves it is unbound from its preamble alone,
        // because its payload ends the container. A version 3 base has only the
        // trailer's own end magic to prove it with.
        for error in [
            append_vector_index_producer_trailer(&path, &producers)
                .expect_err("an already bound v3 base must refuse a second trailer"),
            bind_vector_index_producers_to_bytes(&bound, &producers)
                .expect_err("the byte binder must refuse the same"),
        ] {
            assert!(
                error.to_string().contains("no trailer of its own"),
                "the refusal must come from the existing-trailer guard: {error}"
            );
        }
        assert_eq!(
            std::fs::read(&path).unwrap(),
            bound,
            "a refused second binding must leave the artifact untouched"
        );
    }

    /// `encode_v3` writes no norm section when the norm table is not whole, so
    /// that container really does end at its payload. The floor is then the
    /// exact end, and the reader must still treat the artifact as bare.
    #[test]
    fn a_version_three_container_with_no_norm_section_ends_at_its_payload() {
        let container = synthetic_v3_container(3, 4, 0);
        assert_eq!(
            kvec_base_extent(&container).unwrap().unwrap(),
            KvecBaseExtent::AtLeast(container.len() as u64)
        );
        assert!(matches!(
            VectorIndex::producer_provenance_from_bytes(&container).unwrap(),
            VectorProducerProvenance::UnknownLegacy { .. }
        ));
    }

    /// A version outside the readable range is refused by name, so the next
    /// container bump is loud here rather than silently misread.
    #[test]
    fn a_container_version_outside_the_readable_range_is_refused_by_name() {
        let above = KVEC_MAX_READABLE_VERSION + 1;
        let mut future = synthetic_v3_container(3, 4, 3);
        future[4..8].copy_from_slice(&above.to_le_bytes());
        let error = VectorIndex::producer_provenance_from_bytes(&future)
            .expect_err("a container above the readable range must fail closed");
        assert!(
            error.to_string().contains(&format!(
                "unsupported kvec container version {above} for producer binding, which reads \
                 {KVEC_MIN_READABLE_VERSION} through {KVEC_MAX_READABLE_VERSION}"
            )),
            "the refusal must name the version it saw and the range it reads: {error}"
        );

        let mut below = synthetic_v3_container(3, 4, 3);
        below[4..8].copy_from_slice(&(KVEC_MIN_READABLE_VERSION - 1).to_le_bytes());
        assert!(VectorIndex::producer_provenance_from_bytes(&below).is_err());

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("future-version.kvec");
        std::fs::write(&path, &future).unwrap();
        assert!(VectorIndex::producer_provenance_from_path(&path).is_err());

        // Positive control. The same fixture at a version inside the range is
        // accepted, so this test cannot pass by refusing everything.
        assert!(matches!(
            VectorIndex::producer_provenance_from_bytes(&synthetic_v3_container(3, 4, 3)).unwrap(),
            VectorProducerProvenance::UnknownLegacy { .. }
        ));
    }

    /// The version 3 floor is a real refusal, not a rubber stamp.
    ///
    /// Version 2 gets an exact container end from its preamble and refuses a
    /// trailer that does not begin there. Version 3 can only be given a floor,
    /// so the floor has to refuse a trailer that begins before it, or the check
    /// it replaced would be gone rather than weakened.
    #[test]
    fn a_version_three_trailer_that_starts_inside_the_payload_is_refused() {
        let container = synthetic_v3_container(3, 4, 3);
        let producers = every_producer();
        let bound = bind_vector_index_producers_to_bytes(&container, &producers).unwrap();
        assert_eq!(
            VectorIndex::producer_provenance_from_bytes(&bound).unwrap(),
            VectorProducerProvenance::Known(producers),
            "positive control: the untampered fixture must decode"
        );

        // Move the payload floor four bytes past where the trailer actually
        // begins. Four is close enough that the trailer's own minimum-length
        // check still passes, so the floor check is the only thing left that can
        // refuse this. One f32 per slot makes that offset reachable.
        let trailer_start = container.len() as u64;
        let first_offset = read_u64_le(&bound, 16).unwrap();
        let overlap_floor = trailer_start + 4;
        assert_eq!(
            (overlap_floor - first_offset) % 4,
            0,
            "the forged slot count has to land on the byte it was chosen for"
        );
        let mut overlapping = bound.clone();
        overlapping[24..32].copy_from_slice(&((overlap_floor - first_offset) / 4).to_le_bytes());
        overlapping[32..40].copy_from_slice(&1u64.to_le_bytes());

        for (surface, error) in [
            (
                "bytes",
                VectorIndex::producer_provenance_from_bytes(&overlapping)
                    .expect_err("a trailer beginning inside the payload must fail closed"),
            ),
            ("file", {
                let dir = tempfile::tempdir().unwrap();
                let path = dir.path().join("overlapping.kvec");
                std::fs::write(&path, &overlapping).unwrap();
                VectorIndex::producer_provenance_from_path(&path)
                    .expect_err("the file path must refuse the same overlap")
            }),
        ] {
            assert!(
                error.to_string().contains("begins inside the kvec payload"),
                "the floor check must be what refuses this on the {surface} path, \
                 not the length check: {error}"
            );
        }
    }

    fn genuine_legacy_kvec_bytes(format_version: u8) -> Vec<u8> {
        let graph = kin_vector::HnswGraph::<RetrievalKey> {
            nodes: Vec::new(),
            entry_point: None,
            max_level: 0,
            dimensions: 4,
            id_to_idx: hashbrown::HashMap::new(),
            idx_to_id: Vec::new(),
            free_list: Vec::new(),
            reserved_legacy_slot: 0x1234,
            descriptor: IndexDescriptor::default(),
            backlinks: Vec::new(),
            canonical_order_dirty: false,
            mutation_seq: 0,
            sq_norms: Vec::new(),
        };
        rmp_serde::to_vec(&kin_vector::HnswSnapshot {
            format_version,
            graph,
        })
        .unwrap()
    }

    #[test]
    fn create_and_add_vectors() {
        let idx = VectorIndex::new(4).unwrap();
        let e1 = EntityId::new();
        let e2 = EntityId::new();

        idx.upsert(e1, &[1.0, 0.0, 0.0, 0.0]).unwrap();
        idx.upsert(e2, &[0.0, 1.0, 0.0, 0.0]).unwrap();

        assert_eq!(idx.len(), 2);
        assert!(idx.contains(&e1));
        assert!(idx.contains(&e2));
    }

    #[test]
    fn upsert_retrievable_accepts_artifacts() {
        let idx = VectorIndex::new(4).unwrap();
        // Round-trip test: the id value is opaque to the index, so mint one.
        let key = RetrievalKey::Artifact(kin_model::ArtifactId::new());

        idx.upsert_retrievable(key, &[1.0, 0.0, 0.0, 0.0]).unwrap();

        assert_eq!(idx.len(), 1);
        assert!(idx.contains_retrievable(&key));
    }

    #[test]
    fn dimension_mismatch_rejected() {
        let idx = VectorIndex::new(4).unwrap();
        let e1 = EntityId::new();

        let result = idx.upsert(e1, &[1.0, 0.0]);
        assert!(result.is_err());
    }

    #[test]
    fn search_returns_nearest() {
        let idx = VectorIndex::new(4).unwrap();
        let e1 = EntityId::new();
        let e2 = EntityId::new();
        let e3 = EntityId::new();

        idx.upsert(e1, &[1.0, 0.0, 0.0, 0.0]).unwrap();
        idx.upsert(e2, &[0.0, 1.0, 0.0, 0.0]).unwrap();
        idx.upsert(e3, &[0.9, 0.1, 0.0, 0.0]).unwrap();

        let results = idx.search_similar(&[1.0, 0.0, 0.0, 0.0], 2).unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, RetrievalKey::from(e1));
    }

    #[test]
    fn remove_vector() {
        let idx = VectorIndex::new(4).unwrap();
        let e1 = EntityId::new();

        idx.upsert(e1, &[1.0, 0.0, 0.0, 0.0]).unwrap();
        assert_eq!(idx.len(), 1);

        idx.remove(&e1).unwrap();
        assert_eq!(idx.len(), 0);
    }

    #[test]
    fn upsert_replaces_existing() {
        let idx = VectorIndex::new(4).unwrap();
        let e1 = EntityId::new();

        idx.upsert(e1, &[1.0, 0.0, 0.0, 0.0]).unwrap();
        idx.upsert(e1, &[0.0, 1.0, 0.0, 0.0]).unwrap();

        assert_eq!(idx.len(), 1);

        let results = idx.search_similar(&[0.0, 1.0, 0.0, 0.0], 1).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, RetrievalKey::from(e1));
    }

    #[test]
    fn search_empty_index() {
        let idx = VectorIndex::new(4).unwrap();
        let results = idx.search_similar(&[1.0, 0.0, 0.0, 0.0], 5).unwrap();
        assert!(results.is_empty());
    }

    #[test]
    fn save_reload_preserves_search_coherence() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("vectors.hnsw");

        let idx = VectorIndex::new(4).unwrap();
        let e1 = EntityId::new();
        let e2 = EntityId::new();
        let e3 = EntityId::new();

        idx.upsert(e1, &[1.0, 0.0, 0.0, 0.0]).unwrap();
        idx.upsert(e2, &[0.0, 1.0, 0.0, 0.0]).unwrap();
        idx.upsert(e3, &[0.9, 0.1, 0.0, 0.0]).unwrap();
        idx.save(&path).unwrap();

        let loaded = VectorIndex::load_from_disk(&path).unwrap();
        let results = loaded.search_similar(&[1.0, 0.0, 0.0, 0.0], 2).unwrap();

        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, RetrievalKey::from(e1));
        assert_eq!(results[1].0, RetrievalKey::from(e3));
    }

    #[test]
    fn load_rejects_corrupted_main_index_after_save() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("vectors.hnsw");

        let idx = VectorIndex::new(4).unwrap();
        idx.upsert(EntityId::new(), &[1.0, 0.0, 0.0, 0.0]).unwrap();
        idx.save(&path).unwrap();

        std::fs::write(&path, b"corrupted hnsw index").unwrap();

        let error = VectorIndex::load_from_disk(&path).unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains("failed to deserialize")
                || message.contains("recovery")
                || message.contains("has no current container magic"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn many_vectors_search_quality() {
        let idx = VectorIndex::new(8).unwrap();
        let mut entities = Vec::new();

        for i in 0..100 {
            let eid = EntityId::new();
            let mut vec = [0.0f32; 8];
            vec[i % 8] = 1.0;
            vec[(i + 1) % 8] = 0.5;
            idx.upsert(eid, &vec).unwrap();
            entities.push((eid, vec));
        }

        assert_eq!(idx.len(), 100);

        let results = idx.search_similar(&entities[0].1, 5).unwrap();
        assert!(!results.is_empty());
        // The `i % 8` / `(i + 1) % 8` pattern makes entities 0, 8, 16, … share an
        // identical vector, so the query has many exact (distance-0) matches. The
        // top hit is therefore ANY of those tied entities — asserting one
        // specific (randomly-generated) `EntityId` wins the tie is not a property
        // approximate-kNN guarantees. Assert the search returned a true nearest:
        // the top hit's stored vector equals the query vector.
        let top_vector = idx
            .get_retrievable(&results[0].0)
            .expect("top hit must be retrievable from the index");
        assert_eq!(
            top_vector,
            entities[0].1.to_vec(),
            "top hit must be an exact-match (distance-0) neighbour"
        );
    }

    #[test]
    fn cosine_distance_sanity() {
        assert!((kin_vector::cosine_distance(&[1.0, 0.0], &[1.0, 0.0]) - 0.0).abs() < 1e-6);
        assert!((kin_vector::cosine_distance(&[1.0, 0.0], &[0.0, 1.0]) - 1.0).abs() < 1e-6);
        assert!((kin_vector::cosine_distance(&[1.0, 0.0], &[-1.0, 0.0]) - 2.0).abs() < 1e-6);
    }

    #[test]
    fn load_from_disk_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.hnsw");

        let idx = VectorIndex::new(4).unwrap();
        let e1 = EntityId::new();
        let e2 = EntityId::new();
        idx.upsert(e1, &[1.0, 0.0, 0.0, 0.0]).unwrap();
        idx.upsert(e2, &[0.0, 1.0, 0.0, 0.0]).unwrap();
        idx.save(&path).unwrap();

        // Load without specifying dimensions
        let loaded = VectorIndex::load_from_disk(&path).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded.dimensions(), 4);

        // Search works on loaded index
        let results = loaded.search_similar(&[1.0, 0.0, 0.0, 0.0], 2).unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, RetrievalKey::from(e1));
    }

    #[test]
    fn search_returns_retrieval_keys_for_mixed_ids() {
        let idx = VectorIndex::new(4).unwrap();
        let entity = EntityId::new();
        // Mixed-id search test: the artifact id value is opaque here, so mint one.
        let artifact = kin_model::ArtifactId::new();

        idx.upsert(entity, &[1.0, 0.0, 0.0, 0.0]).unwrap();
        idx.upsert_retrievable(RetrievalKey::Artifact(artifact), &[0.95, 0.05, 0.0, 0.0])
            .unwrap();

        let results = idx.search_similar(&[1.0, 0.0, 0.0, 0.0], 2).unwrap();
        assert_eq!(results[0].0, RetrievalKey::from(entity));
        assert!(results
            .iter()
            .any(|(key, _)| *key == RetrievalKey::Artifact(artifact)));
    }

    #[test]
    fn search_similar_with_roles_enriches_results() {
        let idx = VectorIndex::new(4).unwrap();
        let src_entity = EntityId::new();
        let test_entity = EntityId::new();

        idx.upsert(src_entity, &[1.0, 0.0, 0.0, 0.0]).unwrap();
        idx.upsert(test_entity, &[0.95, 0.05, 0.0, 0.0]).unwrap();

        let mut roles = std::collections::HashMap::new();
        roles.insert(src_entity, EntityRole::Source);
        roles.insert(test_entity, EntityRole::Test);

        let hits = idx
            .search_similar_with_roles(&[1.0, 0.0, 0.0, 0.0], 5, |id| roles.get(id).copied())
            .unwrap();

        assert_eq!(hits.len(), 2);
        // First hit should be the closest (src_entity)
        assert_eq!(hits[0].key, RetrievalKey::from(src_entity));
        assert_eq!(hits[0].role, Some(EntityRole::Source));
        assert_eq!(hits[1].key, RetrievalKey::from(test_entity));
        assert_eq!(hits[1].role, Some(EntityRole::Test));
    }

    #[test]
    fn search_similar_with_roles_artifacts_get_none_role() {
        let idx = VectorIndex::new(4).unwrap();
        // Role resolution ignores artifact id values; any graph-assigned id works.
        let artifact = kin_model::ArtifactId::new();

        idx.upsert_retrievable(RetrievalKey::Artifact(artifact), &[1.0, 0.0, 0.0, 0.0])
            .unwrap();

        let hits = idx
            .search_similar_with_roles(&[1.0, 0.0, 0.0, 0.0], 5, |_| None)
            .unwrap();

        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].role, None);
    }

    #[test]
    fn producer_lineage_distinguishes_raw_and_actual_writes_and_survives_removal() {
        let raw = VectorIndex::new(4).unwrap();
        raw.upsert(EntityId::new(), &[1.0, 0.0, 0.0, 0.0]).unwrap();
        assert_eq!(
            raw.actual_producers(),
            EmbeddingProducerSet::singleton(EmbeddingProducer::Unspecified)
        );

        let index = VectorIndex::new(4).unwrap();
        let cpu_key = RetrievalKey::from(EntityId::new());
        let metal_key = RetrievalKey::from(EntityId::new());
        let cpu = EmbeddingProducerSet::singleton(EmbeddingProducer::Cpu);
        let metal = EmbeddingProducerSet::singleton(EmbeddingProducer::Metal);
        index
            .upsert_retrievable_with_producers(cpu_key, &[1.0, 0.0, 0.0, 0.0], &cpu)
            .unwrap();
        index
            .upsert_retrievable_with_producers(metal_key, &[0.0, 1.0, 0.0, 0.0], &metal)
            .unwrap();
        let mut expected = cpu;
        expected.extend(&metal);
        assert_eq!(index.actual_producers(), expected);

        let cuda = EmbeddingProducerSet::singleton(EmbeddingProducer::Cuda);
        index
            .upsert_retrievable_with_producers(cpu_key, &[0.0, 0.0, 1.0, 0.0], &cuda)
            .unwrap();
        expected.extend(&cuda);
        assert_eq!(
            index.actual_producers(),
            expected,
            "replacement must conservatively retain old lineage and add the actual new producer"
        );

        index.remove_retrievable(&metal_key).unwrap();
        assert_eq!(
            index.actual_producers(),
            expected,
            "removal must preserve conservative producer lineage"
        );
    }

    #[test]
    fn failed_upsert_does_not_change_actual_producer_lineage() {
        let index = VectorIndex::new(4).unwrap();
        let key = RetrievalKey::from(EntityId::new());
        let cpu = EmbeddingProducerSet::singleton(EmbeddingProducer::Cpu);
        index
            .upsert_retrievable_with_producers(key, &[1.0, 0.0, 0.0, 0.0], &cpu)
            .unwrap();
        let before = index.actual_producers();
        let before_vector = index.get_retrievable(&key);
        let before_count = index.len();

        let metal = EmbeddingProducerSet::singleton(EmbeddingProducer::Metal);
        let error = index
            .upsert_retrievable_with_producers(key, &[1.0, 0.0], &metal)
            .expect_err("wrong-dimensional vector must fail before lineage changes");
        assert!(error.to_string().contains("dimension"));
        assert_eq!(index.actual_producers(), before);
        assert_eq!(index.len(), before_count);
        assert_eq!(index.get_retrievable(&key), before_vector);
    }

    #[test]
    fn producer_trailer_round_trip_is_canonical_and_exactly_bound() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("producer-bound.kvec");
        let index = VectorIndex::new(4).unwrap();
        let cpu = EmbeddingProducerSet::singleton(EmbeddingProducer::Cpu);
        let metal = EmbeddingProducerSet::singleton(EmbeddingProducer::Metal);
        index
            .upsert_retrievable_with_producers(
                RetrievalKey::from(EntityId::new()),
                &[1.0, 0.0, 0.0, 0.0],
                &cpu,
            )
            .unwrap();
        index
            .upsert_retrievable_with_producers(
                RetrievalKey::from(EntityId::new()),
                &[0.0, 1.0, 0.0, 0.0],
                &metal,
            )
            .unwrap();
        let mut producers = cpu;
        producers.extend(&metal);
        let mut reverse_insertion = EmbeddingProducerSet::singleton(EmbeddingProducer::Metal);
        reverse_insertion.insert(EmbeddingProducer::Cpu);
        assert_eq!(
            encode_unsigned_producer_trailer(17, &producers).unwrap(),
            encode_unsigned_producer_trailer(17, &reverse_insertion).unwrap(),
            "trailer bytes must not depend on producer insertion order"
        );
        index.set_descriptor(descriptor("model-A@1", "root-1"));
        index.save(&path).unwrap();

        let bytes = std::fs::read(&path).unwrap();
        let base_end = exact_v2_base_end(&bytes);
        let rebound = bind_vector_index_producers_to_bytes(&bytes[..base_end], &producers).unwrap();
        assert_eq!(bytes, rebound, "save and byte binding must be canonical");
        assert_eq!(
            VectorIndex::producer_provenance_from_path(&path).unwrap(),
            VectorProducerProvenance::Known(producers.clone())
        );

        let loaded = VectorIndex::load_from_disk(&path).unwrap();
        assert_eq!(loaded.actual_producers(), producers);
        assert_eq!(loaded.len(), 2);
    }

    #[test]
    fn released_kin_vector_accepts_the_current_trailed_v2_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("released-parser-trailed.kvec");
        let index = VectorIndex::new(4).unwrap();
        let key = RetrievalKey::from(EntityId::new());
        let producers = EmbeddingProducerSet::singleton(EmbeddingProducer::Cpu);
        let expected_descriptor = descriptor("released-parser-model", "released-parser-root");
        index
            .upsert_retrievable_with_producers(key, &[1.0, 0.0, 0.0, 0.0], &producers)
            .unwrap();
        index.set_descriptor(expected_descriptor.clone());
        index.save(&path).unwrap();

        let released = kin_vector::VectorIndex::<RetrievalKey>::load_from_disk(&path)
            .expect("the exact released kin-vector parser must accept trailing KinDB evidence");
        assert_eq!(released.len(), 1);
        assert_eq!(released.dimensions(), 4);
        assert_eq!(released.descriptor(), expected_descriptor);
        assert_eq!(released.get(&key).unwrap(), vec![1.0, 0.0, 0.0, 0.0]);
    }

    #[test]
    fn only_an_exact_readable_v1_container_is_unknown_legacy() {
        let legacy = genuine_legacy_kvec_bytes(KVEC_V1_VERSION);
        assert!(matches!(
            VectorIndex::producer_provenance_from_bytes(&legacy).unwrap(),
            VectorProducerProvenance::UnknownLegacy { .. }
        ));

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("legacy-v1.kvec");
        std::fs::write(&path, &legacy).unwrap();
        assert!(matches!(
            VectorIndex::producer_provenance_from_path(&path).unwrap(),
            VectorProducerProvenance::UnknownLegacy { .. }
        ));

        for incompatible in [
            b"arbitrary garbage".as_slice(),
            PRODUCER_TRAILER_START_MAGIC.as_slice(),
        ] {
            assert!(VectorIndex::producer_provenance_from_bytes(incompatible).is_err());
            assert!(matches!(
                VectorIndex::inspect_producer_provenance_from_bytes(incompatible),
                VectorProducerProvenance::Incompatible { .. }
            ));
        }

        let mut partial_current = legacy.clone();
        partial_current.extend_from_slice(&PRODUCER_TRAILER_START_MAGIC[..4]);
        assert!(VectorIndex::producer_provenance_from_bytes(&partial_current).is_err());
        assert!(matches!(
            VectorIndex::inspect_producer_provenance_from_bytes(&partial_current),
            VectorProducerProvenance::Incompatible { .. }
        ));

        let future_legacy = genuine_legacy_kvec_bytes(KVEC_V1_VERSION + 1);
        assert!(VectorIndex::producer_provenance_from_bytes(&future_legacy).is_err());

        let oversized_path = dir.path().join("oversized-legacy.kvec");
        let oversized = File::create(&oversized_path).unwrap();
        oversized
            .set_len(MAX_LEGACY_PROVENANCE_DECODE_BYTES + 1)
            .unwrap();
        drop(oversized);
        // Assert the CAP's own wording, not merely that an error came back. This
        // fixture is zeroes, so it is undecodable as a v1 container anyway; a
        // bare is_err() passes whether the size bound refused it before decoding
        // or the decoder refused it after, which is the whole property.
        let oversized_error = VectorIndex::producer_provenance_from_path(&oversized_path)
            .expect_err("a legacy container above the classification bound must fail closed");
        assert!(
            oversized_error.to_string().contains(&format!(
                "above the bounded {MAX_LEGACY_PROVENANCE_DECODE_BYTES}-byte provenance classification limit"
            )),
            "the refusal must come from the size bound before decoding: {oversized_error}"
        );
        assert!(matches!(
            VectorIndex::inspect_producer_provenance_from_path(&oversized_path).unwrap(),
            VectorProducerProvenance::Incompatible { .. }
        ));
    }

    #[test]
    fn producer_trailer_rejects_junk_truncation_tampering_and_unbounded_length() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("producer-tamper.kvec");
        let index = VectorIndex::new(4).unwrap();
        let producers = EmbeddingProducerSet::singleton(EmbeddingProducer::Cpu);
        index
            .upsert_retrievable_with_producers(
                RetrievalKey::from(EntityId::new()),
                &[1.0, 0.0, 0.0, 0.0],
                &producers,
            )
            .unwrap();
        index.save(&path).unwrap();
        let bytes = std::fs::read(path).unwrap();
        let base_end = exact_v2_base_end(&bytes);

        assert!(matches!(
            VectorIndex::producer_provenance_from_bytes(&bytes[..base_end]).unwrap(),
            VectorProducerProvenance::UnknownLegacy { .. }
        ));

        let mut junk = bytes[..base_end].to_vec();
        junk.push(0x7f);
        assert!(VectorIndex::producer_provenance_from_bytes(&junk).is_err());
        assert!(matches!(
            VectorIndex::inspect_producer_provenance_from_bytes(&junk),
            VectorProducerProvenance::Incompatible { .. }
        ));

        for truncated_len in (base_end + 1)..bytes.len() {
            assert!(
                VectorIndex::producer_provenance_from_bytes(&bytes[..truncated_len]).is_err(),
                "every partial current trailer must be incompatible at length {truncated_len}"
            );
        }

        let mut tag_tampered = bytes.clone();
        tag_tampered[base_end + PRODUCER_TRAILER_FIXED_UNSIGNED_BYTES] =
            producer_tag(EmbeddingProducer::Metal);
        assert!(VectorIndex::producer_provenance_from_bytes(&tag_tampered).is_err());

        let mut unbounded = bytes.clone();
        let footer_len = unbounded.len() - 16;
        unbounded[footer_len..footer_len + 8]
            .copy_from_slice(&((MAX_PRODUCER_TRAILER_BYTES as u64) + 1).to_le_bytes());
        assert!(VectorIndex::producer_provenance_from_bytes(&unbounded).is_err());

        let mut inserted_junk = bytes.clone();
        inserted_junk.insert(base_end, 0x00);
        assert!(VectorIndex::producer_provenance_from_bytes(&inserted_junk).is_err());

        let base = &bytes[..base_end];
        let producers = {
            let mut set = EmbeddingProducerSet::singleton(EmbeddingProducer::Cpu);
            set.insert(EmbeddingProducer::Metal);
            set
        };
        let canonical = encode_unsigned_producer_trailer(base_end as u64, &producers).unwrap();
        let mut future_version = canonical.clone();
        future_version[8..12].copy_from_slice(&2u32.to_le_bytes());
        assert!(
            VectorIndex::producer_provenance_from_bytes(&bind_test_unsigned_trailer(
                base,
                &future_version,
            ))
            .is_err()
        );

        let mut duplicate = canonical.clone();
        duplicate[PRODUCER_TRAILER_FIXED_UNSIGNED_BYTES..].copy_from_slice(&[1, 1]);
        assert!(
            VectorIndex::producer_provenance_from_bytes(&bind_test_unsigned_trailer(
                base, &duplicate,
            ))
            .is_err()
        );

        let mut descending = canonical.clone();
        descending[PRODUCER_TRAILER_FIXED_UNSIGNED_BYTES..].copy_from_slice(&[2, 1]);
        assert!(
            VectorIndex::producer_provenance_from_bytes(&bind_test_unsigned_trailer(
                base,
                &descending,
            ))
            .is_err()
        );

        let mut unknown = canonical.clone();
        unknown[PRODUCER_TRAILER_FIXED_UNSIGNED_BYTES + 1] = 9;
        assert!(
            VectorIndex::producer_provenance_from_bytes(&bind_test_unsigned_trailer(
                base, &unknown,
            ))
            .is_err()
        );

        let mut wrong_base_len = canonical.clone();
        wrong_base_len[12..20].copy_from_slice(&((base_end as u64) + 1).to_le_bytes());
        assert!(
            VectorIndex::producer_provenance_from_bytes(&bind_test_unsigned_trailer(
                base,
                &wrong_base_len,
            ))
            .is_err()
        );

        let mut wrong_count = canonical.clone();
        wrong_count[20] = 1;
        assert!(
            VectorIndex::producer_provenance_from_bytes(&bind_test_unsigned_trailer(
                base,
                &wrong_count,
            ))
            .is_err()
        );

        let mut wrong_magic = canonical.clone();
        wrong_magic[0] ^= 0x01;
        assert!(
            VectorIndex::producer_provenance_from_bytes(&bind_test_unsigned_trailer(
                base,
                &wrong_magic,
            ))
            .is_err()
        );

        let mut junk_base = base.to_vec();
        junk_base.push(0x00);
        let junk_unsigned =
            encode_unsigned_producer_trailer(junk_base.len() as u64, &producers).unwrap();
        assert!(
            VectorIndex::producer_provenance_from_bytes(&bind_test_unsigned_trailer(
                &junk_base,
                &junk_unsigned,
            ))
            .is_err()
        );
    }

    #[test]
    fn producer_trailer_extent_overflow_and_mismatch_refuse_before_allocation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("extent.kvec");
        let index = VectorIndex::new(4).unwrap();
        index
            .upsert(EntityId::new(), &[1.0, 0.0, 0.0, 0.0])
            .unwrap();
        index.save(&path).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        let base_end = exact_v2_base_end(&bytes);
        let base = &bytes[..base_end];

        for (offset, value) in [
            (16usize, u64::MAX),
            (24usize, u64::MAX),
            (32usize, u64::MAX),
        ] {
            let mut malformed = base.to_vec();
            malformed[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
            assert!(
                VectorIndex::producer_provenance_from_bytes(&malformed).is_err(),
                "overflowing v2 extent field at offset {offset} must refuse"
            );
        }

        let mut beyond_file = base.to_vec();
        beyond_file[16..24].copy_from_slice(&((base.len() as u64) + 4096).to_le_bytes());
        assert!(VectorIndex::producer_provenance_from_bytes(&beyond_file).is_err());
    }

    #[test]
    fn save_receipt_binds_shape_and_producers_before_index_promotion() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("receipt.kvec");
        let index = VectorIndex::new(4).unwrap();
        let producers = EmbeddingProducerSet::singleton(EmbeddingProducer::Cpu);
        index
            .upsert_retrievable_with_producers(
                RetrievalKey::from(EntityId::new()),
                &[1.0, 0.0, 0.0, 0.0],
                &producers,
            )
            .unwrap();
        let captured = std::sync::Mutex::new(None);
        index
            .save_with_provenance(&path, Some(descriptor("model-A@1", "root-1")), |receipt| {
                assert!(
                    !path.exists(),
                    "metadata callback must run before final index promotion"
                );
                *captured.lock().unwrap() = Some(receipt.clone());
                Ok(())
            })
            .unwrap();
        assert!(path.exists());
        let receipt = captured.lock().unwrap().clone().unwrap();
        assert_eq!(receipt.dimensions, 4);
        assert_eq!(receipt.indexed, 1);
        assert_eq!(receipt.actual_producers, producers);
        let (_, persisted_binding) =
            VectorIndex::current_producer_binding_from_bytes(&std::fs::read(&path).unwrap())
                .unwrap()
                .unwrap();
        assert_eq!(receipt.index_binding_sha256, persisted_binding);

        let refused_path = dir.path().join("refused.kvec");
        let error = index
            .save_with_provenance(&refused_path, None, |_| {
                Err(KinDbError::StorageError("metadata refused".to_string()))
            })
            .unwrap_err();
        assert!(error.to_string().contains("metadata refused"));
        assert!(!refused_path.exists());
        let stranded: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| name.contains("producer-base"))
            .collect();
        assert!(stranded.is_empty(), "stranded vector stages: {stranded:?}");
    }

    #[test]
    fn save_and_produced_upsert_share_one_mutation_frontier() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("save-frontier.kvec");
        let index = std::sync::Arc::new(VectorIndex::new(4).unwrap());
        let cpu_key = RetrievalKey::from(EntityId::new());
        let metal_key = RetrievalKey::from(EntityId::new());
        let cpu = EmbeddingProducerSet::singleton(EmbeddingProducer::Cpu);
        let metal = EmbeddingProducerSet::singleton(EmbeddingProducer::Metal);
        index
            .upsert_retrievable_with_producers(cpu_key, &[1.0, 0.0, 0.0, 0.0], &cpu)
            .unwrap();

        let entered = std::sync::Arc::new(std::sync::Barrier::new(2));
        let release = std::sync::Arc::new(std::sync::Barrier::new(2));
        let (receipt_tx, receipt_rx) = std::sync::mpsc::channel();
        let saver_index = std::sync::Arc::clone(&index);
        let saver_path = path.clone();
        let saver_entered = std::sync::Arc::clone(&entered);
        let saver_release = std::sync::Arc::clone(&release);
        let saver = std::thread::spawn(move || {
            saver_index.save_with_provenance(&saver_path, None, |receipt| {
                receipt_tx.send(receipt.clone()).unwrap();
                saver_entered.wait();
                saver_release.wait();
                Ok(())
            })
        });
        entered.wait();
        let receipt = receipt_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap();

        let writer_index = std::sync::Arc::clone(&index);
        let (writer_tx, writer_rx) = std::sync::mpsc::channel();
        let writer = std::thread::spawn(move || {
            let result = writer_index.upsert_retrievable_with_producers(
                metal_key,
                &[0.0, 1.0, 0.0, 0.0],
                &metal,
            );
            writer_tx.send(result).unwrap();
        });
        assert!(
            writer_rx
                .recv_timeout(std::time::Duration::from_millis(50))
                .is_err(),
            "produced upsert must wait while the exact save frontier is held"
        );

        release.wait();
        let saved_receipt = saver.join().unwrap().unwrap();
        writer_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .unwrap()
            .unwrap();
        writer.join().unwrap();
        assert_eq!(receipt, saved_receipt);
        assert_eq!(saved_receipt.indexed, 1);
        assert_eq!(saved_receipt.actual_producers, cpu);

        let saved = VectorIndex::load_from_disk(&path).unwrap();
        assert_eq!(saved.len(), 1);
        assert_eq!(saved.actual_producers(), cpu);
        assert_eq!(index.len(), 2);
        let mut live = cpu;
        live.insert(EmbeddingProducer::Metal);
        assert_eq!(index.actual_producers(), live);
    }

    #[test]
    fn actual_producer_readback_waits_for_the_mutation_frontier() {
        let index = std::sync::Arc::new(VectorIndex::new(4).unwrap());
        let key = RetrievalKey::from(EntityId::new());
        let entered = std::sync::Arc::new(std::sync::Barrier::new(2));
        let release = std::sync::Arc::new(std::sync::Barrier::new(2));
        let entered_hook = std::sync::Arc::clone(&entered);
        let release_hook = std::sync::Arc::clone(&release);
        set_producer_frontier_hook(
            Some(key),
            Some(std::sync::Arc::new(move || {
                entered_hook.wait();
                release_hook.wait();
            })),
        );

        let writer_index = std::sync::Arc::clone(&index);
        let writer = std::thread::spawn(move || {
            writer_index
                .upsert_retrievable_with_producers(
                    key,
                    &[1.0, 0.0, 0.0, 0.0],
                    &EmbeddingProducerSet::singleton(EmbeddingProducer::Cpu),
                )
                .unwrap();
        });
        entered.wait();
        assert!(
            index.contains_retrievable(&key),
            "hook must pause after the vector lands and before producer union"
        );

        let (tx, rx) = std::sync::mpsc::channel();
        let reader_index = std::sync::Arc::clone(&index);
        let reader = std::thread::spawn(move || {
            tx.send(reader_index.actual_producers()).unwrap();
        });
        let early = rx.recv_timeout(std::time::Duration::from_millis(50));
        let was_blocked = early.is_err();
        release.wait();
        writer.join().unwrap();
        let observed = match early {
            Ok(value) => value,
            Err(_) => rx.recv_timeout(std::time::Duration::from_secs(1)).unwrap(),
        };
        reader.join().unwrap();
        set_producer_frontier_hook(None, None);

        assert!(
            was_blocked,
            "readback must not observe the new vector with the old producer set"
        );
        assert_eq!(
            observed,
            EmbeddingProducerSet::singleton(EmbeddingProducer::Cpu)
        );
    }

    fn descriptor(model: &str, root: &str) -> IndexDescriptor {
        IndexDescriptor {
            model_id: Some(model.to_string()),
            graph_root: Some(root.to_string()),
        }
    }

    #[test]
    fn load_compatible_accepts_match_and_rejects_model_or_graph_swap() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("vectors.hnsw");

        let idx = VectorIndex::new(4).unwrap();
        idx.upsert(EntityId::new(), &[1.0, 0.0, 0.0, 0.0]).unwrap();
        idx.set_descriptor(descriptor("model-A@1", "root-1"));
        idx.save(&path).unwrap();

        // Exact match loads.
        assert!(matches!(
            VectorIndex::load_compatible(&path, &descriptor("model-A@1", "root-1")),
            IndexLoadOutcome::Loaded(_)
        ));
        // Same dimension, DIFFERENT model → incompatible (would be silently-wrong).
        assert!(matches!(
            VectorIndex::load_compatible(&path, &descriptor("model-B@1", "root-1")),
            IndexLoadOutcome::Incompatible(_)
        ));
        // Graph root changed → incompatible.
        assert!(matches!(
            VectorIndex::load_compatible(&path, &descriptor("model-A@1", "root-2")),
            IndexLoadOutcome::Incompatible(_)
        ));
        // An unbound expectation is never authority.
        assert!(matches!(
            VectorIndex::load_compatible(&path, &IndexDescriptor::default()),
            IndexLoadOutcome::Incompatible(_)
        ));
    }

    #[test]
    fn load_compatible_rejects_unstamped_or_corrupt_index() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("vectors.hnsw");

        let idx = VectorIndex::new(4).unwrap();
        idx.upsert(EntityId::new(), &[1.0, 0.0, 0.0, 0.0]).unwrap();
        // No set_descriptor: an unstamped index cannot prove compatibility.
        idx.save(&path).unwrap();

        // A pinned identity cannot be proven by an unstamped index → incompatible.
        assert!(matches!(
            VectorIndex::load_compatible(
                &path,
                &IndexDescriptor {
                    model_id: Some("model-A@1".into()),
                    graph_root: Some("root-1".into()),
                },
            ),
            IndexLoadOutcome::Incompatible(_)
        ));

        // An unreadable/corrupt index is Incompatible (archive + rebuild), never a crash.
        std::fs::write(&path, b"corrupt").unwrap();
        assert!(matches!(
            VectorIndex::load_compatible(&path, &IndexDescriptor::default()),
            IndexLoadOutcome::Incompatible(_)
        ));
    }
}
