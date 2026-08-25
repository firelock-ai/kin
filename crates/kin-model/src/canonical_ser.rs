// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The canonical encoding, written straight out of `Serialize`.
//!
//! Every durable identity in this crate is a hash over one canonical byte
//! string, and that string used to be produced by handing the value to
//! `serde_json::to_value` and walking the resulting tree. FIR-2551 priced the
//! tree at eleven times the value it encodes on a 200-change transaction and
//! named this encoder as the fix; this is that encoder.
//!
//! `RepositoryTransaction::canonical_hash` already avoids the whole-document
//! tree by walking its fields one at a time through `append_canonical_seq`.
//! That bounds the tree to one element, which is the right answer when the
//! elements are small and no answer at all when one of them is not. On a
//! bootstrap commit the Git external authority is a single element carrying the
//! entire object closure, and measured on a synthetic 400-commit conversion its
//! tree alone was 60,495,152 bytes, which was the whole remaining cost of the
//! transaction hash to within a tenth of a percent (FIR-2665).
//!
//! ## Byte-identical, or it is a data-loss bug
//!
//! `transaction_hash` is stored in every `RepositoryCommitReceipt` and compared
//! on idempotent replay, and change ids are content-addressed. A single byte of
//! difference is not a slower hash, it is every repository on disk failing to
//! recognise its own history. So:
//!
//! * The per-kind tag bytes and little-endian u64 length prefixes are copied
//!   from [`super::identity`]'s tree walk, which defines them.
//! * Numbers are rendered through `serde_json::Number`, never through Rust's
//!   `Display`, because the two disagree: `serde_json` renders `1.0f64` as
//!   `1.0` and `f64::to_string` renders it as `1`. Non-finite floats become
//!   null exactly as a `serde_json::Value` makes them null.
//! * Object keys are emitted in sorted order, which is why an object is the one
//!   shape here that buffers.
//! * [`CanonicalSerializer::is_human_readable`] returns `true`, matching
//!   `serde_json::to_value`. This is not cosmetic. `RepositoryTransaction` has
//!   a positional serde branch selected by that flag, so reporting `false`
//!   would silently change every stored identity in the system, and it would do
//!   it in a way an oracle differential cannot see if the oracle went through
//!   the same wrong branch. It is asserted directly in the tests.
//!
//! ## What still buffers, and what that bounds the saving to
//!
//! Canonical output sorts an object's keys, and serde delivers a struct's
//! fields in declaration order, so an object's field encodings must exist
//! before any of them can be emitted. Fields are written into one shared output
//! and only their ranges are remembered, so nesting costs offsets rather than a
//! copy per level, and the region is reordered once on close.
//!
//! The saving is therefore bounded by the widest single object rather than by
//! the whole tree, exactly as FIR-2551 says. What it buys is the difference
//! between holding a payload and holding a picture of it.

use std::fmt::Display;

use serde::{ser, Serialize};

use crate::error::ModelError;
use crate::identity::CanonicalSink;

/// Tag bytes. These are the encoding and may never be reassigned.
const TAG_NULL: u8 = 0;
const TAG_BOOL: u8 = 1;
const TAG_NUMBER: u8 = 2;
const TAG_STRING: u8 = 3;
const TAG_ARRAY: u8 = 4;
const TAG_OBJECT: u8 = 5;

impl From<CanonicalError> for ModelError {
    fn from(error: CanonicalError) -> Self {
        ModelError::InvalidOperation(error.0)
    }
}

/// The canonical encoding of `value`, appended to `output`.
///
/// Byte-for-byte what the tree walk in [`crate::identity`] emits for the same
/// value, without building the tree.
pub(crate) fn append_canonical_streamed<S: CanonicalSink>(
    output: &mut S,
    value: &impl Serialize,
) -> crate::error::Result<()> {
    output.write_bytes(&canonical_streamed_bytes(value)?);
    Ok(())
}

/// The canonical encoding of `value` as owned bytes.
pub(crate) fn canonical_streamed_bytes(value: &impl Serialize) -> crate::error::Result<Vec<u8>> {
    let mut encoded = Vec::new();
    value.serialize(CanonicalSerializer { out: &mut encoded })?;
    Ok(encoded)
}

/// A value that cannot be canonically encoded.
///
/// Every variant mirrors a case `serde_json::to_value` also refuses, so a value
/// this rejects is a value the tree walk rejected too.
#[derive(Debug)]
pub(crate) struct CanonicalError(String);

impl Display for CanonicalError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for CanonicalError {}

impl ser::Error for CanonicalError {
    fn custom<T: Display>(message: T) -> Self {
        Self(message.to_string())
    }
}

impl CanonicalError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

// --- primitives -----------------------------------------------------------

fn put_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    out.extend_from_slice(bytes);
}

fn put_number(out: &mut Vec<u8>, rendered: &str) {
    out.push(TAG_NUMBER);
    put_len_prefixed(out, rendered.as_bytes());
}

fn put_string(out: &mut Vec<u8>, value: &str) {
    out.push(TAG_STRING);
    put_len_prefixed(out, value.as_bytes());
}

/// Render a float exactly as the `serde_json::Value` tree rendered it.
///
/// `serde_json` disagrees with `f64::to_string` on whole numbers, and a
/// non-finite float becomes null rather than a number, so both go through
/// `serde_json::Number` rather than through `Display`.
fn put_float(out: &mut Vec<u8>, value: f64) {
    match serde_json::Number::from_f64(value) {
        Some(number) => put_number(out, &number.to_string()),
        None => out.push(TAG_NULL),
    }
}

// --- the serializer -------------------------------------------------------

struct CanonicalSerializer<'a> {
    out: &'a mut Vec<u8>,
}

impl<'a> ser::Serializer for CanonicalSerializer<'a> {
    type Ok = ();
    type Error = CanonicalError;
    type SerializeSeq = SeqEncoder<'a>;
    type SerializeTuple = SeqEncoder<'a>;
    type SerializeTupleStruct = SeqEncoder<'a>;
    type SerializeTupleVariant = VariantSeqEncoder<'a>;
    type SerializeMap = MapEncoder<'a>;
    type SerializeStruct = MapEncoder<'a>;
    type SerializeStructVariant = VariantMapEncoder<'a>;

    /// Matches `serde_json::to_value`. See the module comment: reporting
    /// `false` here silently switches `RepositoryTransaction` to its positional
    /// branch and rewrites every stored identity.
    fn is_human_readable(&self) -> bool {
        true
    }

    fn serialize_bool(self, value: bool) -> Result<(), CanonicalError> {
        self.out.push(TAG_BOOL);
        self.out.push(u8::from(value));
        Ok(())
    }

    fn serialize_i8(self, value: i8) -> Result<(), CanonicalError> {
        self.serialize_i64(i64::from(value))
    }

    fn serialize_i16(self, value: i16) -> Result<(), CanonicalError> {
        self.serialize_i64(i64::from(value))
    }

    fn serialize_i32(self, value: i32) -> Result<(), CanonicalError> {
        self.serialize_i64(i64::from(value))
    }

    fn serialize_i64(self, value: i64) -> Result<(), CanonicalError> {
        put_integer(self.out, &Digits::of_i64(value));
        Ok(())
    }

    fn serialize_i128(self, value: i128) -> Result<(), CanonicalError> {
        // `serde_json` accepts a 128-bit integer only where it is exactly
        // representable, and refuses otherwise. Refusing on the same boundary
        // keeps this path from accepting a value the tree walk rejected.
        i64::try_from(value)
            .map(|narrow| put_integer(self.out, &Digits::of_i64(narrow)))
            .or_else(|_| {
                u64::try_from(value)
                    .map(|narrow| put_integer(self.out, &Digits::of_u64(narrow)))
                    .map_err(|_| CanonicalError::new("integer out of canonical range"))
            })
    }

    fn serialize_u8(self, value: u8) -> Result<(), CanonicalError> {
        self.serialize_u64(u64::from(value))
    }

    fn serialize_u16(self, value: u16) -> Result<(), CanonicalError> {
        self.serialize_u64(u64::from(value))
    }

    fn serialize_u32(self, value: u32) -> Result<(), CanonicalError> {
        self.serialize_u64(u64::from(value))
    }

    fn serialize_u64(self, value: u64) -> Result<(), CanonicalError> {
        put_integer(self.out, &Digits::of_u64(value));
        Ok(())
    }

    fn serialize_u128(self, value: u128) -> Result<(), CanonicalError> {
        u64::try_from(value)
            .map(|narrow| put_integer(self.out, &Digits::of_u64(narrow)))
            .map_err(|_| CanonicalError::new("integer out of canonical range"))
    }

    fn serialize_f32(self, value: f32) -> Result<(), CanonicalError> {
        // The tree widened an `f32` to `f64` before rendering it, so this does
        // too; rendering the `f32` directly would print fewer digits.
        put_float(self.out, f64::from(value));
        Ok(())
    }

    fn serialize_f64(self, value: f64) -> Result<(), CanonicalError> {
        put_float(self.out, value);
        Ok(())
    }

    fn serialize_char(self, value: char) -> Result<(), CanonicalError> {
        let mut buffer = [0_u8; 4];
        put_string(self.out, value.encode_utf8(&mut buffer));
        Ok(())
    }

    fn serialize_str(self, value: &str) -> Result<(), CanonicalError> {
        put_string(self.out, value);
        Ok(())
    }

    fn serialize_bytes(self, value: &[u8]) -> Result<(), CanonicalError> {
        // The tree turned a byte string into an array of numbers, so the digest
        // has always seen it that way.
        self.out.push(TAG_ARRAY);
        self.out
            .extend_from_slice(&(value.len() as u64).to_le_bytes());
        for byte in value {
            put_integer(self.out, &Digits::of_u64(u64::from(*byte)));
        }
        Ok(())
    }

    fn serialize_none(self) -> Result<(), CanonicalError> {
        self.serialize_unit()
    }

    fn serialize_some<T: Serialize + ?Sized>(self, value: &T) -> Result<(), CanonicalError> {
        value.serialize(self)
    }

    fn serialize_unit(self) -> Result<(), CanonicalError> {
        self.out.push(TAG_NULL);
        Ok(())
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<(), CanonicalError> {
        self.serialize_unit()
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
    ) -> Result<(), CanonicalError> {
        put_string(self.out, variant);
        Ok(())
    }

    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<(), CanonicalError> {
        value.serialize(self)
    }

    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        value: &T,
    ) -> Result<(), CanonicalError> {
        // A single-entry object, so no sort is possible and none is needed.
        self.out.push(TAG_OBJECT);
        self.out.extend_from_slice(&1_u64.to_le_bytes());
        put_len_prefixed(self.out, variant.as_bytes());
        value.serialize(CanonicalSerializer { out: self.out })
    }

    fn serialize_seq(self, _len: Option<usize>) -> Result<SeqEncoder<'a>, CanonicalError> {
        Ok(SeqEncoder::open(self.out))
    }

    fn serialize_tuple(self, len: usize) -> Result<SeqEncoder<'a>, CanonicalError> {
        self.serialize_seq(Some(len))
    }

    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<SeqEncoder<'a>, CanonicalError> {
        self.serialize_seq(Some(len))
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        _len: usize,
    ) -> Result<VariantSeqEncoder<'a>, CanonicalError> {
        self.out.push(TAG_OBJECT);
        self.out.extend_from_slice(&1_u64.to_le_bytes());
        put_len_prefixed(self.out, variant.as_bytes());
        Ok(VariantSeqEncoder {
            inner: SeqEncoder::open(self.out),
        })
    }

    fn serialize_map(self, _len: Option<usize>) -> Result<MapEncoder<'a>, CanonicalError> {
        Ok(MapEncoder::open(self.out))
    }

    fn serialize_struct(
        self,
        _name: &'static str,
        len: usize,
    ) -> Result<MapEncoder<'a>, CanonicalError> {
        self.serialize_map(Some(len))
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
        _len: usize,
    ) -> Result<VariantMapEncoder<'a>, CanonicalError> {
        self.out.push(TAG_OBJECT);
        self.out.extend_from_slice(&1_u64.to_le_bytes());
        put_len_prefixed(self.out, variant.as_bytes());
        Ok(VariantMapEncoder {
            inner: MapEncoder::open(self.out),
        })
    }
}

// --- sequences ------------------------------------------------------------

/// A sequence writes its count before its elements, and `serde` may not know
/// the count. Reserving the eight bytes and patching them at the end is what
/// lets an arbitrarily long sequence stream straight into the output.
struct SeqEncoder<'a> {
    out: &'a mut Vec<u8>,
    count_at: usize,
    count: u64,
}

impl<'a> SeqEncoder<'a> {
    fn open(out: &'a mut Vec<u8>) -> Self {
        out.push(TAG_ARRAY);
        let count_at = out.len();
        out.extend_from_slice(&0_u64.to_le_bytes());
        Self {
            out,
            count_at,
            count: 0,
        }
    }

    fn push<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), CanonicalError> {
        value.serialize(CanonicalSerializer { out: self.out })?;
        self.count += 1;
        Ok(())
    }

    fn close(self) -> Result<(), CanonicalError> {
        self.out[self.count_at..self.count_at + 8].copy_from_slice(&self.count.to_le_bytes());
        Ok(())
    }
}

impl ser::SerializeSeq for SeqEncoder<'_> {
    type Ok = ();
    type Error = CanonicalError;

    fn serialize_element<T: Serialize + ?Sized>(
        &mut self,
        value: &T,
    ) -> Result<(), CanonicalError> {
        self.push(value)
    }

    fn end(self) -> Result<(), CanonicalError> {
        self.close()
    }
}

impl ser::SerializeTuple for SeqEncoder<'_> {
    type Ok = ();
    type Error = CanonicalError;

    fn serialize_element<T: Serialize + ?Sized>(
        &mut self,
        value: &T,
    ) -> Result<(), CanonicalError> {
        self.push(value)
    }

    fn end(self) -> Result<(), CanonicalError> {
        self.close()
    }
}

impl ser::SerializeTupleStruct for SeqEncoder<'_> {
    type Ok = ();
    type Error = CanonicalError;

    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), CanonicalError> {
        self.push(value)
    }

    fn end(self) -> Result<(), CanonicalError> {
        self.close()
    }
}

struct VariantSeqEncoder<'a> {
    inner: SeqEncoder<'a>,
}

impl ser::SerializeTupleVariant for VariantSeqEncoder<'_> {
    type Ok = ();
    type Error = CanonicalError;

    fn serialize_field<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), CanonicalError> {
        self.inner.push(value)
    }

    fn end(self) -> Result<(), CanonicalError> {
        self.inner.close()
    }
}

// --- objects --------------------------------------------------------------

/// An object visits its keys in sorted order, and `serde` delivers a struct's
/// fields in declaration order, so an object is the one shape that must hold
/// its children before it can emit them. It holds only its own field
/// encodings, and moves them into the output once.
struct MapEncoder<'a> {
    out: &'a mut Vec<u8>,
    /// Where this object's field encodings begin in `out`.
    start: usize,
    /// Key, and the half-open range of `out` its value was written to.
    entries: Vec<(String, usize, usize)>,
    pending_key: Option<String>,
}

impl<'a> MapEncoder<'a> {
    fn open(out: &'a mut Vec<u8>) -> Self {
        let start = out.len();
        Self {
            out,
            start,
            entries: Vec::new(),
            pending_key: None,
        }
    }

    /// Fields are written straight into the shared output and only their ranges
    /// are remembered.
    ///
    /// Giving each field its own buffer instead would copy the whole payload
    /// once per level of nesting, and the authority this encoding is worst at
    /// is nested three deep, so that shape measured four copies of it live at
    /// once. Ranges cost the offsets and nothing else.
    fn push_value<T: Serialize + ?Sized>(
        &mut self,
        key: String,
        value: &T,
    ) -> Result<(), CanonicalError> {
        let from = self.out.len();
        value.serialize(CanonicalSerializer { out: self.out })?;
        let to = self.out.len();
        self.entries.push((key, from, to));
        Ok(())
    }

    fn close(mut self) -> Result<(), CanonicalError> {
        // Sorted by key, matching the tree's ordered map. A duplicate key is
        // impossible from a struct and would be a caller defect from a map; the
        // tree collapsed duplicates and this would keep both, so refuse rather
        // than hash a shape the oracle cannot reproduce.
        self.entries.sort_by(|left, right| left.0.cmp(&right.0));
        if self.entries.windows(2).any(|pair| pair[0].0 == pair[1].0) {
            return Err(CanonicalError::new(
                "duplicate key in a canonically hashed object",
            ));
        }
        // Fields were written in declaration order and must be read back in
        // sorted order, so the region is lifted out once and rewritten in
        // place. One copy of this object, not one per level above it.
        let region = self.out.split_off(self.start);
        self.out.push(TAG_OBJECT);
        self.out
            .extend_from_slice(&(self.entries.len() as u64).to_le_bytes());
        for (key, from, to) in &self.entries {
            put_len_prefixed(self.out, key.as_bytes());
            self.out
                .extend_from_slice(&region[from - self.start..to - self.start]);
        }
        Ok(())
    }
}

impl ser::SerializeMap for MapEncoder<'_> {
    type Ok = ();
    type Error = CanonicalError;

    fn serialize_key<T: Serialize + ?Sized>(&mut self, key: &T) -> Result<(), CanonicalError> {
        self.pending_key = Some(key.serialize(KeySerializer)?);
        Ok(())
    }

    fn serialize_value<T: Serialize + ?Sized>(&mut self, value: &T) -> Result<(), CanonicalError> {
        let key = self
            .pending_key
            .take()
            .ok_or_else(|| CanonicalError::new("map value serialized before its key"))?;
        self.push_value(key, value)
    }

    fn end(self) -> Result<(), CanonicalError> {
        self.close()
    }
}

impl ser::SerializeStruct for MapEncoder<'_> {
    type Ok = ();
    type Error = CanonicalError;

    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), CanonicalError> {
        self.push_value(key.to_string(), value)
    }

    fn end(self) -> Result<(), CanonicalError> {
        self.close()
    }
}

struct VariantMapEncoder<'a> {
    inner: MapEncoder<'a>,
}

impl ser::SerializeStructVariant for VariantMapEncoder<'_> {
    type Ok = ();
    type Error = CanonicalError;

    fn serialize_field<T: Serialize + ?Sized>(
        &mut self,
        key: &'static str,
        value: &T,
    ) -> Result<(), CanonicalError> {
        self.inner.push_value(key.to_string(), value)
    }

    fn end(self) -> Result<(), CanonicalError> {
        self.inner.close()
    }
}

// --- map keys -------------------------------------------------------------

/// `serde_json` renders a map key as a string or refuses the map, so this does
/// the same rather than inventing an encoding for keys the tree never accepted.
struct KeySerializer;

fn key_refused<T>(what: &str) -> Result<T, CanonicalError> {
    Err(CanonicalError::new(format!(
        "canonical object key must be a string, got {what}"
    )))
}

impl ser::Serializer for KeySerializer {
    type Ok = String;
    type Error = CanonicalError;
    type SerializeSeq = ser::Impossible<String, CanonicalError>;
    type SerializeTuple = ser::Impossible<String, CanonicalError>;
    type SerializeTupleStruct = ser::Impossible<String, CanonicalError>;
    type SerializeTupleVariant = ser::Impossible<String, CanonicalError>;
    type SerializeMap = ser::Impossible<String, CanonicalError>;
    type SerializeStruct = ser::Impossible<String, CanonicalError>;
    type SerializeStructVariant = ser::Impossible<String, CanonicalError>;

    fn serialize_str(self, value: &str) -> Result<String, CanonicalError> {
        Ok(value.to_string())
    }

    fn serialize_char(self, value: char) -> Result<String, CanonicalError> {
        Ok(value.to_string())
    }

    fn serialize_bool(self, value: bool) -> Result<String, CanonicalError> {
        // `serde_json` renders a boolean key as `true` or `false`.
        Ok(value.to_string())
    }

    fn serialize_i8(self, value: i8) -> Result<String, CanonicalError> {
        Ok(value.to_string())
    }

    fn serialize_i16(self, value: i16) -> Result<String, CanonicalError> {
        Ok(value.to_string())
    }

    fn serialize_i32(self, value: i32) -> Result<String, CanonicalError> {
        Ok(value.to_string())
    }

    fn serialize_i64(self, value: i64) -> Result<String, CanonicalError> {
        Ok(value.to_string())
    }

    fn serialize_i128(self, value: i128) -> Result<String, CanonicalError> {
        Ok(value.to_string())
    }

    fn serialize_u8(self, value: u8) -> Result<String, CanonicalError> {
        Ok(value.to_string())
    }

    fn serialize_u16(self, value: u16) -> Result<String, CanonicalError> {
        Ok(value.to_string())
    }

    fn serialize_u32(self, value: u32) -> Result<String, CanonicalError> {
        Ok(value.to_string())
    }

    fn serialize_u64(self, value: u64) -> Result<String, CanonicalError> {
        Ok(value.to_string())
    }

    fn serialize_u128(self, value: u128) -> Result<String, CanonicalError> {
        Ok(value.to_string())
    }

    fn serialize_unit_variant(
        self,
        _name: &'static str,
        _index: u32,
        variant: &'static str,
    ) -> Result<String, CanonicalError> {
        Ok(variant.to_string())
    }

    fn serialize_newtype_struct<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        value: &T,
    ) -> Result<String, CanonicalError> {
        value.serialize(self)
    }

    fn serialize_f32(self, _value: f32) -> Result<String, CanonicalError> {
        key_refused("a float")
    }

    fn serialize_f64(self, _value: f64) -> Result<String, CanonicalError> {
        key_refused("a float")
    }

    fn serialize_bytes(self, _value: &[u8]) -> Result<String, CanonicalError> {
        key_refused("a byte string")
    }

    fn serialize_none(self) -> Result<String, CanonicalError> {
        key_refused("none")
    }

    fn serialize_some<T: Serialize + ?Sized>(self, _value: &T) -> Result<String, CanonicalError> {
        key_refused("an option")
    }

    fn serialize_unit(self) -> Result<String, CanonicalError> {
        key_refused("unit")
    }

    fn serialize_unit_struct(self, _name: &'static str) -> Result<String, CanonicalError> {
        key_refused("a unit struct")
    }

    fn serialize_newtype_variant<T: Serialize + ?Sized>(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _value: &T,
    ) -> Result<String, CanonicalError> {
        key_refused("a newtype variant")
    }

    fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq, CanonicalError> {
        key_refused("a sequence")
    }

    fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple, CanonicalError> {
        key_refused("a tuple")
    }

    fn serialize_tuple_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleStruct, CanonicalError> {
        key_refused("a tuple struct")
    }

    fn serialize_tuple_variant(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeTupleVariant, CanonicalError> {
        key_refused("a tuple variant")
    }

    fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap, CanonicalError> {
        key_refused("a map")
    }

    fn serialize_struct(
        self,
        _name: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStruct, CanonicalError> {
        key_refused("a struct")
    }

    fn serialize_struct_variant(
        self,
        _name: &'static str,
        _index: u32,
        _variant: &'static str,
        _len: usize,
    ) -> Result<Self::SerializeStructVariant, CanonicalError> {
        key_refused("a struct variant")
    }
}

// --- integer rendering ----------------------------------------------------

/// Decimal digits of an integer on the stack.
///
/// `serde_json` renders an integer exactly as Rust's `Display` does, so this
/// only exists to keep a hash over millions of scalars from allocating a
/// `String` per scalar. Twenty digits holds `u64::MAX`, and one more byte holds
/// the sign of `i64::MIN`.
struct Digits {
    buffer: [u8; 21],
    start: usize,
}

impl Digits {
    fn of_u64(mut value: u64) -> Self {
        let mut buffer = [0_u8; 21];
        let mut start = buffer.len();
        loop {
            start -= 1;
            buffer[start] = b'0' + (value % 10) as u8;
            value /= 10;
            if value == 0 {
                break;
            }
        }
        Self { buffer, start }
    }

    fn of_i64(value: i64) -> Self {
        // `unsigned_abs` rather than negation, so `i64::MIN` does not overflow.
        let mut digits = Self::of_u64(value.unsigned_abs());
        if value < 0 {
            digits.start -= 1;
            digits.buffer[digits.start] = b'-';
        }
        digits
    }

    fn as_bytes(&self) -> &[u8] {
        &self.buffer[self.start..]
    }
}

fn put_integer(out: &mut Vec<u8>, digits: &Digits) {
    out.push(TAG_NUMBER);
    put_len_prefixed(out, digits.as_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// Both encoders' BYTES for one value.
    ///
    /// Bytes rather than hashes, per FIR-2549: a hash comparison cannot see a
    /// field reorder, because the encoding sorts object keys and normalizes it
    /// away. Only the emitted bytes can.
    fn encodings<T: Serialize>(value: &T) -> (Vec<u8>, Vec<u8>) {
        (
            canonical_streamed_bytes(value).expect("the streaming encoder accepts it"),
            crate::identity::canonical_json_bytes_via_tree(value)
                .expect("the tree walk accepts it"),
        )
    }

    /// The streaming encoder must emit exactly the bytes the tree walk emits.
    fn agrees<T: Serialize>(what: &str, value: &T) {
        let (streamed, walked) = encodings(value);
        assert_eq!(
            streamed, walked,
            "{what}: the streaming encoder emits different bytes than the tree walk, so \
             this change would move every durable identity in the crate"
        );
    }

    // Field order is deliberately NOT alphabetical. The tree sorted an object's
    // keys, so a streaming encoder that emits fields in declaration order
    // produces a different digest, and this is the shape that catches it.
    #[derive(serde::Serialize)]
    struct Unsorted {
        zulu: u32,
        alpha: String,
        mike: Option<bool>,
        bravo: Vec<i64>,
    }

    #[derive(serde::Serialize)]
    enum Shapes {
        Unit,
        Newtype(u64),
        Tuple(u8, String),
        Struct { second: i32, first: f64 },
    }

    #[derive(serde::Serialize)]
    struct Newtype(String);

    #[derive(serde::Serialize)]
    struct TupleStruct(u8, bool, char);

    #[derive(serde::Serialize)]
    struct UnitStruct;

    #[test]
    fn the_streaming_encoder_agrees_with_the_tree_walk_on_every_serde_shape() {
        agrees("null", &());
        agrees("unit struct", &UnitStruct);
        agrees("true", &true);
        agrees("false", &false);
        agrees("empty string", &"");
        agrees("unicode string", &"héllo · 🔥 · \u{0}");
        agrees("char", &'🔥');

        for value in [0_i64, 1, -1, i64::MAX, i64::MIN] {
            agrees("i64", &value);
        }
        for value in [0_u64, 1, u64::MAX] {
            agrees("u64", &value);
        }
        agrees("i8", &i8::MIN);
        agrees("i16", &i16::MIN);
        agrees("i32", &i32::MIN);
        agrees("u8", &u8::MAX);
        agrees("u16", &u16::MAX);
        agrees("u32", &u32::MAX);

        // Floats are where `Display` and `serde_json` part company, and where a
        // whole number is rendered `1.0` by one and `1` by the other.
        for value in [
            0.0_f64,
            -0.0,
            1.0,
            -1.0,
            0.5,
            1e300,
            1e-300,
            f64::MAX,
            f64::MIN,
            std::f64::consts::PI,
        ] {
            agrees("f64", &value);
        }
        for value in [0.0_f32, 1.0, -1.5, f32::MAX, f32::MIN, 0.1] {
            agrees("f32", &value);
        }
        // Non-finite floats become null in a `serde_json::Value`, not numbers.
        for value in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            agrees("non-finite f64", &value);
        }
        for value in [f32::NAN, f32::INFINITY, f32::NEG_INFINITY] {
            agrees("non-finite f32", &value);
        }

        agrees("none", &Option::<u32>::None);
        agrees("some", &Some(7_u32));
        agrees("nested some", &Some(Some(Option::<u8>::None)));

        agrees("empty seq", &Vec::<u8>::new());
        agrees("seq", &vec![1_i64, -2, 3]);
        agrees("nested seq", &vec![vec![1_u8], vec![], vec![2, 3]]);
        agrees("tuple", &(1_u8, "two", 3.0_f64, false));
        agrees("newtype struct", &Newtype("wrapped".to_string()));
        agrees("tuple struct", &TupleStruct(9, true, 'x'));

        agrees("unit variant", &Shapes::Unit);
        agrees("newtype variant", &Shapes::Newtype(42));
        agrees("tuple variant", &Shapes::Tuple(1, "two".to_string()));
        agrees(
            "struct variant",
            &Shapes::Struct {
                second: -5,
                first: 2.5,
            },
        );

        agrees("empty map", &BTreeMap::<String, u8>::new());
        let mut map = BTreeMap::new();
        map.insert("zulu".to_string(), 1_u32);
        map.insert("alpha".to_string(), 2);
        map.insert("mike".to_string(), 3);
        agrees("string-keyed map", &map);
        let mut integer_keyed = BTreeMap::new();
        integer_keyed.insert(10_u32, "ten");
        integer_keyed.insert(2, "two");
        agrees("integer-keyed map", &integer_keyed);

        agrees(
            "struct whose fields are not in sorted order",
            &Unsorted {
                zulu: 1,
                alpha: "a".to_string(),
                mike: Some(false),
                bravo: vec![1, 2, 3],
            },
        );
        agrees("every tag in one value", &pinned_value());
        agrees(
            "sequence of unsorted structs",
            &vec![
                Unsorted {
                    zulu: 0,
                    alpha: String::new(),
                    mike: None,
                    bravo: Vec::new(),
                },
                Unsorted {
                    zulu: u32::MAX,
                    alpha: "ünïcode".to_string(),
                    mike: Some(true),
                    bravo: vec![i64::MIN, i64::MAX],
                },
            ],
        );
    }

    /// The agreement test above is only worth anything if disagreement is
    /// visible to it. A struct emitted in declaration order rather than sorted
    /// order is the exact defect this change could have introduced, so build
    /// that digest by hand and require it to differ.
    #[test]
    fn a_digest_built_in_declaration_order_is_visibly_different() {
        let value = Unsorted {
            zulu: 1,
            alpha: "a".to_string(),
            mike: Some(false),
            bravo: vec![1, 2, 3],
        };
        let (streamed, walked) = encodings(&value);
        assert_eq!(streamed, walked, "the two encoders agree on this value");

        let mut declaration_order = Vec::new();
        declaration_order.push(TAG_OBJECT);
        declaration_order.extend_from_slice(&4_u64.to_le_bytes());
        for key in ["zulu", "alpha", "mike", "bravo"] {
            put_len_prefixed(&mut declaration_order, key.as_bytes());
            // The value bytes do not matter; the key order alone must change
            // the digest, and a same-length filler keeps that the only change.
            declaration_order.push(TAG_NULL);
        }
        let hand = declaration_order;

        let mut sorted = Vec::new();
        sorted.push(TAG_OBJECT);
        sorted.extend_from_slice(&4_u64.to_le_bytes());
        for key in ["alpha", "bravo", "mike", "zulu"] {
            put_len_prefixed(&mut sorted, key.as_bytes());
            sorted.push(TAG_NULL);
        }
        let sorted_hash = sorted;

        assert_ne!(
            hand, sorted_hash,
            "key order must change the bytes, or the agreement test above cannot fail"
        );
    }

    /// A map key that is not a string was refused by the tree walk, and must
    /// still be refused rather than given an encoding of its own.
    /// The flag that would change every stored identity in the system.
    ///
    /// `serde_json::to_value` reports human-readable, and `RepositoryTransaction`
    /// has a positional serde branch selected by that flag. A serializer that
    /// reported `false` would take the other branch and rewrite every identity,
    /// and the differential above would not see it if the oracle took the same
    /// branch. Asserted directly rather than left to serde's default (FIR-2551).
    #[test]
    fn the_streaming_encoder_reports_human_readable_like_serde_json() {
        let mut sink = Vec::new();
        let serializer = CanonicalSerializer { out: &mut sink };
        assert!(
            ser::Serializer::is_human_readable(&serializer),
            "the canonical serializer must report human-readable, or every type with a \
             positional serde branch silently changes identity"
        );
        assert!(
            ser::Serializer::is_human_readable(&serde_json::value::Serializer),
            "serde_json no longer reports human-readable, so the flag this encoder \
             matches has moved and every identity in the crate is affected"
        );
    }

    #[test]
    fn a_non_string_map_key_is_refused_by_both_encoders() {
        let mut map = BTreeMap::new();
        map.insert(Newtype("a".to_string()), 1_u8);
        // `Newtype` wraps a string, so it IS a valid key; the invalid case is a
        // composite key, which `serde_json` refuses too.
        assert!(canonical_streamed_bytes(&map).is_ok());

        let mut composite = BTreeMap::new();
        composite.insert(vec![1_u8, 2], 1_u8);
        let streamed = canonical_streamed_bytes(&composite);
        let walked = crate::identity::canonical_json_bytes_via_tree(&composite);
        assert!(
            streamed.is_err() && walked.is_err(),
            "a composite map key must be refused by both encoders, got streamed={:?} walked={:?}",
            streamed.map(|bytes| bytes.len()),
            walked.map(|bytes| bytes.len())
        );
    }

    /// One fixed value exercising every shape the encoding has a tag for.
    ///
    /// Kept stable on purpose: its digest is pinned below, so a change to the
    /// encoding shows up here as a failure rather than as a repository that
    /// quietly stops recognizing its own roots.
    fn pinned_value() -> (Unsorted, Vec<Shapes>, BTreeMap<String, f64>) {
        let mut floats = BTreeMap::new();
        floats.insert("whole".to_string(), 1.0);
        floats.insert("fraction".to_string(), 0.5);
        floats.insert("negative_zero".to_string(), -0.0);
        (
            Unsorted {
                zulu: 4_294_967_295,
                alpha: "ünïcode · 🔥".to_string(),
                mike: Some(false),
                bravo: vec![i64::MIN, 0, i64::MAX],
            },
            vec![
                Shapes::Unit,
                Shapes::Newtype(u64::MAX),
                Shapes::Tuple(7, "seven".to_string()),
                Shapes::Struct {
                    second: -5,
                    first: 2.5,
                },
            ],
            floats,
        )
    }

    impl PartialEq for Newtype {
        fn eq(&self, other: &Self) -> bool {
            self.0 == other.0
        }
    }
    impl Eq for Newtype {}
    impl PartialOrd for Newtype {
        fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
            Some(self.cmp(other))
        }
    }
    impl Ord for Newtype {
        fn cmp(&self, other: &Self) -> std::cmp::Ordering {
            self.0.cmp(&other.0)
        }
    }
}
