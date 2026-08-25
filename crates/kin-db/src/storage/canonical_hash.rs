// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Canonical repository-root hashing that never materializes what it hashes.
//!
//! Every authority root folds its inputs through one canonical encoding: a tag
//! byte per node, length-prefixed scalars, and object keys visited in sorted
//! order so a struct's declaration order cannot reach the digest. That encoding
//! was produced by handing the value to `serde_json::to_value` and walking the
//! resulting tree.
//!
//! The tree is the problem. A `serde_json::Value` spends a 32-byte enum on
//! every scalar, a separately allocated `String` on every field name at every
//! repetition, and a `Map` node per object, so it costs many times the bytes it
//! exists to produce. Measured on a synthetic Git bootstrap of 1,200 commits
//! and 3,647 objects, the tree for one repository transaction grew the live
//! heap's high-water mark by 282,848,867 bytes in order to emit 18,396,132
//! bytes of canonical payload, a factor of 15.4 (FIR-2665).
//!
//! Nothing about the encoding required the tree. This module writes the same
//! bytes directly from `Serialize`, so what is held is the payload rather than
//! a decoded picture of it.
//!
//! ## Why the bytes are still buffered
//!
//! Two shapes in the encoding are not streamable on their own terms, and both
//! are answered here rather than by holding everything:
//!
//! * A sequence writes its element count before its elements, and `serde` may
//!   report no length. The count is reserved and patched in place afterwards,
//!   so a sequence of any size costs nothing beyond its own bytes.
//! * An object visits keys in sorted order, and `serde` delivers a struct's
//!   fields in declaration order. Only an object buffers, and only its own
//!   field encodings, which are moved into the parent once and dropped.
//!
//! The result holds one copy of the canonical payload rather than a tree many
//! times its size. It is not zero, and it is not claimed to be.
//!
//! ## Exactness
//!
//! This is a persisted authority root. A byte that differs from the tree walk
//! is not a slower hash, it is a repository that no longer recognizes its own
//! history. Every scalar is therefore encoded through the same
//! `serde_json::Number` formatting the tree used, rather than through Rust's
//! `Display`, which disagrees with it on floats: `serde_json` renders `1.0f64`
//! as `1.0` and `f64::to_string` renders it as `1`. Non-finite floats become
//! null exactly as `serde_json::Value` makes them null.
//!
//! `canonical_hash_tree` retains the original tree walk, and the guard in
//! `tests/canonical_hash_agreement.rs` asserts the two agree over the real
//! repository types. The oracle is kept precisely so the fast path can be
//! disagreed with.

use std::fmt::Display;

use serde::{ser, Serialize};
use sha2::{Digest, Sha256};

/// Tag bytes. These are the encoding and may never be reassigned.
const TAG_NULL: u8 = 0;
const TAG_BOOL: u8 = 1;
const TAG_NUMBER: u8 = 2;
const TAG_STRING: u8 = 3;
const TAG_ARRAY: u8 = 4;
const TAG_OBJECT: u8 = 5;

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

/// Canonical bytes of `value`, written straight out of `Serialize`.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn canonical_bytes<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, CanonicalError> {
    let mut out = Vec::new();
    value.serialize(CanonicalSerializer { out: &mut out })?;
    Ok(out)
}

/// Fold `value`'s canonical encoding into `hasher`.
pub(crate) fn canonical_hash_into<T: Serialize + ?Sized>(
    hasher: &mut Sha256,
    value: &T,
) -> Result<(), CanonicalError> {
    hasher.update(canonical_bytes(value)?);
    Ok(())
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

// --- the oracle -----------------------------------------------------------

/// The original tree walk, kept as the oracle the fast path is checked against.
///
/// This is what every persisted authority root was produced by, so it defines
/// the encoding rather than merely agreeing with it.
#[cfg(test)]
pub(crate) fn canonical_hash_tree<T: Serialize + ?Sized>(
    hasher: &mut Sha256,
    value: &T,
) -> Result<(), serde_json::Error> {
    let value = serde_json::to_value(value)?;
    hash_tree(hasher, &value);
    Ok(())
}

#[cfg(test)]
fn hash_tree(hasher: &mut Sha256, value: &serde_json::Value) {
    match value {
        serde_json::Value::Null => hasher.update([TAG_NULL]),
        serde_json::Value::Bool(value) => hasher.update([TAG_BOOL, u8::from(*value)]),
        serde_json::Value::Number(value) => {
            hasher.update([TAG_NUMBER]);
            hash_len_prefixed(hasher, value.to_string().as_bytes());
        }
        serde_json::Value::String(value) => {
            hasher.update([TAG_STRING]);
            hash_len_prefixed(hasher, value.as_bytes());
        }
        serde_json::Value::Array(values) => {
            hasher.update([TAG_ARRAY]);
            hasher.update((values.len() as u64).to_le_bytes());
            for value in values {
                hash_tree(hasher, value);
            }
        }
        serde_json::Value::Object(values) => {
            hasher.update([TAG_OBJECT]);
            hasher.update((values.len() as u64).to_le_bytes());
            let mut keys: Vec<_> = values.keys().collect();
            keys.sort_unstable();
            for key in keys {
                hash_len_prefixed(hasher, key.as_bytes());
                hash_tree(hasher, &values[key]);
            }
        }
    }
}

#[cfg(test)]
fn hash_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    /// Both encoders' digest of one value.
    fn digests<T: Serialize + ?Sized>(value: &T) -> ([u8; 32], [u8; 32]) {
        let mut streamed = Sha256::new();
        canonical_hash_into(&mut streamed, value).expect("the streaming encoder accepts it");
        let mut walked = Sha256::new();
        canonical_hash_tree(&mut walked, value).expect("the tree walk accepts it");
        (streamed.finalize().into(), walked.finalize().into())
    }

    /// The streaming encoder must agree with the tree walk it replaced.
    fn agrees<T: Serialize + ?Sized>(what: &str, value: &T) {
        let (streamed, walked) = digests(value);
        assert_eq!(
            streamed, walked,
            "{what}: the streaming encoder disagrees with the tree walk, so this change \
             would move a persisted authority root"
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
        let (streamed, walked) = digests(&value);
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
        let mut hand = Sha256::new();
        hand.update(&declaration_order);
        let hand: [u8; 32] = hand.finalize().into();

        let mut sorted = Vec::new();
        sorted.push(TAG_OBJECT);
        sorted.extend_from_slice(&4_u64.to_le_bytes());
        for key in ["alpha", "bravo", "mike", "zulu"] {
            put_len_prefixed(&mut sorted, key.as_bytes());
            sorted.push(TAG_NULL);
        }
        let mut sorted_hash = Sha256::new();
        sorted_hash.update(&sorted);
        let sorted_hash: [u8; 32] = sorted_hash.finalize().into();

        assert_ne!(
            hand, sorted_hash,
            "key order must change the digest, or the agreement test above cannot fail"
        );
    }

    /// A map key that is not a string was refused by the tree walk, and must
    /// still be refused rather than given an encoding of its own.
    #[test]
    fn a_non_string_map_key_is_refused_by_both_encoders() {
        let mut map = BTreeMap::new();
        map.insert(Newtype("a".to_string()), 1_u8);
        // `Newtype` wraps a string, so it IS a valid key; the invalid case is a
        // composite key, which `serde_json` refuses too.
        assert!(canonical_bytes(&map).is_ok());

        let mut composite = BTreeMap::new();
        composite.insert(vec![1_u8, 2], 1_u8);
        let streamed = canonical_bytes(&composite);
        let mut walked = Sha256::new();
        let walked = canonical_hash_tree(&mut walked, &composite);
        assert!(
            streamed.is_err() && walked.is_err(),
            "a composite map key must be refused by both encoders, got streamed={:?} walked={:?}",
            streamed.map(|bytes| bytes.len()),
            walked.map(|()| "ok")
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

    /// The digest of [`pinned_value`] under the tree walk that produced every
    /// persisted authority root before this module existed.
    ///
    /// Every root assertion in the repository suite compares one freshly
    /// computed root against another, so all of them agree with each other no
    /// matter what the encoder does, and none of them can see an encoding
    /// change. This constant is the only thing in the crate that can. It was
    /// taken from the tree walk, so it states the old behavior rather than
    /// blessing the new one.
    const PINNED_TREE_DIGEST: &str =
        "001ee87a027869c064ac7b06709b47416966250931622e90a2ea57fcd09be78e";

    #[test]
    fn the_encoding_still_produces_its_pinned_digest() {
        let value = pinned_value();
        let (streamed, walked) = digests(&value);
        assert_eq!(
            hex::encode(walked),
            PINNED_TREE_DIGEST,
            "the tree walk no longer produces the digest every persisted authority root \
             was built from; the canonical encoding has moved"
        );
        assert_eq!(
            hex::encode(streamed),
            PINNED_TREE_DIGEST,
            "the streaming encoder does not reproduce the pinned canonical digest"
        );
    }

    /// The float that actually appears in repository truth is an `f32` inside a
    /// semantic fingerprint, and `f32` is the case where `Display` and
    /// `serde_json` disagree, so hash a real one rather than only synthetic
    /// shapes.
    #[test]
    fn the_encoders_agree_on_real_repository_values() {
        use kin_model::{
            Entity, EntityId, EntityKind, EntityMetadata, EntityRole, FilePathId,
            FingerprintAlgorithm, Hash256, LanguageId, SemanticFingerprint, Visibility,
        };
        let entity = Entity {
            id: EntityId::from_content("src/lib.rs", "kin", "function", 1),
            kind: EntityKind::Function,
            name: "kin".to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([1; 32]),
                signature_hash: Hash256::from_bytes([2; 32]),
                behavior_hash: Hash256::from_bytes([3; 32]),
                equivalence_hash: Hash256::from_bytes([4; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new("src/lib.rs")),
            span: None,
            signature: "fn kin()".to_string(),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: Some("documented".to_string()),
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        };
        agrees("entity with a whole-number f32 stability score", &entity);

        let mut fractional = entity.clone();
        fractional.fingerprint.stability_score = 0.375;
        agrees("entity with a fractional f32 stability score", &fractional);

        agrees("a sequence of entities", &vec![entity, fractional]);
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
