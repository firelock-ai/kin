// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Element boundaries of a MessagePack positional body, found without
//! decoding anything.
//!
//! `rmp_serde` encodes a struct as an array of its fields in declaration
//! order, and every MessagePack value is self-delimiting, so the byte range
//! of each top-level element can be found by reading markers and jumping over
//! payloads by their declared lengths. Strings and binary payloads are
//! skipped by length and never inspected, which is what makes this walk cost a
//! few hundred milliseconds over a gigabyte where a decode costs seconds and
//! the decoded structure.
//!
//! The walk is exact or it refuses: a truncated payload, a reserved marker or
//! a body that does not end exactly where its last element ends is an error,
//! never a shorter table.

use std::ops::Range;

use rmp::Marker;

use crate::error::KinDbError;

fn truncated(what: &str, at: usize) -> KinDbError {
    KinDbError::StorageError(format!(
        "snapshot body walk: {what} runs past the end of the body at byte {at}"
    ))
}

struct Cursor<'a> {
    body: &'a [u8],
    position: usize,
}

impl Cursor<'_> {
    fn take(&mut self, count: usize, what: &str) -> Result<&[u8], KinDbError> {
        let end = self
            .position
            .checked_add(count)
            .ok_or_else(|| truncated(what, self.position))?;
        let bytes = self
            .body
            .get(self.position..end)
            .ok_or_else(|| truncated(what, self.position))?;
        self.position = end;
        Ok(bytes)
    }

    fn u8(&mut self, what: &str) -> Result<usize, KinDbError> {
        Ok(usize::from(self.take(1, what)?[0]))
    }

    fn u16(&mut self, what: &str) -> Result<usize, KinDbError> {
        let bytes = self.take(2, what)?;
        Ok(usize::from(u16::from_be_bytes([bytes[0], bytes[1]])))
    }

    fn u32(&mut self, what: &str) -> Result<usize, KinDbError> {
        let bytes = self.take(4, what)?;
        usize::try_from(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])).map_err(
            |_| {
                KinDbError::StorageError(format!(
                    "snapshot body walk: {what} length does not fit usize"
                ))
            },
        )
    }

    /// Advance past exactly one value, containers included.
    ///
    /// Iterative rather than recursive: a container adds its element count to
    /// the number of values still owed, so an adversarial nesting depth cannot
    /// exhaust the stack.
    fn skip_value(&mut self) -> Result<(), KinDbError> {
        let mut owed: usize = 1;
        while owed > 0 {
            owed -= 1;
            let marker_at = self.position;
            let marker = Marker::from_u8(self.take(1, "marker")?[0]);
            let payload = match marker {
                Marker::FixPos(_)
                | Marker::FixNeg(_)
                | Marker::Null
                | Marker::True
                | Marker::False => 0,
                Marker::U8 | Marker::I8 => 1,
                Marker::U16 | Marker::I16 => 2,
                Marker::U32 | Marker::I32 | Marker::F32 => 4,
                Marker::U64 | Marker::I64 | Marker::F64 => 8,
                Marker::FixStr(len) => usize::from(len),
                Marker::Str8 | Marker::Bin8 => self.u8("length")?,
                Marker::Str16 | Marker::Bin16 => self.u16("length")?,
                Marker::Str32 | Marker::Bin32 => self.u32("length")?,
                Marker::FixExt1 => 2,
                Marker::FixExt2 => 3,
                Marker::FixExt4 => 5,
                Marker::FixExt8 => 9,
                Marker::FixExt16 => 17,
                Marker::Ext8 => self.u8("length")? + 1,
                Marker::Ext16 => self.u16("length")? + 1,
                Marker::Ext32 => self.u32("length")?.checked_add(1).ok_or_else(|| {
                    KinDbError::StorageError(
                        "snapshot body walk: ext32 length overflows usize".to_string(),
                    )
                })?,
                Marker::FixArray(count) => {
                    owed = owe(owed, usize::from(count))?;
                    0
                }
                Marker::Array16 => {
                    let count = self.u16("array length")?;
                    owed = owe(owed, count)?;
                    0
                }
                Marker::Array32 => {
                    let count = self.u32("array length")?;
                    owed = owe(owed, count)?;
                    0
                }
                Marker::FixMap(count) => {
                    owed = owe(
                        owed,
                        usize::from(count).checked_mul(2).expect("fixmap fits"),
                    )?;
                    0
                }
                Marker::Map16 => {
                    let count = self.u16("map length")?;
                    owed = owe(owed, count.checked_mul(2).expect("map16 fits"))?;
                    0
                }
                Marker::Map32 => {
                    let count = self.u32("map length")?;
                    owed = owe(
                        owed,
                        count.checked_mul(2).ok_or_else(|| {
                            KinDbError::StorageError(
                                "snapshot body walk: map32 length overflows usize".to_string(),
                            )
                        })?,
                    )?;
                    0
                }
                Marker::Reserved => {
                    return Err(KinDbError::StorageError(format!(
                        "snapshot body walk: reserved marker 0xc1 at byte {marker_at}"
                    )));
                }
            };
            if payload > 0 {
                self.take(payload, "payload")?;
            }
        }
        Ok(())
    }
}

fn owe(owed: usize, more: usize) -> Result<usize, KinDbError> {
    owed.checked_add(more).ok_or_else(|| {
        KinDbError::StorageError("snapshot body walk: element count overflows usize".to_string())
    })
}

/// The byte range of every top-level element of `body`, which must be one
/// MessagePack array that fills the body exactly.
pub(crate) fn top_level_element_ranges(body: &[u8]) -> Result<Vec<Range<usize>>, KinDbError> {
    let mut cursor = Cursor { body, position: 0 };
    let count = match Marker::from_u8(cursor.take(1, "body marker")?[0]) {
        Marker::FixArray(count) => usize::from(count),
        Marker::Array16 => cursor.u16("body array length")?,
        Marker::Array32 => cursor.u32("body array length")?,
        other => {
            return Err(KinDbError::StorageError(format!(
                "snapshot body walk: body is not a positional array (marker {other:?})"
            )));
        }
    };
    let mut ranges = Vec::with_capacity(count);
    for _ in 0..count {
        let start = cursor.position;
        cursor.skip_value()?;
        ranges.push(start..cursor.position);
    }
    if cursor.position != body.len() {
        return Err(KinDbError::StorageError(format!(
            "snapshot body walk: {} bytes follow the last of {count} elements",
            body.len() - cursor.position
        )));
    }
    Ok(ranges)
}

/// The entry count a map element declares in its header, without reading the
/// entries. Refuses anything that is not a map.
pub(crate) fn map_entry_count(element: &[u8]) -> Result<usize, KinDbError> {
    let mut cursor = Cursor {
        body: element,
        position: 0,
    };
    match Marker::from_u8(cursor.take(1, "map marker")?[0]) {
        Marker::FixMap(count) => Ok(usize::from(count)),
        Marker::Map16 => cursor.u16("map length"),
        Marker::Map32 => cursor.u32("map length"),
        other => Err(KinDbError::StorageError(format!(
            "snapshot body walk: element is not a map (marker {other:?})"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::de::IgnoredAny;
    use serde::Deserialize;
    use std::io::Cursor as IoCursor;

    /// Every element boundary the walk finds, against the boundary
    /// `rmp_serde` itself reaches when it parses the same element and drops it.
    fn reference_ranges(body: &[u8]) -> Vec<Range<usize>> {
        let mut cursor = IoCursor::new(body);
        let count = rmp::decode::read_array_len(&mut cursor).expect("array header") as usize;
        let mut ranges = Vec::new();
        for _ in 0..count {
            let start = cursor.position() as usize;
            let mut deserializer = rmp_serde::Deserializer::new(&mut cursor);
            IgnoredAny::deserialize(&mut deserializer).expect("rmp_serde parses the element");
            ranges.push(start..cursor.position() as usize);
        }
        assert_eq!(cursor.position() as usize, body.len());
        ranges
    }

    #[derive(serde::Serialize)]
    struct EveryMarker {
        fix_pos: u8,
        fix_neg: i8,
        u8_: u8,
        u16_: u16,
        u32_: u32,
        u64_: u64,
        i8_: i8,
        i16_: i16,
        i32_: i32,
        i64_: i64,
        f32_: f32,
        f64_: f64,
        yes: bool,
        no: bool,
        none: Option<u8>,
        fix_str: String,
        str8: String,
        str16: String,
        str32: String,
        fix_array: Vec<u8>,
        array16: Vec<u16>,
        array32: Vec<u8>,
        fix_map: std::collections::BTreeMap<u8, u8>,
        map16: std::collections::BTreeMap<u32, String>,
        map32: std::collections::BTreeMap<u32, u8>,
        nested: Vec<Vec<std::collections::BTreeMap<String, Vec<Option<i64>>>>>,
        #[serde(with = "serde_bytes_shim")]
        bin: Vec<u8>,
    }

    /// `rmp_serde` writes `Vec<u8>` as an array of integers; a `bin` marker
    /// needs `serialize_bytes`, which this shim provides without a dependency.
    mod serde_bytes_shim {
        pub fn serialize<S: serde::Serializer>(
            bytes: &[u8],
            serializer: S,
        ) -> Result<S::Ok, S::Error> {
            serializer.serialize_bytes(bytes)
        }
    }

    fn every_marker_body() -> Vec<u8> {
        let value = EveryMarker {
            fix_pos: 5,
            fix_neg: -3,
            u8_: 200,
            u16_: 40_000,
            u32_: 3_000_000_000,
            u64_: u64::MAX,
            i8_: -100,
            i16_: -30_000,
            i32_: -2_000_000_000,
            i64_: i64::MIN,
            f32_: 1.5,
            f64_: -2.25,
            yes: true,
            no: false,
            none: None,
            fix_str: "short".to_string(),
            str8: "x".repeat(40),
            str16: "y".repeat(300),
            str32: "z".repeat(70_000),
            fix_array: vec![1, 2, 3],
            array16: (0..20u16).collect(),
            array32: vec![7u8; 70_000],
            fix_map: (0..3u8).map(|k| (k, k)).collect(),
            map16: (0..20u32).map(|k| (k, k.to_string())).collect(),
            map32: (0..70_000u32).map(|k| (k, 1)).collect(),
            nested: vec![vec![[("k".to_string(), vec![Some(1), None])]
                .into_iter()
                .collect()]],
            bin: vec![0xc1; 300],
        };
        rmp_serde::to_vec(&value).expect("encodes")
    }

    #[test]
    fn the_walk_finds_the_boundaries_rmp_serde_finds_for_every_marker_class() {
        let body = every_marker_body();
        let walked = top_level_element_ranges(&body).expect("walks");
        assert_eq!(walked, reference_ranges(&body));
        assert_eq!(walked.len(), 27, "one range per field");
        // Twenty-seven fields need an `array16` header, three bytes, so the
        // first element starts at byte 3 and the last ends at the body's end.
        assert_eq!(walked.first().map(|range| range.start), Some(3));
        assert_eq!(walked.last().map(|range| range.end), Some(body.len()));
    }

    #[test]
    fn a_truncated_body_refuses_rather_than_reporting_fewer_elements() {
        let body = every_marker_body();
        let cut = &body[..body.len() - 10];
        let error = top_level_element_ranges(cut).expect_err("truncated body refuses");
        assert!(error.to_string().contains("runs past the end"), "{error}");
        let control = top_level_element_ranges(&body).expect("the whole body walks");
        assert_eq!(control.len(), 27);
    }

    #[test]
    fn trailing_bytes_after_the_last_element_refuse() {
        let mut body = every_marker_body();
        body.push(0xc0);
        let error = top_level_element_ranges(&body).expect_err("trailing byte refuses");
        assert!(error.to_string().contains("follow the last"), "{error}");
    }

    #[test]
    fn a_reserved_marker_refuses_by_offset() {
        let mut body = every_marker_body();
        // The `fix_pos` element is the first byte after the array header, and
        // the reference walk says where that is rather than this test guessing.
        let first = reference_ranges(&body)[0].start;
        body[first] = 0xc1;
        let error = top_level_element_ranges(&body).expect_err("reserved marker refuses");
        assert!(
            error
                .to_string()
                .contains(&format!("reserved marker 0xc1 at byte {first}")),
            "{error}"
        );
    }

    #[test]
    fn the_map_entry_count_is_read_from_the_header_alone() {
        let body = every_marker_body();
        let ranges = top_level_element_ranges(&body).expect("walks");
        // Field 22 is `fix_map`, 23 is `map16`, 24 is `map32`.
        assert_eq!(map_entry_count(&body[ranges[22].clone()]).unwrap(), 3);
        assert_eq!(map_entry_count(&body[ranges[23].clone()]).unwrap(), 20);
        assert_eq!(map_entry_count(&body[ranges[24].clone()]).unwrap(), 70_000);
        let not_a_map = map_entry_count(&body[ranges[0].clone()]).expect_err("a scalar refuses");
        assert!(
            not_a_map.to_string().contains("is not a map"),
            "{not_a_map}"
        );
    }
}
