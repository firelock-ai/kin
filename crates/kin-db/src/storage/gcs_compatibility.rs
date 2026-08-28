// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

#[cfg(any(feature = "gcs", test))]
use crate::error::KinDbError;

#[cfg(any(feature = "gcs", test))]
const GCS_FULL_AUTHORITY_MAGIC_PREFIX: [u8; 6] = *b"KNGCSF";
#[cfg(any(feature = "gcs", test))]
const GCS_FULL_AUTHORITY_MAGIC_LEN: usize = 8;
#[cfg(any(feature = "gcs", test))]
const GCS_FULL_AUTHORITY_MAX_ENCODED_VERSION: u32 = 99;

/// Versions of the GCS full-authority envelope this KinDB reader accepts.
///
/// This metadata is available even when the `gcs` feature is disabled so a
/// caller can advertise the compatibility of the KinDB build it ships without
/// also linking the GCS client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GcsFullAuthorityEnvelopeCompatibility {
    pub min_supported_version: u32,
    pub current_version: u32,
}

impl GcsFullAuthorityEnvelopeCompatibility {
    /// Whether `version` is accepted by this build's GCS envelope reader.
    pub const fn supports(&self, version: u32) -> bool {
        version >= self.min_supported_version && version <= self.current_version
    }
}

/// Compatibility range for the GCS full-authority envelope reader.
///
/// The current wire magic is `KNGCSF02`, so the reader and writer both derive
/// their encoded version from this one public value.
pub const GCS_FULL_AUTHORITY_ENVELOPE_COMPATIBILITY: GcsFullAuthorityEnvelopeCompatibility =
    GcsFullAuthorityEnvelopeCompatibility {
        min_supported_version: 2,
        current_version: 2,
    };

#[cfg(any(feature = "gcs", test))]
pub(crate) fn full_authority_envelope_magic(version: u32) -> Result<[u8; 8], KinDbError> {
    if version > GCS_FULL_AUTHORITY_MAX_ENCODED_VERSION {
        return Err(KinDbError::StorageError(format!(
            "GCS full-authority envelope version {version} does not fit its two-digit magic"
        )));
    }

    let mut magic = [0_u8; GCS_FULL_AUTHORITY_MAGIC_LEN];
    magic[..GCS_FULL_AUTHORITY_MAGIC_PREFIX.len()]
        .copy_from_slice(&GCS_FULL_AUTHORITY_MAGIC_PREFIX);
    magic[6] = b'0' + (version / 10) as u8;
    magic[7] = b'0' + (version % 10) as u8;
    Ok(magic)
}

#[cfg(any(feature = "gcs", test))]
pub(crate) fn full_authority_envelope_version(bytes: &[u8]) -> Result<u32, KinDbError> {
    let magic = bytes
        .get(..GCS_FULL_AUTHORITY_MAGIC_LEN)
        .ok_or_else(not_current_full_authority_envelope)?;
    if !magic.starts_with(&GCS_FULL_AUTHORITY_MAGIC_PREFIX)
        || !magic[6].is_ascii_digit()
        || !magic[7].is_ascii_digit()
    {
        return Err(not_current_full_authority_envelope());
    }

    Ok(u32::from(magic[6] - b'0') * 10 + u32::from(magic[7] - b'0'))
}

#[cfg(any(feature = "gcs", test))]
fn not_current_full_authority_envelope() -> KinDbError {
    KinDbError::StorageError(
        "GCS snapshot object is not a current full-authority envelope".to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn published_compatibility_accepts_only_its_inclusive_range() {
        let compatibility = GCS_FULL_AUTHORITY_ENVELOPE_COMPATIBILITY;
        assert!(compatibility.min_supported_version <= compatibility.current_version);
        assert!(compatibility.current_version <= GCS_FULL_AUTHORITY_MAX_ENCODED_VERSION);
        assert!(compatibility.supports(compatibility.min_supported_version));
        assert!(compatibility.supports(compatibility.current_version));
        assert!(!compatibility.supports(compatibility.min_supported_version - 1));
        assert!(!compatibility.supports(compatibility.current_version + 1));
    }

    #[test]
    fn magic_roundtrips_the_public_current_version() {
        let compatibility = GCS_FULL_AUTHORITY_ENVELOPE_COMPATIBILITY;
        let magic = full_authority_envelope_magic(compatibility.current_version).unwrap();
        assert_eq!(&magic, b"KNGCSF02");
        assert_eq!(
            full_authority_envelope_version(&magic).unwrap(),
            compatibility.current_version
        );
    }

    /// Keep the codec on the public compatibility value. This fails if the GCS
    /// implementation restores a copied `KNGCSF02` or replaces either codec
    /// read with a private numeric constant.
    #[test]
    fn gcs_codec_has_one_public_version_authority() {
        let source = include_str!("gcs.rs");
        let sanitized = sanitize_rust_source(source).unwrap();
        let production_end = production_end(&sanitized.code).unwrap();
        let production_code = &sanitized.code[..production_end];
        let writer_range =
            function_body_range(production_code, "fn encode_full_snapshot_authority(").unwrap();
        let retained_writer = compact_rust_code(&production_code[writer_range]);
        assert!(
            retained_writer.contains("letmutencoded=Vec::with_capacity")
                && retained_writer
                    .contains("encoded.extend_from_slice(&full_authority_envelope_magic("),
            "the lexical scan must retain the actual encoder body"
        );
        assert_codec_source_is_bound(source).unwrap();

        let writer_binding = concat!(
            "full_authority_envelope_magic(",
            "GCS_FULL_AUTHORITY_ENVELOPE_COMPATIBILITY.current_version,",
            ")"
        );
        let copied_writer = source.replacen(
            "GCS_FULL_AUTHORITY_ENVELOPE_COMPATIBILITY.current_version,",
            "2,",
            1,
        );
        for (class, decoy) in [
            ("line comment", format!("// {writer_binding}")),
            (
                "nested block comment",
                format!("/* outer /* {writer_binding} */ outer */"),
            ),
            (
                "ordinary string",
                format!("const WRITER_DECOY: &str = \"{writer_binding}\";"),
            ),
            (
                "raw string",
                format!("const WRITER_RAW_DECOY: &str = r#\"{writer_binding}\"#;"),
            ),
            (
                "unrelated dead function",
                format!("fn unrelated_writer_decoy() {{ let _ = {writer_binding}; }}"),
            ),
        ] {
            let poisoned = insert_before_test_module(&copied_writer, &decoy);
            assert!(
                assert_codec_source_is_bound(&poisoned).is_err(),
                "accepted a copied writer hidden by a {class} decoy"
            );
        }

        let reader_binding = "GCS_FULL_AUTHORITY_ENVELOPE_COMPATIBILITY.supports(version)";
        let copied_reader = source.replacen(
            reader_binding,
            "GCS_FULL_AUTHORITY_ENVELOPE_COMPATIBILITY.supports(2)",
            1,
        );
        for (class, decoy) in [
            ("line comment", format!("// {reader_binding}")),
            (
                "nested block comment",
                format!("/* outer /* {reader_binding} */ outer */"),
            ),
            (
                "ordinary string",
                format!("const READER_DECOY: &str = \"{reader_binding}\";"),
            ),
            (
                "raw string",
                format!("const READER_RAW_DECOY: &str = r#\"{reader_binding}\"#;"),
            ),
            (
                "unrelated dead function",
                format!("fn unrelated_reader_decoy(version: u32) {{ let _ = {reader_binding}; }}"),
            ),
        ] {
            let poisoned = insert_before_test_module(&copied_reader, &decoy);
            assert!(
                assert_codec_source_is_bound(&poisoned).is_err(),
                "accepted a copied reader hidden by a {class} decoy"
            );
        }

        for (class, decoy) in [
            (
                "ordinary string",
                "const TEST_MARKER_DECOY: &str = \"#[cfg(test)]\";",
            ),
            (
                "nested block comment",
                "/* outer /* #[cfg(test)] */ outer */",
            ),
        ] {
            let source_with_early_marker = source.replacen(
                "impl GcsBackend {",
                &format!("{decoy}\nimpl GcsBackend {{"),
                1,
            );
            assert_codec_source_is_bound(&source_with_early_marker).unwrap_or_else(|error| {
                panic!("{class} test-marker decoy changed the scan: {error}")
            });
        }
    }

    fn insert_before_test_module(source: &str, decoy: &str) -> String {
        source.replacen("#[cfg(test)]", &format!("{decoy}\n#[cfg(test)]"), 1)
    }

    fn assert_codec_source_is_bound(source: &str) -> Result<(), String> {
        let sanitized = sanitize_rust_source(source)?;
        let production_end = production_end(&sanitized.code)?;
        let production_code = &sanitized.code[..production_end];
        let production_uncommented = &sanitized.uncommented[..production_end];

        if production_uncommented.contains("KNGCSF02") {
            return Err("production GCS codec restored a hard-coded current magic".to_string());
        }
        let writer_binding = concat!(
            "full_authority_envelope_magic(",
            "GCS_FULL_AUTHORITY_ENVELOPE_COMPATIBILITY.current_version,",
            ")"
        );
        let writer_range =
            function_body_range(production_code, "fn encode_full_snapshot_authority(")?;
        let writer_body = compact_rust_code(&production_code[writer_range]);
        if writer_body
            .matches("full_authority_envelope_magic(")
            .count()
            != 1
            || writer_body.matches(writer_binding).count() != 1
        {
            return Err(
                "the live writer is not bound exactly once to the public current version"
                    .to_string(),
            );
        }
        let reader_binding = "GCS_FULL_AUTHORITY_ENVELOPE_COMPATIBILITY.supports(version)";
        let reader_range =
            function_body_range(production_code, "fn decode_full_snapshot_authority(")?;
        let reader_body = compact_rust_code(&production_code[reader_range]);
        if reader_body
            .matches("GCS_FULL_AUTHORITY_ENVELOPE_COMPATIBILITY.supports(")
            .count()
            != 1
            || reader_body.matches(reader_binding).count() != 1
        {
            return Err(
                "the live reader is not bound exactly once to the public range".to_string(),
            );
        }
        Ok(())
    }

    fn production_end(source: &str) -> Result<usize, String> {
        let test_module = "pub(crate) mod tests";
        if source.matches(test_module).count() != 1 {
            return Err(
                "GCS codec must contain exactly one production test module boundary".into(),
            );
        }
        Ok(source
            .find(test_module)
            .expect("the exact test module boundary was counted once"))
    }

    fn compact_rust_code(source: &str) -> String {
        source
            .chars()
            .filter(|character| !character.is_whitespace())
            .collect()
    }

    fn function_body_range(
        source: &str,
        signature: &str,
    ) -> Result<std::ops::Range<usize>, String> {
        if source.matches(signature).count() != 1 {
            return Err(format!(
                "GCS codec must contain exactly one {signature} definition"
            ));
        }
        let signature_start = source
            .find(signature)
            .expect("the exact function signature was counted once");
        let body_start = signature_start
            + source[signature_start..]
                .find('{')
                .ok_or_else(|| format!("{signature} has no function body"))?;
        let mut depth = 0_usize;
        for (offset, byte) in source.as_bytes()[body_start..].iter().enumerate() {
            match byte {
                b'{' => depth += 1,
                b'}' => {
                    if depth == 0 {
                        return Err(format!("{signature} has an unmatched closing brace"));
                    }
                    depth -= 1;
                    if depth == 0 {
                        return Ok(body_start..body_start + offset + 1);
                    }
                }
                _ => {}
            }
        }
        Err(format!("{signature} has an unterminated function body"))
    }

    struct SanitizedRustSource {
        uncommented: String,
        code: String,
    }

    fn sanitize_rust_source(source: &str) -> Result<SanitizedRustSource, String> {
        let bytes = source.as_bytes();
        let mut uncommented = bytes.to_vec();
        let mut code = bytes.to_vec();
        let mut index = 0_usize;

        while index < bytes.len() {
            if index + 1 < bytes.len() && bytes[index] == b'/' && bytes[index + 1] == b'/' {
                let start = index;
                index += 2;
                while index < bytes.len() && bytes[index] != b'\n' {
                    index += 1;
                }
                blank_non_newlines(&mut uncommented, start..index);
                blank_non_newlines(&mut code, start..index);
                continue;
            }

            if index + 1 < bytes.len() && bytes[index] == b'/' && bytes[index + 1] == b'*' {
                let start = index;
                index += 2;
                let mut depth = 1_usize;
                while depth > 0 {
                    if index + 1 >= bytes.len() {
                        return Err(
                            "unterminated block comment while inspecting GCS codec source"
                                .to_string(),
                        );
                    }
                    if bytes[index] == b'/' && bytes[index + 1] == b'*' {
                        depth += 1;
                        index += 2;
                    } else if bytes[index] == b'*' && bytes[index + 1] == b'/' {
                        depth -= 1;
                        index += 2;
                    } else {
                        index += 1;
                    }
                }
                blank_non_newlines(&mut uncommented, start..index);
                blank_non_newlines(&mut code, start..index);
                continue;
            }

            if let Some((opening_quote, hash_count)) = raw_string_open(bytes, index) {
                let mut closing_quote = opening_quote + 1;
                let closing_quote = loop {
                    if closing_quote >= bytes.len() {
                        return Err(
                            "unterminated raw string while inspecting GCS codec source".to_string()
                        );
                    }
                    let closes = bytes[closing_quote] == b'"'
                        && closing_quote + 1 + hash_count <= bytes.len()
                        && bytes[closing_quote + 1..closing_quote + 1 + hash_count]
                            .iter()
                            .all(|byte| *byte == b'#');
                    if closes {
                        break closing_quote;
                    }
                    closing_quote += 1;
                };
                blank_non_newlines(&mut code, opening_quote + 1..closing_quote);
                index = closing_quote + 1 + hash_count;
                continue;
            }

            if bytes[index] == b'"' {
                let opening_quote = index;
                index += 1;
                let closing_quote = loop {
                    if index >= bytes.len() {
                        return Err(
                            "unterminated string while inspecting GCS codec source".to_string()
                        );
                    }
                    if bytes[index] == b'\\' {
                        index = (index + 2).min(bytes.len());
                    } else if bytes[index] == b'"' {
                        break index;
                    } else {
                        index += 1;
                    }
                };
                blank_non_newlines(&mut code, opening_quote + 1..closing_quote);
                index = closing_quote + 1;
                continue;
            }

            if bytes[index] == b'\'' {
                if let Some(closing_quote) = char_literal_end(source, index) {
                    blank_non_newlines(&mut code, index + 1..closing_quote);
                    index = closing_quote + 1;
                    continue;
                }
            }

            index += 1;
        }

        let uncommented = String::from_utf8(uncommented)
            .map_err(|error| format!("comment sanitizer produced invalid UTF-8: {error}"))?;
        let code = String::from_utf8(code)
            .map_err(|error| format!("string sanitizer produced invalid UTF-8: {error}"))?;
        Ok(SanitizedRustSource { uncommented, code })
    }

    fn raw_string_open(bytes: &[u8], start: usize) -> Option<(usize, usize)> {
        let mut cursor = match *bytes.get(start)? {
            b'r' => start + 1,
            b'b' | b'c' if bytes.get(start + 1) == Some(&b'r') => start + 2,
            _ => return None,
        };
        let hash_start = cursor;
        while bytes.get(cursor) == Some(&b'#') {
            cursor += 1;
        }
        (bytes.get(cursor) == Some(&b'"')).then_some((cursor, cursor - hash_start))
    }

    fn char_literal_end(source: &str, start: usize) -> Option<usize> {
        let bytes = source.as_bytes();
        let mut cursor = start + 1;
        if bytes.get(cursor) == Some(&b'\\') {
            cursor += 1;
            match *bytes.get(cursor)? {
                b'u' if bytes.get(cursor + 1) == Some(&b'{') => {
                    cursor += 2;
                    while bytes.get(cursor) != Some(&b'}') {
                        cursor += 1;
                        bytes.get(cursor)?;
                    }
                    cursor += 1;
                }
                b'x' => cursor += 3,
                _ => cursor += 1,
            }
        } else {
            let character = source.get(cursor..)?.chars().next()?;
            if matches!(character, '\n' | '\r' | '\'') {
                return None;
            }
            cursor += character.len_utf8();
        }
        (bytes.get(cursor) == Some(&b'\'')).then_some(cursor)
    }

    fn blank_non_newlines(bytes: &mut [u8], range: std::ops::Range<usize>) {
        for byte in &mut bytes[range] {
            if !matches!(*byte, b'\n' | b'\r') {
                *byte = b' ';
            }
        }
    }
}
