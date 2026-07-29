// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::ops::Range;

use kin_model::{EntityId, FileLayout, SourceRegion};

use crate::error::{ProjectionError, Result};

/// A pending splice operation: replace a byte range with new content.
#[derive(Debug, Clone)]
pub struct Splice {
    pub byte_range: Range<usize>,
    pub new_content: Vec<u8>,
}

/// Apply a set of splices to a file's content, producing new content.
///
/// Splices are applied in reverse order (highest byte offset first) so that
/// earlier byte ranges remain valid as we mutate the buffer.
///
/// Returns the new file content after all splices are applied.
pub fn apply_splices(original: &[u8], mut splices: Vec<Splice>) -> Result<Vec<u8>> {
    // Validate all ranges before mutating.
    for splice in &splices {
        if splice.byte_range.end > original.len() {
            return Err(ProjectionError::ByteRangeOutOfBounds {
                range_start: splice.byte_range.start,
                range_end: splice.byte_range.end,
                file_len: original.len(),
            });
        }
        if splice.byte_range.start > splice.byte_range.end {
            return Err(ProjectionError::ByteRangeOutOfBounds {
                range_start: splice.byte_range.start,
                range_end: splice.byte_range.end,
                file_len: original.len(),
            });
        }
    }

    // Sort by start offset descending so we can splice from back to front.
    splices.sort_by_key(|splice| std::cmp::Reverse(splice.byte_range.start));

    // Check for overlapping splices. After sorting descending, splice[i] has
    // a higher start than splice[i+1]. Two splices overlap if the earlier one
    // (lower start, i.e. splice[i+1]) extends past the start of the later one.
    for window in splices.windows(2) {
        let higher = &window[0]; // higher start offset
        let lower = &window[1]; // lower start offset
        if lower.byte_range.end > higher.byte_range.start {
            return Err(ProjectionError::OverlappingSplices {
                first_start: lower.byte_range.start,
                first_end: lower.byte_range.end,
                second_start: higher.byte_range.start,
                second_end: higher.byte_range.end,
            });
        }
    }

    let mut result = original.to_vec();
    for splice in splices {
        result.splice(splice.byte_range.clone(), splice.new_content);
    }

    Ok(result)
}

/// The whitespace run between the start of `start`'s line and `start` itself,
/// or empty when `start` is at a line start or anything non-whitespace precedes
/// it on the line.
///
/// This is the entity's own indentation: an entity span begins at the entity's
/// first token, so for anything nested the file carries the indentation ahead of
/// the span rather than inside it.
fn line_indent_before(original: &[u8], start: usize) -> &[u8] {
    let start = start.min(original.len());
    let line_start = original[..start]
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |newline| newline + 1);
    let indent = &original[line_start..start];
    if !indent.is_empty() && indent.iter().all(|byte| matches!(byte, b' ' | b'\t')) {
        indent
    } else {
        &[]
    }
}

/// Build the splice that replaces an entity's source region with a new body,
/// reading the body's first-line indentation the same way as every other line.
///
/// An entity span starts at the entity's first token, so a nested entity (an
/// impl method, a function inside a module block) has its indentation sitting in
/// the file *before* the span, while every line of its body after the first
/// carries indentation *inside* it. A verbatim splice therefore reads line 1 as
/// relative to the entity's column and lines 2..n as absolute, and a caller that
/// submits the entity exactly as the file shows it gets line 1 indented twice:
/// the caller's copy lands after the file's. It compiles and it is wrong, which
/// is worse than a refusal.
///
/// The fix is to read line 1 absolutely too. When the span is preceded on its
/// line by nothing but whitespace and the new body opens with exactly that
/// whitespace, the splice extends back over the file's copy so the body's own
/// indentation lands at column 0 of the entity's line. A body that does not open
/// with the entity's indentation (an exact span slice, or a deliberate
/// re-indentation) is spliced verbatim, so re-submitting what the read surface
/// returned stays byte-identical.
pub fn entity_body_splice(original: &[u8], byte_range: Range<usize>, new_body: &[u8]) -> Splice {
    let indent = line_indent_before(original, byte_range.start);
    let start = if !indent.is_empty() && new_body.starts_with(indent) {
        byte_range.start - indent.len()
    } else {
        byte_range.start
    };
    Splice {
        byte_range: start..byte_range.end,
        new_content: new_body.to_vec(),
    }
}

/// Build a splice for a specific entity within a FileLayout.
///
/// Finds the entity's byte range in the layout and creates a splice that
/// replaces it with `new_body`, normalizing the body's first-line indentation
/// through [`entity_body_splice`]. `original` is the file the layout describes;
/// the replaced region cannot be decided without it.
pub fn splice_entity(
    original: &[u8],
    layout: &FileLayout,
    entity_id: &EntityId,
    new_body: &[u8],
) -> Result<Splice> {
    for region in &layout.regions {
        if let SourceRegion::EntityRef {
            entity_id: ref eid,
            byte_range,
        } = region
        {
            if eid == entity_id {
                return Ok(entity_body_splice(original, byte_range.clone(), new_body));
            }
        }
    }

    Err(ProjectionError::EntityNotInLayout {
        entity_id: entity_id.to_string(),
        file_id: layout.file_id.to_string(),
    })
}

/// Reconstruct a file from a FileLayout and a content provider.
///
/// The `get_entity_body` closure is called for each EntityRef region to
/// retrieve the entity's current source text. Trivia regions are copied
/// from the original file content.
///
/// Bodies are spliced verbatim over their regions. This runs the graph-to-file
/// direction, where a body is the exact bytes of its own region and the
/// indentation ahead of it is trivia the layout already accounts for; the
/// first-line normalization in [`entity_body_splice`] belongs to the opposite
/// direction, where a caller authors a body against the file it can see.
pub fn reconstruct_file<F>(
    original: &[u8],
    layout: &FileLayout,
    mut get_entity_body: F,
) -> Result<Vec<u8>>
where
    F: FnMut(&EntityId) -> Option<Vec<u8>>,
{
    let mut splices = Vec::new();

    for region in &layout.regions {
        if let SourceRegion::EntityRef {
            entity_id,
            byte_range,
        } = region
        {
            if let Some(new_body) = get_entity_body(entity_id) {
                splices.push(Splice {
                    byte_range: byte_range.clone(),
                    new_content: new_body,
                });
            }
            // If no new body, keep the original bytes (no splice needed).
        }
    }

    apply_splices(original, splices)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{FilePathId, ImportSection, ParseCompleteness};
    use proptest::prelude::*;

    fn make_layout() -> FileLayout {
        FileLayout {
            file_id: FilePathId::new("test.rs"),
            parse_completeness: ParseCompleteness::Full,
            imports: ImportSection {
                byte_range: 0..0,
                items: vec![],
            },
            regions: vec![
                SourceRegion::Trivia { byte_range: 0..10 },
                SourceRegion::EntityRef {
                    entity_id: EntityId::new(),
                    byte_range: 10..20,
                },
                SourceRegion::Trivia { byte_range: 20..25 },
            ],
        }
    }

    #[test]
    fn apply_single_splice() {
        let original = b"hello world!";
        let splices = vec![Splice {
            byte_range: 6..11,
            new_content: b"rust".to_vec(),
        }];
        let result = apply_splices(original, splices).unwrap();
        assert_eq!(result, b"hello rust!");
    }

    #[test]
    fn apply_multiple_splices() {
        let original = b"aaa bbb ccc";
        let splices = vec![
            Splice {
                byte_range: 0..3,
                new_content: b"xxx".to_vec(),
            },
            Splice {
                byte_range: 8..11,
                new_content: b"zzz".to_vec(),
            },
        ];
        let result = apply_splices(original, splices).unwrap();
        assert_eq!(result, b"xxx bbb zzz");
    }

    #[test]
    fn splice_preserves_trivia() {
        // File: "// header\nfn foo() {}\n// end"
        //         0-10       10-21     21-28
        let original = b"// header\nfn foo() {}\n// end";
        let entity_id = EntityId::new();
        let layout = FileLayout {
            file_id: FilePathId::new("test.rs"),
            parse_completeness: ParseCompleteness::Full,
            imports: ImportSection {
                byte_range: 0..0,
                items: vec![],
            },
            regions: vec![
                SourceRegion::Trivia { byte_range: 0..10 },
                SourceRegion::EntityRef {
                    entity_id,
                    byte_range: 10..21,
                },
                SourceRegion::Trivia { byte_range: 21..28 },
            ],
        };

        let splice = splice_entity(original, &layout, &entity_id, b"fn bar() {}").unwrap();
        let result = apply_splices(original, vec![splice]).unwrap();
        assert_eq!(result, b"// header\nfn bar() {}\n// end");
    }

    #[test]
    fn splice_entity_not_found() {
        let layout = make_layout();
        let missing_id = EntityId::new();
        let err = splice_entity(
            b"0123456789abcdefghijklmno",
            &layout,
            &missing_id,
            b"new body",
        )
        .unwrap_err();
        assert!(matches!(err, ProjectionError::EntityNotInLayout { .. }));
    }

    /// An impl-nested method whose new body carries the indentation the file
    /// shows must land at that indentation, not at twice it.
    ///
    /// This is the shape an agent produces: it reads the method as the file
    /// renders it and writes it back the same way. A verbatim splice put the
    /// body's four spaces after the file's four and produced an eight-space
    /// method that compiles and fails `cargo fmt`.
    #[test]
    fn impl_method_body_carrying_its_indentation_is_not_double_indented() {
        let original = b"impl Builder {\n    fn set(&mut self) {\n        self.a = 1;\n    }\n}\n";
        let span = 19..64; // "fn set(&mut self) {\n        self.a = 1;\n    }"
        assert_eq!(
            &original[span.clone()],
            b"fn set(&mut self) {\n        self.a = 1;\n    }"
        );

        let new_body = b"    fn set(&mut self) {\n        self.a = 2;\n    }";
        let splice = entity_body_splice(original, span, new_body);
        let result = apply_splices(original, vec![splice]).unwrap();
        assert_eq!(
            result,
            b"impl Builder {\n    fn set(&mut self) {\n        self.a = 2;\n    }\n}\n"
        );
    }

    /// The exact bytes the read surface serves are the span slice, with no
    /// leading indentation on line 1. Submitting them back unchanged has to stay
    /// byte-identical, or the normalization traded one indent bug for another.
    #[test]
    fn span_slice_body_round_trips_byte_identically() {
        let original = b"impl Builder {\n    fn set(&mut self) {\n        self.a = 1;\n    }\n}\n";
        let span = 19..64;
        let splice = entity_body_splice(original, span.clone(), &original[span]);
        let result = apply_splices(original, vec![splice]).unwrap();
        assert_eq!(result, original);
    }

    /// Nested modules indent the same way impls do, at whatever depth.
    #[test]
    fn nested_module_function_body_carrying_its_indentation_is_not_double_indented() {
        let original = b"mod outer {\n    mod inner {\n        fn f() -> u8 { 1 }\n    }\n}\n";
        let span = 36..54; // "fn f() -> u8 { 1 }"
        assert_eq!(&original[span.clone()], b"fn f() -> u8 { 1 }");

        let new_body = b"        fn f() -> u8 { 2 }";
        let splice = entity_body_splice(original, span, new_body);
        let result = apply_splices(original, vec![splice]).unwrap();
        assert_eq!(
            result,
            b"mod outer {\n    mod inner {\n        fn f() -> u8 { 2 }\n    }\n}\n"
        );
    }

    /// A top-level function has no indentation to double, so the normalization
    /// must leave it exactly alone.
    #[test]
    fn top_level_function_body_is_spliced_verbatim() {
        let original = b"fn f() -> u8 { 1 }\n";
        let splice = entity_body_splice(original, 0..18, b"fn f() -> u8 { 2 }");
        let result = apply_splices(original, vec![splice]).unwrap();
        assert_eq!(result, b"fn f() -> u8 { 2 }\n");
    }

    /// A caller that genuinely wants a deeper indentation still gets it: the
    /// body's own first-line whitespace is what lands, whatever it is.
    #[test]
    fn deliberate_reindentation_is_preserved() {
        let original = b"impl Builder {\n    fn set(&mut self) {}\n}\n";
        let span = 19..39;
        assert_eq!(&original[span.clone()], b"fn set(&mut self) {}");

        // Eight spaces where the file has four: the caller re-indents, and the
        // result is eight, not twelve.
        let splice = entity_body_splice(original, span, b"        fn set(&mut self) {}");
        let result = apply_splices(original, vec![splice]).unwrap();
        assert_eq!(result, b"impl Builder {\n        fn set(&mut self) {}\n}\n");
    }

    /// Only whitespace running to the start of the line counts as the entity's
    /// indentation. A second entity later on the same line has code before it,
    /// so nothing is consumed.
    #[test]
    fn indentation_is_only_consumed_when_the_span_opens_its_line() {
        let original = b"fn a() {} fn b() {}\n";
        // "fn b() {}" starts at 10, preceded on its line by "fn a() {} ".
        let splice = entity_body_splice(original, 10..19, b" fn b() {}");
        assert_eq!(splice.byte_range, 10..19);
        let result = apply_splices(original, vec![splice]).unwrap();
        assert_eq!(result, b"fn a() {}  fn b() {}\n");
    }

    /// Tabs indent too, and a tab prefix must not be matched against a space
    /// prefix.
    #[test]
    fn tab_indentation_is_matched_exactly() {
        let original = b"impl B {\n\tfn f() {}\n}\n";
        let span = 10..19;
        assert_eq!(&original[span.clone()], b"fn f() {}");

        let consumed = entity_body_splice(original, span.clone(), b"\tfn f() {2}");
        assert_eq!(consumed.byte_range, 9..19);

        let untouched = entity_body_splice(original, span, b"    fn f() {2}");
        assert_eq!(untouched.byte_range, 10..19);
    }

    #[test]
    fn out_of_bounds_splice_rejected() {
        let original = b"short";
        let splices = vec![Splice {
            byte_range: 0..100,
            new_content: b"new".to_vec(),
        }];
        let err = apply_splices(original, splices).unwrap_err();
        assert!(matches!(err, ProjectionError::ByteRangeOutOfBounds { .. }));
    }

    #[test]
    fn overlapping_splices_rejected() {
        let original = b"hello world!";
        let splices = vec![
            Splice {
                byte_range: 0..8,
                new_content: b"aaa".to_vec(),
            },
            Splice {
                byte_range: 5..12,
                new_content: b"bbb".to_vec(),
            },
        ];
        let err = apply_splices(original, splices).unwrap_err();
        assert!(matches!(err, ProjectionError::OverlappingSplices { .. }));
    }

    #[test]
    fn nested_splices_rejected() {
        let original = b"hello world!";
        // Inner splice is fully contained within the outer one.
        let splices = vec![
            Splice {
                byte_range: 2..10,
                new_content: b"outer".to_vec(),
            },
            Splice {
                byte_range: 4..7,
                new_content: b"inner".to_vec(),
            },
        ];
        let err = apply_splices(original, splices).unwrap_err();
        assert!(matches!(err, ProjectionError::OverlappingSplices { .. }));
    }

    #[test]
    fn adjacent_splices_pass() {
        let original = b"aaabbbccc";
        let splices = vec![
            Splice {
                byte_range: 0..3,
                new_content: b"xxx".to_vec(),
            },
            Splice {
                byte_range: 3..6,
                new_content: b"yyy".to_vec(),
            },
            Splice {
                byte_range: 6..9,
                new_content: b"zzz".to_vec(),
            },
        ];
        let result = apply_splices(original, splices).unwrap();
        assert_eq!(result, b"xxxyyyzzz");
    }

    #[test]
    fn identical_range_splices_rejected() {
        let original = b"hello world!";
        let splices = vec![
            Splice {
                byte_range: 3..7,
                new_content: b"aaa".to_vec(),
            },
            Splice {
                byte_range: 3..7,
                new_content: b"bbb".to_vec(),
            },
        ];
        let err = apply_splices(original, splices).unwrap_err();
        assert!(matches!(err, ProjectionError::OverlappingSplices { .. }));
    }

    #[test]
    fn empty_splice_is_insertion() {
        let original = b"hello world";
        let splices = vec![Splice {
            byte_range: 5..5,
            new_content: b",".to_vec(),
        }];
        let result = apply_splices(original, splices).unwrap();
        assert_eq!(result, b"hello, world");
    }

    #[test]
    fn reconstruct_replaces_entities() {
        let entity_id = EntityId::new();
        let original = b"// top\nold_body\n// bot";
        let layout = FileLayout {
            file_id: FilePathId::new("test.rs"),
            parse_completeness: ParseCompleteness::Full,
            imports: ImportSection {
                byte_range: 0..0,
                items: vec![],
            },
            regions: vec![
                SourceRegion::Trivia { byte_range: 0..7 },
                SourceRegion::EntityRef {
                    entity_id,
                    byte_range: 7..15,
                },
                SourceRegion::Trivia { byte_range: 15..21 },
            ],
        };

        let result = reconstruct_file(original, &layout, |id| {
            if *id == entity_id {
                Some(b"new_body".to_vec())
            } else {
                None
            }
        })
        .unwrap();

        assert_eq!(result, b"// top\nnew_body\n// bot");
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        #[test]
        fn apply_splices_matches_manual_reconstruction(
            parts in prop::collection::vec(
                (
                    prop::collection::vec(any::<u8>(), 0..8),
                    prop::collection::vec(any::<u8>(), 1..8),
                    prop::collection::vec(any::<u8>(), 0..8),
                ),
                0..8,
            ),
            suffix in prop::collection::vec(any::<u8>(), 0..8),
        ) {
            let mut original = Vec::new();
            let mut expected = Vec::new();
            let mut splices = Vec::new();

            for (prefix, replaced, new_content) in &parts {
                expected.extend_from_slice(prefix);
                original.extend_from_slice(prefix);

                let start = original.len();
                original.extend_from_slice(replaced);
                let end = original.len();

                splices.push(Splice {
                    byte_range: start..end,
                    new_content: new_content.clone(),
                });
                expected.extend_from_slice(new_content);
            }

            original.extend_from_slice(&suffix);
            expected.extend_from_slice(&suffix);

            let result = apply_splices(&original, splices).unwrap();
            prop_assert_eq!(result, expected);
        }

        #[test]
        fn reconstruct_file_preserves_trivia_and_replaces_selected_entities(
            leading_trivia in prop::collection::vec(any::<u8>(), 0..8),
            trailing_trivia in prop::collection::vec(any::<u8>(), 0..8),
            entity_specs in prop::collection::vec(
                (
                    prop::collection::vec(any::<u8>(), 1..8),
                    prop::option::of(prop::collection::vec(any::<u8>(), 0..8)),
                    prop::collection::vec(any::<u8>(), 0..8),
                ),
                1..8,
            ),
        ) {
            let mut original = leading_trivia.clone();
            let mut expected = leading_trivia;
            let mut regions = Vec::new();
            let mut replacements = Vec::new();

            if !original.is_empty() {
                regions.push(SourceRegion::Trivia {
                    byte_range: 0..original.len(),
                });
            }

            for (entity_body, replacement, following_trivia) in &entity_specs {
                let entity_id = EntityId::new();
                let entity_start = original.len();
                original.extend_from_slice(entity_body);
                let entity_end = original.len();
                regions.push(SourceRegion::EntityRef {
                    entity_id,
                    byte_range: entity_start..entity_end,
                });

                if let Some(new_body) = replacement {
                    expected.extend_from_slice(new_body);
                } else {
                    expected.extend_from_slice(entity_body);
                }
                replacements.push((entity_id, replacement.clone()));

                let trivia_start = original.len();
                original.extend_from_slice(following_trivia);
                let trivia_end = original.len();
                if trivia_start != trivia_end {
                    regions.push(SourceRegion::Trivia {
                        byte_range: trivia_start..trivia_end,
                    });
                }
                expected.extend_from_slice(following_trivia);
            }

            let trailing_start = original.len();
            original.extend_from_slice(&trailing_trivia);
            let trailing_end = original.len();
            if trailing_start != trailing_end {
                regions.push(SourceRegion::Trivia {
                    byte_range: trailing_start..trailing_end,
                });
            }
            expected.extend_from_slice(&trailing_trivia);

            let layout = FileLayout {
                file_id: FilePathId::new("fuzz.rs"),
                parse_completeness: ParseCompleteness::Full,
                imports: ImportSection {
                    byte_range: 0..0,
                    items: vec![],
                },
                regions,
            };

            let result = reconstruct_file(&original, &layout, |id| {
                replacements
                    .iter()
                    .find(|(entity_id, _)| entity_id == id)
                    .and_then(|(_, replacement)| replacement.clone())
            }).unwrap();

            prop_assert_eq!(result, expected);
        }
    }
}
