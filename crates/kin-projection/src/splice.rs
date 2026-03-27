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
    splices.sort_by(|a, b| b.byte_range.start.cmp(&a.byte_range.start));

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

/// Build a splice for a specific entity within a FileLayout.
///
/// Finds the entity's byte range in the layout and creates a splice
/// that replaces it with `new_body`.
pub fn splice_entity(layout: &FileLayout, entity_id: &EntityId, new_body: &[u8]) -> Result<Splice> {
    for region in &layout.regions {
        if let SourceRegion::EntityRef {
            entity_id: ref eid,
            byte_range,
        } = region
        {
            if eid == entity_id {
                return Ok(Splice {
                    byte_range: byte_range.clone(),
                    new_content: new_body.to_vec(),
                });
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
    use kin_model::{FilePathId, ImportSection};
    use proptest::prelude::*;

    fn make_layout() -> FileLayout {
        FileLayout {
            file_id: FilePathId::new("test.rs"),
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

        let splice = splice_entity(&layout, &entity_id, b"fn bar() {}").unwrap();
        let result = apply_splices(original, vec![splice]).unwrap();
        assert_eq!(result, b"// header\nfn bar() {}\n// end");
    }

    #[test]
    fn splice_entity_not_found() {
        let layout = make_layout();
        let missing_id = EntityId::new();
        let err = splice_entity(&layout, &missing_id, b"new body").unwrap_err();
        assert!(matches!(err, ProjectionError::EntityNotInLayout { .. }));
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
