use std::ops::Range;

use kin_model::{Entity, EntityId, FileLayout, FilePathId, ImportItem, ImportSection, SourceRegion};

/// Build a FileLayout from a list of extracted entities and the file's source text.
///
/// Entities must have `span` set with `start_byte` and `end_byte`.
/// Regions between (and around) entity spans become Trivia regions.
/// The import section is identified from entities whose span falls within
/// the first import-like region; if no imports are found, an empty import
/// section at byte 0 is used.
pub fn build_layout(
    file_id: &FilePathId,
    entities: &[Entity],
    file_len: usize,
    import_items: &[ImportItem],
) -> FileLayout {
    // Collect entity spans, filtering out entities without byte ranges.
    let mut entity_spans: Vec<(EntityId, Range<usize>)> = entities
        .iter()
        .filter_map(|e| {
            e.span.as_ref().map(|s| (e.id, s.start_byte..s.end_byte))
        })
        .collect();

    // Sort by start byte.
    entity_spans.sort_by_key(|(_, r)| r.start);

    // Build import section.
    let imports = if import_items.is_empty() {
        ImportSection {
            byte_range: 0..0,
            items: vec![],
        }
    } else {
        let import_start = import_items
            .iter()
            .map(|i| i.byte_range.start)
            .min()
            .unwrap_or(0);
        let import_end = import_items
            .iter()
            .map(|i| i.byte_range.end)
            .max()
            .unwrap_or(0);
        ImportSection {
            byte_range: import_start..import_end,
            items: import_items.to_vec(),
        }
    };

    // Build interleaved regions.
    let mut regions = Vec::new();
    let mut cursor = 0;

    for (entity_id, range) in &entity_spans {
        // Gap before this entity becomes trivia.
        if range.start > cursor {
            regions.push(SourceRegion::Trivia {
                byte_range: cursor..range.start,
            });
        }

        regions.push(SourceRegion::EntityRef {
            entity_id: *entity_id,
            byte_range: range.clone(),
        });

        cursor = range.end;
    }

    // Trailing trivia after the last entity.
    if cursor < file_len {
        regions.push(SourceRegion::Trivia {
            byte_range: cursor..file_len,
        });
    }

    FileLayout {
        file_id: file_id.clone(),
        imports,
        regions,
    }
}

/// Update an existing FileLayout when entities change.
///
/// This rebuilds the layout from scratch using the new entity set.
/// It preserves trivia regions between entities.
pub fn update_layout(
    existing: &FileLayout,
    new_entities: &[Entity],
    file_len: usize,
    import_items: &[ImportItem],
) -> FileLayout {
    build_layout(&existing.file_id, new_entities, file_len, import_items)
}

/// Find the entity that contains a given byte offset in a FileLayout.
pub fn entity_at_offset(layout: &FileLayout, offset: usize) -> Option<EntityId> {
    for region in &layout.regions {
        if let SourceRegion::EntityRef {
            entity_id,
            byte_range,
        } = region
        {
            if byte_range.contains(&offset) {
                return Some(*entity_id);
            }
        }
    }
    None
}

/// Get the byte range of an entity in a FileLayout.
pub fn entity_byte_range(layout: &FileLayout, entity_id: &EntityId) -> Option<Range<usize>> {
    for region in &layout.regions {
        if let SourceRegion::EntityRef {
            entity_id: ref eid,
            byte_range,
        } = region
        {
            if eid == entity_id {
                return Some(byte_range.clone());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::*;

    fn make_entity_with_span(name: &str, start: usize, end: usize) -> Entity {
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0; 32]),
                signature_hash: Hash256::from_bytes([0; 32]),
                behavior_hash: Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: None,
            span: Some(SourceSpan {
                file: FilePathId::new("test.rs"),
                start_byte: start,
                end_byte: end,
                start_line: 0,
                start_col: 0,
                end_line: 0,
                end_col: 0,
            }),
            signature: format!("fn {name}()"),
            visibility: Visibility::Public,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    #[test]
    fn build_layout_single_entity() {
        // File: "// top\nfn foo() {}\n// end"
        //        0......7..........18.....24
        let e = make_entity_with_span("foo", 7, 18);
        let layout = build_layout(&FilePathId::new("test.rs"), &[e.clone()], 24, &[]);

        assert_eq!(layout.regions.len(), 3);
        assert!(matches!(&layout.regions[0], SourceRegion::Trivia { byte_range } if *byte_range == (0..7)));
        assert!(matches!(&layout.regions[1], SourceRegion::EntityRef { entity_id, byte_range } if *entity_id == e.id && *byte_range == (7..18)));
        assert!(matches!(&layout.regions[2], SourceRegion::Trivia { byte_range } if *byte_range == (18..24)));
    }

    #[test]
    fn build_layout_multiple_entities() {
        let e1 = make_entity_with_span("foo", 0, 10);
        let e2 = make_entity_with_span("bar", 12, 25);
        let layout = build_layout(&FilePathId::new("test.rs"), &[e2.clone(), e1.clone()], 30, &[]);

        // Should be sorted by start byte
        assert_eq!(layout.regions.len(), 4); // e1, trivia, e2, trailing trivia
        assert!(matches!(&layout.regions[0], SourceRegion::EntityRef { entity_id, .. } if *entity_id == e1.id));
        assert!(matches!(&layout.regions[1], SourceRegion::Trivia { byte_range } if *byte_range == (10..12)));
        assert!(matches!(&layout.regions[2], SourceRegion::EntityRef { entity_id, .. } if *entity_id == e2.id));
    }

    #[test]
    fn build_layout_with_imports() {
        let items = vec![ImportItem {
            source: "std::io".to_string(),
            symbols: vec!["Read".to_string()],
            byte_range: 0..20,
        }];
        let layout = build_layout(&FilePathId::new("test.rs"), &[], 50, &items);

        assert_eq!(layout.imports.byte_range, 0..20);
        assert_eq!(layout.imports.items.len(), 1);
    }

    #[test]
    fn entity_at_offset_finds_correct() {
        let e = make_entity_with_span("foo", 10, 20);
        let layout = build_layout(&FilePathId::new("test.rs"), &[e.clone()], 30, &[]);

        assert_eq!(entity_at_offset(&layout, 15), Some(e.id));
        assert_eq!(entity_at_offset(&layout, 5), None);
        assert_eq!(entity_at_offset(&layout, 25), None);
    }

    #[test]
    fn entity_byte_range_works() {
        let e = make_entity_with_span("foo", 10, 20);
        let layout = build_layout(&FilePathId::new("test.rs"), &[e.clone()], 30, &[]);

        assert_eq!(entity_byte_range(&layout, &e.id), Some(10..20));
        assert_eq!(entity_byte_range(&layout, &EntityId::new()), None);
    }

    #[test]
    fn build_layout_no_entities() {
        let layout = build_layout(&FilePathId::new("empty.rs"), &[], 100, &[]);
        assert_eq!(layout.regions.len(), 1);
        assert!(matches!(&layout.regions[0], SourceRegion::Trivia { byte_range } if *byte_range == (0..100)));
    }

    #[test]
    fn build_layout_entity_at_start() {
        let e = make_entity_with_span("foo", 0, 10);
        let layout = build_layout(&FilePathId::new("test.rs"), &[e.clone()], 20, &[]);

        assert_eq!(layout.regions.len(), 2);
        assert!(matches!(&layout.regions[0], SourceRegion::EntityRef { .. }));
        assert!(matches!(&layout.regions[1], SourceRegion::Trivia { byte_range } if *byte_range == (10..20)));
    }

    #[test]
    fn update_layout_rebuilds() {
        let e1 = make_entity_with_span("foo", 0, 10);
        let layout = build_layout(&FilePathId::new("test.rs"), &[e1], 20, &[]);

        let e2 = make_entity_with_span("bar", 0, 15);
        let updated = update_layout(&layout, &[e2.clone()], 25, &[]);

        assert_eq!(updated.file_id, FilePathId::new("test.rs"));
        assert!(matches!(&updated.regions[0], SourceRegion::EntityRef { entity_id, .. } if *entity_id == e2.id));
    }
}
