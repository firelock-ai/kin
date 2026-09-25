// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use kin_model::{Entity, EntityKind};
use kin_parser::ExtractedRelation;
use std::collections::HashMap;

/// A borrowed per-file source index. Build once for a complete parse, then
/// resolve each raw occurrence against only its same-name declaration group.
pub struct RelationSourceIndex<'a> {
    by_name: HashMap<&'a str, Vec<&'a Entity>>,
}

impl<'a> RelationSourceIndex<'a> {
    pub fn new(entities: &'a [Entity]) -> Self {
        let mut by_name: HashMap<&str, Vec<&Entity>> = HashMap::new();
        for entity in entities {
            by_name.entry(&entity.name).or_default().push(entity);
        }
        Self { by_name }
    }

    /// Repeated names need an exact site and a unique innermost containing
    /// span. Declaration order and name-map overwrites establish no ownership.
    pub fn resolve(&self, relation: &ExtractedRelation) -> Option<&'a Entity> {
        let named = self.by_name.get(relation.src_name.as_str())?;
        let Some(site) = &relation.site else {
            // Preserve ordinary non-Module binding when a module and a real
            // declaration share a name, without choosing between siblings.
            let has_declaration = named.iter().any(|entity| entity.kind != EntityKind::Module);
            let mut candidates = named
                .iter()
                .copied()
                .filter(|entity| !has_declaration || entity.kind != EntityKind::Module);
            let first = candidates.next()?;
            return candidates.next().is_none().then_some(first);
        };
        if site.start_byte >= site.end_byte {
            return None;
        }
        let candidates = || {
            named.iter().copied().filter_map(|entity| {
                let span = entity.span.as_ref()?;
                (span.start_byte <= site.start_byte && site.end_byte <= span.end_byte)
                    .then_some((span.end_byte - span.start_byte, entity))
            })
        };
        let (width, first) = candidates().min_by_key(|(width, _)| *width)?;
        let innermost = first.span.as_ref()?;
        let mut equally_small = 0;
        for (other_width, entity) in candidates() {
            equally_small += usize::from(other_width == width);
            let span = entity.span.as_ref().unwrap();
            if span.start_byte > innermost.start_byte || span.end_byte < innermost.end_byte {
                // Intersecting but non-nested spans establish no lexical owner.
                return None;
            }
        }
        (equally_small == 1).then_some(first)
    }
}

/// Resolve one raw occurrence without retaining an index. Callers processing
/// a whole file should reuse [`RelationSourceIndex`] instead.
pub fn relation_source_entity<'a>(
    relation: &ExtractedRelation,
    entities: &'a [Entity],
) -> Option<&'a Entity> {
    RelationSourceIndex::new(entities).resolve(relation)
}
