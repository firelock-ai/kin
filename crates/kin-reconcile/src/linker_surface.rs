// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Whether one file edit changed anything another file binds against.
//!
//! The cross-file pass that follows a file edit re-derives the edited file and
//! every file waiting on a name it defines or importing it. Those other files
//! did not change. What they bind against in the edited file is its
//! declarations, its imports and its structural relations (containment,
//! inheritance, overrides, includes). An edit that leaves all three exactly as
//! they were cannot change a binding anywhere else, and re-deriving the other
//! files then reproduces the linker's first answer for every call they make,
//! including the name-only guesses a language server has since contradicted
//! at the call site and retired. On a 3,590-file TypeScript repository, a
//! commit that added one comment inside one method body brought back guesses a
//! proof pass had retired in files the commit never touched.
//!
//! The comparison is between two parses of the same file by the same pipeline,
//! the bytes the graph's declarations came from and the bytes being admitted,
//! with positions and body-derived annotations removed. Anything it cannot
//! establish, an unreadable earlier body, an incomplete parse, a declaration
//! added or removed, reads as moved, which re-derives the other files exactly
//! as before.

use kin_blobs::BlobStore;
use kin_index::IndexedFile;
use kin_model::{Entity, EntityId, FilePathId, ParseState, RelationKind};

/// Entity annotations derived from the body or from positions, never from the
/// declaration another file binds against.
///
/// A key left out of this list makes an edit that changes it read as moved,
/// which only costs the re-derivation this module exists to avoid. So the list
/// is the safe place to be incomplete.
const BODY_DERIVED_ENTITY_KEYS: &[&str] = &[
    // The reconciler's record of the bytes the declaration was parsed from.
    "blob_hash",
    kin_parser::extract::EMBEDDING_BODY_PREVIEW_KEY,
    kin_parser::FILE_PARSED_CALL_SITES_KEY,
    kin_parser::FILE_PARSED_IMPORT_STATEMENTS_KEY,
    kin_parser::FILE_PARSED_EXTERNAL_MODULE_IMPORTS_KEY,
    // A position. The order of declarations is compared on its own.
    kin_parser::DECLARATION_LINE_KEY,
    // Derived from the imports, which are compared whole.
    kin_parser::FILE_IMPORT_CONTEXT_KEY,
];

/// Whether the edit that produced `indexed` over a file whose graph
/// declarations are `existing` can change how another file binds.
///
/// `added` and `removed` are the declarations the reconcile adds and removes:
/// any such change moves the surface without further reading, because another
/// file may bind to the new one or have bound to the old one.
pub(crate) fn edit_moves_linker_surface(
    file_id: &FilePathId,
    indexed: &IndexedFile,
    existing: &[Entity],
    added: &[EntityId],
    removed: &[EntityId],
    blob_store: &BlobStore,
) -> bool {
    if !added.is_empty() || !removed.is_empty() || existing.is_empty() {
        return true;
    }
    if !matches!(indexed.parse_state, ParseState::Valid) {
        return true;
    }
    let Some(previous) = kin_index::unanimous_entity_source_digest(existing) else {
        return true;
    };
    if previous == indexed.blob_hash {
        return false;
    }
    let Ok(bytes) = blob_store.read(&previous) else {
        tracing::debug!(
            file = %file_id,
            "the bytes this file's declarations came from are not readable, so its edit \
             re-derives the files that bind against it"
        );
        return true;
    };
    let Ok(kin_index::IndexedAny::EntitySource(before)) =
        kin_index::IndexPipeline::new().index_any_content(file_id, &bytes, previous)
    else {
        return true;
    };
    if !matches!(before.parse_state, ParseState::Valid) {
        return true;
    }
    let moved = LinkerSurface::of(&before) != LinkerSurface::of(indexed);
    tracing::debug!(
        file = %file_id,
        moved,
        "compared what other files bind against in this file before and after the edit"
    );
    moved
}

/// What another file can bind against in one parse, with every position and
/// body-derived annotation removed.
#[derive(Debug, PartialEq, Eq)]
struct LinkerSurface {
    /// Declarations in source order.
    declarations: Vec<String>,
    /// Import and re-export statements, sorted.
    imports: Vec<String>,
    /// Structural relations, sorted.
    structure: Vec<String>,
}

impl LinkerSurface {
    fn of(indexed: &IndexedFile) -> Self {
        let mut ordered: Vec<&Entity> = indexed.entities.iter().collect();
        ordered.sort_by_key(|entity| {
            let span = entity.span.as_ref();
            (
                span.map_or(u32::MAX, |span| span.start_line),
                span.map_or(u32::MAX, |span| span.start_col),
                entity.name.clone(),
            )
        });
        let declarations = ordered.into_iter().map(declaration).collect();
        let mut imports: Vec<String> = indexed
            .imports
            .iter()
            .map(|import| {
                let mut value = serde_json::to_value(import).unwrap_or_default();
                strip(&mut value, "site");
                if let Some(specifiers) = value
                    .get_mut("specifiers")
                    .and_then(serde_json::Value::as_array_mut)
                {
                    for specifier in specifiers {
                        strip(specifier, "site");
                    }
                }
                value.to_string()
            })
            .collect();
        imports.sort();
        let mut structure: Vec<String> = indexed
            .extracted_relations
            .iter()
            .filter(|relation| is_structural(relation))
            .map(|relation| {
                let mut value = serde_json::to_value(relation).unwrap_or_default();
                strip(&mut value, "site");
                value.to_string()
            })
            .collect();
        structure.sort();
        Self {
            declarations,
            imports,
            structure,
        }
    }
}

/// A relation that says what the file declares or how its declarations relate,
/// as opposed to what the file's own code uses. Only the first kind is read
/// when another file binds.
fn is_structural(relation: &kin_parser::ExtractedRelation) -> bool {
    !kin_parser::is_call_extraction_incomplete_marker(relation)
        && !matches!(
            relation.kind,
            RelationKind::Calls
                | RelationKind::Instantiates
                | RelationKind::References
                | RelationKind::UsesMacro
                | RelationKind::UsesType
        )
}

/// One declaration without its identity, position, fingerprint or any
/// body-derived annotation. The parser mints an identity from the line a
/// declaration sits on, so identities are compared by the reconcile's own
/// match instead: `added` and `removed` are empty by the time this is read.
fn declaration(entity: &Entity) -> String {
    let mut value = serde_json::to_value(entity).unwrap_or_default();
    for field in ["id", "span", "fingerprint", "created_in"] {
        strip(&mut value, field);
    }
    // The metadata bag is flattened into `metadata` on the wire.
    if let Some(metadata) = value.get_mut("metadata") {
        for key in BODY_DERIVED_ENTITY_KEYS {
            strip(metadata, key);
        }
    }
    value.to_string()
}

fn strip(value: &mut serde_json::Value, key: &str) {
    if let Some(object) = value.as_object_mut() {
        object.remove(key);
    }
}
