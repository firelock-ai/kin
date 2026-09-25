// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use kin_model::{Entity, EntityKind};

use crate::{AdapterRegistry, ParseError, Result};

/// Check independently readable module coordinates against graph-owned source.
///
/// Older Rust extraction enhanced a same-name synthetic file module's metadata
/// without replacing its whole-file span. The signature and fingerprint already
/// describe a real declaration, so metadata cannot distinguish those persisted
/// nodes. Reparse the authoritative bytes and require the stored span to match an
/// actual declaration exactly. Never repair coordinates as part of a read.
/// Non-container entities retain their existing source-coherence validation.
pub fn validate_module_source_span(entity: &Entity, source: &[u8]) -> Result<()> {
    if !matches!(entity.kind, EntityKind::Module | EntityKind::Package) {
        return Ok(());
    }
    let refusal = || {
        ParseError::Extraction(format!(
        "entity {} has no verified independent module declaration span; reparse/reconcile its source before reading or editing its body",
        entity.id
    ))
    };
    kin_model::require_independent_source(entity).map_err(|_| refusal())?;
    let file = entity.file_origin.as_ref().ok_or_else(refusal)?;
    let span = entity.span.as_ref().ok_or_else(refusal)?;
    if &span.file != file {
        return Err(refusal());
    }
    let adapters = AdapterRegistry::new();
    let adapter = adapters
        .get_by_language(entity.language)
        .ok_or_else(refusal)?;
    let tree = adapter.parse(source)?;
    let parsed = adapter.extract(&tree, source, file)?;
    let matches = parsed
        .entities
        .iter()
        .filter(|candidate| {
            candidate.kind == entity.kind
                && candidate.name == entity.name
                && candidate.signature == entity.signature
                && &candidate.span == span
                && !kin_model::is_file_module_surface(
                    &(*candidate).clone().into_entity(entity.language, file),
                )
        })
        .count();
    if matches != 1 {
        return Err(refusal());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{FilePathId, LanguageId};

    #[test]
    fn module_source_span_rejects_legacy_widening_without_repairing_coordinates() {
        let source =
            b"pub mod defaults { pub fn inside() {} }\npub fn outside() { sibling_only(); }\n";
        let adapters = AdapterRegistry::new();
        let adapter = adapters.get_by_language(LanguageId::Rust).unwrap();
        let file = FilePathId::new("src/defaults.rs");
        let parsed = adapter
            .extract(&adapter.parse(source).unwrap(), source, &file)
            .unwrap();
        let module = parsed
            .entities
            .into_iter()
            .find(|e| e.kind == EntityKind::Module)
            .unwrap()
            .into_entity_with_source(LanguageId::Rust, &file, Some(source));
        validate_module_source_span(&module, source).unwrap();
        let mut legacy = module.clone();
        legacy.span.as_mut().unwrap().end_byte = source.len();
        legacy.span.as_mut().unwrap().end_line = 2;
        legacy.span.as_mut().unwrap().end_col = 0;
        let before = serde_json::to_value(&legacy).unwrap();
        assert!(validate_module_source_span(&legacy, source)
            .unwrap_err()
            .to_string()
            .contains("reparse/reconcile"));
        assert_eq!(serde_json::to_value(&legacy).unwrap(), before);
        let mut wrong_signature = module.clone();
        wrong_signature.signature = "pub mod somebody_else".into();
        assert!(validate_module_source_span(&wrong_signature, source).is_err());
        let standalone = b"pub mod defaults {}";
        let parsed = adapter
            .extract(&adapter.parse(standalone).unwrap(), standalone, &file)
            .unwrap();
        let module = parsed
            .entities
            .into_iter()
            .find(|e| e.kind == EntityKind::Module)
            .unwrap()
            .into_entity(LanguageId::Rust, &file);
        assert_eq!(module.span.as_ref().unwrap().end_byte, standalone.len());
        validate_module_source_span(&module, standalone).unwrap();
    }
}
