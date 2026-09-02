// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Entity ranking and disambiguation algorithms.
//!
//! These functions select the best entity match from a set of candidates,
//! used by both the CLI `trace` command and the MCP server.

use kin_model::Entity;

/// Select the best matching entity from a set of candidates.
///
/// Ranking criteria (in priority order):
/// 1. Exact name match (or normalized match)
/// 2. Qualifier support (parent type/module matches query prefix)
/// 3. Qualified leaf match (entity name ends with query)
/// 4. Method-style hint (both query and name use `::` or neither does)
/// 5. Has file origin (prefer entities with known source locations)
/// 6. Shorter name (prefer less-qualified names as more specific)
/// 7. Definition identity: a body beats a declaration, then file, line, id
///
/// Criterion 7 exists so the answer is a property of the candidates rather than
/// of the order the store listed them in. Everything above it can tie exactly:
/// two entities sharing one name, one kind and one length tie on all six, and
/// `min_by_key` then keeps whichever the store happened to yield first. Six
/// stores built from one tree with differing commit dates split three and three
/// on which of `buffer_grow`'s two entities came first, so `kin trace` answered
/// about the header's declaration on half of them (FIR-3071). The tail terms
/// are read off the entity record, so they cannot vary that way.
///
/// The `qualifier_checker` callback is used to check whether an entity
/// matches a qualifier hint. This allows the caller to provide file-based
/// disambiguation (reading source files) or purely name-based checks.
pub fn select_best_match<'a, F>(
    query: &str,
    matches: &'a [Entity],
    qualifier_checker: F,
) -> Option<&'a Entity>
where
    F: Fn(&Entity, &str) -> bool,
{
    let query = query.trim();
    let normalized_query = normalize_trace_name(query);
    let qualifier_hint = qualifier_hint_from_query(query);

    // If a qualifier was provided, check if ANY candidate supports it.
    // If none do, return None (the qualifier is unmatched).
    let any_qualifier_match = qualifier_hint
        .as_ref()
        .map(|hint| matches.iter().any(|e| qualifier_checker(e, hint)))
        .unwrap_or(true);

    if qualifier_hint.is_some() && !any_qualifier_match {
        return None;
    }

    matches.iter().min_by_key(|e| {
        let normalized_name = normalize_trace_name(&e.name);
        let qualifier_supported = qualifier_hint
            .as_ref()
            .map(|hint| qualifier_checker(e, hint))
            .unwrap_or(false);
        let exact = (e.name == query)
            || (e.id.to_string() == query)
            || (normalized_name == normalized_query);
        let qualified_leaf = e.name.rsplit('.').next() == Some(query)
            || e.name.rsplit("::").next() == Some(query)
            || normalized_name.rsplit('.').next() == Some(query)
            || normalized_name.rsplit("::").next() == Some(query);
        let method_hint = normalized_name.contains("::") == normalized_query.contains("::");
        let file_rank = e.file_origin.is_some();
        (
            !exact,
            !qualifier_supported,
            !qualified_leaf,
            !method_hint,
            !file_rank,
            e.name.len(),
            crate::disambiguation::definition_identity_key(e),
        )
    })
}

/// Extract a qualifier hint from a query string.
///
/// For `"Foo::bar"` returns `Some("foo")`, for `"Foo.bar"` returns `Some("foo")`.
/// Returns `None` if the query has no qualifier prefix.
pub fn qualifier_hint_from_query(query: &str) -> Option<String> {
    query
        .rfind("::")
        .map(|idx| &query[..idx])
        .or_else(|| query.rfind('.').map(|idx| &query[..idx]))
        .map(normalize_symbol_hint)
        .filter(|s| !s.is_empty())
}

/// Normalize a trace name by stripping generic type parameters.
///
/// `"Router<S>::route"` becomes `"Router::route"`, `"Map<K, V>::insert"` becomes `"Map::insert"`.
pub fn normalize_trace_name(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut depth = 0usize;
    for ch in name.chars() {
        match ch {
            '<' => depth += 1,
            '>' => depth = depth.saturating_sub(1),
            _ if depth == 0 => out.push(ch),
            _ => {}
        }
    }
    out
}

/// Normalize a symbol hint for fuzzy matching.
///
/// Strips leading `$`, removes `<>:.` characters, and lowercases.
pub fn normalize_symbol_hint(name: &str) -> String {
    normalize_trace_name(name)
        .trim_start_matches('$')
        .replace(['<', '>', ':', '.'], "")
        .to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{
        Entity, EntityId, EntityKind, EntityMetadata, EntityRole, FingerprintAlgorithm, Hash256,
        LanguageId, SemanticFingerprint, Visibility,
    };

    fn make_entity(name: &str) -> Entity {
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::TypeScript,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_hex(
                    "1111111111111111111111111111111111111111111111111111111111111111",
                )
                .unwrap(),
                signature_hash: Hash256::from_hex(
                    "2222222222222222222222222222222222222222222222222222222222222222",
                )
                .unwrap(),
                behavior_hash: Hash256::from_hex(
                    "3333333333333333333333333333333333333333333333333333333333333333",
                )
                .unwrap(),
                equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: None,
            span: None,
            signature: format!("function {name}()"),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    // Name-only qualifier checker for tests (no file access)
    fn name_only_checker(entity: &Entity, hint: &str) -> bool {
        normalize_symbol_hint(&entity.name).contains(hint)
    }

    #[test]
    fn prefers_exact_name_match() {
        let entities = vec![make_entity("Foo.bar"), make_entity("bar")];
        let picked = select_best_match("bar", &entities, name_only_checker).unwrap();
        assert_eq!(picked.name, "bar");
    }

    #[test]
    fn falls_back_to_qualified_leaf_match() {
        let entities = vec![make_entity("Foo.parseStrict"), make_entity("Foo.parse")];
        let picked = select_best_match("parseStrict", &entities, name_only_checker).unwrap();
        assert_eq!(picked.name, "Foo.parseStrict");
    }

    #[test]
    fn prefers_rust_style_qualified_match_without_generics() {
        let entities = vec![make_entity("Router<S>::route"), make_entity("route")];
        let picked = select_best_match("Router::route", &entities, name_only_checker).unwrap();
        assert_eq!(picked.name, "Router<S>::route");
    }

    #[test]
    fn returns_none_when_qualifier_is_unmatched() {
        let entities = vec![make_entity("run"), make_entity("Helper.run")];
        let picked = select_best_match("$Config::run", &entities, name_only_checker);
        assert!(picked.is_none());
    }

    #[test]
    fn normalize_trace_name_strips_generic_arguments() {
        assert_eq!(normalize_trace_name("Router<S>::route"), "Router::route");
        assert_eq!(normalize_trace_name("Map<K, V>::insert"), "Map::insert");
    }

    #[test]
    fn qualifier_hint_from_qualified_name() {
        assert_eq!(
            qualifier_hint_from_query("Foo::bar"),
            Some("foo".to_string())
        );
        assert_eq!(
            qualifier_hint_from_query("Foo.bar"),
            Some("foo".to_string())
        );
        assert_eq!(qualifier_hint_from_query("bar"), None);
    }
}
