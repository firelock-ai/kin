// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Entity disambiguation — resolving entity queries against the graph.
//!
//! These functions handle the multi-step lookup process: exact match,
//! qualified name match (with generic normalization), and leaf fallback.

use kin_model::{Entity, EntityFilter, GraphStore};

use crate::error::KinError;
use crate::ranking::{normalize_symbol_hint, normalize_trace_name};

/// Query the graph for entities matching a trace query.
///
/// Tries exact name match first, then falls back to qualified name matching
/// (e.g., `Router::route` matching `Router<S>::route`).
pub fn query_trace_matches(graph: &impl GraphStore, query: &str) -> Result<Vec<Entity>, KinError> {
    let filter = EntityFilter {
        name_pattern: Some(query.to_string()),
        ..Default::default()
    };
    let matches = graph
        .query_entities(&filter)
        .map_err(|e| KinError::Graph(e.to_string()))?;
    if !matches.is_empty() {
        return Ok(matches);
    }

    // A query that CARRIES generics, retried with them stripped.
    //
    // `name_pattern` is a case-insensitive substring test against the raw stored
    // name, so it is asymmetric: `Router` finds `Router<S>` because the stored
    // name contains the query, while `Router<S>` finds nothing, because no
    // stored name contains that literal text unless it spells its parameters
    // identically. `Router<S>` against a stored `Router` and against a stored
    // `Router<State>` both returned zero candidates, through this path and
    // through the leaf fallback alike, since a bare generic name carries neither
    // `::` nor `.` for either retry to split on (measured, FIR-3071).
    //
    // Stripping the query is enough because the store keeps the parameters, so
    // the stripped form is a substring of every spelling of the same symbol.
    // Only attempted when the query actually carries generics and stripping
    // changes it, so no query that resolves today takes a different path.
    let ungenerified = normalize_trace_name(query);
    if ungenerified != query && !ungenerified.trim().is_empty() {
        let stripped_filter = EntityFilter {
            name_pattern: Some(ungenerified),
            ..Default::default()
        };
        let stripped_matches = graph
            .query_entities(&stripped_filter)
            .map_err(|e| KinError::Graph(e.to_string()))?;
        if !stripped_matches.is_empty() {
            return Ok(stripped_matches);
        }
    }

    // Try qualified name matching: strip generics and match qualifier + leaf
    if let Some((qualifier, leaf)) = query.rsplit_once("::") {
        if leaf != query {
            let leaf_filter = EntityFilter {
                name_pattern: Some(leaf.to_string()),
                ..Default::default()
            };
            let leaf_matches = graph
                .query_entities(&leaf_filter)
                .map_err(|e| KinError::Graph(e.to_string()))?;
            if leaf_matches.is_empty() {
                return Ok(leaf_matches);
            }

            let qualifier_hint = normalize_symbol_hint(qualifier);
            let qualified_matches: Vec<_> = leaf_matches
                .iter()
                .filter(|entity| {
                    normalize_symbol_hint(&crate::ranking::normalize_trace_name(&entity.name))
                        .contains(&qualifier_hint)
                })
                .cloned()
                .collect();

            if !qualified_matches.is_empty() {
                return Ok(qualified_matches);
            }
        }
    }

    Ok(matches)
}

/// Whether an entity's own record shows it carries a body, rather than only
/// declaring one.
///
/// The parser writes `signature` by clamping the declaration where its body
/// begins: `kin_parser::adapter::declaration_signature` stops at the `body`
/// field, at a `function_body` or `class_body` child, and at the first comment,
/// then trims a trailing `{` or `:`. A definition therefore stores a signature
/// that ends where its body starts, while a declaration stores its whole
/// statement, terminator included. The terminator is the tell: a signature that
/// still ends in `;` is the entire declaration, because the language closed the
/// statement instead of opening a body.
///
/// This holds wherever a language spells a declaration as a terminated
/// statement, which is every language Kin parses that has the distinction at
/// all: a C prototype, a Rust trait method without a default, a TypeScript
/// `declare` or interface member. A definition's signature ends at its
/// parameter list or return type and never at a terminator.
///
/// Read off the entity alone, so it answers the same way for a store built
/// today and one built from the same tree six commits ago, and nothing here
/// consults the filesystem.
pub fn carries_body(entity: &Entity) -> bool {
    !entity.signature.trim_end().ends_with(';')
}

/// The order two entities sharing a name are chosen in when nothing the caller
/// passed pins one.
///
/// Every term is read off the entity record, so the order is a property of the
/// entities and never of the order a store happened to list them in. That is
/// the whole point. `buffer_grow` declared in `buffer.h` and defined in
/// `buffer.c` is one name over two entities; six stores built from one tree
/// with differing commit dates listed the pair one way three times and the
/// other way three times, while twenty consecutive reads of any single store
/// agreed with themselves. A picker that stopped at the first match therefore
/// traced the declaration on half the stores and the definition on the other
/// half, with nothing in the answer saying which (FIR-3071).
///
/// Lower sorts first: a body beats a declaration, then the file path, then the
/// start line, then the id, which `EntityId::from_content` derives from file,
/// name, kind and line and which is therefore stable across rebuilds of the
/// same tree rather than freshly random per store.
pub fn definition_identity_key(entity: &Entity) -> (bool, String, u32, kin_model::EntityId) {
    (
        !carries_body(entity),
        entity
            .file_origin
            .as_ref()
            .map(|origin| origin.0.clone())
            .unwrap_or_default(),
        entity
            .span
            .as_ref()
            .map(|span| span.start_line)
            .unwrap_or(0),
        entity.id,
    )
}

/// Keep a ranked answer unless it is a declaration and the pool holds a
/// definition under the same name.
///
/// The rankers that need this cannot see the difference on their own. Both
/// `kin_ranking::entity_ranking::select_best_entity` and the pickers built on
/// it score name quality, export status, declaration kind and reference counts,
/// and a C prototype ties its own definition on every one of them, so whichever
/// the store listed first wins. That is the FIR-3071 defect in the rankers that
/// [`definition_identity_key`] does not reach, because they never sort by it.
///
/// Narrow rather than replace, deliberately. The ranked answer stands for every
/// query except the one case its key provably cannot decide, so this cannot
/// reorder a result that was already ranked on real signal. A definition beats a
/// declaration; among several definitions the ranker's choice is kept.
///
/// One home for the rule, because two callers need it from two crates that
/// cannot see each other: `kin path` resolves endpoints in `kin-mcp`, `kin refs`
/// resolves in `kin-cli`, and both reach `kin-core`.
pub fn prefer_definition_among_same_name(chosen: Entity, pool: &[Entity]) -> Entity {
    if carries_body(&chosen) {
        return chosen;
    }
    pool.iter()
        .filter(|candidate| candidate.name == chosen.name && carries_body(candidate))
        .min_by_key(|candidate| definition_identity_key(candidate))
        .cloned()
        .unwrap_or(chosen)
}

/// Whether the name index rules out every resolver match for `query`.
///
/// `find_references` and `trace_data_flow` both resolve a caller's name through
/// [`query_trace_matches`] and `kin_ranking::select_best_entity`, and both reach
/// that resolution only after their route has built the state the answer would
/// be read from: a detached graph snapshot with its merkle root recomputed, or a
/// whole-store repository-authority open. Both are linear in store size, and a
/// name that matches nothing pays all of it to conclude what one index lookup
/// already knew.
///
/// Answering `true` promises that both resolvers would miss, so every branch
/// that cannot promise it answers `false` and leaves the caller on the unchanged
/// path. An id, a name the index knows, or a qualified name whose leaf the index
/// knows are all "not certainly a miss" even where resolution would go on to
/// reject them for some other reason.
pub fn name_resolution_certainly_misses(
    graph: &impl GraphStore,
    query: &str,
) -> Result<bool, KinError> {
    let trimmed = query.trim();
    if trimmed.is_empty() || uuid::Uuid::parse_str(trimmed).is_ok() {
        return Ok(false);
    }
    if !name_index_rules_out(graph, trimmed)? {
        return Ok(false);
    }
    // `query_trace_matches` retries a qualified name against its leaf, so a leaf
    // the index knows keeps the caller on the resolving path.
    if let Some((_, leaf)) = trimmed.rsplit_once("::") {
        if leaf != trimmed && !name_index_rules_out(graph, leaf)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn name_index_rules_out(graph: &impl GraphStore, name: &str) -> Result<bool, KinError> {
    let filter = EntityFilter {
        name_pattern: Some(name.to_string()),
        ..Default::default()
    };
    graph
        .query_entities(&filter)
        .map(|matches| matches.is_empty())
        .map_err(|e| KinError::Graph(e.to_string()))
}

/// Fallback: split on `::` or `.` and search for just the leaf name.
///
/// Used when `query_trace_matches` returns empty. For example,
/// `cfg.run` falls back to searching for `run`.
pub fn fallback_leaf_trace_matches(
    graph: &impl GraphStore,
    query: &str,
) -> Result<Vec<Entity>, KinError> {
    let split = query
        .rfind("::")
        .map(|idx| (idx, 2usize))
        .or_else(|| query.rfind('.').map(|idx| (idx, 1usize)));
    let Some((idx, sep_len)) = split else {
        return Ok(Vec::new());
    };
    let leaf = &query[idx + sep_len..];
    if leaf == query {
        return Ok(Vec::new());
    }
    let leaf_filter = EntityFilter {
        name_pattern: Some(leaf.to_string()),
        ..Default::default()
    };
    graph
        .query_entities(&leaf_filter)
        .map_err(|e| KinError::Graph(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_db::InMemoryGraph;
    use kin_model::{
        Entity, EntityId, EntityKind, EntityMetadata, EntityRole, EntityStore,
        FingerprintAlgorithm, Hash256, LanguageId, SemanticFingerprint, Visibility,
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

    /// The generics gap, from the measurement beside it.
    ///
    /// Both of these returned zero candidates through every path before the
    /// stripped retry: the direct lookup misses because `name_pattern` is a
    /// substring test on the raw stored name and `Router<S>` is not a substring
    /// of `Router`, and the leaf fallback misses because a bare generic name has
    /// no `::` or `.` to split on.
    #[test]
    fn a_query_carrying_generics_reaches_a_name_that_spells_them_differently() {
        let store = InMemoryGraph::new();
        store.upsert_entity(&make_entity("Router")).unwrap();
        let plain = query_trace_matches(&store, "Router<S>").unwrap();
        assert_eq!(
            plain.len(),
            1,
            "a generic query must reach the ungenerified stored name"
        );
        assert_eq!(plain[0].name, "Router");

        let other = InMemoryGraph::new();
        other.upsert_entity(&make_entity("Router<State>")).unwrap();
        let renamed = query_trace_matches(&other, "Router<S>").unwrap();
        assert_eq!(
            renamed.len(),
            1,
            "the parameter's spelling must not decide whether a symbol is found"
        );
        assert_eq!(renamed[0].name, "Router<State>");
    }

    /// The retry must not widen a query that already resolves, and must not
    /// invent a match for a name nothing carries.
    #[test]
    fn the_generic_retry_changes_nothing_a_direct_lookup_already_answers() {
        let store = InMemoryGraph::new();
        store.upsert_entity(&make_entity("Router<S>")).unwrap();
        store.upsert_entity(&make_entity("RouterBuilder")).unwrap();

        let exact = query_trace_matches(&store, "Router<S>").unwrap();
        assert_eq!(exact.len(), 1, "the direct hit is returned as it was");
        assert_eq!(exact[0].name, "Router<S>");

        assert!(
            query_trace_matches(&store, "Absent<T>").unwrap().is_empty(),
            "a name nothing carries stays a miss, generics or not"
        );
    }

    /// The rule the rankers cannot see, in the one case it fires and the three
    /// where it must not.
    #[test]
    fn prefer_definition_only_overrides_a_declaration_that_has_a_definition() {
        let mut declaration = make_entity("buffer_grow");
        declaration.signature = "int buffer_grow(buf_t *b, size_t need);".to_string();
        let mut definition = make_entity("buffer_grow");
        definition.signature = "int buffer_grow(buf_t *b, size_t need)".to_string();
        let mut unrelated = make_entity("other_name");
        unrelated.signature = "int other_name(void)".to_string();

        let pool = vec![declaration.clone(), definition.clone(), unrelated.clone()];

        // Fires: a declaration whose definition is in the pool.
        assert_eq!(
            prefer_definition_among_same_name(declaration.clone(), &pool).id,
            definition.id,
            "a declaration must yield to its own definition"
        );
        // Does not fire: the ranked answer already carries a body.
        assert_eq!(
            prefer_definition_among_same_name(definition.clone(), &pool).id,
            definition.id
        );
        // Does not fire: no definition under that name, so the declaration is
        // the only truth the graph holds and must be returned unchanged.
        let only_declaration = vec![declaration.clone(), unrelated];
        assert_eq!(
            prefer_definition_among_same_name(declaration.clone(), &only_declaration).id,
            declaration.id,
            "with no definition to prefer, the declaration stands"
        );
        // Does not fire across names: a definition of a DIFFERENT name must
        // never capture a declaration.
        let mut foreign = make_entity("unrelated_definition");
        foreign.signature = "int unrelated_definition(void)".to_string();
        assert_eq!(
            prefer_definition_among_same_name(declaration.clone(), &[foreign]).id,
            declaration.id
        );
    }

    /// The semicolon rule's language scope, asserted rather than assumed.
    ///
    /// `carries_body` applies to EVERY language, while the kin-index linker's
    /// equivalent gates on C and C++ because C is all that lane measured. Mine
    /// is the wider claim, so it is mine to defend: a signature ending in `;`
    /// must be a declaration in every language Kin parses, never a definition.
    ///
    /// These are the shapes that could break it, each spelled as
    /// `kin_parser::adapter::declaration_signature` stores it. That function
    /// clamps the end at the body's start byte and trims a trailing `{` or `:`,
    /// so a definition's stored signature ends at its parameter list or return
    /// type; only a statement the language itself closed keeps a terminator.
    ///
    /// The controls matter more than the cases. If a definition ever arrives
    /// here with a stored `;`, this test fails and the rule must be gated by
    /// language.
    #[test]
    fn a_stored_signature_ending_in_a_semicolon_is_a_declaration_in_every_language() {
        // Declarations: the language closed the statement, so the terminator is
        // part of what the parser stored.
        let declarations: &[(&str, &str)] = &[
            (
                "C prototype",
                "int redisReaderGetReply(redisReader *r, void **reply);",
            ),
            ("C++ member declaration", "void reset();"),
            (
                "Rust trait method, no default",
                "fn route(&self, req: Request) -> Response;",
            ),
            ("Rust extern block item", "pub fn abs(input: i32) -> i32;"),
            (
                "TypeScript overload signature",
                "parse(input: string): Node;",
            ),
            ("TypeScript interface member", "readonly id: string;"),
            ("Java abstract method", "public abstract void run();"),
            ("C# abstract method", "public abstract int Area();"),
        ];
        for (what, signature) in declarations {
            let mut entity = make_entity("subject");
            entity.signature = signature.to_string();
            assert!(
                !carries_body(&entity),
                "{what} must read as a declaration: {signature:?}"
            );
        }

        // Definitions, stored the way the parser stores them: clamped where the
        // body begins. None of these may end in a terminator, in any language.
        let definitions: &[(&str, &str)] = &[
            (
                "C definition",
                "int redisReaderGetReply(redisReader *r, void **reply)",
            ),
            ("Rust function", "fn route(&self, req: Request) -> Response"),
            (
                "Rust trait method with a default",
                "fn route(&self, req: Request) -> Response",
            ),
            ("TypeScript implementation", "parse(input: string): Node"),
            ("Python function", "def parse(self, text)"),
            ("Go function", "func Parse(text string) (*Node, error)"),
            ("Java method", "public void run()"),
            ("C# method", "public int Area()"),
        ];
        for (what, signature) in definitions {
            let mut entity = make_entity("subject");
            entity.signature = signature.to_string();
            assert!(
                carries_body(&entity),
                "{what} must read as a definition: {signature:?}"
            );
        }
    }

    /// MEASUREMENT, not an assertion. Prints what a generic-bearing query
    /// resolves to today, so the fix is shaped by what this shows rather than by
    /// what the code reads like. Run with --nocapture.
    #[test]
    fn measure_generic_query_resolution_today() {
        let cases: &[(&str, &str)] = &[
            ("Router<S>::route", "Router::route"),
            ("Router<S>::route", "Router<S>::route"),
            ("Router<State>::route", "Router<S>::route"),
            ("Router", "Router<S>"),
            ("Router<S>", "Router"),
            ("Router<S>", "Router<State>"),
            ("Map<K, V>::insert", "Map<K,V>::insert"),
            ("Map<K, V>.insert", "Map<K,V>.insert"),
            ("Result<T, E>", "Result"),
            ("Vec<T>", "Vec"),
        ];
        println!("\nstored_name | query | query_trace_matches | fallback_leaf | resolved");
        for (stored, query) in cases {
            let store = InMemoryGraph::new();
            store.upsert_entity(&make_entity(stored)).unwrap();
            let direct = query_trace_matches(&store, query).unwrap();
            let fallback = if direct.is_empty() {
                fallback_leaf_trace_matches(&store, query).unwrap()
            } else {
                Vec::new()
            };
            let pool = if direct.is_empty() {
                &fallback
            } else {
                &direct
            };
            let resolved = crate::ranking::select_best_match(query, pool, |entity, hint| {
                crate::ranking::normalize_symbol_hint(&entity.name).contains(hint)
            })
            .map(|e| e.name.clone())
            .unwrap_or_else(|| "MISS".to_string());
            println!(
                "{stored} | {query} | {} | {} | {resolved}",
                direct.len(),
                fallback.len()
            );
        }
    }

    #[test]
    fn query_trace_matches_falls_back_to_leaf_for_rust_style_names() {
        let store = InMemoryGraph::new();
        let entity = make_entity("Router<S>::route");
        store.upsert_entity(&entity).unwrap();

        let matches = query_trace_matches(&store, "Router::route").unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].name, "Router<S>::route");
    }

    #[test]
    fn query_trace_matches_rejects_unrelated_leaf_match_for_qualified_name() {
        let store = InMemoryGraph::new();
        store.upsert_entity(&make_entity("run")).unwrap();

        let matches = query_trace_matches(&store, "$Config::run").unwrap();
        assert!(matches.is_empty());
    }

    #[test]
    fn name_resolution_certainly_misses_only_for_a_name_the_index_cannot_place() {
        let store = InMemoryGraph::new();
        store.upsert_entity(&make_entity("route")).unwrap();

        assert!(
            name_resolution_certainly_misses(&store, "no_such_symbol").unwrap(),
            "a name no index entry carries is a certain miss"
        );
        assert!(
            !name_resolution_certainly_misses(&store, "route").unwrap(),
            "a name the index carries must stay on the resolving path"
        );
    }

    /// The three shapes that must never be short-circuited, each of which the
    /// bare name index cannot place on its own: a uuid the caller means as an
    /// id, a qualified name whose leaf resolves, and an empty query whose own
    /// error the resolver owns.
    #[test]
    fn name_resolution_certainly_misses_defers_what_the_name_index_cannot_decide() {
        let store = InMemoryGraph::new();
        let entity = make_entity("run");
        let id = entity.id;
        store.upsert_entity(&entity).unwrap();

        assert!(!name_resolution_certainly_misses(&store, &id.to_string()).unwrap());
        assert!(!name_resolution_certainly_misses(&store, "Config::run").unwrap());
        assert!(!name_resolution_certainly_misses(&store, "   ").unwrap());
    }

    #[test]
    fn fallback_leaf_trace_matches_supports_dotted_queries() {
        let graph = InMemoryGraph::new();
        let run = make_entity("run");
        graph.upsert_entity(&run).unwrap();

        let matches = fallback_leaf_trace_matches(&graph, "cfg.run").unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].name, "run");
    }
}
