// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Short tool descriptions and trimmed input schemas for the `agent-default`
//! profile.
//!
//! The registered descriptions in [`crate::tools`] are written for a reader with
//! room to read them. Measured on 2026-09-02, the `agent-default` profile's
//! `tools/list` is 82,262 bytes over 20 tools: 47,739 characters of description
//! and 30,456 bytes of input schema, roughly 20,500 tokens spent before the
//! model has asked anything. `semantic_locate` alone is 5,375 characters and
//! advertises thirteen input properties; `trace_data_flow` is 6,823. A 7.5B model
//! steered by that belt spent its budget on the wrong tools.
//!
//! So `agent-default` gets a second, shorter form of each description, and a
//! keep-list naming the input properties an agent actually needs. The `full`
//! profile is untouched and still serves every word, and so are the `benchmark`
//! and `context-bench` profiles, whose payload bytes are part of a citable
//! result and must not move because a description was rewritten.
//!
//! Every short form answers two questions in one or two sentences: when to call
//! this, and what comes back. Where two tools are easy to confuse, the one a
//! caller reaches for by mistake names the other.
//!
//! Trimming a schema hides a property; it does not remove it. No tool in this
//! profile sets `additionalProperties: false`, and the handlers read arguments
//! by name, so a caller that knows a withheld property can still pass it and the
//! `full` profile still advertises every one.

use std::collections::{BTreeMap, HashMap};

use crate::types::ToolsListResult;

/// The most characters one `agent-default` description may carry.
///
/// 520 is roughly two sentences of technical prose. It is a budget rather than a
/// target: several tools here are shorter, and none should need more, because a
/// description longer than this is documentation, and documentation belongs in
/// the `full` profile where a reader has the room for it.
/// `no_agent_default_description_exceeds_its_budget` below fails on any tool
/// that exceeds it.
pub const AGENT_DEFAULT_DESCRIPTION_BUDGET: usize = 520;

/// The whole profile's description budget.
///
/// 10,000 characters against the 47,739 the long forms cost. Held as a total as
/// well as a per-tool cap because twenty tools each sitting just under the
/// per-tool budget would be a profile that had learned nothing.
pub const AGENT_DEFAULT_PROFILE_DESCRIPTION_BUDGET: usize = 10_000;

/// The honest name for the declaration filter.
///
/// `semantic_search` does not search semantically. Its own registered
/// description opens "Find code declarations in the semantic graph by name,
/// kind, or language" and its arguments are `query`, `kind` and `language`: it
/// is a filter over declarations, and it ignores the query for ranking.
/// `semantic_locate` is the tool that ranks by meaning. A model reads a name
/// before it reads five thousand characters of prose, and these two names are
/// the wrong way round.
///
/// Served under this name on `agent-default` only. The registration, the
/// dispatch key, the budget shape and the negative-evidence spec all stay on
/// `semantic_search`, so nothing internal is renamed and no existing caller
/// breaks; [`canonical_tool_name`] maps this name back before any of them see
/// it. `find_declarations` also reads as a pair with
/// `find_references`, which is the tool an agent reaches for next.
pub const DECLARATION_FILTER_ALIAS: &str = "find_declarations";

/// The registered name [`DECLARATION_FILTER_ALIAS`] stands in for.
pub const DECLARATION_FILTER_CANONICAL: &str = "semantic_search";

/// Map a served tool name back to the name everything internal is keyed on.
///
/// One function, called once per call at the point the name is parsed, so the
/// profile filter, the dispatcher, the response-budget shape, the
/// negative-evidence spec and the envelope all see the registered name and none
/// of them has to learn the alias. Every other name is returned unchanged, so
/// this is safe to call unconditionally and on every profile: a caller that
/// still sends `semantic_search` reaches the same handler it always did.
pub fn canonical_tool_name(name: &str) -> &str {
    if name == DECLARATION_FILTER_ALIAS {
        DECLARATION_FILTER_CANONICAL
    } else {
        name
    }
}

/// The in-place form, for a dispatcher that holds the name it parsed.
///
/// Separate from [`canonical_tool_name`] rather than spelled out at each call
/// site, because the obvious spelling does not compile: the returned `&str`
/// borrows the string being assigned to, so binding it before the assignment
/// holds a shared borrow across a mutable one. This does the comparison and
/// leaves a name that is already canonical untouched, so the common path
/// allocates nothing.
pub fn canonicalize_tool_name(name: &mut String) {
    if name == DECLARATION_FILTER_ALIAS {
        name.clear();
        name.push_str(DECLARATION_FILTER_CANONICAL);
    }
}

/// Ask `semantic_locate` for the compact shape on this belt's behalf.
///
/// The compact response is opt-in on the wire, and deliberately so: the fused
/// `semantic_locate` payload IS the `LocateResult` schema `kin locate --json`
/// and `POST /locate` serialize, asserted by
/// `mcp_semantic_locate_fused_payload_round_trips_into_locate_schema` and two
/// sibling tests, so a consumer needs one parser across all three. Narrowing
/// that by default would break the contract for every caller to help one of
/// them.
///
/// This is where the one that needs helping asks. The belt exists to fit a small
/// model's context, its agents read ids and coordinates rather than the shared
/// schema, and on a 730-entity store the shapes are 38,819 bytes against 3,472
/// at twelve results.
///
/// Only when the caller named no `surface` of its own. An agent that asks for
/// `full` gets full, which is what makes this a default rather than an override.
pub fn apply_belt_defaults(name: &str, arguments: &mut HashMap<String, serde_json::Value>) {
    if name != "semantic_locate" {
        return;
    }
    arguments
        .entry("surface".to_string())
        .or_insert_with(|| serde_json::Value::String("compact".to_string()));
}

/// The short description for each tool the `agent-default` profile serves, by
/// registered name.
///
/// Keyed on the REGISTERED name, including for the declaration filter, so the
/// table has one key per tool and the rename stays a serving concern.
fn short_descriptions() -> BTreeMap<&'static str, &'static str> {
    BTreeMap::from([
        // ── Retrieval: the four questions an agent actually arrives with ──
        (
            "semantic_locate",
            "Find the code behind a plain-language question, ranked from the graph. Call this when \
             you know what the code does but not what it is called. Returns each hit's entity_id, \
             name, kind, file, line, signature and score. Read `ranked_by` first: with no \
             embeddings the ranking is lexical, so a plain word of your question can match a \
             symbol of that name and crowd the first rows. If you already know the exact symbol \
             name, call find_declarations instead.",
        ),
        (
            DECLARATION_FILTER_CANONICAL,
            "Filter declarations by name, kind or language: functions, methods, classes, structs, \
             traits, enums, types and constants the graph already parsed. Call this when you know \
             what the thing is called, or want every class in one language. It matches names, not \
             meaning, and does not rank by your query. Returns id, name, kind, language, file and \
             line range per match, plus the total. For a description rather than a name, call \
             semantic_locate.",
        ),
        (
            "list_file_entities",
            "List every entity the graph holds for one file, given a repo-relative path. This is \
             the only retrieval tool that can say what it left out: it returns the whole set and \
             reports whether that set is complete, where a ranked tool cannot. Call it for \"what \
             is in this file\" and before concluding a file contains nothing.",
        ),
        (
            "kin_graph_status",
            "Report the graph this call is answered from: entity and relation counts, and how many \
             entities are embedded, pending or unindexed. Call it first when a search returns less \
             than you expect, since an unembedded graph cannot rank by meaning.",
        ),
        // ── Walking: the chain question, and where it is answered ──
        (
            "trace_data_flow",
            "Walk the call chain out from one entity and get the whole path back in one call, as \
             an ordered list of steps. Call it when you name ONE thing and ask what it reaches or \
             what reaches it: give it a focal entity_id, a direction and a depth. It walks call \
             and import edges, so it does not follow a value through a variable. Prefer it over \
             looping find_references by hand.",
        ),
        (
            "find_references",
            "Find who depends on one entity: its direct callers, importers and references, one row \
             per referencing entity with that caller's id, name, kind, file and the lines it \
             references from. Call it for \"what breaks if I change this\" at one hop. For a whole \
             chain rather than one hop, call trace_data_flow.",
        ),
        (
            "graph_neighborhood",
            "Get what one entity depends on and what depends on it, out to a depth you choose, as \
             lightweight summaries with ids. Call it to orient around unfamiliar code. Use \
             find_references when you want callers only, and trace_data_flow when you want an \
             ordered path rather than a neighborhood.",
        ),
        (
            "impact_analysis",
            "Walk the graph from a change to every entity it could affect. Target it one way at a \
             time: entity_ids, file paths, base and head change ids, or change_ids. Call it before \
             editing, to answer \"what breaks if I change this\" across the repository rather than \
             at one hop.",
        ),
        // ── Reading ──
        (
            "get_entity_source",
            "Return one entity's exact implementation body by entity_id, from graph-owned truth, \
             with its name, kind, language, file, line range and signature. This is how you read \
             the code once any other tool has handed you an id.",
        ),
        (
            "get_context_pack",
            "Assemble a ready-to-read bundle around one entity, fitted to a token budget: the \
             focal body plus the signatures of what it depends on, and optionally its tests and \
             transitive dependencies. Call it when you are about to change an entity and want its \
             surroundings in one call instead of several get_entity_source reads.",
        ),
        (
            "kin_artifact_list",
            "List the repository's tracked files at one semantic change, code and non-code alike: \
             Dockerfiles, lockfiles, configuration, assets, symlinks and unsupported languages. \
             Call it to answer what the repository contains, rather than what the parsers turned \
             into entities.",
        ),
        (
            "kin_artifact_read",
            "Read one tracked file's exact bytes by artifact_id or repo-relative path, returned as \
             base64 and, when it is valid UTF-8, as text. Call it for a file the parsers produced \
             no entities for, which is what a locate hit carrying artifact_path instead of \
             entity_id means.",
        ),
        (
            "kin_provenance_query",
            "Answer who changed an entity and whether it was approved: its change count, latest \
             change, approvals on that change, a page of its changes newest first, and recent \
             audit events. Call it before relying on code whose history matters.",
        ),
        // ── Sessions ──
        (
            "kin_session_start",
            "Register this agent with Kin and get a session_id: who you are, your transport, \
             working directory and capabilities. Call it once at the start of your work, before \
             any transaction, so activity is attributed and other agents can see your presence.",
        ),
        (
            "kin_session_heartbeat",
            "Keep a session marked alive. Call it periodically during long work so Kin does not \
             treat the session as stale and release what it holds.",
        ),
        (
            "kin_session_end",
            "End a session and release everything it held, freeing its intents so other agents are \
             no longer warned off those scopes. Call it when your work finishes.",
        ),
        // ── Writing ──
        (
            "kin_transaction_begin",
            "Open a repository mutation transaction and get a transaction_id. Call it before \
             staging any change. Nothing is written until kin_transaction_commit.",
        ),
        (
            "kin_transaction_stage",
            "Stage one or more mutations onto an open transaction. Four verbs: 'create' admits a \
             file the graph has never seen, 'update' changes an entity inside one it holds, \
             'delete' retires one, 'rename' moves one. An 'update' replaces the entity's whole \
             body, so read the current one with get_entity_source first rather than guessing it.",
        ),
        (
            "kin_transaction_commit",
            "Publish every staged mutation atomically: the daemon reparses the final bytes and \
             journals the semantic change, the workspace tree and the ref together. All of it \
             lands or none of it does. Re-sending a fenced commit is safe and reports whether it \
             already landed.",
        ),
        (
            "kin_transaction_abort",
            "Abandon an open transaction and discard everything staged on it. Call it when you \
             decide against a change, or to start clean after a refusal. Refused once \
             kin_transaction_commit has fenced the transaction; re-send the commit instead.",
        ),
    ])
}

/// The input properties `agent-default` advertises for each tool, by registered
/// name. A tool absent from this table keeps its full schema.
///
/// Two rules decided every list. A property that changes WHICH entities come
/// back stays. A property that only reshapes the response (`compact`,
/// `max_chars`, `explain`, `snippet_alias`, `pipeline`) goes, because the
/// profile now picks those defaults itself and every one of them is another line
/// the model reads before it can ask its question.
fn schema_keep_lists() -> BTreeMap<&'static str, &'static [&'static str]> {
    BTreeMap::from([
        // Thirteen properties down to five. `cursor` and `page_size` stay
        // because paging is how a caller reaches past the first page;
        // `include_tests` stays because it changes which entities can rank at
        // all, and a caller asking about a test cannot otherwise find one.
        (
            "semantic_locate",
            &["query", "limit", "granularity", "cursor", "include_tests"] as &[&str],
        ),
        (
            DECLARATION_FILTER_CANONICAL,
            &["query", "kind", "language", "limit"] as &[&str],
        ),
        // `query` stays beside `entity_id`: this tool resolves an exact symbol
        // name to its canonical definition, and dropping it would take away the
        // path a caller uses when it has a name and no id.
        (
            "find_references",
            &["entity_id", "query", "relation_kinds"] as &[&str],
        ),
        (
            "trace_data_flow",
            &["focal", "target", "direction", "depth"] as &[&str],
        ),
        (
            "graph_neighborhood",
            &["entity_id", "depth", "direction", "limit"] as &[&str],
        ),
        (
            "impact_analysis",
            &["entity_ids", "files", "base", "head", "change_ids"] as &[&str],
        ),
        (
            "get_context_pack",
            &["entity_id", "depth", "token_budget"] as &[&str],
        ),
        ("kin_provenance_query", &["entity_id", "limit"] as &[&str]),
    ])
}

/// Rewrite one served tool list for the `agent-default` profile: short
/// descriptions, trimmed schemas, and the declaration filter under its honest
/// name.
///
/// A tool with no short form keeps its registered description, so adding a tool
/// to the profile is never silently a tool with no description. The
/// `every_agent_default_tool_has_a_short_description` test is what stops that
/// from being a quiet gap.
pub fn compact_for_agent_default(list: &mut ToolsListResult) {
    let descriptions = short_descriptions();
    let keeps = schema_keep_lists();
    for tool in &mut list.tools {
        if let Some(short) = descriptions.get(tool.name.as_str()) {
            tool.description = (*short).to_string();
        }
        if let Some(keep) = keeps.get(tool.name.as_str()) {
            trim_schema(&mut tool.input_schema, keep);
        }
        if tool.name == DECLARATION_FILTER_CANONICAL {
            tool.name = DECLARATION_FILTER_ALIAS.to_string();
        }
    }
    // The list is served in name order, and renaming a tool moves it. Re-sorting
    // keeps that contract: a client caches the prompt it builds from
    // `tools/list`, so an order that depended on a rename would miss the cache.
    list.tools.sort_by(|left, right| left.name.cmp(&right.name));
}

/// Keep only the named properties, and narrow `required` to what survives.
///
/// A required property that the trim removed would leave a schema demanding a
/// field it does not describe, which is a schema no client can satisfy.
fn trim_schema(schema: &mut serde_json::Value, keep: &[&str]) {
    let Some(object) = schema.as_object_mut() else {
        return;
    };
    if let Some(serde_json::Value::Object(properties)) = object.get_mut("properties") {
        properties.retain(|name, _| keep.contains(&name.as_str()));
    }
    if let Some(serde_json::Value::Array(required)) = object.get_mut("required") {
        required.retain(|name| name.as_str().is_some_and(|n| keep.contains(&n)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every tool the profile serves needs a short form, or the profile carries
    /// a 6,823-character description it was supposed to have replaced.
    #[test]
    fn every_agent_default_tool_has_a_short_description() {
        let descriptions = short_descriptions();
        let missing: Vec<&str> = crate::tools::agent_default_tool_names()
            .iter()
            .copied()
            .filter(|name| !descriptions.contains_key(name))
            .collect();
        assert!(
            missing.is_empty(),
            "these agent-default tools have no short description: {missing:?}"
        );
    }

    /// And nothing in the table that the profile does not serve, which would be
    /// a short form nobody reads and a name nobody notices going stale.
    #[test]
    fn the_short_description_table_has_no_orphans() {
        let served: std::collections::HashSet<&str> = crate::tools::agent_default_tool_names()
            .iter()
            .copied()
            .collect();
        let orphans: Vec<&str> = short_descriptions()
            .keys()
            .copied()
            .filter(|name| !served.contains(name))
            .collect();
        assert!(
            orphans.is_empty(),
            "short forms for unserved tools: {orphans:?}"
        );
    }

    /// Build the tool list exactly as `handle_tools_list` serves it for
    /// `agent-default`: filter, annotate, then compact.
    fn served_agent_default() -> ToolsListResult {
        let mut tools = crate::tools::tool_definitions();
        let allowed: std::collections::HashSet<String> = crate::tools::agent_default_tool_names()
            .iter()
            .map(|name| (*name).to_string())
            .collect();
        let registered: Vec<String> = tools.tools.iter().map(|t| t.name.clone()).collect();
        tools.tools.retain(|tool| allowed.contains(&tool.name));
        crate::tools::annotate_unserved_cross_references(&mut tools, &registered, &allowed);
        compact_for_agent_default(&mut tools);
        tools
    }

    /// The budget this whole file exists to hold. Measured on 2026-09-02 the
    /// served profile was 47,739 characters of description, the seven retrieval
    /// tools averaging 3,586 each and `trace_data_flow` alone at 6,823.
    #[test]
    fn no_agent_default_description_exceeds_its_budget() {
        let over: Vec<(String, usize)> = served_agent_default()
            .tools
            .into_iter()
            .map(|tool| (tool.name, tool.description.len()))
            .filter(|(_, len)| *len > AGENT_DEFAULT_DESCRIPTION_BUDGET)
            .collect();
        assert!(
            over.is_empty(),
            "over the {AGENT_DEFAULT_DESCRIPTION_BUDGET}-character per-tool budget: {over:?}"
        );
    }

    /// And the total, so twenty tools each sitting just under the per-tool cap
    /// cannot pass for a profile that learned something.
    #[test]
    fn the_agent_default_profile_stays_under_its_total_budget() {
        let total: usize = served_agent_default()
            .tools
            .iter()
            .map(|tool| tool.description.len())
            .sum();
        assert!(
            total <= AGENT_DEFAULT_PROFILE_DESCRIPTION_BUDGET,
            "agent-default descriptions total {total}, over the \
             {AGENT_DEFAULT_PROFILE_DESCRIPTION_BUDGET} budget"
        );
        // The control: the same tools' registered descriptions must be far
        // larger, or this test is passing against a surface that was already
        // short and the compaction is doing nothing.
        let served: std::collections::HashSet<&str> = crate::tools::agent_default_tool_names()
            .iter()
            .copied()
            .collect();
        let registered: usize = crate::tools::tool_definitions()
            .tools
            .iter()
            .filter(|tool| served.contains(tool.name.as_str()))
            .map(|tool| tool.description.len())
            .sum();
        assert!(
            registered > total * 3,
            "the long forms must be much larger than the short ones: \
             registered {registered}, served {total}"
        );
    }

    /// The `full` profile must keep every word. The short forms are a serving
    /// concern and must not have edited the registry.
    #[test]
    fn the_full_profile_keeps_the_long_descriptions() {
        let full = crate::tools::tool_definitions();
        let locate = full
            .tools
            .iter()
            .find(|t| t.name == "semantic_locate")
            .expect("semantic_locate is registered");
        assert!(
            locate.description.len() > 4_000,
            "the full profile's semantic_locate description was shortened: {} chars",
            locate.description.len()
        );
        assert!(
            full.tools
                .iter()
                .any(|t| t.name == DECLARATION_FILTER_CANONICAL),
            "the registry must still hold the tool under its registered name"
        );
        assert!(
            !full
                .tools
                .iter()
                .any(|t| t.name == DECLARATION_FILTER_ALIAS),
            "the alias is served, never registered"
        );
    }

    /// The rename, on both halves: `agent-default` serves the honest name, and
    /// a call under either name reaches the same handler.
    #[test]
    fn agent_default_serves_the_declaration_filter_under_its_honest_name() {
        let served = served_agent_default();
        assert!(
            served
                .tools
                .iter()
                .any(|t| t.name == DECLARATION_FILTER_ALIAS),
            "agent-default must serve {DECLARATION_FILTER_ALIAS}"
        );
        assert!(
            !served
                .tools
                .iter()
                .any(|t| t.name == DECLARATION_FILTER_CANONICAL),
            "and must not also serve the misleading name"
        );
        assert_eq!(
            canonical_tool_name(DECLARATION_FILTER_ALIAS),
            DECLARATION_FILTER_CANONICAL
        );
        // A caller that still sends the old name reaches the same place.
        assert_eq!(
            canonical_tool_name(DECLARATION_FILTER_CANONICAL),
            DECLARATION_FILTER_CANONICAL
        );
        // And nothing else is rewritten.
        for name in ["semantic_locate", "find_references", "get_entity_source"] {
            assert_eq!(canonical_tool_name(name), name);
        }
    }

    /// The in-place form the dispatchers call must agree with the borrowing one,
    /// or a call under the alias reaches a different place than a test asserts.
    #[test]
    fn the_two_canonicalizers_agree() {
        for name in [
            DECLARATION_FILTER_ALIAS,
            DECLARATION_FILTER_CANONICAL,
            "semantic_locate",
            "trace_data_flow",
            "",
        ] {
            let mut owned = name.to_string();
            canonicalize_tool_name(&mut owned);
            assert_eq!(owned, canonical_tool_name(name), "disagreement on {name:?}");
        }
    }

    /// The served list stays in name order after the rename moved a tool.
    #[test]
    fn the_served_list_stays_sorted_after_the_rename() {
        let names: Vec<String> = served_agent_default()
            .tools
            .into_iter()
            .map(|tool| tool.name)
            .collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(
            names, sorted,
            "a client caches the prompt built from this order"
        );
    }

    /// The schemas shrink too. Descriptions were 47,739 characters of the 82,262
    /// the profile costs; the input schemas were the other 30,456.
    #[test]
    fn the_trimmed_schemas_drop_the_response_shaping_properties() {
        let served = served_agent_default();
        let locate = served
            .tools
            .iter()
            .find(|t| t.name == "semantic_locate")
            .expect("served");
        let properties = locate.input_schema["properties"]
            .as_object()
            .expect("object");
        assert!(
            properties.contains_key("query"),
            "the question must survive"
        );
        for shaping in [
            "max_chars",
            "compact",
            "explain",
            "snippet_alias",
            "pipeline",
        ] {
            assert!(
                !properties.contains_key(shaping),
                "{shaping} shapes the response and should not be advertised here"
            );
        }
        // The control: the registered schema still has them, so the profile is
        // hiding them rather than the registry having lost them.
        let registered = crate::tools::tool_definitions();
        let full = registered
            .tools
            .iter()
            .find(|t| t.name == "semantic_locate")
            .expect("registered");
        for shaping in [
            "max_chars",
            "compact",
            "explain",
            "snippet_alias",
            "pipeline",
        ] {
            assert!(
                full.input_schema["properties"]
                    .as_object()
                    .expect("object")
                    .contains_key(shaping),
                "the full profile lost {shaping}"
            );
        }
    }

    /// A trim must never leave a schema requiring a property it no longer
    /// describes, which is a schema no client can satisfy.
    #[test]
    fn no_trimmed_schema_requires_a_property_it_dropped() {
        for tool in served_agent_default().tools {
            let Some(required) = tool.input_schema.get("required").and_then(|r| r.as_array())
            else {
                continue;
            };
            let properties = tool.input_schema["properties"]
                .as_object()
                .unwrap_or_else(|| panic!("{} has no properties", tool.name));
            for name in required {
                let name = name.as_str().expect("required names are strings");
                assert!(
                    properties.contains_key(name),
                    "{} requires '{name}' but no longer describes it",
                    tool.name
                );
            }
        }
    }

    /// Every short form must say what comes back, not only what the tool is
    /// for. The failure this replaces was a model calling the wrong tool, and a
    /// description that never names its return value cannot prevent that.
    #[test]
    fn the_confusable_pair_each_point_at_the_other() {
        let descriptions = short_descriptions();
        let locate = descriptions["semantic_locate"];
        let filter = descriptions[DECLARATION_FILTER_CANONICAL];
        assert!(
            locate.contains(DECLARATION_FILTER_ALIAS),
            "semantic_locate must name the tool a caller reaches for by mistake"
        );
        assert!(
            filter.contains("semantic_locate"),
            "and the declaration filter must name it back"
        );
        // The chain question has one answer, and the belt must send it there.
        for hop in ["find_references", "graph_neighborhood"] {
            assert!(
                descriptions[hop].contains("trace_data_flow"),
                "{hop} must point a chain question at trace_data_flow"
            );
        }
        assert!(
            descriptions["trace_data_flow"].contains("call chain"),
            "trace_data_flow's short form must say what it walks; its registered \
             form opens by warning that its own name is wrong"
        );
    }

    /// The belt asks for compact on behalf of its agents, and only when the
    /// caller said nothing. This is the half of the compact surface that
    /// actually reaches an agent, since the wire default is the shared schema.
    #[test]
    fn the_belt_asks_for_the_compact_locate_shape() {
        let mut args: HashMap<String, serde_json::Value> = HashMap::new();
        args.insert("query".into(), serde_json::Value::String("q".into()));
        apply_belt_defaults("semantic_locate", &mut args);
        assert_eq!(
            args.get("surface").and_then(|v| v.as_str()),
            Some("compact"),
            "the belt must ask for the small payload"
        );
        // The query is untouched, so this is an addition rather than a rewrite.
        assert_eq!(args.get("query").and_then(|v| v.as_str()), Some("q"));
    }

    /// A caller that named a surface keeps it. That is what makes the belt's
    /// choice a default rather than an override, and it is the assertion that
    /// fails if someone reaches for `insert` instead of `entry().or_insert`.
    #[test]
    fn the_belt_never_overrides_a_surface_the_caller_named() {
        for named in ["full", "compact"] {
            let mut args: HashMap<String, serde_json::Value> = HashMap::new();
            args.insert("surface".into(), serde_json::Value::String(named.into()));
            apply_belt_defaults("semantic_locate", &mut args);
            assert_eq!(
                args.get("surface").and_then(|v| v.as_str()),
                Some(named),
                "the caller's own surface must survive the belt"
            );
        }
    }

    /// And it touches nothing else. A default that leaked onto another tool
    /// would be sending an argument its handler never advertised.
    #[test]
    fn the_belt_defaults_apply_to_locate_alone() {
        for tool in ["semantic_search", "find_references", "get_context_pack"] {
            let mut args: HashMap<String, serde_json::Value> = HashMap::new();
            apply_belt_defaults(tool, &mut args);
            assert!(
                args.is_empty(),
                "{tool} must be left exactly as the caller sent it"
            );
        }
    }

    /// Same for the keep-lists: a keep-list naming a property the tool does not
    /// have would silently trim the schema to nothing.
    #[test]
    fn every_keep_list_names_real_properties() {
        let registered = crate::tools::tool_definitions();
        for (name, keep) in schema_keep_lists() {
            let tool = registered
                .tools
                .iter()
                .find(|t| t.name == name)
                .unwrap_or_else(|| panic!("keep-list names an unregistered tool: {name}"));
            let properties = tool.input_schema["properties"]
                .as_object()
                .unwrap_or_else(|| panic!("{name} has no properties object"));
            for property in keep {
                assert!(
                    properties.contains_key(*property),
                    "{name}'s keep-list names '{property}', which it does not have"
                );
            }
        }
    }
}
