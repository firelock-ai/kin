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
//! Measured the same way afterwards, with the acceptance exception below in
//! place, the served profile is 33,464 bytes over 21 tools: 6,188 characters of
//! description and 27,276 bytes of input schema. The descriptions are where the
//! win is, 6,188 against 47,739. The schemas keep most of their bytes on
//! purpose, because a property the shipped proofs or the acceptance suite grade
//! has to stay advertised; [`schema_keep_lists`] names that exception and the
//! checks that own it.
//!
//! Every short form answers two questions in one or two sentences: when to call
//! this, and what comes back. Where two tools are easy to confuse, the one a
//! caller reaches for by mistake names the other.
//!
//! Trimming a schema hides a property; it does not remove it. No tool in this
//! profile sets `additionalProperties: false`, and the handlers read arguments
//! by name, so a caller that knows a withheld property can still pass it and the
//! `full` profile still advertises every one.
//!
//! # Adding a tool to `agent-default`
//!
//! If you added a name to [`crate::tools::agent_default_tool_names`] and
//! `kin-mcp` went red on `every_agent_default_tool_has_a_short_description`,
//! that is this module asking for two entries, not a defect:
//!
//! 1. [`short_descriptions`]: one or two sentences saying when to call the tool
//!    and what comes back, under [`AGENT_DEFAULT_DESCRIPTION_BUDGET`]
//!    characters. Where another tool is easy to confuse with yours, name it, and
//!    add the pointer back in its entry.
//! 2. [`schema_keep_lists`]: the input properties that change WHICH entities
//!    come back. Leave out the ones that only reshape the response, since the
//!    profile picks those itself.
//!
//! The guard is deliberate. Without it a tool joins the belt carrying its full
//! registered description, which is the several-thousand-character form this
//! module exists to replace, and nothing says so.

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

/// The honest name for the declaration filter, accepted on a call and never
/// served.
///
/// `semantic_search` does not search semantically. Its own registered
/// description opens "Find code declarations in the semantic graph by name,
/// kind, or language" and its arguments are `query`, `kind` and `language`: it
/// is a filter over declarations, and it ignores the query for ranking.
/// `semantic_locate` is the tool that ranks by meaning. A model reads a name
/// before it reads five thousand characters of prose, and these two names are
/// the wrong way round.
///
/// That reading still holds, and it was not enough to move the served name.
/// `agent-default` advertised the filter under this name for four landings, and
/// two proofs that run only on `main` went red on every one of them: the
/// install proof throws `MCP tools/list omitted semantic_search`
/// (`.github/workflows/install-proof.yml`) and the Windows npm proof asserts
/// `toolNames.includes('semantic_search')`
/// (`scripts/prove-windows-npm-first-run.mjs`). Renaming a public MCP tool on
/// the default profile is a product decision that has to move those proofs, the
/// docs and the acceptance suite in one deliberate change, rather than ride
/// along inside a payload compaction.
///
/// So the name lives on as an accepted input only. [`canonical_tool_name`] maps
/// it back at each dispatch entry, so a caller that learned it during those four
/// landings still reaches the same handler, while `tools/list` advertises the
/// registered name on every profile.
/// `agent_default_serves_every_name_the_shipped_proofs_assert` is what holds
/// that per pull request.
pub const DECLARATION_FILTER_ALIAS: &str = "find_declarations";

/// The registered name [`DECLARATION_FILTER_ALIAS`] stands in for.
pub const DECLARATION_FILTER_CANONICAL: &str = "semantic_search";

/// Map an accepted tool name back to the name everything internal is keyed on.
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

/// Ask, on this belt's agents' behalf, for the answer shape and the size a
/// small model can afford.
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
/// `full` gets full, which is what makes this a default rather than an override,
/// and every insertion below follows the same rule.
///
/// The rest is the response size. The registered ceiling of 45,000 characters is
/// right for a client with room and wrong for this belt: it is roughly 10,500
/// tokens, so two default answers exhaust a 24,000-token run. Each budget tool
/// therefore gets [`AGENT_DEFAULT_RESPONSE_MAX_CHARS`], the walker gets the
/// shape rather than the bodies, and the context pack gets a token budget that
/// fits inside the same answer. Every one of these is advertised on the served
/// schema by [`apply_belt_schema_defaults`], so a caller reading `tools/list`
/// sees the number the belt actually sends and can raise it with the same
/// `max_chars` it always could.
pub fn apply_belt_defaults(name: &str, arguments: &mut HashMap<String, serde_json::Value>) {
    if name == "semantic_locate" {
        arguments
            .entry("surface".to_string())
            .or_insert_with(|| serde_json::Value::String("compact".to_string()));
    }

    // Shape before bodies on the walker. Not inserted when the caller named
    // either spelling, because `compact` is the alias for `include_body: false`
    // and overriding a caller who asked for one of them would be the belt
    // answering a question it was not asked.
    if name == "trace_data_flow"
        && !arguments.contains_key("include_body")
        && !arguments.contains_key("compact")
    {
        arguments.insert("include_body".to_string(), serde_json::Value::Bool(false));
    }

    if name == "get_context_pack" {
        arguments
            .entry("token_budget".to_string())
            .or_insert_with(|| serde_json::json!(AGENT_DEFAULT_CONTEXT_PACK_TOKEN_BUDGET));
    }

    // A page the client's own per-result budget does not cut. Only when the
    // caller named no limit of its own, so an agent that asks for more pages
    // gets them.
    if name == "semantic_locate" {
        arguments
            .entry("limit".to_string())
            .or_insert_with(|| serde_json::json!(AGENT_DEFAULT_LOCATE_PAGE));
    }

    // The response ceiling, on every belt tool that has one. Both spellings are
    // checked before inserting, because `ResponseBudget::from_arguments` takes
    // the FIRST of `max_chars` then `max_response_chars` that is present: an
    // unconditional insert would silently outrank a caller who had passed
    // `max_response_chars` and hand them a ceiling they never asked for.
    if BUDGET_TOOLS.contains(&name)
        && !arguments.contains_key("max_chars")
        && !arguments.contains_key("max_response_chars")
    {
        arguments.insert(
            "max_chars".to_string(),
            serde_json::json!(AGENT_DEFAULT_RESPONSE_MAX_CHARS),
        );
    }
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
             name, call semantic_search instead.",
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
             than you expect, since an unembedded graph cannot rank by meaning. On a store under \
             continuous reconcile it can answer `sampling=last_settled_selected_graph` instead of a \
             live one: the same counters as of the last settled reading, with a `stale` block \
             giving that reading's age. Read `sampling` to tell the two apart.",
        ),
        // ── Walking: the chain question, and where it is answered ──
        (
            "trace_data_flow",
            "Walk the call chain out from one entity and get the whole path back in one call, as \
             an ordered list of steps. Call it when you name ONE thing and ask what it reaches or \
             what reaches it: give it a focal entity_id, a direction and a depth. It walks call \
             and import edges, so it does not follow a value through a variable. When your question \
             names TWO things and asks how one reaches the other, call trace_path instead.",
        ),
        (
            crate::handlers::path::TOOL_NAME,
            "Find how one entity reaches another and get the routes back as ordered hops. Call it \
             when your question names TWO things: how does A reach B. Takes `from` and `to`, each an \
             exact name, an entity id, or name@file to pin a twin. Every hop carries id, name, kind, \
             file, line and the relation into the next. Read `found` and `gap` before concluding A \
             never reaches B; a class stands for its members. For one endpoint, call \
             trace_data_flow.",
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
/// Two rules decided every list, and one exception overrides the second.
///
/// A property that changes WHICH entities come back stays. A property that only
/// reshapes the response (`explain`, `snippet_alias`, `pipeline`) goes, because
/// the profile picks those defaults itself and every one of them is another
/// line the model reads before it can ask its question.
///
/// The exception: a response-shaping property the shipped proofs or the
/// acceptance suite assert stays anyway, because those checks read the served
/// schema as the contract an agent discovers the knob from. Trimming
/// `include_body` and `compact` off `trace_data_flow` and `max_chars` off every
/// tool that registered one took three acceptance findings red for four
/// landings, and an agent that cannot see the knob cannot ask for bodies or
/// bound a response. Three checks own that contract:
/// `scripts/acceptance/magic_repro.py` `check_6`, which requires `include_body`
/// or `compact` on `trace_data_flow`; `check_14` arm 3, which requires the
/// literal `last_settled_selected_graph` in the served `kin_graph_status`
/// description; and `scripts/acceptance/response_budget_elisions.py` `check_2`,
/// which grades every advertised `max_chars` or `max_response_chars` and
/// reports UNREADABLE when it finds none. Do not trim these again without
/// moving those checks in the same change.
fn schema_keep_lists() -> BTreeMap<&'static str, &'static [&'static str]> {
    BTreeMap::from([
        // Thirteen properties down to five. `cursor` and `page_size` stay
        // because paging is how a caller reaches past the first page;
        // `include_tests` stays because it changes which entities can rank at
        // all, and a caller asking about a test cannot otherwise find one.
        (
            "semantic_locate",
            &[
                "query",
                "limit",
                "granularity",
                "cursor",
                "include_tests",
                "max_chars",
            ] as &[&str],
        ),
        (
            DECLARATION_FILTER_CANONICAL,
            &["query", "kind", "language", "limit", "max_chars"] as &[&str],
        ),
        // `query` stays beside `entity_id`: this tool resolves an exact symbol
        // name to its canonical definition, and dropping it would take away the
        // path a caller uses when it has a name and no id.
        (
            "find_references",
            &["entity_id", "query", "relation_kinds", "max_chars"] as &[&str],
        ),
        (
            "trace_data_flow",
            &[
                "focal",
                "target",
                "direction",
                "depth",
                "include_body",
                "compact",
                "max_response_chars",
                "max_chars",
            ] as &[&str],
        ),
        (
            crate::handlers::path::TOOL_NAME,
            &[
                "from",
                "to",
                "from_file",
                "to_file",
                "direction",
                "max_depth",
                "limit",
                "max_chars",
            ] as &[&str],
        ),
        (
            "graph_neighborhood",
            &["entity_id", "depth", "direction", "limit", "max_chars"] as &[&str],
        ),
        (
            "impact_analysis",
            &[
                "entity_ids",
                "files",
                "base",
                "head",
                "change_ids",
                "max_chars",
            ] as &[&str],
        ),
        (
            "get_context_pack",
            &["entity_id", "depth", "token_budget", "max_chars"] as &[&str],
        ),
        ("kin_provenance_query", &["entity_id", "limit"] as &[&str]),
    ])
}

/// The response ceiling `agent-default` asks for on its agents' behalf.
///
/// Derived from one rule rather than taste: an agent must be able to make at
/// least six tool calls at default answer size inside a 24,000-token run and
/// still have room to answer. That puts one answer at about 2,800 tokens, and at
/// the 4.28 bytes per token measured on this profile's own JSON against
/// `google/gemma-4-e4b` that is about 12,000 characters.
///
/// The registered default is 45,000, which is [`crate::budget::
/// RESPONSE_DEFAULT_MAX_CHARS`] and right for a client with room. On this belt
/// it is catastrophic for the case the belt exists for: 45,000 characters is
/// roughly 10,500 tokens, so TWO default answers exhaust a 24,000-token run
/// before the model has reasoned about either. That is read from source rather
/// than guessed, because `apply_belt_defaults` shaped only `semantic_locate`'s
/// `surface` and every other tool fell through to the registered default.
///
/// Advertised AND injected, deliberately the same number. The acceptance suite
/// treats the served schema as the contract an agent reads, so a belt that
/// injected 12,000 while advertising 45,000 would be lying in the one place a
/// caller looks. Both halves move together, and `full` keeps 45,000.
pub const AGENT_DEFAULT_RESPONSE_MAX_CHARS: u64 = 12_000;

/// The ranked entities `semantic_locate` returns per page on `agent-default`.
///
/// The response cap above bounds what the SERVER builds. This bounds what a
/// CLIENT is handed, which is a different cut and the one that was binding.
/// Measured on the demo's React and VS Code stores on 2026-09-02
/// (`scratchpad/reports/demo-rerun.md`), every `semantic_locate` in all three
/// agentic runs came back cut at the client's own 1,500-token per-result
/// budget, which is 5,250 characters at that harness's 3.5 characters per
/// token. Compaction had made the payload three to five times smaller and it
/// still did not fit, so the cut landed every time and the model re-issued the
/// same query three times per run rather than reading a whole answer.
///
/// A client cut is not a cut Kin can disclose: the server returned inside its
/// own ceiling and the harness truncated afterwards, so none of the remediation
/// text in [`crate::budget`] ever reached the model. The only lever Kin holds is
/// to return a page that fits.
///
/// 12 is counted, not inferred. Read-only against the demo's own daemons on
/// 2026-09-02, with the demo's own binary and environment so no second daemon
/// was started, running the logged command and varying only the page:
///
/// | query | 24 | 13 | 12 | 11 |
/// |---|---|---|---|---|
/// | type character in editor | 6,471 | 4,624 | 4,343 | 4,065 |
/// | handle keyboard input character insertion | 8,732 | 5,281 | 5,029 | 4,779 |
/// | editor handles key press event for character input | 7,425 | 4,305 | 4,038 | 3,769 |
/// | component asking for an update (react) | 7,669 | 4,743 | 4,464 | 4,128 |
///
/// The page-24 column reproduces `demo-rerun.md` byte for byte, which is the
/// control that says this is the same surface it measured. At 13 the densest
/// query is 5,281 bytes and misses the window by 31; at 12 every query fits,
/// the worst with 221 characters to spare. So 12 is the largest page that fits
/// them all.
///
/// An earlier inference from the report's density line put this at 13. It was
/// off by one, which is what counting is for.
///
/// A page is not a cap on what the caller can reach. The answer carries
/// `total_ranked` and `next_cursor`, so an agent that wants more asks for the
/// next page instead of re-asking the same question, which is the behaviour this
/// number exists to buy.
pub const AGENT_DEFAULT_LOCATE_PAGE: u64 = 12;

/// The context pack's own token budget on `agent-default`.
///
/// `get_context_pack` bounds itself in TOKENS as well as characters, and its
/// registered default of 16,000 is larger than the whole answer this belt now
/// asks for. 2,500 sits under the roughly 2,800 tokens
/// [`AGENT_DEFAULT_RESPONSE_MAX_CHARS`] buys, leaving the envelope its room.
pub const AGENT_DEFAULT_CONTEXT_PACK_TOKEN_BUDGET: u64 = 2_500;

/// The belt tools whose registered schema advertises a response budget.
///
/// Held as a list because [`apply_belt_defaults`] runs on every call and
/// building the registry there to rediscover eight names would cost more than
/// it saves. `the_budget_tool_list_matches_the_registry` fails if the registry
/// and this list ever disagree, so it cannot go stale quietly.
const BUDGET_TOOLS: [&str; 8] = [
    "semantic_locate",
    DECLARATION_FILTER_CANONICAL,
    "find_references",
    "trace_data_flow",
    crate::handlers::path::TOOL_NAME,
    "graph_neighborhood",
    "impact_analysis",
    "get_context_pack",
];

/// The properties whose advertised `default` this belt rewrites, by tool.
///
/// A number the profile injects has to be the number the profile advertises, or
/// the served schema stops being the contract the acceptance suite grades it as.
fn belt_schema_defaults() -> BTreeMap<(&'static str, &'static str), serde_json::Value> {
    let mut defaults: BTreeMap<(&'static str, &'static str), serde_json::Value> = BTreeMap::new();
    for tool in BUDGET_TOOLS {
        defaults.insert(
            (tool, "max_chars"),
            serde_json::json!(AGENT_DEFAULT_RESPONSE_MAX_CHARS),
        );
    }
    // `trace_data_flow` registers the same budget under both spellings, and a
    // caller reading either one has to see the same ceiling.
    defaults.insert(
        ("trace_data_flow", "max_response_chars"),
        serde_json::json!(AGENT_DEFAULT_RESPONSE_MAX_CHARS),
    );
    // Shape first. The tool's own belt description tells a model to pass false
    // when it wants the shape of a chain, and then the registered default handed
    // it bodies anyway.
    defaults.insert(
        ("trace_data_flow", "include_body"),
        serde_json::Value::Bool(false),
    );
    defaults.insert(
        ("get_context_pack", "token_budget"),
        serde_json::json!(AGENT_DEFAULT_CONTEXT_PACK_TOKEN_BUDGET),
    );
    defaults.insert(
        ("semantic_locate", "limit"),
        serde_json::json!(AGENT_DEFAULT_LOCATE_PAGE),
    );
    defaults
}

/// Rewrite one tool's advertised property defaults for `agent-default`.
///
/// Only a property the schema already carries is touched, so this can never
/// invent a knob, and only its `default` moves: `minimum` and `maximum` are the
/// server's real limits and stay as registered, which is also what keeps
/// `response_budget_elisions.py` `check_2` satisfied, since it requires
/// `minimum < default <= maximum`.
fn apply_belt_schema_defaults(tool: &str, schema: &mut serde_json::Value) {
    let defaults = belt_schema_defaults();
    let Some(properties) = schema
        .get_mut("properties")
        .and_then(|value| value.as_object_mut())
    else {
        return;
    };
    for (name, property) in properties.iter_mut() {
        let (Some(value), Some(property)) = (
            defaults.get(&(tool, name.as_str())),
            property.as_object_mut(),
        ) else {
            continue;
        };
        property.insert("default".to_string(), value.clone());
    }
}

/// The most characters one `agent-default` PROPERTY description may carry.
///
/// The tool descriptions were the visible half of the belt's cost and 1353 cut
/// them from 47,739 characters to 6,188. Measured on 2026-09-02 against
/// `google/gemma-4-e4b`, the model the demo actually runs, that left the served
/// list at 7,747 tokens of which 6,380 are input schema and only 1,367 are
/// description. The schemas are where the budget goes now, and inside them the
/// bytes are property prose: thirteen property descriptions ran past 200
/// characters, and one of them, `max_chars`, carried the same 649 characters on
/// seven different tools.
///
/// 200 is one plain clause. A property description exists to tell a model what
/// to pass, and the shape, bounds and default are already machine-readable
/// beside it in `type`, `enum`, `minimum`, `maximum` and `default`, so prose
/// that restates them is paid for twice.
/// `no_agent_default_property_description_exceeds_its_budget` fails on any
/// property over it.
pub const AGENT_DEFAULT_PROPERTY_DESCRIPTION_BUDGET: usize = 200;

/// The tools whose schemas this module does not rewrite at all.
///
/// 1353 left the nested transaction contracts whole, and they stay whole: a
/// staged mutation's shape is the thing a caller gets wrong, and it is the one
/// place on this belt where the schema IS the documentation. They cost 11,245
/// bytes and 2,423 tokens between them, which is 31 percent of every token in
/// the served list, and that number belongs in a product decision about which
/// tools a read-only agent is served rather than in a prose trim.
const PROSE_EXEMPT_TOOLS: [&str; 2] = ["kin_transaction_stage", "kin_transaction_commit"];

/// Short property descriptions that read the same on every tool carrying them.
///
/// Keyed by property name alone, because these properties mean one thing across
/// the belt and the long forms said that one thing seven times.
/// [`tool_property_descriptions`] overrides this per tool where the meaning
/// genuinely differs.
fn shared_property_descriptions() -> BTreeMap<&'static str, &'static str> {
    BTreeMap::from([
        (
            "max_chars",
            "Serialized characters this response may occupy. What the budget cut is named under \
             `elisions` and `_kin.response`, and a list it cut keeps one entry, so an empty list \
             means none were found.",
        ),
        (
            "max_response_chars",
            "Serialized characters this response may occupy. `max_chars` is the same parameter \
             under the other retrieval tools' name. A cut chain keeps one step and reports the \
             rest under `elisions.chain`.",
        ),
        (
            "cursor",
            "Opaque token from a prior result's `next_cursor`, returning the next page of the \
             same collection. Pass it back unedited, and omit it for a fresh query.",
        ),
    ])
}

/// Short property descriptions for one tool's property, overriding
/// [`shared_property_descriptions`] where a name means different things.
///
/// Keyed by `(tool, property)`. `direction` is the reason this table exists: it
/// walks callees on `trace_data_flow` and dependencies on `graph_neighborhood`,
/// and one clause cannot honestly say both.
fn tool_property_descriptions() -> BTreeMap<(&'static str, &'static str), &'static str> {
    BTreeMap::from([
        (
            ("semantic_locate", "include_tests"),
            "Rank test-role entities alongside source. Off by default unless your query itself \
             reads as being about tests; what it withheld is counted under \
             `semantic_coverage.graph_bodies`.",
        ),
        (
            ("list_file_entities", "path"),
            "Repository-relative path of the file to enumerate, such as \"lib/express.js\". No \
             leading slash, no \"..\", no Kin or Git control component. Optional only when \
             `cursor` names the file.",
        ),
        (
            ("trace_data_flow", "target"),
            "A symbol you are trying to reach, by exact name or UUID. Neighbours it stays \
             reachable from survive the per-step cap first. Optional; one resolving to nothing \
             is reported in degradations.",
        ),
        (
            ("trace_data_flow", "include_body"),
            "Inline each step's source body. Pass false for the SHAPE of the chain, which is a \
             fraction of the size and is what you want unless you mean to read the code.",
        ),
        (
            ("trace_data_flow", "direction"),
            "Which way to walk: `calls` for callees, `callers` for callers, `both` merges.",
        ),
        (
            ("graph_neighborhood", "direction"),
            "Which way to walk: `out` for what the focal depends on, `in` for what depends on it \
             (blast radius), `both` merges.",
        ),
    ])
}

/// Replace one tool's top-level property descriptions with their short forms.
///
/// Top-level only. A nested schema below a property belongs to whatever
/// contract that property describes, and on this belt the only deep ones are
/// the transaction mutations that [`PROSE_EXEMPT_TOOLS`] keeps whole anyway.
fn shorten_property_descriptions(tool: &str, schema: &mut serde_json::Value) {
    if PROSE_EXEMPT_TOOLS.contains(&tool) {
        return;
    }
    let shared = shared_property_descriptions();
    let per_tool = tool_property_descriptions();
    let Some(properties) = schema
        .get_mut("properties")
        .and_then(|value| value.as_object_mut())
    else {
        return;
    };
    for (name, property) in properties.iter_mut() {
        let short = per_tool
            .get(&(tool, name.as_str()))
            .or_else(|| shared.get(name.as_str()));
        let (Some(short), Some(property)) = (short, property.as_object_mut()) else {
            continue;
        };
        if property.contains_key("description") {
            property.insert(
                "description".to_string(),
                serde_json::Value::String((*short).to_string()),
            );
        }
    }
}

/// Rewrite one served tool list for the `agent-default` profile: short tool
/// descriptions, trimmed schemas, and short property descriptions inside the
/// schemas that survive. Tool names are left exactly as registered, because two
/// proofs that run only on `main` read `tools/list` and assert a name
/// literally.
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
        shorten_property_descriptions(&tool.name, &mut tool.input_schema);
        apply_belt_schema_defaults(&tool.name, &mut tool.input_schema);
    }
    // No name is rewritten here, so the name order `tools::tool_definitions`
    // built survives untouched. A client caches the prompt it builds from
    // `tools/list`, and an order this function moved would miss that cache.
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
            "these agent-default tools have no short description: {missing:?}; add an entry for \
             each in short_descriptions() and schema_keep_lists() in \
             crates/kin-mcp/src/agent_belt.rs, at most {AGENT_DEFAULT_DESCRIPTION_BUDGET} \
             characters per description. Without one the tool joins the belt carrying its full \
             registered description, which is the several-thousand-character form this module \
             exists to replace."
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
            "short_descriptions() in crates/kin-mcp/src/agent_belt.rs has entries for tools the \
             profile no longer serves: {orphans:?}; remove them, or put the names back in \
             agent_default_tool_names() if the removal was accidental"
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
            "the alias is accepted on a call, never registered and never served"
        );
    }

    /// Both halves: `agent-default` serves the registered name, and a call
    /// under either name reaches the same handler.
    ///
    /// The alias was served for four landings and took two main-only proofs red
    /// on each of them. Serving the registered name is what those proofs assert;
    /// accepting the alias on a call is what keeps a caller that learned it in
    /// the meantime working.
    #[test]
    fn agent_default_serves_the_declaration_filter_under_its_registered_name() {
        let served = served_agent_default();
        assert!(
            served
                .tools
                .iter()
                .any(|t| t.name == DECLARATION_FILTER_CANONICAL),
            "agent-default must serve {DECLARATION_FILTER_CANONICAL}"
        );
        assert!(
            !served
                .tools
                .iter()
                .any(|t| t.name == DECLARATION_FILTER_ALIAS),
            "and must not serve the alias, which the shipped proofs do not know"
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

    /// Every tool name the shipped proofs assert by name must be served under
    /// exactly that name on `agent-default`, and no tool may be served under a
    /// name the registry does not carry.
    ///
    /// Two proofs read `tools/list` and assert a tool name literally.
    /// `.github/workflows/install-proof.yml`, in its "Graph query and MCP
    /// tool-call proof" step, throws `MCP tools/list omitted semantic_search`
    /// and then calls that tool twice through `tools/call`.
    /// `scripts/prove-windows-npm-first-run.mjs` asserts
    /// `toolNames.includes('semantic_search')` for both npm entrypoints. Both
    /// jobs are `skipped` on a pull request and graded only on `main`'s push
    /// run, so before this test nothing per-PR could see a served name move:
    /// the change that introduced this module served `semantic_search` as
    /// `find_declarations`, and both proofs stayed red for four landings.
    ///
    /// The second assertion is the general form of that class. A served name
    /// the registry does not carry is a rename by another route, whatever tool
    /// it lands on, and it fails here rather than on `main` a landing later. If
    /// you added a name to one of those two files, add it to
    /// `PROOF_ASSERTED_NAMES` as well. If this test is in your way because you
    /// meant to move a served name, that move takes those two files,
    /// `docs/mcp-tools.md` and the acceptance suite with it, in one change.
    #[test]
    fn agent_default_serves_every_name_the_shipped_proofs_assert() {
        // Read out of the two files named above on 2026-09-02. Both assert
        // `semantic_search` and no other tool name.
        const PROOF_ASSERTED_NAMES: &[&str] = &["semantic_search"];

        let served: Vec<String> = served_agent_default()
            .tools
            .into_iter()
            .map(|tool| tool.name)
            .collect();
        for name in PROOF_ASSERTED_NAMES {
            assert!(
                served.iter().any(|candidate| candidate == name),
                "the shipped proofs call {name} by name and agent-default serves {served:?}"
            );
        }

        let registered: Vec<String> = crate::tools::tool_definitions()
            .tools
            .into_iter()
            .map(|tool| tool.name)
            .collect();
        let unregistered: Vec<&String> = served
            .iter()
            .filter(|name| !registered.contains(*name))
            .collect();
        assert!(
            unregistered.is_empty(),
            "agent-default serves {unregistered:?} under a name the registry does not carry, \
             which is a public rename no per-PR check but this one can see"
        );
    }

    /// No served property description may run past its budget.
    ///
    /// Property prose was 10,153 bytes of the served schemas outside the two
    /// exempt transaction tools, and one clause, `max_chars`, carried the same
    /// 649 characters on seven tools. The shape, bounds and default of a
    /// property are already machine-readable beside its description, so prose
    /// that restates them is paid for on every `tools/list` a small model reads.
    ///
    /// Top-level properties only, and the two tools in [`PROSE_EXEMPT_TOOLS`]
    /// are skipped, because the earlier compaction kept their nested mutation
    /// contracts whole and this test is not the place to reopen that.
    ///
    /// Nothing in the acceptance suite reads a property description, checked
    /// rather than assumed: `magic_repro.py` `check_6` tests for the presence of
    /// the `include_body` or `compact` KEY, `check_14` arm 3 reads the TOOL
    /// description, and `response_budget_elisions.py` `grade_advertised_budget`
    /// reads only `maximum`, `default` and `minimum`. So this budget binds
    /// without moving a check.
    #[test]
    fn no_agent_default_property_description_exceeds_its_budget() {
        let over: Vec<(String, String, usize)> = served_agent_default()
            .tools
            .into_iter()
            .filter(|tool| !PROSE_EXEMPT_TOOLS.contains(&tool.name.as_str()))
            .flat_map(|tool| {
                let properties = tool
                    .input_schema
                    .get("properties")
                    .and_then(|value| value.as_object())
                    .cloned()
                    .unwrap_or_default();
                properties
                    .into_iter()
                    .filter_map(|(name, property)| {
                        let length = property.get("description")?.as_str()?.chars().count();
                        (length > AGENT_DEFAULT_PROPERTY_DESCRIPTION_BUDGET).then_some((
                            tool.name.clone(),
                            name,
                            length,
                        ))
                    })
                    .collect::<Vec<_>>()
            })
            .collect();
        assert!(
            over.is_empty(),
            "over the {AGENT_DEFAULT_PROPERTY_DESCRIPTION_BUDGET}-character property budget: \
             {over:?}; give each one a single clause in shared_property_descriptions or \
             tool_property_descriptions"
        );
    }

    /// The control for the budget above: the registered schemas must still carry
    /// the long forms, or the profile is passing because the registry lost them.
    #[test]
    fn the_full_profile_keeps_the_long_property_descriptions() {
        let full = crate::tools::tool_definitions();
        let locate = full
            .tools
            .iter()
            .find(|tool| tool.name == "semantic_locate")
            .expect("semantic_locate is registered");
        let budget = locate.input_schema["properties"]["max_chars"]["description"]
            .as_str()
            .expect("max_chars carries a description");
        assert!(
            budget.chars().count() > AGENT_DEFAULT_PROPERTY_DESCRIPTION_BUDGET,
            "the full profile's max_chars prose was shortened too: {} chars",
            budget.chars().count()
        );
    }

    /// Every advertised response budget on `agent-default` stays at or under the
    /// cap, and the number advertised is the number injected.
    ///
    /// The registered ceiling is 45,000 characters, about 10,500 gemma-4-e4b
    /// tokens, so two default answers exhaust the 24,000-token run this belt
    /// exists to fit. The cap is derived from one rule: six calls at default
    /// size inside that run with room left to answer.
    ///
    /// Both halves are asserted together on purpose. A belt that injected the
    /// cap while advertising 45,000 would pass any check that reads only one
    /// side, and the served schema is what an agent reads before it decides
    /// whether to narrow its own request. `minimum` and `maximum` are left as
    /// registered, which is also what keeps
    /// `response_budget_elisions.py` `check_2` satisfied, since it requires
    /// `minimum < default <= maximum`.
    #[test]
    fn no_agent_default_response_budget_is_advertised_above_the_cap() {
        let served = served_agent_default();
        let mut problems: Vec<String> = Vec::new();
        for tool in &served.tools {
            let properties = tool
                .input_schema
                .get("properties")
                .and_then(|value| value.as_object());
            let Some(properties) = properties else {
                continue;
            };
            for key in ["max_chars", "max_response_chars"] {
                let Some(property) = properties.get(key) else {
                    continue;
                };
                let advertised = property.get("default").and_then(|value| value.as_u64());
                match advertised {
                    None => problems.push(format!("{}.{key} advertises no default", tool.name)),
                    Some(value) if value > AGENT_DEFAULT_RESPONSE_MAX_CHARS => {
                        problems.push(format!(
                            "{}.{key} advertises {value}, over the \
                             {AGENT_DEFAULT_RESPONSE_MAX_CHARS}-character cap",
                            tool.name
                        ))
                    }
                    Some(_) => {}
                }
                // The number advertised has to be the number the belt sends.
                let mut arguments = HashMap::new();
                apply_belt_defaults(&tool.name, &mut arguments);
                let injected = arguments.get("max_chars").and_then(|value| value.as_u64());
                if injected != Some(AGENT_DEFAULT_RESPONSE_MAX_CHARS) {
                    problems.push(format!(
                        "{} advertises a budget and the belt injects {injected:?}",
                        tool.name
                    ));
                }
            }
        }
        assert!(
            problems.is_empty(),
            "agent-default response budgets disagree with the cap: {problems:#?}"
        );
    }

    /// `semantic_locate`'s served page stays at or under the cap, and the number
    /// advertised is the number injected.
    ///
    /// This is the client-side cut rather than the server-side one. Every
    /// `semantic_locate` in all three agentic runs on the React and VS Code
    /// stores came back cut at the harness's own 1,500-token per-result budget,
    /// and the model answered by re-issuing the same query rather than paging.
    /// A client cut is invisible to Kin, so the page has to fit before it is
    /// sent.
    ///
    /// Advertised and injected are asserted together, for the same reason the
    /// response budget is: a belt that shrank the page it sends while
    /// advertising 20 would leave an agent reasoning about a page size it is not
    /// getting.
    #[test]
    fn the_served_locate_page_stays_under_the_cap() {
        let served = served_agent_default();
        let locate = served
            .tools
            .iter()
            .find(|tool| tool.name == "semantic_locate")
            .expect("agent-default serves semantic_locate");
        let advertised = locate.input_schema["properties"]["limit"]["default"].as_u64();
        assert_eq!(
            advertised,
            Some(AGENT_DEFAULT_LOCATE_PAGE),
            "the served page must be the cap; a client's own per-result budget cuts anything \
             larger and Kin cannot disclose a cut it did not make"
        );

        let mut arguments = HashMap::new();
        apply_belt_defaults("semantic_locate", &mut arguments);
        assert_eq!(
            arguments.get("limit").and_then(|value| value.as_u64()),
            Some(AGENT_DEFAULT_LOCATE_PAGE),
            "the belt must send the page it advertises"
        );

        // The control: the registry must still carry the larger default, so this
        // is the profile choosing a page rather than the registry having lost
        // one.
        let registered = crate::tools::tool_definitions();
        let full = registered
            .tools
            .iter()
            .find(|tool| tool.name == "semantic_locate")
            .expect("semantic_locate is registered");
        let registered_limit = full.input_schema["properties"]["limit"]["default"].as_u64();
        assert!(
            registered_limit.is_some_and(|value| value > AGENT_DEFAULT_LOCATE_PAGE),
            "the full profile's locate page was shrunk too: {registered_limit:?}"
        );
    }

    /// The belt must never outrank a caller who named a budget itself.
    ///
    /// `ResponseBudget::from_arguments` takes the FIRST of `max_chars` then
    /// `max_response_chars` that is present, so an unconditional insert of
    /// `max_chars` would silently override a caller who had passed
    /// `max_response_chars` and answer under a ceiling they never asked for.
    #[test]
    fn the_belt_never_overrides_a_budget_the_caller_named() {
        for key in ["max_chars", "max_response_chars"] {
            let mut arguments = HashMap::from([(key.to_string(), serde_json::json!(58_000u64))]);
            apply_belt_defaults("trace_data_flow", &mut arguments);
            assert_eq!(
                arguments.get(key).and_then(|value| value.as_u64()),
                Some(58_000),
                "the belt moved a {key} the caller named"
            );
            assert!(
                !(key == "max_response_chars" && arguments.contains_key("max_chars")),
                "the belt added max_chars beside a caller's max_response_chars, which \
                 from_arguments would then prefer"
            );
        }
        // Same rule on the walker's shape.
        for key in ["include_body", "compact"] {
            let mut arguments = HashMap::from([(key.to_string(), serde_json::json!(true))]);
            apply_belt_defaults("trace_data_flow", &mut arguments);
            assert_eq!(
                arguments.get(key).and_then(|value| value.as_bool()),
                Some(true),
                "the belt moved a {key} the caller named"
            );
        }
        // And a caller that names nothing gets the belt's shape.
        let mut bare = HashMap::new();
        apply_belt_defaults("trace_data_flow", &mut bare);
        assert_eq!(
            bare.get("include_body").and_then(|value| value.as_bool()),
            Some(false),
            "the walker's default shape on this belt is the chain, not the bodies"
        );
    }

    /// [`BUDGET_TOOLS`] must name exactly the belt tools the REGISTRY gives a
    /// budget property, or the belt caps a subset and nothing says so.
    #[test]
    fn the_budget_tool_list_matches_the_registry() {
        let full = crate::tools::tool_definitions();
        let belt: std::collections::HashSet<&str> = crate::tools::agent_default_tool_names()
            .iter()
            .copied()
            .collect();
        let mut registered: Vec<String> = full
            .tools
            .into_iter()
            .filter(|tool| belt.contains(tool.name.as_str()))
            .filter(|tool| {
                tool.input_schema
                    .get("properties")
                    .and_then(|value| value.as_object())
                    .is_some_and(|properties| {
                        properties.contains_key("max_chars")
                            || properties.contains_key("max_response_chars")
                    })
            })
            .map(|tool| tool.name)
            .collect();
        registered.sort();
        let mut listed: Vec<String> = BUDGET_TOOLS.iter().map(|name| name.to_string()).collect();
        listed.sort();
        assert_eq!(
            listed, registered,
            "BUDGET_TOOLS and the registry disagree about which belt tools carry a budget"
        );
    }

    /// The knobs the shipped acceptance checks read out of the served surface.
    ///
    /// `agent-default` trims response-shaping properties, and three acceptance
    /// checks read exactly those properties as the contract an agent discovers
    /// a knob from. Trimming them took `Product Acceptance` red on `main` for
    /// four landings, as `magic:6`, `magic:14` and `response_budget:2`, while
    /// every pull request stayed green, because that job is `skipped` on a pull
    /// request and graded only on `main`'s push run.
    ///
    /// The three checks, so the next person can find them.
    /// `scripts/acceptance/magic_repro.py` `check_6` requires `include_body` or
    /// `compact` on `trace_data_flow`. Its `check_14` arm 3 requires the literal
    /// `last_settled_selected_graph` in the served `kin_graph_status`
    /// description. `scripts/acceptance/response_budget_elisions.py` `check_2`
    /// grades every advertised `max_chars` or `max_response_chars` and reports
    /// UNREADABLE when it finds none, so the served profile has to advertise a
    /// budget wherever the registry does.
    ///
    /// Every arm collects rather than panics, so one trimmed knob reports itself
    /// and the other two arms still run.
    #[test]
    fn agent_default_serves_every_knob_the_shipped_checks_assert() {
        const BUDGET_KEYS: [&str; 2] = ["max_chars", "max_response_chars"];
        let served = served_agent_default();
        let full = crate::tools::tool_definitions();
        let properties = |list: &ToolsListResult, name: &str| -> Vec<String> {
            list.tools
                .iter()
                .find(|tool| tool.name == name)
                .and_then(|tool| tool.input_schema.get("properties"))
                .and_then(|value| value.as_object())
                .map(|object| object.keys().cloned().collect())
                .unwrap_or_default()
        };
        let has_budget =
            |keys: &[String]| keys.iter().any(|key| BUDGET_KEYS.contains(&key.as_str()));
        let mut problems: Vec<String> = Vec::new();

        // magic_repro.py check_6.
        let trace = properties(&served, "trace_data_flow");
        if !trace
            .iter()
            .any(|key| key == "include_body" || key == "compact")
        {
            problems.push(format!(
                "trace_data_flow advertises neither include_body nor compact, which \
                 magic_repro.py check_6 requires: {trace:?}"
            ));
        }

        // response_budget_elisions.py check_2, graded against the registry's own set.
        for tool in &served.tools {
            if !has_budget(&properties(&full, &tool.name)) {
                continue;
            }
            let keys = properties(&served, &tool.name);
            if !has_budget(&keys) {
                problems.push(format!(
                    "{} registers a budget parameter and agent-default advertises none, so \
                     response_budget_elisions.py check_2 grades a smaller set than it did: \
                     {keys:?}",
                    tool.name
                ));
            }
        }

        // magic_repro.py check_14, arm 3.
        let status = served
            .tools
            .iter()
            .find(|tool| tool.name == "kin_graph_status")
            .map(|tool| tool.description.as_str())
            .unwrap_or_default();
        if !status.contains("last_settled_selected_graph") {
            problems.push(
                "the kin_graph_status short description does not carry \
                 last_settled_selected_graph, which magic_repro.py check_14 arm 3 requires"
                    .to_string(),
            );
        }

        assert!(
            problems.is_empty(),
            "agent-default trimmed a knob a shipped acceptance check reads: {problems:#?}"
        );
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

    /// The served list stays in name order.
    #[test]
    fn the_served_list_stays_sorted() {
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
        // `max_chars` is the exception the keep-list doc names. It shapes the
        // response like the four below, and it stays advertised because
        // response_budget_elisions.py check_2 grades the advertised budget and
        // reports UNREADABLE when no tool carries one. An agent that cannot see
        // it cannot bound a response either.
        assert!(
            properties.contains_key("max_chars"),
            "max_chars is graded off the served schema and must stay advertised"
        );
        for shaping in ["compact", "explain", "snippet_alias", "pipeline"] {
            assert!(
                !properties.contains_key(shaping),
                "{shaping} shapes the response and should not be advertised here"
            );
        }
        // The control: the registered schema still has them all, so the profile
        // is hiding the four rather than the registry having lost them.
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
            locate.contains(DECLARATION_FILTER_CANONICAL),
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
        // The two-endpoint question has its own tool now, so the one-endpoint
        // walker must hand it over rather than leaving a small model to guess.
        assert!(
            descriptions["trace_data_flow"].contains(crate::handlers::path::TOOL_NAME),
            "trace_data_flow must name trace_path for the two-endpoint question"
        );
        assert!(
            descriptions[crate::handlers::path::TOOL_NAME].contains("trace_data_flow"),
            "and trace_path must name it back for the one-endpoint question"
        );
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

    /// Every argument the belt inserts is one the tool's registered schema
    /// advertises, with one named exception, and a tool the belt has no default
    /// for is left exactly as the caller sent it.
    ///
    /// This replaces a form that asserted the belt touched `semantic_locate`
    /// alone. That held while `surface` was the only injection and stopped being
    /// the point once the response ceiling moved onto every budget tool. The
    /// durable invariant is the one that test's own comment named: a default
    /// that leaked onto a tool would be sending an argument its handler never
    /// advertised. That is what this asserts, against the registry rather than
    /// against a list of names that has to be remembered.
    ///
    /// The exception is `semantic_locate`'s `surface`, which the registry
    /// advertises on no profile. The compact shape is opt-in on the wire by
    /// design, the handler reads the argument by name, and no tool in this
    /// profile sets `additionalProperties: false`. It is named here so the
    /// exception stays a decision on the record rather than a hole in the test.
    #[test]
    fn the_belt_only_injects_arguments_the_tool_advertises() {
        const UNADVERTISED_BY_DESIGN: [(&str, &str); 1] = [("semantic_locate", "surface")];
        let full = crate::tools::tool_definitions();
        let mut untouched = 0usize;
        for tool in &full.tools {
            let mut arguments: HashMap<String, serde_json::Value> = HashMap::new();
            apply_belt_defaults(&tool.name, &mut arguments);
            if arguments.is_empty() {
                untouched += 1;
                continue;
            }
            let properties = tool
                .input_schema
                .get("properties")
                .and_then(|value| value.as_object());
            for key in arguments.keys() {
                if UNADVERTISED_BY_DESIGN.contains(&(tool.name.as_str(), key.as_str())) {
                    continue;
                }
                assert!(
                    properties.is_some_and(|properties| properties.contains_key(key)),
                    "the belt injected {key} into {}, whose registered schema does not \
                     advertise it",
                    tool.name
                );
            }
        }
        // The control. Without it the loop above is satisfied by a belt that
        // injects into everything, since every assertion would then be about a
        // tool that has defaults rather than about one that must not.
        assert!(
            untouched > 0,
            "every registered tool received a belt default, so this test proved nothing"
        );
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
                .unwrap_or_else(|| {
                    panic!(
                        "schema_keep_lists() in crates/kin-mcp/src/agent_belt.rs names '{name}', \
                         which tool_definitions() does not register; fix the spelling or drop \
                         the entry"
                    )
                });
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
