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
/// 180 is one sentence of technical prose, down from the 265 that bought two.
/// It is a budget rather than a target: several tools here are shorter, and none
/// should need more, because a description longer than this is documentation,
/// and documentation belongs in the `full` profile where a reader has the room
/// for it. Two sentences were affordable when the belt was measured in tens of
/// thousands of tokens; against a 64k local window they are not, and the second
/// sentence was where the prose crept back.
/// `no_agent_default_description_exceeds_its_budget` below fails on any tool
/// that exceeds it.
pub const AGENT_DEFAULT_DESCRIPTION_BUDGET: usize = 180;

/// The whole profile's description budget.
///
/// 4,500 characters against the 47,739 the long forms cost. Held as a total as
/// well as a per-tool cap because twenty tools each sitting just under the
/// per-tool budget would be a profile that had learned nothing.
pub const AGENT_DEFAULT_PROFILE_DESCRIPTION_BUDGET: usize = 4_500;

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
/// therefore gets [`agent_default_response_max_chars`] for its own name, which
/// is [`AGENT_DEFAULT_RESPONSE_MAX_CHARS`] for a tool that answers with a list
/// and [`AGENT_CHAIN_RESPONSE_MAX_CHARS`] for the two that answer with a chain.
/// The walker gets the shape rather than the bodies, and the context pack gets a
/// token budget that fits inside the answer the list rule sizes. Every one of
/// these is advertised on the served schema by [`apply_belt_schema_defaults`],
/// so a caller reading `tools/list` sees the number the belt actually sends and
/// can raise it with the same `max_chars` it always could.
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
            serde_json::json!(agent_default_response_max_chars(name)),
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
        (
            "find_references",
            "Find who depends on one entity: callers, importers and references, one row each with id, name, kind and file. One hop only; use trace_data_flow for a chain.",
        ),
        (
            "get_context_pack",
            "Assemble a token-bounded context bundle from one entity, several entities or a question: focal bodies plus signatures and routes, instead of several get_entity_source reads.",
        ),
        (
            "get_entity_source",
            "Return one entity's exact graph-owned body by id, when a snippet is not enough.",
        ),
        (
            "graph_neighborhood",
            "Get what one entity depends on and what depends on it, to a depth you choose. Callers only? Use find_references. An ordered path? Use trace_data_flow.",
        ),
        (
            "impact_analysis",
            "Walk the graph from a change to every entity it could affect, targeted one way at a time by entity_ids, files, base and head, or change_ids.",
        ),
        (
            "kin_artifact_list",
            "List the repository's tracked files at one semantic change, code and non-code alike, whether or not the parsers made entities for them.",
        ),
        (
            "kin_artifact_read",
            "Read one tracked file's exact content by artifact_id or repo-relative path: text when valid UTF-8, else base64.",
        ),
        (
            "kin_graph_status",
            "Counts for the graph this call is answered from, and how many entities are embedded, pending or unindexed. `sampling=last_settled_selected_graph` is the last settled reading.",
        ),
        // The one fact an agent cannot discover for itself: that the list it was
        // handed is partial on purpose, and how to reach the rest. Every other
        // short form here describes a capability; this one describes the surface.
        (
            crate::handlers::tool_search::TOOL_NAME,
            "This profile does not serve every tool in the registry. Find tools by describing \
             the job. Each match includes its full \
             schema and invocation.profile_enabled. Discovery does not enable withheld tools; \
             use a connection whose profile serves them. Enabled tools still require normal \
             authorization. Omit `need` to list every tool.",
        ),
        (
            "kin_provenance_query",
            "Answer who changed an entity and whether it was approved: change count, latest change, approvals, a page of changes and recent audit events.",
        ),
        (
            "kin_session_end",
            "Session plumbing for writes. Close an open session and release what it holds, once your writing is done.",
        ),
        (
            "kin_session_heartbeat",
            "Session plumbing for writes. Renew an open session during long work so it does not lapse at its idle TTL.",
        ),
        (
            "kin_mutate",
            "Validate and commit a batch of graph mutations in one atomic call, naming the entity or file each operation changes and the new body it gets.",
        ),
        (
            "kin_session_start",
            "Session plumbing for writes. Open a session and get a session_id, before your first transaction, so the work is attributed.",
        ),
        (
            "kin_transaction_abort",
            "Transaction plumbing for writes. Discard everything staged on an open transaction and close it. Refused once kin_transaction_commit has fenced it.",
        ),
        (
            "kin_transaction_begin",
            "Transaction plumbing for writes. Open a transaction and get a transaction_id. Nothing staged on it lands until kin_transaction_commit.",
        ),
        (
            "kin_transaction_commit",
            "Transaction plumbing for writes. Publish everything staged on one transaction atomically, all of it or none. Re-sending a fenced commit is safe.",
        ),
        (
            "kin_transaction_stage",
            "Transaction plumbing for writes. Stage a create, update, delete or rename onto an open transaction. An update replaces the whole body, so send the complete new text.",
        ),
        (
            "list_file_entities",
            "List every entity the graph holds for one file by repo-relative path, and say whether that list is complete, before concluding a file holds nothing.",
        ),
        (
            "semantic_locate",
            "Find code by a plain-language question, ranked from the graph: id, name, kind, file, line, signature, score. Know the exact name? Use semantic_search.",
        ),
        (
            DECLARATION_FILTER_CANONICAL,
            "Filter declarations by exact name, kind or language; it matches names, not meaning. Asking what code does rather than what it is called? Use semantic_locate.",
        ),
        (
            "trace_data_flow",
            "Walk the call chain out from ONE entity and get the whole ordered path back; it walks call and import edges. Naming TWO things? Use trace_path.",
        ),
        (
            "trace_path",
            "Find how one entity reaches another as ordered hops; read `found` and `gap` before concluding A never reaches B. One endpoint only? Use trace_data_flow.",
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
                "limit_per_step",
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
            &[
                "entity_id",
                "entities",
                "question",
                "depth",
                "token_budget",
                "max_chars",
            ] as &[&str],
        ),
        ("kin_provenance_query", &["entity_id", "limit"] as &[&str]),
        // Both, written out rather than left absent. The tool registers exactly
        // these two, so this trims nothing today; it is here because the belt's
        // rule is that a served tool declares which properties survive, and a
        // property added later would otherwise join the belt unreviewed.
        (
            crate::handlers::tool_search::TOOL_NAME,
            &["need", "limit"] as &[&str],
        ),
    ])
}

/// The response ceiling `agent-default` asks for on its agents' behalf, for
/// every budgeted tool whose answer is a LIST.
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
///
/// A list cut at this number loses its tail and keeps its answer: the rows a
/// reader most wants lead it, and the count beside them says how many were
/// dropped. [`AGENT_CHAIN_RESPONSE_MAX_CHARS`] is the number for the two tools
/// where that is not true.
pub const AGENT_DEFAULT_RESPONSE_MAX_CHARS: u64 = 12_000;

/// The response ceiling `agent-default` asks for on the two tools whose answer
/// is a CHAIN rather than a list.
///
/// The number is the agent's own per-result limit. `kin agent run` cuts one tool
/// result to `ContextWindow::default_result_ceiling()`, an eighth of the window
/// at `kin_agent::context::BYTES_PER_TOKEN`, and on the 65,536-token window the
/// 2026-09-15 trace measurement ran under that is 24,576 bytes. It is the
/// largest ceiling a server can ask for and still know the whole answer reaches
/// the model, because past it the harness cuts and Kin discloses nothing about a
/// cut it did not make. kin-agent is not a dependency of this crate and cannot
/// be, so the number is written here rather than imported, with its derivation
/// beside it.
///
/// Why these two tools and not the whole belt. The rule above sizes an answer so
/// six of them fit a 24,000-token run, and for a ranked list that trade is
/// right: the top of the list IS the answer. A chain is not a list. Cutting it
/// removes the far end, which is the end the question was about, and a walk that
/// never reaches the callee a caller asked about has spent its tokens and
/// answered nothing. #76 measured that on `cli/cli`: at the trace tool's wider
/// per-step default the rendered answer is 16,327 characters, the 12,000 ceiling
/// cut the chain, and an untargeted `trace_data_flow` still did not reach
/// `httpRequest`. `get_context_pack` assembles the same shape, a focal plus the
/// routes and dependencies around it, and sheds from the same far end.
///
/// The cost is stated rather than hidden: two chain answers now fill a
/// 24,000-token run where four fit before. That is the trade the decision makes,
/// and it is made for the tools where a cut answer is not a shorter answer but a
/// wrong one. Every other budgeted tool keeps 12,000.
pub const AGENT_CHAIN_RESPONSE_MAX_CHARS: u64 = 24_576;

/// The belt tools that get [`AGENT_CHAIN_RESPONSE_MAX_CHARS`].
///
/// A list rather than a predicate on the tool's shape, because "is this answer a
/// chain" is not a property the registry carries and inferring it would make the
/// ceiling move when an unrelated field moved.
const CHAIN_RESPONSE_TOOLS: [&str; 2] = ["trace_data_flow", "get_context_pack"];

/// The response ceiling this belt asks for on behalf of `tool`.
///
/// One function so the injected number and the advertised number cannot come
/// apart: `apply_belt_defaults` and `belt_schema_defaults` both read it, and
/// `no_agent_default_response_budget_is_advertised_above_the_cap` grades them
/// against each other through it.
pub fn agent_default_response_max_chars(tool: &str) -> u64 {
    if CHAIN_RESPONSE_TOOLS.contains(&tool) {
        AGENT_CHAIN_RESPONSE_MAX_CHARS
    } else {
        AGENT_DEFAULT_RESPONSE_MAX_CHARS
    }
}

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
///
/// This did not move when the pack's response ceiling did. The two are separate
/// levers and the change to the ceiling was a decision about one of them: this
/// number bounds what the BUILDER assembles, and the ceiling bounds what the
/// response may ship. Raising the ceiling stops a built pack from being cut on
/// the way out; raising this would build a larger one, which is a different
/// question with its own measurement and is not what
/// [`AGENT_CHAIN_RESPONSE_MAX_CHARS`] decided.
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

/// Whole input schemas this belt serves in place of the registered ones.
///
/// A keep-list hides a property. This replaces a schema, which is what a tool
/// needs when the bytes are not in its property LIST but in one property's
/// nested contract, and when the registered top-level keys include combinators a
/// trimmed profile should not advertise.
///
/// `kin_mutate` is the only entry and the reason the mechanism exists. Its
/// registered `operations` item is a seven-branch `oneOf` that spells out every
/// verb synonym and every path rule, 8,406 bytes of input schema on a tool whose
/// whole served definition is 8,699. The form below carries the same five fields
/// under one object and the canonical verb for each operation.
///
/// It advertises less than the server accepts, which is the same bargain every
/// trim in this module makes: no tool here sets `additionalProperties: false` at
/// the top level, the handler reads arguments by name, and the `full` profile
/// still serves every branch. A caller that sends `modify` instead of `update`,
/// a `payload` object, or a `request_id` still reaches the same handler and is
/// validated against the registered schema there.
///
/// `every_schema_override_names_only_registered_properties` holds the one
/// invariant that matters: an override may hide a property but may never invent
/// one, and may never require a property the registered schema does not.
fn belt_schema_overrides() -> BTreeMap<&'static str, serde_json::Value> {
    BTreeMap::from([(
        "kin_mutate",
        serde_json::json!({
            "type": "object",
            "properties": {
                "operations": {
                    "type": "array",
                    "description": "Changes applied together or not at all.",
                    "items": {
                        "type": "object",
                        "properties": {
                            "verb": {
                                "type": "string",
                                "enum": ["update", "create", "replace", "rename", "delete"],
                                "description": "update an entity body; create, replace, rename or delete a tracked file."
                            },
                            "target": {
                                "type": "string",
                                "minLength": 1,
                                "description": "Entity UUID or exact entity name for update; repository-relative path for the file verbs."
                            },
                            "body": {
                                "type": "string",
                                "description": "Complete new UTF-8 text, never a fragment or a diff. Required by update, create and replace."
                            },
                            "destination": {
                                "type": "string",
                                "description": "Repository-relative path the file moves to. Required by rename."
                            },
                            "description": {
                                "type": "string",
                                "description": "One sentence saying what this operation changes."
                            }
                        },
                        "required": ["verb", "target", "description"]
                    }
                },
                "summary": {
                    "type": "string",
                    "description": "One sentence a human reads in history. Omitted, the change records only its id."
                }
            },
            "required": ["operations"]
        }),
    )])
}

/// The properties whose advertised `default` this belt rewrites, by tool.
///
/// A number the profile injects has to be the number the profile advertises, or
/// the served schema stops being the contract the acceptance suite grades it as.
fn belt_schema_defaults() -> BTreeMap<(&'static str, &'static str), serde_json::Value> {
    let mut defaults: BTreeMap<(&'static str, &'static str), serde_json::Value> = BTreeMap::new();
    for tool in BUDGET_TOOLS {
        defaults.insert(
            (tool, "max_chars"),
            serde_json::json!(agent_default_response_max_chars(tool)),
        );
    }
    // `trace_data_flow` registers the same budget under both spellings, and a
    // caller reading either one has to see the same ceiling. This one is not
    // decoration: the handler reads `max_response_chars` and ignores
    // `max_chars`, so the spelling the belt injects bounds the response at the
    // envelope while THIS one is what the walk bounds itself by.
    defaults.insert(
        ("trace_data_flow", "max_response_chars"),
        serde_json::json!(agent_default_response_max_chars("trace_data_flow")),
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
/// 90 is one plain clause. A property description exists to tell a model what
/// to pass, and the shape, bounds and default are already machine-readable
/// beside it in `type`, `enum`, `minimum`, `maximum` and `default`, so prose
/// that restates them is paid for twice.
/// `no_agent_default_property_description_exceeds_its_budget` fails on any
/// property over it.
pub const AGENT_DEFAULT_PROPERTY_DESCRIPTION_BUDGET: usize = 90;

/// The tools whose schemas this module does not rewrite at all.
///
/// The nested transaction contracts stay whole: a staged mutation's shape is the
/// thing a caller gets wrong, and it is the one place on this belt where the
/// schema IS the documentation. Both of these are harness-owned
/// (`kin-agent/src/belt.rs`), so `kin agent run` never puts either on a model's
/// belt and their bytes are paid only by a client wired straight to the MCP
/// server.
///
/// `kin_mutate` used to sit here with them and no longer does. It is the one
/// mutation tool a model IS handed, so its bytes are on the belt of every agent
/// run: 8,699 of the belt's 22,014 bytes, 40 percent of the schema an agent
/// reads before it has asked anything, almost all of it the seven-branch `oneOf`
/// under `operations`. [`belt_schema_overrides`] serves it a single-object form
/// of the same contract instead.
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
            "Character ceiling; what was cut is named in `elisions`.",
        ),
        (
            "max_response_chars",
            "Character ceiling; the same parameter as `max_chars`.",
        ),
        (
            "cursor",
            "Opaque token from a prior result's `next_cursor`. Pass it back unedited.",
        ),
        (
            "session_id",
            "Owning session UUID. In enforce mode it must match the authenticated caller.",
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
            "Rank test-role entities alongside source. Off unless your query is about tests.",
        ),
        (
            ("semantic_locate", "limit"),
            "Max ranked rows per page: entities, or files at file granularity. Default 20.",
        ),
        (
            ("list_file_entities", "path"),
            "Repo-relative file path, no leading slash and no \"..\". Optional when `cursor` names it.",
        ),
        (
            ("list_file_entities", "page_size"),
            "Entities per page (default 200, 1..1000). `total_in_file` is the whole-file count.",
        ),
        (
            ("semantic_search", "kind"),
            "Declaration kind, or `command` for a CLI command's own run function and constructor.",
        ),
        (
            ("trace_data_flow", "target"),
            "A symbol to reach, by exact name or UUID. Its branch survives the per-step cap first.",
        ),
        (
            ("trace_data_flow", "include_body"),
            "Inline each step's source. False gives the chain's shape at a fraction of the size.",
        ),
        (
            ("trace_data_flow", "direction"),
            "Which way to walk: `calls` for callees, `callers` for callers, `both` merges.",
        ),
        (
            ("trace_data_flow", "limit_per_step"),
            "Edges kept per hop. Raise it for a node `clipped_steps` reports as cut.",
        ),
        (
            ("get_context_pack", "entities"),
            "Several focal entity names or UUIDs when the question is about how they connect.",
        ),
        (
            ("get_context_pack", "question"),
            "A plain-language question resolved to one or more focal entities before packing.",
        ),
        (
            ("trace_path", "direction"),
            "`forward`: from reaches to. `reverse`: the other way. `either` (default) tries both.",
        ),
        (
            ("trace_path", "max_depth"),
            "Hops between the two ends (default 6, ceiling 12). Containment hops are not counted.",
        ),
        (
            ("trace_path", "limit"),
            "Routes returned, shortest first (default 3, ceiling 25). See `routes_total`.",
        ),
        (
            ("trace_path", "from_file"),
            "Pin `from` to the entity of that name in this file. Same as the name@file spelling.",
        ),
        (
            ("kin_mutate", "summary"),
            "One sentence a human reads in history. Omitted, the change records only its id.",
        ),
        (
            ("find_references", "relation_kinds"),
            "Filter to calls, imports or references. Defaults to all three.",
        ),
        (
            ("graph_neighborhood", "direction"),
            "`out` for what the focal depends on, `in` for what depends on it, `both` merges.",
        ),
        (
            (crate::handlers::tool_search::TOOL_NAME, "need"),
            "The job in plain language. Omit it to list every registered tool.",
        ),
        (
            (crate::handlers::tool_search::TOOL_NAME, "limit"),
            "Matches returned as full definitions (default 5, ceiling 25). See `matched_names`.",
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
        // Only when it is actually shorter. A "short form" table keyed by
        // property name meets the same name on tools whose registered
        // description is already one clause, and replacing those made three
        // tools BIGGER when this table grew: `kin_transaction_begin` by 41
        // bytes, `kin_session_end` and `kin_session_heartbeat` by 64 each. A
        // trim that can lengthen its subject is not a trim, and the arithmetic
        // hid it because the total still fell.
        let Some(existing) = property.get("description").and_then(|value| value.as_str()) else {
            continue;
        };
        if short.len() < existing.len() {
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
    let overrides = belt_schema_overrides();
    for tool in &mut list.tools {
        if let Some(short) = descriptions.get(tool.name.as_str()) {
            tool.description = (*short).to_string();
        }
        // An override replaces the schema outright, so the keep-list and the
        // property-prose pass below have nothing left to do on that tool: both
        // exist to cut a registered schema down, and the override already is the
        // cut form. The default injection still runs, because a budget this
        // profile advertises has to be the budget it injects whatever produced
        // the schema.
        if let Some(schema) = overrides.get(tool.name.as_str()) {
            tool.input_schema = schema.clone();
        } else {
            if let Some(keep) = keeps.get(tool.name.as_str()) {
                trim_schema(&mut tool.input_schema, keep);
            }
            shorten_property_descriptions(&tool.name, &mut tool.input_schema);
        }
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
    use std::collections::BTreeSet;

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

    /// Every tool the search profile serves needs one too, for the same reason
    /// and with more at stake: that profile serves five tools, so one carrying
    /// its several-thousand-character registered form would be most of the list.
    #[test]
    fn every_agent_search_tool_has_a_short_description() {
        let descriptions = short_descriptions();
        let missing: Vec<&str> = crate::tools::agent_search_tool_names()
            .iter()
            .copied()
            .filter(|name| !descriptions.contains_key(name))
            .collect();
        assert!(
            missing.is_empty(),
            "these agent-search tools have no short description: {missing:?}; add an entry for \
             each in short_descriptions() and schema_keep_lists() in \
             crates/kin-mcp/src/agent_belt.rs, at most {AGENT_DEFAULT_DESCRIPTION_BUDGET} \
             characters per description."
        );
    }

    /// And nothing in the table that no belt profile serves, which would be a
    /// short form nobody reads and a name nobody notices going stale.
    #[test]
    fn the_short_description_table_has_no_orphans() {
        let served: std::collections::HashSet<&str> = crate::tools::agent_default_tool_names()
            .iter()
            .copied()
            .chain(crate::tools::agent_search_tool_names().iter().copied())
            .collect();
        let orphans: Vec<&str> = short_descriptions()
            .keys()
            .copied()
            .filter(|name| !served.contains(name))
            .collect();
        assert!(
            orphans.is_empty(),
            "short_descriptions() in crates/kin-mcp/src/agent_belt.rs has entries for tools no \
             belt profile serves: {orphans:?}; remove them, or put the names back in \
             agent_default_tool_names() or agent_search_tool_names() if the removal was \
             accidental"
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

    /// Every advertised response budget on `agent-default` is the one its own
    /// tool is capped at, and the number advertised is the number injected.
    ///
    /// The registered ceiling is 45,000 characters, about 10,500 gemma-4-e4b
    /// tokens, so two default answers exhaust the 24,000-token run this belt
    /// exists to fit. The list cap is derived from one rule: six calls at
    /// default size inside that run with room left to answer. The two chain
    /// tools are capped at the agent's own per-result limit instead, for the
    /// reason on [`AGENT_CHAIN_RESPONSE_MAX_CHARS`].
    ///
    /// Read per tool rather than against one number, because a single ceiling is
    /// exactly what this stopped being. Asserted as EQUALITY rather than "at or
    /// under", which is stronger than the check it replaced: a tool advertising
    /// less than its cap used to pass, and would now be a silent second policy.
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
        let mut checked = 0usize;
        for tool in &served.tools {
            let properties = tool
                .input_schema
                .get("properties")
                .and_then(|value| value.as_object());
            let Some(properties) = properties else {
                continue;
            };
            let cap = agent_default_response_max_chars(&tool.name);
            for key in ["max_chars", "max_response_chars"] {
                let Some(property) = properties.get(key) else {
                    continue;
                };
                checked += 1;
                let advertised = property.get("default").and_then(|value| value.as_u64());
                match advertised {
                    None => problems.push(format!("{}.{key} advertises no default", tool.name)),
                    Some(value) if value != cap => problems.push(format!(
                        "{}.{key} advertises {value}, and this tool's cap is {cap}",
                        tool.name
                    )),
                    Some(_) => {}
                }
                // The number advertised has to be the number the belt sends.
                let mut arguments = HashMap::new();
                apply_belt_defaults(&tool.name, &mut arguments);
                let injected = arguments.get("max_chars").and_then(|value| value.as_u64());
                if injected != Some(cap) {
                    problems.push(format!(
                        "{} advertises a budget and the belt injects {injected:?} against a cap \
                         of {cap}",
                        tool.name
                    ));
                }
            }
        }
        assert!(
            problems.is_empty(),
            "agent-default response budgets disagree with their caps: {problems:#?}"
        );
        // The sweep has to be reaching the schemas, or an empty problem list is
        // a fixture that found nothing rather than a belt that is right.
        assert!(
            checked >= 9,
            "the sweep found only {checked} budget properties on agent-default, so it is not \
             reaching the served schemas"
        );
        // The split is the point, and a table that collapsed back to one number
        // would satisfy every assertion above.
        assert_eq!(
            agent_default_response_max_chars("trace_data_flow"),
            AGENT_CHAIN_RESPONSE_MAX_CHARS
        );
        assert_eq!(
            agent_default_response_max_chars("get_context_pack"),
            AGENT_CHAIN_RESPONSE_MAX_CHARS
        );
        assert_eq!(
            agent_default_response_max_chars("find_references"),
            AGENT_DEFAULT_RESPONSE_MAX_CHARS
        );
        assert_ne!(
            AGENT_CHAIN_RESPONSE_MAX_CHARS,
            AGENT_DEFAULT_RESPONSE_MAX_CHARS
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

    /// Every remediation or invocation alternative the agent-facing response
    /// names must be present in the schema that same agent receives.
    ///
    /// The first-contact run was told to widen `limit_per_step`, but the belt
    /// had removed that property. It also left `question` and `entities` in
    /// `get_context_pack`'s input alternatives after removing both property
    /// definitions, producing a schema that described only one of its three
    /// valid ways to call the tool.
    #[test]
    fn agent_default_advertises_every_answer_recovery_and_input_alternative() {
        let served = served_agent_default();
        let properties = |name: &str| {
            served
                .tools
                .iter()
                .find(|tool| tool.name == name)
                .unwrap_or_else(|| panic!("agent-default does not serve {name}"))
                .input_schema["properties"]
                .as_object()
                .unwrap_or_else(|| panic!("{name} has no property map"))
        };

        let trace = properties("trace_data_flow");
        assert!(
            trace.contains_key("limit_per_step"),
            "trace remediation tells this profile to widen limit_per_step, so its served schema \
             must advertise the knob: {:?}",
            trace.keys().collect::<Vec<_>>()
        );

        let context = properties("get_context_pack");
        for alternative in ["entity_id", "entities", "question"] {
            assert!(
                context.contains_key(alternative),
                "get_context_pack names `{alternative}` as a valid input alternative but the \
                 served property map omits it: {:?}",
                context.keys().collect::<Vec<_>>()
            );
        }
    }

    /// Every property name a schema requires, directly or inside an `anyOf`,
    /// `oneOf` or `allOf` branch. Combinator branches only: a nested object's
    /// own `required` names ITS properties, not the tool's.
    fn required_property_names(schema: &serde_json::Value) -> Vec<(&str, bool)> {
        let mut names = Vec::new();
        if let Some(required) = schema.get("required").and_then(|value| value.as_array()) {
            names.extend(
                required
                    .iter()
                    .filter_map(|value| value.as_str())
                    .map(|name| (name, false)),
            );
        }
        for combinator in ["anyOf", "oneOf", "allOf"] {
            let Some(branches) = schema.get(combinator).and_then(|value| value.as_array()) else {
                continue;
            };
            for branch in branches {
                names.extend(
                    required_property_names(branch)
                        .into_iter()
                        .map(|(name, _)| (name, true)),
                );
            }
        }
        names
    }

    /// Every backtick-quoted identifier in `text`. Multi-word phrases and
    /// quoted values are not identifiers and are left alone.
    fn backticked_identifiers(text: &str) -> Vec<&str> {
        text.split('`')
            .skip(1)
            .step_by(2)
            .filter(|token| {
                !token.is_empty()
                    && token
                        .chars()
                        .all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
                    && token.starts_with(|ch: char| ch.is_ascii_alphabetic() || ch == '_')
            })
            .collect()
    }

    /// A short property description may not introduce an identifier the tool's
    /// own registered contract never uses.
    ///
    /// This belt shortens a vetted description; it does not get to write a new
    /// claim. The `limit_per_step` short form in this bundle first shipped
    /// naming `truncated_steps`, a response field that exists nowhere in Kin,
    /// while the real disclosure is `clipped_steps` carrying `fanout_truncated`
    /// and `fanout_dropped`. To the agent reading it, an invented field name is
    /// indistinguishable from a real one, and the remediation it anchors is
    /// unfollowable.
    ///
    /// The haystack is the tool's WHOLE registered definition, description and
    /// schema together, so an enum value and a response field both count as
    /// vetted. Scoped to the per-tool table, which is where a description can
    /// name a fact about one tool; the shared table's entries are written to be
    /// true of every tool that takes the property.
    #[test]
    fn no_short_property_description_names_an_identifier_the_tool_never_publishes() {
        let registered = crate::tools::tool_definitions();
        let mut checked = 0usize;
        let mut unknown: Vec<String> = Vec::new();

        for ((tool, property), short) in tool_property_descriptions() {
            let definition = registered
                .tools
                .iter()
                .find(|candidate| candidate.name == tool)
                .unwrap_or_else(|| {
                    panic!("tool_property_descriptions() names unregistered tool {tool}")
                });
            let contract = serde_json::to_string(&definition.input_schema)
                .expect("a registered schema serializes");
            for token in backticked_identifiers(short) {
                checked += 1;
                if contract.contains(token) || definition.description.contains(token) {
                    continue;
                }
                unknown.push(format!("{tool}.{property} names `{token}`"));
            }
        }

        assert!(
            unknown.is_empty(),
            "these short property descriptions name identifiers absent from the tool's own \
             registered description and schema, so an agent is told to read a field that does \
             not exist: {unknown:?}"
        );
        assert!(
            checked >= 10,
            "the sweep read {checked} backticked identifiers out of the per-tool table, so it is \
             not reaching the text it grades"
        );
    }

    /// A served schema must not require a property it does not define.
    ///
    /// [`trim_schema`] filters `properties` and the top-level `required` against
    /// the keep list and touches nothing else, so a constraint nested in a
    /// combinator keeps naming a property the trim removed. `get_context_pack`
    /// shipped exactly that on all three belt profiles: its `anyOf` offers
    /// `entity_id`, `entities` and `question`, and the keep list defined only
    /// the first, so two of the three documented ways to call the tool were
    /// required by the schema and absent from it.
    ///
    /// A sweep rather than those two names, because the next keep-list edit that
    /// drops a constrained property is the same defect, and a test naming the
    /// properties of the last one stays green through it.
    #[test]
    fn no_belt_profile_serves_a_schema_that_requires_a_property_it_does_not_define() {
        let mut names_read = 0usize;
        let mut branch_names_read = 0usize;
        let mut missing: Vec<String> = Vec::new();

        for (profile, names) in [
            ("agent-default", crate::tools::agent_default_tool_names()),
            ("agent-query", crate::tools::agent_query_tool_names()),
            ("agent-search", crate::tools::agent_search_tool_names()),
        ] {
            let allowed: std::collections::HashSet<String> =
                names.iter().map(|name| (*name).to_string()).collect();
            for tool in crate::tools::served_tools_list(Some(&allowed), true).tools {
                let defined: std::collections::HashSet<&str> = tool.input_schema["properties"]
                    .as_object()
                    .map(|properties| properties.keys().map(String::as_str).collect())
                    .unwrap_or_default();
                for (required, from_branch) in required_property_names(&tool.input_schema) {
                    names_read += 1;
                    if from_branch {
                        branch_names_read += 1;
                    }
                    if !defined.contains(required) {
                        missing.push(format!("{profile}/{}: `{required}`", tool.name));
                    }
                }
            }
        }

        assert!(
            missing.is_empty(),
            "these served schemas require a property their own `properties` map does not define, \
             so the profile advertises a way to call the tool it never describes: {missing:?}; add \
             the property to that tool's entry in schema_keep_lists()"
        );
        // Anti-vacuity. A top-level `required` cannot fail this, because
        // `trim_schema` filters that list too, so the sweep is only grading the
        // class while it reads combinator branches. Reading none means the
        // schemas moved out from under it, not that they are clean.
        assert!(
            branch_names_read >= 3,
            "the sweep read {names_read} required names across three profiles and only \
             {branch_names_read} of them from an anyOf/oneOf/allOf branch, which is the only \
             place this defect can live"
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

    /// The session and transaction tools, which are plumbing for writing and
    /// can answer no question about code.
    ///
    /// Written out rather than derived from the difference between the two
    /// belts, for the reason
    /// `agent_query_serves_the_query_half_of_the_agent_belt` gives: a name that
    /// joins the write half should cost somebody a decision here.
    /// `the_lifecycle_set_is_the_write_half_of_the_belt` holds the two in step.
    const LIFECYCLE_TOOLS: [&str; 7] = [
        "kin_session_end",
        "kin_session_heartbeat",
        "kin_session_start",
        "kin_transaction_abort",
        "kin_transaction_begin",
        "kin_transaction_commit",
        "kin_transaction_stage",
    ];

    /// `kin_mutate` is the eighth write tool and is deliberately not lifecycle.
    /// It is the write ACTION rather than the plumbing around one, an agent
    /// asking how to change something should find it, and it names entity
    /// changes on purpose.
    #[test]
    fn the_lifecycle_set_is_the_write_half_of_the_belt() {
        let query: BTreeSet<&str> = crate::tools::agent_query_tool_names()
            .iter()
            .copied()
            .collect();
        let write_half: BTreeSet<&str> = crate::tools::agent_default_tool_names()
            .iter()
            .copied()
            .filter(|name| !query.contains(name) && *name != "kin_mutate")
            .collect();
        assert_eq!(
            write_half,
            LIFECYCLE_TOOLS.into_iter().collect::<BTreeSet<&str>>(),
            "the belt's write half moved; the vocabulary guards below are keyed on it"
        );
    }

    /// Words a locate, reference, context or trace question arrives in.
    ///
    /// A lifecycle description that carries one of these competes with the tool
    /// that answers the question, in a client where the model never sees the
    /// schemas and learns the surface by searching it.
    const QUERY_VOCABULARY: [&str; 24] = [
        "behavior",
        "behaviour",
        "caller",
        "callers",
        "code",
        "context",
        "declaration",
        "depends",
        "entities",
        "entity",
        "find",
        "graph",
        "impact",
        "locate",
        "neighborhood",
        "query",
        "read",
        "reads",
        "reference",
        "references",
        "search",
        "semantic",
        "symbol",
        "trace",
    ];

    /// No lifecycle description may carry the vocabulary of a code question.
    ///
    /// Measured on a third-party client rather than reasoned about. Grok never
    /// sends MCP tool schemas to the model: the model learns a tool by calling
    /// Grok's own `search_tool` with a query, which ranks over tool names and
    /// descriptions. On a pure locate question the ranked top eight came back
    /// holding `kin__kin_transaction_commit` and `kin__kin_session_end`, while
    /// `get_context_pack`, `find_references`, `trace_path` and
    /// `trace_data_flow` did not make the cut. Two of eight slots went to tools
    /// that cannot answer any question, and four that can were never offered.
    ///
    /// The tools stay. A third-party agent's write path is begin, stage, commit,
    /// and deleting the plumbing would take the write path with it. What changes
    /// is that each of them now opens by saying it is plumbing for writing, and
    /// carries no word a code question is phrased in.
    #[test]
    fn no_lifecycle_description_carries_the_vocabulary_of_a_code_question() {
        let descriptions = short_descriptions();
        for tool in LIFECYCLE_TOOLS {
            let description = descriptions
                .get(tool)
                .unwrap_or_else(|| panic!("{tool} has no short description"));
            let words: BTreeSet<String> = tokens(description);
            let carried: Vec<&str> = QUERY_VOCABULARY
                .into_iter()
                .filter(|word| words.contains(*word))
                .collect();
            assert!(
                carried.is_empty(),
                "{tool}'s short description carries query vocabulary {carried:?}, so a ranker \
                 that scores it against a code question will offer it: {description:?}"
            );
            // And the other half of the rule: it has to SAY what it is, or a
            // ranker has nothing to score a write question against.
            assert!(
                words.contains("plumbing") && words.contains("writes"),
                "{tool}'s short description must name itself as plumbing for writes: \
                 {description:?}"
            );
        }
    }

    /// Lowercase alphanumeric words, which is what a lexical ranker sees.
    fn tokens(text: &str) -> BTreeSet<String> {
        text.split(|character: char| !character.is_ascii_alphanumeric())
            .filter(|word| !word.is_empty())
            .map(str::to_ascii_lowercase)
            .collect()
    }

    /// Words that carry no information about WHICH tool answers a question.
    ///
    /// `kin` is here with the grammar. Every tool on this server is a Kin tool,
    /// so the term separates none of them from each other, and half the
    /// registered names happen to carry it as a prefix while the retrieval tools
    /// do not. Leaving it in would score `kin_session_end` above
    /// `semantic_locate` on the word "kin" alone, which is a fact about the
    /// naming convention rather than about either tool.
    const RANKING_STOPWORDS: [&str; 48] = [
        "a", "about", "after", "all", "an", "and", "are", "as", "at", "be", "before", "by", "can",
        "do", "does", "every", "for", "from", "has", "have", "i", "if", "in", "into", "is", "it",
        "its", "kin", "me", "my", "not", "of", "on", "one", "onto", "or", "out", "so", "that",
        "the", "this", "to", "up", "was", "what", "which", "will", "with",
    ];

    /// How many distinct terms of `question` a tool's name and description
    /// carry, which is the signal a lexical ranker orders candidates by.
    ///
    /// A four-character shared prefix counts as a match, so "references" scores
    /// against "reference" and "entities" against "entity". A real ranker stems
    /// or embeds; this is the crudest form of the same idea, and it is enough to
    /// hold the property that matters.
    fn overlap(question: &str, name: &str, description: &str) -> usize {
        let stop: BTreeSet<&str> = RANKING_STOPWORDS.into_iter().collect();
        let surface = tokens(&format!("{name} {description}"));
        tokens(question)
            .iter()
            .filter(|term| !stop.contains(term.as_str()))
            .filter(|term| {
                surface.iter().any(|token| {
                    token == *term
                        || (term.len() >= 4
                            && token.len() >= 4
                            && (token.starts_with(term.as_str())
                                || term.starts_with(token.as_str())))
                })
            })
            .count()
    }

    /// A code question must never rank a lifecycle tool over the tool that
    /// answers it, and a write question must still reach the lifecycle tools.
    ///
    /// This is the regression guard for the ranked-discovery defect. It models a
    /// lexical ranker over the served name and description, which is what a
    /// client that hides schemas gives a model to choose from. The control at
    /// the end is what stops the guard being satisfied by emptying the seven
    /// descriptions out.
    #[test]
    fn a_code_question_never_ranks_a_lifecycle_tool_over_the_tool_that_answers_it() {
        let descriptions = short_descriptions();
        let score = |question: &str, tool: &str| -> usize {
            overlap(
                question,
                tool,
                descriptions
                    .get(tool)
                    .unwrap_or_else(|| panic!("{tool} has no short description")),
            )
        };

        // The first probe is the query the Grok run actually sent.
        let code_questions: [(&str, &[&str]); 6] = [
            (
                "kin semantic locate function behavior exit code",
                &["semantic_locate"],
            ),
            (
                "find every caller and reference of this function",
                &["find_references"],
            ),
            (
                "give me the context around this entity before I change it",
                &["get_context_pack"],
            ),
            (
                "trace the data flow from this function through the call chain",
                &["trace_data_flow"],
            ),
            (
                "what breaks if I change this entity and what does it affect",
                &["impact_analysis"],
            ),
            (
                "how does one function reach another through the code",
                &["trace_path"],
            ),
        ];

        for (question, answering) in code_questions {
            let noise = LIFECYCLE_TOOLS
                .into_iter()
                .map(|tool| (tool, score(question, tool)))
                .max_by_key(|(_, points)| *points)
                .expect("the lifecycle set is not empty");
            assert_eq!(
                noise.1, 0,
                "{:?} scores {} on the code question {question:?}, so a ranker can offer it \
                 in place of a tool that answers: {:?}",
                noise.0, noise.1, descriptions[noise.0]
            );
            for tool in answering {
                let points = score(question, tool);
                assert!(
                    points > noise.1,
                    "{tool} scores {points} on {question:?} against {} for {:?}, so the tool \
                     that answers the question is not the one a ranker offers",
                    noise.1,
                    noise.0
                );
            }
        }

        // The control. A write question has to reach the plumbing, or the guard
        // above would pass on seven blank strings.
        let write_questions: [(&str, &str); 3] = [
            ("commit the staged transaction", "kin_transaction_commit"),
            ("open a session before writing", "kin_session_start"),
            (
                "stage an update onto the open transaction",
                "kin_transaction_stage",
            ),
        ];
        let query_tools: Vec<&str> = crate::tools::agent_query_tool_names().to_vec();
        for (question, answering) in write_questions {
            let points = score(question, answering);
            let best_query = query_tools
                .iter()
                .map(|tool| (*tool, score(question, tool)))
                .max_by_key(|(_, points)| *points)
                .expect("the query profile is not empty");
            assert!(
                points > best_query.1,
                "{answering} scores {points} on the write question {question:?} against {} for \
                 {:?}, so the write path is not what a ranker offers",
                best_query.1,
                best_query.0
            );
        }
    }

    /// The one string a client is guaranteed to hand the model names tools the
    /// model can actually reach, and stays inside its budget.
    ///
    /// The server `instructions` are separate from the profile, and a client may
    /// deliver one without the other. Grok delivers exactly this string and
    /// never the schemas: the model sees it as a synthetic reminder on turn one
    /// and has to search by name for anything else. So a name in here that the
    /// served profile does not carry sends a model looking for a tool that is
    /// not there, which is the same wasted round trip the ranked-discovery
    /// defect above cost, arriving through a different door.
    #[test]
    fn the_server_instructions_name_only_tools_the_profile_serves() {
        // The byte budget is a compile-time assertion beside the string
        // itself, so it is not restated here. This test is about what the
        // bytes SAY.
        let instructions = crate::server::SERVER_INSTRUCTIONS;

        // The tools it must name. A model that never reads a schema learns the
        // surface from these names, so the query half has to be in here.
        let named = [
            "semantic_locate",
            "semantic_search",
            "get_context_pack",
            "find_references",
            "trace_data_flow",
            "trace_path",
            "impact_analysis",
            "list_file_entities",
        ];
        let default: BTreeSet<&str> = crate::tools::agent_default_tool_names()
            .iter()
            .copied()
            .collect();
        let query: BTreeSet<&str> = crate::tools::agent_query_tool_names()
            .iter()
            .copied()
            .collect();
        for tool in named {
            assert!(
                instructions.contains(tool),
                "the instructions no longer name {tool}, so a client that hides schemas gives \
                 the model no way to find it"
            );
            assert!(
                default.contains(tool) && query.contains(tool),
                "the instructions name {tool}, which agent-default or agent-query does not \
                 serve"
            );
        }

        // No lifecycle tool is named. The write path is reachable through the
        // served list and through tool search; spending this budget on plumbing
        // is what the ranked-discovery defect cost in the first place.
        for tool in LIFECYCLE_TOOLS {
            assert!(
                !instructions.contains(tool),
                "the instructions name {tool}, which answers no question and costs the budget \
                 a query tool's line needs"
            );
        }

        // The one instruction that only matters in a client that hides the
        // schemas, and the one every measured run needed and did not get.
        assert!(
            instructions.contains("search for \"kin\" first, before your first file read"),
            "the instructions must tell a model whose client lists tools by search to search \
             for this server before it reads a file: {instructions:?}"
        );
        // And the envelope sentence a reader has to act on survives the cut.
        assert!(
            instructions.contains("_kin.verdict") && instructions.contains("inconclusive"),
            "the verdict contract keeps its one sentence: {instructions:?}"
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
    /// An override may hide a property. It may never invent one, and it may
    /// never require one the registered schema does not.
    ///
    /// The whole bargain of this module is that trimming hides rather than
    /// removes: the handler still reads every registered argument by name and
    /// `full` still advertises them. A replacement schema is the one place that
    /// bargain could be broken quietly, by advertising a knob the server does not
    /// take, so a caller sends it and it is ignored, or by requiring a field the
    /// handler never asks for, so a valid call is refused before it is sent.
    #[test]
    fn every_schema_override_names_only_registered_properties() {
        let registered = crate::tools::tool_definitions();
        for (name, schema) in belt_schema_overrides() {
            let tool = registered
                .tools
                .iter()
                .find(|tool| tool.name == name)
                .unwrap_or_else(|| {
                    panic!(
                        "belt_schema_overrides() in crates/kin-mcp/src/agent_belt.rs names \
                         '{name}', which tool_definitions() does not register"
                    )
                });
            let declared = tool.input_schema["properties"]
                .as_object()
                .unwrap_or_else(|| panic!("{name} has no properties object"));
            let served = schema["properties"]
                .as_object()
                .unwrap_or_else(|| panic!("the {name} override has no properties object"));
            for property in served.keys() {
                assert!(
                    declared.contains_key(property),
                    "the {name} override advertises '{property}', which the registered schema \
                     does not declare, so a caller would send a knob the handler never reads"
                );
            }
            let required = |value: &serde_json::Value| -> Vec<String> {
                value
                    .get("required")
                    .and_then(|value| value.as_array())
                    .map(|names| {
                        names
                            .iter()
                            .filter_map(|name| name.as_str().map(str::to_string))
                            .collect()
                    })
                    .unwrap_or_default()
            };
            let declared_required = required(&tool.input_schema);
            for property in required(&schema) {
                assert!(
                    declared_required.contains(&property),
                    "the {name} override requires '{property}', which the registered schema does \
                     not, so a call the server would accept is refused before it is sent"
                );
                assert!(
                    served.contains_key(&property),
                    "the {name} override requires '{property}' but does not describe it"
                );
            }
            // The control: the override must be much smaller than the schema it
            // replaces, or it is a rewrite that saved nothing and this whole
            // mechanism is cost with no benefit.
            let before = serde_json::to_string(&tool.input_schema)
                .expect("json")
                .len();
            let after = serde_json::to_string(&schema).expect("json").len();
            assert!(
                after * 3 < before,
                "the {name} override is {after} bytes against the registered {before}; an \
                 override that does not cut the schema by much is not worth the divergence"
            );
        }
    }

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
