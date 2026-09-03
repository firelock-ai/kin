// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Plain-language search over Kin's own tool registry.
//!
//! Every tool a profile serves rides in the model's prompt on every turn,
//! because native tool calling re-sends the whole `tools` array. So the served
//! list is a per-turn tax and the registry is far larger than any agent needs at
//! once: 67 tools on `full`, the 66 that preceded this one measured at 142,850
//! bytes, against 13,725 over 14 tools on `agent-query` and 5,976 over the five
//! this tool's own profile serves. Measured across 40 real agentic runs on
//! 2026-09-03, three tools took 96 of the 103 calls made, and nine of
//! `agent-query`'s fourteen were offered and never called once.
//!
//! The answer is not to drop those tools. It is to stop carrying them and to
//! make them findable, which is what this is. A profile serves a small always-on
//! set plus this tool; everything else is reached by describing the job.
//!
//! ## Three properties, and why each one is load-bearing
//!
//! **It reads the registry, never a copy.** [`crate::tools::tool_definitions`]
//! is the same function `tools/list` is built from, so this cannot become a
//! second home where a description drifts. A hand-kept index of tool summaries
//! would be exactly that, and it would go stale the first time a description
//! moved without anyone noticing.
//!
//! **What it returns is callable.** A match is the whole [`ToolDefinition`] as
//! the `full` profile serves it: name, description, annotations and input
//! schema, with nothing trimmed. A search that returned a summary would make an
//! agent guess the arguments, which is how a found tool becomes a failed call.
//! The registered form is deliberate rather than the belt's short form: the
//! short form exists to make a list cheap to carry, and a tool you looked up is
//! one you are about to call.
//!
//! **A match it had no room for is reported, never dropped.** `matched_names`
//! carries every match in rank order and `matches` carries the full definitions
//! for the first `limit` of them, so a narrow `limit` is visible in the answer
//! rather than silent. This tool bounds itself for that reason: it is not in
//! [`crate::budget`]'s shape table, because a budget that shed a schema would
//! hand back a definition that is not the one `full` serves, and fidelity is the
//! property the whole design rests on.
//!
//! It is deliberately absent from [`crate::negative`]'s spec table. An empty
//! match list here is an absence claim about a complete in-memory registry,
//! which is authoritative by construction; synthesizing the graph-flavoured
//! qualifier a retrieval tool gets would report embedding coverage as the reason
//! no tool matched a phrase.
//!
//! ## Why it answers locally on both routes
//!
//! The daemon route forwards unknown tool names to the daemon's generic MCP
//! endpoint. This one is answered in-process on both routes instead, because the
//! answer is the registry compiled into THIS binary. A daemon on a different
//! build would answer with its own registry, and an agent would be handed a
//! schema for a tool this server cannot dispatch.

use std::collections::HashMap;

use crate::error::{McpError, Result};
use crate::types::{ToolCallResult, ToolDefinition};

/// The tool's registered name, spelled once so the registry, the dispatcher,
/// the profile lists and the cross-reference note cannot drift from each other.
pub const TOOL_NAME: &str = "kin_tool_search";

/// Full definitions returned when the caller names no `limit`.
///
/// Five, because a definition is 1,000 to 2,100 bytes and an agent that asked
/// one question wants the tool for it, not a catalogue. Every further match is
/// still named under `matched_names`, so the ceiling costs recall of schemas
/// rather than recall of tools.
const DEFAULT_LIMIT: u64 = 5;

/// The most full definitions one call will return.
///
/// Above this the answer stops being a lookup and becomes the list this tool
/// exists to stop carrying.
const MAX_LIMIT: u64 = 25;

/// Terms carried by nearly every plain-language need, which match nothing
/// useful and would rank on description prose alone.
///
/// Short and deliberately incomplete. A stop list long enough to be clever is a
/// second ranking model nobody can read; this one removes the words that appear
/// in most tool descriptions in this crate.
const STOP_TERMS: &[&str] = &[
    "a", "an", "and", "any", "are", "as", "at", "be", "but", "by", "can", "do", "does", "for",
    "from", "get", "has", "have", "how", "i", "if", "in", "into", "is", "it", "its", "me", "my",
    "of", "on", "or", "out", "shows", "that", "the", "their", "them", "then", "there", "these",
    "they", "this", "to", "up", "was", "what", "when", "where", "which", "who", "will", "with",
    "you", "your",
];

pub const TOOL_SEARCH_DESC: &str = "\
Find the Kin tools this server registers but your profile does not serve, by describing what you \
need in plain language. Kin registers far more tools than any agent profile serves: a profile is a \
small always-on set, chosen so the list you carry on every turn stays cheap, and everything else is \
reached through here. Give `need` a plain-language description of the job (\"what breaks if I \
change this\", \"who calls this function\", \"read one file's exact bytes\") and each match comes \
back as the complete tool definition -- name, description, annotations and input schema -- exactly \
as the `full` profile serves it, so a tool you find is callable on your next turn with nothing \
withheld. `matched_names` lists every match in rank order and `matches` carries the full \
definitions for the first `limit` of them, so a match this call had no room for is reported rather \
than dropped. Omit `need` to enumerate the whole registry. Ranking reads tool names first, then \
titles, then descriptions, and an exact tool name always comes back first. This answers from the \
registry compiled into this server, so what it returns is what this server would serve.";

/// One tool's score against one need, and the definition it scored for.
struct Ranked<'a> {
    definition: &'a ToolDefinition,
    score: u64,
}

/// Split a need into the lowercase terms the ranking scores on.
///
/// A term is a run of `[a-z0-9_]` after lowercasing, which is what an MCP tool
/// name is spelled from, so a caller who types a tool name gets one term rather
/// than two halves of one. Single characters and stop terms are dropped.
fn terms(need: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for raw in need
        .to_ascii_lowercase()
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
    {
        if raw.len() < 2 || STOP_TERMS.contains(&raw) {
            continue;
        }
        let term = raw.to_string();
        if !out.contains(&term) {
            out.push(term);
        }
    }
    out
}

/// Whether `text` contains `term` bounded by non-word characters.
///
/// The same word rule [`crate::tools::unserved_tools_named_in`] uses, for the
/// same reason: `get_entity` inside `get_entity_source` is not a mention of
/// `get_entity`, and a plain `contains` would rank a tool for a name it does not
/// carry.
fn names_as_word(text: &str, term: &str) -> bool {
    let is_word = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    let bytes = text.as_bytes();
    let mut from = 0;
    while let Some(offset) = text[from..].find(term) {
        let start = from + offset;
        let end = start + term.len();
        let before_ok = start == 0 || !is_word(bytes[start - 1]);
        let after_ok = end == bytes.len() || !is_word(bytes[end]);
        if before_ok && after_ok {
            return true;
        }
        from = start + 1;
    }
    false
}

/// What one term is worth against one tool.
///
/// Best hit only, so a term repeated through a long description cannot outrank a
/// term in a name. The weights are ordered by how much the field says about what
/// the tool IS: a name is chosen, a title is written for a picker, and a
/// description is prose that mentions neighbours.
fn term_score(definition: &ToolDefinition, term: &str) -> u64 {
    let name = definition.name.to_ascii_lowercase();
    if name.split('_').any(|segment| segment == term) {
        return 60;
    }
    if name.contains(term) {
        return 30;
    }
    let title = definition.annotations.title.to_ascii_lowercase();
    if names_as_word(&title, term) {
        return 12;
    }
    let description = definition.description.to_ascii_lowercase();
    if names_as_word(&description, term) {
        return 6;
    }
    if description.contains(term) {
        return 3;
    }
    0
}

/// Rank every registered tool against one need, best first.
///
/// An empty need matches everything in name order, which is the registry
/// inventory and the cheapest way to ask what exists at all. A need that is
/// exactly a registered tool name puts that tool first whatever else it scores,
/// so a caller who already knows the name never has to out-rank prose for it.
/// Ties break on name, so the order is stable across builds and a client's
/// cached prompt is not invalidated by a reordering nobody asked for.
fn rank<'a>(definitions: &'a [ToolDefinition], need: &str) -> Vec<Ranked<'a>> {
    let exact = need.trim().to_ascii_lowercase();
    let terms = terms(need);
    let mut ranked: Vec<Ranked<'a>> = definitions
        .iter()
        .filter_map(|definition| {
            let mut score: u64 = terms.iter().map(|term| term_score(definition, term)).sum();
            if definition.name.eq_ignore_ascii_case(&exact) {
                score += 10_000;
            }
            if terms.is_empty() && exact.is_empty() {
                score = 1;
            }
            (score > 0).then_some(Ranked { definition, score })
        })
        .collect();
    ranked.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| left.definition.name.cmp(&right.definition.name))
    });
    ranked
}

/// Read `limit`, clamped to what one response will carry.
fn limit_from(args: &HashMap<String, serde_json::Value>) -> Result<u64> {
    let Some(value) = args.get("limit") else {
        return Ok(DEFAULT_LIMIT);
    };
    if value.is_null() {
        return Ok(DEFAULT_LIMIT);
    }
    let raw = value.as_u64().ok_or_else(|| {
        McpError::InvalidParams(format!(
            "{TOOL_NAME}: `limit` must be a positive integer, got {value}"
        ))
    })?;
    Ok(raw.clamp(1, MAX_LIMIT))
}

/// Answer one tool search from the registry this binary compiled.
pub fn handle_tool_search(args: &HashMap<String, serde_json::Value>) -> Result<ToolCallResult> {
    let need = match args.get("need") {
        None => String::new(),
        Some(value) if value.is_null() => String::new(),
        Some(serde_json::Value::String(text)) => text.clone(),
        Some(other) => {
            return Err(McpError::InvalidParams(format!(
                "{TOOL_NAME}: `need` must be a string, got {other}"
            )))
        }
    };
    let limit = limit_from(args)? as usize;

    let registry = crate::tools::tool_definitions();
    let ranked = rank(&registry.tools, &need);
    let matched_names: Vec<&str> = ranked
        .iter()
        .map(|hit| hit.definition.name.as_str())
        .collect();
    let matches: Vec<&ToolDefinition> = ranked
        .iter()
        .take(limit)
        .map(|hit| hit.definition)
        .collect();
    let withheld = matched_names.len().saturating_sub(matches.len());

    let payload = serde_json::json!({
        "need": need,
        // The full definitions, exactly as `full` serves them. Serialized from
        // the same structs `tools/list` serializes, which is what makes the
        // fidelity assertion a property of the code rather than of a habit.
        "matches": matches,
        // Every match, so a `limit` that cut the list cut schemas and never
        // tools. An agent reading only `matches` still learns the count it did
        // not see from `matches_withheld`.
        "matched_names": matched_names,
        "matches_withheld": withheld,
        "registry": {
            "tools": registry.tools.len(),
            "source": "the tool registry compiled into this server",
        },
    });
    let json = serde_json::to_string_pretty(&payload).map_err(McpError::Json)?;
    Ok(ToolCallResult::text(json))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::tool_definitions;

    fn call(args: serde_json::Value) -> serde_json::Value {
        let map: HashMap<String, serde_json::Value> = args
            .as_object()
            .expect("arguments are an object")
            .iter()
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        let result = handle_tool_search(&map).expect("the search answers");
        let crate::types::ContentBlock::Text { text } = &result.content[0];
        serde_json::from_str(text).expect("the payload is JSON")
    }

    /// Reachability and fidelity together, over the whole registry.
    ///
    /// This is the assertion the design creates the need for: a tool that
    /// becomes unfindable is the new silent failure, and a schema that drifts
    /// from what `full` serves turns a found tool into a failed call. Both are
    /// checked here for EVERY registered tool rather than for a sample, because
    /// a sample would pass while one tool fell out of the index.
    ///
    /// The fidelity half compares serialized bytes through the same serializer
    /// `tools/list` uses, so it is byte-for-byte in the literal sense rather
    /// than a structural comparison that could accept a re-encoded schema.
    #[test]
    fn every_registered_tool_is_findable_by_name_with_the_schema_full_serves() {
        let registry = tool_definitions();
        assert!(
            registry.tools.len() > 40,
            "the registry is unexpectedly small, so this sweep proves little"
        );
        for tool in &registry.tools {
            let payload = call(serde_json::json!({ "need": tool.name }));
            let names: Vec<String> =
                serde_json::from_value(payload["matched_names"].clone()).expect("names");
            assert_eq!(
                names.first().map(String::as_str),
                Some(tool.name.as_str()),
                "{} is not the first match for its own name: {names:?}",
                tool.name
            );

            let served = serde_json::to_string(tool).expect("the registered form serializes");
            let found = payload["matches"]
                .as_array()
                .expect("matches is an array")
                .iter()
                .find(|entry| entry["name"] == serde_json::json!(tool.name))
                .unwrap_or_else(|| panic!("{} was named but not returned", tool.name));
            let round_trip: ToolDefinition =
                serde_json::from_value(found.clone()).expect("the match is a tool definition");
            assert_eq!(
                serde_json::to_string(&round_trip).expect("the found form serializes"),
                served,
                "{} came back with a schema the full profile does not serve",
                tool.name
            );
        }
    }

    /// The control for the sweep above: a name nothing registers finds nothing,
    /// and the answer says so rather than falling back to a ranking.
    #[test]
    fn a_need_that_matches_nothing_returns_an_empty_list_and_says_the_registry_size() {
        let payload = call(serde_json::json!({ "need": "zzz_fab_tool" }));
        assert_eq!(payload["matched_names"], serde_json::json!([]));
        assert_eq!(payload["matches"], serde_json::json!([]));
        assert_eq!(payload["matches_withheld"], serde_json::json!(0));
        assert_eq!(
            payload["registry"]["tools"],
            serde_json::json!(tool_definitions().tools.len()),
            "an empty answer still has to say how large the registry it searched was"
        );
    }

    /// An omitted need enumerates the whole registry, which is the inventory
    /// call, and the schemas it could not carry are counted rather than dropped.
    #[test]
    fn the_empty_need_enumerates_the_whole_registry_and_counts_what_it_withheld() {
        let registry = tool_definitions();
        let payload = call(serde_json::json!({}));
        let names: Vec<String> =
            serde_json::from_value(payload["matched_names"].clone()).expect("names");
        let mut registered: Vec<String> = registry
            .tools
            .iter()
            .map(|tool| tool.name.clone())
            .collect();
        registered.sort();
        let mut found = names.clone();
        found.sort();
        assert_eq!(found, registered, "the inventory is the whole registry");
        assert_eq!(
            payload["matches"].as_array().expect("matches").len(),
            DEFAULT_LIMIT as usize
        );
        assert_eq!(
            payload["matches_withheld"],
            serde_json::json!(registry.tools.len() - DEFAULT_LIMIT as usize),
            "a bounded answer has to report what it did not carry"
        );
    }

    /// Ranking reads the name before the prose. `references` is a segment of two
    /// tool names and appears in the descriptions of ten more, so every tool
    /// carrying it in its NAME has to rank above every tool that only mentions
    /// it.
    ///
    /// Stated as that property rather than as one expected first row, which is
    /// what the first version of this test asserted and what the ranking does
    /// not promise: `bulk_check_references` and `find_references` both carry the
    /// term as a name segment and score identically, so which of the two leads
    /// is decided by the alphabetical tie-break that keeps the order stable
    /// across builds.
    #[test]
    fn a_name_hit_outranks_a_description_hit() {
        let payload = call(serde_json::json!({ "need": "references", "limit": 25 }));
        let names: Vec<String> =
            serde_json::from_value(payload["matched_names"].clone()).expect("names");
        let in_name: Vec<bool> = names
            .iter()
            .map(|name| name.contains("references"))
            .collect();

        // Both controls. Without a name hit the assertion is vacuous, and
        // without a prose hit there is nothing for a name hit to outrank.
        assert!(
            in_name.iter().any(|hit| *hit),
            "no tool matched by name, so this proves nothing about ordering: {names:?}"
        );
        assert!(
            in_name.iter().any(|hit| !*hit),
            "no tool matched by prose, so this proves nothing about ordering: {names:?}"
        );

        let last_name_hit = in_name.iter().rposition(|hit| *hit).expect("a name hit");
        let first_prose_hit = in_name.iter().position(|hit| !*hit).expect("a prose hit");
        assert!(
            last_name_hit < first_prose_hit,
            "a tool that only mentions the term outranks one that carries it in its name: \
             {names:?}"
        );
    }

    /// A plain-language need with no tool name in it still lands on the tool for
    /// the job, through the description. Without this the search is a name
    /// lookup wearing a search's description.
    #[test]
    fn a_plain_language_need_reaches_a_tool_it_never_names() {
        let payload = call(serde_json::json!({
            "need": "what breaks if I change this entity",
            "limit": 25
        }));
        let names: Vec<String> =
            serde_json::from_value(payload["matched_names"].clone()).expect("names");
        assert!(
            names.iter().any(|name| name == "impact_analysis"),
            "the change-impact tool was not reachable from the question it answers: {names:?}"
        );
    }

    /// The search returns the registered form even where the belt serves a short
    /// one. A tool an agent just looked up is a tool it is about to call, and the
    /// short form exists to make a carried list cheap rather than to be the
    /// contract.
    #[test]
    fn the_search_returns_the_registered_form_not_the_belt_short_form() {
        let payload = call(serde_json::json!({ "need": "semantic_locate" }));
        let found = payload["matches"][0]["description"]
            .as_str()
            .expect("a description")
            .to_string();
        let registered = tool_definitions()
            .tools
            .iter()
            .find(|tool| tool.name == "semantic_locate")
            .expect("semantic_locate is registered")
            .description
            .clone();
        assert_eq!(found, registered);
        let mut belt = crate::tools::served_tools_list(
            Some(&crate::tools::name_set(&["semantic_locate"])),
            true,
        );
        let short = belt.tools.remove(0).description;
        assert_ne!(
            short, registered,
            "the belt no longer shortens this description, so the test above compares two \
             identical strings and would pass on a search that served the short form"
        );
    }

    #[test]
    fn the_limit_is_clamped_rather_than_obeyed_without_bound() {
        let payload = call(serde_json::json!({ "need": "", "limit": 10_000 }));
        assert_eq!(
            payload["matches"].as_array().expect("matches").len(),
            MAX_LIMIT as usize
        );
        let one = call(serde_json::json!({ "need": "", "limit": 0 }));
        assert_eq!(one["matches"].as_array().expect("matches").len(), 1);
    }

    #[test]
    fn a_need_of_the_wrong_type_is_refused_rather_than_read_as_empty() {
        let mut args: HashMap<String, serde_json::Value> = HashMap::new();
        args.insert("need".into(), serde_json::json!(7));
        assert!(
            handle_tool_search(&args).is_err(),
            "a numeric need read as the empty inventory would answer a question nobody asked"
        );
    }
}
