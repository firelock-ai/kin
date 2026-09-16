// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The guard that stops a run re-asking a question the graph has already
//! answered.
//!
//! An agent with no shell and no grep has one route to an answer, and when the
//! graph does not hold what it wants there is nothing to fall back to. What it
//! does instead is rephrase. Measured on 2026-09-15, `qwen/qwen3-coder-next`
//! asked `semantic_locate` nine variations of "the gh api command's http
//! request", spent 81,806 of the run's 130,937 tool-result bytes on them, hit
//! the context budget at 59,029 tokens and answered with a guess. The hop it
//! wanted was never in any of the nine answers.
//!
//! This module is the part of the loop that notices. It holds three instruments,
//! and they catch different things:
//!
//! - The repeat rule is precise. It fires when a tool is asked a near-identical
//!   question after that question has already come back with nothing the run had
//!   not seen.
//! - The call budget is blunt. It bounds how many times one retrieval tool may
//!   run at all, whatever it is asked, because a model that rephrases widely
//!   enough never trips the precise rule and still spends the window.
//! - The refusal rule reads a refusal as a result. A change refused twice on the
//!   same target has been told twice that the bytes it sent are not the file's,
//!   and the third attempt is the loop. Measured on 2026-09-15,
//!   `qwen/qwen3-coder-next` took one byte-match refusal on T4 and spent its
//!   remaining sixteen tool calls on graph questions, producing a zero-byte diff
//!   on the task the same model had passed in seven calls a run earlier.
//!
//! Each of them escalates rather than refusing outright, and they share one
//! escalation count: the first two trips tell the model what to do instead, and
//! only a model that keeps going after that ends the run. A run that ends here
//! ends with an answer, because the loop asks for one with the tools taken away,
//! and the stop record names the tool, the question and the gap.
//!
//! Nothing here reads a file, and nothing here decides an answer is wrong. The
//! guard's whole claim is about repetition, and a repeated question that is
//! still producing new entities is left alone, as is a change that keeps landing.

use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

/// How many times a question that has already come back barren may be re-asked
/// before the guard stops running it.
///
/// Two. The first re-ask is how a model checks whether it phrased the question
/// badly, which is a reasonable thing to do once; the second is the last one
/// that can be called a check. A third is the loop.
pub const REPEAT_ALLOWANCE: u32 = 2;

/// How many times one target may be refused before the guard stops the next
/// attempt at it.
///
/// Two, for the same reason the repeat rule allows two. The first refusal is the
/// one the model reads and corrects from, and the corrected call now carries the
/// file's exact bytes, so a second refusal on the same target means the model is
/// not using them. A third would be sent for the same reason the second was.
pub const REFUSAL_ALLOWANCE: u32 = 2;

/// How many escalations a run gets before the guard ends it.
///
/// The first two are directions: do not run this, run that instead. A model that
/// trips the guard a third time has been told twice and is still circling, and
/// the cheapest true thing it can do is say what it could not determine.
pub const ESCALATION_ALLOWANCE: u32 = 2;

/// How alike two questions must be to count as the same one.
///
/// Containment rather than overlap: the share of the SHORTER question's words
/// that appear in the other. A rephrasing is usually the same question with a
/// word added or dropped, and overlap punishes the added word twice while
/// containment reads it as what it is. 0.8 was chosen against the nine measured
/// locate queries, where it groups "gh api command http client request" with
/// "api command http request client" and with "api command implementation http
/// request", and does not group either with "api command cobra command line
/// interface", which is a different question about the same subject.
pub const NEAR_IDENTICAL: f64 = 0.8;

/// The smallest shared vocabulary that can decide anything.
///
/// Two questions sharing one word are not the same question, whatever the ratio
/// says, and a one-word query against a one-word query would otherwise be a
/// perfect match with nothing behind it.
const MIN_SHARED_WORDS: usize = 2;

/// How many times one tool may run in a single run on the default belt.
///
/// `semantic_locate` is the tool the measurement caught running away, and four
/// is the number of separate things a twenty-call run can reasonably need to
/// find before it should be walking edges instead of ranking again. On the
/// measured run the fifth locate onward returned another page of the same
/// neighbourhood and the answer was in none of them.
///
/// `semantic_search` is here because it is the same shape of call against the
/// same index, and a budget that bounded only one of the two would be a budget a
/// model steps around by switching tools. It did not run away on the measured
/// run, which is the honest reason it carries the same number rather than a
/// measured one of its own.
///
/// Every other tool is unbounded here. The run's own tool-call budget is what
/// bounds those, and a bound invented without a measurement behind it is a
/// number that will be wrong in a way nobody can argue with.
pub fn call_budget(tool: &str) -> Option<u32> {
    match tool {
        "semantic_locate" | "semantic_search" => Some(4),
        _ => None,
    }
}

/// The tools whose answers are a set of entities, so "nothing new" means
/// something about them.
///
/// The barren rule reads a result for entity ids and file paths. On a tool that
/// returns neither, such as `kin_graph_status`, an empty reading says nothing
/// about the answer's worth, so those tools are never marked barren and never
/// trip the repeat rule.
fn returns_entities(tool: &str) -> bool {
    matches!(
        tool,
        "semantic_locate"
            | "semantic_search"
            | "find_references"
            | "trace_data_flow"
            | "trace_path"
            | "graph_neighborhood"
            | "impact_analysis"
            | "list_file_entities"
            | "get_context_pack"
    )
}

/// Argument names that change how an answer is SHAPED rather than which
/// entities it holds.
///
/// Left out of a question's identity, so re-asking the same question with a
/// bigger depth or a smaller ceiling is the same question.
const SHAPING_ARGUMENTS: [&str; 15] = [
    "limit",
    "max_chars",
    "max_response_chars",
    "page_size",
    "token_budget",
    "include_body",
    "compact",
    "explain",
    "snippet_alias",
    "pipeline",
    "offset",
    "session_id",
    "request_id",
    "depth",
    "max_depth",
];

/// Words carrying no subject, dropped before two questions are compared.
const STOPWORDS: [&str; 22] = [
    "a", "an", "and", "are", "by", "does", "for", "from", "how", "in", "is", "it", "its", "of",
    "on", "or", "that", "the", "this", "to", "what", "with",
];

/// What the guard says about a call the model is about to make.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Run it.
    Allow,
    /// Do not run it. Give the model this text instead and let it keep working.
    Redirect(String),
    /// Do not run it, and end the run with what it has. The text is the stop
    /// detail, written so a reader knows which question ran away.
    Exhausted(String),
}

/// The argument that names which page of an answer is wanted.
///
/// Held apart from every other argument, and this is the reason: the word
/// measure below compares the SHORTER question's words against the longer, so a
/// question with a page token added is fully contained in the one without it and
/// reads as identical. Asking for the next page is the one re-ask that is always
/// progress, and a rule that cannot see it would block paging outright. Two
/// questions asking for different pages are different questions, whatever their
/// words say.
const PAGE_ARGUMENT: &str = "cursor";

/// One question, as the guard compares questions.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct Question {
    /// The words of every argument that chooses which entities come back.
    words: BTreeSet<String>,
    /// The page token this call asked for, when it named one.
    page: Option<String>,
}

/// The words of a text, lowercased, with punctuation and stopwords gone.
fn words(text: &str) -> BTreeSet<String> {
    text.split(|character: char| !character.is_alphanumeric())
        .filter(|word| !word.is_empty())
        .map(|word| word.to_ascii_lowercase())
        .filter(|word| !STOPWORDS.contains(&word.as_str()))
        .collect()
}

/// Every word in the arguments that chooses WHICH entities come back.
///
/// Walks the whole argument value rather than a fixed list of keys, because the
/// keys differ per tool and a selector this did not know about would silently
/// leave two different questions looking identical.
fn question(arguments: &Value) -> Question {
    let mut words = BTreeSet::new();
    collect_words(arguments, &mut words);
    let page = arguments
        .get(PAGE_ARGUMENT)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .map(str::to_string);
    Question { words, page }
}

fn collect_words(value: &Value, into: &mut BTreeSet<String>) {
    match value {
        Value::String(text) => into.extend(words(text)),
        Value::Number(number) => {
            into.insert(number.to_string());
        }
        Value::Bool(flag) => {
            into.insert(flag.to_string());
        }
        Value::Array(items) => {
            for item in items {
                collect_words(item, into);
            }
        }
        Value::Object(fields) => {
            for (name, field) in fields {
                if SHAPING_ARGUMENTS.contains(&name.as_str()) || name == PAGE_ARGUMENT {
                    continue;
                }
                collect_words(field, into);
            }
        }
        Value::Null => {}
    }
}

/// How much of the shorter question the longer one contains, 0.0 to 1.0.
///
/// Two questions asking for different pages share nothing, whatever their words
/// hold, because the second is asking for what the first did not return.
fn containment(left: &Question, right: &Question) -> f64 {
    if left.page != right.page {
        return 0.0;
    }
    let shared = left.words.intersection(&right.words).count();
    let shorter = left.words.len().min(right.words.len());
    if shorter == 0 || shared < MIN_SHARED_WORDS {
        return 0.0;
    }
    shared as f64 / shorter as f64
}

/// Whether two questions are near enough to be the same question.
pub fn near_identical(left: &Value, right: &Value) -> bool {
    containment(&question(left), &question(right)) >= NEAR_IDENTICAL
}

/// The identifiers a result surfaced: entity ids and repository paths.
///
/// Read off the parsed JSON under the keys that carry them, so a timestamp or a
/// freshness envelope that differs on every call cannot make an identical answer
/// look new. A result that is not JSON returns `None`, which the guard reads as
/// "cannot tell" and never as "nothing".
fn surfaced(result: &str) -> Option<BTreeSet<String>> {
    const IDENTIFIER_KEYS: [&str; 7] = [
        "id",
        "entity_id",
        "file",
        "path",
        "file_path",
        "artifact_path",
        "target",
    ];
    let parsed: Value = serde_json::from_str(result).ok()?;
    let mut found = BTreeSet::new();
    fn walk(value: &Value, keys: &[&str], into: &mut BTreeSet<String>) {
        match value {
            Value::Object(fields) => {
                for (name, field) in fields {
                    if keys.contains(&name.as_str()) {
                        if let Some(text) = field.as_str() {
                            let text = text.trim();
                            if !text.is_empty() {
                                into.insert(text.to_string());
                            }
                        }
                    }
                    walk(field, keys, into);
                }
            }
            Value::Array(items) => {
                for item in items {
                    walk(item, keys, into);
                }
            }
            _ => {}
        }
    }
    walk(&parsed, &IDENTIFIER_KEYS, &mut found);
    Some(found)
}

/// What the model is told to do instead of attempting the same change again.
///
/// It is told to go and read, not to give up: unlike a barren question, a refused
/// change has a route that works, and the refusal it just read carries the bytes
/// that route needs.
const REFUSAL_ESCALATION: &str = "Read the entity's current source with \
     mcp__kin__get_entity_source, copy its bytes without re-escaping them, and send the change \
     once more with `find` set to exactly those bytes. Or name the change instead of matching \
     bytes: call mcp__kin__kin_mutate with one operation {\"verb\": \"update\", \"target\": \
     \"<the entity id>\", \"body\": \"<its complete new source>\", \"description\": \
     \"...\"}, which needs no old bytes at all.";

/// How a redirect closes.
///
/// A run circling a question it cannot answer should say so. A run that cannot land
/// a change should land it, so the refusal rule closes differently.
const CLOSING_ANSWER: &str =
    "Say plainly what you could not determine and which tool could not answer it.";
const CLOSING_CHANGE: &str = "Do not send this change again until you hold those bytes.";

/// What the model is told to do instead, by the tool it was about to re-run.
fn escalation(tool: &str) -> &'static str {
    match tool {
        "semantic_locate" | "semantic_search" => {
            "Stop ranking and start walking. Take an entity you have already been given and call \
             the trace tool with it as `from`, naming `to` if your question has two ends, or call \
             find_references on it."
        }
        "trace_data_flow" | "trace_path" => {
            "The walk is not reaching it. Call find_references on the entity at the end of the \
             hops you do have, or answer now."
        }
        "list_file_entities" | "get_context_pack" | "graph_neighborhood" | "impact_analysis" => {
            "Walking wider is not finding it. Call the trace tool from an entity you already \
             hold, or answer now."
        }
        _ => "Calling this again will not add anything. Use a different tool, or answer now.",
    }
}

/// One question the guard is watching, and what it has done since.
#[derive(Debug, Clone)]
struct Watched {
    question: Question,
    /// Set once a call in this class came back with nothing the run had not
    /// already been shown. It is never cleared: a question that has once been
    /// answered with ground the run already held has shown what it has, and a
    /// latch that a later differently-ranked page could clear is a latch that
    /// never stops the loop it exists to stop.
    barren: bool,
    /// Calls in this class after it went barren.
    repeats: u32,
}

/// The loop's repeat guard for one run.
#[derive(Debug, Default)]
pub struct RepeatGuard {
    watched: Vec<(String, Watched)>,
    /// Calls made per tool, by the tool's server name.
    calls: BTreeMap<String, u32>,
    /// Identifiers each tool has already handed this run.
    seen: BTreeMap<String, BTreeSet<String>>,
    /// Refusals the model can clear by sending different bytes, per tool and
    /// target. Keyed on the target rather than the bytes sent: a run that sends
    /// three different wrong snippets at one file is the loop this bounds, and a
    /// key that included the bytes would never match twice.
    refusals: BTreeMap<(String, String), u32>,
    escalations: u32,
    /// Every escalation this run made, newest last, for the record.
    reasons: Vec<String>,
}

impl RepeatGuard {
    pub fn new() -> Self {
        Self::default()
    }

    /// Why the guard escalated, in the order it did, for the run record.
    pub fn reasons(&self) -> &[String] {
        &self.reasons
    }

    /// How many times the guard stopped a call this run.
    pub fn escalations(&self) -> u32 {
        self.escalations
    }

    /// Decide whether a call should run, before it is sent.
    ///
    /// `tool` is the name the server knows, so a folded belt tool is judged as
    /// the tool it actually reaches.
    pub fn before(&mut self, tool: &str, arguments: &Value) -> Verdict {
        let asked = question(arguments);
        if let Some(budget) = call_budget(tool) {
            let made = self.calls.get(tool).copied().unwrap_or(0);
            if made >= budget {
                return self.escalate(
                    tool,
                    format!(
                        "{tool} has run {made} times, which is this belt's budget of {budget} for \
                         it"
                    ),
                );
            }
        }
        if let Some(index) = self.barren_match(tool, &asked) {
            let repeats = self.watched[index].1.repeats;
            if repeats >= REPEAT_ALLOWANCE {
                let restated = restate(&self.watched[index].1.question);
                return self.escalate(
                    tool,
                    format!(
                        "{tool} has been asked about {restated} {} times since that question last \
                         returned anything new",
                        repeats + 1
                    ),
                );
            }
            self.watched[index].1.repeats += 1;
        }
        *self.calls.entry(tool.to_string()).or_insert(0) += 1;
        Verdict::Allow
    }

    /// Decide whether another attempt at a change should run, before it is sent.
    ///
    /// `target` is what the change names, which for the belt's replacement tool is the
    /// path. Both are compared as written: this rule is about a run repeating itself,
    /// and two spellings of one path are two different things the model asked for.
    pub fn before_change(&mut self, tool: &str, target: &str) -> Verdict {
        let refused = self
            .refusals
            .get(&(tool.to_string(), target.to_string()))
            .copied()
            .unwrap_or(0);
        if refused >= REFUSAL_ALLOWANCE {
            return self.escalate_with(
                format!(
                    "{tool} has been refused {refused} times on `{target}`, and the last refusal \
                     carried that file's exact current bytes"
                ),
                REFUSAL_ESCALATION,
                CLOSING_CHANGE,
            );
        }
        Verdict::Allow
    }

    /// Record a refusal the model can clear by sending different bytes.
    ///
    /// Only that kind. A change repository authority declined to publish is counted
    /// nowhere here, because re-reading the source is not what fixes one and this rule's
    /// whole redirect is an instruction to go and read.
    pub fn record_refusal(&mut self, tool: &str, target: &str) {
        *self
            .refusals
            .entry((tool.to_string(), target.to_string()))
            .or_insert(0) += 1;
    }

    /// Record what a call that ran came back with.
    pub fn record(&mut self, tool: &str, arguments: &Value, result: &str, is_error: bool) {
        if !returns_entities(tool) {
            return;
        }
        let asked = question(arguments);
        let barren = if is_error {
            // A refused or failed call added nothing, whatever it says.
            true
        } else {
            match surfaced(result) {
                // Not JSON, so the guard cannot read what it held. Never barren:
                // this rule may only fire on evidence it actually has.
                None => false,
                Some(found) => {
                    let seen = self.seen.entry(tool.to_string()).or_default();
                    let fresh = found.difference(seen).count();
                    seen.extend(found);
                    fresh == 0
                }
            }
        };
        match self.match_index(tool, &asked) {
            Some(index) => {
                if barren {
                    self.watched[index].1.barren = true;
                }
            }
            None => self.watched.push((
                tool.to_string(),
                Watched {
                    question: asked,
                    barren,
                    repeats: 0,
                },
            )),
        }
    }

    /// The watched class this question belongs to, barren or not.
    fn match_index(&self, tool: &str, asked: &Question) -> Option<usize> {
        self.watched.iter().position(|(name, watched)| {
            name == tool && containment(&watched.question, asked) >= NEAR_IDENTICAL
        })
    }

    /// The watched class this question belongs to, if that class is barren.
    fn barren_match(&self, tool: &str, asked: &Question) -> Option<usize> {
        self.watched.iter().position(|(name, watched)| {
            name == tool
                && watched.barren
                && containment(&watched.question, asked) >= NEAR_IDENTICAL
        })
    }

    /// Turn a tripped retrieval rule into the verdict the loop acts on.
    fn escalate(&mut self, tool: &str, because: String) -> Verdict {
        self.escalate_with(because, escalation(tool), CLOSING_ANSWER)
    }

    /// Turn any tripped rule into the verdict the loop acts on.
    ///
    /// The escalation count is shared across all three rules on purpose: it counts how
    /// many times this run has been told to change course, and a run that has been told
    /// three times is circling whichever rule noticed.
    fn escalate_with(&mut self, because: String, instead: &str, closing: &str) -> Verdict {
        self.escalations += 1;
        self.reasons.push(because.clone());
        if self.escalations > ESCALATION_ALLOWANCE {
            Verdict::Exhausted(format!(
                "{because}, and the run had already been told twice to do something else"
            ))
        } else {
            Verdict::Redirect(format!(
                "[kin agent] This call was not run: {because}. {instead} {closing}"
            ))
        }
    }
}

/// A question written back as words a reader can match to the transcript.
fn restate(question: &Question) -> String {
    let mut words: Vec<&str> = question.words.iter().map(String::as_str).collect();
    words.truncate(6);
    if words.is_empty() {
        return "the same thing".to_string();
    }
    format!("`{}`", words.join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The nine queries the measured run actually sent, in order.
    fn measured_locate_queries() -> Vec<&'static str> {
        vec![
            "gh api command implementation",
            "api command http request client",
            "gh api command http client request",
            "api command run execute http",
            "api command implementation http request",
            "api command cobra command line interface",
            "Client.Request method http.Client",
            "gh api command cobra root",
            "api command implementation cmd api run",
        ]
    }

    fn ranked(ids: &[&str]) -> String {
        let rows: Vec<Value> = ids.iter().map(|id| json!({ "id": id })).collect();
        json!({ "results": rows }).to_string()
    }

    #[test]
    fn a_rephrasing_of_the_same_question_is_the_same_question() {
        assert!(near_identical(
            &json!({ "query": "gh api command http client request" }),
            &json!({ "query": "api command http request client" }),
        ));
    }

    #[test]
    fn a_different_question_about_the_same_subject_is_not_a_repeat() {
        assert!(!near_identical(
            &json!({ "query": "gh api command http client request" }),
            &json!({ "query": "api command cobra command line interface" }),
        ));
    }

    #[test]
    fn a_bigger_depth_does_not_make_it_a_new_question() {
        assert!(near_identical(
            &json!({ "focal": "apiRun", "direction": "calls", "depth": 3 }),
            &json!({ "focal": "apiRun", "direction": "calls", "depth": 6 }),
        ));
    }

    #[test]
    fn the_next_page_is_not_a_repeat() {
        assert!(!near_identical(
            &json!({ "query": "gh api http request" }),
            &json!({ "query": "gh api http request", "cursor": "b3BhcXVl" }),
        ));
    }

    /// The failure that put [`PAGE_ARGUMENT`] in a question's identity. The word
    /// measure alone reads a question with a page token added as identical to
    /// the one without it, because the shorter set is fully contained in the
    /// longer, and a guard that cannot see paging blocks the one re-ask that is
    /// always progress.
    #[test]
    fn a_page_token_is_part_of_a_question_and_not_a_word_in_it() {
        let first = question(&json!({ "query": "gh api http request" }));
        let second = question(&json!({ "query": "gh api http request", "cursor": "b3BhcXVl" }));
        assert_eq!(
            first.words, second.words,
            "a page token must not be read as another word of the question"
        );
        assert_eq!(first.page, None);
        assert_eq!(second.page.as_deref(), Some("b3BhcXVl"));
        assert_eq!(
            containment(&first, &second),
            0.0,
            "two questions asking for different pages share nothing"
        );
    }

    #[test]
    fn paging_on_is_never_blocked_however_far_it_goes() {
        let mut guard = RepeatGuard::new();
        // The first page comes back barren, which is what latches the class.
        let start = json!({ "query": "gh api http request" });
        assert_eq!(guard.before("semantic_locate", &start), Verdict::Allow);
        guard.record("semantic_locate", &start, &ranked(&["a"]), false);
        assert_eq!(guard.before("semantic_locate", &start), Verdict::Allow);
        guard.record("semantic_locate", &start, &ranked(&["a"]), false);
        // Three further pages, each a new token, none of them a repeat of the
        // question the class latched on. The locate budget is what stops them.
        for page in 0..2 {
            let next = json!({ "query": "gh api http request", "cursor": format!("page-{page}") });
            assert_eq!(
                guard.before("semantic_locate", &next),
                Verdict::Allow,
                "page {page} is the next page, not a repeat"
            );
            guard.record("semantic_locate", &next, &ranked(&["a"]), false);
        }
    }

    #[test]
    fn the_other_direction_is_a_different_question() {
        assert!(!near_identical(
            &json!({ "focal": "apiRun", "direction": "calls" }),
            &json!({ "focal": "apiRun", "direction": "callers" }),
        ));
    }

    #[test]
    fn a_question_still_producing_new_entities_is_never_blocked() {
        let mut guard = RepeatGuard::new();
        for round in 0..10 {
            let arguments = json!({ "query": "gh api http request" });
            assert_eq!(
                guard.before("find_references", &arguments),
                Verdict::Allow,
                "round {round} was blocked although every call returned new entities"
            );
            guard.record(
                "find_references",
                &arguments,
                &ranked(&[&format!("entity-{round}")]),
                false,
            );
        }
    }

    #[test]
    fn a_barren_question_is_redirected_after_the_second_repeat() {
        let mut guard = RepeatGuard::new();
        let arguments = json!({ "query": "gh api http request client" });
        // The original, which surfaces two entities.
        assert_eq!(guard.before("find_references", &arguments), Verdict::Allow);
        guard.record("find_references", &arguments, &ranked(&["a", "b"]), false);
        // The same question again, returning the same two: nothing new, so the
        // class latches.
        assert_eq!(guard.before("find_references", &arguments), Verdict::Allow);
        guard.record("find_references", &arguments, &ranked(&["a", "b"]), false);
        // Two repeats are allowed.
        for repeat in 0..REPEAT_ALLOWANCE {
            assert_eq!(
                guard.before("find_references", &arguments),
                Verdict::Allow,
                "repeat {repeat} should still run"
            );
            guard.record("find_references", &arguments, &ranked(&["a", "b"]), false);
        }
        // The third is not.
        let Verdict::Redirect(message) = guard.before("find_references", &arguments) else {
            panic!("the third repeat of a barren question must not run");
        };
        assert!(
            message.contains("was not run"),
            "the model must be told the call did not run: {message}"
        );
        assert!(
            message.contains("find_references"),
            "the redirect must name the tool it stopped: {message}"
        );
    }

    #[test]
    fn an_error_counts_as_nothing_new() {
        let mut guard = RepeatGuard::new();
        let arguments = json!({ "query": "gh api http request client" });
        for _ in 0..=REPEAT_ALLOWANCE {
            assert_eq!(guard.before("semantic_locate", &arguments), Verdict::Allow);
            guard.record("semantic_locate", &arguments, "boom", true);
        }
        assert!(
            matches!(
                guard.before("semantic_locate", &arguments),
                Verdict::Redirect(_)
            ),
            "a question that has only ever errored must stop being asked"
        );
    }

    #[test]
    fn a_result_the_guard_cannot_parse_is_never_called_barren() {
        let mut guard = RepeatGuard::new();
        let arguments = json!({ "query": "gh api http request client" });
        for _ in 0..8 {
            assert_eq!(guard.before("find_references", &arguments), Verdict::Allow);
            guard.record("find_references", &arguments, "a prose answer", false);
        }
    }

    #[test]
    fn a_tool_that_returns_no_entities_never_trips_the_repeat_rule() {
        let mut guard = RepeatGuard::new();
        let arguments = json!({});
        for _ in 0..8 {
            assert_eq!(guard.before("kin_graph_status", &arguments), Verdict::Allow);
            guard.record("kin_graph_status", &arguments, "{\"entities\":9}", false);
        }
    }

    #[test]
    fn the_locate_budget_stops_the_fifth_call_whatever_it_asks() {
        let mut guard = RepeatGuard::new();
        let budget = call_budget("semantic_locate").expect("locate is bounded");
        for (index, query) in measured_locate_queries().iter().enumerate() {
            let arguments = json!({ "query": query });
            let verdict = guard.before("semantic_locate", &arguments);
            if (index as u32) < budget {
                assert_eq!(verdict, Verdict::Allow, "call {} should run", index + 1);
                guard.record(
                    "semantic_locate",
                    &arguments,
                    &ranked(&[&format!("fresh-{index}")]),
                    false,
                );
            } else {
                assert_ne!(
                    verdict,
                    Verdict::Allow,
                    "call {} is past the budget and must not run",
                    index + 1
                );
            }
        }
    }

    #[test]
    fn the_measured_run_ends_instead_of_asking_a_ninth_time() {
        let mut guard = RepeatGuard::new();
        let mut ran = 0;
        let mut ended_at = None;
        for (index, query) in measured_locate_queries().iter().enumerate() {
            let arguments = json!({ "query": query });
            match guard.before("semantic_locate", &arguments) {
                Verdict::Allow => {
                    ran += 1;
                    guard.record(
                        "semantic_locate",
                        &arguments,
                        &ranked(&[&format!("fresh-{index}")]),
                        false,
                    );
                }
                Verdict::Redirect(_) => {}
                Verdict::Exhausted(detail) => {
                    ended_at = Some((index + 1, detail));
                    break;
                }
            }
        }
        assert_eq!(ran, 4, "four locates should have run");
        let (call, detail) = ended_at.expect("the run must end rather than ask nine times");
        assert_eq!(call, 7, "the run should end on the seventh locate");
        assert!(
            detail.contains("semantic_locate"),
            "the stop detail must name the tool that ran away: {detail}"
        );
    }

    #[test]
    fn the_guard_keeps_the_reason_for_every_escalation() {
        let mut guard = RepeatGuard::new();
        for query in measured_locate_queries() {
            let arguments = json!({ "query": query });
            if guard.before("semantic_locate", &arguments) == Verdict::Allow {
                guard.record("semantic_locate", &arguments, &ranked(&[query]), false);
            }
        }
        assert!(
            guard.escalations() > 0 && guard.reasons().len() == guard.escalations() as usize,
            "every escalation must leave a reason: {:?}",
            guard.reasons()
        );
    }

    #[test]
    fn two_refusals_on_one_target_are_allowed_and_the_third_attempt_is_redirected() {
        let mut guard = RepeatGuard::new();
        // The first attempt is not a repeat of anything.
        assert_eq!(
            guard.before_change("edit_file", "pkg/cmd/repo/clone/clone.go"),
            Verdict::Allow
        );
        guard.record_refusal("edit_file", "pkg/cmd/repo/clone/clone.go");
        // The second is how a model checks whether it read the refusal right. That
        // refusal now carries the file's exact bytes, so it is the last free one.
        assert_eq!(
            guard.before_change("edit_file", "pkg/cmd/repo/clone/clone.go"),
            Verdict::Allow
        );
        guard.record_refusal("edit_file", "pkg/cmd/repo/clone/clone.go");
        // The third is not run.
        let Verdict::Redirect(message) =
            guard.before_change("edit_file", "pkg/cmd/repo/clone/clone.go")
        else {
            panic!("a third attempt at a twice-refused target must not run");
        };
        assert!(
            message.contains("was not run") && message.contains("pkg/cmd/repo/clone/clone.go"),
            "the redirect must say what it stopped and on what: {message}"
        );
        // It sends the model to read, not to give up.
        assert!(
            message.contains("get_entity_source") && message.contains("exactly those bytes"),
            "the redirect must send the model to the source: {message}"
        );
        assert!(
            message.contains("kin_mutate"),
            "the redirect must name the route that needs no old bytes: {message}"
        );
        assert!(
            !message.contains("Say plainly what you could not determine"),
            "a change that can still land must not be told to give up: {message}"
        );
        assert_eq!(guard.escalations(), 1);
    }

    #[test]
    fn a_refusal_on_one_target_does_not_bound_another() {
        let mut guard = RepeatGuard::new();
        for _ in 0..REFUSAL_ALLOWANCE {
            assert_eq!(guard.before_change("edit_file", "a.go"), Verdict::Allow);
            guard.record_refusal("edit_file", "a.go");
        }
        assert!(matches!(
            guard.before_change("edit_file", "a.go"),
            Verdict::Redirect(_)
        ));
        // A different file is a different change, and it has been refused nothing.
        assert_eq!(guard.before_change("edit_file", "b.go"), Verdict::Allow);
    }

    #[test]
    fn a_change_that_lands_is_never_bounded() {
        let mut guard = RepeatGuard::new();
        // Nothing records a refusal, so no number of attempts trips the rule. The run's
        // own tool-call budget is what bounds a model that keeps editing successfully.
        for _ in 0..6 {
            assert_eq!(guard.before_change("edit_file", "a.go"), Verdict::Allow);
        }
        assert_eq!(guard.escalations(), 0);
    }

    #[test]
    fn an_escalation_names_the_tool_to_call_next() {
        for (tool, expected) in [
            ("semantic_locate", "trace"),
            ("semantic_search", "find_references"),
            ("trace_path", "find_references"),
        ] {
            assert!(
                escalation(tool).contains(expected),
                "{tool}'s escalation should point at {expected}: {}",
                escalation(tool)
            );
        }
    }
}
