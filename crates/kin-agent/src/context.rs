// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! How much of the model's window the conversation takes, and what one result may cost.
//!
//! Two bounds, because a single answer and a whole conversation fail differently. One tool
//! result can be larger than the model's entire window, so every result is cut to a
//! per-result ceiling with a note that says so and says how to ask for less. A conversation
//! of ordinary results still grows every turn, so the loop also keeps a running estimate of
//! the next request and stops, with a final answer, before that request would not fit.
//!
//! Neither bound can be left to the endpoint. A local server asked for more than its window
//! need not refuse: it can cut the prompt to fit, report a prompt count that no longer grows
//! with the conversation, and let the model answer from whatever survived.
//!
//! The estimate is anchored on the endpoint's own count whenever the endpoint reports one:
//! the last turn's `prompt_tokens` plus `completion_tokens` is what the next request starts
//! from, in the endpoint's own tokenizer. Only what the loop appended since then is estimated
//! from bytes, at [`BYTES_PER_TOKEN`], which is below what Kin's JSON costs on a local model's
//! tokenizer, so the estimate errs toward stopping early rather than overflowing.

use crate::provider::Usage;
use serde_json::{json, Value};

/// Bytes per token the estimate assumes. Kin's pretty-printed JSON measures a little above
/// three bytes a token on a local model, so this is the conservative side of it.
pub const BYTES_PER_TOKEN: u64 = 3;
/// Tokens a chat template adds around each message beyond the message's own text.
const MESSAGE_OVERHEAD_TOKENS: u64 = 8;
/// The most bytes of one tool result a run sends when the caller names no ceiling.
pub const DEFAULT_MAX_RESULT_BYTES: usize = 32 * 1024;
/// The least a derived ceiling may be, so a small window still sees a useful slice.
const MIN_RESULT_BYTES: usize = 4 * 1024;
/// The fewest tokens kept free for the model's answer, and the most.
const MIN_ANSWER_RESERVE: u64 = 1024;
const MAX_ANSWER_RESERVE: u64 = 8192;

/// Tokens a text of `bytes` bytes is estimated to cost.
pub fn estimate_tokens(bytes: u64) -> u64 {
    bytes.div_ceil(BYTES_PER_TOKEN)
}

/// Where a run's context window came from, recorded so a budget stop can be read against it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextSource {
    /// The operator named it with `--context-tokens`.
    Flag,
    /// The endpoint reported the context the model is loaded with.
    Endpoint,
    /// Neither said, so the run budgets for [`crate::DEFAULT_CONTEXT_TOKENS`].
    Default,
}

impl ContextSource {
    pub fn label(self) -> &'static str {
        match self {
            ContextSource::Flag => "flag",
            ContextSource::Endpoint => "endpoint",
            ContextSource::Default => "default",
        }
    }
}

/// The model's context window, in tokens, and where that number came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContextWindow {
    pub tokens: u64,
    pub source: ContextSource,
}

impl ContextWindow {
    /// The per-result ceiling when the caller names none: an eighth of the window, never more
    /// than [`DEFAULT_MAX_RESULT_BYTES`] and never less than a few kilobytes.
    pub fn default_result_ceiling(&self) -> usize {
        let eighth = self.tokens.saturating_mul(BYTES_PER_TOKEN) / 8;
        usize::try_from(eighth)
            .unwrap_or(usize::MAX)
            .clamp(MIN_RESULT_BYTES, DEFAULT_MAX_RESULT_BYTES)
    }

    /// Tokens kept free for the model's answer: an eighth of the window, within fixed bounds.
    pub fn answer_reserve(&self) -> u64 {
        (self.tokens / 8).clamp(MIN_ANSWER_RESERVE, MAX_ANSWER_RESERVE)
    }
}

/// One tool result as the model will receive it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shown {
    pub text: String,
    /// The size of the result as the tool produced it.
    pub original_bytes: usize,
    /// How many of those bytes the model receives. Equal to `original_bytes` when nothing
    /// was cut.
    pub shown_bytes: usize,
}

impl Shown {
    pub fn clipped(&self) -> bool {
        self.shown_bytes < self.original_bytes
    }
}

/// Cut `text` to at most `ceiling` bytes and say so.
///
/// The cut lands on a character boundary, and on a line end when one falls in the last
/// quarter of what is kept, so a pretty-printed payload ends on a whole line. The note names
/// the result's size, the ceiling and how to ask for less, because a model handed a silently
/// shortened list reads the missing rows as rows that do not exist. A text within the ceiling
/// comes back untouched.
pub fn clip_result(mut text: String, ceiling: usize, how_to_ask_for_less: &str) -> Shown {
    let original = text.len();
    if original <= ceiling {
        return Shown {
            text,
            original_bytes: original,
            shown_bytes: original,
        };
    }
    let mut cut = ceiling;
    while !text.is_char_boundary(cut) {
        cut -= 1;
    }
    if let Some(line_end) = text[..cut].rfind('\n') {
        if line_end >= cut - cut / 4 {
            cut = line_end;
        }
    }
    text.truncate(cut);
    text.push_str(&format!(
        "\n\n[kin agent] This result was cut. It is {original} bytes, and this run sends at \
         most {ceiling} bytes of any one result, so only the first {cut} bytes are above and \
         the rest never reached you. Do not read the missing part as absent. \
         {how_to_ask_for_less}"
    ));
    Shown {
        text,
        original_bytes: original,
        shown_bytes: cut,
    }
}

/// How to ask a tool for less, read off the arguments its own schema declares.
///
/// Only arguments the tool actually takes are named, so the advice is always a call the
/// tool will accept.
pub fn how_to_ask_for_less(schema: Option<&Value>) -> String {
    let properties = schema
        .and_then(|schema| schema.get("properties"))
        .and_then(Value::as_object);
    let takes = |name: &str| properties.is_some_and(|properties| properties.contains_key(name));
    let narrower = [
        "limit",
        "max_chars",
        "max_response_chars",
        "max_results",
        "top_k",
        "depth",
    ]
    .into_iter()
    .find(|name| takes(name));
    let pager = ["offset", "cursor", "page"]
        .into_iter()
        .find(|name| takes(name));
    match (narrower, pager) {
        (Some(narrower), Some(pager)) => format!(
            "Call it again with a smaller `{narrower}` and page through the rest with `{pager}`."
        ),
        (Some(narrower), None) => format!("Call it again with a smaller `{narrower}`."),
        (None, Some(pager)) => format!("Page through it with `{pager}`."),
        (None, None) => {
            "Call it again asking about less, such as one symbol or one file.".to_string()
        }
    }
}

/// A running estimate, in tokens, of the next request the loop would send.
#[derive(Debug, Clone)]
pub struct ContextMeter {
    window: ContextWindow,
    reserve: u64,
    /// The endpoint's own count of the last request plus its answer, once it reported one.
    anchor: Option<u64>,
    /// Everything the first request carries: system prompt, task and tool specs.
    baseline_bytes: u64,
    /// Bytes appended since the anchor, or since the start while there is none.
    pending_bytes: u64,
    pending_messages: u64,
}

impl ContextMeter {
    pub fn new(window: ContextWindow, baseline_bytes: u64) -> Self {
        ContextMeter {
            window,
            reserve: window.answer_reserve(),
            anchor: None,
            baseline_bytes,
            pending_bytes: 0,
            pending_messages: 0,
        }
    }

    pub fn window(&self) -> ContextWindow {
        self.window
    }

    pub fn reserve(&self) -> u64 {
        self.reserve
    }

    /// The estimated size of the next request, if it were sent now.
    pub fn used(&self) -> u64 {
        let pending =
            estimate_tokens(self.pending_bytes) + self.pending_messages * MESSAGE_OVERHEAD_TOKENS;
        match self.anchor {
            Some(anchor) => anchor + pending,
            None => estimate_tokens(self.baseline_bytes) + pending,
        }
    }

    /// Whether one more message of `bytes` bytes still leaves the answer its reserve.
    pub fn fits(&self, bytes: u64) -> bool {
        self.used() + estimate_tokens(bytes) + MESSAGE_OVERHEAD_TOKENS + self.reserve
            <= self.window.tokens
    }

    /// Whether the next turn still leaves the answer its reserve.
    pub fn has_room_for_a_turn(&self) -> bool {
        self.used() + self.reserve <= self.window.tokens
    }

    /// Whether a request of the current size, plus one short message, fits the window at all.
    pub fn fits_a_final_request(&self, message_bytes: u64) -> bool {
        self.used() + estimate_tokens(message_bytes) + MESSAGE_OVERHEAD_TOKENS < self.window.tokens
    }

    /// Count one message the loop appended to the conversation.
    pub fn add(&mut self, bytes: u64) {
        self.pending_bytes += bytes;
        self.pending_messages += 1;
    }

    /// Re-anchor on what the endpoint counted for the turn it just answered. `answer_bytes`
    /// is what the loop keeps of that answer, used only when the endpoint counted the prompt
    /// but not the answer.
    pub fn anchor(&mut self, usage: &Usage, answer_bytes: u64) {
        match usage.input_tokens {
            Some(prompt) => {
                let answer = usage
                    .output_tokens
                    .unwrap_or_else(|| estimate_tokens(answer_bytes));
                self.anchor = Some(prompt + answer);
                self.pending_bytes = 0;
                self.pending_messages = 0;
            }
            None => self.add(answer_bytes),
        }
    }

    /// The budget as the result record carries it.
    pub fn to_json(&self) -> Value {
        json!({
            "window_tokens": self.window.tokens,
            "source": self.window.source.label(),
            "reserve_tokens": self.reserve,
            "used_tokens": self.used(),
            "anchored_on_endpoint_count": self.anchor.is_some(),
        })
    }
}

/// What the model is told in place of a result the conversation cannot hold.
pub fn withheld_note(bytes: usize, meter: &ContextMeter) -> String {
    format!(
        "[kin agent] This result was not sent. It is {bytes} bytes, about {} tokens, and the \
         conversation already holds about {} of the model's {} tokens, so it would leave no \
         room for your answer. Do not call more tools. Answer with what you have learned and \
         say plainly what you could not determine.",
        estimate_tokens(bytes as u64),
        meter.used(),
        meter.window.tokens
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn window(tokens: u64) -> ContextWindow {
        ContextWindow {
            tokens,
            source: ContextSource::Flag,
        }
    }

    #[test]
    fn a_result_within_the_ceiling_is_untouched() {
        let shown = clip_result("{\"rows\": 3}".to_string(), 64, "unused");
        assert_eq!(shown.text, "{\"rows\": 3}");
        assert!(!shown.clipped());
    }

    #[test]
    fn a_result_over_the_ceiling_is_cut_with_a_note_naming_size_ceiling_and_paging() {
        let body: String = (0..400).map(|row| format!("row {row:04}\n")).collect();
        let original = body.len();
        let shown = clip_result(body, 1000, "Call it again with a smaller `limit`.");
        assert!(shown.clipped());
        assert_eq!(shown.original_bytes, original);
        assert!(
            shown.shown_bytes <= 1000,
            "kept {} bytes",
            shown.shown_bytes
        );
        let (kept, note) = shown
            .text
            .split_once("\n\n[kin agent] ")
            .expect("the note is appended");
        assert_eq!(kept.len(), shown.shown_bytes);
        // The cut ends on a whole row rather than in the middle of one.
        assert!(kept.ends_with(|c: char| c.is_ascii_digit()), "{kept:?}");
        for needle in [
            &original.to_string(),
            "1000 bytes",
            "smaller `limit`",
            "not read the missing part as absent",
        ] {
            assert!(note.contains(needle), "the note must name {needle}: {note}");
        }
    }

    #[test]
    fn a_cut_never_splits_a_character() {
        let body = "é".repeat(600);
        let shown = clip_result(body, 101, "x");
        // 101 falls inside a two-byte character, so the cut backs off to 100.
        assert_eq!(shown.shown_bytes, 100);
        assert!(shown.text.starts_with(&"é".repeat(50)));
    }

    #[test]
    fn paging_advice_names_only_arguments_the_tool_takes() {
        let listing =
            json!({ "properties": { "limit": {}, "offset": {}, "source_change_id": {} } });
        assert_eq!(
            how_to_ask_for_less(Some(&listing)),
            "Call it again with a smaller `limit` and page through the rest with `offset`."
        );
        let locate = json!({ "properties": { "query": {}, "max_chars": {} } });
        assert_eq!(
            how_to_ask_for_less(Some(&locate)),
            "Call it again with a smaller `max_chars`."
        );
        let status = json!({ "properties": {} });
        let advice = how_to_ask_for_less(Some(&status));
        assert!(
            !advice.contains('`'),
            "no argument may be invented: {advice}"
        );
        assert_eq!(how_to_ask_for_less(None), advice);
    }

    #[test]
    fn the_default_ceiling_scales_with_the_window_inside_fixed_bounds() {
        assert_eq!(
            window(131_072).default_result_ceiling(),
            DEFAULT_MAX_RESULT_BYTES
        );
        assert_eq!(window(32_768).default_result_ceiling(), 12_288);
        assert_eq!(window(2_048).default_result_ceiling(), MIN_RESULT_BYTES);
        assert_eq!(window(131_072).answer_reserve(), MAX_ANSWER_RESERVE);
        assert_eq!(window(32_768).answer_reserve(), 4_096);
        assert_eq!(window(4_096).answer_reserve(), MIN_ANSWER_RESERVE);
    }

    #[test]
    fn the_meter_anchors_on_the_endpoint_count_and_estimates_only_what_came_after() {
        let mut meter = ContextMeter::new(window(32_768), 3_000);
        // Before any count, everything is an estimate from bytes.
        assert_eq!(meter.used(), 1_000);
        meter.anchor(
            &Usage {
                input_tokens: Some(5_000),
                output_tokens: Some(200),
            },
            999_999,
        );
        assert_eq!(
            meter.used(),
            5_200,
            "the endpoint's count replaces the estimate"
        );
        meter.add(3_000);
        assert_eq!(meter.used(), 5_200 + 1_000 + MESSAGE_OVERHEAD_TOKENS);
        // An endpoint that counts the prompt but not the answer: the answer is estimated.
        meter.anchor(
            &Usage {
                input_tokens: Some(7_000),
                output_tokens: None,
            },
            300,
        );
        assert_eq!(meter.used(), 7_100);
        // An endpoint that counts nothing: the answer is appended as an estimate.
        meter.anchor(&Usage::default(), 30);
        assert_eq!(meter.used(), 7_100 + 10 + MESSAGE_OVERHEAD_TOKENS);
    }

    #[test]
    fn the_meter_keeps_the_answer_reserve_free() {
        let mut meter = ContextMeter::new(window(10_000), 0);
        meter.anchor(
            &Usage {
                input_tokens: Some(8_000),
                output_tokens: Some(0),
            },
            0,
        );
        // 10,000 less the 8,000 already counted and the 1,250 reserve leaves 750 tokens, so a
        // message of 742 tokens fits beside the template's 8 and one of 743 does not.
        assert!(meter.fits(742 * BYTES_PER_TOKEN));
        assert!(!meter.fits(743 * BYTES_PER_TOKEN));
        assert!(meter.has_room_for_a_turn());
        meter.add(742 * BYTES_PER_TOKEN);
        assert!(meter.has_room_for_a_turn());
        meter.add(BYTES_PER_TOKEN);
        assert!(!meter.has_room_for_a_turn());
        // The reserve is what a final request may still spend.
        assert!(meter.fits_a_final_request(300));
    }
}
