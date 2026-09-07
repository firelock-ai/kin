// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Multi-token name retrieval for a question phrased as a sentence.
//!
//! `semantic_search` hands its whole query string to the store as one name
//! pattern. The store answers that in two stages and the stages disagree about
//! what a query is. Its name index tokenizes: it tries the exact-name map, then
//! intersects the name-token index across every token of the pattern. Its
//! predicate does not: every candidate the index produced is re-checked with a
//! substring test against the ENTIRE lowercased pattern. So a pattern carrying a
//! space cannot survive, twice over. A long question intersects to nothing and
//! falls through to a substring test no declaration name can pass. A two-word
//! question intersects to real candidates and then loses every one of them to
//! the predicate, because no declaration name contains a space. `reconcile_report`
//! and `reconcile report` tokenize identically and answer differently for that
//! reason alone.
//!
//! Neither stage can be changed from here; they live in the storage engine, a
//! separate repository. What kin can do is stop asking a question its own store
//! cannot answer. This module turns one phrase into a bounded set of
//! single-token name queries, each of which passes both stages by construction
//! because a single token carries no separator, then ranks the union by how much
//! of the question each entity covers.
//!
//! Retrieval and ranking read different things, and the response says so.
//! Candidates come back by declaration NAME, because that is the only index the
//! store offers a token query against; a declaration whose path mentions a query
//! word but whose name mentions none is not in the union at all. Ranking then
//! reads the name, signature, path and doc summary of the candidates that are.
//!
//! Three properties keep this from changing an answer anyone relies on today.
//! It runs only when the whole-query filter returned nothing, so every query
//! that answers today answers identically. It runs only for a query containing
//! whitespace, so a single-identifier lookup that finds nothing still reports a
//! clean miss rather than a page of plausible neighbours. And it says in the
//! response that it ran, because a ranked list assembled this way is a weaker
//! claim than a name match and a reader has to be able to tell.

use std::collections::{HashMap, HashSet};

use kin_model::entity::Entity;
use serde_json::{json, Value};

/// The response key carrying this path's disclosure.
pub const LEXICAL_FALLBACK_KEY: &str = "lexical_fallback";

/// The most query tokens that may fan out into store queries.
///
/// The fan-out is one store query per token, so this is the bound on how much
/// work one sentence can ask for. Eight covers every question shape measured
/// against the hosted route once function words are dropped; past that, the
/// extra tokens are almost always restatements that add no ranking signal.
pub const MAX_QUERY_TOKENS: usize = 8;

/// Tokens shorter than this are dropped before the fan-out.
///
/// A one-character token matches a large fraction of any index and carries
/// almost no evidence about what the reader meant.
const MIN_TOKEN_CHARS: usize = 2;

/// The most entities one token's query may contribute to the union.
///
/// The store returns name matches in relevance order, exact name first, then
/// token hits, then substring hits, so the head of a token's list is its best
/// part and a cap keeps a common word from dominating the scoring pass.
const MAX_CANDIDATES_PER_TOKEN: usize = 400;

/// The most entities the union may hold before further tokens stop adding to it.
const MAX_UNION_CANDIDATES: usize = 2_000;

/// How much of a doc summary is read for token evidence.
const MAX_DOC_CHARS: usize = 400;

/// Field weights. A question token found in a declaration's own name is much
/// stronger evidence than the same token found in the path it happens to sit in.
const WEIGHT_NAME: f64 = 3.0;
const WEIGHT_SIGNATURE: f64 = 1.5;
const WEIGHT_PATH: f64 = 1.0;
const WEIGHT_DOC: f64 = 1.0;

/// Added on top of the name weight when a question token IS the whole
/// declaration name, so an exact identifier inside a sentence outranks a
/// declaration that merely contains it.
const BONUS_EXACT_NAME: f64 = 2.0;

/// English function words, dropped before the fan-out.
///
/// Deliberately short and deliberately free of anything that reads as code. A
/// word like `type`, `new`, `get` or `self` is a real declaration name in most
/// repositories, so dropping it would cost a match; a word like `does` or `the`
/// cannot be, and keeping it costs ranking precision on every question.
const STOP_WORDS: &[&str] = &[
    "a", "an", "and", "any", "are", "as", "at", "be", "been", "but", "by", "can", "could", "did",
    "do", "does", "for", "from", "had", "has", "have", "how", "i", "if", "in", "into", "is", "it",
    "its", "me", "my", "of", "on", "or", "our", "should", "so", "than", "that", "the", "their",
    "them", "then", "there", "these", "they", "this", "to", "was", "we", "were", "what", "when",
    "where", "which", "while", "who", "why", "will", "with", "would", "you", "your",
];

/// The tokens one phrase fans out into, plus what was left behind.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenPlan {
    /// Tokens that will each become their own store query, in the order they
    /// appeared in the question.
    pub tokens: Vec<String>,
    /// Tokens the plan dropped, so the disclosure can say what was ignored
    /// rather than leaving a reader to infer it from a shorter list.
    pub dropped: Vec<String>,
    /// Whether [`MAX_QUERY_TOKENS`] removed tokens that were otherwise usable.
    pub capped: bool,
}

/// Plan the fan-out for `query`, or `None` when this path must not run.
///
/// `None` for a query with no whitespace. A bare identifier is a name lookup and
/// its empty answer is the true answer; replacing that with a ranked page of
/// entities that merely share a word turns a certified miss into something that
/// looks like a find. The measured store has exactly that case in it, an
/// identifier defined in another repository and absent from this index, and it
/// must keep reading as absent.
///
/// `None` also when fewer than two usable tokens survive, since a one-token
/// fan-out is the query the store already ran.
pub fn plan(query: &str) -> Option<TokenPlan> {
    if !query.chars().any(char::is_whitespace) {
        return None;
    }

    let mut tokens: Vec<String> = Vec::new();
    let mut dropped: Vec<String> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();

    // The store's name-token index is built with this tokenizer, so a token it
    // produces is a token that index can be asked for. Splitting the query any
    // other way would be a guess about the index's vocabulary.
    for token in kin_search::tokenize(query) {
        if !seen.insert(token.clone()) {
            continue;
        }
        if token.chars().count() < MIN_TOKEN_CHARS || STOP_WORDS.contains(&token.as_str()) {
            dropped.push(token);
            continue;
        }
        tokens.push(token);
    }

    if tokens.len() < 2 {
        return None;
    }

    let capped = tokens.len() > MAX_QUERY_TOKENS;
    if capped {
        dropped.extend(tokens.drain(MAX_QUERY_TOKENS..));
    }

    Some(TokenPlan {
        tokens,
        dropped,
        capped,
    })
}

/// One token's retrieval outcome, as the caller's store answered it.
#[derive(Debug, Clone)]
pub struct TokenHits {
    /// The token this query was issued for.
    pub token: String,
    /// The pattern that produced these entities: the token, or its singular form
    /// when the token itself matched nothing.
    pub pattern: String,
    /// The entities the store returned, already truncated by the caller.
    pub entities: Vec<Entity>,
    /// How many the store matched BEFORE the caller's truncation.
    ///
    /// Kept separately because this is the number the rarity weight reads, and
    /// the truncated length cannot carry it: a word matching four hundred
    /// declarations and a word matching forty thousand both arrive as four
    /// hundred, so a very common word would weigh exactly as much as a
    /// moderately common one on precisely the store sizes where the difference
    /// decides the ranking.
    pub total_matching: usize,
    /// Whether [`MAX_CANDIDATES_PER_TOKEN`] truncated the store's answer.
    pub truncated: bool,
}

/// The bound a caller must apply to one token's store answer before handing it
/// here, exported so the retrieval loop and the disclosure cannot drift apart.
pub const fn max_candidates_per_token() -> usize {
    MAX_CANDIDATES_PER_TOKEN
}

/// The singular form of a token that reads as an English plural, or `None`.
///
/// A question says "where are projections written" while the declaration is
/// named `ProjectionWriter`, and the index holds the singular token only. This
/// is a spelling reduction, not a stemmer: it changes only the word ending, so
/// it cannot collapse two unrelated identifiers into one token the way an
/// aggressive stem can.
pub fn singular(token: &str) -> Option<String> {
    let len = token.chars().count();
    if token.ends_with("ies") && len > 4 {
        return Some(format!("{}y", &token[..token.len() - 3]));
    }
    for suffix in ["sses", "shes", "ches", "xes", "zes"] {
        if token.ends_with(suffix) && len > suffix.chars().count() + 1 {
            return Some(token[..token.len() - 2].to_string());
        }
    }
    if len > 3
        && token.ends_with('s')
        && !token.ends_with("ss")
        && !token.ends_with("us")
        && !token.ends_with("is")
    {
        return Some(token[..token.len() - 1].to_string());
    }
    None
}

/// The comparison form of a token: its singular spelling when it has one.
fn normalized(token: &str) -> String {
    singular(token).unwrap_or_else(|| token.to_string())
}

/// Where a question token was found on an entity, best field first.
fn field_weight(
    normal: &str,
    name_tokens: &HashSet<String>,
    signature_tokens: &HashSet<String>,
    path_tokens: &HashSet<String>,
    doc_tokens: &HashSet<String>,
) -> Option<f64> {
    if name_tokens.contains(normal) {
        Some(WEIGHT_NAME)
    } else if signature_tokens.contains(normal) {
        Some(WEIGHT_SIGNATURE)
    } else if path_tokens.contains(normal) {
        Some(WEIGHT_PATH)
    } else if doc_tokens.contains(normal) {
        Some(WEIGHT_DOC)
    } else {
        None
    }
}

/// The tokens of one text, reduced to their comparison form.
fn normalized_tokens(text: &str) -> HashSet<String> {
    kin_search::tokenize(text)
        .into_iter()
        .map(|token| normalized(&token))
        .collect()
}

/// How much a token's presence is worth, given how many entities it retrieved.
///
/// A token that names a handful of declarations says far more about what the
/// reader meant than one that names a thousand, and the store's own answer size
/// is the only breadth signal available on this path without a second pass over
/// the index.
fn rarity(document_frequency: usize) -> f64 {
    1.0 / (1.0 + (1.0 + document_frequency as f64).ln())
}

/// One ranked entity and the evidence behind its position.
#[derive(Debug, Clone)]
pub struct RankedEntity {
    pub entity: Entity,
    /// How many distinct question tokens this entity carries anywhere.
    pub coverage: usize,
    /// The weighted sum over those tokens.
    pub score: f64,
}

/// The ranked union of every token's hits, best first.
///
/// Ordered by coverage before score on purpose: an entity carrying four of the
/// question's words is a better answer to the question than one carrying two
/// with a higher weight on each, and coverage is the property a reader can check
/// against the words they typed. Score breaks coverage ties, then the shorter
/// name, then the name itself, then the id, so the order is total and does not
/// depend on the union's assembly order.
pub fn rank(plan: &TokenPlan, hits: &[TokenHits]) -> Vec<RankedEntity> {
    let weights: HashMap<&str, f64> = hits
        .iter()
        .map(|hit| (hit.token.as_str(), rarity(hit.total_matching)))
        .collect();
    let normals: Vec<(String, String)> = plan
        .tokens
        .iter()
        .map(|token| (token.clone(), normalized(token)))
        .collect();

    let mut union: Vec<Entity> = Vec::new();
    let mut seen: HashSet<String> = HashSet::new();
    for hit in hits {
        for entity in &hit.entities {
            if union.len() >= MAX_UNION_CANDIDATES {
                break;
            }
            if seen.insert(entity.id.to_string()) {
                union.push(entity.clone());
            }
        }
    }

    let mut ranked: Vec<RankedEntity> = union
        .into_iter()
        .filter_map(|entity| {
            let name_tokens = normalized_tokens(&entity.name);
            let signature_tokens = normalized_tokens(&entity.signature);
            let path_tokens = entity
                .file_origin
                .as_ref()
                .map(|path| normalized_tokens(&path.to_string()))
                .unwrap_or_default();
            let doc_tokens = entity
                .doc_summary
                .as_deref()
                .map(|doc| {
                    let end = doc
                        .char_indices()
                        .nth(MAX_DOC_CHARS)
                        .map_or(doc.len(), |(index, _)| index);
                    normalized_tokens(&doc[..end])
                })
                .unwrap_or_default();
            let lower_name = entity.name.to_lowercase();

            let mut coverage = 0usize;
            let mut score = 0.0f64;
            for (token, normal) in &normals {
                let Some(weight) = field_weight(
                    normal,
                    &name_tokens,
                    &signature_tokens,
                    &path_tokens,
                    &doc_tokens,
                ) else {
                    continue;
                };
                coverage += 1;
                let exact = if lower_name == *token || lower_name == *normal {
                    BONUS_EXACT_NAME
                } else {
                    0.0
                };
                score += weights.get(token.as_str()).copied().unwrap_or(1.0) * (weight + exact);
            }

            // An entity retrieved by one token's substring match that carries no
            // whole token of the question is noise, not a weak answer.
            (coverage > 0).then_some(RankedEntity {
                entity,
                coverage,
                score,
            })
        })
        .collect();

    ranked.sort_by(|a, b| {
        b.coverage
            .cmp(&a.coverage)
            .then_with(|| b.score.total_cmp(&a.score))
            .then_with(|| a.entity.name.len().cmp(&b.entity.name.len()))
            .then_with(|| a.entity.name.cmp(&b.entity.name))
            .then_with(|| a.entity.id.to_string().cmp(&b.entity.id.to_string()))
    });
    ranked
}

/// The response block saying this path answered, and what it can and cannot claim.
///
/// Attached whenever the fan-out ran, including when it also came back empty. An
/// empty answer to a sentence is the case a reader is most likely to misread, so
/// it is the case that most needs the path named.
pub fn disclosure(plan: &TokenPlan, hits: &[TokenHits], matched: usize) -> Value {
    let unmatched: Vec<&str> = hits
        .iter()
        .filter(|hit| hit.total_matching == 0)
        .map(|hit| hit.token.as_str())
        .collect();
    let truncated: Vec<&str> = hits
        .iter()
        .filter(|hit| hit.truncated)
        .map(|hit| hit.token.as_str())
        .collect();
    let substituted: Vec<Value> = hits
        .iter()
        .filter(|hit| hit.pattern != hit.token)
        .map(|hit| json!({ "token": hit.token, "queried_as": hit.pattern }))
        .collect();

    json!({
        "answered_by": "name_token_coverage",
        "reason": "no_vector_coverage",
        "detail": format!(
            "The whole-query name filter matched nothing, so this answer was assembled by a \
             lexical fallback across {} query tokens. Candidates are retrieved by DECLARATION \
             NAME, one name query per token, so a declaration no query token names is not here \
             even if its path or doc mentions one. Those candidates are then ranked by how many \
             of the question's tokens each carries across its name, signature, path and doc \
             summary. It reads the entity index and never the vector index, so it ranks by word \
             overlap and not by meaning, and a store with no vector coverage has no other path to \
             an answer for a question phrased as a sentence.",
            plan.tokens.len()
        ),
        "query_tokens": plan.tokens,
        "dropped_tokens": plan.dropped,
        "token_cap_applied": plan.capped,
        "tokens_with_no_declaration": unmatched,
        "tokens_truncated_at_cap": truncated,
        "tokens_queried_as_singular": substituted,
        "matched": matched,
        "retrieved_by": "one declaration-name query per token",
        "ranked_by": "token coverage first, then a rarity-weighted field score: name, then \
                      signature, then path, then doc summary",
        "vector_ranked": false,
        "caution": if matched == 0 {
            "This fallback ran and still matched nothing. The absence is a statement about word \
             overlap with declaration names, paths and signatures, not about whether the \
             repository implements the behaviour the question describes."
        } else {
            "These results share words with the question. Word overlap is not a claim that any of \
             them implements what the question asked about; confirm by reading the source."
        },
    })
}

/// The trust gap an empty fallback answer carries, for the absence verdict.
///
/// Returned only when this path ran AND matched nothing. A sentence that no
/// declaration shares a word with is a miss about vocabulary, and certifying it
/// as an authoritative absence is how a question about behaviour comes back
/// reading like proof the behaviour is not there.
pub fn absence_gap(payload: &Value) -> Option<String> {
    let block = payload.get(LEXICAL_FALLBACK_KEY)?.as_object()?;
    if block.get("matched").and_then(Value::as_u64) != Some(0) {
        return None;
    }
    Some(
        "lexical_fallback_matched_nothing: the query is a phrase, the whole-query name filter \
         matched nothing, and the per-token fallback that ran instead ranks by word overlap with \
         declaration names, paths and signatures rather than by meaning, so this absence cannot \
         separate a behaviour the repository lacks from one whose declarations are worded \
         differently than the question"
            .to_string(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_query_with_no_whitespace_never_plans_a_fan_out() {
        assert_eq!(plan("SnapshotManager"), None);
        assert_eq!(plan("reconcile_report"), None);
        assert_eq!(plan("kin::db::open"), None);
    }

    #[test]
    fn a_phrase_plans_its_content_words_and_drops_function_words() {
        let planned = plan("how does reconcile detect a stale graph").expect("phrase plans");
        assert_eq!(
            planned.tokens,
            vec!["reconcile", "detect", "stale", "graph"]
        );
        assert!(planned.dropped.contains(&"how".to_string()));
        assert!(planned.dropped.contains(&"does".to_string()));
        assert!(planned.dropped.contains(&"a".to_string()));
        assert!(!planned.capped);
    }

    #[test]
    fn a_phrase_of_only_function_words_plans_nothing() {
        assert_eq!(plan("how does it do that"), None);
    }

    #[test]
    fn the_fan_out_is_capped_and_says_so() {
        let planned =
            plan("alpha beta gamma delta epsilon zeta eta theta iota kappa").expect("phrase plans");
        assert_eq!(planned.tokens.len(), MAX_QUERY_TOKENS);
        assert!(planned.capped);
        assert!(planned.dropped.contains(&"iota".to_string()));
        assert!(planned.dropped.contains(&"kappa".to_string()));
    }

    #[test]
    fn plural_query_words_reduce_to_the_form_an_index_holds() {
        assert_eq!(singular("projections").as_deref(), Some("projection"));
        assert_eq!(singular("entities").as_deref(), Some("entity"));
        assert_eq!(singular("branches").as_deref(), Some("branch"));
        assert_eq!(singular("tools").as_deref(), Some("tool"));
        assert_eq!(singular("class"), None);
        assert_eq!(singular("status"), None);
        assert_eq!(singular("analysis"), None);
        assert_eq!(singular("is"), None);
    }

    #[test]
    fn rarity_falls_as_a_token_retrieves_more() {
        assert!(rarity(1) > rarity(10));
        assert!(rarity(10) > rarity(1000));
        assert!(rarity(0) > 0.0);
    }
}
