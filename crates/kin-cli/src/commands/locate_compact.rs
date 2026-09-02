// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The compact agent surface for a locate result.
//!
//! [`LocateResult`] is one type serving three boundaries at once: `kin locate
//! --json`, the daemon's `POST /locate` body, and the base the MCP
//! `semantic_locate` payload is built on top of. Every field it carries is read
//! somewhere, so the shape cannot be narrowed in place. This module projects it
//! instead, at the output boundary, leaving the wire type untouched.
//!
//! The projection exists because of what the full shape costs an agent. On a
//! 730-entity hiredis store, `kin locate --json` serializes 28,108 bytes and
//! `--json --page-size 12 --max-files 12` serializes 38,819. Of the compact
//! payload behind those, `files[].symbols` alone is 12,769 bytes, 69 percent,
//! and it is a back-compat roll-up of the same entities the `entities[]` block
//! already carries in a self-describing form. `--no-snippets` does not touch it,
//! which is why a caller that had already asked for the lean form still spent
//! its whole tool budget on one result. The same twelve entities through this
//! projection are 3,472 bytes.
//!
//! What survives is what an agent acts on: the graph handle, the name, the kind,
//! where it lives, the declared signature, the score, the ranked file paths, and
//! an envelope saying how much of the semantic signal was actually behind the
//! ranking. Nothing else.

use serde::{Deserialize, Serialize};

use super::locate::{EmbeddingState, LocateEntity, LocateResult, SemanticCoverage};

/// Which shape a locate surface serializes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LocateSurface {
    /// Every field [`LocateResult`] holds. What `kin locate --json` has always
    /// emitted, and what `--diagnose`, ContextBench and the acceptance scripts
    /// read.
    #[default]
    Full,
    /// The projected agent surface in this module.
    Compact,
}

impl LocateSurface {
    /// The token `--surface` accepts, and the one a payload reports itself by.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Compact => "compact",
        }
    }

    /// Parse a caller-supplied token. Returns `None` for anything else, so a
    /// misspelling is refused rather than silently taken as the default.
    pub fn parse(token: &str) -> Option<Self> {
        match token {
            "full" => Some(Self::Full),
            "compact" => Some(Self::Compact),
            _ => None,
        }
    }
}

/// One ranked hit, reduced to the fields an agent acts on.
///
/// Field names are short because every one of them is repeated per hit, and a
/// twelve-hit page pays for each key twelve times. They are not abbreviated past
/// the point of being readable: an agent reading `id`, `name`, `kind`, `file`,
/// `line`, `signature` and `score` needs no legend.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct CompactEntity {
    /// Stable graph entity id: the handle `get_entity_source`,
    /// `get_context_pack`, `find_references` and `graph_neighborhood` take.
    ///
    /// Omitted on an artifact hit, which has none. [`Self::artifact`] carries
    /// that hit's handle instead. Emitting an empty string here would hand an
    /// agent a dead id that looks exactly like a live one.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub id: String,
    /// Repo-relative path of an artifact hit: a tracked file the parsers
    /// produced no entities for. Present only when [`Self::id`] is absent, and
    /// it is the handle `kin_artifact_read` takes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact: Option<String>,
    pub name: String,
    /// Entity kind (function, method, class, ...), lowercased.
    pub kind: String,
    /// File the entity is defined in. Provenance, not the answer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,
    /// 1-based line the entity starts at. The end line is dropped: an agent that
    /// wants the body reads it by id rather than by line range.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    /// Declared signature from graph truth. Kept even though it is the single
    /// most expensive field here (1,127 of the 2,639 payload bytes across twelve
    /// hiredis entities), because it is what lets an agent call the thing
    /// without a second read.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signature: String,
    /// Composite resolution score, rounded to two decimals.
    ///
    /// Rounded rather than dropped, and worth reading with the caveat the human
    /// surface already states: this score is composed by whichever stage
    /// admitted the row, so it is not comparable between rows. Rank order is the
    /// authoritative signal; the score says how confident the stage was.
    pub score: f32,
    /// How the query reached this entity: `name` when a query token is the
    /// entity's own name, else `semantic` or `text_fallback`. Absent on a record
    /// from a daemon predating the field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub matched: Option<String>,
}

/// The one-object answer to "how much of the semantic signal was behind this
/// ranking".
///
/// This is here because of what the demo stores did on 2026-09-01: they carried
/// no embeddings at all, ranking fell back to name and lexical matches, and
/// nothing in the result an agent read said so. The full payload does say so, in
/// a 406-byte `semantic_coverage` object and a 703-byte `degradations` array,
/// and both were the first things a budget cut threw away. Stating it in four
/// short fields means the caller sees it whether or not the response was cut.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct CompactKinEnvelope {
    /// What the embedding substrate was observed to be: `present`, `partial`,
    /// `absent` or `unknown`. The same vocabulary [`EmbeddingState`] serializes,
    /// so a caller matching on the payload and one matching on the type read the
    /// same words. `unknown` is a state, not a shade of `absent`: it means
    /// nobody could take a reading.
    pub embedding_state: String,
    /// Entities with an embedding indexed.
    pub embedded: usize,
    /// Entities eligible for embedding.
    pub eligible: usize,
    /// Entities still queued.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub pending: usize,
    /// Retrieval capabilities that could not fully run, named one word each
    /// (`vector_index`, `cross_encoder`, ...). The full payload carries the
    /// reason, detail and remediation for each; this carries the fact, so a thin
    /// result is attributable at a glance and `--surface full` has the rest.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub degraded: Vec<String>,
}

/// The projected surface.
///
/// Two of its fields are alternatives, and which one is populated depends on
/// which boundary is serializing. `kin locate --json --surface compact` has no
/// envelope machinery behind it, so it carries [`Self::kin`] and that is where a
/// reader finds the coverage. The MCP `semantic_locate` payload does have such
/// machinery: `kin-mcp`'s envelope builder lifts the payload's own
/// `semantic_coverage` object into the `_kin` it attaches, and a second `_kin`
/// written here would collide with it. So the MCP projection carries
/// [`Self::semantic_coverage`] instead, the coverage object unchanged, and the
/// envelope publishes it under `_kin` exactly as it does today. Both boundaries
/// carry [`Self::ranked_by`], because that sentence is the part a small model
/// reads and it survives any budget cut that reaches the counters.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct CompactLocate {
    pub entities: Vec<CompactEntity>,
    /// Ranked file paths, paths only.
    ///
    /// Kept as a bare list rather than dropped. It costs 233 bytes for twelve
    /// files against the 18,182 the full `files[]` block costs, and it keeps the
    /// key present for every consumer that decides a payload is a locate result
    /// by looking for it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub files: Vec<String>,
    /// Total rows in the full ranking behind this page.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub total_ranked: usize,
    /// Cursor for the next page, when one exists.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<String>,
    /// True when the full ranking was non-empty and NOT ONE entity in it was
    /// named by the query.
    ///
    /// Top level, where the full shape puts it, because `kin-mcp`'s negative
    /// logic reads it from exactly there to tell "found it" from "here are the
    /// best guesses". Moving it inside the envelope would make every compact
    /// response read as a confident answer.
    #[serde(default, skip_serializing_if = "is_false")]
    pub all_fallback: bool,
    /// Which signals actually ranked this result, in one clause.
    pub ranked_by: String,
    /// The CLI envelope. `None` on the MCP projection; see the type docs.
    #[serde(rename = "_kin", default, skip_serializing_if = "Option::is_none")]
    pub kin: Option<CompactKinEnvelope>,
    /// The coverage object, carried unchanged so `kin-mcp` can lift it. `None`
    /// on the CLI projection; see the type docs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub semantic_coverage: Option<SemanticCoverage>,
}

fn is_zero(value: &usize) -> bool {
    *value == 0
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// Round a composite score to two decimals.
///
/// Two decimals because the raw `f32` serializes up to nine significant digits
/// and the ninth carries no information a caller can act on: these scores are
/// stage-composed and not comparable between rows, so precision past the point
/// that separates adjacent ranks is bytes spent on noise.
fn round_score(score: f32) -> f32 {
    (score * 100.0).round() / 100.0
}

/// The clause naming which signals ranked a result, from the embedding state.
///
/// Derived from the state and from nothing else. Deriving it from
/// `SemanticCoverage::complete` instead is the FIR-2543 defect: that flag is a
/// conjunction over the substrate AND the population a query ranked over, so a
/// role filter clearing it would report a fully embedded store as unembedded.
fn ranked_by_clause(state: EmbeddingState) -> &'static str {
    match state {
        EmbeddingState::Present => "vector, lexical and graph signals",
        EmbeddingState::Partial => "lexical and graph signals; the vector signal was partial",
        EmbeddingState::Absent => {
            "lexical and graph signals only; nothing in this graph is embedded"
        }
        EmbeddingState::Unknown => {
            "lexical and graph signals; embedding coverage could not be read"
        }
    }
}

/// Build the envelope from the coverage the query actually reported.
///
/// A result with no `semantic_coverage` at all reports `unknown` rather than
/// guessing `present` from absent counters. A surface that cannot see the
/// observation has not observed anything, and reading zeroes as a healthy store
/// is the structural zero wearing the opposite costume.
fn project_envelope(result: &LocateResult) -> CompactKinEnvelope {
    let coverage: Option<&SemanticCoverage> = result.semantic_coverage.as_ref();
    CompactKinEnvelope {
        embedding_state: observed_state(result).as_str().to_string(),
        embedded: coverage.map_or(0, |c| c.indexed),
        eligible: coverage.map_or(0, |c| c.total),
        pending: coverage.map_or(0, |c| c.pending),
        degraded: degraded_components(result),
    }
}

/// The distinct capability names behind this query's degradations, sorted.
///
/// The names only. The full array's bulk is its `detail` and `remediation`
/// prose, 703 bytes of it on a hiredis query, and `--surface full` still carries
/// every word. What a caller needs from a compact response is that a capability
/// did not fully run and which one.
fn degraded_components(result: &LocateResult) -> Vec<String> {
    let mut components: Vec<String> = result
        .degradations
        .iter()
        .map(|d| d.component.clone())
        .collect();
    components.sort();
    components.dedup();
    components
}

/// The embedding state this result reported, or `Unknown` when it reported none.
fn observed_state(result: &LocateResult) -> EmbeddingState {
    result
        .semantic_coverage
        .as_ref()
        .map_or(EmbeddingState::Unknown, |c| c.embedding_state)
}

/// Project one ranked entity.
fn project_entity(entity: &LocateEntity) -> CompactEntity {
    // An artifact hit carries no entity id, and its path is the handle. Keyed on
    // the id being empty rather than on `id_space`, so a record from a daemon
    // that predates the id-space field still routes its path to the field an
    // agent can use.
    let is_artifact = entity.entity_id.is_empty();
    CompactEntity {
        id: entity.entity_id.clone(),
        artifact: if is_artifact {
            entity.artifact_path.clone()
        } else {
            None
        },
        name: entity.name.clone(),
        kind: entity.kind.clone(),
        file: entity.provenance.file.clone(),
        line: entity.span.map(|span| span[0]),
        signature: entity.signature.clone(),
        score: round_score(entity.score),
        matched: entity.match_kind.map(|kind| kind.as_str().to_string()),
    }
}

/// The half of the projection both boundaries share.
fn project_common(result: &LocateResult) -> CompactLocate {
    CompactLocate {
        entities: result.entities.iter().map(project_entity).collect(),
        files: result.files.iter().map(|f| f.path.clone()).collect(),
        total_ranked: result.total_ranked,
        next_cursor: result.next_cursor.clone(),
        all_fallback: result.all_fallback,
        ranked_by: ranked_by_clause(observed_state(result)).to_string(),
        kin: None,
        semantic_coverage: None,
    }
}

/// Project onto the CLI compact surface: coverage summarized under `_kin`.
pub fn project(result: &LocateResult) -> CompactLocate {
    CompactLocate {
        kin: Some(project_envelope(result)),
        ..project_common(result)
    }
}

/// Project onto the MCP compact surface: the coverage object carried unchanged
/// under its own name, so `kin-mcp`'s envelope builder lifts it into the `_kin`
/// it attaches rather than finding a second one already there.
pub fn project_for_mcp(result: &LocateResult) -> CompactLocate {
    CompactLocate {
        semantic_coverage: result.semantic_coverage.clone(),
        ..project_common(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::commands::locate::{
        LocateFileEntry, LocateMatchKind, LocateProvenance, LocateSymbol, RetrievalDegradation,
    };

    fn coverage(
        state: EmbeddingState,
        indexed: usize,
        total: usize,
        pending: usize,
    ) -> SemanticCoverage {
        SemanticCoverage {
            supported: true,
            indexed,
            total,
            pending,
            complete: state == EmbeddingState::Present,
            embedding_state: state,
            limited_by: Vec::new(),
            read_at: None,
            note: None,
            graph_bodies: None,
        }
    }

    fn entity(index: usize) -> LocateEntity {
        LocateEntity {
            entity_id: format!("11111111-2222-3333-4444-5555555555{index:02}"),
            id_space: Default::default(),
            artifact_path: None,
            kind: "function".into(),
            name: format!("redisAsyncHandleWrite{index}"),
            signature: format!(
                "static int redisAsyncHandleWrite{index}(redisAsyncContext *ac, int flags)"
            ),
            score: 570.90843,
            definition: true,
            span: Some([256, 301]),
            body: Some("static int redisAsyncHandleWrite(...) {\n    /* body */\n}".into()),
            match_kind: Some(LocateMatchKind::TextFallback),
            provenance: LocateProvenance {
                file: Some("async.c".into()),
                origin: "text".into(),
                cosine: None,
            },
            matched_queries: Vec::new(),
        }
    }

    /// One ranked symbol in the back-compat per-file roll-up.
    ///
    /// The fixture has to carry these. Without them the "full" shape it is
    /// measured against lacks the one block this projection exists to drop, so
    /// the size ratio reads 2x instead of the 11x real data shows and the
    /// `!contains("symbols")` assertion passes against data that never had any.
    /// A real hiredis page carries 63 to 74 of these across its files.
    fn symbol(index: usize) -> LocateSymbol {
        LocateSymbol {
            name: format!("redisAsyncHandleWrite{index}"),
            span: Some([256, 301]),
            score: 570.908_43,
            kind: "function".into(),
            definition: true,
            origin: "text".into(),
            cosine: None,
            snippet: Some(
                "static int redisAsyncHandleWrite(redisAsyncContext *ac) {\n    /* body */\n}"
                    .into(),
            ),
        }
    }

    fn file_entry(index: usize) -> LocateFileEntry {
        LocateFileEntry {
            path: format!("src/file{index}.c"),
            score: 12.5,
            signals: vec!["text".into()],
            spans: vec![[1, 40]],
            symbols: (0..6).map(symbol).collect(),
            explain: vec!["a long explain line that the compact surface must not carry".into()],
            provenance: None,
            signal_scores: None,
            score_breakdown: None,
            matched_queries: Vec::new(),
        }
    }

    fn fixture(entities: usize, files: usize) -> LocateResult {
        LocateResult {
            entities: (0..entities).map(entity).collect(),
            files: (0..files).map(file_entry).collect(),
            next_cursor: Some("cursor-token-0123456789abcdef".into()),
            total_ranked: 41,
            semantic_coverage: Some(coverage(EmbeddingState::Absent, 0, 1460, 1460)),
            degradations: vec![RetrievalDegradation {
                component: "vector_index".into(),
                reason: "empty".into(),
                detail: "no entity in this graph carries an embedding".into(),
                remediation: "run 'kin embed'".into(),
            }],
            ..Default::default()
        }
    }

    /// The size bound the whole change exists to buy.
    ///
    /// Twelve entities and twelve files, the page the demo asks for. The full
    /// shape of this same fixture is asserted below it, so the test states the
    /// ratio rather than an unanchored ceiling: a bound with no baseline beside
    /// it passes just as happily when the projection stops projecting.
    #[test]
    fn twelve_results_fit_the_compact_budget() {
        let full = fixture(12, 12);
        let compact = project(&full);
        let compact_bytes = serde_json::to_string(&compact).unwrap().len();
        let full_bytes = serde_json::to_string(&full).unwrap().len();

        assert!(
            compact_bytes < 4096,
            "twelve compact results must stay under 4 KB; got {compact_bytes}"
        );
        assert!(
            full_bytes > compact_bytes * 4,
            "the compact surface must be well under a quarter of the full shape, else it is \
             projecting nothing: full {full_bytes}, compact {compact_bytes}"
        );
        assert_eq!(compact.entities.len(), 12);
        assert_eq!(compact.files.len(), 12);
    }

    /// Every field the agent surface promises, and nothing beside it.
    ///
    /// Asserted over the serialized keys rather than the struct, because the
    /// struct can grow a field with `skip_serializing_if` and stay honest while
    /// a field without one silently rejoins the payload.
    #[test]
    fn the_compact_entity_carries_exactly_the_agent_fields() {
        let compact = project(&fixture(1, 1));
        let value = serde_json::to_value(&compact).unwrap();
        let hit = &value["entities"][0];
        let mut keys: Vec<&str> = hit
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort();
        assert_eq!(
            keys,
            vec![
                "file",
                "id",
                "kind",
                "line",
                "matched",
                "name",
                "score",
                "signature"
            ],
            "the compact hit grew or lost a field"
        );
        assert_eq!(hit["line"], 256, "line is the span start");
        assert_eq!(hit["file"], "async.c");
        // The body is the single largest thing the full shape carries per hit,
        // and the compact surface deliberately does not: the id is the handle
        // for reading it.
        assert!(hit.get("body").is_none(), "the body must not survive");
        assert!(hit.get("span").is_none(), "the end line must not survive");
    }

    /// The file roll-up is paths only. This is where 69 percent of the payload
    /// went.
    #[test]
    fn the_file_rollup_is_paths_only() {
        let compact = project(&fixture(1, 3));
        let value = serde_json::to_value(&compact).unwrap();
        assert!(
            value["files"]
                .as_array()
                .unwrap()
                .iter()
                .all(|f| f.is_string()),
            "files must be a bare path list, not objects"
        );
        let serialized = serde_json::to_string(&compact).unwrap();
        assert!(
            !serialized.contains("symbols"),
            "the back-compat symbol roll-up must not reach the compact surface"
        );
        assert!(
            !serialized.contains("that the compact surface must not carry"),
            "per-file explain lines must not reach the compact surface"
        );
    }

    /// An unembedded store must say so where a reader cannot miss it, because on
    /// 2026-09-01 it did not and the ranking silently fell back to name matches.
    #[test]
    fn an_unembedded_store_says_so_in_the_envelope() {
        let compact = project(&fixture(2, 2));
        let kin = compact
            .kin
            .as_ref()
            .expect("the CLI projection carries _kin");
        assert_eq!(kin.embedding_state, "absent");
        assert_eq!(kin.embedded, 0);
        assert_eq!(kin.eligible, 1460);
        assert_eq!(kin.pending, 1460);
        assert_eq!(kin.degraded, vec!["vector_index".to_string()]);
        assert!(
            compact
                .ranked_by
                .contains("nothing in this graph is embedded"),
            "the surface must name the consequence, not just the state: {}",
            compact.ranked_by
        );
        // And it must be legible in the bytes an agent actually receives, not
        // only in the struct.
        let text = serde_json::to_string(&compact).unwrap();
        assert!(text.contains("\"embedding_state\":\"absent\""), "{text}");
    }

    /// The two projections must not both write `_kin`. The MCP envelope builder
    /// lifts `semantic_coverage` into the `_kin` it attaches, so the MCP
    /// projection carries the coverage object and no envelope of its own; the
    /// CLI projection is the mirror of that.
    #[test]
    fn the_two_projections_carry_opposite_coverage_keys() {
        let result = fixture(2, 2);
        let cli = serde_json::to_value(project(&result)).unwrap();
        let mcp = serde_json::to_value(project_for_mcp(&result)).unwrap();

        assert!(cli.get("_kin").is_some(), "the CLI surface carries _kin");
        assert!(
            cli.get("semantic_coverage").is_none(),
            "and must not also carry the coverage object"
        );
        assert!(
            mcp.get("_kin").is_none(),
            "the MCP surface must leave _kin to the envelope builder"
        );
        assert_eq!(
            mcp["semantic_coverage"]["embedding_state"], "absent",
            "and must carry the coverage object the builder lifts"
        );
        // The clause both boundaries publish.
        assert_eq!(cli["ranked_by"], mcp["ranked_by"]);
    }

    /// Each state gets its own clause. A partial store and an unembedded one
    /// must not read the same, which is the confusion the demo run produced.
    #[test]
    fn every_embedding_state_gets_a_distinct_clause() {
        let clauses: Vec<&str> = [
            EmbeddingState::Present,
            EmbeddingState::Partial,
            EmbeddingState::Absent,
            EmbeddingState::Unknown,
        ]
        .into_iter()
        .map(ranked_by_clause)
        .collect();
        let mut unique = clauses.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), clauses.len(), "two states share a clause");
    }

    /// A result that reported no coverage at all is `unknown`, never `present`.
    #[test]
    fn absent_coverage_reports_unknown_rather_than_guessing() {
        let mut result = fixture(1, 1);
        result.semantic_coverage = None;
        let compact = project(&result);
        let kin = compact.kin.as_ref().unwrap();
        assert_eq!(kin.embedding_state, "unknown");
        assert_eq!(kin.embedded, 0);
        assert_eq!(kin.eligible, 0);
        assert!(compact.ranked_by.contains("could not be read"));
    }

    /// An artifact hit has no entity id, and must not be handed one.
    #[test]
    fn an_artifact_hit_carries_its_path_and_no_dead_id() {
        let mut result = fixture(1, 1);
        result.entities[0].entity_id = String::new();
        result.entities[0].artifact_path = Some("docs/README.md".into());
        let compact = project(&result);
        let value = serde_json::to_value(&compact).unwrap();
        let hit = &value["entities"][0];
        assert!(hit.get("id").is_none(), "an empty id must not serialize");
        assert_eq!(hit["artifact"], "docs/README.md");
    }

    /// `all_fallback` is the difference between "here is your symbol" and "here
    /// are twelve guesses", so it has to survive the projection.
    #[test]
    fn all_fallback_survives_into_the_envelope() {
        let mut result = fixture(3, 3);
        result.all_fallback = true;
        assert!(project(&result).all_fallback);
        // Top level is where kin-mcp's negative logic reads it from, so assert
        // the serialized position and not only the field.
        let value = serde_json::to_value(project_for_mcp(&result)).unwrap();
        assert_eq!(value["all_fallback"], true);
        result.all_fallback = false;
        assert!(!project(&result).all_fallback);
        assert!(
            serde_json::to_value(project(&result))
                .unwrap()
                .get("all_fallback")
                .is_none(),
            "false is the common case and is skipped"
        );
    }

    /// `as_str` and `serde` must spell every variant the same way, or a caller
    /// matching on the compact payload and one matching on the full payload read
    /// different words for the same fact. Compared against serde's own output
    /// rather than against a second hand-written list, which would only prove
    /// the two lists agree.
    #[test]
    fn match_kind_tokens_match_what_serde_writes() {
        for kind in [
            LocateMatchKind::Name,
            LocateMatchKind::Semantic,
            LocateMatchKind::TextFallback,
        ] {
            let serialized = serde_json::to_value(kind).unwrap();
            assert_eq!(
                serialized.as_str().unwrap(),
                kind.as_str(),
                "as_str disagrees with serde for {kind:?}"
            );
        }
    }

    #[test]
    fn scores_round_to_two_decimals() {
        assert_eq!(round_score(570.90843), 570.91);
        assert_eq!(round_score(0.0), 0.0);
        let compact = project(&fixture(1, 1));
        assert_eq!(compact.entities[0].score, 570.91);
    }

    #[test]
    fn surface_tokens_round_trip_and_refuse_a_misspelling() {
        assert_eq!(LocateSurface::parse("full"), Some(LocateSurface::Full));
        assert_eq!(
            LocateSurface::parse("compact"),
            Some(LocateSurface::Compact)
        );
        assert_eq!(LocateSurface::parse("entities"), None);
        assert_eq!(LocateSurface::parse(""), None);
        assert_eq!(LocateSurface::Full.as_str(), "full");
        assert_eq!(LocateSurface::Compact.as_str(), "compact");
        assert_eq!(LocateSurface::default(), LocateSurface::Full);
    }
}
