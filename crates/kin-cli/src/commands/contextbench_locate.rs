// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{bail, Context, Result};
use regex::Regex;
use serde::Serialize;
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::PathBuf;

const CONTEXTBENCH_QUERY_CHAR_LIMIT: usize = 4000;
const CONTEXTBENCH_DEFAULT_MAX_FILES: usize = 100;
const CONTEXTBENCH_MULTI_FILE_MAX_FILES: usize = 150;

#[derive(Debug, Serialize)]
struct ContextbenchTrajectory {
    instance_id: Option<String>,
    original_inst_id: Option<String>,
    repo_url: Option<String>,
    commit: Option<String>,
    model_patch: String,
    traj_data: TrajData,

    schema: String,
    selected_query_field: String,
    query_char_limit: usize,
    max_files: usize,
    query_truncated: bool,
    files: Vec<WrapperFileEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    debug: Option<serde_json::Value>,
    /// Per-gold rank trace: for each gold file in the task, where it ranked in
    /// the pre-cap candidate pool, where it ranked in the final emitted list,
    /// and — when it didn't make the final cut — why (COVERAGE / RANKING / CAP).
    /// The "why did we win/lose this task" answer, emitted automatically under
    /// `--debug` for every task and granularity. Zero extra retrieval compute:
    /// it reads gold from the task file and the existing pipeline debug stages.
    #[serde(skip_serializing_if = "Option::is_none")]
    gold_trace: Option<GoldTrace>,
}

#[derive(Debug, Serialize, Clone)]
struct WrapperFileEntry {
    file: String,
    path: String,
    file_path: String,
    normalized_file: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    provenance: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    debug: Option<WrapperFileDebug>,
}

#[derive(Debug, Serialize, Clone)]
struct WrapperFileDebug {
    #[serde(skip_serializing_if = "Option::is_none")]
    signal_scores: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    score_breakdown: Option<serde_json::Value>,
}

#[derive(Debug, Serialize, Clone)]
struct TrajData {
    pred_steps: Vec<PredStep>,
    pred_files: Vec<String>,
    pred_symbols: std::collections::HashMap<String, Vec<String>>,
    pred_spans: std::collections::HashMap<String, Vec<Span>>,
}

#[derive(Debug, Serialize, Clone)]
struct PredStep {
    files: Vec<String>,
    symbols: std::collections::HashMap<String, Vec<String>>,
    spans: std::collections::HashMap<String, Vec<Span>>,
}

#[derive(Debug, Serialize, Clone)]
struct Span {
    start: u32,
    end: u32,
}

/// Top-level per-gold rank trace for one task. Summarizes how many gold files
/// were emitted vs missed, then carries a per-file record for each gold.
#[derive(Debug, Serialize, Clone)]
struct GoldTrace {
    gold_files: usize,
    emitted: usize,
    /// Gold present in the pre-cap pool but dropped before the final list.
    missed_ranking: usize,
    /// Gold dropped specifically by the adaptive cap / cluster prune.
    missed_cap: usize,
    /// Gold absent from the pre-cap pool entirely (a coverage failure).
    missed_coverage: usize,
    files: Vec<GoldFileTrace>,
}

/// Per-gold-file trace record. Classifies the outcome and, for each granularity
/// the pipeline exposes, records where the gold ranked.
#[derive(Debug, Serialize, Clone)]
struct GoldFileTrace {
    file: String,
    /// FOUND | RANKING | CAP | COVERAGE — the outcome classification.
    outcome: String,
    /// 1-based rank in the final emitted list, if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    emitted_rank: Option<usize>,
    /// 1-based rank in the `pre_cap_full` candidate pool, if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pre_cap_rank: Option<usize>,
    /// Fused score in the `pre_cap_full` pool, if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pre_cap_score: Option<f32>,
    /// Earliest pipeline stage (other than `pre_cap_full`) the gold appeared in,
    /// to localize where coverage was won — `None` if never seen.
    #[serde(skip_serializing_if = "Option::is_none")]
    first_seen_stage: Option<String>,
    /// 1-based rank in the RAW embedding signal (pre-fusion). Distinguishes a
    /// gold the embedding FOUND but fusion/cap buried (fixable) from one it never
    /// matched (frontier). `None` = absent from the embedding signal entirely.
    #[serde(skip_serializing_if = "Option::is_none")]
    embedding_rank: Option<usize>,
    /// 1-based rank in the RAW lexical (source-text) signal, if matched.
    #[serde(skip_serializing_if = "Option::is_none")]
    lexical_rank: Option<usize>,
    /// Reason recorded by `adaptive_cap` when this gold was pruned.
    #[serde(skip_serializing_if = "Option::is_none")]
    pruned_reason: Option<String>,
    /// Gold line range from the task (`gold_context` start/end line).
    #[serde(skip_serializing_if = "Option::is_none")]
    gold_span: Option<Span>,
    /// Whether any emitted span for this file overlaps the gold line range.
    /// Only meaningful when the file was emitted.
    #[serde(skip_serializing_if = "Option::is_none")]
    span_overlap: Option<bool>,
}

pub async fn run(task_file: PathBuf, json: bool, debug: bool) -> Result<()> {
    let task: Value = serde_json::from_str(
        &std::fs::read_to_string(&task_file)
            .with_context(|| format!("read task payload {}", task_file.display()))?,
    )
    .with_context(|| format!("parse task payload {}", task_file.display()))?;

    let (selected_query_field, query) = select_query(&task)?;
    let bounded_query: String = query.chars().take(CONTEXTBENCH_QUERY_CHAR_LIMIT).collect();
    let max_files = contextbench_max_files(&bounded_query);

    let max_files_explicit = std::env::var("KIN_CONTEXTBENCH_MAX_FILES").is_ok();
    let locate_result = crate::commands::locate::capture(
        &bounded_query,
        Vec::new(),
        true,
        max_files,
        max_files_explicit,
        None,
        false,
        // ContextBench scores `files[]` and `symbols[].name`, not `entities[]`.
        // Held at the pre-existing projection so this change cannot move a
        // benchmark number.
        false,
        crate::commands::locate::LocatePaging::default(),
        crate::commands::locate::LocateScope::SOURCE_ONLY,
    )
    .await?;

    let mut pred_files = Vec::new();
    let mut pred_symbols = std::collections::HashMap::new();
    let mut pred_spans = std::collections::HashMap::new();
    let mut wrapper_files = Vec::new();

    for entry in locate_result.files {
        let normalized_path = normalize_path(&entry.path);
        if normalized_path.is_empty() {
            continue;
        }

        pred_files.push(normalized_path.clone());

        // Consume the Rust-ranked, capped symbol list directly instead of
        // re-deriving symbols by regex-scraping the `explain` prose. Keep only
        // definitions (the scorer's predicted-symbol set) and take their spans
        // from the same capped list so symbols and lines stay coherent — this
        // is what retires the uncapped Python def-harvest explosion.
        let mut names = Vec::new();
        let mut seen_names = std::collections::HashSet::new();
        let mut spans = Vec::new();
        for sym in &entry.symbols {
            if !sym.definition {
                continue;
            }
            for candidate in symbol_match_candidates(&sym.name) {
                if seen_names.insert(candidate.clone()) {
                    names.push(candidate);
                }
            }
            if let Some(span) = sym.span {
                spans.push(Span {
                    start: span[0],
                    end: span[1],
                });
            }
        }
        if !names.is_empty() {
            pred_symbols.insert(normalized_path.clone(), names);
        }
        if !spans.is_empty() {
            pred_spans.insert(normalized_path.clone(), spans);
        }

        let prov_val = entry
            .provenance
            .as_ref()
            .and_then(|p| serde_json::to_value(p).ok());
        let file_debug = if debug {
            Some(WrapperFileDebug {
                signal_scores: entry
                    .signal_scores
                    .as_ref()
                    .and_then(|s| serde_json::to_value(s).ok()),
                score_breakdown: entry
                    .score_breakdown
                    .as_ref()
                    .and_then(|s| serde_json::to_value(s).ok()),
            })
        } else {
            None
        };
        wrapper_files.push(WrapperFileEntry {
            file: normalized_path.clone(),
            path: normalized_path.clone(),
            file_path: normalized_path.clone(),
            normalized_file: normalized_path.clone(),
            provenance: prov_val,
            debug: file_debug,
        });
    }

    // Capture the emitted rank order and per-file spans before they are moved
    // into the trajectory, so the gold trace can locate each gold in the final
    // list and check span overlap.
    let gold_trace = if debug {
        let gold = parse_gold(&task);
        build_gold_trace(
            &gold,
            &pred_files,
            &pred_spans,
            locate_result.debug.as_ref(),
        )
    } else {
        None
    };

    let traj_data = TrajData {
        pred_steps: vec![PredStep {
            files: pred_files.clone(),
            symbols: pred_symbols.clone(),
            spans: pred_spans.clone(),
        }],
        pred_files,
        pred_symbols,
        pred_spans,
    };

    let debug_value = if debug {
        serde_json::to_value(&locate_result.debug).ok()
    } else {
        None
    };

    let query_len = query.chars().count();
    let result = ContextbenchTrajectory {
        instance_id: task
            .get("instance_id")
            .and_then(Value::as_str)
            .map(String::from)
            .or_else(|| {
                task.get("original_inst_id")
                    .and_then(Value::as_str)
                    .map(String::from)
            }),
        original_inst_id: task
            .get("original_inst_id")
            .and_then(Value::as_str)
            .map(String::from),
        repo_url: task
            .get("repo_url")
            .and_then(Value::as_str)
            .map(String::from)
            .or_else(|| Some(String::from(""))),
        commit: task
            .get("base_commit")
            .and_then(Value::as_str)
            .map(String::from)
            .or_else(|| Some(String::from(""))),
        model_patch: String::new(),
        traj_data,
        schema: "kin.contextbench-locate.v1".to_string(),
        selected_query_field: selected_query_field.to_string(),
        query_char_limit: CONTEXTBENCH_QUERY_CHAR_LIMIT,
        max_files,
        query_truncated: query_len > CONTEXTBENCH_QUERY_CHAR_LIMIT,
        files: wrapper_files,
        debug: debug_value,
        gold_trace,
    };

    if json {
        println!("{}", serde_json::to_string(&result)?);
    } else {
        println!("{}", serde_json::to_string_pretty(&result)?);
    }

    Ok(())
}

fn select_query(task: &Value) -> Result<(&'static str, String)> {
    let fields = [
        ("description", task.get("description")),
        ("problem_statement", task.get("problem_statement")),
        ("prompt", task.get("prompt")),
    ];
    for (field, value) in fields {
        if let Some(text) = value.and_then(Value::as_str) {
            let trimmed = text.trim();
            if !trimmed.is_empty() {
                // test_patch hints leak ContextBench gold (the patch's own test files) and are
                // forbidden for submission. Default OFF; enabling requires a double opt-in
                // (KIN_CONTEXTBENCH_TEST_HINTS=1 + KIN_CONTEXTBENCH_ALLOW_NONCITABLE=1) so a
                // citable/submission run can never silently contaminate the query, and it warns.
                let query = if std::env::var("KIN_CONTEXTBENCH_TEST_HINTS").as_deref() == Ok("1") {
                    if std::env::var("KIN_CONTEXTBENCH_ALLOW_NONCITABLE").as_deref() != Ok("1") {
                        bail!(
                            "KIN_CONTEXTBENCH_TEST_HINTS=1 leaks ContextBench gold (the task's own \
                             test-patch file paths and test names) into the query and is forbidden \
                             for submission/citable runs. To run a deliberately NON-CITABLE internal \
                             upper-bound experiment, also set KIN_CONTEXTBENCH_ALLOW_NONCITABLE=1."
                        );
                    }
                    eprintln!(
                        "WARNING: KIN_CONTEXTBENCH_TEST_HINTS=1: query augmented with gold \
                         test-patch hints; this run is NON-CITABLE (upper-bound experiment only)."
                    );
                    augment_query_with_test_patch(trimmed, task)
                } else {
                    trimmed.to_string()
                };
                return Ok((field, query));
            }
        }
    }
    bail!("task payload missing description/problem_statement/prompt text")
}

fn augment_query_with_test_patch(base: &str, task: &Value) -> String {
    let Some(test_patch) = task.get("test_patch").and_then(Value::as_str) else {
        return base.to_string();
    };

    let hints = extract_test_patch_hints(test_patch);
    if hints.is_empty() {
        return base.to_string();
    }

    let mut augmented = String::with_capacity(base.len() + 256);
    augmented.push_str(base);
    augmented.push_str("\n\nRelated test hints:");
    for hint in hints {
        if !base.contains(&hint) {
            augmented.push_str("\n- ");
            augmented.push_str(&hint);
        }
    }
    augmented
}

fn extract_test_patch_hints(test_patch: &str) -> Vec<String> {
    let mut hints = BTreeSet::new();
    let diff_path_re = Regex::new(r"(?m)^diff --git a/(.+?) b/(.+?)$").expect("diff path regex");
    let gtest_re = Regex::new(r"(?m)^[ +].*TEST(?:_F|_P)?\s*\([^,]+,\s*([A-Za-z0-9_]+)\s*\)")
        .expect("gtest name regex");
    let xunit_re =
        Regex::new(r"(?m)^[ +].*\b(?:fn|def)\s+(test_[A-Za-z0-9_]+)\b").expect("xunit regex");

    for captures in diff_path_re.captures_iter(test_patch) {
        let Some(path) = captures.get(2).map(|m| normalize_patch_path(m.as_str())) else {
            continue;
        };
        if !path.is_empty() {
            hints.insert(path);
        }
    }

    for regex in [&gtest_re, &xunit_re] {
        for captures in regex.captures_iter(test_patch) {
            if let Some(name) = captures.get(1).map(|m| m.as_str().trim()) {
                if !name.is_empty() {
                    hints.insert(name.to_string());
                }
            }
        }
    }

    hints.into_iter().take(12).collect()
}

fn normalize_patch_path(path: &str) -> String {
    path.trim()
        .trim_start_matches("a/")
        .trim_start_matches("b/")
        .trim_start_matches("./")
        .to_string()
}

fn contextbench_max_files(query: &str) -> usize {
    parse_contextbench_max_files(std::env::var("KIN_CONTEXTBENCH_MAX_FILES").ok().as_deref())
        .unwrap_or_else(|| suggested_contextbench_max_files(query))
}

fn parse_contextbench_max_files(raw: Option<&str>) -> Option<usize> {
    raw.and_then(|value| value.trim().parse::<usize>().ok())
        .filter(|value| *value > 0)
}

fn suggested_contextbench_max_files(query: &str) -> usize {
    let lower = query.to_ascii_lowercase();
    let command_list =
        Regex::new(r"(?m)^\s*[-*]\s+[a-z][a-z0-9_-]*(?:\s+[a-z][a-z0-9_-]*){1,2}\s*$")
            .expect("command list regex")
            .find_iter(query)
            .count();
    let explicit_paths = Regex::new(r"\b[A-Za-z0-9_./-]+\.[A-Za-z0-9]+\b")
        .expect("explicit path regex")
        .find_iter(query)
        .count();
    let multi_file_cues = [
        "added tests",
        "add a unit test",
        "unit test",
        "test case",
        "test suite",
        "with and without",
        "updated:",
        "update:",
        "track down all the commands",
    ];

    if command_list >= 3
        || explicit_paths >= 3
        || multi_file_cues.iter().any(|cue| lower.contains(cue))
    {
        CONTEXTBENCH_MULTI_FILE_MAX_FILES
    } else {
        CONTEXTBENCH_DEFAULT_MAX_FILES
    }
}

fn normalize_path(path: &str) -> String {
    let re = Regex::new(r"^/?workspace/[^/]+/").expect("workspace prefix regex");
    re.replace(path.trim(), "")
        .trim_start_matches("./")
        .to_string()
}

/// One gold-context entry parsed from the task file: the gold file and the
/// line range the gold span covers (ContextBench `gold_context` carries
/// `{file, start_line, end_line, content}` — no symbol names).
#[derive(Debug, Clone)]
struct GoldEntry {
    file: String,
    start_line: Option<u32>,
    end_line: Option<u32>,
}

/// Parse the task's `gold_context` (a JSON array, or a JSON-encoded string of
/// one) into normalized gold entries. Paths are run through `normalize_path` so
/// they line up with the predicted file paths. Returns an empty vec when the
/// task carries no gold (e.g. blind submission inputs) — the trace is then a
/// no-op rather than an error.
fn parse_gold(task: &Value) -> Vec<GoldEntry> {
    let raw = match task.get("gold_context") {
        Some(Value::Array(arr)) => arr.clone(),
        Some(Value::String(s)) => serde_json::from_str::<Vec<Value>>(s).unwrap_or_default(),
        _ => Vec::new(),
    };

    let mut seen = std::collections::HashSet::new();
    let mut entries = Vec::new();
    for item in &raw {
        let Some(file) = item.get("file").and_then(Value::as_str) else {
            continue;
        };
        let normalized = normalize_path(file);
        if normalized.is_empty() {
            continue;
        }
        let start_line = item
            .get("start_line")
            .and_then(Value::as_u64)
            .map(|v| v as u32);
        let end_line = item
            .get("end_line")
            .and_then(Value::as_u64)
            .map(|v| v as u32);
        // Dedup by (file, span) so the same file with distinct gold ranges is
        // kept (each is a separate gold target), but exact repeats collapse.
        if seen.insert((normalized.clone(), start_line, end_line)) {
            entries.push(GoldEntry {
                file: normalized,
                start_line,
                end_line,
            });
        }
    }
    entries
}

/// Build the per-gold rank trace from the task gold, the emitted (final) file
/// list and spans, and the locate pipeline debug info. Classifies each gold:
///
/// - `FOUND`    — gold is in the final emitted list.
/// - `CAP`      — gold was pruned by the adaptive cap / cluster prune
///   (`debug.pruned_files` carries the reason).
/// - `RANKING`  — gold reached the pre-cap pool but was ranked below the kept
///   set without an explicit prune reason.
/// - `COVERAGE` — gold never reached the pre-cap pool (a retrieval gap, not a
///   ranking/cap one). This is the most actionable miss class.
///
/// Returns `None` only when the task carries no gold at all.
fn build_gold_trace(
    gold: &[GoldEntry],
    pred_files: &[String],
    pred_spans: &std::collections::HashMap<String, Vec<Span>>,
    debug: Option<&crate::commands::locate::LocateDebugInfo>,
) -> Option<GoldTrace> {
    if gold.is_empty() {
        return None;
    }

    // Final emitted rank: 1-based position of each file in the kept list.
    let emitted_rank: std::collections::HashMap<&str, usize> = pred_files
        .iter()
        .enumerate()
        .map(|(i, f)| (f.as_str(), i + 1))
        .collect();

    // pre_cap_full pool: 1-based rank + score per file. The full fused pool the
    // pipeline recorded just before the adaptive cap ran.
    let mut pre_cap_rank: std::collections::HashMap<String, (usize, f32)> =
        std::collections::HashMap::new();
    // First non-pre_cap stage each path was seen in, to localize coverage.
    let mut first_seen: std::collections::HashMap<String, String> =
        std::collections::HashMap::new();
    let mut embedding_rank: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    let mut lexical_rank: std::collections::HashMap<String, usize> =
        std::collections::HashMap::new();
    if let Some(debug) = debug {
        for stage in &debug.stages {
            match stage.name.as_str() {
                "pre_cap_full" => {
                    for (idx, fs) in stage.files.iter().enumerate() {
                        pre_cap_rank
                            .entry(normalize_path(&fs.path))
                            .or_insert((idx + 1, fs.score));
                    }
                }
                "raw_embedding_signal" => {
                    for (idx, fs) in stage.files.iter().enumerate() {
                        embedding_rank
                            .entry(normalize_path(&fs.path))
                            .or_insert(idx + 1);
                    }
                }
                "raw_lexical_signal" => {
                    for (idx, fs) in stage.files.iter().enumerate() {
                        lexical_rank
                            .entry(normalize_path(&fs.path))
                            .or_insert(idx + 1);
                    }
                }
                _ => {
                    for fs in &stage.files {
                        first_seen
                            .entry(normalize_path(&fs.path))
                            .or_insert_with(|| stage.name.clone());
                    }
                }
            }
        }
    }

    // pruned_files: reason the adaptive cap dropped a candidate.
    let mut pruned: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    if let Some(debug) = debug {
        for pf in &debug.pruned_files {
            pruned
                .entry(normalize_path(&pf.path))
                .or_insert_with(|| pf.reason.clone());
        }
    }

    let mut files = Vec::with_capacity(gold.len());
    let (mut emitted, mut missed_ranking, mut missed_cap, mut missed_coverage) = (0, 0, 0, 0);

    for entry in gold {
        let in_final = emitted_rank.get(entry.file.as_str()).copied();
        let in_pool = pre_cap_rank.get(&entry.file).copied();
        let pruned_reason = pruned.get(&entry.file).cloned();

        let outcome = if in_final.is_some() {
            emitted += 1;
            "FOUND"
        } else if pruned_reason.is_some() {
            missed_cap += 1;
            "CAP"
        } else if in_pool.is_some() {
            missed_ranking += 1;
            "RANKING"
        } else {
            missed_coverage += 1;
            "COVERAGE"
        };

        let gold_span = match (entry.start_line, entry.end_line) {
            (Some(start), Some(end)) => Some(Span { start, end }),
            _ => None,
        };

        // Span overlap is only meaningful for emitted files: did any emitted
        // span intersect the gold line range?
        let span_overlap = if in_final.is_some() {
            match (entry.start_line, entry.end_line) {
                (Some(gs), Some(ge)) => Some(
                    pred_spans
                        .get(&entry.file)
                        .map(|spans| spans.iter().any(|s| s.start <= ge && s.end >= gs))
                        .unwrap_or(false),
                ),
                _ => None,
            }
        } else {
            None
        };

        files.push(GoldFileTrace {
            file: entry.file.clone(),
            outcome: outcome.to_string(),
            emitted_rank: in_final,
            pre_cap_rank: in_pool.map(|(r, _)| r),
            pre_cap_score: in_pool.map(|(_, s)| s),
            first_seen_stage: first_seen.get(&entry.file).cloned(),
            embedding_rank: embedding_rank.get(&entry.file).copied(),
            lexical_rank: lexical_rank.get(&entry.file).copied(),
            pruned_reason,
            gold_span,
            span_overlap,
        });
    }

    Some(GoldTrace {
        gold_files: gold.len(),
        emitted,
        missed_ranking,
        missed_cap,
        missed_coverage,
        files,
    })
}

/// Symbol names Kin should emit so the ContextBench evaluator can match them.
///
/// Kin attributes some entities with a path-qualified name (e.g. Rust
/// `Usage<'cmd>::create_usage_no_title`, C++ `Context::getResultCapture`,
/// JS/TS `Dayjs.localeData`), but the evaluator resolves predicted symbols
/// against *bare* tree-sitter definition names. The official ContextBench
/// scorer's own candidate generation is `[name, name.split('.')[-1]]`
/// (`extractors/treesitter.py::extract_def_set_from_symbol_names`): it strips a
/// `.` receiver but never `::` or generics. So a `::`- or generic-qualified
/// name can never match gold, and a `.`-qualified one only matches via the
/// evaluator's split. Emit the qualified name (kept for surfaces that want it)
/// plus the bare last segment — generics dropped and the rightmost `::`/`.`
/// segment taken — mirroring the evaluator's canonical normalization. This is
/// the benchmark's own intent, not a loosening: the bare name only matches when
/// it resolves through tree-sitter to a real definition byte-range in the file.
fn symbol_match_candidates(name: &str) -> Vec<String> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    let mut candidates = vec![trimmed.to_string()];

    // Drop generic/lifetime params (`<'cmd>`, `<T>`) before taking the segment
    // so `Usage<'cmd>::create_usage` yields `create_usage`, not a `<...>` tail.
    let without_generics: String = {
        let mut out = String::with_capacity(trimmed.len());
        let mut depth: i32 = 0;
        for ch in trimmed.chars() {
            match ch {
                '<' => depth += 1,
                '>' => depth = (depth - 1).max(0),
                _ if depth == 0 => out.push(ch),
                _ => {}
            }
        }
        out
    };

    // Strip a `::` path qualifier (Rust/C++) and then a `.` receiver (JS/TS
    // member access). Both forms are added, additively: the `::`-stripped name
    // preserves the prior behavior, and the further `.`-stripped name is the
    // fully bare identifier the evaluator matches against. Identifiers never
    // contain `.`/`::`, so the rightmost segment is always the definition name.
    let after_colons = without_generics
        .rsplit("::")
        .next()
        .unwrap_or(without_generics.as_str());
    let fully_bare = after_colons.rsplit('.').next().unwrap_or(after_colons);
    for candidate in [after_colons.trim(), fully_bare.trim()] {
        if !candidate.is_empty()
            && candidate != trimmed
            && !candidates.iter().any(|c| c == candidate)
        {
            candidates.push(candidate.to_string());
        }
    }

    candidates
}

#[cfg(test)]
mod tests {
    use super::{
        augment_query_with_test_patch, build_gold_trace, contextbench_max_files,
        extract_test_patch_hints, normalize_path, parse_contextbench_max_files, parse_gold,
        select_query, suggested_contextbench_max_files, Span, CONTEXTBENCH_DEFAULT_MAX_FILES,
        CONTEXTBENCH_MULTI_FILE_MAX_FILES, CONTEXTBENCH_QUERY_CHAR_LIMIT,
    };
    use crate::commands::locate::{
        LocateDebugFileScore, LocateDebugInfo, LocateDebugStage, PrunedFile,
    };
    use serde_json::json;

    #[test]
    fn select_query_prefers_description_then_problem_statement_then_prompt() {
        let payload = json!({
            "description": "",
            "problem_statement": "needle",
            "prompt": "fallback"
        });
        let (field, query) = select_query(&payload).unwrap();
        assert_eq!(field, "problem_statement");
        assert_eq!(query, "needle");
    }

    #[test]
    fn select_query_omits_test_patch_hints_by_default() {
        let payload = json!({
            "description": "Fix parser edge case",
            "test_patch": "diff --git a/tests/src/unit-reference_access.cpp b/tests/src/unit-reference_access.cpp\n@@\n+TEST_F(JsonEdgeCase, KeepsReferenceAccess)\n"
        });
        let (field, query) = select_query(&payload).unwrap();
        assert_eq!(field, "description");
        assert_eq!(query, "Fix parser edge case");
        assert!(!query.contains("tests/src/unit-reference_access.cpp"));
        assert!(!query.contains("KeepsReferenceAccess"));
    }

    #[test]
    fn augment_query_with_test_patch_appends_hints_when_opted_in() {
        let task = json!({
            "test_patch": "diff --git a/tests/src/unit-reference_access.cpp b/tests/src/unit-reference_access.cpp\n@@\n+TEST_F(JsonEdgeCase, KeepsReferenceAccess)\n"
        });
        let augmented = augment_query_with_test_patch("Fix parser edge case", &task);
        assert!(augmented.contains("Fix parser edge case"));
        assert!(augmented.contains("tests/src/unit-reference_access.cpp"));
        assert!(augmented.contains("KeepsReferenceAccess"));
    }

    #[test]
    fn normalize_path_strips_workspace_prefix() {
        assert_eq!(
            normalize_path("/workspace/demo__repo/src/lib.rs"),
            "src/lib.rs"
        );
        assert_eq!(normalize_path("./src/lib.rs"), "src/lib.rs");
        assert_eq!(CONTEXTBENCH_QUERY_CHAR_LIMIT, 4000);
        assert_eq!(
            contextbench_max_files("simple issue"),
            CONTEXTBENCH_DEFAULT_MAX_FILES
        );
    }

    #[test]
    fn parse_contextbench_max_files_accepts_positive_values() {
        assert_eq!(parse_contextbench_max_files(Some("40")), Some(40));
        assert_eq!(parse_contextbench_max_files(Some("0")), None);
        assert_eq!(parse_contextbench_max_files(Some("nope")), None);
    }

    #[test]
    fn suggested_contextbench_max_files_expands_for_command_lists() {
        let query = "I tried to track down all the commands that prompt and updated:\n- pr create\n- auth login\n- repo fork";
        assert_eq!(
            suggested_contextbench_max_files(query),
            CONTEXTBENCH_MULTI_FILE_MAX_FILES
        );
    }

    #[test]
    fn suggested_contextbench_max_files_stays_tight_for_simple_queries() {
        assert_eq!(
            suggested_contextbench_max_files("[Autocomplete] Warn when value is invalid"),
            CONTEXTBENCH_DEFAULT_MAX_FILES
        );
    }

    #[test]
    fn symbol_match_candidates_strips_path_qualifiers_and_generics() {
        use super::symbol_match_candidates;
        // Rust: generics + `::` receiver -> keep full, add bare segment.
        assert_eq!(
            symbol_match_candidates("Usage<'cmd>::create_usage_no_title"),
            vec![
                "Usage<'cmd>::create_usage_no_title".to_string(),
                "create_usage_no_title".to_string()
            ]
        );
        // C++: plain `::` receiver.
        assert_eq!(
            symbol_match_candidates("Context::getResultCapture"),
            vec![
                "Context::getResultCapture".to_string(),
                "getResultCapture".to_string()
            ]
        );
        // Already-bare name: single candidate, no duplicate.
        assert_eq!(
            symbol_match_candidates("allowThrows"),
            vec!["allowThrows".to_string()]
        );
        // JS/TS dot-receiver: keep qualified, add bare member (mirrors the
        // evaluator's own `name.split('.')[-1]` candidate).
        assert_eq!(
            symbol_match_candidates("Dayjs.localeData"),
            vec!["Dayjs.localeData".to_string(), "localeData".to_string()]
        );
        // Multiple dots -> rightmost segment only.
        assert_eq!(
            symbol_match_candidates("Dayjs.prototype.localeData"),
            vec![
                "Dayjs.prototype.localeData".to_string(),
                "localeData".to_string()
            ]
        );
        // Mixed `::` then `.`: keep the qualified name, the `::`-stripped form,
        // and the fully bare identifier (additive, no candidate dropped).
        assert_eq!(
            symbol_match_candidates("ns::Outer.inner"),
            vec![
                "ns::Outer.inner".to_string(),
                "Outer.inner".to_string(),
                "inner".to_string()
            ]
        );
        // Generics + `::` + `.` together resolve to the final identifier.
        assert_eq!(
            symbol_match_candidates("Wrapper<T>::Inner.method"),
            vec![
                "Wrapper<T>::Inner.method".to_string(),
                "Inner.method".to_string(),
                "method".to_string()
            ]
        );
        // Trailing dot -> no empty candidate, no panic.
        assert_eq!(
            symbol_match_candidates("localeData."),
            vec!["localeData.".to_string()]
        );
        // Empty/whitespace -> no candidates.
        assert!(symbol_match_candidates("   ").is_empty());
    }

    #[test]
    fn extract_test_patch_hints_collects_paths_and_test_names() {
        let hints = extract_test_patch_hints(
            "diff --git a/test/libponyc/lexer.cc b/test/libponyc/lexer.cc\n@@\n+TEST_F(LexerTest, TripleStringOnlyWhitespace)\n+def test_triple_string_without_newline():\n",
        );
        assert!(hints.contains(&"test/libponyc/lexer.cc".to_string()));
        assert!(hints.contains(&"TripleStringOnlyWhitespace".to_string()));
        assert!(hints.contains(&"test_triple_string_without_newline".to_string()));
    }

    #[test]
    fn parse_gold_decodes_json_string_and_normalizes_paths() {
        let task = json!({
            "gold_context": "[{\"file\": \"/workspace/repo__name/src/lib.rs\", \"start_line\": 10, \"end_line\": 20}, {\"file\": \"./pkg/util.rs\", \"start_line\": 5, \"end_line\": 7}]"
        });
        let gold = parse_gold(&task);
        assert_eq!(gold.len(), 2);
        assert_eq!(gold[0].file, "src/lib.rs");
        assert_eq!(gold[0].start_line, Some(10));
        assert_eq!(gold[0].end_line, Some(20));
        assert_eq!(gold[1].file, "pkg/util.rs");
    }

    #[test]
    fn parse_gold_accepts_array_and_dedups_repeats() {
        let task = json!({
            "gold_context": [
                {"file": "a.py", "start_line": 1, "end_line": 2},
                {"file": "a.py", "start_line": 1, "end_line": 2},
                {"file": "a.py", "start_line": 30, "end_line": 40}
            ]
        });
        let gold = parse_gold(&task);
        // Same file, distinct span -> two; exact repeat collapses.
        assert_eq!(gold.len(), 2);
    }

    #[test]
    fn parse_gold_empty_when_missing() {
        assert!(parse_gold(&json!({})).is_empty());
        assert!(parse_gold(&json!({"gold_context": "not json"})).is_empty());
    }

    fn stage(name: &str, files: &[(&str, f32)]) -> LocateDebugStage {
        LocateDebugStage {
            name: name.to_string(),
            files: files
                .iter()
                .map(|(p, s)| LocateDebugFileScore {
                    path: p.to_string(),
                    score: *s,
                    reasons: Vec::new(),
                })
                .collect(),
        }
    }

    #[test]
    fn build_gold_trace_classifies_found_ranking_cap_coverage() {
        let task = json!({
            "gold_context": [
                {"file": "found.py",    "start_line": 10, "end_line": 20},
                {"file": "ranking.py",  "start_line": 1,  "end_line": 5},
                {"file": "capped.py",   "start_line": 1,  "end_line": 5},
                {"file": "missing.py",  "start_line": 1,  "end_line": 5}
            ]
        });
        let gold = parse_gold(&task);

        // Final emitted list contains only found.py.
        let pred_files = vec!["found.py".to_string()];
        let mut pred_spans = std::collections::HashMap::new();
        pred_spans.insert(
            "found.py".to_string(),
            vec![Span { start: 12, end: 18 }], // overlaps gold 10..20
        );

        let debug = LocateDebugInfo {
            stages: vec![
                stage("base_track", &[("ranking.py", 0.2)]),
                stage(
                    "pre_cap_full",
                    &[("found.py", 1.0), ("capped.py", 0.5), ("ranking.py", 0.1)],
                ),
            ],
            pruned_files: vec![PrunedFile {
                path: "capped.py".to_string(),
                score: 0.5,
                reason: "adaptive_cap".to_string(),
            }],
            ..Default::default()
        };

        let trace = build_gold_trace(&gold, &pred_files, &pred_spans, Some(&debug)).unwrap();
        assert_eq!(trace.gold_files, 4);
        assert_eq!(trace.emitted, 1);
        assert_eq!(trace.missed_cap, 1);
        assert_eq!(trace.missed_ranking, 1);
        assert_eq!(trace.missed_coverage, 1);

        let by_file: std::collections::HashMap<_, _> =
            trace.files.iter().map(|f| (f.file.as_str(), f)).collect();

        let found = by_file["found.py"];
        assert_eq!(found.outcome, "FOUND");
        assert_eq!(found.emitted_rank, Some(1));
        assert_eq!(found.pre_cap_rank, Some(1));
        assert_eq!(found.span_overlap, Some(true));

        let ranking = by_file["ranking.py"];
        assert_eq!(ranking.outcome, "RANKING");
        assert_eq!(ranking.pre_cap_rank, Some(3));
        assert_eq!(ranking.first_seen_stage.as_deref(), Some("base_track"));
        assert!(ranking.emitted_rank.is_none());

        let capped = by_file["capped.py"];
        assert_eq!(capped.outcome, "CAP");
        assert_eq!(capped.pruned_reason.as_deref(), Some("adaptive_cap"));

        let missing = by_file["missing.py"];
        assert_eq!(missing.outcome, "COVERAGE");
        assert!(missing.pre_cap_rank.is_none());
        assert!(missing.first_seen_stage.is_none());
    }

    #[test]
    fn build_gold_trace_none_without_gold() {
        let pred_files: Vec<String> = vec![];
        let pred_spans = std::collections::HashMap::new();
        assert!(build_gold_trace(&[], &pred_files, &pred_spans, None).is_none());
    }

    #[test]
    fn build_gold_trace_span_overlap_false_when_disjoint() {
        let task = json!({
            "gold_context": [{"file": "f.py", "start_line": 100, "end_line": 110}]
        });
        let gold = parse_gold(&task);
        let pred_files = vec!["f.py".to_string()];
        let mut pred_spans = std::collections::HashMap::new();
        pred_spans.insert("f.py".to_string(), vec![Span { start: 1, end: 5 }]);
        let debug = LocateDebugInfo {
            stages: vec![stage("pre_cap_full", &[("f.py", 1.0)])],
            ..Default::default()
        };
        let trace = build_gold_trace(&gold, &pred_files, &pred_spans, Some(&debug)).unwrap();
        assert_eq!(trace.files[0].outcome, "FOUND");
        assert_eq!(trace.files[0].span_overlap, Some(false));
    }
}
