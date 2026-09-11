// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! One name, five definitions: every read command has to answer about the same
//! one, say that it chose and how, and point at the line the function is on.
//!
//! The fixture is the shape a recorded demo hit on this repository:
//! `human_bytes` is defined in five files, and in `src/cache.rs` it sits under
//! a gated `use` block, a `#[cfg]` attribute and a doc comment. `kin refs` and
//! `kin impact` used to choose among the five by two different rules and say
//! nothing about it (FIR-3505), and a store whose `cache.rs` records were never
//! re-derived pointed six lines above the function, at its imports (FIR-3548).
//! Everything runs through the real Rust parser and the real cross-file linker.

use kin_cli::commands::impact::{build_impact_response, ImpactRequest};
use kin_cli::commands::refs::{build_refs_response, RefsRequest};
use kin_db::InMemoryGraph;
use kin_index::{link_cross_file, FileParseData};
use kin_model::{
    ArtifactId, Entity, EntityStore, FilePathId, Hash256, LocatedEntry, RepoPath, TransactionDelta,
    TreeDelta, TreeEntry,
};
use kin_parser::{LanguageAdapter, RustAdapter};

/// The function sits under imports, an attribute and a doc comment, the way
/// `crates/kin-cli/src/commands/cache.rs` holds its `human_bytes`.
const CACHE_RS: &str = r#"//! Inspect and bound the embedding cache.

#[cfg(feature = "embeddings")]
use std::path::{Path, PathBuf};

use anyhow::Result;

#[cfg(feature = "embeddings")]
use kin_db::embed::cache_admin::{
    self, AgeBucket, CacheStats,
};

/// Render a binary byte count with IEC unit labels.
#[cfg(feature = "embeddings")]
fn human_bytes(bytes: u64) -> String {
    format!("{bytes} B")
}

pub fn print_status(bytes: u64) -> String {
    human_bytes(bytes)
}
"#;

const BYTE_FMT_RS: &str = r#"pub(super) fn human_bytes(bytes: u64) -> String {
    format!("{bytes} MiB")
}

pub fn memory_line(bytes: u64) -> String {
    human_bytes(bytes)
}
"#;

const INIT_ATTEMPT_RS: &str = r#"pub fn human_bytes(bytes: u64) -> String {
    format!("{bytes} bytes")
}

pub fn doctor_row(bytes: u64) -> String {
    human_bytes(bytes)
}
"#;

const MEMORY_PRESSURE_RS: &str = r#"fn human_bytes(bytes: u64) -> String {
    format!("{bytes}")
}

pub fn describe(bytes: u64) -> String {
    human_bytes(bytes)
}
"#;

const SPAWN_RS: &str = r#"fn human_bytes(bytes: u64) -> String {
    format!("{bytes} b")
}

pub fn cause_sentence(bytes: u64) -> String {
    human_bytes(bytes)
}
"#;

const FILES: [(&str, &str); 5] = [
    ("src/byte_fmt.rs", BYTE_FMT_RS),
    ("src/cache.rs", CACHE_RS),
    ("src/init_attempt.rs", INIT_ATTEMPT_RS),
    ("src/memory_pressure.rs", MEMORY_PRESSURE_RS),
    ("src/spawn.rs", SPAWN_RS),
];

fn parse_rs(file_path: &str, source: &str) -> FileParseData {
    let adapter = RustAdapter;
    let file_id = FilePathId::new(file_path);
    let bytes = source.as_bytes();
    let tree = adapter.parse(bytes).expect("parse fixture");
    let output = adapter.extract(&tree, bytes, &file_id).expect("extract");
    let entities: Vec<Entity> = output
        .entities
        .into_iter()
        .map(|entity| entity.into_entity_with_source(adapter.language_id(), &file_id, Some(bytes)))
        .collect();
    FileParseData {
        file_path: file_path.to_string(),
        entities,
        relations: output.relations,
        imports: output.imports,
    }
}

/// The fixture repository, ingested in the given file order.
fn twins_graph(order: &[(&str, &str)]) -> InMemoryGraph {
    let files: Vec<FileParseData> = order
        .iter()
        .map(|(path, source)| parse_rs(path, source))
        .collect();
    let artifact_ids = files
        .iter()
        .map(|file| (file.file_path.clone(), ArtifactId::new()))
        .collect();
    let relations = link_cross_file(&files, &artifact_ids).expect("link fixture");
    let graph = InMemoryGraph::new();
    for entity in files.iter().flat_map(|file| file.entities.iter()) {
        graph.upsert_entity(entity).expect("upsert entity");
    }
    for relation in &relations {
        graph.upsert_relation(relation).expect("upsert relation");
    }
    graph
}

/// The 1-based line of the first line in `source` containing `needle`.
fn line_of(source: &str, needle: &str) -> u32 {
    let index = source
        .lines()
        .position(|line| line.contains(needle))
        .unwrap_or_else(|| panic!("{needle:?} is not in the fixture"));
    u32::try_from(index + 1).unwrap()
}

fn human_bytes_twins(graph: &InMemoryGraph) -> Vec<Entity> {
    graph
        .query_entities(&kin_model::EntityFilter {
            name_pattern: Some("human_bytes".to_string()),
            ..Default::default()
        })
        .unwrap()
        .into_iter()
        .filter(|entity| entity.name == "human_bytes" && entity.file_origin.is_some())
        .collect()
}

fn healthy_envelope() -> kin_mcp::Envelope {
    kin_mcp::Envelope::daemon().with_health(&serde_json::json!({
        "initialized": true,
        "graph_loaded": true,
        "graph_entity_count": 10,
        "graph_generation": 1,
    }))
}

fn refs_response(graph: &InMemoryGraph, entity: &str) -> kin_cli::commands::refs::RefsResponse {
    let dir = tempfile::tempdir().unwrap();
    let layout = kin_core::KinLayout::new(dir.path().join(".kin"));
    build_refs_response(
        &layout,
        graph,
        &RefsRequest {
            entity: entity.to_string(),
            kind: "all".to_string(),
        },
        &healthy_envelope(),
    )
    .expect("refs response")
}

async fn impact_result(
    graph: &InMemoryGraph,
    entity: &str,
    file: Option<&str>,
) -> anyhow::Result<kin_cli::commands::impact::ImpactResponse> {
    let dir = tempfile::tempdir().unwrap();
    let layout = kin_core::KinLayout::new(dir.path().join(".kin"));
    build_impact_response(
        &layout,
        graph,
        &ImpactRequest {
            entity: entity.to_string(),
            depth: 1,
            file: file.map(ToOwned::to_owned),
            kind: None,
            signature: None,
            require_unique: false,
        },
        &healthy_envelope(),
    )
    .await
}

/// The file an answer's first line points at, read off `@ <path>[:line]`.
fn header_file(first_line: &str) -> String {
    let location = first_line
        .rsplit(" @ ")
        .next()
        .unwrap_or_else(|| panic!("no location in {first_line:?}"));
    location
        .trim_end_matches(':')
        .split([':', ' '])
        .next()
        .unwrap()
        .to_string()
}

/// FIR-3548. The pointer is the function's own line, read from its span, and
/// never the gated `use` block six lines above it.
#[tokio::test]
async fn a_function_under_imports_is_pointed_at_on_its_own_line() {
    let graph = twins_graph(&FILES);
    let fn_line = line_of(CACHE_RS, "fn human_bytes(");
    let use_line = line_of(CACHE_RS, "use kin_db::embed::cache_admin");
    assert!(use_line < fn_line, "the fixture must put the imports first");

    let impact = impact_result(&graph, "human_bytes", Some("src/cache.rs"))
        .await
        .expect("impact");
    let header = &impact.lines[0];
    assert!(
        header.ends_with(&format!("@ src/cache.rs:{fn_line}:")),
        "impact must point at the function's line {fn_line}: {header}"
    );
    assert!(
        !header.contains(&format!("src/cache.rs:{use_line}")),
        "impact must never point at the import block: {header}"
    );

    let refs = refs_response(&graph, "human_bytes@src/cache.rs");
    assert!(
        refs.lines[0].ends_with(&format!("@ src/cache.rs:{fn_line}")),
        "refs must point at the same line: {:?}",
        refs.lines[0]
    );
}

/// Give the `cache.rs` twin a recorded source digest and put `tree_blob` in the
/// graph's tree at its path.
fn record_digest_and_tree(graph: &InMemoryGraph, span_blob: [u8; 32], tree_blob: [u8; 32]) {
    let mut entity = human_bytes_twins(graph)
        .into_iter()
        .find(|entity| entity.file_origin.as_ref().map(|f| f.0.as_str()) == Some("src/cache.rs"))
        .expect("the cache.rs twin");
    let hex: String = span_blob.iter().map(|byte| format!("{byte:02x}")).collect();
    entity
        .metadata
        .extra
        .insert("blob_hash".to_string(), serde_json::Value::String(hex));
    graph.upsert_entity(&entity).expect("re-record the entity");
    graph
        .apply_transaction_delta(&TransactionDelta {
            tree_deltas: vec![TreeDelta::Added {
                artifact_id: ArtifactId::new(),
                new: LocatedEntry::new(
                    RepoPath::from_utf8("src/cache.rs").unwrap(),
                    TreeEntry::blob(Hash256::from_bytes(tree_blob), false),
                ),
            }],
            ..TransactionDelta::default()
        })
        .expect("admit the tree entry");
}

/// FIR-3548, the store the demo ran against. The entity's span was measured
/// against one version of the file and the graph's tree now holds another, so
/// the line would land wherever the function used to be. The answer marks the
/// pointer stale and says why instead of printing that line.
#[tokio::test]
async fn a_span_from_an_older_version_of_the_file_is_marked_stale() {
    let fn_line = line_of(CACHE_RS, "fn human_bytes(");

    let current = twins_graph(&FILES);
    record_digest_and_tree(&current, [0xaa; 32], [0xaa; 32]);
    let agreeing = impact_result(&current, "human_bytes", Some("src/cache.rs"))
        .await
        .expect("impact");
    assert!(
        agreeing.lines[0].ends_with(&format!("@ src/cache.rs:{fn_line}:")),
        "a span measured against the blob the tree holds keeps its line: {}",
        agreeing.lines[0]
    );

    let stale = twins_graph(&FILES);
    record_digest_and_tree(&stale, [0xaa; 32], [0xbb; 32]);
    let impact = impact_result(&stale, "human_bytes", Some("src/cache.rs"))
        .await
        .expect("impact");
    let header = &impact.lines[0];
    assert!(
        header.ends_with("@ src/cache.rs (span stale):"),
        "a span from another version of the file must be marked, not printed: {header}"
    );
    assert!(
        !header.contains(&format!("src/cache.rs:{fn_line}")),
        "no line may be printed for a stale span: {header}"
    );
    let joined = impact.lines.join("\n");
    assert!(
        joined.contains("older version of that file than the graph now holds"),
        "the answer must say why the line is missing: {joined}"
    );

    let refs = refs_response(&stale, "human_bytes@src/cache.rs");
    assert!(
        refs.lines[0].ends_with("@ src/cache.rs (span stale)"),
        "refs reads the same pointer: {:?}",
        refs.lines[0]
    );
}

/// FIR-3505. A bare name reaching five definitions: `kin refs` and `kin impact`
/// answer about the same one, whatever order the store ingested them in, and
/// both list every candidate with its id and the rule that chose.
#[tokio::test]
async fn refs_and_impact_choose_the_same_twin_and_name_every_candidate() {
    let forward = twins_graph(&FILES);
    let mut reversed_files = FILES;
    reversed_files.reverse();
    let reversed = twins_graph(&reversed_files);

    let mut chosen = Vec::new();
    for graph in [&forward, &reversed] {
        let twins = human_bytes_twins(graph);
        assert_eq!(twins.len(), 5, "the fixture defines five twins");

        let refs = refs_response(graph, "human_bytes");
        assert!(refs.error.is_none(), "{:?}", refs.lines);
        let impact = impact_result(graph, "human_bytes", None)
            .await
            .expect("impact");
        let refs_file = header_file(&refs.lines[0]);
        let impact_file = header_file(&impact.lines[0]);
        assert_eq!(
            refs_file, impact_file,
            "refs and impact must answer about the same twin"
        );

        for answer in [refs.lines.join("\n"), impact.lines.join("\n")] {
            assert!(
                answer.contains("'human_bytes' names 5 entities"),
                "the answer must say it chose: {answer}"
            );
            for twin in &twins {
                assert!(
                    answer.contains(&twin.id.to_string()),
                    "every candidate's id must be listed: {answer}"
                );
            }
            assert!(
                answer.contains("a definition before a declaration"),
                "the rule must be stated: {answer}"
            );
        }
        chosen.push(refs_file);
    }
    assert_eq!(
        chosen[0], chosen[1],
        "the choice must not move with the order the store listed the twins in"
    );
}

/// The same pin reaches the same entity whether it is spelled as a suffix on
/// the name or as a flag, and in either command.
#[tokio::test]
async fn one_pin_reaches_one_entity_in_every_spelling_and_command() {
    let graph = twins_graph(&FILES);
    let fn_line = line_of(INIT_ATTEMPT_RS, "fn human_bytes(");
    let expected = format!("src/init_attempt.rs:{fn_line}");

    let by_flag = impact_result(&graph, "human_bytes", Some("src/init_attempt.rs"))
        .await
        .expect("impact");
    let by_suffix = impact_result(&graph, "human_bytes#function@src/init_attempt.rs", None)
        .await
        .expect("impact");
    let refs = refs_response(&graph, "human_bytes@src/init_attempt.rs");
    for first in [&by_flag.lines[0], &by_suffix.lines[0], &refs.lines[0]] {
        assert!(first.contains(&expected), "{first}");
    }
    for answer in [&by_flag.lines, &by_suffix.lines, &refs.lines] {
        assert!(
            !answer.join("\n").contains("names 5 entities"),
            "a pinned query chose nothing, so it carries no candidate note: {answer:?}"
        );
    }
}

/// A pin spelled twice with two values is refused rather than resolved one way
/// or the other.
#[tokio::test]
async fn a_pin_given_twice_with_two_values_is_refused() {
    let graph = twins_graph(&FILES);
    let error = impact_result(&graph, "human_bytes@src/cache.rs", Some("src/spawn.rs"))
        .await
        .expect_err("two values for one pin must be refused");
    assert!(
        format!("{error:#}").contains("given twice"),
        "the refusal must say what was wrong: {error:#}"
    );
}

/// A name that is only part of the names it reaches names none of them, so
/// `kin refs` asks which one rather than answering about a guess.
#[test]
fn a_partial_name_reaching_several_entities_is_asked_about_not_guessed() {
    let graph = twins_graph(&FILES);
    let refs = refs_response(&graph, "human_byte");
    let error = refs
        .error
        .expect("a partial name with twins must be refused");
    assert!(
        error.contains("No entity is named 'human_byte' exactly"),
        "{error}"
    );
    for twin in human_bytes_twins(&graph) {
        assert!(error.contains(&twin.id.to_string()), "{error}");
    }
}
