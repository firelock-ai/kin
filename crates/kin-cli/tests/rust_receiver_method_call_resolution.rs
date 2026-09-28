// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Acceptance reproduction for the two defects FIR-1581 names: a Rust method
//! call resolving to a same-named method in a crate the caller never sees, and
//! a callee listed in a data-flow walk that nothing calls.
//!
//! The fixture is the shape the ticket measured on a ripgrep clone. A `HiArgs`
//! method imports one builder and calls `.multi_line(..)` on it; a second crate
//! defines a builder spelling the same method; and a third crate defines an
//! enum whose variant is spelled `Ok`. Before the fix the trace from
//! `HiArgs::searcher` listed `RegexMatcherBuilder::multi_line`, and the trace
//! from `HiArgs::checked` listed `ParseResult::Ok` for a `Ok(..)` that is the
//! Rust prelude's.
//!
//! These response-builder integration controls use the real indexing pipeline,
//! admitted Cargo/module authority, cross-file linker, and `InMemoryGraph`.
//! They do not launch the CLI or compile the fixture as a Cargo project.
//! The positive controls sit in the same fixture on purpose: a
//! file that DOES import the regex builder must still reach its `multi_line`,
//! and a file that imports the enum's variants must still reach `ParseResult::Ok`,
//! so a gate that simply deleted those entities from the graph would fail here.

use std::{collections::BTreeMap, sync::Arc};

use kin_cli::commands::refs::{build_refs_response, RefsRequest};
use kin_cli::commands::repository_authority::RequestRepositoryAuthority;
use kin_cli::commands::trace_data_flow::{
    build_trace_data_flow_response, TraceDataFlowRequest, TraceDataFlowResponse, TraceDirection,
};
use kin_db::{GraphSnapshot, InMemoryGraph};
use kin_index::{
    linker::{link_cross_file_with_rust_project, ArtifactIdentityMap},
    rust_project::{RustProjectAuthority, RustProjectLimits},
    FileParseCompletenessMap, FileParseData, IndexPipeline,
};
use kin_model::{
    ArtifactId, EntityKind, EntityStore, FilePathId, RepoPath, ResolvedArtifact, ResolvedTree,
    TreeEntry,
};

/// The crate the focal imports. `multi_line` here is the true callee.
const SEARCHER_RS: &str = r#"
pub struct Searcher {
    multi_line: bool,
}

pub struct SearcherBuilder {
    multi_line: bool,
}

impl SearcherBuilder {
    pub fn new() -> SearcherBuilder {
        SearcherBuilder { multi_line: false }
    }

    pub fn multi_line(&mut self, yes: bool) -> &mut SearcherBuilder {
        self.multi_line = yes;
        self
    }

    pub fn build(&self) -> Searcher {
        Searcher {
            multi_line: self.multi_line,
        }
    }
}
"#;

/// The crate the focal never imports, spelling the same method name. This is
/// the wrong-crate callee the ticket measured.
const MATCHER_RS: &str = r#"
pub struct RegexMatcher {
    multi_line: bool,
}

pub struct RegexMatcherBuilder {
    multi_line: bool,
}

impl RegexMatcherBuilder {
    pub fn new() -> RegexMatcherBuilder {
        RegexMatcherBuilder { multi_line: false }
    }

    pub fn multi_line(&mut self, yes: bool) -> &mut RegexMatcherBuilder {
        self.multi_line = yes;
        self
    }

    pub fn build(&self) -> RegexMatcher {
        RegexMatcher {
            multi_line: self.multi_line,
        }
    }
}
"#;

/// The focal's file. It imports the searcher builder and nothing else, so the
/// only `multi_line` it can dispatch to is that builder's. `checked` returns a
/// prelude `Ok`, and `width` is its own method reached through `self`.
const HIARGS_RS: &str = r#"
use grep::searcher::SearcherBuilder;

pub struct HiArgs {
    multiline: bool,
}

impl HiArgs {
    pub fn searcher(&self) -> Searcher {
        let mut builder = SearcherBuilder::new();
        builder.multi_line(self.multiline);
        builder.build()
    }

    pub fn checked(&self) -> Result<u32, u32> {
        Ok(self.width())
    }

    pub fn width(&self) -> u32 {
        7
    }
}
"#;

/// The positive control for the receiver path. This file DOES import the regex
/// builder, so its `.multi_line(..)` must still resolve to that crate.
const MATCHER_BUILDER_RS: &str = r#"
use grep::regex::RegexMatcherBuilder;

pub struct MatcherBuilder {
    multiline: bool,
}

impl MatcherBuilder {
    pub fn matcher(&self) -> RegexMatcher {
        let mut builder = RegexMatcherBuilder::new();
        builder.multi_line(self.multiline);
        builder.build()
    }
}
"#;

/// The enum whose variant is spelled like the prelude's.
const PARSER_RS: &str = r#"
pub enum ParseResult {
    Ok(u32),
    Err(u32),
}

pub fn parse_width(text: &str) -> u32 {
    text.len() as u32
}
"#;

/// The positive control for the variant path. A glob import of the enum's
/// variants binds `Ok` here, so the bare call must still resolve, and the bare
/// call to the explicitly imported free function must also resolve.
const REPORT_RS: &str = r#"
use crate::parser::parse_width;
use crate::parser::ParseResult::*;

pub fn report(text: &str) -> ParseResult {
    Ok(parse_width(text))
}
"#;

fn ripgrep_shaped_workspace() -> (InMemoryGraph, Vec<FileParseData>) {
    // The CLI target owns parser/report. Other files remain admitted source
    // decoys for the existing receiver-name controls; their directory names do
    // not establish Cargo dependency or module authority.
    let sources = [
        ("Cargo.toml", "[package]\nname='receiver-fixture'\nedition='2021'\n[lib]\npath='crates/cli/src/lib.rs'\n"),
        ("crates/cli/src/lib.rs", "pub mod parser; pub mod report;\n"),
        ("crates/cli/src/parser.rs", PARSER_RS),
        ("crates/cli/src/report.rs", REPORT_RS),
        ("crates/core/src/flags/hiargs.rs", HIARGS_RS),
        ("crates/core/src/matcher_builder.rs", MATCHER_BUILDER_RS),
        ("crates/regex/src/matcher.rs", MATCHER_RS),
        ("crates/searcher/src/searcher/mod.rs", SEARCHER_RS),
    ];
    let mut artifacts = Vec::new();
    let mut blobs = BTreeMap::new();
    let mut files = Vec::new();
    let mut identities = ArtifactIdentityMap::new();
    let mut completeness = FileParseCompletenessMap::new();
    for (path, source) in sources {
        let bytes = source.as_bytes();
        let hash = kin_blobs::digest(bytes);
        let id = ArtifactId::new();
        blobs.insert(hash, bytes.to_vec());
        identities.insert(path.to_owned(), id);
        artifacts.push(ResolvedArtifact::new(
            id,
            RepoPath::from_utf8(path).unwrap(),
            TreeEntry::Blob {
                hash,
                executable: false,
            },
        ));
        if path.ends_with(".rs") {
            let indexed = IndexPipeline::new()
                .index_file_content_with_tests(&FilePathId::new(path), bytes, hash)
                .expect("index exact admitted fixture source")
                .indexed_file;
            completeness.insert(path.into(), indexed.file_layout.parse_completeness);
            files.push(FileParseData {
                file_path: path.into(),
                entities: indexed.entities,
                relations: indexed.extracted_relations,
                imports: indexed.imports,
            });
        }
    }
    let tree = ResolvedTree::from_artifacts(artifacts).unwrap();
    let authority =
        RustProjectAuthority::from_admitted_tree(&tree, RustProjectLimits::default(), |hash| {
            blobs
                .get(&hash)
                .cloned()
                .ok_or("missing fixture CAS body".into())
        })
        .expect("derive the CLI target and its modules from admitted source");
    let entities: Vec<_> = files.iter().flat_map(|file| &file.entities).collect();
    let relations = link_cross_file_with_rust_project(
        &files.iter().collect::<Vec<_>>(),
        &entities,
        &identities,
        &completeness,
        &authority,
    )
    .expect("link exact admitted fixture");

    let graph = InMemoryGraph::from_snapshot(GraphSnapshot {
        resolved_tree: tree,
        ..GraphSnapshot::empty()
    })
    .expect("admit the same tree used by project resolution");
    for entity in entities {
        graph.upsert_entity(entity).expect("upsert entity");
    }
    for relation in &relations {
        // Entity-rooted relations only. This fixture upserts into a store that
        // was never given artifact identities, and the linker mints an
        // artifact-level import edge for every resolved specifier, so admitting
        // those here would fail on an endpoint the fixture deliberately does
        // not hold. Nothing under test reads an artifact edge: every case here
        // is about which entity a receiver call resolves to.
        if relation.src.as_entity().is_none() || relation.dst.as_entity().is_none() {
            continue;
        }
        graph.upsert_relation(relation).expect("upsert relation");
    }
    (graph, files)
}

fn entity_id(files: &[FileParseData], name: &str) -> String {
    // Admitting the real root also creates `mod report`. A trace focal is the
    // callable, never whichever same-named declaration happened to arrive first.
    let candidates: Vec<_> = files
        .iter()
        .flat_map(|file| file.entities.iter())
        .filter(|entity| {
            entity.name == name && matches!(entity.kind, EntityKind::Function | EntityKind::Method)
        })
        .collect();
    assert_eq!(
        candidates.len(),
        1,
        "fixture callable `{name}` must be unique"
    );
    candidates[0].id.0.to_string()
}

fn absent_binding() -> kin_core::LocalRepositoryAuthorityBinding {
    let layout = kin_core::KinLayout::new(std::path::PathBuf::from("/absent/.kin"));
    kin_core::LocalRepositoryAuthorityBinding::from_parts(
        kin_model::RepositoryId::new("absent-rust-receiver-method").unwrap(),
        kin_model::WorkspaceId::new(),
        Arc::new(kin_db::LocalFileBackend::new(layout.kindb_dir())),
    )
}

fn trace_callees(
    graph: &InMemoryGraph,
    files: &[FileParseData],
    focal: &str,
) -> TraceDataFlowResponse {
    build_trace_data_flow_response(
        &RequestRepositoryAuthority::pinned(absent_binding()),
        graph,
        &TraceDataFlowRequest {
            cursor: None,
            focal: entity_id(files, focal),
            depth: Some(3),
            direction: Some(TraceDirection::Calls),
            limit_per_step: Some(25),
            include_body: Some(false),
            max_response_chars: None,
            include_type_edges: None,
            target: None,
        },
    )
    .expect("trace fixture")
}

/// Every entity name `trace_data_flow` reports when it walks callees from
/// `focal`, at the ticket's own depth and direction.
fn callee_chain(graph: &InMemoryGraph, files: &[FileParseData], focal: &str) -> Vec<String> {
    trace_callees(graph, files, focal)
        .chain
        .iter()
        .map(|step| step.entity.entity_name.clone())
        .collect()
}

/// The first defect, reproduced and closed. `hiargs.rs` imports one builder, so
/// `builder.multi_line(..)` can only reach that builder's method. The regex
/// crate's identically named method was reached by matching the bare leaf
/// against every `multi_line` in the repository.
#[test]
fn tracing_calls_reaches_only_the_builder_method_the_focal_file_imports() {
    let (graph, files) = ripgrep_shaped_workspace();
    let chain = callee_chain(&graph, &files, "HiArgs::searcher");

    assert!(
        chain
            .iter()
            .any(|name| name == "SearcherBuilder::multi_line"),
        "the imported builder's method is the true callee and must be walked, got {chain:?}"
    );
    assert!(
        !chain
            .iter()
            .any(|name| name == "RegexMatcherBuilder::multi_line"),
        "a same-named method in a crate this file never imports must not be a callee, got {chain:?}"
    );
    assert!(
        !chain.iter().any(|name| name == "RegexMatcher"),
        "nothing under the wrong-crate edge may be reached, got {chain:?}"
    );
}

/// The receiver path this fix must leave working. `matcher_builder.rs` imports
/// the regex builder and calls the same method through it, so the entity the
/// previous test refuses is exactly what this trace must reach.
#[test]
fn tracing_calls_from_the_importing_caller_still_reaches_the_regex_builder() {
    let (graph, files) = ripgrep_shaped_workspace();
    let chain = callee_chain(&graph, &files, "MatcherBuilder::matcher");

    assert!(
        chain
            .iter()
            .any(|name| name == "RegexMatcherBuilder::multi_line"),
        "`builder.multi_line(..)` in a file importing RegexMatcherBuilder must resolve, got {chain:?}"
    );
    assert!(
        !chain
            .iter()
            .any(|name| name == "SearcherBuilder::multi_line"),
        "the searcher crate's method is not reachable from this file, got {chain:?}"
    );
}

/// The second defect, reproduced and closed. `Ok(self.width())` is the Rust
/// prelude's `Result::Ok`. A repository enum spelling a variant the same way
/// captured the call and carried the walk into a module `hiargs.rs` never names.
#[test]
fn tracing_calls_never_crosses_a_prelude_ok_into_the_parser_module() {
    let (graph, files) = ripgrep_shaped_workspace();
    let chain = callee_chain(&graph, &files, "HiArgs::checked");

    assert!(
        !chain.iter().any(|name| name == "ParseResult::Ok"),
        "a prelude `Ok` must not resolve to a repository enum variant, got {chain:?}"
    );
    assert!(
        chain.iter().any(|name| name == "HiArgs::width"),
        "`self.width()` is the one real call in this body and must be walked, got {chain:?}"
    );
}

/// The variant path this fix must leave working. `report.rs` glob-imports the
/// enum's variants, which is the binding Rust allows, so its bare `Ok(..)` must
/// still resolve. The bare call to a free function beside it is the control that
/// the gate did not simply stop resolving bare Rust calls.
#[test]
fn tracing_calls_from_a_variant_importing_caller_still_reaches_the_variant() {
    let (graph, files) = ripgrep_shaped_workspace();
    let chain = callee_chain(&graph, &files, "report");

    assert!(
        chain.iter().any(|name| name == "ParseResult::Ok"),
        "a file importing the enum's variants must still reach `ParseResult::Ok`, got {chain:?}"
    );
    assert!(
        chain.iter().any(|name| name == "parse_width"),
        "a bare call to an imported free function must still resolve, got {chain:?}"
    );
}

/// `self.width()` inside `impl HiArgs` can only be `HiArgs`'s own `width`, and
/// the edge is proven rather than guessed: the receiver is settled by the
/// syntax, so the destination is the entity the graph already stores under
/// `HiArgs::width`.
#[test]
fn a_self_receiver_call_resolves_to_the_owning_type_at_full_strength() {
    let (graph, files) = ripgrep_shaped_workspace();
    let response = trace_callees(&graph, &files, "HiArgs::checked");
    let step = response
        .chain
        .iter()
        .find(|step| step.entity.entity_name == "HiArgs::width")
        .unwrap_or_else(|| panic!("`self.width()` must be walked, got {:?}", response.chain));

    assert_eq!(
        step.resolution, "type_resolved",
        "a receiver the syntax settles proves its destination, got {}",
        step.resolution
    );
}

/// `find_references` and `trace_data_flow` read the same edges, so the two must
/// agree about who calls the regex builder's method: the file importing it does,
/// and the file importing the searcher builder never did.
#[test]
fn find_references_on_the_regex_builder_method_lists_only_the_importing_caller() {
    let (graph, files) = ripgrep_shaped_workspace();
    let layout = kin_core::KinLayout::new(std::path::PathBuf::from("/absent/.kin"));
    let response = build_refs_response(
        &layout,
        &graph,
        &RefsRequest {
            entity: entity_id(&files, "RegexMatcherBuilder::multi_line"),
            kind: "all".to_string(),
        },
        &kin_mcp::Envelope::daemon().with_health(&serde_json::json!({
            "initialized": true, "graph_loaded": true,
            "graph_entity_count": 4, "graph_generation": 1,
        })),
    )
    .expect("refs fixture");
    let listing = response.lines.join("\n");

    assert!(
        listing.contains("MatcherBuilder::matcher"),
        "the importing caller must be listed, got:\n{listing}"
    );
    assert!(
        !listing.contains("HiArgs::searcher"),
        "a file that never imports this builder must not appear as a caller, got:\n{listing}"
    );
}

/// A chain narrowed by a resolution gate must not read as a complete proven
/// one. `HiArgs::searcher` still reaches its callees by matching a bare method
/// leaf, so the response says how many of its steps rest on that.
#[test]
fn the_response_counts_the_steps_it_reached_by_name_alone() {
    let (graph, files) = ripgrep_shaped_workspace();
    let response = trace_callees(&graph, &files, "HiArgs::searcher");

    let name_only = response
        .chain
        .iter()
        .filter(|step| step.resolution == "name_only")
        .count();
    assert!(
        name_only > 0,
        "this fixture is only a control while some hop is name-only, got {:?}",
        response.chain
    );
    assert_eq!(
        response.unproven_steps, name_only,
        "the response must count every name-only hop it returned"
    );
    assert!(
        response.degradations.iter().any(|degradation| {
            degradation.component == "call_resolution" && degradation.reason == "name_only_steps"
        }),
        "a chain resting on name-only hops must disclose that, got {:?}",
        response.degradations
    );
}

/// The proven case, so the disclosure above cannot be a constant. Every hop out
/// of `HiArgs::checked` is settled by the syntax, so nothing is counted and no
/// degradation is raised.
#[test]
fn a_fully_proven_chain_raises_no_name_only_disclosure() {
    let (graph, files) = ripgrep_shaped_workspace();
    let response = trace_callees(&graph, &files, "HiArgs::checked");

    assert_eq!(
        response.unproven_steps, 0,
        "every hop here is proven, got {:?}",
        response.chain
    );
    assert!(
        !response
            .degradations
            .iter()
            .any(|degradation| degradation.component == "call_resolution"),
        "a proven chain must raise no resolution degradation, got {:?}",
        response.degradations
    );
}
