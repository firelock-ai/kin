// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Per-language measurement of `RelationEvidence::source_span` population.
//!
//! A consumer that edits source at a relation's site (rename, codemod, an
//! agent asked to change every caller) can only act on edges whose evidence
//! names a span. `find_references` already serves those spans as
//! `reference_lines`, so how many edges actually carry one decides whether a
//! span-driven edit visits every site or silently skips some. That number had
//! never been measured, and a rate cannot be read off the parser sources: the
//! adapters, the same-file resolver, and the cross-file linker each build
//! evidence separately.
//!
//! This measures it through the real ingest path rather than asserting what
//! the code looks like. Every fixture file goes through
//! `IndexPipeline::index_file_content_with_tests` (the same-file arm, which is
//! what historical and ref-scoped rebuilds call) and then through
//! `IndexPipeline::resolve_cross_file` (the cross-file arm). Relations from
//! both arms are merged by relation id, because an edge is span-backed if any
//! arm recorded a site for it.
//!
//! Reproduce, with the table on stdout:
//!
//! ```text
//! cargo test -p kin-index --test relation_evidence_span_coverage -- --nocapture
//! ```
//!
//! The same counters can be pointed at a real tree instead of these fixtures:
//!
//! ```text
//! KIN_SPAN_COVERAGE_CORPUS=/path/to/repo \
//!   cargo test -p kin-index --test relation_evidence_span_coverage \
//!   -- --ignored --nocapture corpus
//! ```

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use kin_index::linker::ArtifactIdentityMap;
use kin_index::{FileParseData, IndexPipeline};
use kin_model::{ArtifactId, FilePathId, Relation, RelationEvidence, RelationId};

/// A two-file program in one language. Two files so the cross-file linker arm
/// has something to resolve, and every fixture repeats at least one call so
/// multi-site edges are exercised rather than assumed away.
///
/// The calls are written cross-file on purpose. A bare call to a qualified
/// sibling in the *same* file (`render()` calling `compute()` inside one class)
/// used to resolve to no edge at all in every language checked, which would make
/// a fixture look span-less when it was really edge-less. FIR-1826 closed that
/// for the languages where a bare call carries an implicit receiver, so the Java
/// and C# fixtures below now yield that edge too and their `min_calls` floors
/// count it. The cross-file shape stays because it is the one every language
/// resolves, so a fixture's span rate is never confounded by a binding rule.
struct Fixture {
    language: &'static str,
    /// Fewest relations this fixture must yield. A language that silently stops
    /// producing edges would otherwise report 0 spans of 0 relations, which
    /// reads as a measured rate and is not one. Set below the observed count so
    /// ordinary extraction improvements do not trip it, high enough that a
    /// collapse does.
    min_relations: usize,
    /// Fewest `Calls` edges. Zero only where the language has no call syntax to
    /// extract.
    min_calls: usize,
    /// Fewest `Calls` edges that must carry a `RelationEvidence::source_span`.
    ///
    /// Zero for an adapter that does not record call sites yet. A per-language
    /// floor is what a bare total cannot give: a total alone stays satisfied
    /// while Python drops to none and another language makes up the difference,
    /// which is exactly the regression this file exists to catch.
    min_calls_with_span: usize,
    files: &'static [(&'static str, &'static str)],
}

const FIXTURES: &[Fixture] = &[
    Fixture {
        language: "Rust",
        min_relations: 3,
        min_calls: 1,
        min_calls_with_span: 0,
        files: &[
            (
                "defs.rs",
                "pub struct Widget;\n\
                 \n\
                 impl Widget {\n\
                 \x20   pub fn render(&self) -> u32 { helper() }\n\
                 }\n\
                 \n\
                 pub fn compute() -> u32 { 1 }\n\
                 \n\
                 pub fn helper() -> u32 { 2 }\n",
            ),
            (
                "caller.rs",
                "pub fn run() -> u32 {\n\
                 \x20   let first = compute();\n\
                 \x20   let second = compute();\n\
                 \x20   first + second\n\
                 }\n",
            ),
        ],
    },
    Fixture {
        language: "TypeScript",
        min_relations: 3,
        min_calls: 1,
        min_calls_with_span: 1,
        files: &[
            (
                "defs.ts",
                "export function compute(): number { return 1; }\n\
                 export class Widget {\n\
                 \x20 render(): number { return compute(); }\n\
                 }\n",
            ),
            (
                "caller.ts",
                "import { compute } from \"./defs\";\n\
                 export function run(): number {\n\
                 \x20 const first = compute();\n\
                 \x20 const second = compute();\n\
                 \x20 return first + second;\n\
                 }\n",
            ),
        ],
    },
    Fixture {
        language: "JavaScript",
        min_relations: 3,
        min_calls: 1,
        min_calls_with_span: 1,
        files: &[
            (
                "defs.js",
                "export function compute() { return 1; }\n\
                 export class Widget {\n\
                 \x20 render() { return compute(); }\n\
                 }\n",
            ),
            (
                "caller.js",
                "import { compute } from \"./defs\";\n\
                 export function run() {\n\
                 \x20 const first = compute();\n\
                 \x20 const second = compute();\n\
                 \x20 return first + second;\n\
                 }\n",
            ),
        ],
    },
    Fixture {
        language: "Python",
        min_relations: 3,
        min_calls: 1,
        min_calls_with_span: 1,
        files: &[
            (
                "defs.py",
                "def compute():\n\
                 \x20   return 1\n\
                 \n\
                 class Widget:\n\
                 \x20   def render(self):\n\
                 \x20       return compute()\n",
            ),
            (
                "caller.py",
                "from defs import compute\n\
                 \n\
                 def run():\n\
                 \x20   first = compute()\n\
                 \x20   second = compute()\n\
                 \x20   return first + second\n",
            ),
        ],
    },
    Fixture {
        language: "Go",
        min_relations: 2,
        min_calls: 1,
        min_calls_with_span: 0,
        files: &[
            (
                "defs.go",
                "package main\n\
                 \n\
                 func compute() int { return 1 }\n\
                 \n\
                 func helper() int { return compute() }\n",
            ),
            (
                "caller.go",
                "package main\n\
                 \n\
                 func run() int {\n\
                 \x20   first := compute()\n\
                 \x20   second := compute()\n\
                 \x20   return first + second\n\
                 }\n",
            ),
        ],
    },
    Fixture {
        language: "Java",
        min_relations: 4,
        // Two: the cross-file `compute()` every language resolves, and the
        // same-file `render()` -> `compute()` sibling FIR-1826 added.
        min_calls: 2,
        min_calls_with_span: 0,
        files: &[
            (
                "Defs.java",
                "class Defs {\n\
                 \x20 static int compute() { return 1; }\n\
                 \x20 int render() { return compute(); }\n\
                 }\n",
            ),
            (
                "Caller.java",
                "class Caller {\n\
                 \x20 int run() {\n\
                 \x20   int first = compute();\n\
                 \x20   int second = compute();\n\
                 \x20   return first + second;\n\
                 \x20 }\n\
                 }\n",
            ),
        ],
    },
    Fixture {
        language: "CSharp",
        min_relations: 5,
        // Two, for the same reason as Java above.
        min_calls: 2,
        min_calls_with_span: 0,
        files: &[
            (
                "Defs.cs",
                "namespace N { class Defs {\n\
                 \x20 public static int Compute() { return 1; }\n\
                 \x20 public int Render() { return Compute(); }\n\
                 } }\n",
            ),
            (
                "Caller.cs",
                "namespace N { class Caller {\n\
                 \x20 public int Run() {\n\
                 \x20   var first = Compute();\n\
                 \x20   var second = Compute();\n\
                 \x20   return first + second;\n\
                 \x20 }\n\
                 } }\n",
            ),
        ],
    },
    Fixture {
        language: "C",
        min_relations: 2,
        min_calls: 1,
        min_calls_with_span: 0,
        files: &[
            (
                "defs.c",
                "int compute(void) { return 1; }\n\
                 \n\
                 int helper(void) { return compute(); }\n",
            ),
            (
                "caller.c",
                "int run(void) {\n\
                 \x20   int first = compute();\n\
                 \x20   int second = compute();\n\
                 \x20   return first + second;\n\
                 }\n",
            ),
        ],
    },
    Fixture {
        language: "Cpp",
        min_relations: 3,
        min_calls: 1,
        min_calls_with_span: 0,
        files: &[
            (
                "defs.cpp",
                "int compute() { return 1; }\n\
                 \n\
                 class Widget {\n\
                 public:\n\
                 \x20   int render() { return compute(); }\n\
                 };\n",
            ),
            (
                "caller.cpp",
                "int run() {\n\
                 \x20   int first = compute();\n\
                 \x20   int second = compute();\n\
                 \x20   return first + second;\n\
                 }\n",
            ),
        ],
    },
    Fixture {
        language: "Ruby",
        min_relations: 3,
        min_calls: 1,
        min_calls_with_span: 0,
        files: &[
            (
                "defs.rb",
                "class Defs\n\
                 \x20   def compute\n\
                 \x20       1\n\
                 \x20   end\n\
                 \x20   def render\n\
                 \x20       compute()\n\
                 \x20   end\n\
                 end\n",
            ),
            (
                "caller.rb",
                "class Caller\n\
                 \x20   def run\n\
                 \x20       compute()\n\
                 \x20       compute()\n\
                 \x20   end\n\
                 end\n",
            ),
        ],
    },
    Fixture {
        language: "Php",
        min_relations: 3,
        min_calls: 1,
        min_calls_with_span: 0,
        files: &[
            (
                "defs.php",
                "<?php\n\
                 function compute() { return 1; }\n\
                 class Widget {\n\
                 \x20   public function render() { return compute(); }\n\
                 }\n",
            ),
            (
                "caller.php",
                "<?php\n\
                 function run() {\n\
                 \x20   $first = compute();\n\
                 \x20   $second = compute();\n\
                 \x20   return $first + $second;\n\
                 }\n",
            ),
        ],
    },
    Fixture {
        language: "Kotlin",
        min_relations: 3,
        min_calls: 1,
        min_calls_with_span: 0,
        files: &[
            (
                "defs.kt",
                "fun compute(): Int { return 1 }\n\
                 \n\
                 class Widget {\n\
                 \x20   fun render(): Int { return compute() }\n\
                 }\n",
            ),
            (
                "caller.kt",
                "fun run(): Int {\n\
                 \x20   val first = compute()\n\
                 \x20   val second = compute()\n\
                 \x20   return first + second\n\
                 }\n",
            ),
        ],
    },
    Fixture {
        language: "Swift",
        min_relations: 3,
        min_calls: 1,
        min_calls_with_span: 0,
        files: &[
            (
                "defs.swift",
                "func compute() -> Int { return 1 }\n\
                 \n\
                 class Widget {\n\
                 \x20   func render() -> Int { return compute() }\n\
                 }\n",
            ),
            (
                "caller.swift",
                "func run() -> Int {\n\
                 \x20   let first = compute()\n\
                 \x20   let second = compute()\n\
                 \x20   return first + second\n\
                 }\n",
            ),
        ],
    },
    // HCL's floors are zero because it genuinely contributes no entity-level
    // edge: the adapter's relations name a module source path and a provider
    // string, neither of which is an entity, so nothing survives resolution.
    // Its row is here so the table covers the whole adapter fleet rather than
    // quietly omitting the one language with nothing to report.
    Fixture {
        language: "Hcl",
        min_relations: 0,
        min_calls: 0,
        min_calls_with_span: 0,
        files: &[
            (
                "defs.tf",
                "resource \"aws_s3_bucket\" \"assets\" {\n\
                 \x20 bucket = \"assets\"\n\
                 }\n",
            ),
            (
                "caller.tf",
                "resource \"aws_s3_bucket_policy\" \"assets\" {\n\
                 \x20 bucket = aws_s3_bucket.assets.id\n\
                 }\n",
            ),
        ],
    },
];

/// Span population for one language, plus what evidence carries *instead* of a
/// span. The alternatives matter: a rename planner denied a span has to be told
/// what it does get.
#[derive(Default)]
struct Counts {
    relations: usize,
    relations_with_span: usize,
    evidence_records: usize,
    evidence_with_span: usize,
    relations_without_evidence: usize,
    with_parser_rule: usize,
    with_token: usize,
    with_source_path: usize,
    with_resolved_path: usize,
    with_call_shape: usize,
    /// Relation kind -> (relations, relations carrying a span).
    by_kind: BTreeMap<String, (usize, usize)>,
}

impl Counts {
    fn observe(&mut self, relation: &Relation) {
        let has_span = relation
            .evidence
            .iter()
            .any(|evidence| evidence.source_span.is_some());
        self.relations += 1;
        if has_span {
            self.relations_with_span += 1;
        }
        if relation.evidence.is_empty() {
            self.relations_without_evidence += 1;
        }
        let kind_entry = self
            .by_kind
            .entry(format!("{:?}", relation.kind))
            .or_default();
        kind_entry.0 += 1;
        if has_span {
            kind_entry.1 += 1;
        }
        for evidence in &relation.evidence {
            self.observe_evidence(evidence);
        }
    }

    fn observe_evidence(&mut self, evidence: &RelationEvidence) {
        self.evidence_records += 1;
        if evidence.source_span.is_some() {
            self.evidence_with_span += 1;
        }
        if evidence.parser_rule.is_some() {
            self.with_parser_rule += 1;
        }
        if evidence.token.is_some() {
            self.with_token += 1;
        }
        if evidence.source_path.is_some() {
            self.with_source_path += 1;
        }
        if evidence.resolved_path.is_some() {
            self.with_resolved_path += 1;
        }
        if evidence.call_shape.is_some() {
            self.with_call_shape += 1;
        }
        self.assert_field_census_is_exhaustive(evidence);
    }

    /// Destructuring every field makes a future `RelationEvidence` member fail
    /// compilation here until the census accounts for it, so the table can
    /// never quietly stop describing the whole record.
    fn assert_field_census_is_exhaustive(&self, evidence: &RelationEvidence) {
        let RelationEvidence {
            source_span: _,
            parser_rule: _,
            token: _,
            source_path: _,
            resolved_path: _,
            occurrence_count: _,
            call_shape: _,
        } = evidence;
    }

    fn merge(&mut self, other: &Counts) {
        self.relations += other.relations;
        self.relations_with_span += other.relations_with_span;
        self.evidence_records += other.evidence_records;
        self.evidence_with_span += other.evidence_with_span;
        self.relations_without_evidence += other.relations_without_evidence;
        self.with_parser_rule += other.with_parser_rule;
        self.with_token += other.with_token;
        self.with_source_path += other.with_source_path;
        self.with_resolved_path += other.with_resolved_path;
        self.with_call_shape += other.with_call_shape;
        for (kind, (total, spanned)) in &other.by_kind {
            let entry = self.by_kind.entry(kind.clone()).or_default();
            entry.0 += total;
            entry.1 += spanned;
        }
    }

    /// A rate over zero relations is not a rate, so it prints as `n/a` rather
    /// than a `0.0%` that reads like a measured result.
    fn span_percent(&self) -> String {
        percent(self.relations_with_span, self.relations)
    }

    fn calls(&self) -> usize {
        self.by_kind
            .get("Calls")
            .map(|(total, _)| *total)
            .unwrap_or(0)
    }
}

/// Run one language's files through both production ingest arms and merge the
/// resulting relations by id.
///
/// The merge is what a rename planner would see: it asks the graph for an
/// edge's evidence, not for the arm that produced it, so evidence recorded by
/// either arm counts for that edge.
fn measure(files: &[(String, Vec<u8>)]) -> Counts {
    let pipeline = IndexPipeline::new();
    let blob_hash = kin_blobs::Hash256::from_bytes([0u8; 32]);

    let mut merged: HashMap<RelationId, Relation> = HashMap::new();
    let mut parse_data = Vec::new();
    let mut artifact_ids: ArtifactIdentityMap = ArtifactIdentityMap::new();

    for (path, source) in files {
        let file_id = FilePathId::new(path);
        let indexed = pipeline
            .index_file_content_with_tests(&file_id, source, blob_hash)
            .unwrap_or_else(|error| panic!("index `{path}`: {error}"))
            .indexed_file;

        for relation in &indexed.relations {
            merge_relation(&mut merged, relation);
        }

        artifact_ids.insert(path.clone(), ArtifactId::new());
        parse_data.push(FileParseData {
            file_path: path.clone(),
            entities: indexed.entities,
            relations: indexed.extracted_relations,
            imports: indexed.imports,
        });
    }

    let linked = pipeline
        .resolve_cross_file(&parse_data, &artifact_ids)
        .expect("cross-file linking over the measured file set");
    for relation in &linked {
        merge_relation(&mut merged, relation);
    }

    let mut counts = Counts::default();
    for relation in merged.values() {
        counts.observe(relation);
    }
    counts
}

fn merge_relation(merged: &mut HashMap<RelationId, Relation>, relation: &Relation) {
    match merged.get_mut(&relation.id) {
        Some(existing) => existing.evidence.extend(relation.evidence.iter().cloned()),
        None => {
            merged.insert(relation.id, relation.clone());
        }
    }
}

fn percent(part: usize, whole: usize) -> String {
    if whole == 0 {
        return "n/a".to_string();
    }
    format!("{:.1}%", (part as f64 / whole as f64) * 100.0)
}

fn print_table(rows: &[(String, Counts)], title: &str) {
    println!("\n{title}");
    println!(
        "\n| Language | Relations | With source_span | % | Calls edges | Evidence records | Evidence with span |"
    );
    println!("| --- | ---: | ---: | ---: | ---: | ---: | ---: |");
    for (language, counts) in rows {
        println!(
            "| {} | {} | {} | {} | {} | {} | {} |",
            language,
            counts.relations,
            counts.relations_with_span,
            counts.span_percent(),
            counts.calls(),
            counts.evidence_records,
            counts.evidence_with_span,
        );
    }

    let mut total = Counts::default();
    for (_, counts) in rows {
        total.merge(counts);
    }
    println!(
        "| **TOTAL** | {} | {} | {} | {} | {} | {} |",
        total.relations,
        total.relations_with_span,
        total.span_percent(),
        total.calls(),
        total.evidence_records,
        total.evidence_with_span,
    );

    println!("\nBy relation kind (all languages):\n");
    println!("| Relation kind | Relations | With source_span | % |");
    println!("| --- | ---: | ---: | ---: |");
    for (kind, (relations, spanned)) in &total.by_kind {
        println!(
            "| {kind} | {relations} | {spanned} | {} |",
            percent(*spanned, *relations)
        );
    }

    println!("\nWhat evidence carries instead of a span (records, all languages):\n");
    println!(
        "| evidence records | source_span | parser_rule | token | source_path | resolved_path | call_shape |"
    );
    println!("| ---: | ---: | ---: | ---: | ---: | ---: | ---: |");
    println!(
        "| {} | {} | {} | {} | {} | {} | {} |",
        total.evidence_records,
        total.evidence_with_span,
        total.with_parser_rule,
        total.with_token,
        total.with_source_path,
        total.with_resolved_path,
        total.with_call_shape,
    );
    println!(
        "\nRelations carrying no evidence record at all: {}",
        total.relations_without_evidence
    );
}

/// The measured population, pinned so the number the rename gate cites stays
/// live rather than becoming a claim in a document.
///
/// It was zero until FIR-1825: no producer set `RelationEvidence::source_span`,
/// because the parser -> linker seam (`kin_parser::ExtractedRelation`) had no
/// span field to carry one, so the adapters could not hand a site to the
/// resolver even where tree-sitter knew it. The Python and JavaScript adapters
/// now record the call expression's own site, and TypeScript reuses
/// JavaScript's call walker, so all three carry a span on every `Calls` edge in
/// these fixtures. The remaining adapters do not record sites yet and their
/// edges stay spanless.
///
/// This total is a whole-fleet check. The per-language floors above are what
/// keeps a language from silently losing its sites.
///
/// FIR-2690 moved it from 9 to 10. That ticket is FIR-1825's residual: call
/// sites got spans, import sites did not, and `kin rename` refused on any
/// symbol another file imports because the only span it could reach was the
/// importing file's MODULE entity, whose span is the whole file. Entity-level
/// import edges now carry the import statement's own site, so one more relation
/// in these fixtures is span-backed.
///
/// One, not thirteen, and the reason is worth knowing before the next author
/// reads this number as coverage. These fixtures are call-resolution fixtures;
/// they contain a single cross-file import edge between them. The claim "every
/// language records an import span" is proven where it can be proven, in
/// `kin-parser/tests/import_span_coverage.rs`, which parses a fixture per
/// language and asserts each span is non-empty, inside the file, over bytes
/// that mention the module path, and on a line that agrees with its own byte
/// offset. This constant proves something different and narrower: that the
/// linker carries a site the parser recorded all the way onto persisted
/// evidence.
const MEASURED_RELATIONS_WITH_SPAN: usize = 10;

/// Span-backed evidence RECORDS, which exceed span-backed relations whenever one
/// caller reaches one callee at more than one site. Each fixture calls `compute`
/// twice from `run`, so the three site-recording languages contribute four
/// records across three edges apiece. That surplus is the point: it is what
/// `find_references` turns into more than one entry in `reference_lines`.
/// FIR-2690 moved it from 12 to 13, in step with the relation count above: the
/// one new span-backed relation is an entity-level import edge, and an import
/// edge carries exactly one evidence record because a specifier binds once.
/// The surplus of records over relations is unchanged, since it comes from
/// repeat CALL sites and this edge adds none.
const MEASURED_EVIDENCE_RECORDS_WITH_SPAN: usize = 13;

#[test]
fn relation_evidence_span_population_per_language() {
    let mut rows = Vec::new();
    for fixture in FIXTURES {
        let files: Vec<(String, Vec<u8>)> = fixture
            .files
            .iter()
            .map(|(path, source)| (path.to_string(), source.as_bytes().to_vec()))
            .collect();
        rows.push((fixture.language.to_string(), measure(&files)));
    }

    print_table(
        &rows,
        "## Relation evidence source_span population (fixtures)",
    );

    for (fixture, (language, counts)) in FIXTURES.iter().zip(&rows) {
        assert!(
            counts.relations >= fixture.min_relations,
            "`{language}` produced {} relations, below its declared floor of {}; a language \
             contributing none would report 0 spans of 0 relations, which reads as a \
             measurement but is not one",
            counts.relations,
            fixture.min_relations,
        );
        // Calls is the edge a rename planner walks, so a language whose call
        // arm went missing must fail rather than dilute the total.
        assert!(
            counts.calls() >= fixture.min_calls,
            "`{language}` produced {} Calls edges, below its declared floor of {}",
            counts.calls(),
            fixture.min_calls,
        );
        let calls_with_span = counts
            .by_kind
            .get("Calls")
            .map(|(_, spanned)| *spanned)
            .unwrap_or(0);
        assert!(
            calls_with_span >= fixture.min_calls_with_span,
            "`{language}` recorded a site on {calls_with_span} of its {} Calls edges, below its \
             declared floor of {}; a reference row for this language would report callers with \
             no call-site lines",
            counts.calls(),
            fixture.min_calls_with_span,
        );
    }

    let mut total = Counts::default();
    for (_, counts) in &rows {
        total.merge(counts);
    }
    assert_eq!(
        total.relations_with_span, MEASURED_RELATIONS_WITH_SPAN,
        "relation-evidence span population changed. If span emission landed, update \
         MEASURED_RELATIONS_WITH_SPAN to the new measured value and re-cite the rename gate \
         against it; if it fell, a producer stopped recording sites"
    );
    assert!(
        total.evidence_with_span >= total.relations_with_span,
        "every span-backed relation must carry at least one span-backed evidence record, but \
         {} records cover {} relations",
        total.evidence_with_span,
        total.relations_with_span,
    );
    assert_eq!(
        total.evidence_with_span, MEASURED_EVIDENCE_RECORDS_WITH_SPAN,
        "span-backed evidence-record population changed. Records exceed relations because one \
         edge called twice carries one record per site, which is what lets a reference row \
         report both lines"
    );
}

// ── Real-corpus arm ──
//
// The fixtures are small by construction, so they fix the mechanism but not the
// mix of relation kinds a real tree produces. Pointing the same counters at a
// checkout answers the mix question. Reading the tree here is ingestion IO: the
// bytes go straight into the parser, exactly as `kin index` feeds it, and no
// answer is derived from the filesystem.

const CORPUS_ENV: &str = "KIN_SPAN_COVERAGE_CORPUS";
const CORPUS_FILE_CAP_ENV: &str = "KIN_SPAN_COVERAGE_FILE_CAP";
const CORPUS_FILE_CAP_DEFAULT: usize = 2000;

#[test]
#[ignore = "needs KIN_SPAN_COVERAGE_CORPUS pointing at a checkout to measure"]
fn corpus_relation_evidence_span_population() {
    let root = std::env::var(CORPUS_ENV)
        .unwrap_or_else(|_| panic!("set {CORPUS_ENV} to the checkout to measure"));
    let root = PathBuf::from(root);

    let pipeline = IndexPipeline::new();
    let mut by_language: BTreeMap<String, Vec<(String, Vec<u8>)>> = BTreeMap::new();
    let cap = std::env::var(CORPUS_FILE_CAP_ENV)
        .ok()
        .and_then(|raw| raw.parse().ok())
        .unwrap_or(CORPUS_FILE_CAP_DEFAULT);
    let mut paths = Vec::new();
    collect_source_files(&root, &root, &mut paths);
    paths.sort();
    let discovered = paths.len();
    paths.truncate(cap);
    // A cap that silently drops files would make the table read as whole-tree
    // coverage when it is a prefix of one, so say what was dropped.
    println!(
        "corpus {}: {} files discovered, {} measured (cap {} via {CORPUS_FILE_CAP_ENV})",
        root.display(),
        discovered,
        paths.len(),
        cap,
    );

    for path in paths {
        let Ok(source) = std::fs::read(root.join(&path)) else {
            continue;
        };
        let extension = Path::new(&path)
            .extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or_default();
        let Some(adapter) = pipeline
            .registry()
            .get_by_extension_and_content(extension, &source)
        else {
            continue;
        };
        by_language
            .entry(format!("{:?}", adapter.language_id()))
            .or_default()
            .push((path, source));
    }

    assert!(
        !by_language.is_empty(),
        "no parseable source files under {}; the corpus measurement would be vacuous",
        root.display()
    );

    let rows: Vec<(String, Counts)> = by_language
        .into_iter()
        .map(|(language, files)| (language, measure(&files)))
        .collect();
    print_table(
        &rows,
        &format!(
            "## Relation evidence source_span population (corpus: {})",
            root.display()
        ),
    );
}

/// Walk `dir` for files the parser fleet can read, skipping build output and
/// vendored trees so the sample stays first-party source.
fn collect_source_files(root: &Path, dir: &Path, out: &mut Vec<String>) {
    const SKIP: &[&str] = &[
        ".git",
        ".kin",
        "target",
        "node_modules",
        "vendor",
        "dist",
        "build",
        ".venv",
    ];

    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        if SKIP.contains(&name.as_str()) {
            continue;
        }
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        if file_type.is_dir() {
            collect_source_files(root, &path, out);
        } else if file_type.is_file() {
            if let Ok(relative) = path.strip_prefix(root) {
                out.push(relative.to_string_lossy().replace('\\', "/"));
            }
        }
    }
}
