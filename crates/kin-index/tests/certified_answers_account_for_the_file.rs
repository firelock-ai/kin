// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The scripted check for the two certified-wrong findings of the v0.6.0 npm
//! stranger run (FIR-2786, FIR-2775).
//!
//! Both are one class on two languages: an extractor or linker gap becomes a
//! certified, authoritative, wrong answer, because the certification is asserted
//! rather than gated on whether the file was accounted for. The class gets its
//! check here before its fix merges, so it is never rediscovered a release
//! later.
//!
//! ## Why these run through the real pipeline rather than against a fixture
//!
//! Each half of both chains is already unit-tested somewhere. That is exactly
//! the arrangement the trap catalogue warns about: two tests can each be
//! correct, each guard a real property, and jointly guard nothing, because the
//! property that matters lives in the agreement between them. `list_file_entities`
//! proves a hand-built `ParseCompleteness::Partial` does not certify; nothing
//! proved a real file with a broken top-level statement ever reaches `Partial`.
//! `caller_arrival` proves an absent `file_parsed_call_sites` key makes an
//! absence unaccounted; nothing proved the Python adapter actually withholds
//! that key on the shape the stranger hit. These drive the real adapters through
//! the real `IndexPipeline` and assert the join.

use kin_index::IndexPipeline;
use kin_model::{FilePathId, ParseCompleteness};

fn blob_hash() -> kin_blobs::Hash256 {
    kin_blobs::Hash256::from_bytes([7; 32])
}

fn index(path: &str, source: &str) -> kin_index::IndexedFile {
    IndexPipeline::new()
        .index_file_content_with_tests(&FilePathId::new(path), source.as_bytes(), blob_hash())
        .unwrap_or_else(|error| panic!("indexing {path} failed: {error}"))
        .indexed_file
}

/// express's `lib/express.js`, trimmed to the statements that decide the
/// finding. Line 79 of the real file is `exports.static = require('serve-static')`.
const EXPRESS_EXPORT_SURFACE: &str = r#"'use strict';

var bodyParser = require('body-parser');
var Router = require('router');

function createApplication() {
  return {};
}

exports = module.exports = createApplication;

exports.Router = Router;
exports.json = bodyParser.json
exports.raw = bodyParser.raw
exports.static = require('serve-static');
exports.text = bodyParser.text
exports.urlencoded = bodyParser.urlencoded
"#;

/// FIR-2786. `list_file_entities("lib/express.js")` returned eleven entities
/// with `bound: exact`, `status: complete`, `verdict: certified`,
/// `negative.trust: authoritative` and `certifies_enumeration: true`, and did
/// not hold `exports.static`, one of the most-used names in the Express API.
///
/// The enumeration reads the entity set. An import specifier is not in it, so
/// the extractor's decision to leave the re-export as an import alone made the
/// symbol invisible to this tool, to `find_references`, and to every dead-code
/// answer over the file, with no envelope and no degradation to warn about it.
#[test]
fn a_require_re_export_is_in_the_files_entity_set() {
    let indexed = index("lib/express.js", EXPRESS_EXPORT_SURFACE);
    let names: Vec<&str> = indexed
        .entities
        .iter()
        .map(|entity| entity.name.as_str())
        .collect();

    assert!(
        names.contains(&"static"),
        "the enumeration a caller certifies must hold the re-exported symbol; have {names:?}"
    );
    // The controls, so this cannot pass by admitting everything. The member
    // expression exports around it were never the defect and must be unchanged,
    // and the local `require` bindings above them must stay out: readmitting
    // those is the 451-constant bloat that bought the exclusion in the first
    // place, and it would bury the file's functions again.
    for present in [
        "Router",
        "json",
        "raw",
        "text",
        "urlencoded",
        "createApplication",
    ] {
        assert!(
            names.contains(&present),
            "control: {present} must still be an entity; have {names:?}"
        );
    }
    for absent in ["bodyParser", "require", "serve-static"] {
        assert!(
            !names.contains(&absent),
            "control: {absent} is a local dependency binding, not an export; have {names:?}"
        );
    }
    // The import side is unchanged. The entity is not a replacement for the
    // specifier, and a fix that moved the symbol from one surface to the other
    // rather than putting it on both would pass the assertion above.
    let specifiers: Vec<&str> = indexed
        .imports
        .iter()
        .filter(|import| import.module_path == "serve-static")
        .flat_map(|import| {
            import
                .specifiers
                .iter()
                .map(|spec| spec.local_name.as_str())
        })
        .collect();
    assert_eq!(
        specifiers,
        vec!["static"],
        "serve-static must still bind its specifier"
    );
}

/// FIR-2786, the structural half of the acceptance: the certification gate holds
/// on a file the adapter could not fully parse.
///
/// This is the join nothing was asserting. `list_file_entities` gates
/// `certifies_enumeration` on `ParseCompleteness::Full` and proves that against
/// a `Partial` built by hand; the chain from a genuinely broken top-level
/// statement to `Partial` runs through `collect_error_ranges`,
/// `ParseState::Incomplete` and `ParseCompleteness::from_parse_state`, and was
/// pinned nowhere. A rename anywhere along it would have left both ends green
/// while a broken file certified its enumeration as exact.
#[test]
fn a_file_with_a_broken_top_level_statement_cannot_certify_its_enumeration() {
    let broken = index(
        "lib/broken.js",
        "function ok() { return 1; }\nexports.torn = function( {\n",
    );
    assert_ne!(
        broken.file_layout.parse_completeness,
        ParseCompleteness::Full,
        "a file the adapter could not parse through must not report a full parse, because that \
         is the one state that licenses certifying its enumeration as the whole set"
    );
    assert_eq!(
        broken.file_layout.parse_completeness.bucket(),
        "partial",
        "the broken file must reach the exact wire word `list_file_entities` reads back as \
         `file_coverage.parsed`, since that string and not the enum is what the gate matches on"
    );

    // The control, and it is what keeps the gate from becoming a blanket
    // downgrade: the same file, whole, still reports a full parse and so still
    // certifies. A fix that floored every enumeration passes the assertion above
    // and fails right here.
    let whole = index(
        "lib/whole.js",
        "function ok() { return 1; }\nexports.torn = function() { return 2; };\n",
    );
    assert_eq!(
        whole.file_layout.parse_completeness,
        ParseCompleteness::Full,
        "an intact file must still license certification"
    );
}

/// FIR-2775. The exact shape from the stranger's five-symbol probe: a package
/// under `src/`, a test that reaches the module through an absolute
/// `from package import module`, and an attribute call through that binding.
///
/// Two things are asserted and they are different claims. The first is the
/// finding itself: the call produces no entity-level `Calls` edge, so
/// `find_references("note_body")` sees nothing. The second is the one the
/// certification gate rests on: the file reports how many call sites it holds,
/// which is the number `kin_mcp::caller_arrival` subtracts the graph's resolved
/// edges from. Without this second assertion the gate is tested only against a
/// hand-built store and could be keyed on a signal the real path never emits.
///
/// This arm asserted the opposite until FIR-2828: the extractor used to
/// withhold the count from any file whose call extraction it could not fully
/// represent, and the gate keyed on that absence. The absence was the right
/// refusal for the wrong number, since the count it withheld was taken off the
/// relations it emitted and understated any file holding a call it could not
/// name. Counting the call sites instead makes the number safe to report, and a
/// count that is present is the only one the gate can do arithmetic with.
#[test]
fn an_absolute_module_import_attribute_call_still_counts_the_files_call_sites() {
    let caller = index(
        "tests/test_storage.py",
        "from notekeeper import storage\n\n\ndef test_bodies_round_trip(db, note):\n    assert \"x\" in storage.note_body(db, note.id)\n",
    );

    // The parse side read the call: it is not that the extractor missed it.
    assert!(
        caller
            .extracted_relations
            .iter()
            .any(|relation| relation.dst_name == "note_body"),
        "the parser must read the attribute call, or this fixture is testing the wrong thing"
    );
    // And it recorded a receiver, which is what sends it down the linker tier
    // that resolves the binding to the package rather than to the module.
    assert!(
        caller.extracted_relations.iter().any(|relation| {
            relation.dst_name == "note_body" && relation.receiver.as_deref() == Some("storage")
        }),
        "the call must carry its receiver; the receiver is what the failing tier keys on"
    );

    // The number the certification gate subtracts from. It is stamped on every
    // entity of the file, because a consumer settles the file on whichever one
    // it reads first, and it counts the call sites the file holds rather than
    // the relations extraction emitted: this file writes one call, and the
    // linker records no entity-level edge for it, so the gate must see one
    // parsed site against zero edges and decline.
    assert!(
        !caller.entities.is_empty(),
        "the fixture must produce entities, or the count would be absent for the wrong reason"
    );
    for entity in &caller.entities {
        assert_eq!(
            entity
                .metadata
                .extra
                .get(kin_parser::FILE_PARSED_CALL_SITES_KEY)
                .and_then(serde_json::Value::as_u64),
            Some(1),
            "every entity of the file must carry the file's one call site, or the gate has \
             nothing to subtract the graph's edges from: {} carries {:?}",
            entity.name,
            entity
                .metadata
                .extra
                .get(kin_parser::FILE_PARSED_CALL_SITES_KEY)
        );
    }

    // The control, and it is the one the ticket demands: a file whose calls the
    // extractor CAN represent still reports its count, so the gate cannot become
    // a blanket downgrade over every Python file. A direct-name import with a
    // bare call is the shape the stranger's probe found resolves.
    let resolved = index(
        "tests/test_parsing.py",
        "from notekeeper.parsing import extract_tags\n\n\ndef test_tags():\n    assert extract_tags(\"#a\") == [\"a\"]\n",
    );
    let counted = resolved
        .entities
        .iter()
        .filter_map(|entity| {
            entity
                .metadata
                .extra
                .get(kin_parser::FILE_PARSED_CALL_SITES_KEY)
        })
        .count();
    assert!(
        counted > 0,
        "control: a file whose calls the extractor could represent must still report its \
         call-site count, or every Python absence goes inconclusive"
    );
}
