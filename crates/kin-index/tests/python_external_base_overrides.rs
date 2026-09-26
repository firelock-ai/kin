// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! What a Python class's declared base resolves to, and what the graph holds
//! when it resolves to nothing local.
//!
//! Three separate silences used to look identical from the graph's side. A
//! base a library owns, a builtin base, and a base whose bare name collides
//! across the repository all produced no `Overrides` edge at all, so a
//! subclass's method was never seen as an override. The flask shape is the
//! common one: most top-level classes there extend `dict`, a builtin
//! exception, a `click` class, or a `werkzeug` class.
//!
//! Worse than the silence, a base written `module.Class` was decided by a
//! class merely sharing the leaf name in the DECLARING file, ahead of the
//! module the import actually named — and that wrong base was minted at full
//! parser confidence while the `Extends` edge the generic resolver produced
//! for the same declaration resolved through the import and disagreed.
//!
//! This file drives the real parser and the real linker, batch and
//! incremental, over one small package carrying every base shape.

use kin_index::linker::ArtifactIdentityMap;
use kin_index::resolution::{RelationResolution, DISPATCH_CANDIDATE_CONFIDENCE};
use kin_index::{FileParseCompletenessMap, FileParseData, BASE_RESOLUTION_COVERAGE_V1};
use kin_model::{
    ArtifactId, Entity, EntityId, EntityStore, FilePathId, LanguageId, ParseCompleteness, Relation,
    RelationKind, RelationOrigin,
};
use kin_parser::{LanguageAdapter, PythonAdapter};

/// The kind tag the linker derives an external placeholder's identity under.
/// Spelled literally here rather than imported because it is a persisted wire
/// value: a test that reads it from the same constant the producer uses cannot
/// notice the constant changing.
const EXTERNAL_REFERENCE_KIND_TAG: &str = "ExternalReference";

/// The tier an external placeholder edge carries. Also spelled literally, for
/// the same reason.
const EXTERNAL_REFERENCE_CONFIDENCE: f32 = 0.2;

// ── the fixture package ─────────────────────────────────────────────────────

/// The real `Model`, and the sibling method whose `self.save()` call is the
/// one a reader is told to trust or not trust.
const MODELS: &str = "\
class Model:
    def save(self):
        return 'real'

    def persist(self):
        return self.save()
";

/// A second, unrelated `Model`. Its only job is to make the bare name `Model`
/// ambiguous across the repository, so no name tier can rescue a base that the
/// import graph has to decide.
const LEGACY: &str = "\
class Model:
    def save(self):
        return 'legacy'
";

/// A qualified base (`models.Model`) declared in a file that also declares a
/// class of the same leaf name. Python binds `models.Model` to the imported
/// module, never to the local `Model`.
const ROWS: &str = "\
import pkg.models as models


class Model:
    def save(self):
        return 'decoy'


class Row(models.Model):
    def save(self):
        return 'row'
";

/// A colliding bare name settled by an explicit aliased import.
const WORKER: &str = "\
from pkg.legacy import Model as Legacy


class Worker(Legacy):
    def save(self):
        return 'worker'
";

/// A builtin base. Nothing in the file binds `Exception`, so no module
/// coordinate was ever observed for it.
const ERRORS: &str = "\
class ConfigError(Exception):
    def __str__(self):
        return 'bad config'
";

/// A base a third-party library owns, imported by symbol.
const CLI: &str = "\
from click import Group


class AppGroup(Group):
    def get_command(self, ctx, name):
        return None
";

/// The same third-party base, imported by module and written qualified.
const CLI_DOTTED: &str = "\
import click


class DottedGroup(click.Group):
    def get_command(self, ctx, name):
        return None
";

fn parse_py(file_path: &str, source: &str) -> FileParseData {
    let adapter = PythonAdapter;
    let file_id = FilePathId::new(file_path);
    let bytes = source.as_bytes();
    let tree = adapter.parse(bytes).expect("parse");
    let output = adapter.extract(&tree, bytes, &file_id).expect("extract");
    let entities: Vec<Entity> = output
        .entities
        .into_iter()
        .map(|e| e.into_entity_with_source(adapter.language_id(), &file_id, Some(bytes)))
        .collect();
    FileParseData {
        file_path: file_path.to_string(),
        entities,
        relations: output.relations,
        imports: output.imports,
    }
}

fn package() -> Vec<FileParseData> {
    vec![
        parse_py("pkg/models.py", MODELS),
        parse_py("pkg/legacy.py", LEGACY),
        parse_py("pkg/rows.py", ROWS),
        parse_py("pkg/worker.py", WORKER),
        parse_py("pkg/errors.py", ERRORS),
        parse_py("pkg/cli.py", CLI),
        parse_py("pkg/cli_dotted.py", CLI_DOTTED),
    ]
}

fn artifact_ids(files: &[FileParseData]) -> ArtifactIdentityMap {
    files
        .iter()
        .map(|file| (file.file_path.clone(), ArtifactId::new()))
        .collect()
}

fn full_completeness(files: &[FileParseData]) -> FileParseCompletenessMap {
    files
        .iter()
        .map(|file| (file.file_path.clone(), ParseCompleteness::Full))
        .collect()
}

fn link(files: &[FileParseData]) -> Vec<Relation> {
    kin_index::link_cross_file(files, &artifact_ids(files))
        .expect("every fixture file has an explicitly assigned artifact identity")
}

fn link_certified(files: &[FileParseData]) -> Vec<Relation> {
    kin_index::link_cross_file_with_completeness(
        files,
        &artifact_ids(files),
        &full_completeness(files),
    )
    .expect("every fixture file has an explicitly assigned artifact identity")
}

fn entity_id(files: &[FileParseData], file: &str, name: &str) -> EntityId {
    files
        .iter()
        .flat_map(|f| f.entities.iter())
        .find(|e| e.name == name && e.file_origin.as_ref().map(|p| p.0.as_str()) == Some(file))
        .unwrap_or_else(|| panic!("entity `{name}` in `{file}` not found"))
        .id
}

fn entity(files: &[FileParseData], file: &str, name: &str) -> Entity {
    files
        .iter()
        .flat_map(|f| f.entities.iter())
        .find(|e| e.name == name && e.file_origin.as_ref().map(|p| p.0.as_str()) == Some(file))
        .unwrap_or_else(|| panic!("entity `{name}` in `{file}` not found"))
        .clone()
}

fn overrides_from(relations: &[Relation], src: EntityId) -> Vec<&Relation> {
    relations
        .iter()
        .filter(|r| r.kind == RelationKind::Overrides && r.src.as_entity() == Some(src))
        .collect()
}

fn has_override(relations: &[Relation], src: EntityId, dst: EntityId) -> bool {
    relations.iter().any(|r| {
        r.kind == RelationKind::Overrides
            && r.src.as_entity() == Some(src)
            && r.dst.as_entity() == Some(dst)
    })
}

/// The placeholder identity the linker derives for one external symbol.
fn external_placeholder(module: &str, symbol: &str) -> EntityId {
    EntityId::from_content(module, symbol, EXTERNAL_REFERENCE_KIND_TAG, 0)
}

/// The declared-base half of one file's coverage certificate, as
/// (bases declared, bases bound).
fn base_coverage(relations: &[Relation], file: &str) -> Option<(u32, u32)> {
    relations.iter().find_map(|relation| {
        relation.evidence.iter().find_map(|evidence| {
            if evidence.parser_rule.as_deref() != Some(BASE_RESOLUTION_COVERAGE_V1)
                || evidence.source_path.as_deref() != Some(file)
            {
                return None;
            }
            let bound = evidence.token.as_deref()?.parse::<u32>().ok()?;
            Some((evidence.occurrence_count, bound))
        })
    })
}

// ── the import graph decides a qualified base ───────────────────────────────

#[test]
fn a_qualified_base_resolves_through_the_import_graph_not_a_same_file_decoy() {
    let files = package();
    let relations = link(&files);

    let row_save = entity_id(&files, "pkg/rows.py", "Row.save");
    let real_save = entity_id(&files, "pkg/models.py", "Model.save");
    let decoy_save = entity_id(&files, "pkg/rows.py", "Model.save");

    assert!(
        has_override(&relations, row_save, real_save),
        "`class Row(models.Model)` overrides the `Model` the import named: {:#?}",
        overrides_from(&relations, row_save)
    );
    assert!(
        !has_override(&relations, row_save, decoy_save),
        "a class merely sharing the base's leaf name in the declaring file is not the base: {:#?}",
        overrides_from(&relations, row_save)
    );
}

/// The `Overrides` and `Extends` edges for one declaration are two answers to
/// the same question, and they used to disagree: `Extends` resolved through
/// the import, `Overrides` through the same-file leaf name.
#[test]
fn the_override_edge_agrees_with_the_extends_edge_for_the_same_declaration() {
    let files = package();
    let relations = link(&files);

    let row = entity_id(&files, "pkg/rows.py", "Row");
    let real_model = entity_id(&files, "pkg/models.py", "Model");

    assert!(
        relations.iter().any(|r| r.kind == RelationKind::Extends
            && r.src.as_entity() == Some(row)
            && r.dst.as_entity() == Some(real_model)),
        "the generic resolver puts Row's base in pkg/models.py"
    );
    let row_save = entity_id(&files, "pkg/rows.py", "Row.save");
    let real_save = entity_id(&files, "pkg/models.py", "Model.save");
    assert!(
        has_override(&relations, row_save, real_save),
        "and the override walk must reach the same class"
    );
}

#[test]
fn an_explicitly_imported_colliding_base_resolves_to_the_module_it_names() {
    let files = package();
    let relations = link(&files);

    let worker_save = entity_id(&files, "pkg/worker.py", "Worker.save");
    let legacy_save = entity_id(&files, "pkg/legacy.py", "Model.save");

    assert!(
        has_override(&relations, worker_save, legacy_save),
        "`from pkg.legacy import Model as Legacy` settles a name three files declare: {:#?}",
        overrides_from(&relations, worker_save)
    );
}

/// The consumer consequence, and the reason this is a defect rather than a
/// gap: with the override edge landing on the decoy, the REAL `Model.save` had
/// no override, so `Model.persist`'s `self.save()` was published as a uniquely
/// resolved destination at full confidence — a confident callee that Python's
/// own method resolution order does not have to reach.
#[test]
fn an_overridden_base_implementation_is_no_longer_a_confident_callee() {
    let files = package();
    let relations = link(&files);

    let persist = entity_id(&files, "pkg/models.py", "Model.persist");
    let save = entity_id(&files, "pkg/models.py", "Model.save");

    let call = relations
        .iter()
        .find(|r| {
            r.kind == RelationKind::Calls
                && r.src.as_entity() == Some(persist)
                && r.dst.as_entity() == Some(save)
        })
        .unwrap_or_else(|| panic!("self.save() must still resolve: {relations:#?}"));

    assert_eq!(
        call.confidence, DISPATCH_CANDIDATE_CONFIDENCE,
        "a self-call to a method a subclass replaces keeps its dispatch qualification: {call:#?}"
    );
    assert_eq!(
        RelationResolution::of(call),
        RelationResolution::ImportScoped
    );
}

/// The same fact read the way a consumer reads it: off the graph's own
/// `Overrides` edges, through the helper `overridden_by` is published from.
#[test]
fn the_graph_names_the_overriding_method_of_the_real_base() {
    use kin_db::InMemoryGraph;

    let files = package();
    let relations = link(&files);

    let graph = InMemoryGraph::new();
    for file in &files {
        for entity in &file.entities {
            graph.upsert_entity(entity).expect("local entity admits");
        }
    }
    for relation in &relations {
        let _ = graph.upsert_relation(relation);
    }

    let real_save = entity(&files, "pkg/models.py", "Model.save");
    let named: Vec<String> = kin_index::overriding_methods(&graph, &real_save)
        .expect("read the override edges back")
        .into_iter()
        .map(|candidate| candidate.qualified_name)
        .collect();
    assert_eq!(
        named,
        vec!["Row.save".to_string()],
        "the real base's override is readable from the graph"
    );
}

// ── an external base is a placeholder, not a silence ────────────────────────

#[test]
fn an_external_library_base_mints_the_external_import_placeholder() {
    let files = package();
    let relations = link(&files);

    let get_command = entity_id(&files, "pkg/cli.py", "AppGroup.get_command");
    let placeholder = external_placeholder("click", "Group.get_command");

    let edges = overrides_from(&relations, get_command);
    assert_eq!(
        edges.len(),
        1,
        "one declared base, one override edge: {edges:#?}"
    );
    let edge = edges[0];
    assert_eq!(
        edge.dst.as_entity(),
        Some(placeholder),
        "the destination is the deterministic coordinate for click's Group.get_command"
    );
    assert!(
        kin_index::is_external_import_placeholder(edge),
        "and it satisfies the linker's one external-placeholder contract: {edge:#?}"
    );
    assert_eq!(edge.import_source.as_deref(), Some("click"));
    assert_eq!(edge.origin, RelationOrigin::Inferred);
    assert_eq!(edge.confidence, EXTERNAL_REFERENCE_CONFIDENCE);
    assert_eq!(
        edge.evidence
            .first()
            .and_then(|record| record.token.as_deref()),
        Some("Group.get_command"),
        "carrying the member's owner-qualified name inside the external module"
    );
    assert!(
        !RelationResolution::of(edge).is_proven(),
        "the edge does not claim the external base declares this member"
    );
}

/// The admission path has to be able to bind the node this edge names, or the
/// edge is a dangling endpoint rather than coverage.
#[test]
fn the_placeholder_an_external_base_names_resolves_to_a_bindable_target() {
    let files = package();
    let relations = link(&files);
    let get_command = entity_id(&files, "pkg/cli.py", "AppGroup.get_command");
    let edge = overrides_from(&relations, get_command)[0];

    let target = kin_index::placeholder_target_entity(edge, LanguageId::Python)
        .expect("a placeholder relation names the target it stands for");
    assert_eq!(
        target.id,
        external_placeholder("click", "Group.get_command")
    );
    assert!(
        kin_index::is_external_reference_target(&target),
        "and that target reads as owned outside this repository: {target:#?}"
    );
    assert!(target.file_origin.is_none());
}

/// `from click import Group` and `import click` + `click.Group` are the same
/// base. They must land on the same node, or one repository holds two answers
/// for one library class.
#[test]
fn both_spellings_of_an_external_base_land_on_one_placeholder() {
    let files = package();
    let relations = link(&files);

    let by_symbol = entity_id(&files, "pkg/cli.py", "AppGroup.get_command");
    let by_module = entity_id(&files, "pkg/cli_dotted.py", "DottedGroup.get_command");

    let placeholder = external_placeholder("click", "Group.get_command");
    assert!(has_override(&relations, by_symbol, placeholder));
    assert!(has_override(&relations, by_module, placeholder));
}

// ── a base nothing bound is disclosed, not guessed ──────────────────────────

#[test]
fn a_builtin_base_mints_no_edge_and_is_disclosed_by_the_certificate() {
    let files = package();
    let relations = link_certified(&files);

    let dunder_str = entity_id(&files, "pkg/errors.py", "ConfigError.__str__");
    assert!(
        overrides_from(&relations, dunder_str).is_empty(),
        "no module named `Exception`, so no coordinate exists to stand for it: {:#?}",
        overrides_from(&relations, dunder_str)
    );
    assert_eq!(
        base_coverage(&relations, "pkg/errors.py"),
        Some((1, 0)),
        "the file declares one base and bound none, and the certificate says so"
    );
}

#[test]
fn the_certificate_counts_an_external_base_as_bound() {
    let files = package();
    let relations = link_certified(&files);

    assert_eq!(
        base_coverage(&relations, "pkg/cli.py"),
        Some((1, 1)),
        "an external base reached the placeholder, so it is bound rather than missing"
    );
    assert_eq!(
        base_coverage(&relations, "pkg/rows.py"),
        Some((1, 1)),
        "the qualified base bound to the module it named"
    );
    assert_eq!(
        base_coverage(&relations, "pkg/legacy.py"),
        Some((0, 0)),
        "a file whose classes declare no base reports zero declared, not an absence"
    );
}

// ── incremental-linker parity (the historical-replay and daemon path) ───────

/// Every `Overrides` edge, from both linkers, as a comparable tuple.
fn override_shapes(relations: &[Relation]) -> Vec<(String, String, u32)> {
    let mut shapes: Vec<(String, String, u32)> = relations
        .iter()
        .filter(|r| r.kind == RelationKind::Overrides)
        .map(|r| (r.src.to_string(), r.dst.to_string(), r.confidence.to_bits()))
        .collect();
    shapes.sort();
    shapes
}

#[test]
fn incremental_linking_matches_batch_on_every_base_shape() {
    use kin_index::{link_cross_file_incremental, IncrementalLinker};

    let files = package();
    let mut linker = IncrementalLinker::new();
    for file in &files {
        linker.add_file(&file.file_path, ArtifactId::new(), &file.entities);
    }
    linker.record_class_bases(&files);

    let batch = link(&files);
    let incremental = link_cross_file_incremental(&files, &linker)
        .expect("every fixture file has an explicitly assigned artifact identity");

    assert_eq!(
        override_shapes(&incremental),
        override_shapes(&batch),
        "the two linkers must derive one hierarchy, resolved base and external base alike"
    );
}

#[test]
fn the_incremental_certificate_discloses_bases_with_batch_parity() {
    use kin_index::{link_cross_file_incremental_with_completeness, IncrementalLinker};

    let files = package();
    let mut linker = IncrementalLinker::new();
    for file in &files {
        linker.add_file(&file.file_path, ArtifactId::new(), &file.entities);
    }
    linker.record_class_bases(&files);

    let batch = link_certified(&files);
    let incremental =
        link_cross_file_incremental_with_completeness(&files, &linker, &full_completeness(&files))
            .expect("every fixture file has an explicitly assigned artifact identity");

    for file in &files {
        assert_eq!(
            base_coverage(&incremental, &file.file_path),
            base_coverage(&batch, &file.file_path),
            "base-resolution disclosure for {} must not depend on which linker ran",
            file.file_path
        );
    }
}

/// The relink shape a daemon actually produces: the subclass file alone is
/// re-parsed, while its base file last changed in an earlier step. The base
/// must still be decided by the import the subclass wrote.
#[test]
fn a_subclass_only_relink_keeps_its_qualified_base_with_batch_parity() {
    use kin_index::{link_cross_file_incremental, IncrementalLinker};

    let files = package();
    let mut linker = IncrementalLinker::new();
    for file in &files {
        linker.add_file(&file.file_path, ArtifactId::new(), &file.entities);
    }
    linker.record_class_bases(&files);

    let rows = files
        .iter()
        .find(|file| file.file_path == "pkg/rows.py")
        .expect("the fixture holds pkg/rows.py")
        .clone();
    let relations = link_cross_file_incremental(std::slice::from_ref(&rows), &linker)
        .expect("every fixture file has an explicitly assigned artifact identity");

    let row_save = entity_id(&files, "pkg/rows.py", "Row.save");
    let real_save = entity_id(&files, "pkg/models.py", "Model.save");
    let decoy_save = entity_id(&files, "pkg/rows.py", "Model.save");
    assert!(
        has_override(&relations, row_save, real_save),
        "relinking the subclass alone still reaches the imported base: {:#?}",
        overrides_from(&relations, row_save)
    );
    assert!(!has_override(&relations, row_save, decoy_save));
}

/// An external base survives a relink of its own file alone, which is the step
/// where the import binding has to come from this parse rather than from
/// retained state.
#[test]
fn an_external_base_survives_a_file_only_relink() {
    use kin_index::{link_cross_file_incremental, IncrementalLinker};

    let files = package();
    let mut linker = IncrementalLinker::new();
    for file in &files {
        linker.add_file(&file.file_path, ArtifactId::new(), &file.entities);
    }
    linker.record_class_bases(&files);

    let cli = files
        .iter()
        .find(|file| file.file_path == "pkg/cli.py")
        .expect("the fixture holds pkg/cli.py")
        .clone();
    let relations = link_cross_file_incremental(std::slice::from_ref(&cli), &linker)
        .expect("every fixture file has an explicitly assigned artifact identity");

    let get_command = entity_id(&files, "pkg/cli.py", "AppGroup.get_command");
    assert!(
        has_override(
            &relations,
            get_command,
            external_placeholder("click", "Group.get_command")
        ),
        "{:#?}",
        overrides_from(&relations, get_command)
    );
}

/// A checkpoint round trip is where PR 153's alias handling last diverged, so
/// the same restore has to hold for base resolution.
#[test]
fn a_restored_checkpoint_keeps_every_base_shape() {
    use kin_index::{link_cross_file_incremental, IncrementalLinker};

    let files = package();
    let mut linker = IncrementalLinker::new();
    for file in &files {
        linker.add_file(&file.file_path, ArtifactId::new(), &file.entities);
    }
    linker.record_class_bases(&files);

    let bytes = serde_json::to_vec(&linker.to_checkpoint_v1()).expect("serialize checkpoint");
    let checkpoint = serde_json::from_slice(&bytes).expect("read checkpoint back");
    let restored = IncrementalLinker::from_checkpoint_v1(checkpoint).expect("restore checkpoint");

    let before = link_cross_file_incremental(&files, &linker).expect("link before the round trip");
    let after = link_cross_file_incremental(&files, &restored).expect("link after the round trip");
    assert_eq!(override_shapes(&after), override_shapes(&before));
}
