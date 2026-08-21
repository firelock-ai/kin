// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Two Python relation defects, driven through the real parser and the real
//! linker so the fixtures state what a repository actually looks like.
//!
//! FIR-2500: a method call arrived at the linker as its bare leaf, so the
//! receiver's declared type was never consulted. `find_references` on
//! `HTTPAdapter.send` in a requests-shaped package counted zero callers and
//! held the one it did see as an unproven same-name candidate, while the
//! annotation naming the receiver's type sat in the same graph.
//!
//! FIR-2508: a Python module entity is named for the file stem, so a module and
//! a same-named function land on the linker's one `(file, name)` slot. The
//! module took it, every caller of the function parked on the module node, and
//! `kin dead-code` printed the program's primary function as unreferenced.
//!
//! The fixtures below are the two shapes those tickets were found on: a package
//! shaped like `requests`' adapters, and a module whose name matches its
//! primary function.

use kin_index::{
    link_cross_file as link_cross_file_with_identities, link_cross_file_incremental, FileParseData,
    IncrementalLinker,
};
use kin_model::{ArtifactId, Entity, EntityId, EntityKind, FilePathId, RelationKind};
use kin_parser::{LanguageAdapter, PythonAdapter};

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

fn link_cross_file(files: &[FileParseData]) -> Vec<kin_model::Relation> {
    let artifact_ids = files
        .iter()
        .map(|file| (file.file_path.clone(), ArtifactId::new()))
        .collect();
    link_cross_file_with_identities(files, &artifact_ids)
        .expect("every fixture file has an explicitly assigned artifact identity")
}

/// Link the same fixture through the live-edit path, so a rule proven on the
/// batch linker is proven on the one a running daemon uses too.
fn link_incremental(files: &[FileParseData]) -> Vec<kin_model::Relation> {
    let mut linker = IncrementalLinker::new();
    for file in files {
        linker.add_file(&file.file_path, ArtifactId::new(), &file.entities);
    }
    link_cross_file_incremental(files, &linker)
        .expect("the incremental index holds every fixture file")
}

/// The id of the entity of `kind` named `name` in `file`.
///
/// The kind is part of the query on purpose: this suite is about two entities
/// that share a file and a name, so a lookup keyed on the name alone would pick
/// one of them by accident and the assertion built on it would prove nothing.
fn entity_id(files: &[FileParseData], file: &str, name: &str, kind: EntityKind) -> EntityId {
    let matches: Vec<&Entity> = files
        .iter()
        .flat_map(|f| f.entities.iter())
        .filter(|e| {
            e.name == name
                && e.kind == kind
                && e.file_origin.as_ref().map(|p| p.0.as_str()) == Some(file)
        })
        .collect();
    assert_eq!(
        matches.len(),
        1,
        "expected exactly one {kind:?} named `{name}` in `{file}`, found {}",
        matches.len()
    );
    matches[0].id
}

fn callers_of(relations: &[kin_model::Relation], dst: EntityId) -> Vec<EntityId> {
    let mut callers: Vec<EntityId> = relations
        .iter()
        .filter(|r| r.kind == RelationKind::Calls && r.dst.as_entity() == Some(dst))
        .filter_map(|r| r.src.as_entity())
        .collect();
    callers.sort();
    callers.dedup();
    callers
}

fn has_call(relations: &[kin_model::Relation], src: EntityId, dst: EntityId) -> bool {
    relations.iter().any(|r| {
        r.kind == RelationKind::Calls
            && r.src.as_entity() == Some(src)
            && r.dst.as_entity() == Some(dst)
    })
}

// ── FIR-2500: the receiver's declared type ──────────────────────────────────

const ADAPTERS_PY: &str = r#"
class BaseAdapter:
    def close(self):
        pass


class HTTPAdapter(BaseAdapter):
    def send(self, request, stream=False):
        return build_response(request)


def build_response(request):
    return request
"#;

/// A caller that annotates the receiver in its signature, which is the
/// `Session.send` shape: the adapter is handed in and its type is written down.
const SESSIONS_PY: &str = r#"
from adapters import HTTPAdapter


class Session:
    def send(self, request, adapter: HTTPAdapter):
        return adapter.send(request)
"#;

/// A caller that annotates the receiver as a field of its own class, which is
/// the `HTTPDigestAuth.handle_401` shape: the adapter is reached through an
/// attribute whose type the class declares.
const AUTH_PY: &str = r#"
from adapters import HTTPAdapter


class HTTPDigestAuth:
    connection: HTTPAdapter

    def handle_401(self, prep):
        return self.connection.send(prep)
"#;

fn requests_shaped_package() -> Vec<FileParseData> {
    vec![
        parse_py("adapters.py", ADAPTERS_PY),
        parse_py("sessions.py", SESSIONS_PY),
        parse_py("auth.py", AUTH_PY),
    ]
}

#[test]
fn a_method_call_binds_through_the_receivers_annotated_parameter_type() {
    let files = requests_shaped_package();
    let target = entity_id(
        &files,
        "adapters.py",
        "HTTPAdapter.send",
        EntityKind::Method,
    );
    let caller = entity_id(&files, "sessions.py", "Session.send", EntityKind::Method);

    let relations = link_cross_file(&files);

    assert!(
        has_call(&relations, caller, target),
        "`adapter.send(request)` under `adapter: HTTPAdapter` must bind to \
         HTTPAdapter.send; binding by bare name instead is what made \
         find_references count this caller as an unproven candidate"
    );
}

#[test]
fn a_method_call_binds_through_a_class_declared_attribute_type() {
    let files = requests_shaped_package();
    let target = entity_id(
        &files,
        "adapters.py",
        "HTTPAdapter.send",
        EntityKind::Method,
    );
    let caller = entity_id(
        &files,
        "auth.py",
        "HTTPDigestAuth.handle_401",
        EntityKind::Method,
    );

    let relations = link_cross_file(&files);

    assert!(
        has_call(&relations, caller, target),
        "`self.connection.send(prep)` under `connection: HTTPAdapter` must bind \
         to HTTPAdapter.send; this is the call site find_references missed \
         entirely while the annotation proving it was in the graph"
    );
}

#[test]
fn both_declared_receiver_callers_reach_the_method_and_nothing_else_does() {
    let files = requests_shaped_package();
    let target = entity_id(
        &files,
        "adapters.py",
        "HTTPAdapter.send",
        EntityKind::Method,
    );
    let session_send = entity_id(&files, "sessions.py", "Session.send", EntityKind::Method);
    let handle_401 = entity_id(
        &files,
        "auth.py",
        "HTTPDigestAuth.handle_401",
        EntityKind::Method,
    );

    let relations = link_cross_file(&files);
    let mut expected = vec![session_send, handle_401];
    expected.sort();

    assert_eq!(
        callers_of(&relations, target),
        expected,
        "find_references on HTTPAdapter.send must return both callers and no \
         third: the count the ticket recorded was zero"
    );
}

#[test]
fn the_incremental_linker_binds_the_same_declared_receiver_types() {
    let files = requests_shaped_package();
    let target = entity_id(
        &files,
        "adapters.py",
        "HTTPAdapter.send",
        EntityKind::Method,
    );
    let session_send = entity_id(&files, "sessions.py", "Session.send", EntityKind::Method);
    let handle_401 = entity_id(
        &files,
        "auth.py",
        "HTTPDigestAuth.handle_401",
        EntityKind::Method,
    );

    let relations = link_incremental(&files);
    let mut expected = vec![session_send, handle_401];
    expected.sort();

    assert_eq!(
        callers_of(&relations, target),
        expected,
        "a live edit must resolve the receiver's declared type exactly as the \
         full index does; a rule proven only on the batch path leaves the \
         running daemon on the old behaviour"
    );
}

#[test]
fn an_aliased_class_attribute_type_binds_where_the_bare_name_rule_cannot() {
    // The attribute half of the discriminating pair. `self.connection.send` is
    // the `HTTPDigestAuth.handle_401` shape, and under an aliased import the
    // owner key the bare-name rule builds is `Transport.send`, which matches
    // nothing. Only the class body's declaration says what type that attribute
    // holds.
    let files = vec![
        parse_py("adapters.py", ADAPTERS_PY),
        parse_py(
            "auth.py",
            r#"
from adapters import HTTPAdapter as Transport


class HTTPDigestAuth:
    connection: Transport

    def handle_401(self, prep):
        return self.connection.send(prep)
"#,
        ),
    ];
    let target = entity_id(
        &files,
        "adapters.py",
        "HTTPAdapter.send",
        EntityKind::Method,
    );
    let caller = entity_id(
        &files,
        "auth.py",
        "HTTPDigestAuth.handle_401",
        EntityKind::Method,
    );

    let relations = link_cross_file(&files);

    assert!(
        has_call(&relations, caller, target),
        "an attribute whose declared type is an aliased import must bind to the \
         class the alias names; nothing else in the linker can reach it"
    );
}

#[test]
fn an_aliased_declared_type_binds_where_the_bare_name_rule_cannot() {
    // The discriminating case, and the one that says the declared-type tier is
    // what does the work here. The bare-name rule settles a receiver call
    // against the owners the calling file's import bindings name, and it builds
    // those owner keys from the LOCAL name: `Transport.send` matches no entity,
    // because the method is stored as `HTTPAdapter.send`. So the pre-fix linker
    // reaches no owner at all and leaves the call unlinked, which is the "0
    // counted, candidate withheld" answer the ticket recorded. The annotation
    // says which type it is, and the import says what that name resolves to.
    let files = vec![
        parse_py("adapters.py", ADAPTERS_PY),
        parse_py(
            "sessions.py",
            r#"
from adapters import HTTPAdapter as Transport


class Session:
    def send(self, request, adapter: Transport):
        return adapter.send(request)
"#,
        ),
    ];
    let target = entity_id(
        &files,
        "adapters.py",
        "HTTPAdapter.send",
        EntityKind::Method,
    );
    let caller = entity_id(&files, "sessions.py", "Session.send", EntityKind::Method);

    let relations = link_cross_file(&files);

    assert!(
        has_call(&relations, caller, target),
        "a receiver declared under an aliased import must bind to the class the \
         alias names; the bare-name rule cannot reach it, so this edge exists \
         only if the declared type was consulted"
    );
}

#[test]
fn an_undeclared_aliased_receiver_still_reaches_no_owner() {
    // Pass two of the pair above. Same file, same alias, same call, and the one
    // annotation removed. Nothing else can bind it, so the edge must be absent:
    // that is what makes the test above evidence rather than a coincidence of
    // the fixture.
    let files = vec![
        parse_py("adapters.py", ADAPTERS_PY),
        parse_py(
            "sessions.py",
            r#"
from adapters import HTTPAdapter as Transport


class Session:
    def send(self, request):
        adapter = self.get_adapter(request)
        return adapter.send(request)
"#,
        ),
    ];
    let target = entity_id(
        &files,
        "adapters.py",
        "HTTPAdapter.send",
        EntityKind::Method,
    );
    let caller = entity_id(&files, "sessions.py", "Session.send", EntityKind::Method);

    let relations = link_cross_file(&files);

    assert!(
        !has_call(&relations, caller, target),
        "with no annotation the linker has no proof of the receiver's type, and \
         a bare-name match through an alias is not one; binding here would mean \
         the declared-type tier is not what bound the aliased case"
    );
}

#[test]
fn the_incremental_linker_binds_an_aliased_declared_type_too() {
    let files = vec![
        parse_py("adapters.py", ADAPTERS_PY),
        parse_py(
            "sessions.py",
            r#"
from adapters import HTTPAdapter as Transport


class Session:
    def send(self, request, adapter: Transport):
        return adapter.send(request)
"#,
        ),
    ];
    let target = entity_id(
        &files,
        "adapters.py",
        "HTTPAdapter.send",
        EntityKind::Method,
    );
    let caller = entity_id(&files, "sessions.py", "Session.send", EntityKind::Method);

    let relations = link_incremental(&files);

    assert!(
        has_call(&relations, caller, target),
        "the live-edit path must bind the aliased declared type as well"
    );
}

#[test]
fn an_inherited_method_binds_through_the_declared_subclass() {
    // `close` is declared on BaseAdapter and reached through a receiver
    // annotated with the subclass, so the type must be walked to its ancestor
    // rather than matched against the leaf `close`.
    let files = vec![
        parse_py("adapters.py", ADAPTERS_PY),
        parse_py(
            "pool.py",
            r#"
from adapters import HTTPAdapter


class Pool:
    def release(self, adapter: HTTPAdapter):
        adapter.close()
"#,
        ),
    ];
    let target = entity_id(
        &files,
        "adapters.py",
        "BaseAdapter.close",
        EntityKind::Method,
    );
    let caller = entity_id(&files, "pool.py", "Pool.release", EntityKind::Method);

    let relations = link_cross_file(&files);

    assert!(
        has_call(&relations, caller, target),
        "a declared receiver type that does not define the method must reach \
         the ancestor that does"
    );
}

#[test]
fn an_undeclared_receiver_still_binds_by_the_disclaimed_bare_name_rule() {
    // The scoping half. Nothing annotates `adapter` here, so the call must
    // reach HTTPAdapter.send exactly as it did before the declared-type tier
    // existed: through the file's import naming the one owner it can see.
    let files = vec![
        parse_py("adapters.py", ADAPTERS_PY),
        parse_py(
            "sessions.py",
            r#"
from adapters import HTTPAdapter


class Session:
    def send(self, request):
        adapter = self.get_adapter(request)
        return adapter.send(request)
"#,
        ),
    ];
    let target = entity_id(
        &files,
        "adapters.py",
        "HTTPAdapter.send",
        EntityKind::Method,
    );
    let caller = entity_id(&files, "sessions.py", "Session.send", EntityKind::Method);

    let relations = link_cross_file(&files);

    assert!(
        has_call(&relations, caller, target),
        "an unannotated receiver must keep the bare-name path it had; the \
         declared-type tier may add recall and must never remove it"
    );
}

#[test]
fn a_declared_type_the_repository_does_not_define_falls_back_to_the_bare_leaf() {
    // The fail-open half. `ThirdPartyAdapter` is not an entity anywhere, so the
    // owner-qualified name resolves to nothing. The call must not vanish: it
    // returns to the leaf `send` and settles by the rule that governed it
    // before, which here is the one owner the file's imports name.
    let files = vec![
        parse_py("adapters.py", ADAPTERS_PY),
        parse_py(
            "sessions.py",
            r#"
from adapters import HTTPAdapter
from vendor import ThirdPartyAdapter


class Session:
    def send(self, request, adapter: ThirdPartyAdapter):
        return adapter.send(request)
"#,
        ),
    ];
    let target = entity_id(
        &files,
        "adapters.py",
        "HTTPAdapter.send",
        EntityKind::Method,
    );
    let caller = entity_id(&files, "sessions.py", "Session.send", EntityKind::Method);

    let relations = link_cross_file(&files);

    assert!(
        has_call(&relations, caller, target),
        "a declared type this repository does not hold must fall back to the \
         disclaimed bare-name match, not to no edge at all"
    );
}

// ── FIR-2508: a module and a same-named function ────────────────────────────

const SEARCH_PY: &str = r#"
class Hit:
    def __init__(self, path):
        self.path = path


def search(store, terms, limit=20):
    return [Hit(term) for term in terms]
"#;

const CLI_PY: &str = r#"
from nk.search import search


def cmd_search(store, terms):
    return search(store, terms)
"#;

const TEST_SEARCH_PY: &str = r#"
from nk.search import search


def test_search_returns_hits():
    return search(None, ["a"])
"#;

fn module_name_collision_package() -> Vec<FileParseData> {
    vec![
        parse_py("nk/search.py", SEARCH_PY),
        parse_py("nk/cli.py", CLI_PY),
        parse_py("tests/test_search.py", TEST_SEARCH_PY),
    ]
}

#[test]
fn a_package_re_export_reaches_the_function_past_its_module_twin() {
    // `nk/__init__.py` re-exports `search`, so a caller writing
    // `from nk import search` pins its callee to the package rather than to the
    // module file. The package's own file does not declare the symbol, so the
    // linker falls back to the one same-named entity in that directory — and
    // the module entity named for `search.py` sits there too, making it two.
    // Two is not one, so the pinned call was refused outright and the caller
    // got no edge at all, which is a stricter loss than parking the edge on the
    // wrong node.
    let files = vec![
        parse_py("nk/__init__.py", "from nk.search import search\n"),
        parse_py("nk/search.py", SEARCH_PY),
        parse_py(
            "app.py",
            r#"
from nk import search


def run(store, terms):
    return search(store, terms)
"#,
        ),
    ];
    let function = entity_id(&files, "nk/search.py", "search", EntityKind::Function);
    let module = entity_id(&files, "nk/search.py", "search", EntityKind::Module);
    let run = entity_id(&files, "app.py", "run", EntityKind::Function);

    let relations = link_cross_file(&files);

    assert!(
        has_call(&relations, run, function),
        "a call pinned to a package must reach the function that package \
         re-exports; the module entity sharing its name is not a second \
         candidate, because a module is not callable"
    );
    assert!(
        callers_of(&relations, module).is_empty(),
        "and the module must still hold no call edges of its own"
    );
}

#[test]
fn a_module_does_not_take_the_call_edges_of_its_same_named_function() {
    let files = module_name_collision_package();
    let function = entity_id(&files, "nk/search.py", "search", EntityKind::Function);
    let module = entity_id(&files, "nk/search.py", "search", EntityKind::Module);
    let cmd_search = entity_id(&files, "nk/cli.py", "cmd_search", EntityKind::Function);

    let relations = link_cross_file(&files);

    assert!(
        has_call(&relations, cmd_search, function),
        "a caller of `search` must reach the function; parking that edge on the \
         module named for the file is what made kin dead-code print the \
         program's primary function as unreferenced"
    );
    assert!(
        callers_of(&relations, module).is_empty(),
        "a module is not callable, so no Calls edge may land on it"
    );
}

#[test]
fn every_caller_of_a_module_named_function_reaches_it() {
    let files = module_name_collision_package();
    let function = entity_id(&files, "nk/search.py", "search", EntityKind::Function);
    let cmd_search = entity_id(&files, "nk/cli.py", "cmd_search", EntityKind::Function);
    let test_search = entity_id(
        &files,
        "tests/test_search.py",
        "test_search_returns_hits",
        EntityKind::Function,
    );

    let relations = link_cross_file(&files);
    let mut expected = vec![cmd_search, test_search];
    expected.sort();

    assert_eq!(
        callers_of(&relations, function),
        expected,
        "the module twin in the same-name bucket must not read as an \
         ambiguity that drops every caller's edge"
    );
}

#[test]
fn the_incremental_linker_keeps_the_module_off_the_functions_call_edges() {
    let files = module_name_collision_package();
    let function = entity_id(&files, "nk/search.py", "search", EntityKind::Function);
    let module = entity_id(&files, "nk/search.py", "search", EntityKind::Module);
    let cmd_search = entity_id(&files, "nk/cli.py", "cmd_search", EntityKind::Function);

    let relations = link_incremental(&files);

    assert!(
        has_call(&relations, cmd_search, function),
        "the live-edit path is the one the ticket was found on: its per-file \
         index took the module last, so the module won the slot outright"
    );
    assert!(
        callers_of(&relations, module).is_empty(),
        "a module is not callable on the live path either"
    );
}
