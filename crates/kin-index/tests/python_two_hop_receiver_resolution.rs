// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The two-hop receiver: a call written through an attribute of a value whose
//! type the calling scope declares, where the attribute's own type is declared
//! on a class in another file.
//!
//! FIR-2507 / FIR-2537. `requests` writes the shape at `src/requests/auth.py`:
//!
//! ```python
//! def handle_401(self, r: Response, **kwargs: Any) -> Response:
//!     ...
//!     _r = r.connection.send(prep, **kwargs)
//! ```
//!
//! Both hops are declared. `r: Response` is a parameter annotation in the
//! calling scope, and `connection: HTTPAdapter` is a class-body annotation on
//! `Response` in `src/requests/models.py`. Nothing has to be inferred to join
//! them, and yet `find_references(HTTPAdapter.send)` counted zero callers from
//! `auth.py`: the receiver as source spells it is `r.connection`, which the
//! calling file's own annotations never key, so the call arrived at the linker
//! as the bare leaf `send`.
//!
//! FIR-2500 fixed the ONE-hop shapes, an annotated parameter and an annotated
//! attribute of the enclosing class, both of which the calling file declares by
//! itself. The second hop is the one that needs a repository-wide table,
//! because the declaration that settles it lives on another class in another
//! file.
//!
//! Every fixture here is DECLARED on both hops. A receiver the source does not
//! annotate keeps the bare-leaf behaviour it always had, which is what the
//! recall-preservation tests below pin, so this tier can only add edges.

use kin_index::{
    link_cross_file as link_cross_file_with_identities, link_cross_file_incremental, FileParseData,
    IncrementalLinker, RelationResolution,
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

fn call_resolution(
    relations: &[kin_model::Relation],
    src: EntityId,
    dst: EntityId,
) -> Option<RelationResolution> {
    relations
        .iter()
        .find(|r| {
            r.kind == RelationKind::Calls
                && r.src.as_entity() == Some(src)
                && r.dst.as_entity() == Some(dst)
        })
        .map(RelationResolution::of)
}

// ── The requests shape, three files ─────────────────────────────────────────

const ADAPTERS_PY: &str = r#"
class BaseAdapter:
    def close(self):
        pass


class HTTPAdapter(BaseAdapter):
    def send(self, request, stream=False):
        return request
"#;

/// The class carrying the attribute whose type settles the second hop. This is
/// `requests`' `models.py`: `class Response` declares `connection: HTTPAdapter`
/// in its class body, and nothing else in the repository says what that
/// attribute holds.
const MODELS_PY: &str = r#"
from adapters import HTTPAdapter


class Response:
    status_code: int
    connection: HTTPAdapter
"#;

/// The caller. `r: Response` is declared in the signature, `r.connection` is
/// the attribute, and `send` is the method. Both hops are written down.
const AUTH_PY: &str = r#"
from models import Response


class HTTPDigestAuth:
    def handle_401(self, r: Response, **kwargs):
        prep = r.request
        return r.connection.send(prep, **kwargs)
"#;

fn requests_shaped_package() -> Vec<FileParseData> {
    vec![
        parse_py("adapters.py", ADAPTERS_PY),
        parse_py("models.py", MODELS_PY),
        parse_py("auth.py", AUTH_PY),
    ]
}

#[test]
fn a_two_hop_receiver_binds_through_a_class_attribute_declared_in_another_file() {
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
        "`r.connection.send(prep)` under `r: Response` and \
         `Response.connection: HTTPAdapter` must bind to HTTPAdapter.send. \
         Both hops are declared in source and neither is in the calling file, \
         which is why the one-hop tier could not see it and \
         find_references(HTTPAdapter.send) counted this caller as nothing"
    );
}

#[test]
fn the_two_hop_edge_publishes_itself_as_type_resolved() {
    // The marker is the half a reader acts on. An edge the linker bound by
    // matching a leaf name publishes `name_only`, and every count that may
    // only use proven edges drops it. This edge was joined from two
    // declarations the source writes down, so it must publish `type_resolved`.
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

    assert_eq!(
        call_resolution(&relations, caller, target),
        Some(RelationResolution::TypeResolved),
        "a two-hop edge joined from two declarations is as proven as a one-hop \
         one; publishing it as name_only would keep every proof-weighted count \
         reading zero for a call the source spells out"
    );
}

#[test]
fn the_incremental_linker_binds_the_same_two_hop_receiver() {
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

    let relations = link_incremental(&files);

    assert!(
        has_call(&relations, caller, target),
        "a live edit must join the two declarations exactly as the full index \
         does; a rule proven only on the batch path leaves the running daemon \
         on the old behaviour"
    );
}

#[test]
fn the_two_hop_caller_is_the_only_caller_the_fixture_holds() {
    // The count is the assertion the stranger's `kin refs` failed. One caller
    // exists in this fixture and the answer must be exactly that one: an extra
    // name-matched arrival would be a wrong answer wearing a right number.
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

    assert_eq!(
        callers_of(&relations, target),
        vec![caller],
        "find_references on HTTPAdapter.send must return the two-hop caller \
         and no other; the count the ticket recorded was zero"
    );
}

#[test]
fn a_type_checking_guarded_import_still_carries_the_attribute_declaration() {
    // The shape `requests` actually writes. `models.py:90` imports HTTPAdapter
    // inside `if TYPE_CHECKING:`, which is the only place a purely annotational
    // import can live without a cycle at runtime. A table built by ignoring
    // guarded imports would miss the real repository while passing every
    // fixture that imports at module scope.
    let files = vec![
        parse_py("adapters.py", ADAPTERS_PY),
        parse_py(
            "models.py",
            r#"
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from adapters import HTTPAdapter


class Response:
    connection: HTTPAdapter
"#,
        ),
        parse_py("auth.py", AUTH_PY),
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
        "an attribute annotation whose class arrives through a TYPE_CHECKING \
         import must still bind; that guard is where a type-only import is \
         supposed to live and it is where requests puts this one"
    );
}

#[test]
fn a_two_hop_receiver_whose_classes_share_the_calling_file_binds() {
    // The same join with no file boundary anywhere. Kept separate because the
    // linker's same-file tiers are a different branch from its cross-file ones,
    // and a fix that only reached across files would leave the easier shape
    // broken while every cross-file fixture passed.
    let files = vec![parse_py(
        "store.py",
        r#"
class Adapter:
    def send(self, request):
        return request


class Response:
    connection: Adapter


def forward(r: Response, request):
    return r.connection.send(request)
"#,
    )];
    let target = entity_id(&files, "store.py", "Adapter.send", EntityKind::Method);
    let caller = entity_id(&files, "store.py", "forward", EntityKind::Function);

    let relations = link_cross_file(&files);

    assert!(
        has_call(&relations, caller, target),
        "a two-hop receiver whose declarations are all in the calling file \
         must bind; nothing about this join needs a file boundary"
    );
}

// ── The attribute table must be keyed by its class ──────────────────────────

#[test]
fn an_attribute_name_two_classes_declare_binds_to_the_declared_owners_type() {
    // The discriminator. Both classes declare an attribute spelled
    // `connection`, with different types. A table keyed on the attribute name
    // alone would answer with whichever it stored last, which is a wrong edge
    // rather than a missing one, and wrong edges are worse.
    let files = vec![
        parse_py(
            "adapters.py",
            r#"
class HTTPAdapter:
    def send(self, request):
        return request


class SocketAdapter:
    def send(self, request):
        return request
"#,
        ),
        parse_py(
            "models.py",
            r#"
from adapters import HTTPAdapter, SocketAdapter


class Response:
    connection: HTTPAdapter


class SocketResponse:
    connection: SocketAdapter
"#,
        ),
        parse_py(
            "auth.py",
            r#"
from models import SocketResponse


class Auth:
    def handle(self, r: SocketResponse, prep):
        return r.connection.send(prep)
"#,
        ),
    ];
    let socket_send = entity_id(
        &files,
        "adapters.py",
        "SocketAdapter.send",
        EntityKind::Method,
    );
    let http_send = entity_id(
        &files,
        "adapters.py",
        "HTTPAdapter.send",
        EntityKind::Method,
    );
    let caller = entity_id(&files, "auth.py", "Auth.handle", EntityKind::Method);

    let relations = link_cross_file(&files);

    assert!(
        has_call(&relations, caller, socket_send),
        "`r: SocketResponse` declares which class owns the `connection` \
         attribute, so the call must reach SocketAdapter.send"
    );
    assert!(
        !has_call(&relations, caller, http_send),
        "the other class's `connection` attribute says nothing about this \
         call; binding it would be a fabricated edge, which is a worse answer \
         than the missing one this fixture started from"
    );
}

// ── Recall preservation: this tier may add edges and never remove one ───────

#[test]
fn an_undeclared_two_hop_receiver_keeps_its_bare_name_behaviour() {
    // The scoping half. Nothing annotates `r` here, so no first hop is
    // declared and the table is never consulted. The call must reach whatever
    // the bare-name rule reached before, which here is the one owner the
    // calling file's import names.
    let files = vec![
        parse_py("adapters.py", ADAPTERS_PY),
        parse_py(
            "auth.py",
            r#"
from adapters import HTTPAdapter


class Auth:
    def handle(self, r, prep):
        return r.connection.send(prep)
"#,
        ),
    ];
    let target = entity_id(
        &files,
        "adapters.py",
        "HTTPAdapter.send",
        EntityKind::Method,
    );
    let caller = entity_id(&files, "auth.py", "Auth.handle", EntityKind::Method);

    let relations = link_cross_file(&files);

    assert!(
        has_call(&relations, caller, target),
        "an unannotated two-hop receiver must keep the bare-name path it had; \
         the declared-type tier may add recall and must never remove it"
    );
}

#[test]
fn a_declared_attribute_type_the_repository_does_not_define_falls_back() {
    // The fail-open half. `Response.connection` is declared, and its type is a
    // class no file here defines, so the join names nothing. The call must
    // return to the leaf `send` and settle by the rule that governed it before.
    let files = vec![
        parse_py("adapters.py", ADAPTERS_PY),
        parse_py(
            "models.py",
            r#"
from vendor import ThirdPartyAdapter


class Response:
    connection: ThirdPartyAdapter
"#,
        ),
        parse_py(
            "auth.py",
            r#"
from adapters import HTTPAdapter
from models import Response


class Auth:
    def handle(self, r: Response, prep):
        return r.connection.send(prep)
"#,
        ),
    ];
    let target = entity_id(
        &files,
        "adapters.py",
        "HTTPAdapter.send",
        EntityKind::Method,
    );
    let caller = entity_id(&files, "auth.py", "Auth.handle", EntityKind::Method);

    let relations = link_cross_file(&files);

    assert!(
        has_call(&relations, caller, target),
        "a declared attribute type this repository does not hold must fall \
         back to the disclaimed bare-name match, not to no edge at all"
    );
}

#[test]
fn an_attribute_the_class_never_declares_falls_back_to_the_bare_leaf() {
    // `Response` is declared as the first hop's type and it declares no
    // `connection` attribute at all. The table has no entry, the join produces
    // nothing, and the call must keep the behaviour it had.
    let files = vec![
        parse_py("adapters.py", ADAPTERS_PY),
        parse_py(
            "models.py",
            r#"
class Response:
    status_code: int
"#,
        ),
        parse_py(
            "auth.py",
            r#"
from adapters import HTTPAdapter
from models import Response


class Auth:
    def handle(self, r: Response, prep):
        return r.connection.send(prep)
"#,
        ),
    ];
    let target = entity_id(
        &files,
        "adapters.py",
        "HTTPAdapter.send",
        EntityKind::Method,
    );
    let caller = entity_id(&files, "auth.py", "Auth.handle", EntityKind::Method);

    let relations = link_cross_file(&files);

    assert!(
        has_call(&relations, caller, target),
        "an undeclared attribute leaves the join with nothing to say, and a \
         tier with nothing to say must hand the call back unchanged"
    );
}

#[test]
fn a_three_hop_receiver_is_left_to_the_bare_name_rule() {
    // The bound. This tier joins exactly one declared attribute onto one
    // declared root. `a.b.c.send()` needs two joins and the second one is not
    // written down here, so the tier must decline rather than guess, and the
    // call keeps the bare leaf it arrived with.
    let files = vec![
        parse_py("adapters.py", ADAPTERS_PY),
        parse_py(
            "models.py",
            r#"
from adapters import HTTPAdapter


class Inner:
    connection: HTTPAdapter


class Response:
    inner: Inner
"#,
        ),
        parse_py(
            "auth.py",
            r#"
from adapters import HTTPAdapter
from models import Response


class Auth:
    def handle(self, r: Response, prep):
        return r.inner.connection.send(prep)
"#,
        ),
    ];
    let target = entity_id(
        &files,
        "adapters.py",
        "HTTPAdapter.send",
        EntityKind::Method,
    );
    let caller = entity_id(&files, "auth.py", "Auth.handle", EntityKind::Method);

    let relations = link_cross_file(&files);

    assert!(
        has_call(&relations, caller, target),
        "a three-hop receiver is out of this tier's scope and must keep the \
         bare-name edge it already had; declining is the correct answer and \
         losing the edge is not"
    );
    assert_eq!(
        call_resolution(&relations, caller, target),
        Some(RelationResolution::NameOnly),
        "an edge this tier declined to prove must still publish itself as \
         name_only; a tier that declines must not leave a proven marker behind"
    );
}

#[test]
fn a_guarded_import_does_not_widen_the_bare_name_owner_tier() {
    // The regression this change caused and this fixture caught. Recording a
    // TYPE_CHECKING import as an ordinary one gave `sessions.py` two visible
    // owners of `send`, so the tier that settles a bare method name from the
    // one owner a file imports correctly declined, and `Session.send`'s real
    // call to `adapter.send(request)` stopped resolving to anything. Measured
    // on the pinned requests tree: the edge disappeared while the two-hop edge
    // appeared, which is trading one crown caller for the other.
    let files = vec![
        parse_py(
            "adapters.py",
            r#"
class BaseAdapter:
    def send(self, request):
        raise NotImplementedError


class HTTPAdapter(BaseAdapter):
    def send(self, request, stream=False):
        return request
"#,
        ),
        parse_py(
            "sessions.py",
            r#"
from typing import TYPE_CHECKING

from adapters import HTTPAdapter

if TYPE_CHECKING:
    from adapters import BaseAdapter


class Session:
    fallback: BaseAdapter

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
        "an unannotated receiver must still settle on the one owner the file \
         IMPORTS; a name a guard binds for annotations is not a second owner \
         for the bare-name rule"
    );
}

#[test]
fn a_declined_two_hop_call_keeps_the_edge_the_bare_leaf_would_have_had() {
    // The hand-back invariant, on the shape that exposed it. The parser writes
    // the owner half from declarations, so a call whose join fails carries a
    // name the source never spelled. Tier (d) mints its cross-repo placeholder
    // from `dst_name`, and a dotted name there produced no edge at all: four
    // real unresolved-receiver edges vanished from the requests measurement
    // until a declining tier handed the call back unchanged.
    let files = vec![parse_py(
        "client.py",
        r#"
from vendor import Transport


class Session:
    transport: Transport


def run(session: Session, payload):
    return session.transport.dispatch(payload)
"#,
    )];
    let caller = entity_id(&files, "client.py", "run", EntityKind::Function);

    let relations = link_cross_file(&files);

    let outgoing: Vec<&kin_model::Relation> = relations
        .iter()
        .filter(|r| r.kind == RelationKind::Calls && r.src.as_entity() == Some(caller))
        .collect();

    // Tier (e) builds its token as `{receiver}.{symbol}` and refuses a symbol
    // that carries a dot of its own, so the parser's `Session.transport.dispatch`
    // reached it as a symbol it could not use and no edge was recorded at all.
    assert!(
        outgoing.iter().any(|r| r
            .evidence
            .iter()
            .any(|e| e.token.as_deref() == Some("session.transport.dispatch"))),
        "a two-hop call the repository cannot settle must still record the \
         call it makes, through the receiver the source wrote and the bare \
         symbol it read; got {outgoing:?}"
    );
}

#[test]
fn an_attribute_annotated_only_in_init_is_outside_the_tables_scope() {
    // The bound this table is drawn at, pinned so it is a decision rather than
    // an accident. `self.connection: HTTPAdapter = None` inside `__init__`
    // declares the same thing a class-body annotation does, and the table reads
    // class bodies only. The call must keep the behaviour it had rather than
    // resolve halfway: recording the bound here is what makes widening it
    // later a visible change instead of a silent one.
    let files = vec![
        parse_py("adapters.py", ADAPTERS_PY),
        parse_py(
            "models.py",
            r#"
from adapters import HTTPAdapter


class Response:
    def __init__(self):
        self.connection: HTTPAdapter = None
"#,
        ),
        parse_py(
            "auth.py",
            r#"
from models import Response


class Auth:
    def handle(self, r: Response, prep):
        return r.connection.send(prep)
"#,
        ),
    ];
    let target = entity_id(
        &files,
        "adapters.py",
        "HTTPAdapter.send",
        EntityKind::Method,
    );
    let caller = entity_id(&files, "auth.py", "Auth.handle", EntityKind::Method);

    let relations = link_cross_file(&files);

    assert!(
        !has_call(&relations, caller, target),
        "an attribute declared only in __init__ is outside this table's scope \
         today; if this starts binding, the bound moved and this fixture is \
         the place to say so deliberately"
    );
}
