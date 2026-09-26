// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! A decorator written through an object is a member call, and it binds like one.
//!
//! `@app.post("/items/")` above `def create_item` calls the method `post` on the
//! value `app`. The decorated definition owns that call site, as it owns every
//! decorator it carries, but the call can only reach a member of `app`'s type.
//! A free function that happens to be named `post` is never the destination,
//! whether it sits in another file or in the same one.
//!
//! Each case indexes real source through the pipeline, which resolves a file's
//! own relations, and then links every file cross-file. The graph holds both
//! halves, so both are checked together.

use std::collections::HashMap;

use kin_index::{link_cross_file, FileParseData, IndexPipeline};
use kin_model::{ArtifactId, Entity, EntityId, FilePathId, Relation, RelationKind};

struct Indexed {
    files: Vec<FileParseData>,
    relations: Vec<Relation>,
}

fn index(sources: &[(&str, &str)]) -> Indexed {
    let pipeline = IndexPipeline::new();
    let mut files = Vec::new();
    let mut relations = Vec::new();
    for (path, source) in sources {
        let bytes = source.as_bytes();
        let indexed = pipeline
            .index_file_content_with_tests(&FilePathId::new(*path), bytes, kin_blobs::digest(bytes))
            .expect("index fixture source")
            .indexed_file;
        relations.extend(indexed.relations);
        files.push(FileParseData {
            file_path: indexed.file_id.0.clone(),
            entities: indexed.entities,
            relations: indexed.extracted_relations,
            imports: indexed.imports,
        });
    }
    let artifact_ids: HashMap<String, ArtifactId> = files
        .iter()
        .map(|file| (file.file_path.clone(), ArtifactId::new()))
        .collect();
    relations.extend(link_cross_file(&files, &artifact_ids).expect("link fixture"));
    Indexed { files, relations }
}

impl Indexed {
    fn entity(&self, file: &str, name: &str) -> &Entity {
        self.files
            .iter()
            .filter(|parsed| parsed.file_path == file)
            .flat_map(|parsed| parsed.entities.iter())
            .find(|entity| entity.name == name)
            .unwrap_or_else(|| panic!("entity `{name}` in `{file}` not found"))
    }

    fn id(&self, file: &str, name: &str) -> EntityId {
        self.entity(file, name).id
    }

    fn calls_from(&self, src: EntityId) -> Vec<(String, String)> {
        let mut named: Vec<_> = self
            .relations
            .iter()
            .filter(|relation| {
                relation.kind == RelationKind::Calls && relation.src.as_entity() == Some(src)
            })
            .filter_map(|relation| {
                let dst = relation.dst.as_entity()?;
                let entity = self
                    .files
                    .iter()
                    .flat_map(|parsed| parsed.entities.iter())
                    .find(|entity| entity.id == dst)?;
                Some((entity.file_origin.as_ref()?.0.clone(), entity.name.clone()))
            })
            .collect();
        named.sort();
        named.dedup();
        named
    }

    fn calls(&self, src: EntityId, dst: EntityId) -> bool {
        self.relations.iter().any(|relation| {
            relation.kind == RelationKind::Calls
                && relation.src.as_entity() == Some(src)
                && relation.dst.as_entity() == Some(dst)
        })
    }
}

const APPLICATIONS: &str = "\
class FastAPI:
    def post(self, path, **kwargs):
        def decorator(func):
            return func
        return decorator

    def get(self, path, **kwargs):
        def decorator(func):
            return func
        return decorator
";

const ROUTING: &str = "\
class APIRouter:
    def get(self, path, **kwargs):
        def decorator(func):
            return func
        return decorator
";

const PACKAGE: &str = "\
from .applications import FastAPI as FastAPI
from .routing import APIRouter as APIRouter
";

/// `docs_src/body/tutorial002_py310.py` in fastapi, as written.
const TUTORIAL: &str = "\
from fastapi import FastAPI
from pydantic import BaseModel


class Item(BaseModel):
    name: str
    price: float


app = FastAPI()


@app.post(\"/items/\")
async def create_item(item: Item):
    item_dict = item.model_dump()
    return item_dict
";

/// `tests/test_additional_properties_bool.py` in fastapi, trimmed: a route
/// handler that is itself named `post`, registered through `@app.post`, and a
/// test that drives it through a client.
const HANDLER_NAMED_POST: &str = "\
from fastapi import FastAPI
from fastapi.testclient import TestClient

app = FastAPI()


@app.post(\"/\")
async def post(foo=None):
    return foo


client = TestClient(app)


def test_call_invalid():
    response = client.post(\"/\", json={\"foo\": {\"bar\": \"baz\"}})
    assert response.status_code == 422
";

#[test]
fn an_app_decorator_binds_the_app_method_and_never_an_unrelated_free_function() {
    let graph = index(&[
        ("fastapi/applications.py", APPLICATIONS),
        ("fastapi/routing.py", ROUTING),
        ("fastapi/__init__.py", PACKAGE),
        ("docs_src/body/tutorial002_py310.py", TUTORIAL),
        (
            "tests/test_additional_properties_bool.py",
            HANDLER_NAMED_POST,
        ),
    ]);
    let create_item = graph.id("docs_src/body/tutorial002_py310.py", "create_item");
    let handler = graph.id("tests/test_additional_properties_bool.py", "post");
    let test_call_invalid = graph.id(
        "tests/test_additional_properties_bool.py",
        "test_call_invalid",
    );
    let fastapi_post = graph.id("fastapi/applications.py", "FastAPI.post");

    assert!(
        !graph.calls(create_item, handler),
        "`@app.post` on create_item is a call through `app`, not a call to the free \
         function `post` in another file; create_item calls {:?}",
        graph.calls_from(create_item)
    );
    assert!(
        !graph.calls(handler, handler),
        "the handler named `post` does not call itself through its own `@app.post`; \
         it calls {:?}",
        graph.calls_from(handler)
    );
    assert!(
        !graph.calls(test_call_invalid, handler),
        "`client.post(...)` is a call through `client`, not a call to the same-file \
         function `post`; test_call_invalid calls {:?}",
        graph.calls_from(test_call_invalid)
    );

    // The positive half: the file imports exactly one owner that defines `post`,
    // so the decorator binds that owner's method, which is what a type checker
    // resolves `app.post` to.
    for decorated in [create_item, handler] {
        assert!(
            graph.calls(decorated, fastapi_post),
            "`@app.post` binds FastAPI.post, the one imported owner defining `post`; \
             the decorated function calls {:?}",
            graph.calls_from(decorated)
        );
    }
}

#[test]
fn a_decorator_through_an_object_whose_owner_is_ambiguous_links_nothing() {
    // Both imported owners define `get`, and no free function is ever a member
    // of `app`. Nothing at the call site chooses between the two methods, so no
    // edge is the honest answer.
    let graph = index(&[
        ("fastapi/applications.py", APPLICATIONS),
        ("fastapi/routing.py", ROUTING),
        ("fastapi/__init__.py", PACKAGE),
        ("helpers.py", "def get(url):\n    return url\n"),
        (
            "main.py",
            "from fastapi import APIRouter, FastAPI\n\napp = FastAPI()\n\n\n@app.get(\"/\")\ndef root():\n    return 1\n",
        ),
    ]);
    let root = graph.id("main.py", "root");
    assert!(
        graph.calls_from(root).is_empty(),
        "an object call whose owner the file cannot settle links nothing, got {:?}",
        graph.calls_from(root)
    );
}

#[test]
fn a_router_decorator_binds_the_router_method_the_file_imports() {
    let graph = index(&[
        ("fastapi/applications.py", APPLICATIONS),
        ("fastapi/routing.py", ROUTING),
        ("fastapi/__init__.py", PACKAGE),
        ("helpers.py", "def get(url):\n    return url\n"),
        (
            "items.py",
            "from fastapi import APIRouter\n\nrouter = APIRouter()\n\n\n@router.get(\"/items\")\ndef read_items():\n    return []\n",
        ),
    ]);
    let read_items = graph.id("items.py", "read_items");
    assert_eq!(
        graph.calls_from(read_items),
        vec![(
            "fastapi/routing.py".to_string(),
            "APIRouter.get".to_string()
        )],
        "`@router.get` binds only the method of the one imported owner"
    );
}

#[test]
fn a_decorator_naming_a_free_function_still_binds_it() {
    // Bare decorators are calls to the function they name, imported or local.
    let graph = index(&[
        ("registry.py", "def register(func):\n    return func\n"),
        (
            "handlers.py",
            "from registry import register\n\n\ndef traced(func):\n    return func\n\n\n@register\n@traced\ndef handle():\n    return 1\n",
        ),
    ]);
    let handle = graph.id("handlers.py", "handle");
    assert!(
        graph.calls(handle, graph.id("registry.py", "register")),
        "an imported bare decorator binds the function it imports, got {:?}",
        graph.calls_from(handle)
    );
    assert!(
        graph.calls(handle, graph.id("handlers.py", "traced")),
        "a same-file bare decorator binds the local function, got {:?}",
        graph.calls_from(handle)
    );
}

#[test]
fn free_function_and_method_calls_in_a_body_keep_their_bindings() {
    let graph = index(&[
        ("fastapi/applications.py", APPLICATIONS),
        ("fastapi/__init__.py", PACKAGE),
        ("fastapi/routing.py", ROUTING),
        ("helpers.py", "def compute(value):\n    return value\n"),
        ("decoys.py", "def post(url):\n    return url\n"),
        (
            "wiring.py",
            "from fastapi import FastAPI\nfrom helpers import compute\n\n\ndef local_step(value):\n    return value\n\n\ndef wire(app: FastAPI, handler):\n    local_step(compute(1))\n    return app.post(\"/x\")(handler)\n",
        ),
    ]);
    let wire = graph.id("wiring.py", "wire");
    assert!(
        graph.calls(wire, graph.id("helpers.py", "compute")),
        "an imported free-function call binds its definition, got {:?}",
        graph.calls_from(wire)
    );
    assert!(
        graph.calls(wire, graph.id("wiring.py", "local_step")),
        "a same-file free-function call binds the local definition, got {:?}",
        graph.calls_from(wire)
    );
    assert!(
        graph.calls(wire, graph.id("fastapi/applications.py", "FastAPI.post")),
        "a method call through a typed receiver binds the method, got {:?}",
        graph.calls_from(wire)
    );
    assert!(
        !graph.calls(wire, graph.id("decoys.py", "post")),
        "a method call never binds a free function by its leaf, got {:?}",
        graph.calls_from(wire)
    );
}

#[test]
fn a_member_call_never_binds_a_same_file_free_function_by_its_leaf() {
    // The per-file resolver answers a file's own names before the linker runs.
    // A call through a value reaches a member of that value's type, so the
    // same-file free function sharing the leaf is a decoy for it, exactly as the
    // linker already treats it.
    let graph = index(&[(
        "service.py",
        "def get(key):\n    return key\n\n\ndef helper():\n    return 1\n\n\ndef lookup(settings):\n    helper()\n    return settings.get(\"name\")\n",
    )]);
    let lookup = graph.id("service.py", "lookup");
    assert!(
        !graph.calls(lookup, graph.id("service.py", "get")),
        "`settings.get(...)` does not call the module-level `get`, got {:?}",
        graph.calls_from(lookup)
    );
    assert!(
        graph.calls(lookup, graph.id("service.py", "helper")),
        "a bare same-file call still binds the local function, got {:?}",
        graph.calls_from(lookup)
    );
}
