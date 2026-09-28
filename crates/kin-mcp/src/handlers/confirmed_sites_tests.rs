// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! A site `find_references` confirms is one some counted edge recorded.
//!
//! A compiler-graded measurement of Go call sites on cli/cli at `14d339d9`,
//! with gopls enriching the store, scored four false sites for
//! `Repository.RepoOwner`:
//! `create.go:649` and `:697`, `clone.go:162` and `fork.go:260`. Each is a
//! `RepoOwner()` call on a `ghrepo.Interface` value, which the Go type checker
//! resolves to the interface method. gopls resolved every one of them there,
//! and the language-server edges in the store say so. What confirmed them was
//! the row: `NewCreateContext` also calls `Repository.RepoOwner` directly on
//! lines 678 and 723, and the parser's receiver fan-out recorded all four
//! `.RepoOwner()` calls against every method of that name. One row per caller,
//! summarized as its strongest edge and the union of every edge's lines,
//! confirmed the fan-out's sites under gopls's resolution.
//!
//! These tests build that store in miniature, through the tool itself, and hold
//! the answer to what each edge proved. They also guard the other direction,
//! and other languages: every site a proven edge recorded stays confirmed.

use std::collections::HashMap;

use kin_db::InMemoryGraph;
use kin_model::entity::SourceSpan;
use kin_model::ids::RelationId;
use kin_model::relation::{Relation, RelationOrigin};
use kin_model::{
    Entity, EntityId, EntityKind, EntityMetadata, EntityRole, EntityStore, FilePathId,
    FingerprintAlgorithm, GraphNodeId, Hash256, LanguageId, RelationEvidence, RelationKind,
    SemanticFingerprint, Visibility,
};

use super::entities::handle_find_references;
use crate::types::{ContentBlock, ToolCallResult};

/// The confidence the linker's receiver-method fan-out persists.
const FAN_OUT: f32 = kin_index::resolution::RECEIVER_NAME_FANOUT_CONFIDENCE;

/// Produce a multi-site parser edge through the real linker. A scalar tier
/// alone cannot prove every occurrence of an aggregated edge; the linker must
/// stamp each fresh occurrence before combining them.
pub(super) fn linked_calls(src: &Entity, dst: &Entity, lines: &[u32]) -> Relation {
    let last_line = *lines.iter().max().expect("at least one call site");
    let file = &src.file_origin.as_ref().unwrap().0;
    let target_file = &dst.file_origin.as_ref().unwrap().0;
    let same_file = file == target_file;
    let import_source = if same_file {
        None
    } else {
        // These fixtures use sibling files, so the parser can pin the exact
        // module without depending on a global same-name lookup.
        let parent = file.rsplit_once('/').unwrap().0;
        let name = target_file.strip_prefix(&format!("{parent}/")).unwrap();
        // This is a synthetic module pin for a consumer test, not a test of
        // each language's import syntax or project module discovery.
        Some(format!("./{name}"))
    };
    let relations = lines
        .iter()
        .map(|line| kin_parser::ExtractedRelation {
            kind: RelationKind::Calls,
            src_name: src.name.clone(),
            dst_name: dst.name.clone(),
            import_source: import_source.clone(),
            call_shape: None,
            receiver: None,
            site: Some(kin_parser::RelationSite {
                start_byte: *line as usize * 10,
                end_byte: *line as usize * 10 + 1,
                start_line: line - 1,
                start_col: 0,
                end_line: line - 1,
                end_col: 1,
                syntactic_role: None,
            }),
        })
        .collect();
    // A raw occurrence must have a lexical owner, as it does in a parse.
    let mut caller = src.clone();
    caller.span = Some(SourceSpan {
        file: FilePathId::new(file),
        start_byte: 0,
        end_byte: last_line as usize * 10 + 2,
        start_line: 0,
        start_col: 0,
        end_line: last_line,
        end_col: 0,
    });
    let mut files = vec![kin_index::FileParseData {
        file_path: file.clone(),
        entities: if same_file {
            vec![caller, dst.clone()]
        } else {
            vec![caller]
        },
        relations,
        imports: vec![],
    }];
    if !same_file {
        files.push(kin_index::FileParseData {
            file_path: target_file.clone(),
            entities: vec![dst.clone()],
            relations: vec![],
            imports: vec![],
        });
    }
    let artifact_ids = files
        .iter()
        .map(|file| (file.file_path.clone(), kin_model::ArtifactId::new()))
        .collect();
    let relation = kin_index::link_cross_file(&files, &artifact_ids)
        .unwrap()
        .into_iter()
        .find(|rel| {
            rel.kind == RelationKind::Calls
                && rel.src == GraphNodeId::Entity(src.id)
                && rel.dst == GraphNodeId::Entity(dst.id)
        })
        .expect("the linker resolved the fixture's calls");
    assert_eq!(relation.confidence, if same_file { 1.0 } else { 0.9 });
    assert_eq!(
        relation.origin,
        if same_file {
            RelationOrigin::Parsed
        } else {
            RelationOrigin::Inferred
        }
    );
    relation
}

fn entity(language: LanguageId, kind: EntityKind, name: &str, file: &str) -> Entity {
    Entity {
        id: EntityId::new(),
        kind,
        name: name.to_string(),
        language,
        fingerprint: SemanticFingerprint {
            algorithm: FingerprintAlgorithm::V1TreeSitter,
            ast_hash: Hash256::from_bytes([0; 32]),
            signature_hash: Hash256::from_bytes([0; 32]),
            behavior_hash: Hash256::from_bytes([0; 32]),
            equivalence_hash: Hash256::from_bytes([0; 32]),
            stability_score: 1.0,
        },
        file_origin: Some(FilePathId::new(file)),
        span: None,
        signature: name.to_string(),
        visibility: Visibility::Public,
        role: EntityRole::Source,
        doc_summary: None,
        metadata: EntityMetadata::default(),
        lineage_parent: None,
        created_in: None,
        superseded_by: None,
    }
}

/// An edge recording one site per 1-based line in `lines`, all in `file`.
fn edge(
    src: &Entity,
    dst: &Entity,
    kind: RelationKind,
    origin: RelationOrigin,
    confidence: f32,
    file: &str,
    lines: &[u32],
) -> Relation {
    // What this build records: a Go method's reference sites are proven one
    // by one, and every other destination's keep the plain rule.
    let rule = match origin {
        RelationOrigin::Lsp if kind == RelationKind::Calls => Some("lsp_call_hierarchy"),
        RelationOrigin::Lsp if dst.language == LanguageId::Go && dst.kind == EntityKind::Method => {
            Some(kin_model::LSP_PROVEN_METHOD_REFERENCES_RULE)
        }
        RelationOrigin::Lsp => Some(kin_model::LSP_REFERENCES_RULE),
        _ => None,
    };
    Relation {
        id: RelationId::new(),
        kind,
        src: GraphNodeId::Entity(src.id),
        dst: GraphNodeId::Entity(dst.id),
        confidence,
        origin,
        created_in: None,
        import_source: None,
        evidence: lines
            .iter()
            .map(|line| RelationEvidence {
                source_span: Some(SourceSpan {
                    file: FilePathId::new(file),
                    start_byte: 0,
                    end_byte: 1,
                    // Graph lines are 0-based; the tool serves them 1-based.
                    start_line: line - 1,
                    start_col: 0,
                    end_line: line - 1,
                    end_col: 1,
                }),
                parser_rule: rule.map(str::to_string),
                occurrence_count: 1,
                ..RelationEvidence::default()
            })
            .collect(),
    }
}

fn body(result: &ToolCallResult) -> serde_json::Value {
    let ContentBlock::Text { text } = result.content.first().expect("a content block");
    serde_json::from_str(text).expect("a JSON reply")
}

async fn find_references(store: &InMemoryGraph, focal: &Entity) -> serde_json::Value {
    find_references_with(store, focal, &[]).await
}

async fn find_references_with(
    store: &InMemoryGraph,
    focal: &Entity,
    extra: &[(&str, serde_json::Value)],
) -> serde_json::Value {
    let mut args = HashMap::from([(
        "entity_id".to_string(),
        serde_json::json!(focal.id.to_string()),
    )]);
    for (key, value) in extra {
        args.insert(key.to_string(), value.clone());
    }
    body(&handle_find_references(&args, store, None).await.unwrap())
}

/// `(name, sites)` for every row in `rows`, in reply order.
///
/// A row serves its sites inside its caller, and these fixtures' callers carry
/// no span, so each site is counted rather than placed. Which lines a split
/// keeps is pinned where the row is cut, in `common`'s reference-site tests
/// and in `parser_site_confidence`.
fn sites(rows: &serde_json::Value) -> Vec<(String, usize)> {
    rows.as_array()
        .expect("an array of rows")
        .iter()
        .map(|row| {
            let sites = row["sites"].as_array().expect("every row lists its sites");
            assert_eq!(row["site_count"], sites.len(), "{row:#}");
            (row["name"].as_str().unwrap().to_string(), sites.len())
        })
        .collect()
}

fn row_named<'a>(rows: &'a serde_json::Value, name: &str) -> &'a serde_json::Value {
    rows.as_array()
        .unwrap()
        .iter()
        .find(|row| row["name"] == name)
        .unwrap_or_else(|| panic!("no row named {name} in {rows:#}"))
}

const CREATE_GO: &str = "pkg/cmd/pr/create/create.go";

/// The gh CLI store around `RepoOwner`, as the K-gopls tier built it.
///
/// `NewCreateContext` calls `RepoOwner()` four times. Lines 678 and 723 are
/// calls on an `*api.Repository`, and gopls resolves them to
/// `Repository.RepoOwner`; lines 649 and 697 are calls on a
/// `ghrepo.Interface`, and gopls resolves them to `Interface.RepoOwner`. Both
/// the outgoing-call arm and the references arm recorded exactly that. The
/// parser saw four `x.RepoOwner()` calls it could not type and fanned each one
/// out to every method named `RepoOwner`.
struct RepoOwnerStore {
    store: InMemoryGraph,
    concrete: Entity,
    interface: Entity,
}

fn repo_owner_store() -> RepoOwnerStore {
    let store = InMemoryGraph::new();
    let concrete = entity(
        LanguageId::Go,
        EntityKind::Method,
        "Repository.RepoOwner",
        "api/queries_repo.go",
    );
    let interface = entity(
        LanguageId::Go,
        EntityKind::Method,
        "Interface.RepoOwner",
        "internal/ghrepo/repo.go",
    );
    let twin = entity(
        LanguageId::Go,
        EntityKind::Method,
        "ghRepo.RepoOwner",
        "internal/ghrepo/repo.go",
    );
    let caller = entity(
        LanguageId::Go,
        EntityKind::Function,
        "NewCreateContext",
        CREATE_GO,
    );
    for e in [&concrete, &interface, &twin, &caller] {
        store.upsert_entity(e).unwrap();
    }
    for (target, proven) in [(&concrete, [678, 723]), (&interface, [649, 697])] {
        for kind in [RelationKind::Calls, RelationKind::References] {
            store
                .upsert_relation(&edge(
                    &caller,
                    target,
                    kind,
                    RelationOrigin::Lsp,
                    0.95,
                    CREATE_GO,
                    &proven,
                ))
                .unwrap();
        }
    }
    for target in [&concrete, &interface, &twin] {
        store
            .upsert_relation(&edge(
                &caller,
                target,
                RelationKind::Calls,
                RelationOrigin::Inferred,
                FAN_OUT,
                CREATE_GO,
                &[649, 678, 697, 723],
            ))
            .unwrap();
    }
    RepoOwnerStore {
        store,
        concrete,
        interface,
    }
}

/// The four false rows, as the study found them: calls through the interface
/// confirmed as calls of the concrete method. The two direct calls, which both
/// the language server and the fan-out recorded, stay confirmed.
#[tokio::test]
async fn a_concrete_method_confirms_only_the_sites_gopls_resolved_to_it() {
    let fixture = repo_owner_store();
    let reply = find_references(&fixture.store, &fixture.concrete).await;

    assert_eq!(
        sites(&reply["references"]),
        vec![("NewCreateContext".to_string(), 2)],
        "only the direct calls are confirmed; 649 and 697 are calls on a ghrepo.Interface \
         value that nothing resolved to this method: {reply:#}"
    );
    let counted = row_named(&reply["references"], "NewCreateContext");
    assert_eq!(counted["resolution"], "type_resolved", "{reply:#}");
    assert_eq!(
        counted["sites_partial_reason"], "unconfirmed_sites_in_candidates",
        "the counted row says its caller has more sites held as candidates: {reply:#}"
    );

    // Held, not dropped, and labelled with what resolved them: nothing.
    let held = row_named(&reply["candidates"], "NewCreateContext");
    assert_eq!(held["site_count"], 2, "{reply:#}");
    assert_eq!(held["resolution"], "name_only", "{reply:#}");
    assert_eq!(
        held["relation_kinds"],
        serde_json::json!(["calls"]),
        "{reply:#}"
    );

    assert_eq!(reply["total_upstream"], 1, "{reply:#}");
    let candidates = reply["candidates"].as_array().unwrap().len() as u64;
    assert_eq!(reply["unconfirmed_candidates"], candidates, "{reply:#}");
    assert_eq!(
        reply["counts"]["receiver_name_candidates"], candidates,
        "the held part is a receiver-name candidate: {reply:#}"
    );
    let dispatch = reply["counts"]["interface_dispatch_candidates"]
        .as_u64()
        .unwrap_or(0);
    assert_eq!(
        reply["counts"]["upstream_including_unconfirmed"],
        1 + dispatch,
        "one caller counted for some sites and held for others is one caller: {reply:#}"
    );
}

/// The mirror, and the direction released stores already hold: the direct
/// calls of the concrete method confirmed as calls of the interface method.
#[tokio::test]
async fn an_interface_method_confirms_only_the_calls_written_against_it() {
    let fixture = repo_owner_store();
    let reply = find_references(&fixture.store, &fixture.interface).await;

    assert_eq!(
        sites(&reply["references"]),
        vec![("NewCreateContext".to_string(), 2)],
        "678 and 723 are calls on an *api.Repository: {reply:#}"
    );
    let held = row_named(&reply["candidates"], "NewCreateContext");
    assert_eq!(held["site_count"], 2, "{reply:#}");
    assert_eq!(held["resolution"], "name_only", "{reply:#}");
}

/// Asked for the wide read, a receiver-name guess is still held: the fan-out
/// ground holds at every floor, for a counted caller's sites as for a row.
#[tokio::test]
async fn the_wide_read_still_holds_a_counted_callers_fan_out_sites() {
    let fixture = repo_owner_store();
    let reply = find_references_with(
        &fixture.store,
        &fixture.concrete,
        &[("min_resolution", serde_json::json!("name_only"))],
    )
    .await;
    assert_eq!(
        sites(&reply["references"]),
        vec![("NewCreateContext".to_string(), 2)],
        "{reply:#}"
    );
    let held = row_named(&reply["candidates"], "NewCreateContext");
    assert_eq!(held["site_count"], 2, "{reply:#}");
}

/// Python, through pyright's shape: a counted caller keeps every site a
/// proven edge recorded, a caller with only proven edges is untouched and
/// still certifies its sites, and only the site nothing proved is held.
#[tokio::test]
async fn every_proven_python_call_site_stays_confirmed() {
    let store = InMemoryGraph::new();
    // Synthetic geometry: place the focal beside the parser-certain caller.
    // The real requests layout has HTTPAdapter.send in adapters.py.
    let focal = entity(
        LanguageId::Python,
        EntityKind::Method,
        "HTTPAdapter.send",
        "src/requests/auth.py",
    );
    // pyright proved line 784; the fan-out also recorded 790, a `.send()` on a
    // receiver nothing typed.
    let session_send = entity(
        LanguageId::Python,
        EntityKind::Method,
        "Session.send",
        "src/requests/sessions.py",
    );
    // Parser-certain calls to a method in the same file and nothing weaker.
    let handle_401 = entity(
        LanguageId::Python,
        EntityKind::Method,
        "HTTPDigestAuth.handle_401",
        "src/requests/auth.py",
    );
    // A proven call and a proven reference from one caller, two kinds.
    let request = entity(
        LanguageId::Python,
        EntityKind::Method,
        "Session.request",
        "src/requests/sessions.py",
    );
    for e in [&focal, &session_send, &handle_401, &request] {
        store.upsert_entity(e).unwrap();
    }
    let sessions = "src/requests/sessions.py";
    for relation in [
        edge(
            &session_send,
            &focal,
            RelationKind::Calls,
            RelationOrigin::Lsp,
            0.95,
            sessions,
            &[784],
        ),
        edge(
            &session_send,
            &focal,
            RelationKind::Calls,
            RelationOrigin::Inferred,
            FAN_OUT,
            sessions,
            &[784, 790],
        ),
        linked_calls(&handle_401, &focal, &[262, 281]),
        edge(
            &request,
            &focal,
            RelationKind::Calls,
            RelationOrigin::Inferred,
            0.9,
            sessions,
            &[589],
        ),
        edge(
            &request,
            &focal,
            RelationKind::References,
            RelationOrigin::Inferred,
            0.9,
            sessions,
            &[575],
        ),
    ] {
        store.upsert_relation(&relation).unwrap();
    }

    let reply = find_references(&store, &focal).await;
    assert_eq!(
        sites(&reply["references"]),
        vec![
            ("HTTPDigestAuth.handle_401".to_string(), 2),
            ("Session.request".to_string(), 2),
            ("Session.send".to_string(), 1),
        ],
        "every site a proven edge recorded is confirmed: {reply:#}"
    );
    assert_eq!(
        sites(&reply["candidates"]),
        vec![("Session.send".to_string(), 1)],
        "and only the site nothing proved is held: {reply:#}"
    );
    assert!(
        row_named(&reply["references"], "HTTPDigestAuth.handle_401")["sites_partial_reason"]
            .is_null(),
        "a caller with nothing held still certifies its sites: {reply:#}"
    );
    assert!(
        row_named(&reply["references"], "Session.request")["sites_partial_reason"].is_null(),
        "two proven kinds from one caller are not a split: {reply:#}"
    );
}

/// A caller reached through a proven override keeps its composed site, and
/// the fan-out's other site on the same caller is held rather than counted
/// under the composition.
#[tokio::test]
async fn a_composed_caller_keeps_its_proven_site_and_holds_the_guess() {
    let store = InMemoryGraph::new();
    let adapters = "src/requests/adapters.py";
    let sessions = "src/requests/sessions.py";
    let base = entity(
        LanguageId::Python,
        EntityKind::Method,
        "BaseAdapter.send",
        adapters,
    );
    let focal = entity(
        LanguageId::Python,
        EntityKind::Method,
        "HTTPAdapter.send",
        adapters,
    );
    let caller = entity(
        LanguageId::Python,
        EntityKind::Method,
        "Session.send",
        sessions,
    );
    for e in [&base, &focal, &caller] {
        store.upsert_entity(e).unwrap();
    }
    for relation in [
        // pyright: `adapter.send(...)` resolves to the declared base.
        edge(
            &caller,
            &base,
            RelationKind::Calls,
            RelationOrigin::Lsp,
            0.95,
            sessions,
            &[784],
        ),
        // A proven override.
        edge(
            &focal,
            &base,
            RelationKind::Overrides,
            RelationOrigin::Lsp,
            0.95,
            adapters,
            &[],
        ),
        // The fan-out, straight at the focal, on both sites.
        edge(
            &caller,
            &focal,
            RelationKind::Calls,
            RelationOrigin::Inferred,
            FAN_OUT,
            sessions,
            &[784, 790],
        ),
    ] {
        store.upsert_relation(&relation).unwrap();
    }

    let reply = find_references(&store, &focal).await;
    assert_eq!(
        sites(&reply["references"]),
        vec![("Session.send".to_string(), 1)],
        "{reply:#}"
    );
    assert_eq!(
        row_named(&reply["references"], "Session.send")["via_override_of"],
        "BaseAdapter.send",
        "{reply:#}"
    );
    assert_eq!(
        sites(&reply["candidates"]),
        vec![("Session.send".to_string(), 1)],
        "{reply:#}"
    );
}

/// TypeScript under the default floor: a reference the linker matched by name
/// alone is held beside the caller's import-scoped calls rather than counted
/// under them, and the wide read counts it again, whole.
#[tokio::test]
async fn a_name_only_reference_beside_an_import_scoped_call_follows_the_floor() {
    let store = InMemoryGraph::new();
    let focal = entity(
        LanguageId::TypeScript,
        EntityKind::Function,
        "compose",
        "src/compose.ts",
    );
    let caller = entity(
        LanguageId::TypeScript,
        EntityKind::Function,
        "dispatch",
        "src/hono-base.ts",
    );
    for e in [&focal, &caller] {
        store.upsert_entity(e).unwrap();
    }
    let file = "src/hono-base.ts";
    for relation in [
        linked_calls(&caller, &focal, &[412, 420]),
        edge(
            &caller,
            &focal,
            RelationKind::References,
            RelationOrigin::Inferred,
            0.7,
            file,
            &[433],
        ),
    ] {
        store.upsert_relation(&relation).unwrap();
    }

    let reply = find_references(&store, &focal).await;
    assert_eq!(
        sites(&reply["references"]),
        vec![("dispatch".to_string(), 2)],
        "{reply:#}"
    );
    assert_eq!(
        sites(&reply["candidates"]),
        vec![("dispatch".to_string(), 1)],
        "{reply:#}"
    );
    assert_eq!(
        reply["counts"]["unresolved_name_candidates"], 1,
        "{reply:#}"
    );
    assert_eq!(reply["counts"]["receiver_name_candidates"], 0, "{reply:#}");

    let wide = find_references_with(
        &store,
        &focal,
        &[("min_resolution", serde_json::json!("name_only"))],
    )
    .await;
    assert_eq!(
        sites(&wide["references"]),
        vec![("dispatch".to_string(), 3)],
        "the wide read counts the name-only site again: {wide:#}"
    );
    assert_eq!(wide["candidates"], serde_json::json!([]), "{wide:#}");
}

/// A store a released build enriched: gopls's widened answer for
/// `Interface.RepoOwner`, recorded as it came under the plain rule, so it
/// names the direct `Repository.RepoOwner` calls on lines 678 and 723 beside
/// the calls through the interface on 649 and 697. No later sweep removes
/// those records. They confirm nothing now; the interface method's calls stay
/// confirmed through the call hierarchy, whose outgoing calls were never
/// widened, and once a sweep re-derives the proven sites they confirm again.
#[tokio::test]
async fn a_released_builds_widened_interface_references_confirm_nothing() {
    let store = InMemoryGraph::new();
    let interface = entity(
        LanguageId::Go,
        EntityKind::Method,
        "Interface.RepoOwner",
        "internal/ghrepo/repo.go",
    );
    let caller = entity(
        LanguageId::Go,
        EntityKind::Function,
        "NewCreateContext",
        CREATE_GO,
    );
    // A caller that only ever calls the concrete method, which the released
    // build's widened answer made a reference of the interface method too.
    let direct_only = entity(
        LanguageId::Go,
        EntityKind::Function,
        "cloneRun",
        "pkg/cmd/repo/clone/clone.go",
    );
    for e in [&interface, &caller, &direct_only] {
        store.upsert_entity(e).unwrap();
    }
    let widened = |src: &Entity, file: &str, lines: &[u32]| {
        let mut relation = edge(
            src,
            &interface,
            RelationKind::References,
            RelationOrigin::Lsp,
            0.95,
            file,
            lines,
        );
        for record in &mut relation.evidence {
            record.parser_rule = Some(kin_model::LSP_REFERENCES_RULE.to_string());
        }
        relation
    };
    let released_widened = widened(&caller, CREATE_GO, &[649, 678, 697, 723]);
    store.upsert_relation(&released_widened).unwrap();
    store
        .upsert_relation(&widened(
            &direct_only,
            "pkg/cmd/repo/clone/clone.go",
            &[195],
        ))
        .unwrap();
    store
        .upsert_relation(&edge(
            &caller,
            &interface,
            RelationKind::Calls,
            RelationOrigin::Lsp,
            0.95,
            CREATE_GO,
            &[649, 697],
        ))
        .unwrap();

    let reply = find_references(&store, &interface).await;
    assert_eq!(
        sites(&reply["references"]),
        vec![("NewCreateContext".to_string(), 2)],
        "the widened records confirm nothing, and cloneRun, which never calls the interface \
         method, is no caller of it: {reply:#}"
    );
    assert_eq!(
        row_named(&reply["references"], "NewCreateContext")["relation_kinds"],
        serde_json::json!(["calls"]),
        "{reply:#}"
    );

    // A sweep of this build re-derives the edge: the proven sites join it.
    let mut rederived = released_widened.clone();
    rederived.evidence.extend(
        edge(
            &caller,
            &interface,
            RelationKind::References,
            RelationOrigin::Lsp,
            0.95,
            CREATE_GO,
            &[649, 697],
        )
        .evidence,
    );
    store.upsert_relation(&rederived).unwrap();
    let reply = find_references(&store, &interface).await;
    assert_eq!(
        sites(&reply["references"]),
        vec![("NewCreateContext".to_string(), 2)],
        "{reply:#}"
    );
    assert_eq!(
        row_named(&reply["references"], "NewCreateContext")["relation_kinds"],
        serde_json::json!(["calls", "references"]),
        "the proven references read again: {reply:#}"
    );
}

/// One caller reaching the focal three ways: through a receiver-name guess
/// alone, through a name-only reference beside that guess, or through a
/// parser-certain call. With `proven_elsewhere` the store also holds an
/// unrelated proven cross-file call in the same language, which keeps the
/// ordinary floor; without it the store resolves nothing above `name_only`
/// for Go and the floor degrades.
#[derive(Clone, Copy, Debug)]
enum OneCaller {
    GuessOnly,
    NameOnlyBesideGuess,
    ProvenCall,
}

fn one_caller_store(shape: OneCaller, proven_elsewhere: bool) -> (InMemoryGraph, Entity) {
    let store = InMemoryGraph::new();
    let focal = entity(
        LanguageId::Go,
        EntityKind::Method,
        "Client.RequestBody",
        "api/client.go",
    );
    let caller = entity(
        LanguageId::Go,
        EntityKind::Function,
        "apiRun",
        "pkg/cmd/api/api.go",
    );
    for e in [&focal, &caller] {
        store.upsert_entity(e).unwrap();
    }
    let file = "pkg/cmd/api/api.go";
    let guess = edge(
        &caller,
        &focal,
        RelationKind::Calls,
        RelationOrigin::Inferred,
        FAN_OUT,
        file,
        &[44],
    );
    let edges = match shape {
        OneCaller::GuessOnly => vec![guess],
        OneCaller::NameOnlyBesideGuess => vec![
            guess,
            edge(
                &caller,
                &focal,
                RelationKind::References,
                RelationOrigin::Inferred,
                0.7,
                file,
                &[40],
            ),
        ],
        OneCaller::ProvenCall => vec![edge(
            &caller,
            &focal,
            RelationKind::Calls,
            RelationOrigin::Parsed,
            1.0,
            file,
            &[48],
        )],
    };
    for relation in edges {
        store.upsert_relation(&relation).unwrap();
    }
    if proven_elsewhere {
        let other_target = entity(
            LanguageId::Go,
            EntityKind::Function,
            "ghrepo.FullName",
            "internal/ghrepo/repo.go",
        );
        let other_caller = entity(
            LanguageId::Go,
            EntityKind::Function,
            "cloneRun",
            "pkg/cmd/repo/clone/clone.go",
        );
        for e in [&other_target, &other_caller] {
            store.upsert_entity(e).unwrap();
        }
        store
            .upsert_relation(&edge(
                &other_caller,
                &other_target,
                RelationKind::Calls,
                RelationOrigin::Parsed,
                1.0,
                "pkg/cmd/repo/clone/clone.go",
                &[120],
            ))
            .unwrap();
    }
    (store, focal)
}

/// `bulk_check_references` counts one caller's direct edges as
/// `find_references` does, for a receiver-name guess, a name-only reference
/// beside one, and a parser-certain call, at the ordinary floor and at the
/// degraded one. It counted edges, and every edge but an explicit
/// derived-member candidate: the name-only-beside-guess caller read 2 in the
/// batch where the single answer reads 0 under the ordinary floor and 1 under
/// the degraded one, and the guess read 1 where the single answer reads 0.
///
/// The scope is direct edges. `find_references` also composes a caller over a
/// proven override, which a batch does not, and this does not claim it does.
#[tokio::test]
async fn a_batch_counts_one_callers_direct_edges_as_a_single_answer_does() {
    // (shape, the store proves Go elsewhere, callers counted, the floor they
    // were counted at, callers counted at name_only only because it degraded)
    for (shape, proven_elsewhere, expected, floor, name_only_kept) in [
        (OneCaller::GuessOnly, true, 0, "import_scoped", 0),
        (OneCaller::GuessOnly, false, 0, "name_only", 0),
        (OneCaller::NameOnlyBesideGuess, true, 0, "import_scoped", 0),
        (OneCaller::NameOnlyBesideGuess, false, 1, "name_only", 1),
        (OneCaller::ProvenCall, true, 1, "import_scoped", 0),
        (OneCaller::ProvenCall, false, 1, "import_scoped", 0),
    ] {
        let (store, focal) = one_caller_store(shape, proven_elsewhere);
        let single = find_references(&store, &focal).await;
        let batch = body(
            &super::entities::handle_bulk_check_references(
                &HashMap::from([(
                    "entity_ids".to_string(),
                    serde_json::json!([focal.id.to_string()]),
                )]),
                &store,
            )
            .unwrap(),
        );
        let row = &batch["results"][0];
        let case = format!("{shape:?} proven_elsewhere={proven_elsewhere}");
        assert_eq!(single["total_upstream"], expected, "{case}: {single:#}");
        assert_eq!(
            row["known_reference_count"], expected,
            "{case}: the batch counts the caller the single answer counts: {batch:#}"
        );
        // A caller kept only by the degraded floor is said to be, as the single
        // answer's `name_only_ceiling` disclosure says it, and a proven call is
        // not: the two counts of 1 read apart.
        assert_eq!(row["counting_floor"], floor, "{case}: {batch:#}");
        assert_eq!(
            row["name_only_ceiling_kept"], name_only_kept,
            "{case}: {batch:#}"
        );
        let single_discloses_ceiling = single["degradations"]
            .as_array()
            .is_some_and(|all| all.iter().any(|d| d["reason"] == "name_only_ceiling"));
        assert_eq!(
            single_discloses_ceiling,
            name_only_kept > 0,
            "{case}: the batch discloses the ceiling exactly where the single answer does: \
             {single:#}"
        );
        match expected {
            0 => {
                assert!(
                    row["has_references"].is_null(),
                    "{case}: a caller held as a candidate is not a proved absence: {batch:#}"
                );
                assert_eq!(row["unconfirmed_candidate_count"], 1, "{case}: {batch:#}");
                assert_eq!(
                    row["verdict_reason"], "unconfirmed candidate references remain",
                    "{case}: {batch:#}"
                );
            }
            _ => {
                assert_eq!(row["has_references"], true, "{case}: {batch:#}");
                assert_eq!(row["unconfirmed_candidate_count"], 0, "{case}: {batch:#}");
            }
        }
    }
}
