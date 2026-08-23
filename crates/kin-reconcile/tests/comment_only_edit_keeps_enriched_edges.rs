// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! A comment-only edit must not cost the store a relation.
//!
//! FIR-2598: on the rc0547b run a 26-line docstring added to the top of
//! `psf/requests`' `sessions.py` cost the graph 11 `Calls` edges and one
//! `Overrides` edge, including the `SessionRedirectMixin.send` override that
//! `find_references` had been composing its second caller through. No
//! executable line moved and no declaration changed, so every one of those
//! edges was still true about the file after the edit.
//!
//! The shape is the mixin: a base declares a method, a subclass overrides it,
//! and a sibling method on the base calls it through `self`. That is what makes
//! the `Overrides` edge load-bearing, and it is the shape the run lost.

use std::path::PathBuf;

use kin_blobs::BlobStore;
use kin_db::InMemoryGraph;
use kin_index::FileEvent;
use kin_model::{
    ArtifactId, Entity, EntityId, EntityStore, GraphNodeId, Hash256, LocatedEntry, Relation,
    RelationId, RelationKind, RelationOrigin, RepoPath, TransactionDelta, TreeDelta, TreeEntry,
};
use kin_reconcile::Reconciler;
use tempfile::TempDir;

/// A repository built the way a user builds one: write the file, admit its
/// artifact, reconcile, apply.
struct LiveRepo {
    dir: TempDir,
    graph: InMemoryGraph,
    blobs: BlobStore,
    reconciler: Reconciler,
}

impl LiveRepo {
    fn new() -> Self {
        let dir = TempDir::new().expect("temp repo");
        let blobs = BlobStore::new(dir.path().join("blobs")).expect("blob store");
        let graph = InMemoryGraph::new();
        let mut reconciler = Reconciler::new(dir.path().to_path_buf());
        reconciler.seed_cross_file_linker_from_graph(&graph);
        Self {
            dir,
            graph,
            blobs,
            reconciler,
        }
    }

    fn abs(&self, rel: &str) -> PathBuf {
        self.dir.path().join(rel)
    }

    fn commit(&mut self, rel: &str, source: &str) -> TransactionDelta {
        let path = self.abs(rel);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).expect("create parent");
        }
        std::fs::write(&path, source).expect("write source");

        let blob_hash = self.blobs.write(source.as_bytes()).expect("store blob");
        let repo_path = RepoPath::from_utf8(rel.to_string()).expect("repo path");
        let entry = TreeEntry::blob(Hash256::from_bytes(blob_hash.0), false);
        let tree_delta = match self.graph.artifact_id_at_path(&repo_path) {
            Some(artifact_id) => {
                let old_entry = self
                    .graph
                    .get_tree_entry(&kin_model::FilePathId::new(rel))
                    .ok()
                    .flatten();
                match old_entry {
                    Some(old) if old == entry => None,
                    Some(old) => Some(TreeDelta::Updated {
                        artifact_id,
                        old: LocatedEntry::new(repo_path.clone(), old),
                        new: LocatedEntry::new(repo_path, entry),
                    }),
                    None => Some(TreeDelta::Added {
                        artifact_id,
                        new: LocatedEntry::new(repo_path, entry),
                    }),
                }
            }
            None => Some(TreeDelta::Added {
                artifact_id: ArtifactId::new(),
                new: LocatedEntry::new(repo_path, entry),
            }),
        };
        if let Some(tree_delta) = tree_delta {
            self.graph
                .apply_transaction_delta(&TransactionDelta {
                    tree_deltas: vec![tree_delta],
                    ..TransactionDelta::default()
                })
                .expect("admit artifact");
        }

        let result = self
            .reconciler
            .reconcile_file_change(&FileEvent::Changed(path), &self.blobs, &self.graph)
            .expect("reconcile succeeds");
        let (_, delta) = result.into_parts();
        self.graph
            .apply_transaction_delta(&delta)
            .expect("apply reconciled delta");
        delta
    }

    fn entity(&self, name: &str) -> Entity {
        let mut matches: Vec<Entity> = self
            .graph
            .list_all_entities()
            .expect("list entities")
            .into_iter()
            .filter(|entity| entity.name == name)
            .collect();
        assert_eq!(
            matches.len(),
            1,
            "expected exactly one entity named {name}, got {:?}",
            matches.iter().map(|e| &e.name).collect::<Vec<_>>()
        );
        matches.pop().expect("checked above")
    }

    /// Install one language-server edge, the way the daemon's enrichment pass
    /// installs the ones it derives: straight onto the live graph, with `Lsp`
    /// origin, and never through a parse.
    fn enrich(&self, kind: RelationKind, src: EntityId, dst: EntityId) {
        self.enrich_at(kind, src, dst, None);
    }

    /// The same, carrying the call-site position a language server reports.
    ///
    /// `kin-lsp` records that position with zero byte offsets and real line
    /// numbers, which is what `find_references` publishes as a reference line,
    /// so the span shape here is the shape the defect was measured on.
    fn enrich_at(
        &self,
        kind: RelationKind,
        src: EntityId,
        dst: EntityId,
        line: Option<u32>,
    ) -> RelationId {
        let id = RelationId::new();
        self.graph
            .upsert_relation(&Relation {
                id,
                kind,
                src: GraphNodeId::Entity(src),
                dst: GraphNodeId::Entity(dst),
                confidence: 1.0,
                origin: RelationOrigin::Lsp,
                created_in: None,
                import_source: None,
                evidence: line
                    .map(|line| {
                        vec![kin_model::RelationEvidence {
                            source_span: Some(kin_model::SourceSpan {
                                file: kin_model::FilePathId::new("sessions.py"),
                                start_byte: 0,
                                end_byte: 0,
                                start_line: line,
                                start_col: 8,
                                end_line: line,
                                end_col: 20,
                            }),
                            ..kin_model::RelationEvidence::default()
                        }]
                    })
                    .unwrap_or_default(),
            })
            .expect("install enrichment edge");
        id
    }

    /// Every relation the graph holds whose source is `src`, deduplicated.
    fn edges_from(&self, src: EntityId) -> Vec<Relation> {
        let mut seen = std::collections::HashSet::new();
        self.graph
            .get_all_relations_for_entity(&src)
            .expect("relations for entity")
            .into_iter()
            .filter(|relation| relation.src == GraphNodeId::Entity(src))
            .filter(|relation| seen.insert(relation.id))
            .collect()
    }

    fn relation(&self, id: RelationId) -> Option<Relation> {
        self.graph
            .list_all_entities()
            .expect("list entities")
            .into_iter()
            .flat_map(|entity| {
                self.graph
                    .get_all_relations_for_entity(&entity.id)
                    .expect("relations for entity")
            })
            .find(|relation| relation.id == id)
    }

    /// Every relation in the store, as `(kind, origin)` pairs with a count.
    ///
    /// Keyed on kind and origin rather than on relation id, because a re-parse
    /// legitimately re-mints an id for the same edge and this suite is about
    /// whether the edge is still there at all.
    fn census(&self) -> Vec<(RelationKind, RelationOrigin, usize)> {
        let mut seen = std::collections::HashSet::new();
        let mut counts: std::collections::BTreeMap<
            (String, String),
            (RelationKind, RelationOrigin, usize),
        > = std::collections::BTreeMap::new();
        for entity in self.graph.list_all_entities().expect("list entities") {
            for relation in self
                .graph
                .get_all_relations_for_entity(&entity.id)
                .expect("relations for entity")
            {
                if !seen.insert(relation.id) {
                    continue;
                }
                let key = (
                    format!("{:?}", relation.kind),
                    format!("{:?}", relation.origin),
                );
                counts
                    .entry(key)
                    .or_insert((relation.kind, relation.origin, 0))
                    .2 += 1;
            }
        }
        counts.into_values().collect()
    }

    fn count(&self, kind: RelationKind, origin: RelationOrigin) -> usize {
        self.census()
            .into_iter()
            .find(|(k, o, _)| *k == kind && *o == origin)
            .map(|(_, _, count)| count)
            .unwrap_or(0)
    }
}

/// The `sessions.py` shape: `SessionRedirectMixin` declares `send` and calls it
/// through `self` from a sibling, and `Session` overrides it.
const SESSIONS: &str = r#"import time


class SessionRedirectMixin:
    def send(self, request, **kwargs):
        raise NotImplementedError

    def get_redirect_target(self, resp):
        return resp.headers.get("location")

    def resolve_redirects(self, resp, req, **kwargs):
        target = self.get_redirect_target(resp)
        while target:
            resp = self.send(req, **kwargs)
            target = self.get_redirect_target(resp)
        return resp

    def rebuild_auth(self, prepared, response):
        return prepared


class Session(SessionRedirectMixin):
    def request(self, method, url):
        prepared = self.prepare(method, url)
        return self.send(prepared)

    def prepare(self, method, url):
        return (method, url)

    def send(self, request, **kwargs):
        time.sleep(0)
        return request
"#;

/// Twenty-six lines of module docstring, exactly the edit the run made: prose
/// above every declaration, no executable line touched.
fn with_leading_docstring(source: &str) -> String {
    let mut docstring = String::from("\"\"\"Session and redirect handling.\n");
    for index in 1..=23 {
        docstring.push_str(&format!("Redirect flow note {index}.\n"));
    }
    docstring.push_str("\"\"\"\n");
    assert_eq!(
        docstring.lines().count(),
        25,
        "the docstring block is fixed at 25 lines plus the blank line below it"
    );
    format!("{docstring}\n{source}")
}

/// The reported defect, driven through the real parser, the real linker and the
/// real reconciler.
#[test]
fn a_comment_only_edit_keeps_every_edge_the_file_already_had() {
    let mut repo = LiveRepo::new();
    repo.commit("sessions.py", SESSIONS);

    // The store as an enriched one looks: the parser's own edges, plus the two
    // a language-server sweep contributes. The override edge is the one the
    // run lost, and the call edge is the class the run lost eleven of.
    let mixin_send = repo.entity("SessionRedirectMixin.send");
    let session_send = repo.entity("Session.send");
    let resolve_redirects = repo.entity("SessionRedirectMixin.resolve_redirects");
    repo.enrich(RelationKind::Overrides, session_send.id, mixin_send.id);
    repo.enrich(RelationKind::Calls, resolve_redirects.id, session_send.id);

    let before = repo.census();
    let parsed_calls_before = repo.count(RelationKind::Calls, RelationOrigin::Parsed);
    let lsp_calls_before = repo.count(RelationKind::Calls, RelationOrigin::Lsp);
    let lsp_overrides_before = repo.count(RelationKind::Overrides, RelationOrigin::Lsp);
    assert!(
        parsed_calls_before > 0,
        "the fixture must produce parser call edges: {before:?}"
    );
    assert_eq!(lsp_calls_before, 1, "{before:?}");
    assert_eq!(lsp_overrides_before, 1, "{before:?}");

    let edited = with_leading_docstring(SESSIONS);
    assert_eq!(
        edited.lines().count(),
        SESSIONS.lines().count() + 26,
        "the edit adds 26 lines and touches nothing else"
    );
    assert!(
        edited.ends_with(SESSIONS),
        "every executable line is byte-identical after the edit"
    );

    repo.commit("sessions.py", &edited);
    let after = repo.census();

    assert_eq!(
        repo.count(RelationKind::Calls, RelationOrigin::Lsp),
        lsp_calls_before,
        "a docstring above the file cost it a language-server call edge\nbefore: \
         {before:?}\nafter:  {after:?}"
    );
    assert_eq!(
        repo.count(RelationKind::Overrides, RelationOrigin::Lsp),
        lsp_overrides_before,
        "a docstring above the file cost it the override edge\nbefore: {before:?}\nafter:  \
         {after:?}"
    );
    assert_eq!(
        repo.count(RelationKind::Calls, RelationOrigin::Parsed),
        parsed_calls_before,
        "a docstring above the file cost it parser call edges\nbefore: {before:?}\nafter:  \
         {after:?}"
    );
}

/// FIR-2644, the half FIR-2598's fixture could not hold.
///
/// `Session` overrides `SessionRedirectMixin.send`, both declared in one file.
/// `kin_index::linker` is the only producer of `Overrides`, and the live
/// reconcile path threw its same-file output away on the ground that the
/// pipeline's per-file resolution already carried it. It does not, so the edge
/// arrived at the retire loop as a parser-derived edge with both endpoints in
/// the file that this pass had not produced, which is the `parser_authoritative`
/// condition exactly, and a docstring deleted it. `find_references` composes its
/// second caller of `Session.send` through that edge, so the answer halved.
#[test]
fn a_same_file_override_survives_a_comment_only_edit() {
    let mut repo = LiveRepo::new();
    repo.commit("sessions.py", SESSIONS);

    let mixin_send = repo.entity("SessionRedirectMixin.send");
    let session_send = repo.entity("Session.send");
    let parsed_override = |repo: &LiveRepo| {
        repo.edges_from(session_send.id)
            .into_iter()
            .filter(|relation| {
                relation.kind == RelationKind::Overrides
                    && relation.dst == GraphNodeId::Entity(mixin_send.id)
                    && relation.origin == RelationOrigin::Parsed
            })
            .count()
    };
    assert_eq!(
        parsed_override(&repo),
        1,
        "the live path must derive the same-file override at all, or this test cannot fail: {:?}",
        repo.census()
    );

    repo.commit("sessions.py", &with_leading_docstring(SESSIONS));

    assert_eq!(
        parsed_override(&repo),
        1,
        "a docstring above the file cost it the same-file override edge: {:?}",
        repo.census()
    );
}

/// A parser edge and the language-server edge that agrees with it are two facts
/// under one key, and a re-anchor must keep both.
///
/// They are held with two ids: the parser derives its id from the triple, and
/// `kin-lsp` derives its own from the same triple in its own namespace. Matching
/// the re-derived parse to the lowest id in the bucket wrote the parse onto the
/// enrichment edge's identity, which destroyed the enrichment edge and left the
/// real parser edge unmatched and stale.
#[test]
fn an_enrichment_edge_and_the_parse_that_agrees_with_it_both_survive_an_edit() {
    let mut repo = LiveRepo::new();
    repo.commit("sessions.py", SESSIONS);

    let request = repo.entity("Session.request");
    let session_send = repo.entity("Session.send");
    let parsed_call = repo
        .edges_from(request.id)
        .into_iter()
        .find(|relation| {
            relation.kind == RelationKind::Calls
                && relation.dst == GraphNodeId::Entity(session_send.id)
                && relation.origin == RelationOrigin::Parsed
        })
        .expect("the fixture must produce the parser call edge this test is about");
    let enrichment = repo.enrich_at(RelationKind::Calls, request.id, session_send.id, Some(24));
    assert_ne!(
        enrichment, parsed_call.id,
        "the two facts must be held under different ids for this test to mean anything"
    );

    repo.commit("sessions.py", &with_leading_docstring(SESSIONS));

    let survivors = repo
        .edges_from(request.id)
        .into_iter()
        .filter(|relation| {
            relation.kind == RelationKind::Calls
                && relation.dst == GraphNodeId::Entity(session_send.id)
        })
        .map(|relation| (relation.id, relation.origin))
        .collect::<Vec<_>>();
    assert!(
        survivors.contains(&(enrichment, RelationOrigin::Lsp)),
        "the enrichment edge lost its identity to the parse that agrees with it: {survivors:?}"
    );
    assert_eq!(
        survivors
            .iter()
            .filter(|(_, origin)| *origin == RelationOrigin::Parsed)
            .count(),
        1,
        "exactly one parser copy of the key may survive: {survivors:?}"
    );
}

/// A preserved enrichment span is placed where its declaration moved to.
///
/// Nothing on the reconcile path re-derives a language-server edge, so before
/// this its span stayed where the sweep recorded it and `find_references`
/// published a pre-edit line as a current call site.
#[test]
fn a_preserved_enrichment_span_moves_with_the_declaration_that_holds_it() {
    let mut repo = LiveRepo::new();
    repo.commit("sessions.py", SESSIONS);

    let request = repo.entity("Session.request");
    let session_send = repo.entity("Session.send");
    let call_line = request
        .span
        .as_ref()
        .expect("the caller carries a span")
        .start_line
        + 2;
    let enrichment = repo.enrich_at(
        RelationKind::Calls,
        request.id,
        session_send.id,
        Some(call_line),
    );

    repo.commit("sessions.py", &with_leading_docstring(SESSIONS));

    let placed = repo
        .relation(enrichment)
        .expect("the enrichment edge survives the edit");
    let span = placed.evidence[0]
        .source_span
        .as_ref()
        .expect("the span was placed rather than cleared");
    assert_eq!(
        span.start_line,
        call_line + 26,
        "the 26-line docstring moved the declaration, so its call site moved with it"
    );
    assert_eq!(
        (span.start_col, span.end_col),
        (8, 20),
        "a placement moves lines and invents no columns"
    );
}

/// The transport hop, so a call site can leave the file it is written in.
const ADAPTERS: &str = r#"class BaseAdapter:
    def send(self, request, **kwargs):
        raise NotImplementedError


class HTTPAdapter(BaseAdapter):
    def send(self, request, **kwargs):
        return request
"#;

/// `sessions.py` again, calling into `adapters.py`.
const SESSIONS_WITH_ADAPTER: &str = r#"from adapters import HTTPAdapter


class Session:
    def get_adapter(self, url):
        return HTTPAdapter()

    def send(self, request, **kwargs):
        adapter = self.get_adapter(request)
        return adapter.send(request, **kwargs)
"#;

/// A surplus parser copy of a cross-file key is retired even though its
/// destination is in another file.
///
/// The retire rule asked for both endpoints to be inside the file, so a second
/// parser-derived copy of an edge leaving it could never be collected: it
/// survived every later pass carrying whatever span the resolver that minted it
/// recorded, and `find_references` published that span beside the current one.
/// The authority is that this pass read this file and re-derived that exact
/// edge from it, which is a fact about the source half alone.
#[test]
fn a_surplus_parser_copy_of_a_cross_file_edge_is_retired() {
    let mut repo = LiveRepo::new();
    repo.commit("adapters.py", ADAPTERS);
    repo.commit("sessions.py", SESSIONS_WITH_ADAPTER);

    let in_adapters = |node: GraphNodeId| {
        node.as_entity()
            .and_then(|id| repo.graph.get_entity(&id).ok().flatten())
            .and_then(|entity| entity.file_origin)
            .is_some_and(|file| file.0 == "adapters.py")
    };
    let sessions_entities: Vec<Entity> = repo
        .graph
        .list_all_entities()
        .expect("list entities")
        .into_iter()
        .filter(|entity| {
            entity
                .file_origin
                .as_ref()
                .is_some_and(|file| file.0 == "sessions.py")
        })
        .collect();
    let original = sessions_entities
        .iter()
        .flat_map(|entity| repo.edges_from(entity.id))
        .find(|relation| {
            matches!(
                relation.origin,
                RelationOrigin::Parsed | RelationOrigin::Inferred
            ) && in_adapters(relation.dst)
        })
        .expect("the fixture must produce a parser edge that leaves the file");
    let source_entity = original.src.as_entity().expect("an entity-sourced edge");

    // The shape an older resolver left behind: a second parser-derived copy of
    // the same key, under its own id, carrying the pre-edit line.
    let surplus = Relation {
        id: RelationId::new(),
        ..original.clone()
    };
    repo.graph
        .upsert_relation(&surplus)
        .expect("seed the surplus copy");
    assert_ne!(surplus.id, original.id);

    repo.commit(
        "sessions.py",
        &with_leading_docstring(SESSIONS_WITH_ADAPTER),
    );

    let survivors: Vec<RelationId> = repo
        .edges_from(source_entity)
        .into_iter()
        .filter(|relation| relation.kind == original.kind && relation.dst == original.dst)
        .filter(|relation| {
            matches!(
                relation.origin,
                RelationOrigin::Parsed | RelationOrigin::Inferred
            )
        })
        .map(|relation| relation.id)
        .collect();
    // One identity, and the claim is the count rather than which uuid won.
    // The pass re-derives the edge and binds it to a parser identity from the
    // bucket; either id is that edge, and both carry the payload this parse
    // produced. What may not survive is a second copy, because that is the one
    // still holding the line the call has left.
    assert_eq!(
        survivors.len(),
        1,
        "a re-anchored cross-file edge must keep one parser identity, not two: {survivors:?}"
    );
    let kept = repo
        .relation(survivors[0])
        .expect("the surviving edge is readable");
    assert_eq!(
        kept.dst, original.dst,
        "the survivor is the edge this test seeded a copy of"
    );
}
