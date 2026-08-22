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
        self.graph
            .upsert_relation(&Relation {
                id: RelationId::new(),
                kind,
                src: GraphNodeId::Entity(src),
                dst: GraphNodeId::Entity(dst),
                confidence: 1.0,
                origin: RelationOrigin::Lsp,
                created_in: None,
                import_source: None,
                evidence: Vec::new(),
            })
            .expect("install enrichment edge");
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
