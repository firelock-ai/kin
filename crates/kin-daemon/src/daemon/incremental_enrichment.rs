// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Enriching a file again after an edit.
//!
//! An edit re-derives the declarations of the file it touched, and the linker
//! binds their calls again. That includes every guess a sweep had settled:
//! the re-derivation cannot tell a guess the server refuted from one it never
//! answered, so the guesses come back as they were before the sweep.
//!
//! This pass settles the file again the way the sweep does, with the same
//! file pass. The declarations the edit re-derived are asked whole: every
//! identifier inside them and their call hierarchy. Each of their calls is
//! proven from the definition answer at its callee token, a guess an answer
//! outside the repository contradicts is refuted, and the symbol outside is
//! named and proven under the server's proof context. The per-declaration
//! arms the sweep asks follow.
//!
//! An edit re-derives every declaration of its file, since each carries the
//! body it was parsed from, so in practice this is the sweep's own pass over
//! the file. Like the sweep, it then gives every caller in the file its
//! call-site ledger under the server's proof context, retracts the proofs
//! those ledgers no longer hold when every pass finished, and records the
//! file's completion mark when every question was answered. The edit retired
//! the ledgers of the callers it changed, so without this the mark would name
//! callers with no ledger, which a mark never may. A request that names only
//! some of a file's declarations is asked about those, and for the file's
//! other callers only at the calls whose guesses no standing proof confirms,
//! with those callers' call hierarchy, so a guess settled before the edit is
//! settled again. Such a pass knows only part of the file's sites, so it
//! writes no ledger and records no mark: the rest of the file is owed to the
//! next sweep, which asks about every file without one.
//!
//! The server is asked everything before anything is written, and the writes
//! go through the capture the answers were proven against, which refuses them
//! once the graph's authority epoch has moved. Any graph write moves it,
//! including the watcher's reconcile of a commit's own working-tree write,
//! which changes nothing, and that write lands while the pass after a
//! `kin_mutate` commit is still asking. So a refused write takes a fresh
//! capture, and when it holds the same entities and tree, the same answers
//! are written through it. When it does not, the file changed under the pass,
//! and the sweep asks again.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::path::Path;

use kin_lsp::file_enrichment::FileScope;
use kin_model::{EntityId, EntityStore as _, GraphNodeId, RelationKind, RelationOrigin};

use super::lsp_publication::{LedgerRequest, QueryInputs, Refused};
use super::{DaemonState, EnrichmentWrite, EntityArms, LedgerWrite, PendingEnrichment, SweepTally};
use crate::call_site_ledger::PassEnding;

/// What one pass over a changed file did.
#[derive(Debug, Default)]
pub(crate) struct IncrementalPass {
    /// What reached the graph: relations, proofs and settled guesses.
    pub(crate) written: EnrichmentWrite,
    /// Why the answers were discarded, when they were.
    pub(crate) refused: Option<Refused>,
    /// Queries that got no considered answer. Each keeps the file from its
    /// completion mark, and none abandons what the others proved.
    pub(crate) failed_queries: usize,
    /// What the first of them was.
    pub(crate) first_failure: Option<String>,
    /// Whether the request named every declaration of the file, so the pass
    /// asked about the whole file as the sweep does.
    pub(crate) whole_file: bool,
    /// Whether the file was recorded as finished, for the next enrichment
    /// publication to commit its completion mark with its relations.
    pub(crate) marked: bool,
    /// The call-site ledgers a pass over the whole file gave its callers.
    pub(crate) ledgers: LedgerWrite,
    /// Calls of declarations the request did not name, asked again because
    /// no standing proof confirmed the guess the edit bound there.
    pub(crate) reasked_calls: usize,
    /// Times the answers were written again under a fresh capture, because a
    /// graph write elsewhere moved the authority epoch while the server was
    /// asked and left the entities and tree they were proven against as they
    /// were.
    pub(crate) revalidated: usize,
}

/// How many times a pass writes its answers again under a fresh capture
/// before it hands the file to a sweep. Each time costs one capture and no
/// question to the server.
const REVALIDATIONS: usize = 3;

/// Everything the server answered about one changed file, before any of it
/// reaches the graph.
struct Answers {
    relations: Vec<kin_model::Relation>,
    sites: Vec<kin_lsp::call_sites::SiteAnswer>,
    names: kin_lsp::call_sites::ExternalNames,
    context: kin_model::ProofContext,
    /// Whether every question was answered, by the sweep's rules.
    completed: bool,
    /// What the file's call-site ledgers need beyond the answers, as the
    /// sweep hands them over (see [`LedgerRequest`]).
    unproven: Vec<kin_lsp::call_sites::UnprovenSite>,
    produced_references: HashSet<kin_model::RelationId>,
    ending: PassEnding,
    not_in_build: bool,
    /// Whether every pass over the file finished, so a proof its ledgers do
    /// not hold may be retracted.
    retract: bool,
}

/// Enrich `file` after an edit that re-derived the declarations `changed`.
///
/// `inputs` is the capture the answers are proven against, `text` the
/// admitted source of `file` in it, already open in `server`. The server is
/// asked everything first, and only then does anything reach the graph,
/// through a capture that refuses the write once the graph has moved past
/// it. When a write elsewhere moved only the authority epoch, the same
/// answers are written under a fresh capture, since the entities and tree
/// they were proven against are unchanged.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn enrich_changed_file(
    state: &DaemonState,
    inputs: &QueryInputs,
    server: &kin_lsp::lifecycle::LspServer,
    language: kin_model::LanguageId,
    index: &kin_lsp::EntityIndex,
    root: &Path,
    file: &str,
    text: &str,
    changed: &[EntityId],
) -> IncrementalPass {
    let load_document = |path: &str| inputs.document(path);
    let documents: Option<kin_lsp::DocumentProvider<'_>> = Some(&load_document);
    let declarations: Vec<kin_lsp::EntityRef> = inputs
        .entities
        .iter()
        .filter(|entity| {
            entity
                .file_origin
                .as_ref()
                .is_some_and(|origin| origin.0 == file)
        })
        .filter_map(|entity| super::lsp_entity_ref(entity, file))
        .collect();
    let changed: HashSet<EntityId> = changed.iter().copied().collect();
    let asked: Vec<&kin_lsp::EntityRef> = declarations
        .iter()
        .filter(|entity| changed.contains(&entity.id))
        .collect();
    let whole_file = asked.len() == declarations.len();
    let mut pass = IncrementalPass {
        whole_file,
        ..IncrementalPass::default()
    };
    let scope = if whole_file {
        FileScope::whole_file()
    } else {
        let others: Vec<EntityId> = declarations
            .iter()
            .map(|entity| entity.id)
            .filter(|id| !changed.contains(id))
            .collect();
        let calls = unsettled_calls(state, inputs, file, text, &others);
        pass.reasked_calls = calls.len();
        FileScope::callers(asked.iter().map(|entity| entity.id), calls)
    };

    // The context this server answers under is now the current one for its
    // language, exactly as the sweep records it before asking about a file,
    // so the ledgers this pass writes and the ones a sweep writes are judged
    // against the same context.
    let context = server.proof_context(language);
    super::note_current_proof_context(state, language, &context);

    // The file pass, under the sweep's budget and counted by its rules.
    let mut tally = SweepTally::default();
    let answered_before = server.client.answered();
    let (mut result, mut failure, covered, mut ending) = super::file_definitions_within_budget(
        kin_lsp::file_enrichment::enrich_file_definitions_in(
            server,
            &root.join(file),
            text,
            index,
            root,
            documents,
            &scope,
        ),
        super::lsp_file_definitions_budget(),
        file,
        &mut tally,
    )
    .await;
    // What the server proved at each identifier and each call range, kept to
    // settle the file's guesses once its relations are in, and the symbols
    // its outside answers name.
    let mut sites = std::mem::take(&mut result.site_answers);
    sites.extend(kin_lsp::call_sites::call_hierarchy_answers(
        &result.relations,
    ));
    let mut names = std::mem::take(&mut result.external_names);
    // What the definitions pass asked and could not prove, and the references
    // the passes produce, for the file's call-site ledgers.
    let unproven = std::mem::take(&mut result.unproven_sites);
    let mut produced_references = super::produced_reference_ids(&result.relations);
    let mut unprovable =
        super::file_pass_unprovable(std::mem::take(&mut result.unprovable), &declarations);
    let mut relations = result.relations;

    // Each named declaration's own arms, and its calls too when the file pass
    // did not have its call hierarchy answered.
    let arms = if covered {
        EntityArms::AllButCalls
    } else {
        EntityArms::All
    };
    let mut hierarchy_outside = Vec::new();
    for entity in &asked {
        let (derived, outcomes) = super::enrich_single_entity(
            server,
            entity,
            index,
            root,
            documents,
            arms,
            std::time::Duration::from_secs(5),
        )
        .await;
        tally.query_failures += outcomes.failures;
        tally.query_declines += outcomes.declines;
        tally.query_refusals += outcomes.refusals.len();
        unprovable.extend(outcomes.refusals);
        if failure.is_none() {
            failure = outcomes.first_failure;
        }
        sites.extend(kin_lsp::call_sites::call_hierarchy_answers(&derived));
        hierarchy_outside.extend(outcomes.outside_sites);
        produced_references.extend(super::produced_reference_ids(&derived));
        relations.extend(derived);
    }
    // A call the calls arm resolved outside the repository refutes the guesses
    // at its range and names its symbol, as the file pass's own do.
    if !hierarchy_outside.is_empty() {
        let unnamed: Vec<kin_lsp::call_sites::OutsideLocation> = hierarchy_outside
            .iter()
            .filter_map(|answer| match &answer.target {
                kin_lsp::call_sites::SiteTarget::Outside(location)
                    if !names.contains_key(location) =>
                {
                    Some(location.clone())
                }
                _ => None,
            })
            .collect();
        names.extend(server.external_symbols().name_all(server, &unnamed).await);
        sites.extend(hierarchy_outside);
    }

    // How the passes over the file ended, decided as the sweep decides it, so
    // the ledgers say what each unanswered site came to and a file whose
    // passes failed is never retracted. What holds the sweep's file back holds
    // this one back too.
    let nothing_answered = super::declined_everything(
        tally.query_declines,
        server.client.answered() - answered_before,
    );
    let disconnected = server.is_disconnected();
    if ending == PassEnding::Complete {
        if disconnected {
            ending = PassEnding::Stopped(kin_model::ServerFailure::Crash);
        } else if nothing_answered.is_some() {
            ending = PassEnding::NothingAnswered;
        }
    }
    let retract = nothing_answered.is_none()
        && !disconnected
        && ending == PassEnding::Complete
        && super::file_passes_completed(&tally, 0, 0);
    if let Some(reason) = nothing_answered {
        tally.query_failures += 1;
        failure.get_or_insert(reason);
    }
    if disconnected {
        tally.query_failures += 1;
        failure.get_or_insert_with(|| "its language server stopped answering".to_string());
    }
    pass.failed_queries = tally.query_failures;
    pass.first_failure = failure;
    let answers = Answers {
        relations,
        sites,
        names,
        context,
        completed: super::file_passes_completed(&tally, 0, 0),
        unproven,
        produced_references,
        ending,
        not_in_build: server.in_no_build(&root.join(file)),
        retract,
    };

    let request = Request {
        index,
        root,
        file,
        text,
    };
    write(state, inputs, inputs, &request, &answers, &mut pass).await;
    while pass.refused == Some(Refused::Stale) && pass.revalidated < REVALIDATIONS {
        let Ok(fresh) = QueryInputs::capture(state).await else {
            break;
        };
        if !fresh.describes_same_graph(inputs) {
            break;
        }
        pass.revalidated += 1;
        pass.refused = None;
        write(state, inputs, &fresh, &request, &answers, &mut pass).await;
    }
    // What the server answered in a way this build cannot prove is settled,
    // not owed, as on the sweep.
    super::record_unprovable_queries(state, file, unprovable);
    pass
}

/// The file one pass is about, and what its answers were asked against.
struct Request<'a> {
    index: &'a kin_lsp::EntityIndex,
    root: &'a Path,
    file: &'a str,
    /// The admitted source of `file`.
    text: &'a str,
}

/// Write `answers` about the requested file through `capture`: the
/// relations, then the settlement of the file's guesses in the graph they
/// landed in, then, for a whole file whose every question was answered, its
/// completion. `asked` is the capture the answers were proven against; a
/// completion is recorded only while no marker retirement has happened since
/// it was taken.
///
/// A pass over the whole file settles it as the sweep does, through
/// [`QueryInputs::settle_file`], which also gives every caller in the file its
/// call-site ledger and makes the file's proofs agree with them. A pass over
/// part of the file knows only some of its sites, so it settles the guesses
/// its answers contradict and writes no ledger.
async fn write(
    state: &DaemonState,
    asked: &QueryInputs,
    capture: &QueryInputs,
    request: &Request<'_>,
    answers: &Answers,
    pass: &mut IncrementalPass,
) {
    let Request {
        index,
        root,
        file,
        text,
    } = *request;
    let mut written = EnrichmentWrite::default();
    let mut pending = PendingEnrichment::default();
    let mut refused = capture
        .absorb(state, &mut pending, answers.relations.clone())
        .await
        .map(|batch| written += batch)
        .err();
    if refused.is_none() {
        refused = capture
            .flush(state, &mut pending)
            .await
            .map(|batch| written += batch)
            .err();
    }
    if refused.is_none() && pass.whole_file {
        let entities: Vec<&kin_model::Entity> = capture
            .entities
            .iter()
            .filter(|entity| {
                entity
                    .file_origin
                    .as_ref()
                    .is_some_and(|origin| origin.0 == file)
            })
            .collect();
        let uri = kin_lsp::protocol::path_to_uri(&root.join(file));
        refused = capture
            .settle_file(
                state,
                text,
                &answers.sites,
                &answers.names,
                &answers.context,
                LedgerRequest {
                    file,
                    uri: &uri,
                    index,
                    entities: &entities,
                    unproven: &answers.unproven,
                    produced_references: &answers.produced_references,
                    ending: answers.ending,
                    not_in_build: answers.not_in_build,
                    retract: answers.retract,
                },
            )
            .await
            .map(|(batch, ledgers)| {
                written += batch;
                pass.ledgers = ledgers;
            })
            .err();
    } else if refused.is_none() {
        refused = capture
            .settle(
                state,
                file,
                text,
                &answers.sites,
                &answers.names,
                Some(&answers.context),
            )
            .await
            .map(|batch| written += batch)
            .err();
    }
    if refused.is_none()
        && pass.whole_file
        && answers.completed
        && written.lost() == 0
        && capture.marker_epoch == asked.marker_epoch
    {
        match capture.record_file_completed(state, file).await {
            Ok(recorded) => pass.marked = recorded,
            Err(reason) => refused = Some(reason),
        }
    }
    pass.written += written;
    pass.refused = refused;
}

/// The calls of `callers` in `file` whose settlement an edit undid, as each
/// caller and the byte its callee token starts at.
///
/// A call counts when the linker binds it to a repository declaration and no
/// standing language-server proof from the same caller to that declaration
/// records the same callee token. A proof that names the bound declaration
/// keeps the guess whatever else is asked, so its call is not asked again.
/// Every other guess may be one a sweep refuted, and the edit bound it again.
fn unsettled_calls(
    state: &DaemonState,
    inputs: &QueryInputs,
    file: &str,
    text: &str,
    callers: &[EntityId],
) -> BTreeSet<(EntityId, usize)> {
    let in_repository: HashSet<EntityId> = inputs
        .entities
        .iter()
        .filter(|entity| entity.file_origin.is_some())
        .map(|entity| entity.id)
        .collect();
    let mut calls = BTreeSet::new();
    for caller in callers {
        let Ok(relations) = state.graph.get_all_relations_for_entity(caller) else {
            continue;
        };
        let outgoing: Vec<&kin_model::Relation> = relations
            .iter()
            .filter(|relation| {
                relation.kind == RelationKind::Calls && relation.src == GraphNodeId::Entity(*caller)
            })
            .collect();
        let mut proven: HashMap<EntityId, HashSet<(usize, usize)>> = HashMap::new();
        for relation in &outgoing {
            let (RelationOrigin::Lsp, GraphNodeId::Entity(target)) =
                (relation.origin, relation.dst)
            else {
                continue;
            };
            proven.entry(target).or_default().extend(
                relation
                    .evidence
                    .iter()
                    .filter_map(|evidence| evidence.source_span.as_ref())
                    .map(|span| (span.start_byte, span.end_byte)),
            );
        }
        for edge in &outgoing {
            if matches!(edge.origin, RelationOrigin::Lsp | RelationOrigin::Manual)
                || kin_index::is_external_import_placeholder(edge)
            {
                continue;
            }
            let GraphNodeId::Entity(bound) = edge.dst else {
                continue;
            };
            if !in_repository.contains(&bound) {
                continue;
            }
            for span in edge
                .evidence
                .iter()
                .filter_map(|evidence| evidence.source_span.as_ref())
                .filter(|span| span.file.0 == file)
            {
                let Some(token) = kin_lsp::call_sites::callee_token(file, text, span) else {
                    continue;
                };
                let confirmed = proven
                    .get(&bound)
                    .is_some_and(|sites| sites.contains(&(token.start_byte, token.end_byte)));
                if !confirmed {
                    calls.insert((*caller, token.start_byte));
                }
            }
        }
    }
    calls
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{Entity, LanguageId, Relation};
    use serde_json::{json, Value};
    use std::collections::BTreeMap;

    const PEER: &str = include_str!("../../../kin-lsp/src/enrichment_test_peer.py");

    /// A scripted language server that answers `method@uri#column` from
    /// `responses`, and every other question with nothing.
    async fn peer(root: &Path, responses: &Value) -> kin_lsp::lifecycle::LspServer {
        let script = PEER.replace("os.environ[\"KIN_LSP_TEST_RESPONSES\"]", "sys.argv[1]");
        let responses = responses.to_string();
        kin_lsp::lifecycle::LspServer::start(
            "python3",
            &["-u", "-c", &script, &responses],
            root,
            None,
            None,
        )
        .await
        .unwrap()
    }

    fn index_of(inputs: &QueryInputs, root: &Path) -> kin_lsp::EntityIndex {
        kin_lsp::EntityIndex::new(
            inputs
                .entities
                .iter()
                .filter_map(|entity| {
                    super::super::lsp_entity_ref(entity, &entity.file_origin.as_ref()?.0)
                })
                .collect(),
            root,
        )
    }

    /// One file of a sweep, in the order the sweep runs it: the server's proof
    /// context noted as current, the whole-file pass, each declaration's own
    /// arms, the relations installed, then the answers settled under that
    /// context and every caller in the file given its call-site ledger, with
    /// the proofs the ledgers no longer hold retracted.
    async fn sweep_file(state: &DaemonState, root: &Path, file: &str, responses: &Value) {
        let inputs = QueryInputs::capture(state).await.unwrap();
        let index = index_of(&inputs, root);
        let text = inputs.document(file).expect("the file is admitted");
        let server = peer(root, responses).await;
        let context = server.proof_context(LanguageId::Python);
        super::super::note_current_proof_context(state, LanguageId::Python, &context);
        let provider = |path: &str| inputs.document(path);
        let mut result = kin_lsp::file_enrichment::enrich_file_definitions(
            &server,
            &root.join(file),
            &text,
            &index,
            root,
            Some(&provider),
        )
        .await
        .unwrap();
        let mut answers = std::mem::take(&mut result.site_answers);
        answers.extend(kin_lsp::call_sites::call_hierarchy_answers(
            &result.relations,
        ));
        let names = std::mem::take(&mut result.external_names);
        let unproven = std::mem::take(&mut result.unproven_sites);
        let mut produced = super::super::produced_reference_ids(&result.relations);
        let mut relations = std::mem::take(&mut result.relations);
        let entities: Vec<&Entity> = inputs
            .entities
            .iter()
            .filter(|entity| {
                entity
                    .file_origin
                    .as_ref()
                    .is_some_and(|origin| origin.0 == file)
            })
            .collect();
        let arms = if result.call_hierarchy_complete {
            EntityArms::AllButCalls
        } else {
            EntityArms::All
        };
        for entity in entities
            .iter()
            .filter_map(|entity| super::super::lsp_entity_ref(entity, file))
        {
            let (derived, _) = super::super::enrich_single_entity(
                &server,
                &entity,
                &index,
                root,
                Some(&provider),
                arms,
                std::time::Duration::from_secs(5),
            )
            .await;
            answers.extend(kin_lsp::call_sites::call_hierarchy_answers(&derived));
            produced.extend(super::super::produced_reference_ids(&derived));
            relations.extend(derived);
        }
        server.shutdown().await.unwrap();
        let mut pending = PendingEnrichment::default();
        inputs.absorb(state, &mut pending, relations).await.unwrap();
        inputs.flush(state, &mut pending).await.unwrap();
        let uri = uri(root, file);
        inputs
            .settle_file(
                state,
                &text,
                &answers,
                &names,
                &context,
                LedgerRequest {
                    file,
                    uri: &uri,
                    index: &index,
                    entities: &entities,
                    unproven: &unproven,
                    produced_references: &produced,
                    ending: PassEnding::Complete,
                    not_in_build: false,
                    retract: true,
                },
            )
            .await
            .unwrap();
    }

    /// The pass the daemon runs for an incremental request about `file`.
    async fn enrich_after_edit(
        state: &DaemonState,
        root: &Path,
        file: &str,
        changed: &[EntityId],
        responses: &Value,
    ) -> IncrementalPass {
        let inputs = QueryInputs::capture(state).await.unwrap();
        enrich_through(state, &inputs, root, file, changed, responses).await
    }

    /// [`enrich_after_edit`] through a capture the caller took.
    async fn enrich_through(
        state: &DaemonState,
        inputs: &QueryInputs,
        root: &Path,
        file: &str,
        changed: &[EntityId],
        responses: &Value,
    ) -> IncrementalPass {
        let index = index_of(inputs, root);
        let text = inputs.document(file).expect("the file is admitted");
        let server = peer(root, responses).await;
        let pass = enrich_changed_file(
            state,
            inputs,
            &server,
            LanguageId::Python,
            &index,
            root,
            file,
            &text,
            changed,
        )
        .await;
        server.shutdown().await.unwrap();
        pass
    }

    /// A repository whose `app/run.py` holds `run`, and the daemon state over
    /// it, with a channel that receives the enrichment requests edits queue.
    struct Fixture {
        root: tempfile::TempDir,
        state: DaemonState,
        requests: tokio::sync::mpsc::Receiver<crate::state::LspEnrichmentMessage>,
    }

    impl Fixture {
        async fn new(run: &str, extra: &[(&str, &str)]) -> Self {
            let root = tempfile::tempdir().unwrap();
            let class = |name: &str| {
                format!(
                    "class {name}:\n    def send(self, x):\n        return x\n\n    def close(self):\n        return None\n\n    def open(self):\n        return None\n"
                )
            };
            std::fs::create_dir(root.path().join("app")).unwrap();
            std::fs::write(root.path().join("app/__init__.py"), "").unwrap();
            std::fs::write(root.path().join("app/run.py"), run).unwrap();
            std::fs::write(root.path().join("app/alpha.py"), class("Alpha")).unwrap();
            std::fs::write(root.path().join("app/beta.py"), class("Beta")).unwrap();
            for (file, text) in extra {
                std::fs::write(root.path().join(file), text).unwrap();
            }
            let init = kin_core::init(root.path()).unwrap();
            let (tx, requests) = tokio::sync::mpsc::channel(256);
            let mut state = DaemonState::open(init.layout.clone()).unwrap();
            state.lsp_enrichment_tx = Some(tx);
            crate::loop_runner::sync_filesystem_with_graph(&state)
                .await
                .unwrap();
            let mut fixture = Self {
                root,
                state,
                requests,
            };
            fixture.drain();
            fixture
        }

        fn path(&self) -> &Path {
            self.root.path()
        }

        /// Every incremental request queued since the last drain, by file.
        fn drain(&mut self) -> HashMap<String, Vec<EntityId>> {
            let mut requests: HashMap<String, Vec<EntityId>> = HashMap::new();
            while let Ok(message) = self.requests.try_recv() {
                if let crate::state::LspEnrichmentMessage::Incremental(request) = message {
                    requests
                        .entry(request.file_id.0)
                        .or_default()
                        .extend(request.changed_entity_ids);
                }
            }
            requests
        }

        /// Rewrite `app/run.py` and reconcile it, as a save does, and answer
        /// the declarations the edit's own enrichment request names.
        async fn edit_run(&mut self, text: &str) -> Vec<EntityId> {
            std::fs::write(self.path().join("app/run.py"), text).unwrap();
            crate::loop_runner::sync_filesystem_with_graph(&self.state)
                .await
                .unwrap();
            self.drain()
                .remove("app/run.py")
                .expect("an edit queues an enrichment request for its file")
        }

        fn named(&self, name: &str, file: &str) -> EntityId {
            self.state
                .graph
                .list_all_entities()
                .unwrap()
                .into_iter()
                .find(|entity: &Entity| {
                    entity.name == name
                        && entity.kind != kin_model::EntityKind::Module
                        && entity
                            .file_origin
                            .as_ref()
                            .is_some_and(|origin| origin.0 == file)
                })
                .unwrap_or_else(|| panic!("the fixture declares {name} in {file}"))
                .id
        }

        fn declarations(&self, file: &str) -> Vec<EntityId> {
            self.state
                .graph
                .list_all_entities()
                .unwrap()
                .into_iter()
                .filter(|entity| {
                    entity
                        .file_origin
                        .as_ref()
                        .is_some_and(|origin| origin.0 == file)
                })
                .map(|entity| entity.id)
                .collect()
        }

        fn calls_from(&self, caller: EntityId) -> Vec<Relation> {
            self.state
                .graph
                .get_all_relations_for_entity(&caller)
                .unwrap()
                .into_iter()
                .filter(|relation| {
                    relation.kind == RelationKind::Calls
                        && relation.src == GraphNodeId::Entity(caller)
                })
                .collect()
        }

        /// The linker's name-only guesses from `caller` to `callee`.
        fn guesses(&self, caller: EntityId, callee: EntityId) -> usize {
            self.calls_from(caller)
                .iter()
                .filter(|relation| {
                    relation.dst == GraphNodeId::Entity(callee)
                        && relation.origin != RelationOrigin::Lsp
                        && kin_index::RelationResolution::of(relation)
                            == kin_index::RelationResolution::NameOnly
                })
                .count()
        }

        /// The call sites, as the text at each, a language-server proof from
        /// `caller` to `callee` records.
        fn proven_sites(&self, caller: EntityId, callee: GraphNodeId, text: &str) -> Vec<String> {
            let mut relations = self.calls_from(caller);
            relations.extend(
                self.state
                    .graph
                    .get_external_relations_for_entity(&caller)
                    .unwrap(),
            );
            let mut sites: Vec<String> = relations
                .iter()
                .filter(|relation| relation.dst == callee && relation.origin == RelationOrigin::Lsp)
                .flat_map(|relation| relation.evidence.iter())
                .filter_map(|evidence| evidence.source_span.as_ref())
                .filter(|span| span.end_byte > span.start_byte)
                .map(|span| {
                    let line = text[..span.start_byte].matches('\n').count();
                    format!("{line}:{}", &text[span.start_byte..span.end_byte])
                })
                .collect();
            sites.sort();
            sites.dedup();
            sites
        }

        fn marked(&self, file: &str) -> bool {
            self.state
                .lsp_pending_marks
                .lock()
                .unwrap()
                .contains_key(file)
        }

        /// The call-site ledgers the graph holds for the callers `file`
        /// declares, exactly as stored, by caller.
        fn ledger_records(&self, file: &str) -> BTreeMap<EntityId, kin_model::CallSiteLedger> {
            self.declarations(file)
                .into_iter()
                .filter_map(|caller| {
                    let record = self.state.graph.get_resolution_record(
                        &kin_model::ResolutionRecordId::call_sites(caller),
                    )?;
                    Some((caller, record.as_call_sites()?.clone()))
                })
                .collect()
        }

        /// [`Self::ledger_records`] in a form two stores can be compared in:
        /// by caller name, each ledger's census, whether it was proven under
        /// the proof context current for Python, and every site's key and
        /// state, with each target named.
        fn ledgers(&self, file: &str) -> BTreeMap<String, (u32, bool, Vec<(u32, u32, String)>)> {
            let current = self
                .state
                .lsp_current_contexts
                .lock()
                .unwrap()
                .get(&LanguageId::Python)
                .copied();
            let name = |id: &EntityId| {
                self.state
                    .graph
                    .get_entity(id)
                    .unwrap()
                    .map(|entity| entity.name)
                    .unwrap_or_else(|| id.to_string())
            };
            self.ledger_records(file)
                .into_iter()
                .map(|(caller, ledger)| {
                    let sites = ledger
                        .sites
                        .iter()
                        .map(|site| {
                            let state = match &site.state {
                                kin_model::CallSiteState::ProvenTarget { target } => {
                                    format!("proven_target {}", name(target))
                                }
                                other => format!("{other:?}"),
                            };
                            (site.offset, site.length, state)
                        })
                        .collect();
                    (
                        name(&caller),
                        (ledger.census, Some(ledger.context) == current, sites),
                    )
                })
                .collect()
        }
    }

    fn uri(root: &Path, file: &str) -> String {
        kin_lsp::protocol::path_to_uri(&root.join(file))
    }

    /// A definition answer naming `line:start-end` of `target`.
    fn at(target: &str, line: u32, start: u32, end: u32) -> Value {
        json!({"result": [{"uri": target, "range": {
            "start": {"line": line, "character": start},
            "end": {"line": line, "character": end}}}]})
    }

    /// Definition answers for `app/run.py`, keyed by the column of the callee
    /// token they answer. The scripted server matches on the column alone,
    /// so each fixture puts every answered callee at a column no other
    /// identifier in the file starts at.
    fn answers(root: &Path, by_column: &[(usize, Value)]) -> Value {
        let mut responses = json!({"initialize": {"result": {"capabilities": {
            "definitionProvider": true, "callHierarchyProvider": false
        }}}});
        let run = uri(root, "app/run.py");
        for (column, answer) in by_column {
            responses[format!("textDocument/definition@{run}#{column}")] = answer.clone();
        }
        responses
    }

    fn column(text: &str, line: usize, token: &str) -> usize {
        text.lines().nth(line).unwrap().find(token).unwrap()
    }

    /// An edit to a caller re-proves its calls: the guess the sweep refuted
    /// comes back with the edit and goes again, the proof records the call
    /// where it now is, and a call the edit added is proven too.
    #[tokio::test]
    async fn an_edit_to_a_caller_reproves_its_calls() {
        let before = "from app.alpha import Alpha\n\n\ndef run(client):\n    xx = client.close()\n";
        let mut fixture = Fixture::new(before, &[]).await;
        let root = fixture.path().to_path_buf();
        let beta = uri(&root, "app/beta.py");
        sweep_file(
            &fixture.state,
            &root,
            "app/run.py",
            &answers(&root, &[(column(before, 4, "close"), at(&beta, 4, 8, 13))]),
        )
        .await;
        let run = fixture.named("run", "app/run.py");
        let alpha_close = fixture.named("Alpha.close", "app/alpha.py");
        let alpha_open = fixture.named("Alpha.open", "app/alpha.py");
        let beta_close = fixture.named("Beta.close", "app/beta.py");
        let beta_open = fixture.named("Beta.open", "app/beta.py");
        assert_eq!(fixture.guesses(run, alpha_close), 0, "the sweep settled it");

        // The edit moves the call and adds another.
        let after = "from app.alpha import Alpha\n\n\ndef run(client):\n    q = 1\n    wwwwwwwww = client.close()\n    vvvvvvvvvvvvvvv = client.open()\n";
        let changed = fixture.edit_run(after).await;
        assert_eq!(
            fixture.guesses(run, alpha_close),
            1,
            "the edit bound the refuted guess again, which is what this test is about"
        );
        assert_eq!(fixture.guesses(run, alpha_open), 1);

        let pass = enrich_after_edit(
            &fixture.state,
            &root,
            "app/run.py",
            &changed,
            &answers(
                &root,
                &[
                    (column(after, 5, "close"), at(&beta, 4, 8, 13)),
                    (column(after, 6, "open"), at(&beta, 7, 8, 12)),
                ],
            ),
        )
        .await;
        assert_eq!(pass.refused, None);
        assert_eq!(
            (
                fixture.guesses(run, alpha_close),
                fixture.guesses(run, alpha_open)
            ),
            (0, 0),
            "both guesses are refuted again: {:#?}",
            fixture.calls_from(run)
        );
        assert!(
            fixture
                .proven_sites(run, GraphNodeId::Entity(beta_close), after)
                .contains(&"5:close".to_string()),
            "the moved call is proven where it now is: {:?}",
            fixture.proven_sites(run, GraphNodeId::Entity(beta_close), after)
        );
        assert_eq!(
            fixture.proven_sites(run, GraphNodeId::Entity(beta_open), after),
            ["6:open"],
            "the added call is proven"
        );
    }

    /// A guess the sweep settled in a caller the edit did not touch stays
    /// settled. The edit re-links the whole file, so the guess comes back,
    /// and the pass that follows the edit settles it again: whether the
    /// request names every declaration of the file, as an edit's does, or
    /// only the edited one. Only the pass over the whole file records the
    /// file's completion mark.
    #[tokio::test]
    async fn a_settled_guess_elsewhere_in_the_file_stays_retired() {
        let before = "from app.alpha import Alpha\n\n\ndef run(client):\n    client.send(1)\n\n\ndef other(client):\n    zzzzzz = client.close()\n";
        let after = "from app.alpha import Alpha\n\n\ndef run(client):\n    client.send(2)\n    return None\n\n\ndef other(client):\n    zzzzzz = client.close()\n";
        for whole in [true, false] {
            let mut fixture = Fixture::new(before, &[]).await;
            let root = fixture.path().to_path_buf();
            let beta = uri(&root, "app/beta.py");
            let close_answer = (column(before, 8, "close"), at(&beta, 4, 8, 13));
            sweep_file(
                &fixture.state,
                &root,
                "app/run.py",
                &answers(&root, std::slice::from_ref(&close_answer)),
            )
            .await;
            let other = fixture.named("other", "app/run.py");
            let run = fixture.named("run", "app/run.py");
            let alpha_close = fixture.named("Alpha.close", "app/alpha.py");
            let beta_close = fixture.named("Beta.close", "app/beta.py");
            assert_eq!(
                fixture.guesses(other, alpha_close),
                0,
                "the sweep settled it"
            );

            let changed = fixture.edit_run(after).await;
            let mut declarations = fixture.declarations("app/run.py");
            let mut named = changed.clone();
            declarations.sort();
            named.sort();
            assert_eq!(
                named, declarations,
                "an edit re-derives, and names, every declaration of its file"
            );
            assert_eq!(
                fixture.guesses(other, alpha_close),
                1,
                "the edit to `run` bound `other`'s refuted guess again"
            );
            let request = if whole { changed } else { vec![run] };
            let pass = enrich_after_edit(
                &fixture.state,
                &root,
                "app/run.py",
                &request,
                &answers(&root, &[close_answer]),
            )
            .await;
            assert_eq!(pass.refused, None);
            assert_eq!(
                fixture.guesses(other, alpha_close),
                0,
                "whole file {whole}: the settled guess is settled again: {:#?}",
                fixture.calls_from(other)
            );
            assert_eq!(pass.whole_file, whole);
            assert_eq!(
                fixture.proven_sites(other, GraphNodeId::Entity(beta_close), after),
                ["9:close"],
                "whole file {whole}"
            );
            if whole {
                assert!(pass.marked && fixture.marked("app/run.py"));
            } else {
                assert_eq!(pass.reasked_calls, 1, "only the unconfirmed call is asked");
                assert!(
                    !pass.marked && !fixture.marked("app/run.py"),
                    "a pass over part of the file records no mark"
                );
            }
        }
    }

    /// A call the server answers outside the repository still refutes the
    /// guess after an edit, and is proven as a call to the named external
    /// symbol at the site where the call now is.
    #[tokio::test]
    async fn an_outside_answer_after_an_edit_refutes_and_names_the_external_symbol() {
        let before = "from app.alpha import Alpha\n\n\ndef run(client):\n    client.send(1)\n";
        let mut fixture = Fixture::new(before, &[]).await;
        let root = fixture.path().to_path_buf();
        // The declaration outside the repository: an interpreter's own
        // library, which names its package by the version in its path.
        let outside = tempfile::tempdir().unwrap();
        let library = outside.path().join("lib/python3.12");
        std::fs::create_dir_all(&library).unwrap();
        std::fs::write(
            library.join("transport.py"),
            "class Client:\n    def send(self, request):\n        return request\n",
        )
        .unwrap();
        let transport = uri(&library, "transport.py");
        let symbols = json!({"result": [{
            "name": "Client", "kind": 5,
            "range": {"start": {"line": 0, "character": 0}, "end": {"line": 2, "character": 22}},
            "selectionRange": {"start": {"line": 0, "character": 6}, "end": {"line": 0, "character": 12}},
            "children": [{
                "name": "send", "kind": 6,
                "range": {"start": {"line": 1, "character": 4}, "end": {"line": 2, "character": 22}},
                "selectionRange": {"start": {"line": 1, "character": 8}, "end": {"line": 1, "character": 12}}
            }]
        }]});
        let with_symbols = |mut responses: Value| {
            responses[format!("textDocument/documentSymbol@{transport}#")] = symbols.clone();
            responses
        };
        sweep_file(
            &fixture.state,
            &root,
            "app/run.py",
            &with_symbols(answers(
                &root,
                &[(column(before, 4, "send"), at(&transport, 1, 8, 12))],
            )),
        )
        .await;
        let run = fixture.named("run", "app/run.py");
        let alpha_send = fixture.named("Alpha.send", "app/alpha.py");
        let external: Vec<Relation> = fixture
            .state
            .graph
            .get_external_relations_for_entity(&run)
            .unwrap();
        assert_eq!(fixture.guesses(run, alpha_send), 0, "the sweep refuted it");
        let [proven] = external.as_slice() else {
            panic!("the sweep proves one call into the named symbol: {external:#?}");
        };
        let symbol = proven.dst;

        let after = "from app.alpha import Alpha\n\n\ndef run(client):\n    count = 1\n    yyyyyyyyyyyyyyyyy = client.send(count)\n";
        let changed = fixture.edit_run(after).await;
        assert_eq!(
            fixture.guesses(run, alpha_send),
            1,
            "the edit bound it again"
        );
        let pass = enrich_after_edit(
            &fixture.state,
            &root,
            "app/run.py",
            &changed,
            &with_symbols(answers(
                &root,
                &[(column(after, 5, "send"), at(&transport, 1, 8, 12))],
            )),
        )
        .await;
        assert_eq!(pass.refused, None);
        assert_eq!(
            fixture.guesses(run, alpha_send),
            0,
            "the outside answer refutes the guess again: {:#?}",
            fixture.calls_from(run)
        );
        assert!(
            fixture
                .proven_sites(run, symbol, after)
                .contains(&"5:send".to_string()),
            "the call into the named symbol is proven where it now is: {:?}",
            fixture.proven_sites(run, symbol, after)
        );
        assert!(pass.marked, "the whole file was answered");
    }

    /// A graph write that moves only the authority epoch while the server is
    /// asked, as the watcher's reconcile of a commit's own working-tree write
    /// does, no longer throws the pass away: its answers are written under a
    /// fresh capture, since the entities and tree they were proven against are
    /// unchanged. A pass whose file changed under it is still refused and left
    /// to the sweep.
    #[tokio::test]
    async fn a_pass_outlives_an_epoch_move_but_not_an_edit_under_it() {
        let before = "from app.alpha import Alpha\n\n\ndef run(client):\n    xx = client.close()\n";
        let mut fixture = Fixture::new(before, &[]).await;
        let root = fixture.path().to_path_buf();
        let beta = uri(&root, "app/beta.py");
        let close = (column(before, 4, "close"), at(&beta, 4, 8, 13));
        sweep_file(
            &fixture.state,
            &root,
            "app/run.py",
            &answers(&root, std::slice::from_ref(&close)),
        )
        .await;
        let run = fixture.named("run", "app/run.py");
        let alpha_close = fixture.named("Alpha.close", "app/alpha.py");

        let after = "from app.alpha import Alpha\n\n\ndef run(client):\n    q = 1\n    xx = client.close()\n";
        let changed = fixture.edit_run(after).await;
        assert_eq!(
            fixture.guesses(run, alpha_close),
            1,
            "the edit bound it again"
        );
        let inputs = QueryInputs::capture(&fixture.state).await.unwrap();
        // A write that changes nothing the pass asked about moves the epoch.
        drop(fixture.state.begin_graph_authority_mutation());
        let pass = enrich_through(
            &fixture.state,
            &inputs,
            &root,
            "app/run.py",
            &changed,
            &answers(&root, std::slice::from_ref(&close)),
        )
        .await;
        assert_eq!(pass.refused, None);
        assert_eq!(pass.revalidated, 1);
        assert!(pass.marked, "the whole file was answered");
        assert_eq!(
            fixture.guesses(run, alpha_close),
            0,
            "and its guess settled"
        );

        // The file changes after the capture: its answers describe a graph
        // that is gone, and the sweep asks again.
        let stale = QueryInputs::capture(&fixture.state).await.unwrap();
        let edited = "from app.alpha import Alpha\n\n\ndef run(client):\n    q = 2\n    xx = client.close()\n";
        let changed = fixture.edit_run(edited).await;
        let pass = enrich_through(
            &fixture.state,
            &stale,
            &root,
            "app/run.py",
            &changed,
            &answers(&root, &[close]),
        )
        .await;
        assert_eq!(pass.refused, Some(Refused::Stale));
        assert_eq!(pass.revalidated, 0);
        assert!(!pass.marked && !fixture.marked("app/run.py"));
    }

    /// An incremental pass over an edited file leaves the call-site ledgers a
    /// sweep of that file leaves, and so may record the file's mark: in the
    /// same store, where a sweep changes only the peer's proof context, and
    /// in a store that was only ever swept at the edited text.
    #[tokio::test]
    async fn an_incremental_pass_leaves_the_ledgers_a_fresh_sweep_does() {
        async fn validated_ledgers(
            fixture: &Fixture,
        ) -> (
            kin_model::ProofContext,
            BTreeMap<EntityId, kin_model::CallSiteLedger>,
        ) {
            let current = fixture.state.lsp_current_contexts.lock().unwrap()[&LanguageId::Python];
            let record = fixture.state.graph.get_resolution_record(&current).unwrap();
            let context = record.as_proof_context().unwrap().clone();
            assert_eq!(context.language, LanguageId::Python);
            let ledgers = fixture.ledger_records("app/run.py");
            assert_eq!(ledgers.len(), fixture.declarations("app/run.py").len());
            for ledger in ledgers.values() {
                assert_eq!(
                    ledger.context, current,
                    "every caller uses this peer's context"
                );
            }
            // These direct file-pass helpers omit the worker's validation
            // orchestration. Record the actual peer context through its normal
            // fresh-capture path, then require the persisted validation too.
            let inputs = QueryInputs::capture(&fixture.state).await.unwrap();
            let validation = kin_model::ContextValidationState::Validated {
                context: context.clone(),
            };
            inputs
                .record_context_validation(&fixture.state, LanguageId::Python, validation.clone())
                .await
                .unwrap();
            let record = fixture
                .state
                .graph
                .get_resolution_record(&kin_model::ResolutionRecordId::context_validation(
                    LanguageId::Python,
                ))
                .unwrap();
            let persisted = record.as_context_validation().unwrap();
            assert_eq!(persisted.state, validation);
            assert_eq!(persisted.current_context(), Some(current));
            (context, ledgers)
        }

        fn same_resolver_context(a: &kin_model::ProofContext, b: &kin_model::ProofContext) {
            // Each helper starts a new `python3 -c` peer. On Linux its
            // interpreter is intentionally unidentifiable, so each launch has
            // a fresh configuration hash. Every other context field must match.
            let mut normalized = b.clone();
            normalized.configuration_hash = a.configuration_hash;
            assert_eq!(&normalized, a);
        }

        let before = "from app.alpha import Alpha\n\n\ndef run(client):\n    xx = client.close()\n\n\ndef other(client):\n    zzzzzz = client.send(1)\n";
        let after = "from app.alpha import Alpha\n\n\ndef run(client):\n    q = 1\n    wwwwwwwww = client.close()\n    vvvvvvvvvvvvvvv = client.open()\n\n\ndef other(client):\n    zzzzzz = client.send(1)\n";
        let answered = |root: &Path, text: &str, close_line: usize, send_line: usize| {
            let beta = uri(root, "app/beta.py");
            let mut by_column = vec![
                (column(text, close_line, "close"), at(&beta, 4, 8, 13)),
                (column(text, send_line, "send"), at(&beta, 1, 8, 12)),
            ];
            if text.contains("client.open()") {
                by_column.push((column(text, close_line + 1, "open"), at(&beta, 7, 8, 12)));
            }
            answers(root, &by_column)
        };

        // Swept at the old text, edited, and enriched by the incremental pass.
        let mut edited = Fixture::new(before, &[]).await;
        let root = edited.path().to_path_buf();
        sweep_file(
            &edited.state,
            &root,
            "app/run.py",
            &answered(&root, before, 4, 8),
        )
        .await;
        let changed = edited.edit_run(after).await;
        let run = edited.named("run", "app/run.py");
        assert!(
            !edited.ledger_records("app/run.py").contains_key(&run),
            "the edit changed `run`, which retired its ledger"
        );
        let pass = enrich_after_edit(
            &edited.state,
            &root,
            "app/run.py",
            &changed,
            &answered(&root, after, 5, 10),
        )
        .await;
        assert_eq!(pass.refused, None);
        assert!(pass.whole_file && pass.marked, "{pass:#?}");
        assert!(
            pass.ledgers.censused && pass.ledgers.refused == 0,
            "{pass:#?}"
        );
        let incremental = edited.ledgers("app/run.py");
        assert_eq!(
            incremental.get("run").map(|(census, current, sites)| (
                *census,
                *current,
                sites.iter().map(|site| site.2.clone()).collect::<Vec<_>>()
            )),
            Some((
                2,
                true,
                vec![
                    "proven_target Beta.close".to_string(),
                    "proven_target Beta.open".to_string()
                ]
            )),
            "every call `run` makes now has its state, under the current context: \
             {incremental:#?}"
        );
        assert!(incremental.contains_key("other"), "{incremental:#?}");

        // A sweep with a separately started peer changes no ledger payload.
        let (incremental_context, held) = validated_ledgers(&edited).await;
        sweep_file(
            &edited.state,
            &root,
            "app/run.py",
            &answered(&root, after, 5, 10),
        )
        .await;
        let (sweep_context, mut swept) = validated_ledgers(&edited).await;
        same_resolver_context(&incremental_context, &sweep_context);
        for ledger in swept.values_mut() {
            ledger.context = kin_model::ResolutionRecordId::proof_context(&incremental_context);
        }
        assert_eq!(
            swept, held,
            "all ledger fields except the checked peer context agree"
        );

        // A store that only ever saw the edited text, swept once.
        let fresh = Fixture::new(after, &[]).await;
        let fresh_root = fresh.path().to_path_buf();
        sweep_file(
            &fresh.state,
            &fresh_root,
            "app/run.py",
            &answered(&fresh_root, after, 5, 10),
        )
        .await;
        let (fresh_context, _) = validated_ledgers(&fresh).await;
        same_resolver_context(&incremental_context, &fresh_context);
        assert_eq!(
            incremental,
            fresh.ledgers("app/run.py"),
            "the incremental pass leaves the ledgers a fresh sweep of the file leaves"
        );
    }
}
