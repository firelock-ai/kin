// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The package this question is about, that this graph has never seen.
//!
//! A retrieval verdict describes the graph. When the answer to the question
//! lives in a dependency the graph never admitted, describing the graph
//! accurately is not the same as answering, and nothing in the envelope
//! separated the two. A stranger asked v0.7.2 where `router.param` callbacks are
//! registered and how a request is dispatched, on `expressjs/express` at
//! `023767fe`. Express's router is the external `router` package:
//! `lib/application.js:26` and `lib/express.js:19` both read
//! `var Router = require('router')`, and that package was never admitted. The
//! response came back `verdict.state: "certified"`, `limiting_factor: null`,
//! `completeness.bound: "exact"`, `status: "complete"`. Every word of that is
//! true about the graph and silent about the question, and nothing in it
//! distinguishes "I searched everything and found it" from "I searched
//! everything I have and the answer is elsewhere" (FIR-3306).
//!
//! The fact was already in the graph, which is why this reads no files. The
//! linker models an import it could not resolve locally as a placeholder
//! relation carrying the module specifier the importing file named, pointing at
//! an external reference target: an entity with [`EntityRole::External`] and no
//! `file_origin`, standing for a definition that lives somewhere this repository
//! does not own. `kin graph status` on that same express store printed
//! `External reference targets: 19` beside `239 name a module outside this
//! repository`. `trace_data_flow` already renders the same fact per crossing;
//! this raises it to the one verdict, where every tool's answer passes.
//!
//! ## Two ways to be wrong, and the guards against each
//!
//! **Refusing too much.** Every repository with dependencies has unadmitted
//! modules, so an observation that fired whenever one EXISTS would refuse every
//! answer, and a verdict that cannot say yes is worth no more than one that
//! cannot say no. Two guards. The question must NAME the symbol, and the symbol
//! must resolve to no definition this repository owns. The second one is not
//! belt and braces: express binds `send`, `path`, `resolve`, `parse` and `http`
//! from unadmitted modules, and `lib/response.js` defines `res.send` itself, so
//! without it a question about `res.send` would go inconclusive about code
//! sitting in the graph.
//!
//! **Refusing too little.** The scan is bounded, and a bound whose evidence is
//! discarded is the original defect wearing the other face: a question naming
//! the 513th target with no match in the examined prefix would produce no block,
//! the verdict would read that absence as silence, and a certified answer would
//! stay certified over an observation that never completed. So an incomplete
//! scan publishes a block WITH its reason even when it matched nothing, and the
//! verdict refuses on the reason. The same holds when the store's own query
//! fails: a read that could not run is not a read that found nothing.
//!
//! ## Published shape
//!
//! ```json
//! "outside_graph": {
//!   "scan": "complete",
//!   "asked_about": ["router"],
//!   "symbols": [{ "symbol": "Router", "modules": ["router"] }],
//!   "targets_examined": 19,
//!   "targets_matching": 19
//! }
//! ```
//!
//! `scan` is `complete`, `budget_exhausted` or `read_failed`, and only the first
//! licenses reading an empty `symbols` as "this question stays inside the
//! graph". [`crate::verdict`] consumes the block as an input: any of the three
//! states with something to report makes the response inconclusive, and
//! [`crate::verdict::Verdict::project_onto_completeness`] takes `complete` and
//! `exact` off the same response.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Value};

use kin_model::entity::{Entity, EntityKind, EntityRole};
use kin_model::graph::{EntityFilter, EntityPage, EntityPageResult, EntityStore};
use kin_model::ids::EntityId;
use kin_model::relation::Relation;

/// The exact read surface this observation consumes.
///
/// Named as its own trait for the same reason `kin_review::ImpactGraph` is: the
/// cases that decide whether this module is honest are a store that CANNOT
/// answer and a store whose kind index cannot serve `Module`, and neither is
/// reachable through the real graph. Against the full `EntityStore` those two
/// fixtures would be thirty-six delegating methods each, which is enough
/// boilerplate that they would not get written, and a disclosure whose failure
/// paths are untested is the defect it exists to prevent.
///
/// `None` is "this store could not answer", never "this store answered
/// nothing". Every caller below treats the difference as load-bearing.
pub trait OutsideGraphReads {
    /// One bounded window of the entities matching `filter`, in the store's own
    /// order, with the total it matched.
    fn page(&self, filter: &EntityFilter, page: &EntityPage) -> Option<EntityPageResult>;
    /// Every entity the store's name index returns for `name`.
    fn named(&self, name: &str) -> Option<Vec<Entity>>;
    /// Every relation touching `id`, in either direction.
    fn relations(&self, id: &EntityId) -> Option<Vec<Relation>>;
}

impl<S: EntityStore> OutsideGraphReads for S {
    fn page(&self, filter: &EntityFilter, page: &EntityPage) -> Option<EntityPageResult> {
        self.query_entities_page(filter, page).ok()
    }

    fn named(&self, name: &str) -> Option<Vec<Entity>> {
        self.query_entities(&EntityFilter {
            name_pattern: Some(name.to_string()),
            ..EntityFilter::default()
        })
        .ok()
    }

    fn relations(&self, id: &EntityId) -> Option<Vec<Relation>> {
        self.get_all_relations_for_entity(id).ok()
    }
}

/// Reserved, additive payload key carrying the unadmitted-dependency
/// observation. Read by [`crate::verdict`].
pub const OUTSIDE_GRAPH_KEY: &str = "outside_graph";

/// The argument names a tool carries its question under.
///
/// `query` is what nearly every retrieval tool takes; `get_context_pack` takes
/// `question`. Both are read, in this order, because a tool that takes both
/// means the same thing by them and the first non-empty one is the question.
const QUESTION_ARGUMENTS: [&str; 2] = ["query", "question"];

/// The most external reference targets one observation examines.
///
/// External targets are a small set even on a large repository (nineteen on
/// express), and the cap is here so that "small in practice" is not the only
/// thing bounding it. A store holding more publishes `scan: "budget_exhausted"`,
/// which is an honest "there may be more" rather than a claim that the rest are
/// absent.
const TARGET_BUDGET: usize = 512;

/// How far the observation got, and therefore what an empty answer means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScanState {
    /// Every external reference target this store holds was examined, so an
    /// empty result IS a result: this question names nothing outside the graph.
    Complete,
    /// [`TARGET_BUDGET`] stopped the walk with targets left. An empty result
    /// here means the match may be among the ones never looked at.
    BudgetExhausted,
    /// The store could not answer the query at all. A read that did not run is
    /// not a read that found nothing.
    ReadFailed,
}

impl ScanState {
    fn as_str(self) -> &'static str {
        match self {
            ScanState::Complete => "complete",
            ScanState::BudgetExhausted => "budget_exhausted",
            ScanState::ReadFailed => "read_failed",
        }
    }
}

/// One identifier a question named that this graph holds no definition for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutsideSymbol {
    /// The symbol as the graph records it, which is what the importing file
    /// bound: `Router`.
    pub symbol: String,
    /// The module specifiers that reach it, verbatim as the importing file
    /// named them: `router`, `@scope/pkg`, `requests.adapters`. Empty when no
    /// edge into the symbol recorded one, which is itself worth reporting.
    pub modules: BTreeSet<String>,
}

/// What one store observed about the identifiers a question named.
#[derive(Debug, Clone)]
pub struct OutsideGraphObservation {
    /// How far the scan got.
    pub scan: ScanState,
    /// The tokens of the question that matched, folded to lowercase.
    pub asked_about: BTreeSet<String>,
    /// The symbols they matched, each a definition this graph does not hold.
    pub symbols: Vec<OutsideSymbol>,
    /// How many rows of the store's external-entity page were examined.
    pub targets_examined: usize,
    /// How many rows that query matched in total, which is larger than
    /// `targets_examined` exactly when the budget stopped the walk.
    pub targets_matching: usize,
}

impl Default for OutsideGraphObservation {
    fn default() -> Self {
        Self {
            scan: ScanState::Complete,
            asked_about: BTreeSet::new(),
            symbols: Vec::new(),
            targets_examined: 0,
            targets_matching: 0,
        }
    }
}

impl OutsideGraphObservation {
    /// Whether this observation has anything to publish.
    ///
    /// A complete scan that matched nothing has not: it looked at everything and
    /// the question named none of it, which is the ordinary case and the one
    /// that must stay quiet. An INCOMPLETE scan that matched nothing has, and
    /// that is the whole point of this method existing rather than a bare
    /// `symbols.is_empty()`.
    pub fn is_reportable(&self) -> bool {
        !self.symbols.is_empty() || self.scan != ScanState::Complete
    }
}

/// The question this call asked, from whichever argument the tool carries it in.
pub fn question_argument<'a>(
    arguments: &'a std::collections::HashMap<String, Value>,
) -> Option<&'a str> {
    QUESTION_ARGUMENTS.iter().find_map(|name| {
        arguments
            .get(*name)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|question| !question.is_empty())
    })
}

/// Observe whether `question` names an identifier this graph resolved to a
/// definition it does not hold, reading the graph and nothing else.
///
/// An external reference target is the linker's own model of exactly that: a
/// node it created because a `Calls` or `References` site named a module it
/// could not resolve locally. [`kin_index::is_external_reference_target`] is the
/// predicate, and it is deliberately the conjunction of the role and an absent
/// `file_origin`, because [`EntityRole::External`] is also assigned to real,
/// locally defined entities under `third_party/` and those own their source.
///
/// The module specifier is read off the placeholder relation reaching the
/// matched target, which is where the importing file recorded it. That lookup,
/// and the local-definition check beside it, run only for a target the question
/// already named, so a question about code this repository owns costs one
/// filtered entity page and nothing else.
pub fn observe<S: OutsideGraphReads + ?Sized>(store: &S, question: &str) -> OutsideGraphObservation {
    let mut observed = OutsideGraphObservation::default();
    let tokens = question_tokens(question);
    if tokens.is_empty() {
        return observed;
    }

    let Some(page) = external_targets(store) else {
        observed.scan = ScanState::ReadFailed;
        return observed;
    };
    observed.targets_matching = page.total_matching;

    // Counted off the page rather than off the predicate below, because that is
    // what `total_matching` is comparable to. Counting only the rows that pass
    // `is_external_reference_target` would read a page holding one locally
    // defined `third_party/` entity as a truncated scan forever.
    observed.targets_examined = page.entities.len();

    let mut by_symbol: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for entity in page.entities {
        if !kin_index::is_external_reference_target(&entity) {
            continue;
        }

        let folded = entity.name.to_ascii_lowercase();
        if !tokens.contains(&folded) {
            continue;
        }
        // The second guard. A symbol this repository also defines is answerable
        // from the graph whatever else imports something by that name, and
        // refusing there would put a floor under every question about a common
        // word. On express, `send`, `path`, `resolve` and `parse` are all bound
        // from unadmitted modules AND defined locally.
        if defines_locally(store, &entity.name) {
            continue;
        }
        observed.asked_about.insert(folded);
        let modules = by_symbol.entry(entity.name.clone()).or_default();
        if let Some(relations) = store.relations(&entity.id) {
            for relation in relations {
                if relation.dst.as_entity() != Some(entity.id) {
                    continue;
                }
                let Some(specifier) = relation.import_source.as_deref().map(str::trim) else {
                    continue;
                };
                if !specifier.is_empty() {
                    modules.insert(specifier.to_string());
                }
            }
        }
    }

    if observed.targets_matching > observed.targets_examined {
        observed.scan = ScanState::BudgetExhausted;
    }
    observed.symbols = by_symbol
        .into_iter()
        .map(|(symbol, modules)| OutsideSymbol { symbol, modules })
        .collect();
    observed
}

/// One bounded page of this store's external reference targets, or `None` when
/// the store could not answer.
///
/// The kind is in the filter as well as the role, and it is there for cost: a
/// single-kind filter is served by the store's kind index where a role-only
/// filter falls through to a scan of every entity, and this observation runs on
/// every retrieval call that carries a question. The linker builds every
/// external reference target as a `Module`.
///
/// The narrowing is not trusted, though, which is the second query. A store
/// whose kind index cannot serve `Module` answers the narrow filter with
/// nothing, and nothing is indistinguishable from a repository that imports
/// nothing: exactly the false "you are fine" this module exists to stop. So an
/// empty narrow answer is re-asked by role alone, and only an empty answer to
/// THAT means there are no targets.
fn external_targets<S: OutsideGraphReads + ?Sized>(store: &S) -> Option<EntityPageResult> {
    let page = EntityPage::first(TARGET_BUDGET);
    let narrow = store.page(
        &EntityFilter {
            kinds: Some(vec![EntityKind::Module]),
            roles: Some(vec![EntityRole::External]),
            ..EntityFilter::default()
        },
        &page,
    )?;
    if narrow.total_matching > 0 {
        return Some(narrow);
    }
    store.page(
        &EntityFilter {
            roles: Some(vec![EntityRole::External]),
            ..EntityFilter::default()
        },
        &page,
    )
}

/// Whether this repository defines something a question asking for `name` would
/// be answered by.
///
/// Asked through the store's name index rather than by scanning, and only for a
/// name the question already named. An external reference target is not a
/// definition, which is what the filter on the outcome is for: the target that
/// triggered the question is itself a same-named entity.
///
/// The dotted-suffix arm is the one that matters in practice, and it is not a
/// convenience. Express imports `send` from the unadmitted `send` package AND
/// defines the method a reader means by it as `res.send` in `lib/response.js`.
/// An exact-name test sees two different strings, lets the question through, and
/// answers "the answer may be outside this graph" about a function sitting in
/// it. The same collision holds there for `path`, `resolve`, `parse` and `http`.
fn defines_locally<S: OutsideGraphReads + ?Sized>(store: &S, name: &str) -> bool {
    store
        .named(name)
        .map(|entities| {
            entities.iter().any(|entity| {
                !kin_index::is_external_reference_target(entity) && names_the_same(&entity.name, name)
            })
        })
        .unwrap_or(false)
}

/// Whether a defined entity's name is what a question asking for `token` meant:
/// the whole name, or its last dotted segment.
fn names_the_same(defined: &str, token: &str) -> bool {
    defined.eq_ignore_ascii_case(token)
        || defined
            .rsplit('.')
            .next()
            .is_some_and(|leaf| leaf.eq_ignore_ascii_case(token))
}

/// The block to publish, or `None` when a complete scan found nothing to say.
pub fn block(observed: &OutsideGraphObservation) -> Option<Value> {
    if !observed.is_reportable() {
        return None;
    }
    Some(json!({
        "scan": observed.scan.as_str(),
        "asked_about": observed.asked_about.iter().cloned().collect::<Vec<_>>(),
        "symbols": observed
            .symbols
            .iter()
            .map(|entry| json!({
                "symbol": entry.symbol,
                "modules": entry.modules.iter().cloned().collect::<Vec<_>>(),
            }))
            .collect::<Vec<_>>(),
        "targets_examined": observed.targets_examined,
        "targets_matching": observed.targets_matching,
    }))
}

/// Observe and render in one call, for a caller holding a store and a question.
pub fn observe_for_question<S: OutsideGraphReads + ?Sized>(store: &S, question: &str) -> Option<Value> {
    block(&observe(store, question))
}

/// The identifier-shaped tokens of a question, ASCII-lowercased.
///
/// `router.param` yields `router` and `param`, because a dotted path names each
/// of its segments and the package is the first one. Case is folded because a
/// question says `router` where the binding says `Router`, and both name the
/// same thing.
fn question_tokens(question: &str) -> BTreeSet<String> {
    question
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|token| !token.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

/// The limiting-factor clause for a published block, or `None` when the block is
/// missing or has nothing to report.
///
/// One sentence in the clause shape [`crate::verdict`] composes: a label, a
/// colon, and the fact a reader acts on. A matched symbol names its module,
/// because "one dependency is outside this graph" sends nobody anywhere and
/// "`router` is outside this graph" sends them to admit it. An incomplete scan
/// says so instead, and says which way it stopped, because a bound whose
/// evidence is dropped is the same false certification wearing another face.
pub fn limiting_clause(block: &Value) -> Option<String> {
    let named: Vec<String> = block
        .get("symbols")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|entry| {
            let symbol = entry.get("symbol").and_then(Value::as_str)?;
            let modules: Vec<&str> = entry
                .get("modules")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(Value::as_str)
                .collect();
            Some(match modules.as_slice() {
                [] => format!("`{symbol}` (no module recorded)"),
                modules => format!("`{symbol}` from `{}`", modules.join("`, `")),
            })
        })
        .collect();
    if !named.is_empty() {
        return Some(format!(
            "dependency_outside_graph: this question names {}, which this repository imports and \
             this graph holds no definitions for, so the answer may live entirely outside what \
             was searched; admit the package or read it at its source",
            named.join(", ")
        ));
    }
    match block.get("scan").and_then(Value::as_str) {
        Some("budget_exhausted") => {
            let examined = block
                .get("targets_examined")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let matching = block
                .get("targets_matching")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            Some(format!(
                "dependency_scan_incomplete: {examined} of this repository's {matching} \
                 unadmitted imports were checked against this question before the scan hit its \
                 budget, so nothing here says the answer is not in one of the rest"
            ))
        }
        Some("read_failed") => Some(
            "dependency_scan_unavailable: this store could not be asked which of its imports \
             are unadmitted, so nothing here says the answer to this question is in the graph \
             at all"
                .to_string(),
        ),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_db::InMemoryGraph;
    use kin_index::linker::{ArtifactIdentityMap, FileParseData};
    use kin_model::entity::{
        EntityMetadata, FingerprintAlgorithm, SemanticFingerprint, Visibility,
    };
    use kin_model::graph::EntityStore as _;
    use kin_model::ids::{FilePathId, Hash256, LanguageId};
    use kin_model::relation::RelationKind;
    use kin_model::ArtifactId;
    use kin_parser::extract::ExtractedRelation;

    fn fingerprint() -> SemanticFingerprint {
        SemanticFingerprint {
            algorithm: FingerprintAlgorithm::V1TreeSitter,
            ast_hash: Hash256::from_bytes([0; 32]),
            signature_hash: Hash256::from_bytes([0; 32]),
            behavior_hash: Hash256::from_bytes([0; 32]),
            equivalence_hash: Hash256::from_bytes([0; 32]),
            stability_score: 1.0,
        }
    }

    /// A locally defined entity: the kind a question usually names.
    fn local(name: &str, file: &str) -> Entity {
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::JavaScript,
            fingerprint: fingerprint(),
            file_origin: Some(FilePathId::new(file)),
            span: None,
            signature: format!("function {name}()"),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    /// An external reference target of the shape the linker builds, for the
    /// fixtures that need many of them. The linker-driven store below is what
    /// proves this shape is the real one.
    fn external_target(symbol: &str) -> Entity {
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Module,
            name: symbol.to_string(),
            language: LanguageId::JavaScript,
            fingerprint: fingerprint(),
            file_origin: None,
            span: None,
            signature: String::new(),
            visibility: Visibility::Public,
            role: EntityRole::External,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    /// The express file that requires the router package, as the parser hands it
    /// to the linker: one local function, and one `Calls` site naming `Router`
    /// out of the module `router`, which no file in this repository provides.
    fn express_files() -> Vec<FileParseData> {
        vec![FileParseData {
            file_path: "lib/application.js".to_string(),
            entities: vec![local("app.handle", "lib/application.js")],
            relations: vec![ExtractedRelation {
                kind: RelationKind::Calls,
                src_name: "app.handle".to_string(),
                dst_name: "Router".to_string(),
                import_source: Some("router".to_string()),
                call_shape: None,
                receiver: None,
                site: None,
            }],
            imports: Vec::new(),
        }]
    }

    /// The store the express question was asked against, built by running the
    /// real linker rather than by hand.
    ///
    /// This is the control that makes the rest of this module mean anything. The
    /// observation keys on an external reference target and on the
    /// `import_source` of the edge reaching it, and a fixture asserting those by
    /// hand would go on passing after the linker stopped producing them. Here
    /// the linker produces the edges, `placeholder_target_entity` produces the
    /// targets they point at, and the assertions below would fail if either
    /// shape changed.
    fn linked_express_store() -> InMemoryGraph {
        let files = express_files();
        let artifact_ids = ArtifactIdentityMap::from([
            ("lib/application.js".to_string(), ArtifactId::new()),
            ("lib/response.js".to_string(), ArtifactId::new()),
        ]);
        let relations = kin_index::link_cross_file(&files, &artifact_ids)
            .expect("the linker resolves these two files");

        let graph = InMemoryGraph::new();
        let mut targets = 0;
        for relation in &relations {
            if !kin_index::is_external_import_placeholder(relation) {
                continue;
            }
            let target = kin_index::placeholder_target_entity(relation, LanguageId::JavaScript)
                .expect("a placeholder relation names the target it stands for");
            assert!(
                kin_index::is_external_reference_target(&target),
                "the linker's own target is what this module scans for"
            );
            assert_eq!(
                target.kind,
                EntityKind::Module,
                "and the kind the fast path narrows on is the kind the linker uses"
            );
            graph.upsert_entity(&target).expect("target admits");
            targets += 1;
        }
        assert_eq!(targets, 1, "the fixture's one unadmitted import");

        for file in &files {
            for entity in &file.entities {
                graph.upsert_entity(entity).expect("local entity admits");
            }
        }
        for relation in &relations {
            let _ = graph.upsert_relation(relation);
        }
        graph
    }

    /// The reported shape. The question names `router`, the graph resolved
    /// `Router` to a definition it does not hold, and the response says so with
    /// the module named.
    #[test]
    fn a_question_naming_an_unadmitted_package_is_disclosed_with_the_module() {
        let graph = linked_express_store();
        let block = observe_for_question(
            &graph,
            "where router.param callbacks are registered and stored, and how a request is \
             dispatched through the middleware stack",
        )
        .expect("the question names a symbol this graph holds no definition for");

        assert_eq!(block["scan"], serde_json::json!("complete"));
        assert_eq!(block["asked_about"], serde_json::json!(["router"]));
        assert_eq!(
            block["symbols"],
            serde_json::json!([{ "symbol": "Router", "modules": ["router"] }]),
            "the specifier the importing file named is what a reader acts on: {block}"
        );
        let clause = limiting_clause(&block).expect("a published block carries its clause");
        assert!(
            clause.starts_with("dependency_outside_graph:"),
            "the clause carries its own label: {clause}"
        );
        assert!(
            clause.contains("`Router` from `router`"),
            "and names the module rather than counting: {clause}"
        );
    }

    /// A question that spells the symbol the way the code does matches too. The
    /// express question happened to spell the package lowercase, which is the
    /// case the graph does NOT record: the binding is `Router`.
    #[test]
    fn a_question_naming_the_symbol_in_its_own_case_is_disclosed() {
        let graph = linked_express_store();
        let block = observe_for_question(&graph, "how does Router dispatch a request")
            .expect("`Router` is the name the graph holds for the unadmitted symbol");
        assert_eq!(
            block["symbols"],
            serde_json::json!([{ "symbol": "Router", "modules": ["router"] }]),
            "matching must not depend on which case the asker used: {block}"
        );
    }

    /// The control the review found missing, and the one that decides whether
    /// this is usable at all.
    ///
    /// `send` is BOTH an unadmitted import and a function this repository
    /// defines. A question about it is answerable from the graph, so refusing
    /// there would put a floor under every question about a common word. On the
    /// real express tree the same collision holds for `path`, `resolve`, `parse`
    /// and `http`.
    #[test]
    fn a_question_naming_a_symbol_this_repository_also_defines_discloses_nothing() {
        // Built rather than linked, and the reason is itself the point. The
        // linker binds a call by name when this repository defines that name, so
        // it never emits a placeholder for one; the collision reaches a real
        // graph because the two sides are spelled differently. Express imports
        // `send` from the unadmitted `send` package and defines the method a
        // reader means by it as `res.send`, so both entities exist and the
        // question's token matches both. The target's shape is the one the
        // linker control above verified.
        let graph = linked_express_store();
        graph
            .upsert_entity(&external_target("send"))
            .expect("the unadmitted import admits");
        graph
            .upsert_entity(&local("res.send", "lib/response.js"))
            .expect("the local definition admits");

        assert!(
            observe(&graph, "where does res.send set the content length")
                .symbols
                .is_empty(),
            "`res.send` is defined in this repository, so this question is answerable from it"
        );
        assert!(
            observe_for_question(&graph, "where does res.send set the content length").is_none(),
            "and nothing is published, so the answer stays certifiable"
        );

        // The control on the control: the same store, the same shape, a symbol
        // this repository does NOT define, and the disclosure still fires.
        assert!(
            observe_for_question(&graph, "where does Router dispatch a request").is_some(),
            "suppressing a locally defined name must not suppress everything else"
        );
    }

    /// The other control. A question about code this repository owns, on a store
    /// that does hold unadmitted packages, discloses nothing.
    #[test]
    fn a_question_about_local_code_discloses_nothing() {
        let graph = linked_express_store();
        assert!(
            observe_for_question(&graph, "where does app.handle prepare the response").is_none(),
            "the unadmitted `router` package exists in this store, and this question does not \
             name it, so there is nothing to disclose"
        );
    }

    /// A question naming nothing at all is not a question, and the observation
    /// never reaches the graph for one.
    #[test]
    fn an_empty_question_reads_no_graph() {
        let graph = linked_express_store();
        assert!(observe_for_question(&graph, "   ").is_none());
        assert_eq!(observe(&graph, "").targets_examined, 0);
    }

    /// A dotted path names each of its segments, because the package is the
    /// first one and a caller writes `router.param`, not `router`.
    #[test]
    fn a_dotted_question_names_each_of_its_segments() {
        let tokens = question_tokens("router.param and Router#handle");
        assert!(tokens.contains("router"));
        assert!(tokens.contains("param"));
        assert!(tokens.contains("handle"));
    }

    /// The question is read from whichever argument the tool carries it in.
    /// `get_context_pack` takes `question`; the rest take `query`.
    #[test]
    fn the_question_is_read_from_either_argument_name() {
        let mut arguments = std::collections::HashMap::new();
        assert_eq!(question_argument(&arguments), None);
        arguments.insert("question".to_string(), json!("where is Router"));
        assert_eq!(question_argument(&arguments), Some("where is Router"));
        arguments.insert("query".to_string(), json!("  "));
        assert_eq!(
            question_argument(&arguments),
            Some("where is Router"),
            "a blank `query` is not a question, so the other name still answers"
        );
        arguments.insert("query".to_string(), json!(" where is param "));
        assert_eq!(
            question_argument(&arguments),
            Some("where is param"),
            "`query` leads when both carry one, and both are trimmed"
        );
    }

    // ── The boundary cases: a scan that did not finish, and a store that could
    // ── not answer. Neither is reachable through a real graph, which is why the
    // ── read surface is its own trait.

    /// A store holding more external targets than the budget examines, with the
    /// asked-for symbol deliberately outside the examined prefix.
    struct OverBudgetStore {
        page: Vec<Entity>,
        total: usize,
    }

    impl OutsideGraphReads for OverBudgetStore {
        fn page(&self, _filter: &EntityFilter, page: &EntityPage) -> Option<EntityPageResult> {
            let mut entities = self.page.clone();
            entities.truncate(page.limit);
            Some(EntityPageResult {
                entities,
                total_matching: self.total,
                next_offset: Some(page.limit),
            })
        }
        fn named(&self, _name: &str) -> Option<Vec<Entity>> {
            Some(Vec::new())
        }
        fn relations(&self, _id: &EntityId) -> Option<Vec<Relation>> {
            Some(Vec::new())
        }
    }

    /// A bounded scan that did not finish may not be read as an answer.
    ///
    /// The cap is reasonable; discarding its evidence is not. A question naming
    /// the 513th target with no match in the examined prefix produced no block
    /// at all before this, the verdict read that absence as silence, and a
    /// certified answer stayed certified over an observation that never
    /// completed. That is the false certification this module exists to stop,
    /// rebuilt one level down at its own boundary.
    #[test]
    fn a_scan_that_hit_its_budget_says_so_even_with_nothing_matched() {
        let store = OverBudgetStore {
            // 512 targets none of which the question names, and one more the
            // store counts but never hands over.
            page: (0..TARGET_BUDGET)
                .map(|index| external_target(&format!("unrelated_{index}")))
                .collect(),
            total: TARGET_BUDGET + 1,
        };
        let observed = observe(&store, "where does Router dispatch a request");
        assert!(
            observed.symbols.is_empty(),
            "the fixture's point is that nothing matched in the examined prefix"
        );
        assert_eq!(observed.scan, ScanState::BudgetExhausted);
        assert!(
            observed.is_reportable(),
            "an incomplete scan has something to say even with no match"
        );

        let block = block(&observed).expect("an incomplete scan publishes its reason");
        assert_eq!(block["scan"], json!("budget_exhausted"));
        assert_eq!(block["targets_examined"], json!(TARGET_BUDGET));
        assert_eq!(block["targets_matching"], json!(TARGET_BUDGET + 1));
        let clause = limiting_clause(&block).expect("and the verdict gets a reason to refuse on");
        assert!(
            clause.starts_with("dependency_scan_incomplete:"),
            "the clause names the boundary rather than a symbol: {clause}"
        );
        assert!(
            clause.contains("512 of this repository's 513"),
            "and says how much of the scan ran: {clause}"
        );
    }

    /// A store that cannot answer the query at all.
    struct UnreadableStore;

    impl OutsideGraphReads for UnreadableStore {
        fn page(&self, _filter: &EntityFilter, _page: &EntityPage) -> Option<EntityPageResult> {
            None
        }
        fn named(&self, _name: &str) -> Option<Vec<Entity>> {
            None
        }
        fn relations(&self, _id: &EntityId) -> Option<Vec<Relation>> {
            None
        }
    }

    /// A read that did not run is not a read that found nothing.
    #[test]
    fn a_store_that_could_not_be_asked_is_reported_rather_than_read_as_clean() {
        let observed = observe(&UnreadableStore, "where does Router dispatch a request");
        assert_eq!(observed.scan, ScanState::ReadFailed);
        assert!(observed.is_reportable());
        let block = block(&observed).expect("a failed read publishes its reason");
        assert_eq!(block["scan"], json!("read_failed"));
        let clause = limiting_clause(&block).expect("and the verdict refuses on it");
        assert!(
            clause.starts_with("dependency_scan_unavailable:"),
            "the clause names what could not be done: {clause}"
        );
    }

    /// A store whose kind index cannot serve `Module`: the narrow query answers
    /// nothing, the role query answers everything.
    struct NoKindIndexStore {
        targets: Vec<Entity>,
    }

    impl OutsideGraphReads for NoKindIndexStore {
        fn page(&self, filter: &EntityFilter, page: &EntityPage) -> Option<EntityPageResult> {
            if filter.kinds.is_some() {
                return Some(EntityPageResult {
                    entities: Vec::new(),
                    total_matching: 0,
                    next_offset: None,
                });
            }
            let mut entities = self.targets.clone();
            entities.truncate(page.limit);
            Some(EntityPageResult {
                total_matching: self.targets.len(),
                entities,
                next_offset: None,
            })
        }
        fn named(&self, _name: &str) -> Option<Vec<Entity>> {
            Some(Vec::new())
        }
        fn relations(&self, _id: &EntityId) -> Option<Vec<Relation>> {
            Some(Vec::new())
        }
    }

    /// The kind narrowing is a cost optimisation and is not trusted as an
    /// answer.
    ///
    /// A store whose kind index cannot serve `Module` returns nothing to the
    /// narrow query, and nothing is indistinguishable from a repository that
    /// imports nothing: exactly the false "you are fine" this module exists to
    /// stop. So an empty narrow answer is re-asked by role alone.
    #[test]
    fn an_empty_kind_narrowed_answer_is_re_asked_by_role() {
        let store = NoKindIndexStore {
            targets: vec![external_target("Router")],
        };
        let observed = observe(&store, "where does Router dispatch a request");
        assert_eq!(
            observed.symbols.len(),
            1,
            "the role query found what the kind index could not serve"
        );
        assert_eq!(observed.symbols[0].symbol, "Router");
        assert!(
            observed.symbols[0].modules.is_empty(),
            "this fixture records no import edge, and the block says so rather than inventing one"
        );
        let clause = limiting_clause(&block(&observed).expect("a match publishes"))
            .expect("a matched symbol carries a clause");
        assert!(
            clause.contains("`Router` (no module recorded)"),
            "an unsourced symbol is reported as one: {clause}"
        );
    }
}
