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
//! everything I have and the answer is elsewhere".
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
    /// Symbols the question named that come from an unadmitted module AND are
    /// defined in this repository. Reported so a reader can see the collision,
    /// and kept out of [`Self::symbols`] so the verdict does not refuse on a
    /// question the graph can answer.
    pub also_defined_locally: Vec<OutsideSymbol>,
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
            also_defined_locally: Vec::new(),
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
        !self.symbols.is_empty()
            || !self.also_defined_locally.is_empty()
            || self.scan != ScanState::Complete
    }
}

/// The question this call asked, from whichever argument the tool carries it in.
pub fn question_argument(arguments: &std::collections::HashMap<String, Value>) -> Option<&str> {
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
pub fn observe<S: OutsideGraphReads + ?Sized>(
    store: &S,
    question: &str,
) -> OutsideGraphObservation {
    let mut observed = OutsideGraphObservation::default();
    let tokens = question_tokens(question);
    if tokens.is_empty() {
        return observed;
    }

    let Some(page) = external_targets(store) else {
        observed.scan = ScanState::ReadFailed;
        return observed;
    };
    observed.targets_matching = page.total;
    observed.targets_examined = page.examined_rows;
    if page.stopped_short {
        observed.scan = ScanState::BudgetExhausted;
    }

    let mut by_symbol: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let mut also_local: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for entity in page.entities {
        if !question_names(&tokens, question, &entity.name) {
            continue;
        }
        observed
            .asked_about
            .insert(entity.name.to_ascii_lowercase());
        // The second guard, and the second bucket rather than a silent drop. A
        // symbol this repository also defines is answerable from the graph
        // whatever else imports something by that name, so refusing there would
        // put a floor under every question about a common word: express binds
        // `send`, `path`, `resolve` and `parse` from unadmitted modules and
        // defines the methods a reader means by them in its own source. But
        // "answerable" is not "answered", and dropping the fact left a reader
        // with no way to learn that the name they asked about ALSO comes from a
        // package this graph cannot see. So it is reported under its own key,
        // which the verdict does not refuse on.
        let bucket = if defines_locally(store, &entity.name) {
            &mut also_local
        } else {
            &mut by_symbol
        };
        let modules = bucket.entry(entity.name.clone()).or_default();
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

    observed.symbols = by_symbol
        .into_iter()
        .map(|(symbol, modules)| OutsideSymbol { symbol, modules })
        .collect();
    observed.also_defined_locally = also_local
        .into_iter()
        .map(|(symbol, modules)| OutsideSymbol { symbol, modules })
        .collect();
    observed
}

/// Whether the question named this symbol in a way that means the symbol.
///
/// A bare lowercase token is not enough on its own, and the reason is a package
/// list rather than a principle: an unadmitted dependency named `error`,
/// `request`, `path` or `send` would otherwise match every question containing
/// that ordinary English word, and a disclosure that fires on the word "error"
/// is a floor under the whole surface.
///
/// Two forms qualify, and both mean the asker was naming an identifier rather
/// than using a word. The question wrote it qualified, with a dot on either side
/// (`router.param`, `express.Router`), which is what a caller describing an API
/// does. Or the question spelled it exactly as the graph records it AND that
/// spelling is not a bare lowercase word: `Router` and `parse_url` are spellings
/// a caller only produces by naming the symbol, where `error` is a spelling
/// every English sentence produces by accident.
fn question_names(tokens: &BTreeSet<String>, question: &str, symbol: &str) -> bool {
    if !tokens.contains(&symbol.to_ascii_lowercase()) {
        return false;
    }
    let looks_like_an_identifier = symbol
        .chars()
        .any(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_');
    if looks_like_an_identifier && question.contains(symbol) {
        return true;
    }
    let folded = question.to_ascii_lowercase();
    let needle = symbol.to_ascii_lowercase();
    folded.match_indices(&needle).any(|(at, _)| {
        let before = folded[..at].chars().next_back();
        let after = folded[at + needle.len()..].chars().next();
        let bounded = |c: Option<char>| !c.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_');
        bounded(before) && bounded(after) && (before == Some('.') || after == Some('.'))
    })
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
fn external_targets<S: OutsideGraphReads + ?Sized>(store: &S) -> Option<ExternalTargets> {
    let narrow = paged(
        store,
        &EntityFilter {
            kinds: Some(vec![EntityKind::Module]),
            roles: Some(vec![EntityRole::External]),
            ..EntityFilter::default()
        },
    )?;
    if narrow.total > 0 {
        return Some(narrow);
    }
    paged(
        store,
        &EntityFilter {
            roles: Some(vec![EntityRole::External]),
            ..EntityFilter::default()
        },
    )
}

/// Every external reference target the filter matches, followed page by page up
/// to [`TARGET_BUDGET`].
///
/// One page was not paging. A repository with more external targets than one
/// page holds read `budget_exhausted` on every call forever, which is a
/// permanent floor under every question that store is ever asked, and the
/// budget is supposed to bound a scan rather than end it.
///
/// The budget counts EXTERNAL REFERENCE TARGETS, not rows. A row that is
/// `EntityRole::External` because it lives under `third_party/` owns its source
/// and is not what this scans for, so counting it would spend the budget on
/// entities the answer never considers.
fn paged<S: OutsideGraphReads + ?Sized>(
    store: &S,
    filter: &EntityFilter,
) -> Option<ExternalTargets> {
    let mut collected = ExternalTargets::default();
    let mut offset = 0usize;
    loop {
        let window = TARGET_BUDGET.saturating_sub(collected.entities.len());
        if window == 0 {
            collected.stopped_short = collected.examined_rows < collected.total;
            return Some(collected);
        }
        let page = store.page(filter, &EntityPage::new(offset, window))?;
        collected.total = page.total_matching;
        collected.examined_rows += page.entities.len();
        collected.entities.extend(
            page.entities
                .into_iter()
                .filter(kin_index::is_external_reference_target),
        );
        match page.next_offset {
            Some(next) if next > offset && collected.examined_rows < collected.total => {
                offset = next;
            }
            _ => {
                collected.stopped_short = collected.examined_rows < collected.total;
                return Some(collected);
            }
        }
    }
}

/// The external reference targets one scan collected, and whether it finished.
#[derive(Debug, Default)]
struct ExternalTargets {
    /// The targets themselves, at most [`TARGET_BUDGET`] of them.
    entities: Vec<Entity>,
    /// Rows the store handed over, including ones that were not targets.
    examined_rows: usize,
    /// How many rows the filter matched in total.
    total: usize,
    /// Whether the budget stopped the walk with rows left unread.
    stopped_short: bool,
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
                !kin_index::is_external_reference_target(entity)
                    && names_the_same(&entity.name, name)
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
        "also_defined_locally": observed
            .also_defined_locally
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
pub fn observe_for_question<S: OutsideGraphReads + ?Sized>(
    store: &S,
    question: &str,
) -> Option<Value> {
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

        let observed = observe(&graph, "where does res.send set the content length");
        assert!(
            observed.symbols.is_empty(),
            "`res.send` is defined in this repository, so this question is answerable from it"
        );
        assert_eq!(
            observed.also_defined_locally.len(),
            1,
            "and the collision is reported rather than dropped, so a reader can see that the \
             name also comes from a package this graph cannot look into"
        );
        assert_eq!(observed.also_defined_locally[0].symbol, "send");

        let block = block(&observed).expect("the collision is worth publishing");
        assert_eq!(
            block["symbols"],
            serde_json::json!([]),
            "nothing in the refusing bucket: {block}"
        );
        assert_eq!(
            block["also_defined_locally"][0]["symbol"],
            serde_json::json!("send")
        );
        assert!(
            limiting_clause(&block).is_none(),
            "and the verdict does not refuse on a question the graph can answer"
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
        rows: Vec<Entity>,
        /// The most rows one window may hold, so the walk has to follow
        /// `next_offset` to see them all rather than taking one page.
        window: usize,
    }

    impl OutsideGraphReads for OverBudgetStore {
        fn page(&self, _filter: &EntityFilter, page: &EntityPage) -> Option<EntityPageResult> {
            let start = page.offset.min(self.rows.len());
            let end = (start + page.limit.min(self.window)).min(self.rows.len());
            Some(EntityPageResult {
                entities: self.rows[start..end].to_vec(),
                total_matching: self.rows.len(),
                next_offset: (end < self.rows.len()).then_some(end),
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
        let mut rows: Vec<Entity> = (0..TARGET_BUDGET)
            .map(|index| external_target(&format!("Unrelated{index}")))
            .collect();
        // The symbol the question names sits one past the budget, so only a
        // walk that ran to the end would find it, and only a walk that reports
        // stopping early is honest about not having.
        rows.push(external_target("Router"));
        let store = OverBudgetStore { rows, window: 64 };
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
        assert_eq!(
            block["targets_examined"],
            json!(TARGET_BUDGET),
            "the walk followed its pages to the budget rather than stopping at the first \
             window, which a 64-row window makes visible: {block}"
        );
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

    /// The same store, one target fewer, so the whole set fits inside the
    /// budget: the walk must find a symbol that lives past the first window.
    ///
    /// Without following `next_offset` this comes back empty and complete,
    /// which is a certified answer over a scan that read an eighth of the
    /// targets.
    #[test]
    fn the_walk_follows_its_pages_to_find_a_target_past_the_first_window() {
        let mut rows: Vec<Entity> = (0..200)
            .map(|index| external_target(&format!("Unrelated{index}")))
            .collect();
        rows.push(external_target("Router"));
        let store = OverBudgetStore { rows, window: 64 };

        let observed = observe(&store, "where does Router dispatch a request");
        assert_eq!(observed.scan, ScanState::Complete, "the whole set fits");
        assert_eq!(observed.targets_examined, 201);
        assert_eq!(
            observed.symbols.len(),
            1,
            "the target sits at row 201 of a 64-row window, so only a walk that paged finds it"
        );
        assert_eq!(observed.symbols[0].symbol, "Router");
    }

    /// A question that merely contains an ordinary word does not refuse.
    ///
    /// An unadmitted dependency named `error`, `request` or `path` would
    /// otherwise match every question containing that English word, and a
    /// disclosure that fires on the word "error" is a floor under the whole
    /// surface. The symbol has to be named as an identifier: spelled the way the
    /// graph records it, or written qualified with a dot.
    #[test]
    fn an_ordinary_word_that_happens_to_name_a_package_does_not_refuse() {
        let store = OverBudgetStore {
            rows: vec![external_target("error")],
            window: 64,
        };
        assert!(
            observe(&store, "what happens on an error in the response path")
                .symbols
                .is_empty(),
            "a question using the word is not a question naming the symbol"
        );

        // The two forms that DO name it, without which the arm above would pass
        // on a rule that had stopped matching anything.
        assert_eq!(
            observe(&store, "who calls error.format").symbols.len(),
            1,
            "a qualified mention names the identifier"
        );
        let store = OverBudgetStore {
            rows: vec![external_target("Router")],
            window: 64,
        };
        assert_eq!(
            observe(&store, "where is Router built").symbols.len(),
            1,
            "and so does spelling it the way the graph records it"
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
