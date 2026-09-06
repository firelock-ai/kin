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
//! ## Why the question has to name it
//!
//! Every repository with dependencies has unadmitted modules, so an observation
//! that fired whenever one EXISTS would refuse every answer, and a verdict that
//! cannot say yes is worth no more than one that cannot say no. The trigger is
//! therefore an identifier the QUESTION names that this graph resolved to a
//! definition it does not hold: on the express question, the token `router`
//! against the external target `Router`; on a question about code this
//! repository owns, nothing, and the block is absent.
//!
//! ## Published shape
//!
//! ```json
//! "outside_graph": {
//!   "asked_about": ["router"],
//!   "symbols": [{ "symbol": "Router", "modules": ["router"] }],
//!   "targets_examined": 19,
//!   "budget_exhausted": false
//! }
//! ```
//!
//! [`crate::verdict`] consumes it as an input: present means inconclusive with
//! the module named in the limiting factor, and
//! [`crate::verdict::Verdict::project_onto_completeness`] takes `complete` and
//! `exact` off the same response. Absent says nothing either way, because the
//! observation is taken only where a question exists to take it against.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{json, Value};

use kin_model::entity::EntityRole;
use kin_model::graph::{EntityFilter, EntityStore};

/// Reserved, additive payload key carrying the unadmitted-dependency
/// observation. Read by [`crate::verdict`].
pub const OUTSIDE_GRAPH_KEY: &str = "outside_graph";

/// The most external reference targets one observation examines.
///
/// The scan is over external targets alone, which is a small set even on a large
/// repository (nineteen on express), and the cap is here so that "small in
/// practice" is not the only thing bounding it. A store holding more publishes
/// `budget_exhausted: true`, which is an honest "there may be more" rather than
/// a claim that the rest are absent.
const TARGET_BUDGET: usize = 512;

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
#[derive(Debug, Clone, Default)]
pub struct OutsideGraphObservation {
    /// The tokens of the question that matched, folded to lowercase.
    pub asked_about: BTreeSet<String>,
    /// The symbols they matched, each a definition this graph does not hold.
    pub symbols: Vec<OutsideSymbol>,
    /// How many external reference targets were examined.
    pub targets_examined: usize,
    /// Whether [`TARGET_BUDGET`] stopped the walk before it ran out of targets.
    pub budget_exhausted: bool,
}

impl OutsideGraphObservation {
    /// Whether the question named anything this graph cannot see into.
    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }
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
/// matched target, which is where the importing file recorded it. That lookup
/// runs only for a target the question already named, so a question about code
/// this repository owns costs one filtered entity query and no relation reads.
pub fn observe<S: EntityStore>(store: &S, question: &str) -> OutsideGraphObservation {
    let mut observed = OutsideGraphObservation::default();
    let tokens = question_tokens(question);
    if tokens.is_empty() {
        return observed;
    }
    let Ok(candidates) = store.query_entities(&EntityFilter {
        roles: Some(vec![EntityRole::External]),
        ..EntityFilter::default()
    }) else {
        return observed;
    };

    let mut by_symbol: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for entity in candidates {
        if !kin_index::is_external_reference_target(&entity) {
            continue;
        }
        if observed.targets_examined >= TARGET_BUDGET {
            observed.budget_exhausted = true;
            break;
        }
        observed.targets_examined += 1;

        let folded = entity.name.to_ascii_lowercase();
        if !tokens.contains(&folded) {
            continue;
        }
        observed.asked_about.insert(folded);
        let modules = by_symbol.entry(entity.name.clone()).or_default();
        if let Ok(relations) = store.get_all_relations_for_entity(&entity.id) {
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
    observed
}

/// The block to publish, or `None` when the question named nothing outside the
/// graph.
pub fn block(observed: &OutsideGraphObservation) -> Option<Value> {
    if observed.is_empty() {
        return None;
    }
    Some(json!({
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
        "budget_exhausted": observed.budget_exhausted,
    }))
}

/// Observe and render in one call, for a handler holding a store and a question.
pub fn observe_for_question<S: EntityStore>(store: &S, question: &str) -> Option<Value> {
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
/// missing or names nothing.
///
/// One sentence in the clause shape [`crate::verdict`] composes: a label, a
/// colon, and the fact a reader acts on. It names the module rather than
/// counting, because "one dependency is outside this graph" sends nobody
/// anywhere and "`router` is outside this graph" sends them to admit it.
pub fn limiting_clause(block: &Value) -> Option<String> {
    let named: Vec<String> = block
        .get("symbols")
        .and_then(Value::as_array)?
        .iter()
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
    if named.is_empty() {
        return None;
    }
    Some(format!(
        "dependency_outside_graph: this question names {}, which this repository imports and \
         this graph holds no definitions for, so the answer may live entirely outside what was \
         searched; admit the package or read it at its source",
        named.join(", ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_db::InMemoryGraph;
    use kin_index::linker::{ArtifactIdentityMap, FileParseData};
    use kin_model::entity::{
        Entity, EntityKind, EntityMetadata, FingerprintAlgorithm, SemanticFingerprint, Visibility,
    };
    use kin_model::ids::{EntityId, FilePathId, Hash256, LanguageId};
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

    /// The express file that requires the router package, as the parser hands it
    /// to the linker: one local function, and one `Calls` site naming `Router`
    /// out of the module `router`, which no file in this repository provides.
    fn express_application() -> FileParseData {
        FileParseData {
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
        }
    }

    /// The store the express question was asked against, built by running the
    /// real linker rather than by hand.
    ///
    /// This is the control that makes the rest of this module mean anything. The
    /// observation keys on an external reference target and on the
    /// `import_source` of the edge reaching it, and a fixture asserting those by
    /// hand would go on passing after the linker stopped producing them. Here
    /// the linker produces the edge, `placeholder_target_entity` produces the
    /// target it points at, and both assertions below would fail if either
    /// shape changed.
    fn linked_express_store() -> InMemoryGraph {
        let files = [express_application()];
        let artifact_ids =
            ArtifactIdentityMap::from([("lib/application.js".to_string(), ArtifactId::new())]);
        let relations = kin_index::link_cross_file(&files, &artifact_ids)
            .expect("the linker resolves this one file");

        let placeholder = relations
            .iter()
            .find(|relation| kin_index::is_external_import_placeholder(relation))
            .expect("a Calls site naming a module no file provides is an external placeholder");
        let target = kin_index::placeholder_target_entity(placeholder, LanguageId::JavaScript)
            .expect("a placeholder relation names the target it stands for");
        assert!(
            kin_index::is_external_reference_target(&target),
            "the linker's own target is what this module scans for"
        );
        assert_eq!(target.name, "Router");
        assert_eq!(placeholder.import_source.as_deref(), Some("router"));

        let graph = InMemoryGraph::new();
        for entity in &files[0].entities {
            graph.upsert_entity(entity).expect("local entity admits");
        }
        graph.upsert_entity(&target).expect("target admits");
        for relation in &relations {
            let _ = graph.upsert_relation(relation);
        }
        graph
    }

    /// FIR-3306. The question names `router`, the graph resolved `Router` to a
    /// definition it does not hold, and the response says so with the module
    /// named.
    #[test]
    fn a_question_naming_an_unadmitted_package_is_disclosed_with_the_module() {
        let graph = linked_express_store();
        let block = observe_for_question(
            &graph,
            "where router.param callbacks are registered and stored, and how a request is \
             dispatched through the middleware stack",
        )
        .expect("the question names a symbol this graph holds no definition for");

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

    /// The express question happened to spell the package in lowercase, which
    /// is the case the graph does NOT record: the binding is `Router`. A
    /// question that names it the way the code does has to match too, and this
    /// is the arm that proves the fold is load-bearing rather than incidental.
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

    /// The control. The same store, a question about code this repository owns,
    /// and no block at all. Without this the disclosure would fire on every
    /// answer from every repository that has dependencies, which is all of them,
    /// and a verdict that cannot say yes is worth no more than one that cannot
    /// say no.
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
        assert!(observe(&graph, "").targets_examined == 0);
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
}
