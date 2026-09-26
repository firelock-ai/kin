// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Symbols outside the repository, as the text commands render them.
//!
//! A call a language server proved into a package the repository depends on
//! is an edge to an external symbol node, addressed `external_reference:<uuid>`.
//! The MCP tools serve such a call as a row that
//! [`kin_mcp::handlers::external_symbols`] builds, and the text commands render
//! that same row here instead of deriving their own, so `kin refs`, `kin
//! context` and `kin trace` say what `find_references`, `get_context_pack` and
//! `trace_data_flow` say about one call.
//!
//! A site is printed as `+N`, N lines below the first line of the entity that
//! makes the call, the offset a numbered body shows. Nothing here prints a
//! path, a URI or a line for the external declaration, because the graph
//! records none, and nothing here reads a file: the text at a site is cut from
//! the caller's own body through the body reader the command already holds.

use std::cell::RefCell;
use std::collections::HashMap;

use anyhow::Result;
use kin_mcp::handlers::external_symbols::{self as mcp, ExternalSymbolNode, SiteText};
use kin_model::{Entity, EntityId, GraphStore, SourceSpan};

/// The note an answer carries once when it prints a site, so `+2` is never
/// read as a file line.
pub const SITE_OFFSET_NOTE: &str = "note: a site is +N, N lines below the first line of the \
     entity that makes the call, the offset a numbered body shows. A symbol outside this \
     repository has no location in the graph, so none is printed for it.";

/// The longest text quoted at one site.
const CALLEE_TEXT_MAX_CHARS: usize = 60;

/// The external symbol a command argument names, or `None` when it names none.
///
/// The lookup `get_entity` and `find_references` answer with: an
/// `external_reference:<uuid>` address, or a bare uuid no entity carries.
pub fn lookup<G: GraphStore>(graph: &G, text: &str) -> Result<Option<ExternalSymbolNode>> {
    mcp::lookup_external_symbol(graph, text)
        .map_err(|error| anyhow::anyhow!("read external symbol '{}': {error}", text.trim()))
}

/// Whether the argument is spelled as an external symbol's address, whether
/// or not this graph holds one under it.
pub fn is_address(text: &str) -> bool {
    mcp::is_external_address(text)
}

/// `Array.map (external symbol, npm typescript 5.6.3, standard library)`, read
/// off a row [`mcp::external_symbol_json`] built.
pub fn symbol_label(symbol: &serde_json::Value) -> String {
    let name = symbol["name"]
        .as_str()
        .filter(|name| !name.is_empty())
        .or_else(|| symbol["symbol"].as_str())
        .unwrap_or("?");
    let mut facts = vec!["external symbol".to_string()];
    let package: Vec<&str> = ["manager", "name", "version"]
        .iter()
        .filter_map(|key| symbol["package"][*key].as_str())
        .collect();
    if !package.is_empty() {
        facts.push(package.join(" "));
    }
    if symbol["stdlib"].as_bool() == Some(true) {
        facts.push("standard library".to_string());
    }
    format!("{name} ({})", facts.join(", "))
}

/// [`symbol_label`] for a symbol an argument named.
pub fn node_label(node: &ExternalSymbolNode) -> String {
    symbol_label(&mcp::external_symbol_json(&node.id, Some(&node.reference)))
}

/// What proved one edge: `proven_external by lsp:tsserver 5.6.3
/// (lsp_definition)`, read off the `site_state` and `proof` of a row.
pub fn proof_label(row: &serde_json::Value) -> String {
    let mut label = if row["site_state"].as_str() == Some(mcp::PROVEN_EXTERNAL) {
        mcp::PROVEN_EXTERNAL.to_string()
    } else {
        format!(
            "not proven by a language server ({})",
            row["resolution"].as_str().unwrap_or("unresolved")
        )
    };
    let proof = &row["proof"];
    match proof["resolver"].as_str() {
        Some(resolver) => {
            label.push_str(&format!(" by {resolver}"));
            if let Some(version) = proof["resolver_version"].as_str() {
                label.push_str(&format!(" {version}"));
            }
            if let Some(rule) = proof["rule"].as_str() {
                label.push_str(&format!(" ({rule})"));
            }
        }
        None if proof.is_null() => label.push_str(", no proof context recorded"),
        None => label.push_str(&format!(
            ", proof context {} not held in this graph",
            proof["context"].as_str().unwrap_or("?")
        )),
    }
    label
}

/// `sites +2 `map`, +5 `map``: each site of a row, addressed inside the caller,
/// with the text at it when the caller's body was read.
pub fn sites_label(sites: &serde_json::Value) -> String {
    let Some(sites) = sites.as_array().filter(|sites| !sites.is_empty()) else {
        return "sites none recorded".to_string();
    };
    let rendered: Vec<String> = sites
        .iter()
        .map(|site| {
            let offset = match site["line_in_entity"].as_u64() {
                Some(line) => format!("+{line}"),
                None => "+? (outside the caller)".to_string(),
            };
            match site["callee"].as_str().map(callee_text) {
                Some(text) if !text.is_empty() => format!("{offset} `{text}`"),
                _ => offset,
            }
        })
        .collect();
    format!("sites {}", rendered.join(", "))
}

/// The first line of the text at a site, trimmed and bounded, so one quote
/// cannot run a row across the screen.
fn callee_text(text: &str) -> String {
    let line = text.lines().next().unwrap_or("").trim();
    if line.chars().count() <= CALLEE_TEXT_MAX_CHARS {
        return line.to_string();
    }
    let mut cut: String = line.chars().take(CALLEE_TEXT_MAX_CHARS).collect();
    cut.push_str("...");
    cut
}

/// One call an entity makes to a symbol outside the repository, as one line:
/// `[Calls ->] Array.map (external symbol, npm typescript 5.6.3, standard
/// library) proven_external by lsp:tsserver 5.6.3 (lsp_definition), sites +2
/// `map`, +5 `map`, id external_reference:<uuid>`.
///
/// `row` is a row [`mcp::external_call_row`] built, the one `get_entity` and
/// `get_context_pack` serve under `external_calls`.
pub fn call_line(row: &serde_json::Value) -> String {
    format!(
        "[{} ->] {} {}, {}, id {}",
        row["relation_kind"].as_str().unwrap_or("Calls"),
        symbol_label(row),
        proof_label(row),
        sites_label(&row["sites"]),
        row["id"].as_str().unwrap_or("?"),
    )
}

/// [`call_line`] for a trace, where the call is a leaf: the symbol has no body
/// or edges of its own in this graph, so nothing past it can be followed.
pub fn leaf_line(row: &serde_json::Value) -> String {
    format!("{}, leaf", call_line(row))
}

/// What a command that answers about entities says when it is handed a symbol
/// outside the repository: what the argument names, why the command has
/// nothing to build from it, and the command that does answer about it.
///
/// `why` finishes the first sentence after "so": "`kin context` has no body
/// or neighborhood of its own here to build a pack around".
pub fn refusal_lines(node: &ExternalSymbolNode, why: &str) -> Vec<String> {
    let address = node.address();
    vec![
        format!(
            "{address} names {}, declared outside this repository, so {why}.",
            node_label(node)
        ),
        format!(
            "hint: `kin refs {address}` lists the entities in this repository that call it, \
             with each call's sites and proof, and `kin context <caller>` lists a caller's \
             calls into it."
        ),
    ]
}

/// An argument a command that answers about repository entities cannot take.
pub enum ExternalArgument {
    /// It names a symbol outside the repository that this graph holds.
    Symbol(Vec<String>),
    /// It is spelled as one, and this graph holds no symbol under it.
    UnknownAddress(Vec<String>),
}

impl ExternalArgument {
    /// Whether the argument named nothing at all, which a command reports as
    /// an absence; a symbol that exists is the wrong kind of argument instead.
    pub fn is_absent(&self) -> bool {
        matches!(self, Self::UnknownAddress(_))
    }

    /// The refusal, ready to print.
    pub fn into_lines(self) -> Vec<String> {
        match self {
            Self::Symbol(lines) | Self::UnknownAddress(lines) => lines,
        }
    }
}

/// Whether an argument is a symbol outside the repository, or spelled as one,
/// with the refusal [`refusal_lines`] or [`unknown_address_lines`] words for it.
/// `None` for any other argument, which the command resolves as it always did.
pub fn external_argument<G: GraphStore>(
    graph: &G,
    text: &str,
    why: &str,
) -> Result<Option<ExternalArgument>> {
    if let Some(node) = lookup(graph, text)? {
        return Ok(Some(ExternalArgument::Symbol(refusal_lines(&node, why))));
    }
    if is_address(text) {
        return Ok(Some(ExternalArgument::UnknownAddress(
            unknown_address_lines(text),
        )));
    }
    Ok(None)
}

/// [`external_argument`], as the lines a command refuses with.
pub fn entity_argument_refusal<G: GraphStore>(
    graph: &G,
    text: &str,
    why: &str,
) -> Result<Option<Vec<String>>> {
    Ok(external_argument(graph, text, why)?.map(ExternalArgument::into_lines))
}

/// What a command says for an `external_reference:` address this graph holds
/// no symbol under. Kept apart from an entity miss, whose hints (a name search,
/// `kin xref`) cannot find an external symbol.
pub fn unknown_address_lines(text: &str) -> Vec<String> {
    vec![
        format!(
            "{} names no symbol outside the repository that this repository's graph holds.",
            text.trim()
        ),
        "hint: an external_reference id is per store. Read it again from a current answer \
         against this repository: `kin context <caller>` or `kin trace <caller>` lists a \
         caller's external calls with their ids."
            .to_string(),
    ]
}

/// The text at a caller's sites, cut from the caller's own body as `read`
/// returns it, each caller read at most once and no more than
/// [`mcp::CALLEE_TEXT_READS_MAX`] callers per answer.
///
/// `read` returns the exact bytes of the caller's span, starting at its first
/// byte, or `None` when it cannot. It is the body reader the command already
/// holds, so a site is quoted from the same authority the command reads bodies
/// from, and never from a file.
pub struct BodySiteText<F> {
    read: RefCell<F>,
    bodies: RefCell<HashMap<EntityId, Option<String>>>,
}

impl<F: FnMut(&Entity) -> Option<String>> BodySiteText<F> {
    pub fn new(read: F) -> Self {
        Self {
            read: RefCell::new(read),
            bodies: RefCell::new(HashMap::new()),
        }
    }
}

impl<F: FnMut(&Entity) -> Option<String>> SiteText for BodySiteText<F> {
    fn quote(
        &self,
        caller: &Entity,
        site: &SourceSpan,
    ) -> std::result::Result<String, &'static str> {
        let Some(span) = caller.span.as_ref() else {
            return Err("caller_has_no_span");
        };
        if site.file != span.file
            || site.start_byte < span.start_byte
            || site.end_byte > span.end_byte
            || site.end_byte < site.start_byte
        {
            return Err("site_outside_caller");
        }
        let mut bodies = self.bodies.borrow_mut();
        if !bodies.contains_key(&caller.id) {
            if bodies.len() >= mcp::CALLEE_TEXT_READS_MAX {
                return Err("callee_text_read_limit");
            }
            let body = (self.read.borrow_mut())(caller);
            bodies.insert(caller.id, body);
        }
        match &bodies[&caller.id] {
            Some(body) => mcp::quote_site(caller, site, body, span.start_byte),
            None => Err("caller_source_unavailable"),
        }
    }
}

/// A small store holding one proven call into a symbol outside the repository,
/// shared by the command tests.
///
/// `render` calls `Array.map` from TypeScript's own library at two sites, two
/// and five lines below its first line, under a tsserver proof context, and
/// calls `helper` inside the repository as well.
#[cfg(test)]
pub(crate) mod fixture {
    use kin_db::InMemoryGraph;
    use kin_model::{
        Entity, EntityId, EntityKind, EntityMetadata, EntityRole, EntityStore, ExternalReference,
        ExternalReferenceDelta, ExternalSymbol, FilePathId, FingerprintAlgorithm, GraphNodeId,
        Hash256, LanguageId, ProofContext, Relation, RelationDelta, RelationEvidence, RelationId,
        RelationKind, RelationOrigin, ResolutionRecord, ResolutionRecordDelta, ScipDescriptor,
        ScipPackage, SemanticFingerprint, SourceSpan, TransactionDelta, Visibility,
    };

    pub(crate) const APP_TS: &str = "src/app.ts";
    /// Where `render`'s span starts in its file.
    const RENDER_START_BYTE: usize = 100;
    const RENDER_START_LINE: u32 = 10;
    const RENDER_LEN: usize = 200;
    /// The two sites, as (lines below the first, bytes into the body).
    pub(crate) const SITES: [(u32, usize); 2] = [(2, 30), (5, 80)];

    pub(crate) struct ExternalStore {
        pub(crate) graph: InMemoryGraph,
        pub(crate) caller: Entity,
        pub(crate) helper: Entity,
        pub(crate) node: ExternalReference,
    }

    impl ExternalStore {
        pub(crate) fn address(&self) -> String {
            format!("external_reference:{}", self.node.id)
        }
    }

    fn entity(name: &str, start_line: u32, start_byte: usize, with_origin: bool) -> Entity {
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::TypeScript,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0; 32]),
                signature_hash: Hash256::from_bytes([0; 32]),
                behavior_hash: Hash256::from_bytes([0; 32]),
                equivalence_hash: Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: with_origin.then(|| FilePathId::new(APP_TS)),
            span: Some(SourceSpan {
                file: FilePathId::new(APP_TS),
                start_byte,
                end_byte: start_byte + RENDER_LEN,
                start_line,
                start_col: 0,
                end_line: start_line + 8,
                end_col: 1,
            }),
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

    pub(crate) fn array_map() -> ExternalSymbol {
        ExternalSymbol::new(
            ScipPackage::new("npm", "typescript", "5.6.3").unwrap(),
            vec![
                ScipDescriptor::namespace("lib.es5.d.ts"),
                ScipDescriptor::type_("Array"),
                ScipDescriptor::method("map"),
            ],
        )
        .unwrap()
    }

    pub(crate) fn tsserver() -> ResolutionRecord {
        ResolutionRecord::ProofContext(ProofContext {
            language: LanguageId::TypeScript,
            resolver: "lsp:tsserver".to_string(),
            resolver_version: "5.6.3".to_string(),
            configuration_hash: Hash256::from_bytes([1; 32]),
            environment_hash: Hash256::from_bytes([2; 32]),
            environment_summary: "typescript 5.6.3".to_string(),
        })
    }

    /// The store. `with_origin` gives the entities a file origin, which a
    /// command that reads source through repository authority would try to
    /// read; without one they keep only their spans.
    pub(crate) fn external_store(with_origin: bool) -> ExternalStore {
        store(with_origin, true)
    }

    /// The store without the call to `helper`, so every call `render` makes
    /// leaves the repository.
    pub(crate) fn external_only_store(with_origin: bool) -> ExternalStore {
        store(with_origin, false)
    }

    fn store(with_origin: bool, calls_helper: bool) -> ExternalStore {
        let graph = InMemoryGraph::new();
        let caller = entity("render", RENDER_START_LINE, RENDER_START_BYTE, with_origin);
        let helper = entity("helper", 40, 900, with_origin);
        graph.upsert_entity(&caller).unwrap();
        graph.upsert_entity(&helper).unwrap();
        if calls_helper {
            graph
                .upsert_relation(&Relation {
                    id: RelationId::new(),
                    kind: RelationKind::Calls,
                    src: GraphNodeId::Entity(caller.id),
                    dst: GraphNodeId::Entity(helper.id),
                    confidence: 1.0,
                    origin: RelationOrigin::Parsed,
                    created_in: None,
                    import_source: None,
                    evidence: Vec::new(),
                })
                .unwrap();
        }

        let node = array_map().to_reference().unwrap();
        let context = tsserver();
        let token = context.id().context_token();
        let src = GraphNodeId::Entity(caller.id);
        let dst = GraphNodeId::ExternalReference(node.id);
        let span = caller.span.clone().unwrap();
        let evidence = SITES
            .iter()
            .map(|(line, byte)| RelationEvidence {
                source_span: Some(SourceSpan {
                    file: span.file.clone(),
                    start_byte: span.start_byte + byte,
                    end_byte: span.start_byte + byte + 3,
                    start_line: span.start_line + line,
                    start_col: 4,
                    end_line: span.start_line + line,
                    end_col: 7,
                }),
                parser_rule: Some("lsp_definition".to_string()),
                token: Some(token.clone()),
                occurrence_count: 1,
                ..RelationEvidence::default()
            })
            .collect();
        let call = Relation {
            id: RelationId::resolver(RelationKind::Calls, &src, &dst),
            kind: RelationKind::Calls,
            src,
            dst,
            confidence: 1.0,
            origin: RelationOrigin::Lsp,
            created_in: None,
            import_source: None,
            evidence,
        };
        graph
            .apply_transaction_delta(&TransactionDelta {
                relation_deltas: vec![RelationDelta::Added { new: call }],
                external_reference_deltas: vec![ExternalReferenceDelta::Added {
                    new: node.clone(),
                }],
                resolution_record_deltas: vec![ResolutionRecordDelta::Added { new: context }],
                ..TransactionDelta::default()
            })
            .unwrap();
        ExternalStore {
            graph,
            caller,
            helper,
            node,
        }
    }

    /// `render`'s body as its span would cut it, with `map` at both sites.
    pub(crate) fn render_body() -> String {
        let mut body = vec![b' '; RENDER_LEN];
        for (_, byte) in SITES {
            body[byte..byte + 3].copy_from_slice(b"map");
        }
        String::from_utf8(body).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_call_row_renders_as_one_line_with_its_symbol_proof_and_sites() {
        let store = fixture::external_store(false);
        let body = fixture::render_body();
        let text = BodySiteText::new(|caller: &Entity| {
            (caller.id == store.caller.id).then(|| body.clone())
        });
        let (rows, total) = mcp::external_call_rows(&store.graph, &store.caller, &text).unwrap();
        assert_eq!(total, 1);
        assert_eq!(
            call_line(&rows[0]),
            format!(
                "[Calls ->] Array.map (external symbol, npm typescript 5.6.3, standard library) \
                 proven_external by lsp:tsserver 5.6.3 (lsp_definition), sites +2 `map`, +5 \
                 `map`, id {}",
                store.address()
            )
        );

        // Without a body reader a site keeps its offset and quotes nothing.
        let none = BodySiteText::new(|_: &Entity| None);
        let (rows, _) = mcp::external_call_rows(&store.graph, &store.caller, &none).unwrap();
        assert!(
            call_line(&rows[0]).contains("sites +2, +5,"),
            "{}",
            call_line(&rows[0])
        );
    }

    #[test]
    fn an_edge_without_proof_says_so_rather_than_naming_a_resolver() {
        let row = serde_json::json!({
            "site_state": null,
            "resolution": "name_only",
            "proof": null,
        });
        assert_eq!(
            proof_label(&row),
            "not proven by a language server (name_only), no proof context recorded"
        );
    }

    #[test]
    fn a_long_callee_is_cut_to_one_bounded_line() {
        let long = format!("{}\nsecond line", "x".repeat(100));
        let cut = callee_text(&long);
        assert!(cut.ends_with("..."), "{cut}");
        assert_eq!(cut.chars().count(), CALLEE_TEXT_MAX_CHARS + 3);
    }
}
