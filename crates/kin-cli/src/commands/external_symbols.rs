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

/// Why `kin work create`, `link` and `implement` refuse a scope naming a
/// symbol outside the repository, the clause after the command's name.
pub const WORK_SCOPE_WHY: &str = "links work to repository scopes and has nothing of it here \
     to link work to; link one of its callers instead";

/// Why `kin work list --scope` refuses one: no work can be linked to it, so the
/// filter could only answer empty, which reads as an absence it is not.
pub const WORK_LIST_WHY: &str = "filters work by the repository scopes it is linked to, and no \
     work can be linked to it; filter by one of its callers instead";

/// Why `kin note list` refuses one: `kin note add` refuses it, so no note is
/// anchored there to list.
pub const NOTE_LIST_WHY: &str = "lists notes anchored to repository entities, and none can be \
     anchored to it; list the notes on one of its callers instead";

/// Why `kin review note` and `kin review discuss` refuse one as their scope.
pub const REVIEW_SCOPE_WHY: &str = "anchors review notes and discussions to repository \
     entities and has nothing of it here to anchor one to; anchor it on one of its callers \
     instead";

/// Why `kin intent register` refuses one: an intent locks repository scopes.
pub const INTENT_WHY: &str = "declares intent on repository scopes and has nothing of it here \
     to lock; declare the intent on one of its callers instead";

/// Why `kin traffic show` refuses one: no intent can be declared on it, so a
/// report on it could only be empty, which reads as a clear path it is not.
pub const TRAFFIC_WHY: &str = "reports the intents declared on repository scopes, and none can \
     be declared on it; check one of its callers instead";

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

/// The spelling [`mcp::external_symbols_named`] matched a name by, in words.
fn matched_label(matched: &str) -> &'static str {
    match matched {
        mcp::MATCHED_SCIP_SYMBOL => "whole SCIP symbol",
        mcp::MATCHED_SCIP_DESCRIPTORS => "SCIP descriptor chain",
        _ => "name",
    }
}

/// The line an answer reached by a name leads with: the symbol outside the
/// repository the name named, and the spelling that matched it, which
/// `find_references` reports under `focal_resolution`.
pub fn named_line(name: &str, node: &ExternalSymbolNode, matched: &str) -> String {
    format!(
        "{} names no entity in this repository; it names {}, matched by its {}.",
        name.trim(),
        node_label(node),
        matched_label(matched)
    )
}

/// A name several symbols outside the repository carry and no entity does:
/// every candidate by its address, and no answer about any of them, as
/// `find_references` lists the same candidates.
pub fn name_candidate_lines(
    command: &str,
    name: &str,
    candidates: &[ExternalSymbolNode],
) -> Vec<String> {
    let listed = kin_mcp::handlers::entities::NAME_CANDIDATES_LISTED_MAX;
    let mut lines = vec![format!(
        "{} names {} symbols declared outside this repository, one per package or version \
         the resolver loaded, so {command} answered about none of them. Run it again with \
         one candidate's address:",
        name.trim(),
        candidates.len()
    )];
    lines.extend(
        candidates
            .iter()
            .take(listed)
            .map(|node| format!("  {}  {}", node.address(), node_label(node))),
    );
    if candidates.len() > listed {
        lines.push(format!("  ... and {} more", candidates.len() - listed));
    }
    lines
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
                // A site with no offset says why: the caller records no span
                // to count from, or the site lies outside it.
                None => match site["callee_unavailable"].as_str() {
                    Some("caller_has_no_span") => "+? (caller has no span)".to_string(),
                    _ => "+? (outside the caller)".to_string(),
                },
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
pub(crate) fn callee_text(text: &str) -> String {
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
    address_refusal_lines(&node.address(), &node_label(node), why)
}

/// [`refusal_lines`] from the symbol's address and its [`symbol_label`], for a
/// refusal a daemon route answered with rather than a symbol read here.
fn address_refusal_lines(address: &str, label: &str, why: &str) -> Vec<String> {
    vec![
        format!("{address} names {label}, declared outside this repository, so {why}."),
        format!(
            "hint: `kin refs {address}` lists the entities in this repository that call it, \
             with each call's sites and proof, and `kin context <caller>` lists a caller's \
             calls into it."
        ),
    ]
}

/// What a command that takes a work, review, annotation or intent scope says
/// when the scope names a symbol outside the repository: by its address, as
/// an `entity:` scope or by its bare id. `None` for every other scope, which
/// the command parses as it always did.
///
/// The check is the one the MCP tools ask, so a scope either surface refuses,
/// the other refuses too.
pub fn scope_argument_refusal<G: GraphStore>(
    graph: &G,
    scope: &str,
    why: &str,
) -> Result<Option<Vec<String>>> {
    use kin_mcp::handlers::common::{external_scope_target, UnanchoredTarget};
    let target = external_scope_target(graph, scope)
        .map_err(|error| anyhow::anyhow!("read external symbol '{}': {error}", scope.trim()))?;
    Ok(match target {
        Some(UnanchoredTarget::External(node)) => Some(refusal_lines(&node, why)),
        Some(UnanchoredTarget::UnknownExternalAddress(text)) => Some(unknown_address_lines(&text)),
        Some(UnanchoredTarget::NotInGraph(_)) | None => None,
    })
}

/// The lines a command prints for a daemon route that refused a scope naming
/// a symbol outside the repository, read from the route's error body: the
/// refusal the MCP tool gives, carrying `external_symbol_not_served` and the
/// symbol's record, or the absence of an address naming nothing held. `None`
/// for any other body, which the command reports as it always did.
pub fn relayed_refusal_lines(body: &str, why: &str) -> Option<Vec<String>> {
    let body = body.trim();
    if let Some(address) = body.strip_prefix(&format!("{}: ", mcp::EXTERNAL_SYMBOL_NOT_FOUND)) {
        return Some(unknown_address_lines(address));
    }
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    let error = &value["error"];
    if error["code"].as_str() != Some(mcp::EXTERNAL_SYMBOL_NOT_SERVED) {
        return None;
    }
    let address = error["id"].as_str()?;
    Some(address_refusal_lines(
        address,
        &symbol_label(&error["symbol"]),
        why,
    ))
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

    /// A daemon intent or traffic route refuses a scope naming a symbol
    /// outside the repository with the MCP tool's JSON. `kin intent register`
    /// and `kin traffic show` print it in the words every scope argument is
    /// refused with, and leave any other body to their usual report.
    #[test]
    fn a_relayed_scope_refusal_prints_as_the_commands_own() {
        let store = fixture::external_store(false);
        let address = store.address();
        let refusal = kin_mcp::handlers::external_symbols::external_scope_refusal(
            &store.graph,
            &serde_json::json!([address]),
            "kin_register_intent",
            "scopes",
        )
        .unwrap()
        .expect("a refusal");
        let why = format!("`kin intent register` {}", INTENT_WHY);
        let lines = relayed_refusal_lines(&refusal, &why).expect("rendered");
        assert_eq!(
            lines,
            refusal_lines(
                &lookup(&store.graph, &address).unwrap().expect("the symbol"),
                &why
            )
        );
        let unknown = "external_reference:00000000-0000-8000-8000-000000000000";
        assert_eq!(
            relayed_refusal_lines(&format!("External symbol not found: {unknown}"), &why),
            Some(unknown_address_lines(unknown))
        );
        assert_eq!(
            relayed_refusal_lines("unrecognized scope \"x\"", &why),
            None
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
