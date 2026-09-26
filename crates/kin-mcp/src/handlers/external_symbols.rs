// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Symbols outside the repository, as the read tools serve them.
//!
//! A call a language server resolved into a package the repository depends on
//! is an edge to an external symbol node: `Array.map` in TypeScript's own
//! library, `json.dumps` in Python's. The node is the whole of what the graph
//! knows about the declaration. It carries the package, the version the
//! resolver loaded and the SCIP descriptor chain, and never a path, a URI or a
//! line of the declaration, because none is recorded.
//!
//! Every tool that lists an entity's calls renders such an edge through this
//! module, so one call reads the same way wherever it appears:
//!
//! - the target: `kind: "external_symbol"`, `id: "external_reference:<uuid>"`,
//!   `name`, `package`, `stdlib` and `symbol`;
//! - the edge: `resolution`, `site_state: "proven_external"` and `proof`, the
//!   resolver and proof context the evidence names;
//! - its sites: `line_in_entity`, counted from 0 at the caller's first line as
//!   a numbered body counts its `+N` offsets, and `callee`, the text at the
//!   site, cut from the caller's own body.
//!
//! The id is the spelling [`GraphNodeId`]'s display emits, and every tool that
//! takes an id accepts it: `get_entity`, `find_references` and
//! `graph_neighborhood` answer for the symbol, `get_entity_source` refuses
//! with [`EXTERNAL_SYMBOL_NO_SOURCE`] rather than looking for its source
//! anywhere, and every other tool that answers about repository entities
//! refuses with [`EXTERNAL_SYMBOL_NOT_SERVED`], the symbol's record and the
//! three tools that do answer, never with a miss.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};

use kin_context::{ExternalEdge, ExternalEdgeProof, ExternalEdgeReader};
use kin_index::RelationResolution;
use kin_model::entity::{Entity, SourceSpan};
use kin_model::graph::GraphStore;
use kin_model::ids::EntityId;
use kin_model::relation::{GraphNodeId, RelationKind};
use kin_model::{ExternalReference, ExternalReferenceId, ExternalSymbol};

use super::common::{read_entity_source_exact, HeldSourceAuthority, LAST_READ_SOURCE};
use crate::error::{McpError, Result};
use crate::types::ToolCallResult;

/// The `kind` every external symbol row carries.
pub const EXTERNAL_SYMBOL_KIND: &str = "external_symbol";

/// The `site_state` of a call a language server proved into an external
/// symbol, spelled as the call-site ledger spells the same state.
pub const PROVEN_EXTERNAL: &str = "proven_external";

/// The error code `get_entity_source` refuses an external symbol with.
pub const EXTERNAL_SYMBOL_NO_SOURCE: &str = "external_symbol_has_no_repository_source";

/// The error code every other tool that answers about repository entities
/// refuses an external symbol with: the id names a symbol the graph holds,
/// and this tool has nothing of the symbol's own here to answer from.
pub const EXTERNAL_SYMBOL_NOT_SERVED: &str = "external_symbol_not_served";

/// The tools that do answer about an external symbol, in the order a refusal
/// names them.
pub const EXTERNAL_SYMBOL_SERVED_BY: [&str; 3] =
    ["get_entity", "find_references", "graph_neighborhood"];

/// The error code an annotation refuses an entity id with when this graph
/// holds no entity and no external symbol under it.
pub const ENTITY_NOT_IN_GRAPH: &str = "entity_not_in_graph";

/// The group an entity's external calls are served under.
pub const EXTERNAL_CALLS_KEY: &str = "external_calls";

/// External call rows one list serves before it says how many it withheld.
pub const EXTERNAL_CALLS_MAX: usize = 50;

/// Callers whose bodies one answer reads to quote the text at their sites.
/// Past it a site keeps its `line_in_entity` and says why its `callee` is null.
pub const CALLEE_TEXT_READS_MAX: usize = 50;

/// The largest caller body read to quote a site.
const CALLER_BODY_MAX_BYTES: usize = 1_000_000;

/// The prefix of an external symbol's address.
const ADDRESS_PREFIX: &str = "external_reference:";

/// An external symbol's address, the spelling [`GraphNodeId`] displays.
pub fn external_address(id: &ExternalReferenceId) -> String {
    GraphNodeId::ExternalReference(*id).to_string()
}

/// Whether `text` is spelled as an external symbol's address.
pub fn is_external_address(text: &str) -> bool {
    text.trim().starts_with(ADDRESS_PREFIX)
}

/// An external symbol an id argument named, with its record.
#[derive(Debug, Clone)]
pub struct ExternalSymbolNode {
    pub id: ExternalReferenceId,
    pub reference: ExternalReference,
}

impl ExternalSymbolNode {
    pub fn address(&self) -> String {
        external_address(&self.id)
    }

    pub fn symbol(&self) -> Option<ExternalSymbol> {
        ExternalSymbol::from_reference(&self.reference)
    }

    /// `Array.map` for a SCIP symbol, the recorded selector otherwise.
    pub fn display_name(&self) -> String {
        match self.symbol() {
            Some(symbol) => symbol.display_name(),
            None => self.reference.symbol.clone(),
        }
    }

    /// `npm typescript 5.6.3`, or `None` outside the SCIP namespace.
    fn package_label(&self) -> Option<String> {
        self.symbol().map(|symbol| symbol.package.encode())
    }
}

/// The external symbol an id argument names, or `None` when it names none.
///
/// `external_reference:<uuid>` names the symbol with that identity. A bare
/// uuid names an entity first, and the external symbol with that identity only
/// when no entity has it, so the uuid inside an edge's typed end resolves too.
/// A string that is neither, or an address this graph holds no symbol under,
/// is `None`, and the caller reports its own miss.
pub fn lookup_external_symbol<G: GraphStore>(
    store: &G,
    text: &str,
) -> Result<Option<ExternalSymbolNode>> {
    let trimmed = text.trim();
    let uuid = match trimmed.strip_prefix(ADDRESS_PREFIX) {
        Some(rest) => match uuid::Uuid::parse_str(rest.trim()) {
            Ok(uuid) => uuid,
            Err(_) => return Ok(None),
        },
        None => match uuid::Uuid::parse_str(trimmed) {
            Ok(uuid) => {
                if store
                    .get_entity(&EntityId(uuid))
                    .map_err(McpError::graph)?
                    .is_some()
                {
                    return Ok(None);
                }
                uuid
            }
            Err(_) => return Ok(None),
        },
    };
    let id = ExternalReferenceId(uuid);
    Ok(store
        .lookup_external_reference(&id)
        .map_err(McpError::graph)?
        .map(|reference| ExternalSymbolNode { id, reference }))
}

/// The target fields of an external symbol row.
pub fn external_symbol_json(
    id: &ExternalReferenceId,
    reference: Option<&ExternalReference>,
) -> serde_json::Value {
    let symbol = reference.and_then(ExternalSymbol::from_reference);
    let (name, package, stdlib, selector) = match (&symbol, reference) {
        (Some(symbol), _) => (
            symbol.display_name(),
            serde_json::json!({
                "manager": symbol.package.manager,
                "name": symbol.package.name,
                "version": symbol.package.version,
            }),
            symbol.is_stdlib(),
            symbol.encode_descriptors(),
        ),
        // A namespace other than SCIP's owns the meaning of its selector, so
        // it is served as recorded and nothing is read into it.
        (None, Some(reference)) => (
            reference.symbol.clone(),
            serde_json::Value::Null,
            false,
            reference.symbol.clone(),
        ),
        (None, None) => (String::new(), serde_json::Value::Null, false, String::new()),
    };
    serde_json::json!({
        "kind": EXTERNAL_SYMBOL_KIND,
        "id": external_address(id),
        "name": name,
        "package": package,
        "stdlib": stdlib,
        "symbol": selector,
    })
}

/// Distinct repository entities with an edge of `kind` into the symbol.
fn distinct_entities(edges: &[ExternalEdge], kind: Option<RelationKind>) -> usize {
    edges
        .iter()
        .filter(|edge| kind.is_none_or(|kind| edge.relation.kind == kind))
        .map(|edge| edge.entity)
        .collect::<HashSet<_>>()
        .len()
}

/// What `get_entity` answers for an external symbol: the symbol record, how
/// many entities call it, and how many reach it by any edge.
pub fn external_symbol_record_json<G: GraphStore>(
    store: &G,
    node: &ExternalSymbolNode,
) -> Result<serde_json::Value> {
    let edges = ExternalEdgeReader::new(store)
        .incoming(&node.id, EXTERNAL_EDGE_KINDS)
        .map_err(McpError::from)?;
    let mut value = external_symbol_json(&node.id, Some(&node.reference));
    value["caller_count"] = serde_json::json!(distinct_entities(&edges, Some(RelationKind::Calls)));
    value["referrer_count"] = serde_json::json!(distinct_entities(&edges, None));
    Ok(value)
}

/// The refusal `get_entity_source` answers an external symbol with, as the
/// JSON text of the error.
///
/// Shared with the daemon's source route, which carries it as the message of
/// a source outcome, so both routes refuse with the same bytes.
pub fn external_source_refusal_text(node: &ExternalSymbolNode) -> String {
    let package = node
        .package_label()
        .map(|package| format!(" in {package}"))
        .unwrap_or_default();
    serde_json::json!({"error": {
        "code": EXTERNAL_SYMBOL_NO_SOURCE,
        "id": node.address(),
        "message": format!(
            "{}{package} is declared outside this repository, so the graph holds its \
             identity and its callers here but no source to return; read a caller with \
             get_entity_source or list them with find_references.",
            node.display_name()
        ),
    }})
    .to_string()
}

/// [`external_source_refusal_text`] as a tool error.
pub fn external_source_refusal(node: &ExternalSymbolNode) -> ToolCallResult {
    ToolCallResult::error(external_source_refusal_text(node))
}

/// The code and sentence of a refusal [`external_source_refusal_text`] wrote,
/// or `None` for any other message.
pub fn external_source_refusal_parts(message: &str) -> Option<(String, String)> {
    let value: serde_json::Value = serde_json::from_str(message).ok()?;
    let error = value.get("error")?;
    let code = error.get("code")?.as_str()?;
    if code != EXTERNAL_SYMBOL_NO_SOURCE {
        return None;
    }
    Some((
        code.to_string(),
        error.get("message")?.as_str()?.to_string(),
    ))
}

/// The sentence a tool refuses an external symbol with: what the id names,
/// why `tool` has nothing of it here to answer from, and the tools that do
/// answer about it.
///
/// `why` finishes the clause after the tool's name: "has no revisions of it
/// here to list". Nothing in the sentence reads as a miss, because the graph
/// holds the symbol.
pub fn external_not_served_message(node: &ExternalSymbolNode, tool: &str, why: &str) -> String {
    let package = node
        .package_label()
        .map(|package| format!(" in {package}"))
        .unwrap_or_default();
    format!(
        "{} names {}{package}, a symbol declared outside this repository, so {tool} {why}. \
         get_entity returns its record, and find_references and graph_neighborhood list the \
         entities in this repository that call it.",
        node.address(),
        node.display_name()
    )
}

/// The refusal every tool that answers about repository entities gives an
/// external symbol, as JSON: [`EXTERNAL_SYMBOL_NOT_SERVED`], the tool and the
/// argument that named the symbol, the symbol's record with its caller counts
/// as `get_entity` serves it, and the tools that answer about it.
pub fn external_not_served_json<G: GraphStore>(
    store: &G,
    node: &ExternalSymbolNode,
    tool: &str,
    argument: &str,
    why: &str,
) -> Result<serde_json::Value> {
    Ok(serde_json::json!({"error": {
        "code": EXTERNAL_SYMBOL_NOT_SERVED,
        "tool": tool,
        "argument": argument,
        "id": node.address(),
        "message": external_not_served_message(node, tool, why),
        "symbol": external_symbol_record_json(store, node)?,
        "served_by": EXTERNAL_SYMBOL_SERVED_BY,
    }}))
}

/// [`external_not_served_json`] as the text of an error, the bytes every
/// route that serves `tool` refuses with.
pub fn external_not_served_text<G: GraphStore>(
    store: &G,
    node: &ExternalSymbolNode,
    tool: &str,
    argument: &str,
    why: &str,
) -> Result<String> {
    Ok(external_not_served_json(store, node, tool, argument, why)?.to_string())
}

/// [`external_not_served_json`] as a tool error.
pub fn external_not_served<G: GraphStore>(
    store: &G,
    node: &ExternalSymbolNode,
    tool: &str,
    argument: &str,
    why: &str,
) -> Result<ToolCallResult> {
    Ok(ToolCallResult::error(external_not_served_text(
        store, node, tool, argument, why,
    )?))
}

/// What a tool answers for an `external_reference:` address this graph holds
/// no symbol under: the absence `get_entity` reports, never an invalid id.
pub fn external_symbol_not_found(text: &str) -> ToolCallResult {
    ToolCallResult::error(format!("External symbol not found: {}", text.trim()))
}

/// The answer a tool that answers about repository entities gives an id
/// argument naming an external symbol, or spelled as one's address, and
/// `None` for any other id, which the tool resolves as it always did.
pub fn external_id_refusal<G: GraphStore>(
    store: &G,
    text: &str,
    tool: &str,
    argument: &str,
    why: &str,
) -> Result<Option<ToolCallResult>> {
    if let Some(node) = lookup_external_symbol(store, text)? {
        return external_not_served(store, &node, tool, argument, why).map(Some);
    }
    if is_external_address(text) {
        return Ok(Some(external_symbol_not_found(text)));
    }
    Ok(None)
}

/// [`external_id_refusal`] for the first of several ids that names an
/// external symbol or is spelled as one's address. A call naming one is
/// refused whole, so no answer about the rest reads as covering it.
pub fn external_ids_refusal<G: GraphStore>(
    store: &G,
    ids: &[String],
    tool: &str,
    argument: &str,
    why: &str,
) -> Result<Option<ToolCallResult>> {
    for id in ids {
        if let Some(refusal) = external_id_refusal(store, id, tool, argument, why)? {
            return Ok(Some(refusal));
        }
    }
    Ok(None)
}

/// Where the text at a caller's sites comes from.
///
/// The text is always the caller's own, read from its graph-owned body: the
/// external declaration has no body in this graph to read.
pub trait SiteText {
    /// The text at `site` inside `caller`, or why it cannot be quoted.
    fn quote(
        &self,
        caller: &Entity,
        site: &SourceSpan,
    ) -> std::result::Result<String, &'static str>;
}

/// The text at `site`, cut from `body`, the caller's body starting at file
/// byte `body_start`, or why it cannot be.
pub fn quote_site(
    caller: &Entity,
    site: &SourceSpan,
    body: &str,
    body_start: usize,
) -> std::result::Result<String, &'static str> {
    let Some(span) = caller.span.as_ref() else {
        return Err("caller_has_no_span");
    };
    if site.file != span.file || site.start_byte < body_start || site.end_byte < site.start_byte {
        return Err("site_outside_caller");
    }
    body.get(site.start_byte - body_start..site.end_byte - body_start)
        .map(str::to_string)
        .ok_or("site_outside_caller")
}

/// The text at a caller's sites, read from the caller's graph-owned body, each
/// caller's body once and no more than [`CALLEE_TEXT_READS_MAX`] of them.
pub struct CalleeText<'held, 'store, G: GraphStore> {
    held: &'held HeldSourceAuthority<'store, G>,
    bodies: RefCell<HashMap<EntityId, std::result::Result<String, &'static str>>>,
}

impl<'held, 'store, G: GraphStore> CalleeText<'held, 'store, G> {
    pub fn new(held: &'held HeldSourceAuthority<'store, G>) -> Self {
        Self {
            held,
            bodies: RefCell::new(HashMap::new()),
        }
    }
}

impl<G: GraphStore> SiteText for CalleeText<'_, '_, G> {
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
            if bodies.len() >= CALLEE_TEXT_READS_MAX {
                return Err("callee_text_read_limit");
            }
            // The body read reports what it read through a thread-local the
            // surrounding answer may already have taken for its own body, so
            // it is put back as this read found it.
            let prior = LAST_READ_SOURCE.with(|cell| cell.get());
            let body = match read_entity_source_exact(self.held, caller, CALLER_BODY_MAX_BYTES) {
                Ok(Some(source)) => Ok(source.body),
                Ok(None) | Err(_) => Err("caller_source_unavailable"),
            };
            LAST_READ_SOURCE.with(|cell| cell.set(prior));
            bodies.insert(caller.id, body);
        }
        match &bodies[&caller.id] {
            Ok(body) => quote_site(caller, site, body, span.start_byte),
            Err(reason) => Err(reason),
        }
    }
}

/// One site of an external edge, addressed inside `caller` and never by a
/// file line.
fn site_json<T: SiteText + ?Sized>(
    caller: &Entity,
    site: &SourceSpan,
    text: &T,
) -> serde_json::Value {
    let line_in_entity = caller
        .span
        .as_ref()
        .filter(|span| span.file == site.file)
        .and_then(|span| site.start_line.checked_sub(span.start_line));
    let mut value = serde_json::json!({ "line_in_entity": line_in_entity });
    match text.quote(caller, site) {
        Ok(callee) => value["callee"] = serde_json::json!(callee),
        Err(reason) => {
            value["callee"] = serde_json::Value::Null;
            value["callee_unavailable"] = serde_json::json!(reason);
        }
    }
    value
}

/// The resolver and proof context an edge's evidence names.
pub fn proof_json(proof: Option<&ExternalEdgeProof>) -> serde_json::Value {
    let Some(proof) = proof else {
        return serde_json::Value::Null;
    };
    serde_json::json!({
        "resolver": proof.record.as_ref().map(|record| record.resolver.clone()),
        "resolver_version": proof.record.as_ref().map(|record| record.resolver_version.clone()),
        "context": proof.context.0.to_string(),
        "rule": proof.rule,
    })
}

/// The fields every row about one external edge carries: how it was resolved,
/// its site state, its proof and its sites inside `caller`.
pub fn external_edge_fields<T: SiteText + ?Sized>(
    edge: &ExternalEdge,
    caller: Option<&Entity>,
    text: &T,
) -> serde_json::Map<String, serde_json::Value> {
    let sites: Vec<serde_json::Value> = match caller {
        Some(caller) => edge
            .sites()
            .into_iter()
            .map(|site| site_json(caller, site, text))
            .collect(),
        None => Vec::new(),
    };
    let mut fields = serde_json::Map::new();
    fields.insert(
        "resolution".into(),
        serde_json::json!(RelationResolution::of(&edge.relation).as_str()),
    );
    fields.insert(
        "site_state".into(),
        if edge.is_proven() {
            serde_json::json!(PROVEN_EXTERNAL)
        } else {
            serde_json::Value::Null
        },
    );
    fields.insert("proof".into(), proof_json(edge.proof.as_ref()));
    fields.insert("sites".into(), serde_json::Value::Array(sites));
    fields
}

/// One row of an entity's calls whose target is outside the repository.
pub fn external_call_row<T: SiteText + ?Sized>(
    edge: &ExternalEdge,
    caller: &Entity,
    text: &T,
) -> serde_json::Value {
    let mut row = external_symbol_json(&edge.target, edge.reference.as_ref());
    let object = row.as_object_mut().expect("symbol object");
    object.insert(
        "relation_kind".into(),
        serde_json::json!(format!("{:?}", edge.relation.kind)),
    );
    object.extend(external_edge_fields(edge, Some(caller), text));
    row
}

/// The calls `caller` makes to symbols outside the repository, as rows, at
/// most [`EXTERNAL_CALLS_MAX`] of them, and how many there were.
pub fn external_call_rows<G: GraphStore, T: SiteText + ?Sized>(
    store: &G,
    caller: &Entity,
    text: &T,
) -> Result<(Vec<serde_json::Value>, usize)> {
    let edges = kin_context::focal_external_calls(store, &caller.id).map_err(McpError::from)?;
    let total = edges.len();
    let rows = edges
        .iter()
        .take(EXTERNAL_CALLS_MAX)
        .map(|edge| external_call_row(edge, caller, text))
        .collect();
    Ok((rows, total))
}

/// Every focal's calls into symbols outside the repository, each row naming
/// its focal in `caller_id`, at most [`EXTERNAL_CALLS_MAX`] rows in all, and
/// how many there were: [`external_call_rows`] for a pack built from several
/// focals.
pub fn focals_external_call_rows<G: GraphStore, T: SiteText + ?Sized>(
    store: &G,
    focals: &[Entity],
    text: &T,
) -> Result<(Vec<serde_json::Value>, usize)> {
    let mut rows = Vec::new();
    let mut total = 0usize;
    for focal in focals {
        let (focal_rows, focal_total) = external_call_rows(store, focal, text)?;
        total += focal_total;
        for mut row in focal_rows {
            if rows.len() >= EXTERNAL_CALLS_MAX {
                break;
            }
            row["caller_id"] = serde_json::json!(focal.id.to_string());
            rows.push(row);
        }
    }
    Ok((rows, total))
}

/// Attach `caller`'s external calls to an object answer under
/// [`EXTERNAL_CALLS_KEY`], only when it has any, with the count withheld when
/// the list was capped.
pub fn attach_external_calls<G: GraphStore, T: SiteText + ?Sized>(
    store: &G,
    caller: &Entity,
    text: &T,
    value: &mut serde_json::Value,
) -> Result<()> {
    let (rows, total) = external_call_rows(store, caller, text)?;
    if rows.is_empty() {
        return Ok(());
    }
    let kept = rows.len();
    value[EXTERNAL_CALLS_KEY] = serde_json::Value::Array(rows);
    if total > kept {
        value["external_calls_withheld"] = serde_json::json!(total - kept);
    }
    Ok(())
}

/// One `graph_neighborhood` edge row for an edge with an external end: the
/// keys every edge row carries, `to`, the far node's id, and the edge fields.
pub fn external_relation_row<T: SiteText + ?Sized>(
    edge: &ExternalEdge,
    direction: &str,
    from: String,
    to: String,
    caller: Option<&Entity>,
    text: &T,
) -> serde_json::Value {
    let mut row = serde_json::json!({
        "src": edge.relation.src,
        "dst": edge.relation.dst,
        "kind": format!("{:?}", edge.relation.kind),
        "direction": direction,
        "from": from,
        "to": to,
    });
    row.as_object_mut()
        .expect("edge object")
        .extend(external_edge_fields(edge, caller, text));
    row
}

/// Every relation kind an edge into an external symbol can carry, for the
/// walks that read all of them.
pub const EXTERNAL_EDGE_KINDS: &[RelationKind] = &[
    RelationKind::Calls,
    RelationKind::Imports,
    RelationKind::References,
    RelationKind::UsesType,
    RelationKind::UsesMacro,
    RelationKind::Instantiates,
    RelationKind::Implements,
    RelationKind::Extends,
    RelationKind::Overrides,
    RelationKind::DependsOn,
    RelationKind::Includes,
];

/// The `cross_repo` block of a reference answer about an external symbol.
///
/// The spine federates references to repository entities; a symbol outside
/// every repository is not one of its keys, so no cross-repo authority applies
/// and none is asked. The answer lists this repository's callers.
pub const CROSS_REPO_NOT_APPLICABLE: &str = "not_applicable";

/// `find_references` for an external symbol: one row per repository entity
/// with an edge into it, each carrying the edge's proof and its sites inside
/// the caller, in the counts and keys every reference answer carries.
pub fn external_references_reply<G: GraphStore>(
    store: &G,
    node: &ExternalSymbolNode,
    relation_kinds: &[RelationKind],
    include_snippets: bool,
    min_resolution: RelationResolution,
    repository_authority: Option<&super::repository_authority::RequestRepositoryAuthority>,
) -> Result<serde_json::Value> {
    let held = HeldSourceAuthority::new(store, repository_authority);
    let text = CalleeText::new(&held);
    let edges = ExternalEdgeReader::new(store)
        .incoming(&node.id, relation_kinds)
        .map_err(McpError::from)?;

    // One row per referencing entity, the unit every reference answer counts.
    let mut grouped: Vec<(EntityId, Vec<ExternalEdge>)> = Vec::new();
    for edge in edges {
        match grouped.last_mut() {
            Some((entity, held)) if *entity == edge.entity => held.push(edge),
            _ => grouped.push((edge.entity, vec![edge])),
        }
    }

    let mut rows: Vec<(
        String,
        String,
        String,
        serde_json::Value,
        RelationResolution,
        usize,
    )> = Vec::new();
    for (entity_id, edges) in grouped {
        let Some(caller) = store.get_entity(&entity_id).map_err(McpError::graph)? else {
            continue;
        };
        let resolution = edges
            .iter()
            .map(|edge| RelationResolution::of(&edge.relation))
            .max()
            .unwrap_or(RelationResolution::NameOnly);
        let mut kinds: Vec<&'static str> = edges
            .iter()
            .map(|edge| super::common::relation_kind_name(edge.relation.kind))
            .collect();
        kinds.sort_unstable();
        kinds.dedup();
        let proven = edges.iter().any(ExternalEdge::is_proven);
        let proof = edges.iter().find_map(|edge| edge.proof.as_ref());
        let mut spans: Vec<&SourceSpan> = edges.iter().flat_map(ExternalEdge::sites).collect();
        spans.sort_by_key(|span| (span.start_byte, span.end_byte));
        spans.dedup_by_key(|span| (span.start_byte, span.end_byte));
        let sites: Vec<serde_json::Value> = spans
            .into_iter()
            .map(|site| site_json(&caller, site, &text))
            .collect();
        let file_path = caller
            .file_origin
            .as_ref()
            .map(|path| path.to_string())
            .unwrap_or_default();
        let mut row = serde_json::json!({
            "entity_id": caller.id.to_string(),
            "name": caller.name,
            "kind": format!("{:?}", caller.kind),
            "role": caller.role,
            "file_path": caller.file_origin.as_ref().map(|path| path.to_string()),
            "start_line": super::common::entity_presentation_start_line(&caller),
            "relation_kinds": kinds,
            "resolution": resolution.as_str(),
            "site_state": if proven {
                serde_json::json!(PROVEN_EXTERNAL)
            } else {
                serde_json::Value::Null
            },
            "proof": proof_json(proof),
            "site_count": sites.len(),
            "sites": sites,
        });
        if include_snippets {
            row["signature"] = serde_json::json!(caller.signature);
        }
        let site_count = row["site_count"].as_u64().unwrap_or(0) as usize;
        rows.push((
            file_path,
            caller.name.clone(),
            caller.id.to_string(),
            row,
            resolution,
            site_count,
        ));
    }
    rows.sort_by(|left, right| {
        left.0
            .cmp(&right.0)
            .then_with(|| left.1.cmp(&right.1))
            .then_with(|| left.2.cmp(&right.2))
    });

    let mut references = Vec::new();
    let mut candidates = Vec::new();
    let mut files = HashSet::new();
    let mut reference_sites = 0usize;
    for (file_path, _, _, row, resolution, sites) in rows {
        if resolution < min_resolution {
            candidates.push(row);
            continue;
        }
        files.insert(file_path);
        reference_sites += sites;
        references.push(row);
    }
    let counts = serde_json::json!({
        "counted": "referencing_entities",
        "referencing_entities": references.len(),
        "files": files.len(),
        "reference_sites": reference_sites,
        "known_reference_sites": reference_sites,
        "reference_sites_complete": true,
        "receiver_name_candidates": 0,
        "unresolved_name_candidates": candidates.len(),
        "upstream_including_unconfirmed": references.len() + candidates.len(),
    });
    Ok(serde_json::json!({
        "focal_entity": external_symbol_json(&node.id, Some(&node.reference)),
        "relation_kinds": relation_kinds
            .iter()
            .copied()
            .map(super::common::relation_kind_name)
            .collect::<Vec<_>>(),
        "total_upstream": references.len(),
        "unconfirmed_candidates": candidates.len(),
        "counts": counts,
        "references": references,
        "candidates": candidates,
        "cross_repo": {
            "status": CROSS_REPO_NOT_APPLICABLE,
            "reason": "the focal is a symbol outside every repository, so this answer lists \
                       the callers this repository holds",
        },
        // An external symbol's identity is exact, so the id names one symbol
        // and there is no name ambiguity to report.
        "focal_resolution": {
            "addressed_by": "entity_id",
            "same_name_candidates": 1,
            "matched": EXTERNAL_SYMBOL_KIND,
            "other_candidates": [],
        },
        // Why the list is a floor. An edge into an external symbol exists only
        // where a language server proved the call, so a caller in a file no
        // resolver answered for is not here, and nothing measures how many.
        "degradations": [{
            "component": "external_callers",
            "reason": "proven_calls_only",
            "detail": "Only calls a language server proved into this symbol are recorded, \
                       so a caller in a file no resolver answered for is not listed and \
                       this list is a floor.",
        }],
    }))
}

/// The keys a `trace_data_flow` step carries about a symbol outside the
/// repository. Every other step carries them as null, so a chain keeps the one
/// key set its consumers parse.
pub const EXTERNAL_TRACE_KEYS: [&str; 6] = [
    "package",
    "stdlib",
    "symbol",
    "site_state",
    "proof",
    "sites",
];

/// Give a trace step every external key it does not carry, as null.
pub fn fill_external_trace_keys(step: &mut serde_json::Value) {
    if let Some(object) = step.as_object_mut() {
        for key in EXTERNAL_TRACE_KEYS {
            object
                .entry(key.to_string())
                .or_insert(serde_json::Value::Null);
        }
    }
}

/// The boundary a trace step on a symbol outside the repository sits on,
/// named by the package the resolver loaded.
pub fn external_crossing(edge: &ExternalEdge) -> kin_index::TraceCrossing {
    let specifier = edge.symbol().map(|symbol| symbol.package.name);
    kin_index::TraceCrossing {
        status: if specifier.is_some() {
            "named".to_string()
        } else {
            "unknown".to_string()
        },
        specifier,
        receiver: None,
        note: "A language server proved this call into a package outside the repository. The \
               graph holds the symbol's identity and no body, so the walk stops here."
            .to_string(),
    }
}

/// The entity keys and external keys of a trace step on a symbol outside the
/// repository: identity where an entity step has its own, null where the
/// repository holds nothing (file, lines, signature, body), and the proof and
/// sites of the call from `parent`.
pub fn external_trace_record<T: SiteText + ?Sized>(
    edge: &ExternalEdge,
    parent: Option<&Entity>,
    text: &T,
) -> serde_json::Map<String, serde_json::Value> {
    let target = external_symbol_json(&edge.target, edge.reference.as_ref());
    let mut record = serde_json::Map::new();
    record.insert("entity_id".into(), target["id"].clone());
    record.insert("entity_name".into(), target["name"].clone());
    record.insert(
        "entity_kind".into(),
        serde_json::json!(EXTERNAL_SYMBOL_KIND),
    );
    record.insert("entity_role".into(), serde_json::json!("external"));
    record.insert("entity_file".into(), serde_json::Value::Null);
    record.insert("external".into(), serde_json::json!(true));
    for key in [
        "start_line",
        "end_line",
        "signature",
        "body",
        "span_coherence",
    ] {
        record.insert(key.into(), serde_json::Value::Null);
    }
    record.insert(
        "crossing".into(),
        serde_json::to_value(external_crossing(edge)).unwrap_or(serde_json::Value::Null),
    );
    for key in ["package", "stdlib", "symbol"] {
        record.insert(key.into(), target[key].clone());
    }
    let mut fields = external_edge_fields(edge, parent, text);
    for key in ["site_state", "proof", "sites"] {
        record.insert(
            key.into(),
            fields.remove(key).unwrap_or(serde_json::Value::Null),
        );
    }
    record
}

/// The external calls a trace node offers as leaf steps: one edge per target,
/// the strongest by trace rank, of the kinds the walk admits, and how many
/// edges of those kinds the node held before `visited` removed any.
pub fn trace_external_callees<G: GraphStore>(
    reader: &mut ExternalEdgeReader<'_, G>,
    node: &EntityId,
    allowed: &HashSet<RelationKind>,
    visited: &HashSet<ExternalReferenceId>,
) -> Result<(Vec<ExternalEdge>, usize)> {
    let mut callees: Vec<ExternalEdge> = Vec::new();
    let mut admissible = 0usize;
    for edge in reader.outgoing(node, None).map_err(McpError::from)? {
        if !allowed.contains(&edge.relation.kind) {
            continue;
        }
        admissible += 1;
        if visited.contains(&edge.target) {
            continue;
        }
        match callees.iter_mut().find(|held| held.target == edge.target) {
            Some(held) => {
                if kin_ranking::entity_ranking::trace_relation_rank(edge.relation.kind)
                    > kin_ranking::entity_ranking::trace_relation_rank(held.relation.kind)
                {
                    *held = edge;
                }
            }
            None => callees.push(edge),
        }
    }
    Ok((callees, admissible))
}
