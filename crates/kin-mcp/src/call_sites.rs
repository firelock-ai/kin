// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Call sites, as every read tool serves them.
//!
//! A caller's call-site ledger holds one state for each call expression the
//! parser reads in its body. What a tool serves for a site is read through
//! [`kin_model::read_caller_sites`], the one reading every surface shares, and
//! added up with [`kin_model::CallSiteTally`]. This module is where the read
//! tools meet that reading:
//!
//! - [`GraphSiteFacts`] answers the reading's questions from a [`GraphStore`]:
//!   the ledger under [`ResolutionRecordId::call_sites`], the proof context
//!   each language's resolver runs under now, as the process that runs the
//!   resolvers published it with [`publish_current_proof_contexts`], and why
//!   no resolver can prove a language's sites, from whether that process
//!   switched enrichment off ([`publish_enrichment_switched_off`]) and the
//!   language-server readiness it probed
//!   ([`crate::edge_coverage::publish_language_server_readiness`]);
//! - [`focal_block`], [`callers_block`] and [`store_block`] build the one
//!   `call_sites` payload block, which carries the tally, the scope it was
//!   taken over and the verdict clauses it calls for, and for a single focal
//!   one row per site;
//! - [`text_lines`] renders that block for a terminal, so the CLI and the MCP
//!   tools say the same thing about one store.
//!
//! A site is addressed inside its caller: `line_in_entity`, counted from 0 at
//! the caller's first line, and `callee`, the text at the site cut from the
//! caller's own body through the caller-body reader the answer already holds.
//! Never a file line.

use std::collections::{BTreeMap, HashMap};

use kin_model::entity::{Entity, SourceSpan};
use kin_model::graph::GraphStore;
use kin_model::{
    read_caller_sites, site_state_reason, CallSite, CallSiteFacts, CallSiteLedger, CallSiteTally,
    CallerSites, EntityId, LanguageId, NoResolver, ResolutionRecordId, SiteStateKind,
};
use serde_json::{json, Value};

use crate::handlers::external_symbols::SiteText;

/// The key every payload carries the block under.
pub const CALL_SITES_KEY: &str = "call_sites";

/// Site rows one block serves before it says how many it withheld.
pub const CALL_SITE_ROWS_MAX: usize = 50;

/// Files with owed callers a store-wide block names before it says how many
/// more there are.
pub const OWED_FILES_MAX: usize = 20;

/// The scope of a block taken over one focal's own sites.
pub const FOCAL_SCOPE: &str = "the focal's own body";

/// The scope of a block taken over several focals' own sites.
pub const FOCALS_SCOPE: &str = "the focals' own bodies";

/// The scope of a block taken over the callers in the files that import the
/// focal's file.
pub const FAMILY_SCOPE: &str = "the files that import the focal's file";

/// The scope of a block taken over the whole store.
pub const STORE_SCOPE: &str = "the store";

// ── The proof contexts resolvers run under now ────────────────────────────

/// The proof context each language's resolver runs under now.
pub type ProofContexts = HashMap<LanguageId, ResolutionRecordId>;

static PUBLISHED_CONTEXTS: std::sync::RwLock<Option<ProofContexts>> = std::sync::RwLock::new(None);

/// Publish the proof context each language's resolver runs under now.
///
/// Published by the process that starts the resolvers, when one starts,
/// because knowing the context needs the resolver running and a query path
/// must not spawn one. A ledger proven under any other context reads as
/// stale. Until this is called every context is unknown, and unknown reads no
/// ledger as stale, which is the reading a process that never looked should
/// give. A language the map does not name is unknown in the same way.
pub fn publish_current_proof_contexts(contexts: HashMap<LanguageId, ResolutionRecordId>) {
    if let Ok(mut slot) = PUBLISHED_CONTEXTS.write() {
        *slot = Some(contexts);
    }
}

/// The proof contexts [`publish_current_proof_contexts`] last published, or
/// `None` when nothing has, which is not an empty map: it means nobody looked.
pub fn published_current_proof_contexts() -> Option<HashMap<LanguageId, ResolutionRecordId>> {
    PUBLISHED_CONTEXTS
        .read()
        .ok()
        .and_then(|contexts| contexts.clone())
}

/// The contexts a reader consults: a test's own, when it declared some, and
/// the published ones otherwise.
fn current_contexts() -> Option<ProofContexts> {
    #[cfg(test)]
    if let Some(contexts) = test_support::context_override() {
        return Some(contexts);
    }
    published_current_proof_contexts()
}

/// Lets a test state which proof context each language's resolver runs
/// under. Thread-local, so it holds for the test that set it whether the
/// suite runs threaded or one process per test.
#[cfg(test)]
pub(crate) mod test_support {
    use super::{LanguageId, ProofContexts, ResolutionRecordId};
    use std::cell::RefCell;

    thread_local! {
        static CONTEXTS: RefCell<Option<ProofContexts>> = const { RefCell::new(None) };
    }

    pub(crate) fn context_override() -> Option<ProofContexts> {
        CONTEXTS.with(|contexts| contexts.borrow().clone())
    }

    thread_local! {
        static SWITCHED_OFF: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
    }

    pub(crate) fn switched_off_override() -> Option<bool> {
        SWITCHED_OFF.with(std::cell::Cell::get)
    }

    /// Restores the previous answer on drop, including on unwind.
    pub(crate) struct SwitchedOffGuard(Option<bool>);

    impl Drop for SwitchedOffGuard {
        fn drop(&mut self) {
            SWITCHED_OFF.with(|slot| slot.set(self.0));
        }
    }

    /// Declare, for the rest of this scope, whether enrichment is switched
    /// off for the process serving the graph.
    #[must_use = "binding the guard is what keeps the declared answer in force"]
    pub(crate) fn scoped_enrichment_switched_off(switched_off: bool) -> SwitchedOffGuard {
        SwitchedOffGuard(SWITCHED_OFF.with(|slot| slot.replace(Some(switched_off))))
    }

    /// Restores the previous contexts on drop, including on unwind.
    pub(crate) struct ContextGuard(Option<ProofContexts>);

    impl Drop for ContextGuard {
        fn drop(&mut self) {
            CONTEXTS.with(|slot| *slot.borrow_mut() = self.0.take());
        }
    }

    /// Declare, for the rest of this scope, that each language's resolver
    /// runs under exactly the context paired with it.
    #[must_use = "binding the guard is what keeps the declared contexts in force"]
    pub(crate) fn scoped_proof_contexts(
        contexts: &[(LanguageId, ResolutionRecordId)],
    ) -> ContextGuard {
        ContextGuard(CONTEXTS.with(|slot| {
            slot.borrow_mut()
                .replace(contexts.iter().copied().collect())
        }))
    }
}

// ── Why no resolver can prove a language's call sites ─────────────────────

static ENRICHMENT_SWITCHED_OFF: std::sync::RwLock<Option<bool>> = std::sync::RwLock::new(None);

/// Publish whether language-server enrichment is switched off for the process
/// serving this graph.
///
/// Published by the process that decides it, when it decides it, because a
/// switched-off daemon publishes no language-server readiness: it never
/// looks. Until this is called it is unknown, and unknown claims nothing.
pub fn publish_enrichment_switched_off(switched_off: bool) {
    if let Ok(mut slot) = ENRICHMENT_SWITCHED_OFF.write() {
        *slot = Some(switched_off);
    }
}

/// Whether enrichment is switched off: a test's own answer, when it declared
/// one, and the published one otherwise.
fn enrichment_switched_off() -> Option<bool> {
    #[cfg(test)]
    if let Some(switched_off) = test_support::switched_off_override() {
        return Some(switched_off);
    }
    ENRICHMENT_SWITCHED_OFF.read().ok().and_then(|slot| *slot)
}

/// Why no resolver can prove `language`'s call sites, from what the process
/// running the resolvers published: enrichment switched off, then its probe
/// of the language's server. A server the probe found missing, or that
/// could not start, proves nothing until the host changes, and a language no
/// build of Kin enriches never has one. Nothing published, or a language the
/// probe did not report on, is unknown, and reads as owed.
pub fn no_resolver_for(
    switched_off: Option<bool>,
    readiness: Option<&kin_core::reference_coverage::LanguageServerReadinessMap>,
    language: LanguageId,
) -> Option<NoResolver> {
    use kin_core::reference_coverage::{LanguageServerReadiness, ENRICHABLE_LANGUAGES};
    if switched_off == Some(true) {
        return Some(NoResolver::EnrichmentOff);
    }
    match readiness?.get(&language) {
        Some(LanguageServerReadiness::Absent) => Some(NoResolver::NoLanguageServer),
        Some(LanguageServerReadiness::Unusable { reason }) => Some(NoResolver::ServerCannotStart {
            reason: reason.clone(),
        }),
        Some(LanguageServerReadiness::Usable) => None,
        None if !ENRICHABLE_LANGUAGES.contains(&language) => Some(NoResolver::NoLanguageServer),
        None => None,
    }
}

// ── The reading's facts, from a graph ─────────────────────────────────────

/// What the call-site reading learns about a caller, answered from a graph.
///
/// The ledger is the graph's record under [`ResolutionRecordId::call_sites`].
/// A record that could not be read counts as no ledger, which reads as owed
/// enrichment: an unreadable ledger never settles a site. Whether a caller's
/// derivation is owed is not something a graph read can prove cheaply, so it
/// answers `false` and the response's source-derivation observation
/// qualifies the answer instead.
pub struct GraphSiteFacts<'s, G: GraphStore + ?Sized> {
    store: &'s G,
    contexts: Option<ProofContexts>,
    switched_off: Option<bool>,
    readiness: Option<kin_core::reference_coverage::LanguageServerReadinessMap>,
}

impl<'s, G: GraphStore + ?Sized> GraphSiteFacts<'s, G> {
    /// Facts about `store`, under the proof contexts and resolver
    /// availability published now.
    pub fn new(store: &'s G) -> Self {
        Self {
            store,
            contexts: current_contexts(),
            switched_off: enrichment_switched_off(),
            readiness: crate::edge_coverage::published_language_server_readiness(),
        }
    }
}

impl<G: GraphStore + ?Sized> CallSiteFacts for GraphSiteFacts<'_, G> {
    fn ledger(&self, caller: EntityId) -> Option<CallSiteLedger> {
        self.store
            .lookup_resolution_record(&ResolutionRecordId::call_sites(caller))
            .ok()
            .flatten()
            .and_then(|record| record.as_call_sites().cloned())
    }

    fn current_context(&self, language: LanguageId) -> Option<ResolutionRecordId> {
        self.contexts.as_ref()?.get(&language).copied()
    }

    fn no_resolver(&self, language: LanguageId) -> Option<NoResolver> {
        no_resolver_for(self.switched_off, self.readiness.as_ref(), language)
    }
}

// ── The block ─────────────────────────────────────────────────────────────

/// The block for a tally taken over `scope`: the tally's own fields, the
/// scope, and the verdict clauses it calls for, which are empty exactly when
/// it is settled.
///
/// `by_state` names only the states some site in scope reads as, because
/// this block rides every pack under its token budget; a state it does not
/// name holds no site. The store-wide block lists every state in `shares`.
pub fn block_json(tally: &CallSiteTally, scope: &str) -> Value {
    let mut block = tally.to_json();
    if let Some(by_state) = block["by_state"].as_object_mut() {
        by_state.retain(|_, count| count.as_u64() != Some(0));
    }
    block["scope"] = json!(scope);
    block["clauses"] = json!(tally.clauses(scope));
    block
}

/// Where a site sits inside its caller: its line counted from 0 at the
/// caller's first line, and the text at the site, both cut from the caller's
/// own body through `text`.
fn site_address<T: SiteText + ?Sized>(
    caller: &Entity,
    site: &CallSite,
    text: &T,
) -> (Option<u64>, Result<String, &'static str>) {
    let Some(span) = caller.span.as_ref() else {
        return (None, Err("caller_has_no_span"));
    };
    let start = span.start_byte + site.offset as usize;
    let cut = |start_byte: usize, end_byte: usize| SourceSpan {
        file: span.file.clone(),
        start_byte,
        end_byte,
        start_line: 0,
        start_col: 0,
        end_line: 0,
        end_col: 0,
    };
    let callee = text.quote(caller, &cut(start, start + site.length as usize));
    let line = text
        .quote(caller, &cut(span.start_byte, start))
        .ok()
        .map(|before| before.matches('\n').count() as u64);
    (line, callee)
}

/// One site of a caller's ledger, as the block serves it.
fn site_row<T: SiteText + ?Sized>(
    caller: &Entity,
    reading: &CallerSites,
    site: &CallSite,
    text: &T,
) -> Value {
    let (line_in_entity, callee) = site_address(caller, site, text);
    let mut row = json!({
        "line_in_entity": line_in_entity,
        "callee": callee.as_ref().ok(),
        "state": reading.site_kind(site).wire(),
        "reason": site_state_reason(&site.state),
        "target": site.state.proven_node().map(|node| node.to_string()),
    });
    if let Err(reason) = callee {
        row["callee_unavailable"] = json!(reason);
    }
    if matches!(reading, CallerSites::Stale(_)) {
        row["recorded_state"] = json!(site.state.wire());
    }
    row
}

/// The block for one focal's own call sites, with a row for each site its
/// ledger holds, at most [`CALL_SITE_ROWS_MAX`] of them.
///
/// `reading` says what stands between the reader and the focal's ledger:
/// `current`, `owed_enrichment`, `owed_derivation`, `proof_context_stale` or
/// `no_sites` for a focal with no source text. An owed focal has no rows,
/// because how many sites it holds is not known.
pub fn focal_block<G: GraphStore + ?Sized, T: SiteText + ?Sized>(
    store: &G,
    focal: &Entity,
    text: &T,
) -> Value {
    let facts = GraphSiteFacts::new(store);
    let reading = read_caller_sites(&facts, focal);
    let mut tally = CallSiteTally::default();
    tally.add(&reading);
    let mut block = block_json(&tally, FOCAL_SCOPE);
    block["reading"] = json!(reading.wire());
    let sites = reading
        .ledger()
        .map(|ledger| ledger.sites.as_slice())
        .unwrap_or_default();
    let rows: Vec<Value> = sites
        .iter()
        .take(CALL_SITE_ROWS_MAX)
        .map(|site| site_row(focal, &reading, site, text))
        .collect();
    block["rows"] = Value::Array(rows);
    let withheld = sites.len().saturating_sub(CALL_SITE_ROWS_MAX);
    if withheld > 0 {
        block["rows_withheld"] = json!(withheld);
    }
    // The proof context a stale ledger was proven under, which is what a
    // reader asks after when told it is stale. A current one is the context
    // its resolver runs under now, and naming it adds nothing.
    if let CallerSites::Stale(ledger) = &reading {
        block["stale_context"] = json!(ledger.context.to_string());
    }
    block
}

/// Read every caller in `callers` into one tally.
pub fn tally_callers<'e, G: GraphStore + ?Sized>(
    store: &G,
    callers: impl IntoIterator<Item = &'e Entity>,
) -> CallSiteTally {
    let facts = GraphSiteFacts::new(store);
    let mut tally = CallSiteTally::default();
    for caller in callers {
        tally.add(&read_caller_sites(&facts, caller));
    }
    tally
}

/// The block for several callers, tallied over `scope`, with no rows.
pub fn callers_block<'e, G: GraphStore + ?Sized>(
    store: &G,
    callers: impl IntoIterator<Item = &'e Entity>,
    scope: &str,
) -> Value {
    block_json(&tally_callers(store, callers), scope)
}

/// One file holding callers whose sites the graph has not settled, because
/// no current ledger describes them.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct OwedFile {
    /// The file, as the graph names it.
    pub file: String,
    /// Callers in it with no current ledger.
    pub callers: u64,
}

/// Every file holding a spanned entity no current ledger describes, with how
/// many such callers each holds, in path order.
///
/// A caller reads as owed when its derivation or its enrichment is owed, and
/// as stale when its ledger was proven under a context its resolver no
/// longer runs under; both are callers with no current ledger. A caller no
/// resolver can prove on this host now is not owed, since no sweep will reach
/// it, and is left out.
pub fn owed_files<G: GraphStore + ?Sized>(store: &G, entities: &[Entity]) -> Vec<OwedFile> {
    let facts = GraphSiteFacts::new(store);
    let mut by_file: BTreeMap<String, u64> = BTreeMap::new();
    for entity in entities {
        let Some(span) = entity.span.as_ref() else {
            continue;
        };
        if matches!(
            read_caller_sites(&facts, entity),
            CallerSites::Current(_) | CallerSites::NoSites | CallerSites::NoResolver { .. }
        ) {
            continue;
        }
        *by_file.entry(span.file.0.clone()).or_insert(0) += 1;
    }
    by_file
        .into_iter()
        .map(|(file, callers)| OwedFile { file, callers })
        .collect()
}

/// Owed callers of `language` in files outside `inside`, the way
/// [`owed_files`] reads them, or `None` when the entity index could not be
/// read.
///
/// The family scope is the files that import the focal's file, and a caller
/// can reach the focal without importing that file: a Python method called
/// through a proxy such as `current_app`, or a Go function called from
/// another file of the same package. While such a caller is still owed its
/// sites, the family tally cannot see it, so a settled family is not a
/// settled answer. Measured on Flask right after `kin init`: `kin refs
/// ensure_sync` printed 10 of its 12 callers as settled while the sweep still
/// owed `views.py`, which reaches it through `current_app`.
///
/// Such a caller reaches the focal by name, so only an owed caller whose body
/// could spell the focal's name is counted (see [`could_name_focal`]). One
/// whose span holds no bytes holds no call, and one whose parse-time preview
/// is its whole body and never spells the name cannot call the focal by it.
/// Every other owed caller counts, including one whose preview was cut short
/// or absent, because a name missing from part of a body proves nothing about
/// the rest.
pub fn owed_outside<G: GraphStore + ?Sized>(
    store: &G,
    language: LanguageId,
    inside: &std::collections::HashSet<String>,
    focal_name: &str,
) -> Option<Vec<OwedFile>> {
    let filter = kin_model::graph::EntityFilter {
        languages: Some(vec![language]),
        ..Default::default()
    };
    let entities = store.query_entities(&filter).ok()?;
    let outside: Vec<Entity> = entities
        .into_iter()
        .filter(|entity| {
            entity.span.as_ref().is_some_and(|span| {
                !inside.contains(&span.file.0) && span.start_byte < span.end_byte
            }) && could_name_focal(entity, focal_name)
        })
        .collect();
    Some(owed_files(store, &outside))
}

/// The longest preview the parser keeps whole; a longer body is summarised
/// with gaps, so its preview no longer proves what the body leaves out.
const WHOLE_BODY_PREVIEW_CHARS: usize = 8000;

/// The names a call site may spell to reach `focal_name`: each segment of it.
///
/// The graph names a member by its owner, `Session.send` or `Store::open`,
/// and a call spells the member, `self.send(...)`, or only the owner, as a
/// constructor call `HTTPAdapter()` reaches `HTTPAdapter.__init__`. So a body
/// is searched for every segment, never for the qualified name, which no call
/// spells: searching for it ruled out every owed caller of a method.
pub fn focal_call_names(focal_name: &str) -> impl Iterator<Item = &str> {
    focal_name
        .split(['.', ':'])
        .filter(|segment| !segment.is_empty())
}

/// Whether `entity`'s body could spell a name a call to `focal_name` uses,
/// read off its parse-time preview: false only when that preview is the whole
/// body and spells none of them.
pub fn could_name_focal(entity: &Entity, focal_name: &str) -> bool {
    let Some(preview) = entity
        .metadata
        .extra
        .get(kin_parser::extract::EMBEDDING_BODY_PREVIEW_KEY)
        .and_then(Value::as_str)
    else {
        return true;
    };
    preview.chars().count() > WHOLE_BODY_PREVIEW_CHARS
        || focal_call_names(focal_name).any(|name| preview.contains(name))
        || focal_call_names(focal_name).next().is_none()
}

/// The clause a family block carries while callers outside its scope are
/// owed, or while whether they are could not be read.
pub fn owed_outside_clause(owed: Option<&[OwedFile]>) -> Option<String> {
    match owed {
        None => Some(owed_outside_unreadable_clause()),
        Some([]) => None,
        Some(files) => Some(owed_outside_counts_clause(
            files.len() as u64,
            files.iter().map(|file| file.callers).sum(),
        )),
    }
}

/// [`owed_outside_clause`] for `callers` owed callers in `files` files, so a
/// reader of the published counts states the same sentence.
pub fn owed_outside_counts_clause(files: u64, callers: u64) -> String {
    format!(
        "{}: {callers} caller(s) in {files} file(s) outside {FAMILY_SCOPE} have call sites the \
         graph has not settled yet because their derivation or enrichment is owed, and a caller \
         can reach the focal without importing its file, so one may be missing from this \
         answer until `kin daemon sweep` settles them",
        kin_model::call_site_reading::CALL_SITES_OWED
    )
}

/// [`owed_outside_clause`] when the entity index could not be read.
pub fn owed_outside_unreadable_clause() -> String {
    format!(
        "{}: the entity index for the focal's language could not be read, so callers outside \
         {FAMILY_SCOPE} were not checked, and one that reaches the focal without importing its \
         file may be missing from this answer",
        kin_model::call_site_reading::CALL_SITES_OWED
    )
}

/// The block for the callers in the files that import the focal's file,
/// qualified by the owed callers outside them.
///
/// Unsettled with [`owed_outside_clause`] whenever that clause applies, even
/// when every site inside the family is settled, and it names the outside
/// files it counted, at most [`OWED_FILES_MAX`] of them.
pub fn family_block(tally: &CallSiteTally, owed_outside: Option<&[OwedFile]>) -> Value {
    let mut block = block_json(tally, FAMILY_SCOPE);
    let Some(clause) = owed_outside_clause(owed_outside) else {
        return block;
    };
    block["settled"] = json!(false);
    if let Some(clauses) = block["clauses"].as_array_mut() {
        clauses.push(json!(clause));
    } else {
        block["clauses"] = json!([clause]);
    }
    match owed_outside {
        Some(files) => {
            block["owed_outside_scope"] = json!({
                "file_count": files.len(),
                "callers": files.iter().map(|file| file.callers).sum::<u64>(),
                "files": files.iter().take(OWED_FILES_MAX).collect::<Vec<_>>(),
            });
            if files.len() > OWED_FILES_MAX {
                block["owed_outside_scope"]["files_withheld"] = json!(files.len() - OWED_FILES_MAX);
            }
        }
        None => block["owed_outside_scope"] = json!({ "unreadable": true }),
    }
    block
}

/// The store-wide block: the tally over every entity the store holds, each
/// state's share of the census, how many callers are owed, and the files
/// holding them, at most [`OWED_FILES_MAX`] of them.
///
/// The census is the sites the read ledgers hold, so the shares add up to it.
/// An owed caller contributes no site, since how many it holds is not known,
/// which is why a store with callers owed is not settled whatever its shares
/// say.
pub fn store_block<G: GraphStore + ?Sized>(store: &G) -> crate::error::Result<Value> {
    let entities = store
        .list_all_entities()
        .map_err(crate::error::McpError::graph)?;
    Ok(store_block_over(store, &entities))
}

/// [`store_block`] over a listing of every entity the caller already holds,
/// so a surface that listed the store once does not list it again.
pub fn store_block_over<G: GraphStore + ?Sized>(store: &G, entities: &[Entity]) -> Value {
    let tally = tally_callers(store, entities);
    let mut block = block_json(&tally, STORE_SCOPE);
    block["census"] = json!(tally.sites);
    block["callers_owed"] = json!(tally.callers_owed());
    let shares: serde_json::Map<String, Value> = SiteStateKind::ALL
        .iter()
        .filter(|kind| !kind.is_uncounted())
        .map(|kind| {
            (
                kind.wire().to_string(),
                json!({
                    "sites": tally.count(*kind),
                    "share": tally.share(*kind),
                }),
            )
        })
        .collect();
    block["shares"] = Value::Object(shares);
    let owed = owed_files(store, entities);
    block["owed_file_count"] = json!(owed.len());
    block["owed_files"] = json!(owed.iter().take(OWED_FILES_MAX).collect::<Vec<_>>());
    if owed.len() > OWED_FILES_MAX {
        block["owed_files_withheld"] = json!(owed.len() - OWED_FILES_MAX);
    }
    block
}

// ── Text ──────────────────────────────────────────────────────────────────

/// A share as a whole percentage, the way a terminal line states it.
fn percent(share: Option<f64>) -> String {
    match share {
        Some(share) => format!("{:.0}%", share * 100.0),
        None => "no share".to_string(),
    }
}

/// The block as terminal lines, so the CLI says what the MCP payload says.
///
/// A focal's block lists one line per row, `+N` lines below the caller's
/// first line with the text at the site, the state, its reason and the target
/// id when a resolver proved one. A store-wide block lists each state's share
/// of the census. Every block ends with the clauses it calls for, one per
/// line, or with the sentence that it is settled.
pub fn text_lines(block: &Value) -> Vec<String> {
    let mut lines = Vec::new();
    let scope = block["scope"].as_str().unwrap_or("this answer");
    let sites = block["sites"].as_u64().unwrap_or(0);
    let callers = block["callers"].as_u64().unwrap_or(0);
    let owed = block["callers_owed_derivation"].as_u64().unwrap_or(0)
        + block["callers_owed_enrichment"].as_u64().unwrap_or(0);
    let unproven = block["callers_unproven_no_resolver"].as_u64().unwrap_or(0);
    let mut header = format!("Call sites in {scope}: {sites} across {callers} caller(s)");
    if owed > 0 {
        header.push_str(&format!(", {owed} caller(s) owed"));
    }
    if unproven > 0 {
        header.push_str(&format!(", {unproven} caller(s) no resolver can prove"));
    }
    if let Some(reading) = block["reading"].as_str() {
        header.push_str(&format!(" ({reading})"));
    }
    lines.push(header);
    if let Some(cannot_name) = block["owed_callers_cannot_name_focal"]
        .as_u64()
        .filter(|count| *count > 0)
    {
        lines.push(format!(
            "  {cannot_name} more owed caller(s) there never spell the focal's name, so they \
             cannot call it by name and are not counted"
        ));
    }
    if let Some(shares) = block["shares"].as_object() {
        let parts: Vec<String> = shares
            .iter()
            .filter(|(_, share)| share["sites"].as_u64().unwrap_or(0) > 0)
            .map(|(state, share)| {
                format!(
                    "{state} {} ({})",
                    share["sites"].as_u64().unwrap_or(0),
                    percent(share["share"].as_f64())
                )
            })
            .collect();
        if !parts.is_empty() {
            lines.push(format!("  by state: {}", parts.join(", ")));
        }
    }
    if let Some(files) = block["owed_files"].as_array() {
        for file in files {
            lines.push(format!(
                "  owed enrichment: {} ({} caller(s))",
                file["file"].as_str().unwrap_or("?"),
                file["callers"].as_u64().unwrap_or(0)
            ));
        }
        if let Some(withheld) = block["owed_files_withheld"].as_u64() {
            lines.push(format!(
                "  ({withheld} more files with owed callers are not listed)"
            ));
        }
    }
    if let Some(files) = block["owed_outside_scope"]["files"].as_array() {
        for file in files.iter().take(5) {
            lines.push(format!(
                "  owed outside {scope}: {} ({} caller(s))",
                file["file"].as_str().unwrap_or("?"),
                file["callers"].as_u64().unwrap_or(0)
            ));
        }
        let more = block["owed_outside_scope"]["file_count"]
            .as_u64()
            .unwrap_or(0)
            .saturating_sub(5);
        if more > 0 {
            lines.push(format!(
                "  ({more} more files outside {scope} with owed callers are not listed)"
            ));
        }
    }
    if let Some(rows) = block["rows"].as_array() {
        for row in rows {
            let at = row["line_in_entity"]
                .as_u64()
                .map(|line| format!("+{line}"))
                .unwrap_or_else(|| "+?".to_string());
            let callee = row["callee"]
                .as_str()
                .map(|callee| format!("`{callee}`"))
                .unwrap_or_else(|| {
                    format!(
                        "(text unavailable: {})",
                        row["callee_unavailable"].as_str().unwrap_or("unknown")
                    )
                });
            let mut line = format!("  {at} {callee} {}", row["state"].as_str().unwrap_or("?"));
            if let Some(reason) = row["reason"].as_str() {
                line.push_str(&format!(" ({reason})"));
            }
            if let Some(target) = row["target"].as_str() {
                line.push_str(&format!(" -> {target}"));
            }
            lines.push(line);
        }
        if let Some(withheld) = block["rows_withheld"].as_u64() {
            lines.push(format!(
                "  ({withheld} more sites past the {CALL_SITE_ROWS_MAX}-row cap are not listed)"
            ));
        }
    }
    let clauses: Vec<&str> = block["clauses"]
        .as_array()
        .map(|clauses| clauses.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    if clauses.is_empty() {
        lines.push("  every site in scope is settled".to_string());
    } else {
        for clause in clauses {
            lines.push(format!("  not settled: {clause}"));
        }
    }
    lines
}

/// Graphs holding call-site ledgers, for the tests of every surface that
/// serves them.
#[cfg(test)]
pub(crate) mod fixture {
    use kin_db::InMemoryGraph;
    use kin_model::entity::{Entity, EntityMetadata, SourceSpan};
    use kin_model::graph::EntityStore as _;
    use kin_model::{
        CallSite, CallSiteLedger, CallSiteState, EntityId, EntityKind, EntityRole, FilePathId,
        FingerprintAlgorithm, Hash256, LanguageId, ProofContext, ResolutionRecord,
        ResolutionRecordDelta, ResolutionRecordId, SemanticFingerprint, TransactionDelta,
        Visibility,
    };

    /// A function whose own text is `body`, starting at byte `start` of
    /// `file`.
    pub(crate) fn spanned_entity(
        name: &str,
        file: &str,
        language: LanguageId,
        start: usize,
        body: &str,
    ) -> Entity {
        Entity {
            id: EntityId::from_content(file, name, "Function", start as u32),
            kind: EntityKind::Function,
            name: name.to_string(),
            language,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0; 32]),
                signature_hash: Hash256::from_bytes([0; 32]),
                behavior_hash: Hash256::from_bytes([9; 32]),
                equivalence_hash: Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new(file)),
            span: Some(SourceSpan {
                file: FilePathId::new(file),
                start_byte: start,
                end_byte: start + body.len(),
                start_line: 10,
                start_col: 0,
                end_line: 10 + body.matches('\n').count() as u32,
                end_col: 0,
            }),
            signature: format!("def {name}()"),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    /// The proof context `language`'s resolver ran under, told apart from
    /// another by `version`.
    pub(crate) fn proof_context(language: LanguageId, version: &str) -> ResolutionRecord {
        ResolutionRecord::ProofContext(ProofContext {
            language,
            resolver: "lsp:pyright".to_string(),
            resolver_version: version.to_string(),
            configuration_hash: Hash256::from_bytes([0x41; 32]),
            environment_hash: Hash256::from_bytes([0x42; 32]),
            environment_summary: "python 3.12".to_string(),
        })
    }

    /// `caller`'s ledger under `context`, one site per callee token, each
    /// token found in `body` at or after the previous one.
    pub(crate) fn ledger(
        caller: &Entity,
        body: &str,
        context: ResolutionRecordId,
        sites: Vec<(&str, CallSiteState)>,
    ) -> ResolutionRecord {
        let mut from = 0usize;
        let sites: Vec<CallSite> = sites
            .into_iter()
            .map(|(token, state)| {
                let offset = from + body[from..].find(token).expect("the token is in the body");
                from = offset + token.len();
                CallSite {
                    offset: offset as u32,
                    length: token.len() as u32,
                    state,
                }
            })
            .collect();
        ResolutionRecord::CallSites(CallSiteLedger {
            caller: caller.id,
            behavior_hash: caller.fingerprint.behavior_hash,
            body_hash: Hash256::from_bytes([0x43; 32]),
            context,
            census: sites.len() as u32,
            sites,
        })
    }

    /// Put `entities` in the graph, then `records` in one transaction, each
    /// proof context a ledger names before the ledger.
    pub(crate) fn admit(
        store: &InMemoryGraph,
        entities: &[&Entity],
        records: Vec<ResolutionRecord>,
    ) {
        let mut records = records;
        records.sort_by_key(|record| !matches!(record, ResolutionRecord::ProofContext(_)));
        let records: Vec<ResolutionRecord> = records
            .into_iter()
            .filter(|record| {
                store
                    .lookup_resolution_record(&record.id())
                    .ok()
                    .flatten()
                    .is_none()
            })
            .collect();
        for entity in entities {
            if store.get_entity(&entity.id).ok().flatten().is_none() {
                store
                    .upsert_entity(entity)
                    .expect("the fixture's entity is admitted");
            }
        }
        store
            .apply_transaction_delta(&TransactionDelta {
                resolution_record_deltas: records
                    .into_iter()
                    .map(|new| ResolutionRecordDelta::Added { new })
                    .collect(),
                ..TransactionDelta::default()
            })
            .expect("the fixture's records are admitted");
    }

    /// The id a record goes by.
    pub(crate) fn id_of(record: &ResolutionRecord) -> ResolutionRecordId {
        record.id()
    }
}

#[cfg(test)]
mod tests {
    use super::fixture::{admit, id_of, ledger, proof_context, spanned_entity};
    use super::*;
    use crate::handlers::external_symbols::quote_site;
    use kin_db::InMemoryGraph;
    use kin_model::graph::EntityStore as _;
    use kin_model::{
        CallSiteState, ExternalReference, ExternalReferenceDelta, TransactionDelta,
        UnresolvedReason,
    };

    /// Why no resolver can prove a language's sites, from what was published:
    /// a switched-off daemon first, then the probe's word per language, and
    /// a language no build of Kin enriches never has a resolver. Nothing
    /// published, or a language the probe did not report on, claims nothing.
    #[test]
    fn no_resolver_is_read_from_what_the_resolver_process_published() {
        use kin_core::reference_coverage::{LanguageServerReadiness, LanguageServerReadinessMap};
        let probed: LanguageServerReadinessMap = [
            (LanguageId::Python, LanguageServerReadiness::Usable),
            (LanguageId::Go, LanguageServerReadiness::Absent),
            (
                LanguageId::Rust,
                LanguageServerReadiness::Unusable {
                    reason: "no Cargo".to_string(),
                },
            ),
        ]
        .into_iter()
        .collect();
        let read = |off, readiness, language| no_resolver_for(off, readiness, language);
        assert_eq!(read(None, None, LanguageId::Python), None);
        assert_eq!(read(Some(false), None, LanguageId::Python), None);
        assert_eq!(
            read(Some(true), Some(&probed), LanguageId::Python),
            Some(NoResolver::EnrichmentOff)
        );
        assert_eq!(read(Some(false), Some(&probed), LanguageId::Python), None);
        assert_eq!(
            read(Some(false), Some(&probed), LanguageId::Go),
            Some(NoResolver::NoLanguageServer)
        );
        assert_eq!(
            read(Some(false), Some(&probed), LanguageId::Rust),
            Some(NoResolver::ServerCannotStart {
                reason: "no Cargo".to_string()
            })
        );
        // Enrichable, and the probe said nothing about it: unknown.
        assert_eq!(
            read(Some(false), Some(&probed), LanguageId::TypeScript),
            None
        );
        // A language no build of Kin enriches.
        assert_eq!(
            read(Some(false), Some(&probed), LanguageId::Java),
            Some(NoResolver::NoLanguageServer)
        );
    }

    const BODY: &str = "def run(data):\n    helper(data)\n    json.dumps(data)\n    handler(data)\n    mystery(data)\n";

    /// The caller's own body, as the answer's body reader would hand it over.
    struct Body(&'static str);

    impl SiteText for Body {
        fn quote(&self, caller: &Entity, site: &SourceSpan) -> Result<String, &'static str> {
            let span = caller.span.as_ref().ok_or("caller_has_no_span")?;
            quote_site(caller, site, self.0, span.start_byte)
        }
    }

    struct Fixture {
        store: InMemoryGraph,
        run: Entity,
        helper: Entity,
        external: ExternalReference,
        context: ResolutionRecordId,
    }

    /// `run` calls `helper` in the repository, `dumps` outside it, a value
    /// bound to `handler`, and `mystery`, which the resolver answered and could
    /// not place.
    fn fixture(with_ledger: bool) -> Fixture {
        let store = InMemoryGraph::new();
        let run = spanned_entity("run", "app.py", LanguageId::Python, 200, BODY);
        let helper = spanned_entity(
            "helper",
            "app.py",
            LanguageId::Python,
            20,
            "def helper(data):\n    pass\n",
        );
        let external =
            ExternalReference::new_resolved("kin-scip-v1", "pip python 3.12", "json/dumps().")
                .expect("a resolved external symbol");
        store
            .apply_transaction_delta(&TransactionDelta {
                external_reference_deltas: vec![ExternalReferenceDelta::Added {
                    new: external.clone(),
                }],
                ..TransactionDelta::default()
            })
            .expect("the external symbol is admitted");
        let context = proof_context(LanguageId::Python, "1.1.400");
        let context_id = id_of(&context);
        let mut records = vec![context];
        if with_ledger {
            // Every spanned entity a sweep finishes gets a ledger, a caller
            // with no call an empty one.
            records.push(ledger(&helper, "", context_id, Vec::new()));
            records.push(ledger(
                &run,
                BODY,
                context_id,
                vec![
                    ("helper", CallSiteState::ProvenTarget { target: helper.id }),
                    (
                        "dumps",
                        CallSiteState::ProvenExternal {
                            target: external.id,
                        },
                    ),
                    ("handler", CallSiteState::Binding { may_call: None }),
                    (
                        "mystery",
                        CallSiteState::Unresolved {
                            reason: UnresolvedReason::NoAnswer,
                        },
                    ),
                ],
            ));
        }
        admit(&store, &[&run, &helper], records);
        Fixture {
            store,
            run,
            helper,
            external,
            context: context_id,
        }
    }

    #[test]
    fn a_focal_with_a_ledger_serves_one_row_per_site_addressed_inside_the_focal() {
        let fixture = fixture(true);
        let block = focal_block(&fixture.store, &fixture.run, &Body(BODY));
        assert_eq!(block["reading"], "current", "{block}");
        assert_eq!(block["scope"], FOCAL_SCOPE);
        assert_eq!(block["sites"], 4);
        assert_eq!(block["settled"], false);
        assert_eq!(
            block["rows"],
            json!([
                {
                    "line_in_entity": 1,
                    "callee": "helper",
                    "state": "proven_target",
                    "reason": null,
                    "target": format!("entity:{}", fixture.helper.id),
                },
                {
                    "line_in_entity": 2,
                    "callee": "dumps",
                    "state": "proven_external",
                    "reason": null,
                    "target": format!("external_reference:{}", fixture.external.id),
                },
                {
                    "line_in_entity": 3,
                    "callee": "handler",
                    "state": "binding",
                    "reason": null,
                    "target": null,
                },
                {
                    "line_in_entity": 4,
                    "callee": "mystery",
                    "state": "unresolved",
                    "reason": "no_answer",
                    "target": null,
                },
            ]),
            "{block}"
        );
        let text = serde_json::to_string(&block).unwrap();
        assert!(
            !text.contains("start_line") && !text.contains("app.py"),
            "a site is never addressed by file or file line: {block}"
        );
        assert_eq!(
            block["clauses"],
            json!([
                "binding_unproven: 1 of the 4 call sites in the focal's own body call through a \
                 value binding, which proves no target",
                "call_sites_unresolved: 1 of the 4 call sites in the focal's own body got an \
                 answer that proves no target",
            ])
        );
    }

    #[test]
    fn a_spanned_focal_with_no_ledger_reads_as_owed_enrichment() {
        let fixture = fixture(false);
        let block = focal_block(&fixture.store, &fixture.run, &Body(BODY));
        assert_eq!(block["reading"], "owed_enrichment", "{block}");
        assert_eq!(block["callers_owed_enrichment"], 1);
        assert_eq!(block["sites"], 0);
        assert_eq!(block["rows"], json!([]));
        assert_eq!(block["settled"], false);
        let clauses = block["clauses"].as_array().expect("clauses");
        assert_eq!(clauses.len(), 1, "{block}");
        assert!(
            clauses[0]
                .as_str()
                .is_some_and(|clause| clause.starts_with("call_sites_owed: ")),
            "{block}"
        );

        let mut spanless = fixture.run.clone();
        spanless.span = None;
        let block = focal_block(&fixture.store, &spanless, &Body(BODY));
        assert_eq!(block["reading"], "no_sites", "{block}");
        assert_eq!(
            block["settled"], true,
            "a focal with no text holds no site: {block}"
        );
    }

    #[test]
    fn a_ledger_proven_under_another_context_reads_as_stale() {
        let fixture = fixture(true);
        let newer = id_of(&proof_context(LanguageId::Python, "1.1.401"));
        let _guard = test_support::scoped_proof_contexts(&[(LanguageId::Python, newer)]);
        let block = focal_block(&fixture.store, &fixture.run, &Body(BODY));
        assert_eq!(block["reading"], "proof_context_stale", "{block}");
        assert_eq!(block["callers_stale"], 1);
        assert_eq!(block["by_state"]["proof_context_stale"], 4);
        assert_eq!(block["rows"][0]["state"], "proof_context_stale");
        assert_eq!(block["rows"][0]["recorded_state"], "proven_target");
        assert_eq!(block["stale_context"], fixture.context.to_string());
        drop(_guard);

        let _same = test_support::scoped_proof_contexts(&[(LanguageId::Python, fixture.context)]);
        let block = focal_block(&fixture.store, &fixture.run, &Body(BODY));
        assert_eq!(block["reading"], "current", "{block}");
    }

    #[test]
    fn a_published_context_is_the_one_every_reader_holds_a_ledger_against() {
        // Kotlin, because no other test in this crate holds a Kotlin ledger,
        // and the publication is process-wide.
        let store = InMemoryGraph::new();
        let body = "fun main() {\n    greet()\n}\n";
        let main = spanned_entity("main", "Main.kt", LanguageId::Kotlin, 0, body);
        let context = proof_context(LanguageId::Kotlin, "1.0");
        let recorded = ledger(
            &main,
            body,
            id_of(&context),
            vec![("greet", CallSiteState::ProvenOutside)],
        );
        admit(&store, &[&main], vec![context, recorded]);
        let newer = id_of(&proof_context(LanguageId::Kotlin, "2.0"));
        publish_current_proof_contexts(HashMap::from([(LanguageId::Kotlin, newer)]));
        assert_eq!(
            published_current_proof_contexts()
                .and_then(|contexts| contexts.get(&LanguageId::Kotlin).copied()),
            Some(newer)
        );
        let reading = read_caller_sites(&GraphSiteFacts::new(&store), &main);
        publish_current_proof_contexts(HashMap::new());
        assert!(matches!(reading, CallerSites::Stale(_)), "{reading:?}");
        assert!(matches!(
            read_caller_sites(&GraphSiteFacts::new(&store), &main),
            CallerSites::Current(_)
        ));
    }

    #[test]
    fn the_store_block_s_shares_add_up_to_its_census_and_name_the_owed_files() {
        let fixture = fixture(true);
        let owed = spanned_entity(
            "later",
            "lib/tools.py",
            LanguageId::Python,
            0,
            "def later():\n    pass\n",
        );
        admit(&fixture.store, &[&owed], Vec::new());
        let block = store_block(&fixture.store).expect("the store reads");
        assert_eq!(block["scope"], STORE_SCOPE);
        assert_eq!(block["census"], 4, "{block}");
        assert_eq!(block["callers_owed"], 1, "{block}");
        let shares = block["shares"].as_object().expect("shares");
        let total: u64 = shares
            .values()
            .map(|share| share["sites"].as_u64().unwrap_or(0))
            .sum();
        assert_eq!(total, 4, "the shares add up to the census: {block}");
        assert_eq!(shares["proven_target"]["share"], 0.25);
        assert_eq!(shares["unresolved"]["sites"], 1);
        assert_eq!(
            block["owed_files"],
            json!([{"file": "lib/tools.py", "callers": 1}]),
            "{block}"
        );
        assert_eq!(block["settled"], false);

        let lines = text_lines(&block);
        assert!(
            lines
                .iter()
                .any(|line| line.contains("proven_target 1 (25%)")),
            "{lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|line| line.contains("owed enrichment: lib/tools.py (1 caller(s))")),
            "{lines:?}"
        );
    }

    #[test]
    fn a_focal_block_renders_as_lines_addressed_inside_the_focal() {
        let fixture = fixture(true);
        let lines = text_lines(&focal_block(&fixture.store, &fixture.run, &Body(BODY)));
        assert!(
            lines.contains(&format!(
                "  +1 `helper` proven_target -> entity:{}",
                fixture.helper.id
            )),
            "{lines:?}"
        );
        assert!(
            lines.contains(&"  +4 `mystery` unresolved (no_answer)".to_string()),
            "{lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|line| line.starts_with("  not settled: call_sites_unresolved: ")),
            "{lines:?}"
        );
    }
}

#[cfg(test)]
mod owed_outside_tests {
    use serde_json::json;

    use super::{family_block, text_lines, OwedFile, FAMILY_SCOPE};
    use crate::caller_arrival::{impact_arrival_gaps, owed_outside_gap, CALLER_ARRIVAL_KEY};

    fn owed(file: &str, callers: u64) -> OwedFile {
        OwedFile {
            file: file.to_string(),
            callers,
        }
    }

    #[test]
    fn a_settled_family_with_nothing_owed_outside_stays_settled() {
        let tally = kin_model::CallSiteTally::default();
        let block = family_block(&tally, Some(&[]));
        assert_eq!(block["settled"], true, "{block}");
        assert_eq!(block["scope"], FAMILY_SCOPE, "{block}");
        assert!(block.get("owed_outside_scope").is_none(), "{block}");
        assert!(text_lines(&block)
            .iter()
            .any(|line| line == "  every site in scope is settled"));
    }

    #[test]
    fn an_owed_caller_outside_the_family_unsettles_it_and_names_the_file() {
        let tally = kin_model::CallSiteTally::default();
        let block = family_block(
            &tally,
            Some(&[owed("pkg/views.py", 2), owed("pkg/ctx.py", 1)]),
        );
        assert_eq!(block["settled"], false, "{block}");
        assert_eq!(block["owed_outside_scope"]["file_count"], 2, "{block}");
        assert_eq!(block["owed_outside_scope"]["callers"], 3, "{block}");
        let text = text_lines(&block).join("\n");
        assert!(!text.contains("every site in scope is settled"), "{text}");
        assert!(
            text.contains("not settled: call_sites_owed: 3 caller(s) in 2 file(s) outside"),
            "{text}"
        );
        assert!(text.contains("pkg/views.py (2 caller(s))"), "{text}");
        assert!(text.contains("kin daemon sweep"), "{text}");
    }

    #[test]
    fn an_unreadable_index_refuses_rather_than_certifying() {
        let tally = kin_model::CallSiteTally::default();
        let block = family_block(&tally, None);
        assert_eq!(block["settled"], false, "{block}");
        assert_eq!(block["owed_outside_scope"]["unreadable"], true, "{block}");
        let payload = json!({ CALLER_ARRIVAL_KEY: { "state": "accounted",
            "owed_outside_scope": { "unreadable": true } } });
        let gap = owed_outside_gap(&payload).expect("an unreadable index is a gap");
        assert!(gap.starts_with("call_sites_owed: "), "{gap}");
    }

    /// A caller outside the family reaches the focal by name, so an owed one
    /// counts only while its body could spell that name: a whole preview that
    /// never does rules it out, and a cut or absent preview never does.
    #[test]
    fn only_a_body_that_could_spell_the_focal_counts_outside_the_family() {
        use kin_model::graph::EntityStore as _;
        let graph = kin_db::InMemoryGraph::new();
        let body = |name: &str, preview: Option<String>| {
            let mut entity = super::fixture::spanned_entity(
                name,
                &format!("pkg/{name}.py"),
                kin_model::LanguageId::Python,
                20,
                "def f():\n    g()\n",
            );
            if let Some(preview) = preview {
                entity.metadata.extra.insert(
                    kin_parser::extract::EMBEDDING_BODY_PREVIEW_KEY.to_string(),
                    json!(preview),
                );
            }
            graph.upsert_entity(&entity).unwrap();
        };
        body(
            "names_it",
            Some("def names_it(): current_app.ensure_sync(f)".into()),
        );
        body("never_does", Some("def never_does(): print(1)".into()));
        body(
            "cut_short",
            Some(format!("def cut_short(): {}", "x".repeat(9000))),
        );
        body("no_preview", None);
        // The graph names the focal by its owner, and a call spells only
        // the member, so the qualified name is what the reading is handed.
        let owed = super::owed_outside(
            &graph,
            kin_model::LanguageId::Python,
            &std::collections::HashSet::new(),
            "App.ensure_sync",
        )
        .expect("the index reads");
        let files: Vec<&str> = owed.iter().map(|file| file.file.as_str()).collect();
        assert_eq!(
            files,
            ["pkg/cut_short.py", "pkg/names_it.py", "pkg/no_preview.py"],
            "{owed:?}"
        );
    }

    /// A call spells a member without its owner, or the owner alone for a
    /// constructor, so a body is searched for every segment of the focal's
    /// name, whichever separator the language uses.
    #[test]
    fn a_focal_is_named_by_every_segment_a_call_may_spell() {
        fn names(name: &str) -> Vec<&str> {
            super::focal_call_names(name).collect()
        }
        assert_eq!(names("App.ensure_sync"), ["App", "ensure_sync"]);
        assert_eq!(names("Store::open"), ["Store", "open"]);
        assert_eq!(names("parse_note"), ["parse_note"]);
        assert_eq!(names("Trailing."), ["Trailing"]);

        let entity = |preview: &str| {
            let mut entity = super::fixture::spanned_entity(
                "caller",
                "pkg/caller.py",
                kin_model::LanguageId::Python,
                0,
                preview,
            );
            entity.metadata.extra.insert(
                kin_parser::extract::EMBEDDING_BODY_PREVIEW_KEY.to_string(),
                json!(preview),
            );
            entity
        };
        let constructs = entity("def make(): return HTTPAdapter()");
        assert!(super::could_name_focal(&constructs, "HTTPAdapter.__init__"));
        let sends = entity("def go(self): return self.send(req)");
        assert!(super::could_name_focal(&sends, "Session.send"));
        let unrelated = entity("def go(): return print(1)");
        assert!(!super::could_name_focal(&unrelated, "Session.send"));
    }

    /// Impact's zero consumer counts are not whole while a caller outside a
    /// family is owed, even when every family is accounted.
    #[test]
    fn impact_names_the_owed_callers_outside_an_accounted_reading() {
        let payload = json!({ CALLER_ARRIVAL_KEY: {
            "state": "accounted",
            "entities_examined": 1,
            "entities": [],
            "owed_outside_scope": { "file_count": 1, "callers": 2,
                "files": [{ "file": "pkg/views.py", "callers": 2 }] },
        } });
        let gaps = impact_arrival_gaps(&payload);
        assert_eq!(gaps.len(), 1, "{gaps:?}");
        assert!(
            gaps[0].starts_with("call_sites_owed: 2 caller(s) in 1 file(s) outside"),
            "{gaps:?}"
        );
        let settled = json!({ CALLER_ARRIVAL_KEY: {
            "state": "accounted", "entities_examined": 1, "entities": [] } });
        assert!(impact_arrival_gaps(&settled).is_empty());
    }
}
