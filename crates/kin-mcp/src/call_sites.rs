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
//!   validated in the selected graph for each language, and why
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

use std::collections::{BTreeMap, HashMap, HashSet};

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

/// Illustrative unsettled candidates in a reference answer. Counts, reasons
/// and clauses still describe the full scan; samples must leave room for the
/// proven reference rows and their qualifications at the default budget.
pub const CALL_SITE_CANDIDATE_SAMPLE_MAX: usize = 5;

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
/// stale to the scheduler. This compatibility publication is not read authority:
/// readers use the selected graph's durable context-validation records.
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

/// Lets a test state which proof context each language's resolver runs
/// under. Thread-local, so it holds for the test that set it whether the
/// suite runs threaded or one process per test.
#[cfg(test)]
pub(crate) mod test_support {
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
        Some(LanguageServerReadiness::Disabled) => Some(NoResolver::EnrichmentOff),
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
    switched_off: Option<bool>,
    readiness: Option<kin_core::reference_coverage::LanguageServerReadinessMap>,
}

impl<'s, G: GraphStore + ?Sized> GraphSiteFacts<'s, G> {
    /// Facts about `store`, under its own recorded context validation.
    pub fn new(store: &'s G) -> Self {
        Self {
            store,
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
        self.store
            .lookup_resolution_record(&ResolutionRecordId::context_validation(language))
            .ok()
            .flatten()
            .and_then(|record| {
                record
                    .as_context_validation()
                    .and_then(|validation| validation.current_context())
            })
    }

    fn context_unverified_reason(&self, language: LanguageId) -> String {
        match self
            .store
            .lookup_resolution_record(&ResolutionRecordId::context_validation(language))
        {
            Ok(Some(kin_model::ResolutionRecord::ContextValidation(
                kin_model::ContextValidation {
                    state: kin_model::ContextValidationState::Unverified { reason },
                    ..
                },
            ))) => reason,
            Err(_) => "the selected graph's proof-context validation could not be read".into(),
            _ => "the selected graph has no recorded proof-context validation".into(),
        }
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
    if matches!(
        reading,
        CallerSites::Stale(_) | CallerSites::Unverified { .. }
    ) {
        row["recorded_state"] = json!(site.state.wire());
    }
    row
}

/// The block for one focal's own call sites, with a row for each site its
/// ledger holds, at most [`CALL_SITE_ROWS_MAX`] of them.
///
/// `reading` says what stands between the reader and the focal's ledger:
/// `current`, `owed_enrichment`, `owed_derivation`, `proof_context_stale`,
/// `proof_context_unverified` or
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
    if let CallerSites::Unverified { ledger, reason } = &reading {
        block["unverified_context"] = json!(ledger.context.to_string());
        block["validation_reason"] = json!(reason);
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
    names: &[String],
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
            }) && could_name_focal(entity, names)
        })
        .collect();
    Some(owed_files(store, &outside))
}

/// The longest preview the parser keeps whole; a longer body is summarised
/// with gaps, so its preview no longer proves what the body leaves out.
const WHOLE_BODY_PREVIEW_CHARS: usize = 8000;

pub use kin_model::{calling_languages, focal_call_names, FocalEscape};

/// The body preview the parser keeps on `entity`, when it is the whole body:
/// every identifier the body holds, with its whitespace collapsed. `None` for
/// an entity with no preview, or one cut short because the body is longer
/// than [`WHOLE_BODY_PREVIEW_CHARS`].
pub fn whole_body_preview(entity: &Entity) -> Option<&str> {
    entity
        .metadata
        .extra
        .get(kin_parser::extract::EMBEDDING_BODY_PREVIEW_KEY)
        .and_then(Value::as_str)
        .filter(|preview| preview.chars().count() <= WHOLE_BODY_PREVIEW_CHARS)
}

/// Whether `entity`'s body could spell one of `names`, the names a call to
/// the focal is spelled with (see [`focal_call_names`]), read off its
/// parse-time preview: false only when that preview is the whole body and
/// spells none of them. A focal with no call name rules nothing out.
pub fn could_name_focal(entity: &Entity, names: &[String]) -> bool {
    let names: Vec<&str> = names
        .iter()
        .map(String::as_str)
        .filter(|name| !name.is_empty())
        .collect();
    if names.is_empty() {
        return true;
    }
    let preview = entity
        .metadata
        .extra
        .get(kin_parser::extract::EMBEDDING_BODY_PREVIEW_KEY)
        .and_then(Value::as_str);
    match preview {
        None => true,
        Some(preview) if preview.chars().count() > WHOLE_BODY_PREVIEW_CHARS => true,
        Some(preview) => names.iter().any(|name| preview.contains(name)),
    }
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

// ── Which unsettled sites anywhere in the store could be calls to one focal ──

/// The scope of a block taken over every caller in the store whose body
/// could call the focal by name, or through a value when the focal escapes.
pub const NAMED_SCOPE: &str = "the store's callers that could call the focal";

/// A site reader that holds no text, for a surface with no graph-held body to
/// read. Every site it is asked about reads as unknown, so every rule that
/// needs text keeps the site.
pub struct NoSiteText;

impl SiteText for NoSiteText {
    fn quote(&self, _caller: &Entity, _site: &SourceSpan) -> Result<String, &'static str> {
        Err("caller_text_not_held")
    }
}

/// `entity`'s exact text from its first byte, read through `text`, or `None`
/// when the reader cannot give it.
fn exact_text<T: SiteText + ?Sized>(text: &T, entity: &Entity) -> Option<String> {
    let span = entity.span.as_ref()?;
    text.quote(
        entity,
        &SourceSpan {
            file: span.file.clone(),
            start_byte: span.start_byte,
            end_byte: span.end_byte,
            start_line: 0,
            start_col: 0,
            end_line: 0,
            end_col: 0,
        },
    )
    .ok()
}

/// Whether `text` is one identifier, the shape of a placeable callee token.
fn is_identifier(text: &str) -> bool {
    let mut chars = text.chars();
    chars
        .next()
        .is_some_and(|first| first.is_alphabetic() || first == '_' || first == '$')
        && chars
            .all(|character| character.is_alphanumeric() || character == '_' || character == '$')
}

/// A call site anywhere in the store that could be a call to a focal but is
/// not settled.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CandidateSite {
    /// The caller holding the site.
    pub caller: EntityId,
    /// The caller's name, as the graph names it.
    pub caller_name: String,
    /// The caller's file, as the graph names it. Served as
    /// `projection.path`: a projection of the caller, never its address,
    /// which is `caller`.
    #[serde(rename = "projection", serialize_with = "serialize_projection")]
    pub caller_file: Option<String>,
    /// The site's line counted from 0 at the caller's first line, when the
    /// caller's text was read.
    pub line_in_entity: Option<u64>,
    /// The site's callee token, when the site has one and the caller's text
    /// was read. `None` for a site with no placeable callee.
    pub callee: Option<String>,
    /// What a reader serves for the site.
    pub state: SiteStateKind,
    /// The site's own reason: the unresolved reason, the server failure or
    /// the not-in-build reason.
    pub state_reason: Option<String>,
    /// Why it can reach the focal (see [`kin_model::site_could_call_at`]).
    pub reason: &'static str,
}

/// A candidate's file as the labelled projection every reference row serves:
/// `{"path": ...}`.
fn serialize_projection<S: serde::Serializer>(
    path: &Option<String>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error> {
    use serde::ser::SerializeMap;
    let mut projection = serializer.serialize_map(Some(1))?;
    projection.serialize_entry("path", path)?;
    projection.end()
}

/// A caller a store-wide scan read, with its reading narrowed to its settled
/// sites and the unsettled ones that could call the focal.
#[derive(Debug, Clone)]
pub struct ScannedCaller {
    pub entity: Entity,
    pub reading: CallerSites,
}

/// What a store-wide reading of one focal's possible callers found.
#[derive(Debug, Clone)]
pub struct FocalScan {
    /// The names a call to the focal is spelled with.
    pub names: Vec<String>,
    /// Whether the focal may be held as a value.
    pub escape: FocalEscape,
    /// Every unsettled site that could be a call to the focal, in caller
    /// file, caller name and site order.
    pub candidates: Vec<CandidateSite>,
    /// Every caller whose body could call the focal by name, or through a
    /// value when it escapes, or that a proven site calls it from, each read
    /// through the one site-state reading and narrowed.
    pub callers: Vec<ScannedCaller>,
    /// Callers some proven site calls the focal from.
    pub proven_callers: HashSet<EntityId>,
    kept: HashSet<(EntityId, u32, u32)>,
    judged: HashSet<EntityId>,
}

impl FocalScan {
    /// Whether `site` of `caller` could be a call to the focal. A caller the
    /// scan ruled out by its whole body holds no such site.
    pub fn keeps(&self, caller: EntityId, site: &CallSite) -> bool {
        self.judged.contains(&caller) && self.kept.contains(&(caller, site.offset, site.length))
    }

    /// Whether the scan read `caller`.
    pub fn read(&self, caller: EntityId) -> bool {
        self.judged.contains(&caller)
    }

    /// The tally over every caller the scan read, narrowed.
    pub fn tally(&self) -> CallSiteTally {
        let mut tally = CallSiteTally::default();
        for caller in &self.callers {
            tally.add(&caller.reading);
        }
        tally
    }

    /// Callers read that no current ledger describes.
    pub fn callers_without_current_ledger(&self) -> usize {
        self.callers
            .iter()
            .filter(|caller| {
                !matches!(
                    caller.reading,
                    CallerSites::Current(_) | CallerSites::NoSites
                )
            })
            .count()
    }
}

/// Caller bodies a store-wide reading reads to judge sites while the focal
/// is contained, past which a site keeps whatever text would have ruled out.
pub const SCAN_TEXT_READS_MAX: usize = 500;

/// The census answer of a reading that took no census: unknown, which every
/// rule reads as escaping.
pub const NO_CENSUS: FocalEscape = FocalEscape::Unknown {
    reason: "no escape census was taken for this reading",
};

/// Read every caller in the store that could be a call to `focal`, through
/// the one site-state reading, and keep each unsettled site the rule of
/// [`kin_model::site_could_call_at`] keeps under `escape`, the census answer
/// for the focal (see
/// [`crate::handlers::common::HeldSourceAuthority::escape_evidence_batch`]).
///
/// While the focal may escape, every unsettled site of every caller in the
/// calling languages is kept and no text is needed to decide; `text` then
/// only fills the callee and line of the rows a block serves. While it is
/// contained, a caller whose whole preview spells none of its call names
/// holds no site that could call it (the census saw no dynamic access in
/// the domain), and the rest are judged by their exact text, read through
/// `text`. A reader that holds no text keeps every site text would have
/// ruled out.
pub fn scan_focal<G: GraphStore + ?Sized, T: SiteText + ?Sized>(
    store: &G,
    focal: &Entity,
    text: &T,
    escape: FocalEscape,
) -> crate::error::Result<FocalScan> {
    let names = focal_call_names(focal);
    let escapes = escape.may_escape();
    let proven_callers: HashSet<EntityId> = store
        .get_all_relations_for_entity(&focal.id)
        .map_err(crate::error::McpError::graph)?
        .iter()
        .filter(|relation| {
            relation.kind == kin_model::RelationKind::Calls
                && relation.dst.as_entity() == Some(focal.id)
        })
        .filter_map(|relation| relation.src.as_entity())
        .collect();
    let entities = store
        .query_entities(&kin_model::graph::EntityFilter {
            languages: Some(calling_languages(focal.language)),
            ..Default::default()
        })
        .map_err(crate::error::McpError::graph)?;
    let facts = GraphSiteFacts::new(store);
    let mut scan = FocalScan {
        names,
        escape,
        candidates: Vec::new(),
        callers: Vec::new(),
        proven_callers,
        kept: HashSet::new(),
        judged: HashSet::new(),
    };
    if matches!(scan.escape, FocalEscape::NonCallable { .. }) {
        // Proven reference edges remain in the answer. This proof only rules
        // unproven call sites out of the focal's call domain.
        return Ok(scan);
    }
    // Each kept site with its caller's index in `scan.callers` and its key,
    // so rows sort by site and the served ones can be addressed after.
    let mut kept_sites: Vec<(CandidateSite, usize, (u32, u32))> = Vec::new();
    for entity in entities {
        let Some(span) = entity
            .span
            .as_ref()
            .filter(|span| span.start_byte < span.end_byte)
        else {
            continue;
        };
        let file = span.file.0.clone();
        if !escapes
            && !could_name_focal(&entity, &scan.names)
            && !scan.proven_callers.contains(&entity.id)
        {
            continue;
        }
        let reading = read_caller_sites(&facts, &entity);
        scan.judged.insert(entity.id);
        let Some(ledger) = reading.ledger() else {
            scan.callers.push(ScannedCaller { entity, reading });
            continue;
        };
        let recorded_only = !matches!(reading, CallerSites::Current(_));
        // While the focal is contained, text decides which sites could call
        // it. While it may escape, every unsettled site stays whatever the
        // text says, and the text of a caller that could spell a call name is
        // still read so a site whose callee spells it is told apart from one
        // kept only because the focal may be held as a value. That is what
        // puts the named sites first, where a reader looks.
        let could_name = could_name_focal(&entity, &scan.names);
        let body = if (!escapes || could_name)
            && ledger
                .sites
                .iter()
                .any(|site| recorded_only || !SiteStateKind::of(&site.state).is_settled())
        {
            exact_text(text, &entity)
        } else {
            None
        };
        let spelling = body.as_deref().or_else(|| whole_body_preview(&entity));
        let mut keys = Vec::new();
        for site in &ledger.sites {
            // A ledger under another context or none recorded its states
            // under a proof that may not hold, so a site it recorded as
            // settled is judged as a site with no answer, by its text.
            let judged = if recorded_only && SiteStateKind::of(&site.state).is_settled() {
                CallSite {
                    state: kin_model::CallSiteState::Unresolved {
                        reason: kin_model::UnresolvedReason::NoAnswer,
                    },
                    ..site.clone()
                }
            } else {
                site.clone()
            };
            let at = body
                .as_deref()
                .and_then(|body| kin_model::site_text(site, body));
            let Some(mut why) =
                kin_model::site_could_call_at(&judged, at, &scan.names, spelling, escapes)
            else {
                continue;
            };
            // A caller whose body could spell a call name but whose text was
            // not read (past the read bound) may hold a named site; saying it
            // is kept only because the focal escapes would be a guess.
            if escapes
                && could_name
                && body.is_none()
                && why == kin_model::call_site_reading::REACH_FOCAL_ESCAPES
            {
                why = kin_model::call_site_reading::REACH_TEXT_UNKNOWN;
            }
            keys.push(site.key());
            kept_sites.push((
                CandidateSite {
                    caller: entity.id,
                    caller_name: entity.name.clone(),
                    caller_file: Some(file.clone()),
                    line_in_entity: body.as_deref().and_then(|body| line_in(body, site)),
                    callee: at.filter(|text| is_identifier(text)).map(str::to_string),
                    state: reading.site_kind(site),
                    state_reason: site_state_reason(&site.state),
                    reason: why,
                },
                scan.callers.len(),
                site.key(),
            ));
        }
        let kept: HashSet<(u32, u32)> = keys.iter().copied().collect();
        for (offset, length) in keys {
            scan.kept.insert((entity.id, offset, length));
        }
        let narrowed = reading.retain_sites(|site| {
            (!recorded_only && SiteStateKind::of(&site.state).is_settled())
                || kept.contains(&site.key())
        });
        scan.callers.push(ScannedCaller {
            entity,
            reading: narrowed,
        });
    }
    kept_sites.sort_by(|(left, _, left_key), (right, _, right_key)| {
        (
            reach_rank(left.reason),
            &left.caller_file,
            &left.caller_name,
            left.caller,
            left_key,
        )
            .cmp(&(
                reach_rank(right.reason),
                &right.caller_file,
                &right.caller_name,
                right.caller,
                right_key,
            ))
    });
    // The rows a block serves are addressed inside their callers even when
    // no text was needed to keep them.
    let mut bodies: HashMap<usize, Option<String>> = HashMap::new();
    for (row, caller, (offset, length)) in kept_sites.iter_mut().take(CALL_SITE_ROWS_MAX) {
        if row.line_in_entity.is_some() {
            continue;
        }
        let body = bodies
            .entry(*caller)
            .or_insert_with(|| exact_text(text, &scan.callers[*caller].entity));
        if let Some(body) = body.as_deref() {
            let site = CallSite {
                offset: *offset,
                length: *length,
                state: kin_model::CallSiteState::ProvenOutside,
            };
            row.line_in_entity = line_in(body, &site);
            row.callee = kin_model::site_text(&site, body)
                .filter(|text| is_identifier(text))
                .map(str::to_string);
        }
    }
    scan.candidates = kept_sites.into_iter().map(|(row, _, _)| row).collect();
    Ok(scan)
}

/// How strongly a kept site's reason ties it to the focal, strongest first:
/// its callee spells a call name, then its caller's body does, then it could
/// reach the focal only through access the text cannot name, and last it is
/// kept only because the focal may be held as a value. Rows sort by this
/// before file, so the sites a reader should check come before the ones every
/// unsettled site in the store would be.
pub fn reach_rank(reason: &str) -> u8 {
    match reason {
        kin_model::call_site_reading::REACH_CALLEE_SPELLS => 0,
        kin_model::call_site_reading::REACH_BODY_SPELLS => 1,
        kin_model::call_site_reading::REACH_FOCAL_ESCAPES => 3,
        _ => 2,
    }
}

/// The line of `site` inside a caller whose exact text is `body`, counted
/// from 0 at its first line.
fn line_in(body: &str, site: &CallSite) -> Option<u64> {
    body.get(..site.offset as usize)
        .map(|before| before.matches('\n').count() as u64)
}

/// Every unsettled site in the store that could be a call to `focal`, read
/// from ledgers alone, with no text reader and no census: the focal reads as
/// escaping, so every unsettled site of the calling languages is kept.
/// [`unsettled_sites_naming_with`] is the same reading with the graph-held
/// text and the census an answer holds.
pub fn unsettled_sites_naming<G: GraphStore + ?Sized>(
    store: &G,
    focal: &Entity,
) -> crate::error::Result<Vec<CandidateSite>> {
    unsettled_sites_naming_with(store, focal, &NoSiteText, NO_CENSUS)
}

/// [`unsettled_sites_naming`] with `text`, the reader of callers' graph-held
/// text the answer already holds, under `escape`, its census for the focal.
pub fn unsettled_sites_naming_with<G: GraphStore + ?Sized, T: SiteText + ?Sized>(
    store: &G,
    focal: &Entity,
    text: &T,
    escape: FocalEscape,
) -> crate::error::Result<Vec<CandidateSite>> {
    Ok(scan_focal(store, focal, text, escape)?.candidates)
}

/// Why the store's ledgers alone do not settle who calls a focal.
pub const UNSETTLED_CANDIDATE_SITES: &str = "unsettled_candidate_sites";
/// A ledger in scope was not proven under the selected graph's validated
/// context for its language.
pub const LEDGER_NOT_UNDER_CURRENT_CONTEXT: &str = "ledger_not_under_current_context";
/// A proven site in scope names an entity the graph no longer holds.
pub const PROVEN_TARGET_NOT_LIVE: &str = "proven_target_not_live";
/// A file in scope holds call expressions no ledger attributes to a caller.
pub const UNATTRIBUTED_EXPRESSIONS: &str = "unattributed_expressions";
/// The selected graph holds no validated proof context for the focal's
/// language, or for a caller's.
pub const NO_VALIDATED_CONTEXT: &str = "no_validated_context";
/// A caller whose body could call the focal has no ledger at all: its
/// derivation or enrichment is owed, or no resolver can prove its sites.
pub const CALLERS_WITHOUT_LEDGER: &str = "callers_without_ledger";

/// Whether the store's call-site ledgers alone settle who calls a focal.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct CallsEvidence {
    /// True only when every condition below holds.
    pub settled: bool,
    /// Store-wide unsettled sites that could be calls to the focal.
    pub candidates: Vec<CandidateSite>,
    /// Why it is not settled, each once, in this order:
    /// [`UNSETTLED_CANDIDATE_SITES`], [`CALLERS_WITHOUT_LEDGER`],
    /// [`NO_VALIDATED_CONTEXT`], [`LEDGER_NOT_UNDER_CURRENT_CONTEXT`],
    /// [`PROVEN_TARGET_NOT_LIVE`], [`UNATTRIBUTED_EXPRESSIONS`].
    pub unsettled_because: Vec<&'static str>,
    /// Callers whose ledgers were read.
    pub callers_read: usize,
    /// Whether the focal may be held as a value, which widens which sites
    /// could call it.
    pub escape: FocalEscape,
}

/// Whether the store's call-site ledgers alone settle who calls `focal`,
/// with no text reader (see [`unsettled_sites_naming`]).
pub fn calls_evidence_for<G: GraphStore + ?Sized>(
    store: &G,
    focal: &Entity,
) -> crate::error::Result<CallsEvidence> {
    calls_evidence_for_with(store, focal, &NoSiteText, NO_CENSUS)
}

/// [`calls_evidence_for`] with `text`, the reader of callers' graph-held
/// text the answer already holds, under `escape`, its census for the focal.
///
/// Candidate rows are narrowed by which sites could call the focal. The
/// replacement proof separately audits every entity and file in the potential
/// calling-language domain, including empty ledgers and files with no candidate
/// rows. Never the import family, and never an empty tally read as settled. It
/// is settled only when:
///
/// 1. no unsettled site anywhere could be a call to the focal;
/// 2. no caller that could call it lacks a ledger;
/// 3. every ledger in scope was proven under the selected graph's validated
///    context for its language, the focal's own language included;
/// 4. every proven target in those ledgers names an entity the graph holds;
/// 5. every graph-owned file in the potential calling-language domain
///    attributes each parsed call expression to a caller: its ledgers'
///    censuses add up to the parse-side count stamped on the file. An
///    unavailable inventory or a file with no parse census is not complete.
pub fn calls_evidence_for_with<G: GraphStore + ?Sized, T: SiteText + ?Sized>(
    store: &G,
    focal: &Entity,
    text: &T,
    escape: FocalEscape,
) -> crate::error::Result<CallsEvidence> {
    let scan = scan_focal(store, focal, text, escape)?;
    Ok(calls_evidence_from(store, focal, &scan))
}

/// [`calls_evidence_for_with`] over a scan the answer already took.
pub fn calls_evidence_from<G: GraphStore + ?Sized>(
    store: &G,
    focal: &Entity,
    scan: &FocalScan,
) -> CallsEvidence {
    let facts = GraphSiteFacts::new(store);
    let mut because: Vec<&'static str> = Vec::new();
    let mut add = |reason: &'static str| {
        if !because.contains(&reason) {
            because.push(reason);
        }
    };
    if !scan.candidates.is_empty() {
        add(UNSETTLED_CANDIDATE_SITES);
    }
    // Candidate rows are a result, not a completeness census. An empty stale
    // ledger or an unattributed expression produces no row but still prevents
    // replacing the store's binding proof. Audit the full calling-language
    // domain, including entities the name filter correctly omitted from rows.
    let in_scope: Vec<ScannedCaller> = match store.query_entities(&kin_model::graph::EntityFilter {
        languages: Some(calling_languages(focal.language)),
        ..Default::default()
    }) {
        Ok(entities) => entities
            .into_iter()
            .map(|entity| {
                let reading = read_caller_sites(&facts, &entity);
                ScannedCaller { entity, reading }
            })
            .collect(),
        Err(_) => {
            add(UNATTRIBUTED_EXPRESSIONS);
            Vec::new()
        }
    };
    if in_scope.iter().any(|caller| {
        matches!(
            caller.reading,
            CallerSites::OwedDerivation
                | CallerSites::OwedEnrichment
                | CallerSites::NoResolver { .. }
        )
    }) {
        add(CALLERS_WITHOUT_LEDGER);
    }
    if facts.current_context(focal.language).is_none() {
        add(NO_VALIDATED_CONTEXT);
    }
    let mut files: BTreeMap<String, ()> = BTreeMap::new();
    // The resolved tree also holds admitted files with no entity rows. Their
    // missing parse-side census is a gap, not evidence of zero expressions.
    match store.resolved_tree_snapshot() {
        Ok(Some(tree)) => {
            let languages = calling_languages(focal.language);
            for artifact in tree.artifacts() {
                if !matches!(artifact.entry, kin_model::TreeEntry::Blob { .. }) {
                    continue;
                }
                // Extensions are ASCII even when the filename is not UTF-8.
                // Classify that suffix first: an unrelated raw-byte asset is
                // outside this proof, but an unreadable source path is a gap.
                let bytes = artifact.path.as_bytes();
                let language = bytes
                    .iter()
                    .rposition(|byte| *byte == b'.')
                    .and_then(|at| std::str::from_utf8(&bytes[at..]).ok())
                    .and_then(kin_model::language_of_path);
                if !language.is_some_and(|language| languages.contains(&language)) {
                    continue;
                }
                let Some(path) = artifact.path.as_utf8() else {
                    add(UNATTRIBUTED_EXPRESSIONS);
                    continue;
                };
                files.insert(path.to_owned(), ());
            }
        }
        _ => add(UNATTRIBUTED_EXPRESSIONS),
    }
    let mut callers_read = 0usize;
    for caller in &in_scope {
        // NoSites is valid only with its file's zero-call census. Keep that
        // file in the audit even though it has no ledger and no candidate.
        if let Some(file) = caller
            .entity
            .file_origin
            .as_ref()
            .or_else(|| caller.entity.span.as_ref().map(|span| &span.file))
        {
            files.insert(file.0.clone(), ());
        }
        let Some(ledger) = caller.reading.ledger() else {
            continue;
        };
        callers_read += 1;
        match &caller.reading {
            CallerSites::Current(_) => {}
            CallerSites::Unverified { .. } => add(NO_VALIDATED_CONTEXT),
            _ => add(LEDGER_NOT_UNDER_CURRENT_CONTEXT),
        }
        // The full reading retains every proven target, including sites
        // unrelated to the focal whose liveness still supports this proof.
        if ledger.sites.iter().any(|site| match site.state {
            kin_model::CallSiteState::ProvenTarget { target }
            | kin_model::CallSiteState::ProvenDeclaration {
                declaration: target,
                ..
            } => !matches!(store.get_entity(&target), Ok(Some(_))),
            _ => false,
        }) {
            add(PROVEN_TARGET_NOT_LIVE);
        }
    }
    for file in files.keys() {
        if !file_attributes_every_call(store, &facts, file) {
            add(UNATTRIBUTED_EXPRESSIONS);
            break;
        }
    }
    CallsEvidence {
        settled: because.is_empty(),
        candidates: scan.candidates.clone(),
        unsettled_because: because,
        callers_read,
        escape: scan.escape.clone(),
    }
}

/// Whether every call expression the parser read in `file` belongs to a
/// ledger: the censuses of its entities' current ledgers add up to at least
/// the parse-side count stamped on the file. A file with no parse-side count,
/// or with an entity whose ledger is not current, cannot show it.
fn file_attributes_every_call<G: GraphStore + ?Sized>(
    store: &G,
    facts: &GraphSiteFacts<'_, G>,
    file: &str,
) -> bool {
    let Ok(entities) = store.query_entities(&kin_model::graph::EntityFilter {
        file_path: Some(kin_model::FilePathId::new(file)),
        ..Default::default()
    }) else {
        return false;
    };
    let Some(parsed) = entities.iter().find_map(|entity| {
        entity
            .metadata
            .extra
            .get(kin_model::call_site_reading::FILE_PARSED_CALL_SITES_KEY)
            .and_then(Value::as_u64)
    }) else {
        return false;
    };
    let mut census = 0u64;
    for entity in &entities {
        match read_caller_sites(facts, entity) {
            CallerSites::Current(ledger) => census += u64::from(ledger.census),
            CallerSites::NoSites => {}
            _ => return false,
        }
    }
    census >= parsed
}

/// The block `find_references` serves for a focal: the tally over every
/// caller in the store that could call it, narrowed to the sites that could,
/// and one row per unsettled site that could be a call to it, at most
/// [`CALL_SITE_CANDIDATE_SAMPLE_MAX`] of them. The block is unsettled exactly while its
/// clauses name something, and any candidate row is such a site.
pub fn named_block(scan: &FocalScan) -> Value {
    let tally = scan.tally();
    let mut block = block_json(&tally, NAMED_SCOPE);
    block["call_names"] = json!(scan.names);
    block["focal_escape"] = json!(scan.escape);
    block["candidate_count"] = json!(scan.candidates.len());
    let mut by_reason: BTreeMap<&str, usize> = BTreeMap::new();
    for candidate in &scan.candidates {
        *by_reason.entry(candidate.reason).or_default() += 1;
    }
    block["candidates_by_reason"] = json!(by_reason);
    block["candidates"] = json!(scan
        .candidates
        .iter()
        .take(CALL_SITE_CANDIDATE_SAMPLE_MAX)
        .collect::<Vec<_>>());
    let withheld = scan
        .candidates
        .len()
        .saturating_sub(CALL_SITE_CANDIDATE_SAMPLE_MAX);
    if withheld > 0 {
        block["candidates_withheld"] = json!(withheld);
    }
    block
}

// ── Text ──────────────────────────────────────────────────────────────────

/// Candidate rows a terminal answer lists before saying how many more.
pub const CANDIDATE_LINES_MAX: usize = 20;

/// The unsettled call sites a store-wide reading kept, in plain words for a
/// person at a terminal: the ones whose callee or caller body spells the
/// focal's name, each at its caller and its line in that caller, then every
/// other one counted by why it is kept. Empty when the reading kept none.
pub fn candidate_lines(scan: &FocalScan, focal_name: &str) -> Vec<String> {
    use kin_model::call_site_reading::{
        REACH_BODY_SPELLS, REACH_CALLEE_SPELLS, REACH_FOCAL_ESCAPES,
    };
    if scan.candidates.is_empty() {
        return Vec::new();
    }
    let names_it = |reason: &str| reason == REACH_CALLEE_SPELLS || reason == REACH_BODY_SPELLS;
    let named: Vec<&CandidateSite> = scan
        .candidates
        .iter()
        .filter(|candidate| names_it(candidate.reason))
        .collect();
    let mut lines = vec![format!(
        "Unproven call sites that could call {focal_name}: {}.",
        scan.candidates.len()
    )];
    if !named.is_empty() {
        lines.push(format!(
            "  {} name {focal_name}, so check them first:",
            named.len()
        ));
        for candidate in named.iter().take(CANDIDATE_LINES_MAX) {
            let at = candidate
                .line_in_entity
                .map(|line| format!(", line {line} in it"))
                .unwrap_or_default();
            let callee = candidate
                .callee
                .as_deref()
                .map(|callee| format!(" calls {callee}"))
                .unwrap_or_default();
            let why = candidate
                .state_reason
                .as_deref()
                .map(|reason| format!(" ({})", reason.replace('_', " ")))
                .unwrap_or_default();
            lines.push(format!(
                "    {}{at}{callee}, {}{why}",
                candidate.caller_name,
                candidate.state.wire().replace('_', " ")
            ));
        }
        if named.len() > CANDIDATE_LINES_MAX {
            lines.push(format!(
                "    and {} more that name it.",
                named.len() - CANDIDATE_LINES_MAX
            ));
        }
    }
    let mut rest: BTreeMap<&str, usize> = BTreeMap::new();
    for candidate in scan.candidates.iter().filter(|c| !names_it(c.reason)) {
        *rest.entry(candidate.reason).or_default() += 1;
    }
    for (reason, count) in rest {
        let line = if reason == REACH_FOCAL_ESCAPES {
            let census = match &scan.escape {
                FocalEscape::Unknown { reason } => {
                    format!("this graph cannot rule that out ({reason})")
                }
                FocalEscape::Escapes { reason } => format!("it may be ({reason})"),
                FocalEscape::Contained { .. } | FocalEscape::NonCallable { .. } => {
                    "it is not".to_string()
                }
            };
            format!(
                "  {count} more could reach it only if {focal_name} is held as a value, and {census}."
            )
        } else {
            format!("  {count} more are kept because of {reason}.")
        };
        lines.push(line);
    }
    lines
}

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
        // This fixture admits a resolver's completed evidence, including its
        // validation. Tests for legacy/missing validation remove that record.
        let validations: Vec<_> = records
            .iter()
            .filter_map(|record| record.as_proof_context())
            .map(|context| {
                ResolutionRecord::ContextValidation(kin_model::ContextValidation {
                    language: context.language,
                    state: kin_model::ContextValidationState::Validated {
                        context: context.clone(),
                    },
                })
            })
            .collect();
        let mut records = records;
        records.extend(validations);
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

    fn census_entity(
        name: &str,
        file: &str,
        language: LanguageId,
        body: &str,
        parsed: u64,
    ) -> Entity {
        let mut entity = spanned_entity(name, file, language, 0, body);
        entity.metadata.extra.insert(
            kin_model::call_site_reading::FILE_PARSED_CALL_SITES_KEY.into(),
            json!(parsed),
        );
        entity
    }

    #[test]
    fn calls_evidence_audits_empty_stale_and_unverified_domain_ledgers() {
        use kin_model::{ResolutionRecord, ResolutionRecordDelta};
        for unverified in [false, true] {
            let store = InMemoryGraph::new();
            let focal = census_entity(
                "target",
                "target.ts",
                LanguageId::TypeScript,
                "function target() {}",
                0,
            );
            // JavaScript can call TypeScript. Its absent validation must not be
            // hidden by the focal language's independently valid context.
            let caller_language = if unverified {
                LanguageId::JavaScript
            } else {
                LanguageId::TypeScript
            };
            let caller = census_entity(
                "unrelated",
                "caller.js",
                caller_language,
                "function unrelated() {}",
                0,
            );
            let focal_context = proof_context(LanguageId::TypeScript, "current");
            let caller_context = proof_context(caller_language, "current");
            let caller_record = ledger(&caller, "", caller_context.id(), vec![]);
            admit(
                &store,
                &[&focal, &caller],
                vec![
                    focal_context.clone(),
                    ledger(&focal, "", focal_context.id(), vec![]),
                ],
            );
            admit(
                &store,
                &[],
                vec![caller_context.clone(), caller_record.clone()],
            );
            assert!(calls_evidence_for(&store, &focal).unwrap().settled);
            let changes = if unverified {
                let old = store
                    .lookup_resolution_record(&ResolutionRecordId::context_validation(
                        caller_language,
                    ))
                    .unwrap()
                    .unwrap();
                vec![ResolutionRecordDelta::Removed { old }]
            } else {
                let old_context = proof_context(caller_language, "old");
                let mut old_ledger = caller_record.clone();
                let ResolutionRecord::CallSites(record) = &mut old_ledger else {
                    unreachable!()
                };
                record.context = old_context.id();
                vec![
                    ResolutionRecordDelta::Added { new: old_context },
                    ResolutionRecordDelta::Modified {
                        old: caller_record,
                        new: old_ledger,
                    },
                ]
            };
            store
                .apply_transaction_delta(&TransactionDelta {
                    resolution_record_deltas: changes,
                    ..Default::default()
                })
                .unwrap();
            let evidence = calls_evidence_for(&store, &focal).unwrap();
            assert!(evidence.candidates.is_empty());
            assert!(!evidence.settled);
            assert!(
                evidence.unsettled_because.contains(&if unverified {
                    NO_VALIDATED_CONTEXT
                } else {
                    LEDGER_NOT_UNDER_CURRENT_CONTEXT
                }),
                "{evidence:?}"
            );
        }
    }

    #[test]
    fn calls_evidence_audits_unattributed_files_omitted_from_candidate_rows() {
        for proven_outside in [false, true] {
            let store = InMemoryGraph::new();
            let focal = census_entity(
                "target",
                "target.ts",
                LanguageId::TypeScript,
                "function target() {}",
                0,
            );
            let body = "function unrelated() { external(); hidden(); }";
            let mut caller =
                census_entity("unrelated", "caller.ts", LanguageId::TypeScript, body, 2);
            caller.metadata.extra.insert(
                kin_parser::extract::EMBEDDING_BODY_PREVIEW_KEY.into(),
                json!(body),
            );
            let context = proof_context(LanguageId::TypeScript, "current");
            admit(
                &store,
                &[&focal, &caller],
                vec![
                    context.clone(),
                    ledger(&focal, "", context.id(), vec![]),
                    ledger(
                        &caller,
                        body,
                        context.id(),
                        if proven_outside {
                            vec![("external", CallSiteState::ProvenOutside)]
                        } else {
                            vec![]
                        },
                    ),
                ],
            );
            let scan = scan_focal(
                &store,
                &focal,
                &NoSiteText,
                FocalEscape::Contained {
                    entities_checked: 2,
                },
            )
            .unwrap();
            assert!(scan.candidates.is_empty());
            assert!(
                !scan
                    .callers
                    .iter()
                    .any(|scanned| scanned.entity.id == caller.id),
                "the unrelated preview is omitted from focal candidate rows"
            );
            let evidence = calls_evidence_from(&store, &focal, &scan);
            assert!(!evidence.settled);
            assert!(
                evidence
                    .unsettled_because
                    .contains(&UNATTRIBUTED_EXPRESSIONS),
                "{evidence:?}"
            );
        }
    }

    #[test]
    fn calls_evidence_includes_calling_domain_files_without_entities() {
        let store = InMemoryGraph::new();
        let focal = census_entity(
            "target",
            "target.ts",
            LanguageId::TypeScript,
            "function target() {}",
            0,
        );
        let context = proof_context(LanguageId::TypeScript, "current");
        admit(
            &store,
            &[&focal],
            vec![context.clone(), ledger(&focal, "", context.id(), vec![])],
        );
        assert!(calls_evidence_for(&store, &focal).unwrap().settled);
        store
            .apply_transaction_delta(&TransactionDelta {
                tree_deltas: vec![kin_model::TreeDelta::Added {
                    artifact_id: kin_model::ArtifactId::new(),
                    new: kin_model::LocatedEntry::new(
                        kin_model::RepoPath::from_utf8("unattributed.js").unwrap(),
                        kin_model::TreeEntry::blob(
                            kin_model::Hash256::from_bytes([0x61; 32]),
                            false,
                        ),
                    ),
                }],
                ..Default::default()
            })
            .unwrap();
        let evidence = calls_evidence_for(&store, &focal).unwrap();
        assert!(evidence.candidates.is_empty());
        assert!(!evidence.settled);
        assert!(
            evidence
                .unsettled_because
                .contains(&UNATTRIBUTED_EXPRESSIONS),
            "{evidence:?}"
        );
    }

    #[test]
    fn calls_evidence_raw_byte_paths_only_bound_calling_domain_blobs() {
        let cases: &[(&[u8], bool, bool)] = &[
            (b"assets/\xff.png", false, true),
            (b"other/\xff.py", false, true),
            (b"src/\xff.ts", false, false),
            (b"src/\xff.js", false, false),
            (b"src/\xff.ts", true, true),
            (b"src/linked.ts", true, true),
        ];
        for &(path, symlink, settled) in cases {
            let store = InMemoryGraph::new();
            let focal = census_entity(
                "target",
                "target.ts",
                LanguageId::TypeScript,
                "function target() {}",
                0,
            );
            let context = proof_context(LanguageId::TypeScript, "current");
            admit(
                &store,
                &[&focal],
                vec![context.clone(), ledger(&focal, "", context.id(), vec![])],
            );
            let hash = kin_model::Hash256::from_bytes([0x62; 32]);
            store
                .apply_transaction_delta(&TransactionDelta {
                    tree_deltas: vec![kin_model::TreeDelta::Added {
                        artifact_id: kin_model::ArtifactId::new(),
                        new: kin_model::LocatedEntry::new(
                            kin_model::RepoPath::from_bytes(path).unwrap(),
                            if symlink {
                                kin_model::TreeEntry::symlink(hash)
                            } else {
                                kin_model::TreeEntry::blob(hash, false)
                            },
                        ),
                    }],
                    ..Default::default()
                })
                .unwrap();
            let evidence = calls_evidence_for(&store, &focal).unwrap();
            assert_eq!(
                evidence.settled, settled,
                "{path:?}, symlink={symlink}: {evidence:?}"
            );
            assert!(evidence.candidates.is_empty());
            assert_eq!(
                evidence
                    .unsettled_because
                    .contains(&UNATTRIBUTED_EXPRESSIONS),
                !settled
            );
        }
    }

    #[test]
    fn calls_evidence_keeps_true_no_sites_and_current_empty_ledgers_settled() {
        for empty_ledger in [false, true] {
            let store = InMemoryGraph::new();
            let focal = census_entity(
                "target",
                "target.ts",
                LanguageId::TypeScript,
                "function target() {}",
                0,
            );
            let caller = census_entity(
                "unrelated",
                "caller.ts",
                LanguageId::TypeScript,
                "function unrelated() {}",
                0,
            );
            let context = proof_context(LanguageId::TypeScript, "current");
            let mut records = vec![context.clone()];
            if empty_ledger {
                records.extend([
                    ledger(&focal, "", context.id(), vec![]),
                    ledger(&caller, "", context.id(), vec![]),
                ]);
            }
            admit(&store, &[&focal, &caller], records);
            let facts = GraphSiteFacts::new(&store);
            if !empty_ledger {
                assert!(matches!(
                    read_caller_sites(&facts, &caller),
                    CallerSites::NoSites
                ));
            }
            let evidence = calls_evidence_for(&store, &focal).unwrap();
            assert!(evidence.settled, "{evidence:?}");
            assert!(evidence.candidates.is_empty());
            assert_eq!(evidence.callers_read, if empty_ledger { 2 } else { 0 });
        }
    }

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
    struct Body<'a>(&'a str);

    impl SiteText for Body<'_> {
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
    fn non_callable_binding_removes_uncertain_calls_without_weakening_the_strict_audit() {
        let fixture = fixture(false);
        let before = scan_focal(&fixture.store, &fixture.helper, &Body(BODY), NO_CENSUS).unwrap();
        assert!(!before.callers.is_empty());
        let proof = FocalEscape::NonCallable {
            reason: "the selected parser census proves a scalar binding",
            entities_checked: 2,
        };
        let scan = scan_focal(&fixture.store, &fixture.helper, &Body(BODY), proof).unwrap();
        assert!(scan.candidates.is_empty());
        assert!(scan.callers.is_empty());
        assert_eq!(scan.proven_callers, before.proven_callers);
        let block = named_block(&scan);
        assert_eq!(block["settled"], true);
        assert_eq!(block["focal_escape"]["escape"], "non_callable");
        let strict = calls_evidence_from(&fixture.store, &fixture.helper, &scan);
        assert!(!strict.settled);
        assert!(strict.unsettled_because.contains(&CALLERS_WITHOUT_LEDGER));
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
    fn a_site_whose_callee_spells_the_focal_is_listed_before_escape_only_sites() {
        use kin_model::call_site_reading::{REACH_CALLEE_SPELLS, REACH_FOCAL_ESCAPES};
        let fixture = fixture(true);
        let focal = spanned_entity(
            "mystery",
            "lib.py",
            LanguageId::Python,
            0,
            "def mystery(data):\n    pass\n",
        );
        // A census that cannot rule escape out keeps every unsettled site, and
        // the one whose callee spells the focal's name still comes first.
        let escape = FocalEscape::Unknown {
            reason: "dynamic reflective access in the domain",
        };
        let scan = scan_focal(&fixture.store, &focal, &Body(BODY), escape).unwrap();
        let rows: Vec<(Option<&str>, &str)> = scan
            .candidates
            .iter()
            .map(|candidate| (candidate.callee.as_deref(), candidate.reason))
            .collect();
        assert_eq!(
            rows,
            vec![
                (Some("mystery"), REACH_CALLEE_SPELLS),
                (Some("handler"), REACH_FOCAL_ESCAPES),
            ]
        );
        let block = named_block(&scan);
        assert_eq!(block["candidate_count"], 2, "{block}");
        assert_eq!(
            block["candidates_by_reason"][REACH_CALLEE_SPELLS], 1,
            "{block}"
        );
        assert_eq!(
            block["candidates_by_reason"][REACH_FOCAL_ESCAPES], 1,
            "{block}"
        );
    }

    #[test]
    fn named_candidate_samples_preserve_the_full_census_and_uncertainty() {
        for site_count in [0, 3, 5, 613] {
            let store = InMemoryGraph::new();
            let body = format!("def run():\n{}", "    mystery()\n".repeat(site_count));
            let caller = spanned_entity("run", "app.py", LanguageId::Python, 0, &body);
            let focal = spanned_entity(
                "mystery",
                "lib.py",
                LanguageId::Python,
                0,
                "def mystery(): pass\n",
            );
            let context = proof_context(LanguageId::Python, "current");
            let records = vec![
                context.clone(),
                ledger(
                    &caller,
                    &body,
                    context.id(),
                    (0..site_count)
                        .map(|_| {
                            (
                                "mystery",
                                CallSiteState::Unresolved {
                                    reason: UnresolvedReason::NoAnswer,
                                },
                            )
                        })
                        .collect(),
                ),
            ];
            admit(&store, &[&caller], records);
            let scan = scan_focal(
                &store,
                &focal,
                &Body(&body),
                FocalEscape::Unknown {
                    reason: "dynamic reflective access in the domain",
                },
            )
            .unwrap();
            assert_eq!(scan.candidates.len(), site_count);
            let block = named_block(&scan);
            // Sampling presentation must not change any whole-scan truth.
            for (key, value) in block_json(&scan.tally(), NAMED_SCOPE).as_object().unwrap() {
                assert_eq!(&block[key], value, "{key}, {site_count}");
            }
            let kept = site_count.min(5);
            assert_eq!(block["candidates"], json!(&scan.candidates[..kept]));
            assert_eq!(block["candidate_count"], site_count);
            assert_eq!(
                block["candidates_withheld"].as_u64().unwrap_or(0),
                (site_count - kept) as u64
            );
            assert_eq!(
                block["candidates_by_reason"]
                    .as_object()
                    .unwrap()
                    .values()
                    .map(|count| count.as_u64().unwrap())
                    .sum::<u64>(),
                site_count as u64
            );
            if site_count > 0 {
                assert_eq!(block["settled"], false);
                assert!(!block["clauses"].as_array().unwrap().is_empty());
                assert_eq!(block["sites"], site_count);
            } else {
                assert!(block.get("candidates_withheld").is_none());
            }
        }
    }

    #[test]
    fn a_terminal_lists_the_named_candidates_and_counts_the_rest() {
        let fixture = fixture(true);
        let focal = spanned_entity(
            "mystery",
            "lib.py",
            LanguageId::Python,
            0,
            "def mystery(data):\n    pass\n",
        );
        let escape = FocalEscape::Unknown {
            reason: "dynamic reflective access in the domain",
        };
        let scan = scan_focal(&fixture.store, &focal, &Body(BODY), escape).unwrap();
        assert_eq!(
            candidate_lines(&scan, "mystery"),
            vec![
                "Unproven call sites that could call mystery: 2.".to_string(),
                "  1 name mystery, so check them first:".to_string(),
                "    run, line 4 in it calls mystery, unresolved (no answer)".to_string(),
                "  1 more could reach it only if mystery is held as a value, and this graph \
                 cannot rule that out (dynamic reflective access in the domain)."
                    .to_string(),
            ]
        );
    }

    /// A candidate row is addressed by its caller's id and its line in that
    /// caller. Its file rides only as the labelled projection every reference
    /// row serves, never as a bare path.
    #[test]
    fn a_candidate_row_serves_its_file_as_a_projection() {
        let fixture = fixture(true);
        let focal = spanned_entity(
            "mystery",
            "lib.py",
            LanguageId::Python,
            0,
            "def mystery(data):\n    pass\n",
        );
        let escape = FocalEscape::Unknown {
            reason: "dynamic reflective access in the domain",
        };
        let scan = scan_focal(&fixture.store, &focal, &Body(BODY), escape).unwrap();
        let block = named_block(&scan);
        let rows = block["candidates"].as_array().expect("candidate rows");
        assert!(!rows.is_empty(), "{block}");
        for row in rows {
            assert!(row.get("caller_file").is_none(), "{row}");
            assert!(row.get("file_path").is_none(), "{row}");
            assert!(
                row["projection"]["path"].is_string(),
                "the caller's file is a labelled projection: {row}"
            );
            assert!(row["caller"].is_string(), "{row}");
        }
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

    fn set_validation(store: &InMemoryGraph, state: Option<kin_model::ContextValidationState>) {
        use kin_model::{EntityStore, ResolutionRecord, ResolutionRecordDelta};
        let id = ResolutionRecordId::context_validation(LanguageId::Python);
        let old = store.lookup_resolution_record(&id).unwrap();
        let new = state.map(|state| {
            ResolutionRecord::ContextValidation(kin_model::ContextValidation {
                language: LanguageId::Python,
                state,
            })
        });
        let delta = match (old, new) {
            (Some(old), Some(new)) => ResolutionRecordDelta::Modified { old, new },
            (None, Some(new)) => ResolutionRecordDelta::Added { new },
            (Some(old), None) => ResolutionRecordDelta::Removed { old },
            (None, None) => return,
        };
        store
            .apply_transaction_delta(&kin_model::TransactionDelta {
                resolution_record_deltas: vec![delta],
                ..Default::default()
            })
            .unwrap();
    }

    #[test]
    fn context_validation_selected_graph_controls_stale_and_current_readings() {
        let fixture = fixture(true);
        let newer = proof_context(LanguageId::Python, "1.1.401");
        set_validation(
            &fixture.store,
            Some(kin_model::ContextValidationState::Validated {
                context: newer.as_proof_context().unwrap().clone(),
            }),
        );
        let block = focal_block(&fixture.store, &fixture.run, &Body(BODY));
        assert_eq!(block["reading"], "proof_context_stale", "{block}");
        assert_eq!(block["callers_stale"], 1);
        assert_eq!(block["by_state"]["proof_context_stale"], 4);
        assert_eq!(block["rows"][0]["recorded_state"], "proven_target");
        assert_eq!(block["stale_context"], fixture.context.to_string());

        let historical = self::fixture(true);
        // Publishing another resolver's context cannot change this selected graph.
        publish_current_proof_contexts(HashMap::from([(LanguageId::Python, newer.id())]));
        let block = focal_block(&historical.store, &historical.run, &Body(BODY));
        publish_current_proof_contexts(HashMap::new());
        assert_eq!(block["reading"], "current", "{block}");
    }

    #[test]
    fn context_validation_missing_or_unverified_survives_reopen_and_preserves_proof() {
        for state in [
            None,
            Some(kin_model::ContextValidationState::Unverified {
                reason: "server could not start; validation not completed".into(),
            }),
        ] {
            let fixture = fixture(true);
            set_validation(&fixture.store, state.clone());
            let reopened = InMemoryGraph::from_snapshot(fixture.store.to_snapshot()).unwrap();
            let block = focal_block(&reopened, &fixture.run, &Body(BODY));
            assert_eq!(block["reading"], "proof_context_unverified", "{block}");
            assert_eq!(block["settled"], false);
            assert_eq!(block["callers_unverified"], 1);
            assert_eq!(block["by_state"]["proof_context_unverified"], 4);
            assert_eq!(block["rows"][0]["recorded_state"], "proven_target");
            assert!(!block["rows"][0]["target"].is_null());
            assert_eq!(block["unverified_context"], fixture.context.to_string());
            assert!(block["clauses"][0]
                .as_str()
                .unwrap()
                .starts_with("proof_context_unverified:"));
            assert!(!block["clauses"][0].as_str().unwrap().contains("; "));
            if state.is_some() {
                assert_eq!(
                    block["validation_reason"],
                    "server could not start; validation not completed"
                );
            } else {
                assert!(block["validation_reason"]
                    .as_str()
                    .unwrap()
                    .contains("no recorded"));
            }
            assert!(!owed_files(&reopened, std::slice::from_ref(&fixture.run)).is_empty());
            let good = self::fixture(true);
            let good_reopened = InMemoryGraph::from_snapshot(good.store.to_snapshot()).unwrap();
            assert_eq!(
                focal_block(&good_reopened, &good.run, &Body(BODY))["reading"],
                "current"
            );
        }
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
        // The graph names the focal by its owner, but an ordinary method
        // call spells the member, so derive its call names from the entity.
        let mut focal = super::fixture::spanned_entity(
            "App.ensure_sync",
            "pkg/app.py",
            kin_model::LanguageId::Python,
            0,
            "def ensure_sync(self, f): return f",
        );
        focal.kind = kin_model::EntityKind::Method;
        let names = super::focal_call_names(&focal);
        let owed = super::owed_outside(
            &graph,
            kin_model::LanguageId::Python,
            &std::collections::HashSet::new(),
            &names,
        )
        .expect("the index reads");
        let files: Vec<&str> = owed.iter().map(|file| file.file.as_str()).collect();
        assert_eq!(
            files,
            ["pkg/cut_short.py", "pkg/names_it.py", "pkg/no_preview.py"],
            "{owed:?}"
        );
    }

    /// An ordinary method call spells its member, while a constructor may
    /// spell the owner instead. Qualified owners alone must not widen a method.
    #[test]
    fn a_focal_is_named_by_every_segment_a_call_may_spell() {
        use kin_model::EntityKind;
        fn names(name: &str, kind: EntityKind) -> Vec<String> {
            let mut focal = super::fixture::spanned_entity(
                name,
                "pkg/focal.py",
                kin_model::LanguageId::Python,
                0,
                "def f(): pass",
            );
            focal.kind = kind;
            super::focal_call_names(&focal)
        }
        assert_eq!(
            names("App.ensure_sync", EntityKind::Method),
            ["ensure_sync"]
        );
        assert_eq!(names("Store::open", EntityKind::Method), ["open"]);
        assert_eq!(names("parse_note", EntityKind::Function), ["parse_note"]);
        assert_eq!(names("Trailing.", EntityKind::Class), ["Trailing"]);
        assert_eq!(
            names("HTTPAdapter.__init__", EntityKind::Method),
            ["HTTPAdapter", "__init__"]
        );

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
        assert!(super::could_name_focal(
            &constructs,
            &names("HTTPAdapter.__init__", EntityKind::Method)
        ));
        let sends = entity("def go(self): return self.send(req)");
        assert!(super::could_name_focal(
            &sends,
            &names("Session.send", EntityKind::Method)
        ));
        let unrelated = entity("def go(): return print(1)");
        assert!(!super::could_name_focal(
            &unrelated,
            &names("Session.send", EntityKind::Method)
        ));
        let owner_only = entity("def go(): return Session()");
        assert!(!super::could_name_focal(
            &owner_only,
            &names("Session.send", EntityKind::Method)
        ));
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
