// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The one reading of a call site's state that every surface serves.
//!
//! A caller's [`CallSiteLedger`] holds one state for each call expression the
//! parser reads in its body. What a reader serves for a site is that state,
//! unless something about the caller makes the ledger's answer not the
//! current one. The order is fixed, and MCP, the CLI and the `_kin` envelope
//! all read through [`read_caller_sites`] so they cannot disagree about it:
//!
//! 1. the caller's file holds bytes its entities were not derived from: its
//!    derivation is owed, and nothing about its sites is known;
//! 2. the graph holds no ledger for the caller: its enrichment is owed, unless
//!    no resolver for its language can prove anything on this host now
//!    (enrichment is switched off, no language server serves the language,
//!    or the one that does cannot start, say for a missing analysis
//!    environment), in which case its sites are unproven and waiting will
//!    not settle them;
//! 3. the ledger was proven under a proof context its resolver no longer runs
//!    under: every site reads as stale;
//! 4. otherwise, each site reads as the state its ledger records.
//!
//! A caller with no source span holds no text and so no call site, and
//! neither does one in a file the parser read no call expression in, which a
//! sweep leaves without ledgers.
//!
//! [`CallSiteTally`] adds readings up for an answer's scope and names the
//! verdict clauses they call for: an answer is inconclusive while a site in
//! its scope is owed, unresolved, server-failed, not in any build, a binding
//! that proves no target, or proven under a stale context.

use std::collections::BTreeMap;

use serde::Serialize;

use crate::{CallSite, CallSiteLedger, CallSiteState, Entity, EntityId, LanguageId};
use crate::{ResolutionRecordId, ServerFailure, UnresolvedReason};

/// Verdict clause: a site in scope belongs to a caller whose sites the graph
/// has not settled yet, because its derivation or its enrichment is owed and
/// a sweep will still reach it.
pub const CALL_SITES_OWED: &str = "call_sites_owed";
/// Verdict clause: a caller in scope holds no ledger and no resolver for its
/// language can prove its sites on this host now (see [`NoResolver`]), so
/// waiting for enrichment will not settle them.
pub const CALL_SITES_UNPROVEN_NO_RESOLVER: &str = "call_sites_unproven_no_resolver";
/// Verdict clause: a site in scope got an answer that proves no target.
pub const CALL_SITES_UNRESOLVED: &str = "call_sites_unresolved";
/// Verdict clause: the resolver timed out, crashed or broke protocol at a
/// site in scope.
pub const CALL_SITES_SERVER_FAILED: &str = "call_sites_server_failed";
/// Verdict clause: a site in scope is in a file no build compiles.
pub const CALL_SITES_NOT_IN_BUILD: &str = "call_sites_not_in_build";
/// Verdict clause: a site in scope was proven under a proof context its
/// resolver no longer runs under.
pub const PROOF_CONTEXT_STALE: &str = "proof_context_stale";
/// Verdict clause: a site in scope calls through a value binding, which
/// proves no target.
pub const BINDING_UNPROVEN: &str = "binding_unproven";

/// What a reader serves for one call site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SiteStateKind {
    ProvenTarget,
    ProvenExternal,
    ProvenOutside,
    ProvenDeclaration,
    Binding,
    NotInBuild,
    ServerFailed,
    Unresolved,
    OwedDerivation,
    OwedEnrichment,
    ProofContextStale,
    UnprovenNoResolver,
}

impl SiteStateKind {
    /// Every kind, in the order payloads list them.
    pub const ALL: [SiteStateKind; 12] = [
        Self::ProvenTarget,
        Self::ProvenExternal,
        Self::ProvenOutside,
        Self::ProvenDeclaration,
        Self::Binding,
        Self::NotInBuild,
        Self::ServerFailed,
        Self::Unresolved,
        Self::OwedDerivation,
        Self::OwedEnrichment,
        Self::ProofContextStale,
        Self::UnprovenNoResolver,
    ];

    /// Whether a site read as this kind belongs to a caller no ledger
    /// describes, so the site itself is not counted: how many such a caller
    /// holds is not known.
    pub fn is_uncounted(self) -> bool {
        matches!(
            self,
            Self::OwedDerivation | Self::OwedEnrichment | Self::UnprovenNoResolver
        )
    }

    /// The kind of a state a ledger records.
    pub fn of(state: &CallSiteState) -> Self {
        match state {
            CallSiteState::ProvenTarget { .. } => Self::ProvenTarget,
            CallSiteState::ProvenExternal { .. } => Self::ProvenExternal,
            CallSiteState::ProvenOutside => Self::ProvenOutside,
            CallSiteState::ProvenDeclaration { .. } => Self::ProvenDeclaration,
            CallSiteState::Binding { .. } => Self::Binding,
            CallSiteState::NotInBuild { .. } => Self::NotInBuild,
            CallSiteState::ServerFailed { .. } => Self::ServerFailed,
            CallSiteState::Unresolved { .. } => Self::Unresolved,
        }
    }

    /// The kind's name, as payloads spell it.
    pub fn wire(self) -> &'static str {
        match self {
            Self::ProvenTarget => "proven_target",
            Self::ProvenExternal => "proven_external",
            Self::ProvenOutside => "proven_outside",
            Self::ProvenDeclaration => "proven_declaration",
            Self::Binding => "binding",
            Self::NotInBuild => "not_in_build",
            Self::ServerFailed => "server_failed",
            Self::Unresolved => "unresolved",
            Self::OwedDerivation => "owed_derivation",
            Self::OwedEnrichment => "owed_enrichment",
            Self::ProofContextStale => "proof_context_stale",
            Self::UnprovenNoResolver => "unproven_no_resolver",
        }
    }

    /// Whether a site read as this kind is settled: a resolver proved where
    /// the call goes, inside the repository or out of it.
    pub fn is_settled(self) -> bool {
        matches!(
            self,
            Self::ProvenTarget
                | Self::ProvenExternal
                | Self::ProvenOutside
                | Self::ProvenDeclaration
        )
    }

    /// The verdict clause a site of this kind in an answer's scope calls
    /// for, or `None` for a settled one.
    pub fn verdict_code(self) -> Option<&'static str> {
        match self {
            Self::ProvenTarget
            | Self::ProvenExternal
            | Self::ProvenOutside
            | Self::ProvenDeclaration => None,
            Self::Binding => Some(BINDING_UNPROVEN),
            Self::NotInBuild => Some(CALL_SITES_NOT_IN_BUILD),
            Self::ServerFailed => Some(CALL_SITES_SERVER_FAILED),
            Self::Unresolved => Some(CALL_SITES_UNRESOLVED),
            Self::OwedDerivation | Self::OwedEnrichment => Some(CALL_SITES_OWED),
            Self::ProofContextStale => Some(PROOF_CONTEXT_STALE),
            Self::UnprovenNoResolver => Some(CALL_SITES_UNPROVEN_NO_RESOLVER),
        }
    }
}

/// Why no resolver can prove a language's call sites on this host now.
///
/// Read only for a caller the graph holds no current ledger for: a ledger an
/// earlier resolver wrote still says what it proved. Each case is one waiting
/// does not change, which is what separates it from owed enrichment, which a
/// sweep will still reach.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(tag = "case", rename_all = "snake_case")]
pub enum NoResolver {
    /// Language-server enrichment is switched off for the process serving the
    /// graph, so no language server is consulted for any language.
    EnrichmentOff,
    /// No language server for the language is installed, or this build wires
    /// none for it.
    NoLanguageServer,
    /// A language server for the language was found and cannot start, for
    /// the reason it gave: its analysis environment is missing, say.
    ServerCannotStart { reason: String },
}

impl NoResolver {
    /// The case's name, as payloads spell it.
    pub fn wire(&self) -> &'static str {
        match self {
            Self::EnrichmentOff => "enrichment_off",
            Self::NoLanguageServer => "no_language_server",
            Self::ServerCannotStart { .. } => "server_cannot_start",
        }
    }

    /// Why, as a clause fragment about `language`. It never holds the `"; "`
    /// that separates verdict clauses, and a server's own reason is cut to a
    /// bounded length.
    pub fn sentence(&self, language: LanguageId) -> String {
        const REASON_MAX_CHARS: usize = 160;
        match self {
            Self::EnrichmentOff => {
                format!("{language}: language-server enrichment is switched off")
            }
            Self::NoLanguageServer => {
                format!("{language}: no language server for it is installed or wired")
            }
            Self::ServerCannotStart { reason } => {
                let mut reason: String = reason
                    .replace(';', ",")
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ");
                if reason.chars().count() > REASON_MAX_CHARS {
                    reason = reason.chars().take(REASON_MAX_CHARS).collect::<String>() + "...";
                }
                format!("{language}: its language server cannot start ({reason})")
            }
        }
    }
}

/// Why a site's state is what it is, in the words a payload uses: the
/// unresolved reason, the server failure or the not-in-build reason. `None`
/// for a state that carries none.
pub fn site_state_reason(state: &CallSiteState) -> Option<String> {
    match state {
        CallSiteState::Unresolved { reason } => Some(UnresolvedReason::wire(*reason).to_string()),
        CallSiteState::ServerFailed { reason } => Some(ServerFailure::wire(*reason).to_string()),
        CallSiteState::NotInBuild { reason } => Some(reason.clone()),
        _ => None,
    }
}

/// What a reader can learn about a caller from outside its ledger.
pub trait CallSiteFacts {
    /// The ledger of `caller`'s call sites, when the graph holds one.
    fn ledger(&self, caller: EntityId) -> Option<CallSiteLedger>;

    /// Whether `caller` was derived from bytes other than the ones its file
    /// holds now. A reader that cannot tell answers `false`, and the
    /// source-derivation observation qualifies its answer instead.
    fn derivation_owed(&self, _caller: &Entity) -> bool {
        false
    }

    /// The proof context `language`'s resolver runs under now, or `None`
    /// when this reader cannot know, which reads no ledger as stale.
    fn current_context(&self, _language: LanguageId) -> Option<ResolutionRecordId> {
        None
    }

    /// Why no resolver can prove `language`'s call sites on this host now,
    /// or `None` when one can or this reader cannot know. `None` reads a
    /// caller with no ledger as owed enrichment, the reading a process that
    /// never looked should give.
    fn no_resolver(&self, _language: LanguageId) -> Option<NoResolver> {
        None
    }
}

/// What the graph holds about one caller's call sites, read in the order
/// every surface reads it in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CallerSites {
    /// The caller's file holds bytes its entities were not derived from.
    OwedDerivation,
    /// No ledger describes the caller as the graph holds it.
    OwedEnrichment,
    /// No ledger describes the caller as the graph holds it, and no resolver
    /// for its language can prove its sites on this host now.
    NoResolver {
        language: LanguageId,
        why: NoResolver,
    },
    /// The caller has no source text, so no call site.
    NoSites,
    /// The ledger was proven under a context its resolver no longer runs
    /// under, so every site reads as stale.
    Stale(CallSiteLedger),
    /// The ledger is the caller's current state.
    Current(CallSiteLedger),
}

impl CallerSites {
    /// The ledger read, when there is one.
    pub fn ledger(&self) -> Option<&CallSiteLedger> {
        match self {
            Self::Stale(ledger) | Self::Current(ledger) => Some(ledger),
            _ => None,
        }
    }

    /// The caller's standing, as payloads spell it.
    pub fn wire(&self) -> &'static str {
        match self {
            Self::OwedDerivation => SiteStateKind::OwedDerivation.wire(),
            Self::OwedEnrichment => SiteStateKind::OwedEnrichment.wire(),
            Self::NoResolver { .. } => SiteStateKind::UnprovenNoResolver.wire(),
            Self::NoSites => "no_sites",
            Self::Stale(_) => SiteStateKind::ProofContextStale.wire(),
            Self::Current(_) => "current",
        }
    }

    /// What a reader serves for `site`, a site of this caller's ledger.
    pub fn site_kind(&self, site: &CallSite) -> SiteStateKind {
        match self {
            Self::OwedDerivation => SiteStateKind::OwedDerivation,
            Self::OwedEnrichment | Self::NoSites => SiteStateKind::OwedEnrichment,
            Self::NoResolver { .. } => SiteStateKind::UnprovenNoResolver,
            Self::Stale(_) => SiteStateKind::ProofContextStale,
            Self::Current(_) => SiteStateKind::of(&site.state),
        }
    }

    /// Whether every site of the caller is known: no owed derivation or
    /// enrichment stands between the reader and its ledger.
    pub fn is_known(&self) -> bool {
        matches!(self, Self::NoSites | Self::Stale(_) | Self::Current(_))
    }
}

/// The entity metadata key under which the parser records how many call sites
/// it read in the entity's whole file. The parser crate names it
/// `FILE_PARSED_CALL_SITES_KEY`; it is spelled here because this crate sits
/// below the parser.
pub const FILE_PARSED_CALL_SITES_KEY: &str = "file_parsed_call_sites";

/// Whether the parser read no call site at all in `entity`'s file, which is
/// the one case where an entity holds no call site whatever any sweep did: a
/// file with no call expression gets no ledger, and needs none.
pub fn in_a_file_without_calls(entity: &Entity) -> bool {
    entity
        .metadata
        .extra
        .get(FILE_PARSED_CALL_SITES_KEY)
        .and_then(serde_json::Value::as_u64)
        == Some(0)
}

/// Read one caller's call sites: owed derivation first, then a missing
/// ledger, then a stale proof context, then the ledger itself.
///
/// A missing ledger is owed enrichment while a resolver for the caller's
/// language can still prove its sites, and unproven for want of a resolver
/// when none can on this host now (see [`CallSiteFacts::no_resolver`]).
///
/// A ledger whose recorded behavior hash is not the caller's describes a body
/// the caller no longer has and reads as a missing one. Storage retires such
/// a ledger in the transaction that changes the caller, so this is only ever
/// a reader's guard against a graph it did not see settle.
pub fn read_caller_sites<F: CallSiteFacts + ?Sized>(facts: &F, caller: &Entity) -> CallerSites {
    if facts.derivation_owed(caller) {
        return CallerSites::OwedDerivation;
    }
    let unledgered = || match facts.no_resolver(caller.language) {
        Some(why) => CallerSites::NoResolver {
            language: caller.language,
            why,
        },
        None => CallerSites::OwedEnrichment,
    };
    let Some(ledger) = facts.ledger(caller.id) else {
        return if caller.span.is_none() || in_a_file_without_calls(caller) {
            CallerSites::NoSites
        } else {
            unledgered()
        };
    };
    if ledger.behavior_hash != caller.fingerprint.behavior_hash {
        return unledgered();
    }
    if facts
        .current_context(caller.language)
        .is_some_and(|current| current != ledger.context)
    {
        return CallerSites::Stale(ledger);
    }
    CallerSites::Current(ledger)
}

/// Readings added up over an answer's scope.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct CallSiteTally {
    /// Callers read.
    pub callers: u64,
    /// Callers whose sites are not known because their derivation is owed.
    pub callers_owed_derivation: u64,
    /// Callers whose sites are not known because no ledger describes them.
    pub callers_owed_enrichment: u64,
    /// Callers no ledger describes whose sites no resolver can prove on this
    /// host now, so waiting will not settle them.
    pub callers_unproven_no_resolver: u64,
    /// Those callers by why, one entry per language and case, as
    /// [`NoResolver::sentence`] states it.
    pub no_resolver: BTreeMap<String, u64>,
    /// Callers whose ledger was proven under a stale context.
    pub callers_stale: u64,
    /// Sites the read ledgers hold, stale ones included.
    pub sites: u64,
    /// Those sites by what a reader serves for them. Owed callers contribute
    /// no site, since how many they hold is not known.
    pub by_state: BTreeMap<SiteStateKind, u64>,
}

impl CallSiteTally {
    /// Add one caller's reading, counting every site its ledger holds.
    pub fn add(&mut self, reading: &CallerSites) {
        self.add_sites(reading, |_| true);
    }

    /// Add one caller's reading, counting only the sites `keep` admits.
    pub fn add_sites(&mut self, reading: &CallerSites, keep: impl Fn(&CallSite) -> bool) {
        self.callers += 1;
        match reading {
            CallerSites::OwedDerivation => self.callers_owed_derivation += 1,
            CallerSites::OwedEnrichment => self.callers_owed_enrichment += 1,
            CallerSites::NoResolver { language, why } => {
                self.callers_unproven_no_resolver += 1;
                *self.no_resolver.entry(why.sentence(*language)).or_insert(0) += 1;
            }
            CallerSites::NoSites => {}
            CallerSites::Stale(_) | CallerSites::Current(_) => {
                if matches!(reading, CallerSites::Stale(_)) {
                    self.callers_stale += 1;
                }
                let ledger = reading
                    .ledger()
                    .expect("a stale or current reading holds a ledger");
                for site in ledger.sites.iter().filter(|site| keep(site)) {
                    self.sites += 1;
                    *self.by_state.entry(reading.site_kind(site)).or_insert(0) += 1;
                }
            }
        }
    }

    /// Fold another tally into this one.
    pub fn merge(&mut self, other: &CallSiteTally) {
        self.callers += other.callers;
        self.callers_owed_derivation += other.callers_owed_derivation;
        self.callers_owed_enrichment += other.callers_owed_enrichment;
        self.callers_unproven_no_resolver += other.callers_unproven_no_resolver;
        for (why, count) in &other.no_resolver {
            *self.no_resolver.entry(why.clone()).or_insert(0) += count;
        }
        self.callers_stale += other.callers_stale;
        self.sites += other.sites;
        for (kind, count) in &other.by_state {
            *self.by_state.entry(*kind).or_insert(0) += count;
        }
    }

    /// Sites read as `kind`.
    pub fn count(&self, kind: SiteStateKind) -> u64 {
        self.by_state.get(&kind).copied().unwrap_or(0)
    }

    /// The share of the census read as `kind`: its sites over every site the
    /// read ledgers hold, or `None` when they hold none.
    pub fn share(&self, kind: SiteStateKind) -> Option<f64> {
        (self.sites > 0).then(|| self.count(kind) as f64 / self.sites as f64)
    }

    /// Sites whose state settles nothing, plus none for owed callers, whose
    /// sites are not counted.
    pub fn unsettled_sites(&self) -> u64 {
        self.by_state
            .iter()
            .filter(|(kind, _)| !kind.is_settled())
            .map(|(_, count)| count)
            .sum()
    }

    /// Callers whose sites are not known.
    pub fn callers_owed(&self) -> u64 {
        self.callers_owed_derivation + self.callers_owed_enrichment
    }

    /// Whether every site in scope is known and settled.
    pub fn is_settled(&self) -> bool {
        self.callers_owed() == 0
            && self.callers_unproven_no_resolver == 0
            && self.unsettled_sites() == 0
    }

    /// The verdict clauses this tally calls for, each `<code>: <why>`, in
    /// code order, with no clause separator inside any of them. `scope` names
    /// what the tally was taken over, such as "the focal's body".
    pub fn clauses(&self, scope: &str) -> Vec<String> {
        let mut clauses = Vec::new();
        let owed = self.callers_owed();
        if owed > 0 {
            clauses.push(format!(
                "{CALL_SITES_OWED}: {owed} of the {} callers in {scope} have call sites the graph \
                 has not settled yet because their derivation or enrichment is owed, so a call \
                 there is not accounted for",
                self.callers
            ));
        }
        if self.callers_unproven_no_resolver > 0 {
            let why: Vec<&str> = self.no_resolver.keys().map(String::as_str).collect();
            clauses.push(format!(
                "{CALL_SITES_UNPROVEN_NO_RESOLVER}: {} of the {} callers in {scope} have call \
                 sites no resolver can prove on this host now ({}), so waiting for enrichment \
                 will not settle them",
                self.callers_unproven_no_resolver,
                self.callers,
                why.join(", ")
            ));
        }
        let mut by_code: BTreeMap<&'static str, u64> = BTreeMap::new();
        for (kind, count) in &self.by_state {
            if let Some(code) = kind.verdict_code() {
                *by_code.entry(code).or_insert(0) += count;
            }
        }
        for (code, count) in by_code {
            if count == 0 {
                continue;
            }
            let why = match code {
                BINDING_UNPROVEN => "call through a value binding, which proves no target",
                CALL_SITES_NOT_IN_BUILD => "sit in a file no build of the repository compiles",
                CALL_SITES_SERVER_FAILED => {
                    "got no answer because the resolver timed out, crashed or broke protocol"
                }
                CALL_SITES_UNRESOLVED => "got an answer that proves no target",
                PROOF_CONTEXT_STALE => {
                    "were proven under a proof context the resolver no longer runs under"
                }
                _ => "are not settled",
            };
            clauses.push(format!(
                "{code}: {count} of the {} call sites in {scope} {why}",
                self.sites
            ));
        }
        clauses.sort();
        clauses
    }

    /// The tally as a payload block: counts per state for every kind, the
    /// caller counts, and whether it is settled.
    pub fn to_json(&self) -> serde_json::Value {
        let by_state: serde_json::Map<String, serde_json::Value> = SiteStateKind::ALL
            .iter()
            .filter(|kind| !kind.is_uncounted())
            .map(|kind| {
                (
                    kind.wire().to_string(),
                    serde_json::json!(self.count(*kind)),
                )
            })
            .collect();
        serde_json::json!({
            "settled": self.is_settled(),
            "callers": self.callers,
            "callers_owed_derivation": self.callers_owed_derivation,
            "callers_owed_enrichment": self.callers_owed_enrichment,
            "callers_unproven_no_resolver": self.callers_unproven_no_resolver,
            "no_resolver": self.no_resolver,
            "callers_stale": self.callers_stale,
            "sites": self.sites,
            "by_state": by_state,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CallSite, EntityKind, EntityMetadata, EntityRole, FilePathId, FingerprintAlgorithm,
        Hash256, SemanticFingerprint, SourceSpan, Visibility,
    };
    use uuid::Uuid;

    fn caller(id: u128, spanned: bool) -> Entity {
        Entity {
            id: EntityId(Uuid::from_u128(id)),
            kind: EntityKind::Function,
            name: "run".to_string(),
            language: LanguageId::Python,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0; 32]),
                signature_hash: Hash256::from_bytes([0; 32]),
                behavior_hash: Hash256::from_bytes([7; 32]),
                equivalence_hash: Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new("app.py")),
            span: spanned.then(|| SourceSpan {
                file: FilePathId::new("app.py"),
                start_byte: 0,
                end_byte: 40,
                start_line: 0,
                start_col: 0,
                end_line: 2,
                end_col: 0,
            }),
            signature: "def run()".to_string(),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    fn context(value: u128) -> ResolutionRecordId {
        ResolutionRecordId(Uuid::from_u128(value))
    }

    fn ledger(caller: &Entity, context_id: ResolutionRecordId) -> CallSiteLedger {
        let states = [
            CallSiteState::ProvenTarget {
                target: EntityId(Uuid::from_u128(99)),
            },
            CallSiteState::ProvenOutside,
            CallSiteState::Unresolved {
                reason: UnresolvedReason::NoAnswer,
            },
            CallSiteState::Binding { may_call: None },
            CallSiteState::ServerFailed {
                reason: ServerFailure::Timeout,
            },
        ];
        CallSiteLedger {
            caller: caller.id,
            behavior_hash: caller.fingerprint.behavior_hash,
            body_hash: Hash256::from_bytes([1; 32]),
            context: context_id,
            census: states.len() as u32,
            sites: states
                .into_iter()
                .enumerate()
                .map(|(at, state)| CallSite {
                    offset: at as u32 * 5,
                    length: 3,
                    state,
                })
                .collect(),
        }
    }

    #[derive(Default)]
    struct Facts {
        ledgers: Vec<CallSiteLedger>,
        owed: bool,
        current: Option<ResolutionRecordId>,
        no_resolver: Option<NoResolver>,
    }

    impl CallSiteFacts for Facts {
        fn ledger(&self, caller: EntityId) -> Option<CallSiteLedger> {
            self.ledgers
                .iter()
                .find(|ledger| ledger.caller == caller)
                .cloned()
        }

        fn derivation_owed(&self, _caller: &Entity) -> bool {
            self.owed
        }

        fn current_context(&self, _language: LanguageId) -> Option<ResolutionRecordId> {
            self.current
        }

        fn no_resolver(&self, _language: LanguageId) -> Option<NoResolver> {
            self.no_resolver.clone()
        }
    }

    #[test]
    fn a_caller_reads_owed_derivation_then_owed_enrichment_then_stale_then_its_ledger() {
        let run = caller(1, true);
        let held = ledger(&run, context(5));

        let owed = Facts {
            ledgers: vec![held.clone()],
            owed: true,
            current: Some(context(6)),
            ..Facts::default()
        };
        assert_eq!(read_caller_sites(&owed, &run), CallerSites::OwedDerivation);

        let missing = Facts {
            current: Some(context(6)),
            ..Facts::default()
        };
        assert_eq!(
            read_caller_sites(&missing, &run),
            CallerSites::OwedEnrichment
        );
        assert_eq!(
            read_caller_sites(&missing, &caller(2, false)),
            CallerSites::NoSites,
            "a caller with no text holds no call site"
        );
        let mut quiet = caller(4, true);
        quiet
            .metadata
            .extra
            .insert(FILE_PARSED_CALL_SITES_KEY.into(), serde_json::json!(0));
        assert_eq!(
            read_caller_sites(&missing, &quiet),
            CallerSites::NoSites,
            "nor does one in a file the parser read no call in"
        );
        quiet
            .metadata
            .extra
            .insert(FILE_PARSED_CALL_SITES_KEY.into(), serde_json::json!(3));
        assert_eq!(
            read_caller_sites(&missing, &quiet),
            CallerSites::OwedEnrichment
        );

        let stale = Facts {
            ledgers: vec![held.clone()],
            current: Some(context(6)),
            ..Facts::default()
        };
        let reading = read_caller_sites(&stale, &run);
        assert_eq!(reading, CallerSites::Stale(held.clone()));
        assert_eq!(
            reading.site_kind(&held.sites[0]),
            SiteStateKind::ProofContextStale
        );

        for current in [Some(context(5)), None] {
            let facts = Facts {
                ledgers: vec![held.clone()],
                current,
                ..Facts::default()
            };
            let reading = read_caller_sites(&facts, &run);
            assert_eq!(reading, CallerSites::Current(held.clone()));
            assert_eq!(
                held.sites
                    .iter()
                    .map(|site| reading.site_kind(site).wire())
                    .collect::<Vec<_>>(),
                [
                    "proven_target",
                    "proven_outside",
                    "unresolved",
                    "binding",
                    "server_failed"
                ]
            );
        }

        let mut moved = held;
        moved.behavior_hash = Hash256::from_bytes([8; 32]);
        let moved = Facts {
            ledgers: vec![moved],
            ..Facts::default()
        };
        assert_eq!(
            read_caller_sites(&moved, &run),
            CallerSites::OwedEnrichment,
            "a ledger of another body is no ledger of this one"
        );
    }

    /// A caller with no ledger reads as owed while a resolver can still prove
    /// its sites, and as unproven for want of a resolver when none can on this
    /// host now: its own clause, naming why, and never `call_sites_owed`. A
    /// caller a ledger describes reads as its ledger either way, and owed
    /// derivation still comes first, since a reconcile settles it.
    #[test]
    fn a_caller_no_resolver_can_prove_reads_unproven_not_owed() {
        let run = caller(1, true);
        let other = caller(3, true);
        let cases = [
            (
                NoResolver::EnrichmentOff,
                "python: language-server enrichment is switched off",
            ),
            (
                NoResolver::NoLanguageServer,
                "python: no language server for it is installed or wired",
            ),
            (
                NoResolver::ServerCannotStart {
                    reason: "no Python environment; run uv sync".to_string(),
                },
                "python: its language server cannot start (no Python environment, run uv sync)",
            ),
        ];
        for (why, sentence) in cases {
            let facts = Facts {
                ledgers: vec![ledger(&run, context(5))],
                no_resolver: Some(why.clone()),
                ..Facts::default()
            };
            assert_eq!(
                read_caller_sites(&facts, &other),
                CallerSites::NoResolver {
                    language: LanguageId::Python,
                    why: why.clone()
                }
            );
            assert!(matches!(
                read_caller_sites(&facts, &run),
                CallerSites::Current(_)
            ));
            let owed_first = Facts {
                owed: true,
                ..Facts {
                    no_resolver: Some(why.clone()),
                    ..Facts::default()
                }
            };
            assert_eq!(
                read_caller_sites(&owed_first, &other),
                CallerSites::OwedDerivation
            );

            let mut tally = CallSiteTally::default();
            tally.add(&read_caller_sites(&facts, &other));
            assert!(!tally.is_settled(), "unproven is inconclusive");
            assert_eq!(tally.callers_owed(), 0);
            assert_eq!(tally.callers_unproven_no_resolver, 1);
            let clauses = tally.clauses("scope");
            assert_eq!(
                clauses,
                [format!(
                    "{CALL_SITES_UNPROVEN_NO_RESOLVER}: 1 of the 1 callers in scope have call \
                     sites no resolver can prove on this host now ({sentence}), so waiting for \
                     enrichment will not settle them"
                )]
            );
            assert!(clauses.iter().all(|clause| !clause.contains("; ")));
            let json = tally.to_json();
            assert_eq!(json["callers_unproven_no_resolver"], 1);
            assert_eq!(json["no_resolver"][sentence], 1);
            assert!(json["by_state"].get("unproven_no_resolver").is_none());
        }
        // No fact, no claim: a reader that cannot know reads it as owed.
        let unknown = Facts::default();
        assert_eq!(
            read_caller_sites(&unknown, &other),
            CallerSites::OwedEnrichment
        );
    }

    #[test]
    fn a_tally_names_every_unsettled_state_and_certifies_only_a_settled_scope() {
        let run = caller(1, true);
        let other = caller(3, true);
        let facts = Facts {
            ledgers: vec![ledger(&run, context(5))],
            ..Facts::default()
        };
        let mut tally = CallSiteTally::default();
        tally.add(&read_caller_sites(&facts, &run));
        tally.add(&read_caller_sites(&facts, &other));
        assert_eq!(tally.callers, 2);
        assert_eq!(tally.callers_owed_enrichment, 1);
        assert_eq!(tally.sites, 5);
        assert_eq!(tally.unsettled_sites(), 3);
        assert!(!tally.is_settled());
        let labels: Vec<String> = tally
            .clauses("scope")
            .iter()
            .map(|clause| clause.split(':').next().unwrap().to_string())
            .collect();
        assert_eq!(
            labels,
            [
                BINDING_UNPROVEN,
                CALL_SITES_OWED,
                CALL_SITES_SERVER_FAILED,
                CALL_SITES_UNRESOLVED
            ]
        );
        assert!(tally
            .clauses("scope")
            .iter()
            .all(|clause| !clause.contains("; ")));

        let mut settled = CallSiteTally::default();
        settled.add_sites(&read_caller_sites(&facts, &run), |site| {
            SiteStateKind::of(&site.state).is_settled()
        });
        assert!(settled.is_settled());
        assert!(settled.clauses("scope").is_empty());
        assert_eq!(settled.to_json()["by_state"]["proven_target"], 1);
        assert_eq!(settled.to_json()["settled"], true);

        let mut merged = CallSiteTally::default();
        merged.merge(&tally);
        merged.merge(&settled);
        assert_eq!(merged.sites, 7);
        assert_eq!(merged.count(SiteStateKind::ProvenTarget), 2);
    }

    #[test]
    fn each_state_s_share_is_its_part_of_the_census_and_the_shares_make_the_whole() {
        let run = caller(1, true);
        let facts = Facts {
            ledgers: vec![ledger(&run, context(5))],
            ..Facts::default()
        };
        let mut tally = CallSiteTally::default();
        tally.add(&read_caller_sites(&facts, &run));
        assert_eq!(tally.share(SiteStateKind::ProvenTarget), Some(0.2));
        assert_eq!(tally.share(SiteStateKind::ProvenExternal), Some(0.0));
        let whole: f64 = SiteStateKind::ALL
            .iter()
            .filter_map(|kind| tally.share(*kind))
            .sum();
        assert!(
            (whole - 1.0).abs() < 1e-9,
            "the shares make the census: {whole}"
        );

        let mut owed_only = CallSiteTally::default();
        owed_only.add(&read_caller_sites(&Facts::default(), &run));
        assert_eq!(
            owed_only.share(SiteStateKind::ProvenTarget),
            None,
            "a census of nothing has no shares, which is not a share of zero"
        );
    }
}
