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

use crate::{CallSite, CallSiteLedger, CallSiteState, Entity, EntityId, EntityKind, LanguageId};
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
/// The selected graph does not validate the context a recorded ledger used.
pub const PROOF_CONTEXT_UNVERIFIED: &str = "proof_context_unverified";
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
    ProofContextUnverified,
    UnprovenNoResolver,
}

impl SiteStateKind {
    /// Every kind, in the order payloads list them.
    pub const ALL: [SiteStateKind; 13] = [
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
        Self::ProofContextUnverified,
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
            Self::ProofContextUnverified => PROOF_CONTEXT_UNVERIFIED,
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
            Self::ProofContextUnverified => Some(PROOF_CONTEXT_UNVERIFIED),
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

    /// The context validated in the selected graph for `language`. `None`
    /// leaves recorded ledgers unverified, never implicitly current.
    fn current_context(&self, _language: LanguageId) -> Option<ResolutionRecordId> {
        None
    }

    /// Why the selected graph cannot validate a recorded ledger's context.
    /// Historical readers answer from their selected revision, not this host.
    fn context_unverified_reason(&self, _language: LanguageId) -> String {
        "the selected graph has no recorded proof-context validation".into()
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
    /// The ledger remains recorded evidence, but the selected graph does not
    /// validate its context. Its targets do not establish current validity.
    Unverified {
        ledger: CallSiteLedger,
        reason: String,
    },
    /// The ledger is the caller's current state.
    Current(CallSiteLedger),
}

impl CallerSites {
    /// The ledger read, when there is one.
    pub fn ledger(&self) -> Option<&CallSiteLedger> {
        match self {
            Self::Stale(ledger) | Self::Current(ledger) | Self::Unverified { ledger, .. } => {
                Some(ledger)
            }
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
            Self::Unverified { .. } => SiteStateKind::ProofContextUnverified.wire(),
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
            Self::Unverified { .. } => SiteStateKind::ProofContextUnverified,
            Self::Current(_) => SiteStateKind::of(&site.state),
        }
    }

    /// Whether every site of the caller is known: no owed derivation or
    /// enrichment stands between the reader and its ledger.
    pub fn is_known(&self) -> bool {
        matches!(
            self,
            Self::NoSites | Self::Stale(_) | Self::Current(_) | Self::Unverified { .. }
        )
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
    match facts.current_context(caller.language) {
        Some(current) if current == ledger.context => CallerSites::Current(ledger),
        Some(_) => CallerSites::Stale(ledger),
        None => CallerSites::Unverified {
            ledger,
            reason: facts.context_unverified_reason(caller.language),
        },
    }
}

// ── Which unsettled sites could be a call to one focal ────────────────────

/// Why an unsettled site could be a call to a focal: its callee token is one
/// of the names a call to the focal is spelled with.
pub const REACH_CALLEE_SPELLS: &str = "callee spells the name";
/// Why an unsettled site could be a call to a focal: it names no callee token
/// a reader can compare, and the caller's body spells one of the focal's call
/// names, as `getattr(ctx, "pop")()` spells `pop`.
pub const REACH_BODY_SPELLS: &str = "body spells the name";
/// Why an unsettled site could be a call to a focal: it may call through a
/// value, and the focal escapes as one, so a call that never spells the
/// focal's name can still reach it.
pub const REACH_FOCAL_ESCAPES: &str = "focal escapes as a value";
/// Why an unsettled site could be a call to a focal: the reader holds neither
/// its callee text nor its caller's body, so nothing rules it out.
pub const REACH_TEXT_UNKNOWN: &str = "caller text unknown";
/// Why an unsettled site could be a call to a focal: the focal has no name a
/// call could spell, so no site can be ruled out by name.
pub const REACH_NAME_UNKNOWN: &str = "focal name unknown";
/// Why an unsettled site could be a call to a focal: its callee is reached
/// through a name built or looked up at run time (`getattr(x, name)`,
/// `handlers[key]`, `eval`), which can reach any focal without spelling it.
pub const REACH_DYNAMIC_ACCESS: &str = "dynamic reflective access";

/// Member names that make a method a constructor, which a call reaches by
/// spelling its type: `HTTPAdapter(...)` reaches `HTTPAdapter.__init__`.
const CONSTRUCTOR_MEMBERS: [&str; 6] = [
    "__init__",
    "__new__",
    "constructor",
    "__construct",
    "init",
    "new",
];

/// The names a call to `focal` is spelled with.
///
/// The graph names a member by its owner, `Session.send` or `Store::open`, and
/// no call spells that qualified name. A call to a function or to a method
/// that is not a constructor spells the member, `self.send(...)`, so only the
/// last segment is a call name: `Store.containsElement` is called as
/// `containsElement`, and a body that spells only `Store` does not call it.
///
/// A constructor is reached by spelling its type, `HTTPAdapter()` for
/// `HTTPAdapter.__init__`, and by its own name from a subclass,
/// `super().__init__()`, so every segment is a call name. A method is a
/// constructor when its member is one a language reserves for one (`__init__`,
/// `__new__`, `constructor`, `__construct`, `init`, `new`) or repeats its
/// owner's name, as Java and C++ spell one. Every other kind, a class above
/// all, keeps every segment, since the type name is what a call spells.
pub fn focal_call_names(focal: &Entity) -> Vec<String> {
    let segments: Vec<&str> = focal
        .name
        .split(['.', ':'])
        .filter(|segment| !segment.is_empty())
        .collect();
    let Some(member) = segments.last().copied() else {
        return Vec::new();
    };
    let owner = segments.len().checked_sub(2).map(|at| segments[at]);
    let member_only = match focal.kind {
        EntityKind::Function => true,
        EntityKind::Method => !(CONSTRUCTOR_MEMBERS.contains(&member) || owner == Some(member)),
        _ => false,
    };
    if member_only {
        return vec![member.to_string()];
    }
    let mut names: Vec<String> = Vec::new();
    for segment in segments {
        if !names.iter().any(|name| name == segment) {
            names.push(segment.to_string());
        }
    }
    names
}

/// Whether `text` is one identifier, which is what a placeable callee token
/// is: the parser keys a site by its callee token when the call names one,
/// and by the whole call expression when it does not.
fn is_identifier(text: &str) -> bool {
    let mut chars = text.chars();
    chars
        .next()
        .is_some_and(|first| first.is_alphabetic() || first == '_' || first == '$')
        && chars
            .all(|character| character.is_alphanumeric() || character == '_' || character == '$')
}

/// The text at `site` inside `caller_text`, the caller's exact own text from
/// its first byte, which is what a ledger keys its sites against. `None` when
/// the key falls outside that text or off a character boundary.
pub fn site_text<'t>(site: &CallSite, caller_text: &'t str) -> Option<&'t str> {
    let start = site.offset as usize;
    caller_text.get(start..start.checked_add(site.length as usize)?)
}

/// Whether one unsettled site could be a call to a focal whose calls are
/// spelled `names` (see [`focal_call_names`]), and why: the reason, or `None`
/// when it cannot reach the focal. Settled sites are not asked, and answer
/// `None`: a resolver proved where they go.
///
/// `caller_body` is text holding every identifier the caller's body holds: its
/// exact text, or a complete whitespace-collapsed copy of it. Only whether it
/// spells a name is read from it, never an offset. `None` means the body is
/// not known, and every site the body would have had to rule out is kept.
///
/// `focal_escapes` says whether the focal escapes as a value, such as a
/// reference to it that is not a call, so a call through a value slot may
/// hold it.
///
/// Without the site's own text a reader cannot compare its callee, so a
/// placeable site is kept whenever the body spells a name. [`site_could_call_at`]
/// states the rule, for a reader that holds the site's text as well.
pub fn site_could_call(
    site: &CallSite,
    names: &[String],
    caller_body: Option<&str>,
    focal_escapes: bool,
) -> Option<&'static str> {
    site_could_call_at(site, None, names, caller_body, focal_escapes)
}

/// [`site_could_call`] for a reader that holds `site_text`, the text at the
/// site's key cut from the caller's exact text (see [`site_text`]).
///
/// The rule, in order:
///
/// 1. When the focal escapes as a value, every unsettled site could be a call
///    to it. No unsettled state proves its callee is a different named
///    declaration: a binding calls through a value slot, and an unresolved
///    site, a server failure or a site no build compiles holds no proof either
///    way, so `callback()` may call a focal passed around as a value. The
///    reason is [`REACH_CALLEE_SPELLS`] when the site's token spells a name,
///    and [`REACH_FOCAL_ESCAPES`] otherwise.
/// 2. Otherwise a binding never could. Its callee text is the slot's name,
///    never the target's, and a slot can hold the focal only if the focal
///    escapes as a value.
/// 3. A site with no placeable callee token (its reason is
///    `callee_not_placeable` or `reflective`, or its text is a whole call
///    expression rather than one identifier) is judged by its callee
///    expression, as [`unplaceable_access`] reads it: a dynamic access could
///    be a call to any focal, and so could one whose text is not held; a
///    literal lookup could be one only when a literal spells a name; anything
///    else calls through a value, which rule 1 already covered.
/// 4. A focal with no call name rules nothing out.
/// 5. A site whose callee token is one of `names` could be a call to it.
/// 6. A placeable site whose token the reader holds and that spells none of
///    `names` cannot be one.
/// 7. A placeable site whose token the reader does not hold could be one when
///    the body spells a name, since its token might, and is kept when the
///    body is not known either.
pub fn site_could_call_at(
    site: &CallSite,
    site_text: Option<&str>,
    names: &[String],
    caller_body: Option<&str>,
    focal_escapes: bool,
) -> Option<&'static str> {
    use crate::CallSiteState as State;
    if SiteStateKind::of(&site.state).is_settled() {
        return None;
    }
    let names: Vec<&str> = names
        .iter()
        .map(String::as_str)
        .filter(|name| !name.is_empty())
        .collect();
    let token = site_text.filter(|text| is_identifier(text));
    let token_spells = token.is_some_and(|token| names.contains(&token));
    if focal_escapes {
        return Some(if token_spells {
            REACH_CALLEE_SPELLS
        } else {
            REACH_FOCAL_ESCAPES
        });
    }
    if matches!(site.state, State::Binding { .. }) {
        return None;
    }
    // A site the parser keyed by its callee token is placeable whatever its
    // state says: a pass that never asked about a token leaves it
    // `callee_not_placeable`, and its token is still the name it calls.
    let unplaceable = match site_text {
        Some(text) => !is_identifier(text),
        None => matches!(
            site.state,
            State::Unresolved {
                reason: UnresolvedReason::CalleeNotPlaceable | UnresolvedReason::Reflective
            }
        ),
    };
    if unplaceable {
        return match site_text.map(unplaceable_access) {
            None | Some(UnplaceableAccess::Dynamic) => Some(REACH_DYNAMIC_ACCESS),
            Some(UnplaceableAccess::Literal(literals)) => literals
                .iter()
                .any(|literal| names.contains(&literal.as_str()))
                .then_some(REACH_CALLEE_SPELLS),
            Some(UnplaceableAccess::ThroughValue) => None,
        };
    }
    if names.is_empty() {
        return Some(REACH_NAME_UNKNOWN);
    }
    if token_spells {
        return Some(REACH_CALLEE_SPELLS);
    }
    if token.is_some() {
        return None;
    }
    match caller_body.map(|body| names.iter().any(|name| body.contains(name))) {
        Some(true) => Some(REACH_BODY_SPELLS),
        Some(false) => None,
        None => Some(REACH_TEXT_UNKNOWN),
    }
}

/// How a call whose callee is not one identifier reaches what it calls.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnplaceableAccess {
    /// Through a name built or looked up at run time: it can reach any focal
    /// without spelling it.
    Dynamic,
    /// Through lookups whose names are all string literals, which are these.
    /// It reaches only a focal one of them spells.
    Literal(Vec<String>),
    /// Through a value an expression produced, `make()(x)` or `pair[0](x)`:
    /// it reaches a focal only if the focal escapes as a value.
    ThroughValue,
}

/// Functions and names that look a callee up by a name computed at run time
/// when their name argument is not a literal, or always.
const DYNAMIC_LOOKUPS: [&str; 5] = [
    "getattr",
    "Reflect.get",
    "__import__",
    "import_module",
    "import",
];
const ALWAYS_DYNAMIC: [&str; 8] = [
    "globals",
    "vars",
    "locals",
    "__dict__",
    "eval",
    "exec",
    "Function",
    "Reflect.apply",
];

/// Read a call expression whose callee is not one identifier, `text`, the
/// whole expression as a ledger keys it, by its callee part: the text before
/// its last argument list.
///
/// Dynamic when that part names a lookup by a run-time name (`getattr`,
/// `Reflect.get`, `__import__`, `import_module`, `import`) whose name
/// argument is not one string literal, uses `globals`, `vars`, `locals`,
/// `__dict__`, `eval`, `exec`, `Function` or `Reflect.apply` at all,
/// subscripts with a key that is neither a string nor a number literal, or
/// builds a string (a template, an f-string, `.format`, or a `+` or `%` beside
/// a string literal). Literal when every lookup it makes is by a string
/// literal, and through a value otherwise. The reading leans to dynamic
/// wherever the text is unusual, since a literal reading is what lets a site
/// be ruled out.
pub fn unplaceable_access(text: &str) -> UnplaceableAccess {
    let callee = callee_part(text);
    if ALWAYS_DYNAMIC.iter().any(|name| spells_word(callee, name))
        || callee.contains('`')
        || callee.contains(".format")
        || builds_a_string(callee)
    {
        return UnplaceableAccess::Dynamic;
    }
    let mut literals = Vec::new();
    for lookup in DYNAMIC_LOOKUPS {
        for (at, _) in callee.match_indices(lookup) {
            if !starts_word(callee, at) || !ends_word(callee, at + lookup.len()) {
                continue;
            }
            let rest = callee[at + lookup.len()..].trim_start();
            let Some(arguments) = rest.strip_prefix('(').and_then(balanced_group) else {
                return UnplaceableAccess::Dynamic;
            };
            let name_argument = if matches!(lookup, "import" | "__import__" | "import_module") {
                arguments.split(',').next()
            } else {
                arguments.split(',').nth(1)
            };
            match name_argument.and_then(|argument| string_literal(argument.trim())) {
                Some(literal) => literals.push(literal),
                None => return UnplaceableAccess::Dynamic,
            }
        }
    }
    let mut depth_start = None;
    let mut depth = 0usize;
    let bytes = callee.as_bytes();
    let mut in_string: Option<u8> = None;
    for (at, byte) in bytes.iter().enumerate() {
        if let Some(quote) = in_string {
            if *byte == quote && (at == 0 || bytes[at - 1] != b'\\') {
                in_string = None;
            }
            continue;
        }
        match byte {
            b'"' | b'\'' => in_string = Some(*byte),
            b'[' => {
                if depth == 0 {
                    depth_start = Some(at + 1);
                }
                depth += 1;
            }
            b']' if depth > 0 => {
                depth -= 1;
                if depth == 0 {
                    let key = callee[depth_start.unwrap_or(at)..at].trim();
                    if let Some(literal) = string_literal(key) {
                        literals.push(literal);
                    } else if !key
                        .chars()
                        .all(|character| character.is_ascii_digit() || character == '-')
                        || key.is_empty()
                    {
                        return UnplaceableAccess::Dynamic;
                    }
                }
            }
            _ => {}
        }
    }
    if literals.is_empty() {
        UnplaceableAccess::ThroughValue
    } else {
        UnplaceableAccess::Literal(literals)
    }
}

/// The text before a call expression's last argument list: the callee part.
fn callee_part(text: &str) -> &str {
    let trimmed = text.trim_end();
    let Some(without_close) = trimmed.strip_suffix(')') else {
        return trimmed;
    };
    let mut depth = 1usize;
    for (at, character) in without_close.char_indices().rev() {
        match character {
            ')' => depth += 1,
            '(' => {
                depth -= 1;
                if depth == 0 {
                    return &without_close[..at];
                }
            }
            _ => {}
        }
    }
    trimmed
}

/// The text inside a group whose opening `(` was already stripped, up to its
/// balanced closing `)`.
fn balanced_group(text: &str) -> Option<&str> {
    let mut depth = 1usize;
    for (at, character) in text.char_indices() {
        match character {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&text[..at]);
                }
            }
            _ => {}
        }
    }
    None
}

/// The content of `text` when it is exactly one plain string literal, quoted
/// with `'` or `"`, with no escape or interpolation in it.
fn string_literal(text: &str) -> Option<String> {
    let quote = text
        .chars()
        .next()
        .filter(|quote| *quote == '"' || *quote == '\'')?;
    let inner = text.strip_prefix(quote)?.strip_suffix(quote)?;
    (!inner.contains(quote) && !inner.contains('\\') && !inner.contains('{'))
        .then(|| inner.to_string())
}

/// Whether `text` builds a string at run time: an f-string, or a `+` or `%`
/// in an expression holding a string literal.
fn builds_a_string(text: &str) -> bool {
    let bytes = text.as_bytes();
    let quoted = text.contains('"') || text.contains('\'');
    let f_string = bytes.windows(2).enumerate().any(|(at, pair)| {
        matches!(pair[0], b'f' | b'F')
            && matches!(pair[1], b'"' | b'\'')
            && (at == 0 || !(bytes[at - 1].is_ascii_alphanumeric() || bytes[at - 1] == b'_'))
    });
    f_string || quoted && (text.contains('+') || text.contains('%'))
}

fn starts_word(text: &str, at: usize) -> bool {
    !text[..at].chars().next_back().is_some_and(|character| {
        character.is_alphanumeric() || character == '_' || character == '$'
    })
}

fn ends_word(text: &str, end: usize) -> bool {
    !text[end..].chars().next().is_some_and(|character| {
        character.is_alphanumeric() || character == '_' || character == '$'
    })
}

/// Whether `word` stands in `text` as a whole identifier.
fn spells_word(text: &str, word: &str) -> bool {
    text.match_indices(word)
        .any(|(at, _)| starts_word(text, at) && ends_word(text, at + word.len()))
}

/// A parenthesized Python from-import binds static names, unlike a dynamic
/// `import(name)` call. Recognize only a complete statement with a dotted
/// module and plain names (optionally renamed); expressions and comments do
/// not qualify. Renaming still counts as a value escape in the source census.
fn static_from_import_names(text: &str, import_at: usize, arguments: &str, rest: &str) -> bool {
    let identifier = |name: &str| {
        let mut bytes = name.bytes();
        bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
            && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    };
    let mut prefix = text[..import_at]
        .rsplit('\n')
        .next()
        .unwrap_or("")
        .split_whitespace();
    if prefix.next() != Some("from") {
        return false;
    }
    let Some(module) = prefix.next() else {
        return false;
    };
    let dotted = module.trim_start_matches('.');
    if prefix.next().is_some() || (!dotted.is_empty() && !dotted.split('.').all(identifier)) {
        return false;
    }
    let tail = &rest[arguments.len() + 2..];
    if !matches!(tail.split('\n').next().unwrap_or("").trim(), "" | ";") {
        return false;
    }
    let names = arguments
        .trim()
        .strip_suffix(',')
        .unwrap_or(arguments.trim());
    !names.is_empty()
        && names.split(',').all(|item| {
            let words: Vec<_> = item.split_whitespace().collect();
            match words.as_slice() {
                [name] => identifier(name),
                [name, "as", alias] => identifier(name) && identifier(alias),
                _ => false,
            }
        })
}

/// Whether `text` holds a construct that reaches a value through a name
/// computed at run time, so any focal may escape through it without its name
/// being spelled: a subscript whose key is neither a string nor a number
/// literal, a lookup by a run-time name (`getattr`, `Reflect.get`,
/// `__import__`, `import_module`, `import(`) whose name is not one string
/// literal, any use of `globals`, `vars`, `locals`, `__dict__`, `eval`,
/// `exec`, `Function` or `Reflect.apply`, or a string built at run time (an
/// f-string, a template, `.format`, or `+` or `%` beside a string literal).
///
/// Simple and sound rather than precise: a list display after a keyword
/// (`return [a]`) reads as a subscript, and any f-string reads as a built
/// name. Every misreading leans toward dynamic.
pub fn holds_dynamic_access(text: &str) -> bool {
    if ALWAYS_DYNAMIC.iter().any(|name| spells_word(text, name))
        || text.contains('`')
        || text.contains(".format")
        || builds_a_string(text)
    {
        return true;
    }
    for lookup in DYNAMIC_LOOKUPS {
        for (at, _) in text.match_indices(lookup) {
            if !starts_word(text, at) || !ends_word(text, at + lookup.len()) {
                continue;
            }
            let rest = text[at + lookup.len()..].trim_start();
            let Some(group) = rest.strip_prefix('(') else {
                // `import` as a statement keyword, not a call: no argument
                // list follows it.
                if lookup == "import" {
                    continue;
                }
                return true;
            };
            let Some(arguments) = balanced_group(group) else {
                return true;
            };
            if lookup == "import" && static_from_import_names(text, at, arguments, rest) {
                continue;
            }
            let name_argument = if matches!(lookup, "import" | "__import__" | "import_module") {
                arguments.split(',').next()
            } else {
                arguments.split(',').nth(1)
            };
            if name_argument
                .and_then(|argument| string_literal(argument.trim()))
                .is_none()
            {
                return true;
            }
        }
    }
    // Scan raw text conservatively. An apostrophe in a comment is not a
    // string delimiter, and guessing otherwise can hide a later subscript.
    // A computed access inside prose or a string may qualify the census as
    // unknown; this guard must never certify absence by skipping such text.
    for (at, _) in text.match_indices('[') {
        let before = text[..at].trim_end();
        let before = before.strip_suffix("?.").unwrap_or(before).trim_end();
        let subscript = before.chars().next_back().is_some_and(|previous| {
            previous.is_alphanumeric() || matches!(previous, '_' | '$' | ')' | ']' | '"' | '\'')
        });
        if !subscript {
            continue;
        }
        let Some(key) = text[at + 1..].split(']').next() else {
            return true;
        };
        let key = key.trim();
        let numeric = !key.is_empty()
            && key
                .chars()
                .all(|character| character.is_ascii_digit() || character == '-');
        if !numeric && string_literal(key).is_none() {
            return true;
        }
    }
    false
}

/// The language a file of this path is parsed as, by its extension, or
/// `None` for one no adapter parses.
pub fn language_of_path(path: &str) -> Option<LanguageId> {
    let extension = path.rsplit_once('.')?.1;
    Some(match extension {
        "py" | "pyi" => LanguageId::Python,
        "ts" | "tsx" | "mts" | "cts" => LanguageId::TypeScript,
        "js" | "jsx" | "mjs" | "cjs" => LanguageId::JavaScript,
        "go" => LanguageId::Go,
        "java" => LanguageId::Java,
        "rs" => LanguageId::Rust,
        "c" | "h" => LanguageId::C,
        "cpp" | "hpp" | "cc" | "cxx" | "hh" | "hxx" => LanguageId::Cpp,
        "cs" => LanguageId::CSharp,
        "rb" => LanguageId::Ruby,
        "php" => LanguageId::Php,
        "swift" => LanguageId::Swift,
        "kt" | "kts" => LanguageId::Kotlin,
        "tf" | "tfvars" => LanguageId::Hcl,
        _ => return None,
    })
}

/// Languages whose callers can call a focal of `language` by name: its own,
/// and the one it shares modules with, JavaScript with TypeScript and C with
/// C++.
pub fn calling_languages(language: LanguageId) -> Vec<LanguageId> {
    match language {
        LanguageId::TypeScript | LanguageId::JavaScript => {
            vec![LanguageId::TypeScript, LanguageId::JavaScript]
        }
        LanguageId::C | LanguageId::Cpp => vec![LanguageId::C, LanguageId::Cpp],
        other => vec![other],
    }
}

/// Whether a focal can be held as a value, so a call that never spells its
/// name may still reach it: the `focal_escapes` every predicate above takes.
///
/// Proven, never assumed. A reference edge is no proof either way: a
/// references pass can fail and leave none, a ledger censuses only call
/// expressions, so `handler = target` is recorded nowhere else, and a stale
/// reference can be retracted because a pass did not reproduce it. So the
/// focal is contained only when a census of its call names over the store's
/// text accounts for every occurrence, and anything unproven reads as
/// escaping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "escape", rename_all = "snake_case")]
pub enum FocalEscape {
    /// The selected graph records a scalar initializer and proves that its
    /// binding cannot be replaced in the calling domain.
    NonCallable {
        reason: &'static str,
        entities_checked: usize,
    },
    /// Some occurrence of the focal's name is not a call: it may be held as a
    /// value.
    Escapes { reason: &'static str },
    /// Every occurrence of the focal's call names in the store is a
    /// declaration of that name, an import binding it as itself, or a
    /// recorded call site's callee.
    Contained { entities_checked: usize },
    /// Could not be proven either way; consumers treat it as escaping.
    Unknown { reason: &'static str },
}

impl FocalEscape {
    /// Whether the focal may be held as a value: anything but a proven
    /// containment.
    pub fn may_escape(&self) -> bool {
        !matches!(self, Self::Contained { .. } | Self::NonCallable { .. })
    }
}

impl CallerSites {
    /// This reading with only the sites `keep` admits in its ledger. A
    /// reading with no ledger is returned as it is.
    pub fn retain_sites(&self, keep: impl Fn(&CallSite) -> bool) -> CallerSites {
        let narrow = |ledger: &CallSiteLedger| CallSiteLedger {
            sites: ledger
                .sites
                .iter()
                .filter(|site| keep(site))
                .cloned()
                .collect(),
            ..ledger.clone()
        };
        match self {
            Self::Current(ledger) => Self::Current(narrow(ledger)),
            Self::Stale(ledger) => Self::Stale(narrow(ledger)),
            Self::Unverified { ledger, reason } => Self::Unverified {
                ledger: narrow(ledger),
                reason: reason.clone(),
            },
            other => other.clone(),
        }
    }
}

/// A caller's reading restricted to what could reach a focal whose calls are
/// spelled `names`: its settled sites unchanged, its unsettled sites only
/// where [`site_could_call`] says so. A stale or unverified ledger is judged
/// by the states it recorded, and its reading stays unsettled by its caller
/// count whatever sites it keeps. A reading with no ledger is unchanged, and
/// unknown callee or body evidence keeps a site.
///
/// The ledger's census is kept: it still counts every call expression the
/// caller holds, and the sites dropped are ones that cannot call the focal.
pub fn scope_caller_sites(
    sites: &CallerSites,
    names: &[String],
    caller_body: Option<&str>,
    focal_escapes: bool,
) -> CallerSites {
    sites.retain_sites(|site| {
        SiteStateKind::of(&site.state).is_settled()
            || site_could_call(site, names, caller_body, focal_escapes).is_some()
    })
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
    /// Callers whose ledger context the selected graph has not validated.
    pub callers_unverified: u64,
    /// Recorded validation failures, or missing validation, by caller count.
    pub unverified_contexts: BTreeMap<String, u64>,
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
            CallerSites::Stale(_) | CallerSites::Current(_) | CallerSites::Unverified { .. } => {
                if matches!(reading, CallerSites::Stale(_)) {
                    self.callers_stale += 1;
                }
                if let CallerSites::Unverified { reason, .. } = reading {
                    self.callers_unverified += 1;
                    *self.unverified_contexts.entry(reason.clone()).or_insert(0) += 1;
                }
                let ledger = reading.ledger().expect("a recorded reading holds a ledger");
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
        self.callers_unverified += other.callers_unverified;
        for (reason, count) in &other.unverified_contexts {
            *self.unverified_contexts.entry(reason.clone()).or_insert(0) += count;
        }
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
            && self.callers_stale == 0
            && self.callers_unverified == 0
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
        if self.callers_stale > 0 && self.count(SiteStateKind::ProofContextStale) == 0 {
            clauses.push(format!(
                "{PROOF_CONTEXT_STALE}: {} of the {} callers in {scope} have a recorded ledger whose context differs from the selected graph's validated context, so its empty site set does not establish absence",
                self.callers_stale, self.callers
            ));
        }
        if self.callers_unverified > 0 {
            // Reasons are data, not additional verdict clauses. Preserve their
            // original text in the structured map and keep the clause boundary.
            let reasons = self
                .unverified_contexts
                .keys()
                .map(|reason| reason.replace("; ", ", "))
                .collect::<Vec<_>>()
                .join(", ");
            clauses.push(format!(
                "{PROOF_CONTEXT_UNVERIFIED}: {} of the {} callers in {scope} have recorded call-site evidence whose proof context is unverified ({reasons}), so these proofs do not establish current validity",
                self.callers_unverified, self.callers
            ));
        }
        for (kind, count) in &self.by_state {
            if let Some(code) = kind.verdict_code() {
                if code == PROOF_CONTEXT_UNVERIFIED {
                    continue;
                }
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
            "callers_unverified": self.callers_unverified,
            "unverified_contexts": self.unverified_contexts,
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

        {
            let current = Some(context(5));
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
                current: Some(context(5)),
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
    fn context_validation_missing_keeps_recorded_sites_but_never_certifies() {
        let run = caller(1, true);
        let held = ledger(&run, context(5));
        let facts = Facts {
            ledgers: vec![held.clone()],
            ..Facts::default()
        };
        let reading = read_caller_sites(&facts, &run);
        assert!(matches!(&reading, CallerSites::Unverified { .. }));
        assert_eq!(reading.ledger(), Some(&held));
        assert_eq!(
            reading.site_kind(&held.sites[0]),
            SiteStateKind::ProofContextUnverified
        );
        let mut tally = CallSiteTally::default();
        tally.add(&reading);
        assert!(!tally.is_settled());
        assert_eq!(tally.callers_unverified, 1);
        assert_eq!(tally.sites, 5);
        assert_eq!(tally.count(SiteStateKind::ProofContextUnverified), 5);
        assert_eq!(tally.clauses("scope").len(), 1);
        assert!(tally.clauses("scope")[0].starts_with(PROOF_CONTEXT_UNVERIFIED));
        let mut merged = CallSiteTally::default();
        merged.merge(&tally);
        assert_eq!(merged.to_json(), tally.to_json());
        let empty = CallerSites::Unverified {
            ledger: CallSiteLedger {
                census: 0,
                sites: vec![],
                ..held
            },
            reason: "validation failed; retry needed".into(),
        };
        let mut tally = CallSiteTally::default();
        tally.add(&empty);
        assert!(
            !tally.is_settled(),
            "an empty ledger is still recorded proof"
        );
        assert_eq!(tally.clauses("scope").len(), 1);
        assert!(!tally.clauses("scope")[0].contains("; "));
    }

    #[test]
    fn context_validation_stale_empty_ledger_cannot_certify_but_current_empty_can() {
        let run = caller(1, true);
        let held = CallSiteLedger {
            census: 0,
            sites: vec![],
            ..ledger(&run, context(5))
        };
        let facts = Facts {
            ledgers: vec![held.clone()],
            current: Some(context(6)),
            ..Facts::default()
        };
        let reading = read_caller_sites(&facts, &run);
        assert!(matches!(reading, CallerSites::Stale(_)));
        let mut stale = CallSiteTally::default();
        stale.add(&reading);
        assert_eq!(stale.sites, 0);
        assert!(!stale.is_settled());
        assert_eq!(stale.clauses("scope").len(), 1);
        assert!(stale.clauses("scope")[0].starts_with(PROOF_CONTEXT_STALE));
        assert!(!stale.clauses("scope")[0].contains("; "));
        for reading in [CallerSites::Current(held), CallerSites::NoSites] {
            let mut tally = CallSiteTally::default();
            tally.add(&reading);
            assert!(tally.is_settled());
            assert!(tally.clauses("scope").is_empty());
        }
    }

    #[test]
    fn a_tally_names_every_unsettled_state_and_certifies_only_a_settled_scope() {
        let run = caller(1, true);
        let other = caller(3, true);
        let facts = Facts {
            ledgers: vec![ledger(&run, context(5))],
            current: Some(context(5)),
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

    fn named(name: &str, kind: EntityKind) -> Entity {
        Entity {
            name: name.to_string(),
            kind,
            ..caller(9, true)
        }
    }

    fn names(name: &str, kind: EntityKind) -> Vec<String> {
        focal_call_names(&named(name, kind))
    }

    /// A method is called by its member and a function by its own name, so
    /// the owner is no call name for either. A constructor is called by its
    /// type as well as its own name, and a class by its name.
    #[test]
    fn focal_call_names_match_the_member_segment_of_a_method_that_is_not_a_constructor() {
        assert_eq!(
            names("Store.containsElement", EntityKind::Method),
            ["containsElement"]
        );
        assert_eq!(names("AppContext.pop", EntityKind::Method), ["pop"]);
        assert_eq!(names("Store::open", EntityKind::Method), ["open"]);
        assert_eq!(
            names("_make_timedelta", EntityKind::Function),
            ["_make_timedelta"]
        );
        assert_eq!(
            names("HTTPAdapter.__init__", EntityKind::Method),
            ["HTTPAdapter", "__init__"]
        );
        assert_eq!(
            names("Foo.constructor", EntityKind::Method),
            ["Foo", "constructor"]
        );
        assert_eq!(names("Store::new", EntityKind::Method), ["Store", "new"]);
        assert_eq!(names("Point.Point", EntityKind::Method), ["Point"]);
        assert_eq!(names("Outer.Inner", EntityKind::Class), ["Outer", "Inner"]);
        assert_eq!(names("Session", EntityKind::Class), ["Session"]);
        assert!(names("", EntityKind::Method).is_empty());
    }

    const BODY: &str = "def run(ctx):\n    ctx.pop()\n    json.dumps(x)\n    handler(x)\n    getattr(ctx, \"pop\")()\n    callback(x)\n";

    /// The site at `token` in [`BODY`], in `state`.
    fn site_at(token: &str, state: CallSiteState) -> CallSite {
        let offset = BODY.find(token).expect("the token is in the body");
        CallSite {
            offset: offset as u32,
            length: token.len() as u32,
            state,
        }
    }

    fn unresolved(reason: UnresolvedReason) -> CallSiteState {
        CallSiteState::Unresolved { reason }
    }

    fn reach(site: &CallSite, names: &[String], escapes: bool) -> Option<&'static str> {
        site_could_call_at(site, site_text(site, BODY), names, Some(BODY), escapes)
    }

    #[test]
    fn an_unsettled_site_whose_callee_is_another_name_cannot_call_the_focal() {
        let pop = vec!["pop".to_string()];
        let dumps = site_at("dumps", unresolved(UnresolvedReason::NoAnswer));
        assert_eq!(site_text(&dumps, BODY), Some("dumps"));
        assert_eq!(reach(&dumps, &pop, false), None);
        assert_eq!(
            reach(&dumps, &pop, true),
            Some(REACH_FOCAL_ESCAPES),
            "an unresolved site proves no other declaration, so an escaped focal may be its callee"
        );
        let failed = site_at(
            "dumps",
            CallSiteState::ServerFailed {
                reason: crate::ServerFailure::Timeout,
            },
        );
        assert_eq!(reach(&failed, &pop, false), None);
        let named = site_at("pop", unresolved(UnresolvedReason::NoAnswer));
        assert_eq!(reach(&named, &pop, false), Some(REACH_CALLEE_SPELLS));
        let failed_named = site_at(
            "pop",
            CallSiteState::ServerFailed {
                reason: crate::ServerFailure::Crash,
            },
        );
        assert_eq!(reach(&failed_named, &pop, false), Some(REACH_CALLEE_SPELLS));
        let settled = site_at(
            "pop",
            CallSiteState::ProvenTarget {
                target: EntityId(Uuid::from_u128(1)),
            },
        );
        assert_eq!(
            reach(&settled, &pop, true),
            None,
            "a settled site is not asked"
        );
    }

    /// No unresolved reason proves the callee is another named declaration,
    /// so once the focal escapes as a value, `callback()` with no definition
    /// answer may call it. While it does not escape, a token that is not its
    /// name rules the site out.
    #[test]
    fn an_unresolved_site_at_another_callee_counts_only_when_the_focal_escapes() {
        let timedelta = vec!["_make_timedelta".to_string()];
        for reason in [
            UnresolvedReason::NoAnswer,
            UnresolvedReason::OutsideTheGraph,
            UnresolvedReason::AnswersDisagree,
        ] {
            let site = site_at("callback", unresolved(reason));
            assert_eq!(site_text(&site, BODY), Some("callback"));
            assert_eq!(
                reach(&site, &timedelta, true),
                Some(REACH_FOCAL_ESCAPES),
                "{reason:?}"
            );
            assert_eq!(
                site_could_call(&site, &timedelta, None, true),
                Some(REACH_FOCAL_ESCAPES),
                "{reason:?}"
            );
            assert_eq!(reach(&site, &timedelta, false), None, "{reason:?}");
        }
        let spelled = site_at("pop", unresolved(UnresolvedReason::NoAnswer));
        assert_eq!(
            reach(&spelled, &["pop".to_string()], true),
            Some(REACH_CALLEE_SPELLS),
            "a token that spells the name says so, escaped or not"
        );
    }

    /// A binding's callee text is its slot's name, never its target's, so
    /// no text, known, unknown or spelling the name, places the focal there.
    /// Only the focal escaping as a value does.
    #[test]
    fn a_binding_site_is_decided_by_the_focal_escaping_alone() {
        let pop = vec!["pop".to_string()];
        let slot = site_at("handler", CallSiteState::Binding { may_call: None });
        assert_eq!(
            site_could_call(&slot, &pop, Some(BODY), false),
            None,
            "a body spelling the name does not place the focal in a slot"
        );
        assert_eq!(site_could_call(&slot, &pop, None, false), None);
        assert_eq!(
            site_could_call(&slot, &pop, Some(BODY), true),
            Some(REACH_FOCAL_ESCAPES)
        );
        assert_eq!(
            site_could_call(&slot, &pop, None, true),
            Some(REACH_FOCAL_ESCAPES)
        );
        let named_slot = site_at("pop", CallSiteState::Binding { may_call: None });
        assert_eq!(reach(&named_slot, &pop, false), None);
        assert_eq!(reach(&named_slot, &pop, true), Some(REACH_CALLEE_SPELLS));
    }

    #[test]
    fn a_binding_site_counts_only_when_the_focal_escapes_as_a_value() {
        let timedelta = vec!["_make_timedelta".to_string()];
        let binding = site_at("handler", CallSiteState::Binding { may_call: None });
        assert_eq!(reach(&binding, &timedelta, false), None);
        assert_eq!(reach(&binding, &timedelta, true), Some(REACH_FOCAL_ESCAPES));
        // A server that failed, or a file no build compiles, never said the
        // site was not a binding.
        for state in [
            CallSiteState::ServerFailed {
                reason: crate::ServerFailure::ProtocolError,
            },
            CallSiteState::NotInBuild {
                reason: "no build".into(),
            },
        ] {
            let site = site_at("handler", state);
            assert_eq!(reach(&site, &timedelta, false), None);
            assert_eq!(reach(&site, &timedelta, true), Some(REACH_FOCAL_ESCAPES));
        }
    }

    /// A site with no placeable callee is judged by its callee expression:
    /// a literal lookup counts only when a literal spells the name, a dynamic
    /// one always, and one whose text is not held is read as dynamic.
    #[test]
    fn an_unplaceable_site_counts_by_its_access_literal_or_dynamic() {
        let pop = vec!["pop".to_string()];
        let other = vec!["push".to_string()];
        let expression = "getattr(ctx, \"pop\")()";
        for reason in [
            UnresolvedReason::CalleeNotPlaceable,
            UnresolvedReason::Reflective,
        ] {
            let site = site_at(expression, unresolved(reason));
            assert_eq!(reach(&site, &pop, false), Some(REACH_CALLEE_SPELLS));
            assert_eq!(
                reach(&site, &other, false),
                None,
                "a literal that spells another name cannot reach a contained focal"
            );
            assert_eq!(
                reach(&site, &other, true),
                Some(REACH_FOCAL_ESCAPES),
                "an escaped focal may be stored under any literal name"
            );
            assert_eq!(
                site_could_call(&site, &other, None, false),
                Some(REACH_DYNAMIC_ACCESS),
                "an access whose text is not held reads as dynamic"
            );
        }
        let not_in_build = site_at(
            expression,
            CallSiteState::NotInBuild {
                reason: "no build".into(),
            },
        );
        assert_eq!(reach(&not_in_build, &pop, false), Some(REACH_CALLEE_SPELLS));
        assert_eq!(reach(&not_in_build, &other, false), None);
        // A pass that never asked about a token leaves it not placeable, and
        // its token still names what it calls.
        let unasked = site_at("pop", unresolved(UnresolvedReason::CalleeNotPlaceable));
        assert_eq!(reach(&unasked, &pop, false), Some(REACH_CALLEE_SPELLS));
        assert_eq!(reach(&unasked, &other, false), None);
    }

    /// `getattr(ctx, 'po' + 'p')` reaches `pop` without spelling it.
    #[test]
    fn a_dynamic_access_stays_a_candidate_whatever_the_name() {
        const DYNAMIC: &str = "def run(ctx, key):\n    getattr(ctx, 'po' + 'p')()\n    handlers[key](1)\n    make()(2)\n";
        let at = |token: &str| {
            let offset = DYNAMIC.find(token).expect("token in body");
            CallSite {
                offset: offset as u32,
                length: token.len() as u32,
                state: unresolved(UnresolvedReason::CalleeNotPlaceable),
            }
        };
        let other = vec!["push".to_string()];
        for expression in ["getattr(ctx, 'po' + 'p')()", "handlers[key](1)"] {
            let site = at(expression);
            assert_eq!(
                site_could_call_at(
                    &site,
                    site_text(&site, DYNAMIC),
                    &other,
                    Some(DYNAMIC),
                    false
                ),
                Some(REACH_DYNAMIC_ACCESS),
                "{expression}"
            );
        }
        let through_value = at("make()(2)");
        assert_eq!(
            site_could_call_at(
                &through_value,
                site_text(&through_value, DYNAMIC),
                &other,
                Some(DYNAMIC),
                false
            ),
            None,
            "a call through a produced value reaches only an escaped focal"
        );
        assert_eq!(
            site_could_call_at(
                &through_value,
                site_text(&through_value, DYNAMIC),
                &other,
                Some(DYNAMIC),
                true
            ),
            Some(REACH_FOCAL_ESCAPES)
        );
    }

    #[test]
    fn unplaceable_access_reads_the_callee_part_only() {
        assert_eq!(
            unplaceable_access("getattr(ctx, \"pop\")()"),
            UnplaceableAccess::Literal(vec!["pop".into()])
        );
        assert_eq!(
            unplaceable_access("handlers[\"push\"](x)"),
            UnplaceableAccess::Literal(vec!["push".into()])
        );
        assert_eq!(
            unplaceable_access("getattr(ctx, name)()"),
            UnplaceableAccess::Dynamic
        );
        assert_eq!(
            unplaceable_access("getattr(ctx, 'po' + 'p')()"),
            UnplaceableAccess::Dynamic
        );
        assert_eq!(
            unplaceable_access("getattr(self, f\"on_{e}\")()"),
            UnplaceableAccess::Dynamic
        );
        assert_eq!(
            unplaceable_access("globals()[n]()"),
            UnplaceableAccess::Dynamic
        );
        assert_eq!(
            unplaceable_access("Reflect.apply(f, t, [])"),
            UnplaceableAccess::Dynamic
        );
        assert_eq!(
            unplaceable_access("pair[0](x)"),
            UnplaceableAccess::ThroughValue
        );
        assert_eq!(
            unplaceable_access("make()(eval(x))"),
            UnplaceableAccess::ThroughValue,
            "the arguments are not the callee"
        );
    }

    #[test]
    fn holds_dynamic_access_finds_computed_names_anywhere() {
        for text in [
            "handler = obj[key]",
            "handler = mod?.[key]",
            "// don't hide the next access\nhandler = mod[key]",
            "# don't hide the next access\nhandler = mod[key]",
            "/* caller's handler */ handler = mod?.[key]",
            "h = getattr(m, name)",
            "f = globals()[n]",
            "g = eval(src)",
            "x = importlib.import_module(mod)",
            "name = 'po' + 'p'",
            "name = f\"{a}\"",
            "v = obj.__dict__",
        ] {
            assert!(holds_dynamic_access(text), "{text}");
        }
        for text in [
            "handler = obj[\"key\"]",
            "handler = mod?.[\"key\"]",
            "// caller's comment\nhandler = target()",
            "first = items[0]",
            "h = getattr(m, \"name\")",
            "import os\nfrom pkg import target\n",
            "def target(x):\n    return x\n",
        ] {
            assert!(!holds_dynamic_access(text), "{text}");
        }
    }

    #[test]
    fn static_parenthesized_imports_do_not_hide_dynamic_imports_or_access() {
        for text in [
            "from pkg.lib import (\n other, target,\n)\n",
            "from .pkg import (target as alias)\n",
            "from .. import (target,)",
            "import(\"./known.js\")",
        ] {
            assert!(!holds_dynamic_access(text), "{text}");
        }
        for text in [
            "import(moduleName)",
            "from pkg import (target + suffix)",
            "from pkg import (target,, other)",
            "from pkg import (target # comment\n)",
            "from pkg import (target",
            "import(moduleName",
            "from pkg import (target) extra",
            "from pkg import (target)\nmod?.[key]",
            "from pkg import (target)\n// caller's note\nmod[key]",
        ] {
            assert!(holds_dynamic_access(text), "{text}");
        }
    }

    #[test]
    fn language_of_path_follows_the_parsers_extensions() {
        assert_eq!(
            language_of_path("src/flask/app.py"),
            Some(LanguageId::Python)
        );
        assert_eq!(language_of_path("a/b.tsx"), Some(LanguageId::TypeScript));
        assert_eq!(language_of_path("a/b.mjs"), Some(LanguageId::JavaScript));
        assert_eq!(language_of_path("README.md"), None);
        assert_eq!(language_of_path("Makefile"), None);
    }

    /// Without the site's own text the callee cannot be compared, so a body
    /// that spells the name keeps a placeable site, one that does not rules it
    /// out, and no body keeps it.
    #[test]
    fn without_the_site_text_the_body_decides_and_unknown_keeps_the_site() {
        let pop = vec!["pop".to_string()];
        let dumps = site_at("dumps", unresolved(UnresolvedReason::NoAnswer));
        assert_eq!(
            site_could_call(&dumps, &pop, Some(BODY), false),
            Some(REACH_BODY_SPELLS)
        );
        assert_eq!(
            site_could_call(&dumps, &pop, Some("def f(): json.dumps(x)"), false),
            None
        );
        assert_eq!(
            site_could_call(&dumps, &pop, None, false),
            Some(REACH_TEXT_UNKNOWN)
        );
        assert_eq!(
            site_could_call(&dumps, &[], Some(BODY), false),
            Some(REACH_NAME_UNKNOWN),
            "a focal with no call name rules nothing out"
        );
    }

    #[test]
    fn a_scoped_reading_keeps_settled_sites_and_the_unsettled_ones_that_could_call() {
        let run = caller(1, true);
        let target = EntityId(Uuid::from_u128(99));
        let ledger = CallSiteLedger {
            caller: run.id,
            behavior_hash: run.fingerprint.behavior_hash,
            body_hash: Hash256::from_bytes([1; 32]),
            context: context(5),
            census: 4,
            sites: vec![
                site_at("pop", CallSiteState::ProvenTarget { target }),
                site_at("dumps", unresolved(UnresolvedReason::NoAnswer)),
                site_at("handler", CallSiteState::Binding { may_call: None }),
                site_at(
                    "getattr(ctx, \"pop\")()",
                    unresolved(UnresolvedReason::CalleeNotPlaceable),
                ),
            ],
        };
        let reading = CallerSites::Current(ledger.clone());
        let pop = vec!["pop".to_string()];
        let body = "def run(ctx): ctx.pop() json.dumps(x) handler(x) getattr(ctx, \"pop\")()";
        let scoped = scope_caller_sites(&reading, &pop, Some(body), false);
        let kept = scoped.ledger().expect("a ledger").clone();
        assert_eq!(kept.census, 4, "the census still counts every expression");
        // Without site text the body spells `pop`, so every unsettled site is
        // kept but the binding, which needs the focal to escape.
        assert_eq!(
            kept.sites
                .iter()
                .map(|site| site.state.wire())
                .collect::<Vec<_>>(),
            ["proven_target", "unresolved", "unresolved"]
        );
        let precise = reading.retain_sites(|site| {
            SiteStateKind::of(&site.state).is_settled()
                || site_could_call_at(site, site_text(site, BODY), &pop, Some(BODY), false)
                    .is_some()
        });
        let mut tally = CallSiteTally::default();
        tally.add(&precise);
        assert_eq!(tally.sites, 2, "{tally:?}");
        assert_eq!(tally.count(SiteStateKind::Unresolved), 1);
        assert_eq!(
            tally
                .clauses("scope")
                .iter()
                .map(|clause| clause.split(':').next().unwrap())
                .collect::<Vec<_>>(),
            [CALL_SITES_UNRESOLVED]
        );
        // Without its text, the unplaceable site reads as dynamic and stays;
        // with it, its literal spells another name and it goes.
        let push = vec!["push".to_string()];
        let unread = scope_caller_sites(&reading, &push, Some(body), false);
        assert_eq!(unread.ledger().expect("a ledger").sites.len(), 2);
        let nothing = reading.retain_sites(|site| {
            SiteStateKind::of(&site.state).is_settled()
                || site_could_call_at(site, site_text(site, BODY), &push, Some(BODY), false)
                    .is_some()
        });
        let mut settled = CallSiteTally::default();
        settled.add(&nothing);
        assert!(settled.is_settled(), "{settled:?}");
        for unchanged in [CallerSites::OwedEnrichment, CallerSites::NoSites] {
            assert_eq!(scope_caller_sites(&unchanged, &pop, None, true), unchanged);
        }
        let stale = scope_caller_sites(&CallerSites::Stale(ledger), &pop, Some(body), false);
        let mut stale_tally = CallSiteTally::default();
        stale_tally.add(&stale);
        assert!(!stale_tally.is_settled(), "a stale reading stays unsettled");
    }

    #[test]
    fn each_state_s_share_is_its_part_of_the_census_and_the_shares_make_the_whole() {
        let run = caller(1, true);
        let facts = Facts {
            ledgers: vec![ledger(&run, context(5))],
            current: Some(context(5)),
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
