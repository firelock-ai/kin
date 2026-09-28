// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Resolution records: what a resolver proved about calls, and under which
//! proof context it proved it.
//!
//! A resolution record is graph state beside entities, relations and external
//! references. There are three kinds:
//!
//! - a [`ProofContext`] names the resolver that answered, its version, and
//!   hashes of the configuration and environment it answered under. Proven
//!   edges point at one through their evidence token
//!   ([`ResolutionRecordId::context_token`]), so a reader can tell which
//!   resolver proved an edge and whether that proof is still current;
//! - a [`CallSiteLedger`] holds the state of every call site inside one caller;
//! - a [`DispatchSet`] holds the declarations one dynamic call may reach.
//!
//! Records follow the graph they describe. [`ResolutionRecordSet::plan`]
//! decides, with the entity and external-reference deltas of the same
//! transaction, which records a transaction retires without naming them: a
//! ledger whose caller changes or is removed, and any record that names a node
//! the transaction removes. Every store applies that one rule, so the live
//! graph, history replay and workspace overlays agree about which records
//! survive.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::fmt;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::change::{EntityDelta, TransactionDelta};
use crate::external_reference::{ExternalReferenceDelta, ExternalReferenceId};
use crate::ids::{EntityId, Hash256, LanguageId};
use crate::relation::GraphNodeId;
use crate::{ModelError, Result};

/// UUID-v5 namespace for resolution-record identities.
///
/// This immutable namespace is itself UUID-v5 derived from
/// `https://kin.dev/namespaces/resolution-record-id/v1`. Changing it would
/// change every persisted resolution-record ID.
pub const RESOLUTION_RECORD_ID_NAMESPACE_V1: Uuid =
    Uuid::from_u128(0x5776_427f_aa7f_56c8_bc6e_7760_18e9_bca9);

const RESOLUTION_RECORD_ID_DOMAIN_V1: &[u8] = b"kin.resolution-record.id.v1\0";

/// The prefix of the evidence token that names a proof context.
pub const PROOF_CONTEXT_TOKEN_PREFIX: &str = "ctx:";

const MAX_RESOLVER_BYTES: usize = 128;
const MAX_VERSION_BYTES: usize = 256;
const MAX_SUMMARY_BYTES: usize = 4096;
const MAX_REASON_BYTES: usize = 512;

/// Stable identity of one resolution record.
///
/// Domain-separated UUID-v5. A proof context is addressed by its whole
/// content, so one context is one record wherever it is recorded. A ledger is
/// addressed by its caller, so a caller has at most one. A dispatch set is
/// addressed by its scope and the context it was proven under.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, JsonSchema,
)]
pub struct ResolutionRecordId(pub Uuid);

impl ResolutionRecordId {
    /// The identity of `context`, derived from every field it carries.
    pub fn proof_context(context: &ProofContext) -> Self {
        let mut preimage = IdPreimage::new(b"proof_context");
        preimage.field(context.language.to_string().as_bytes());
        preimage.field(context.resolver.as_bytes());
        preimage.field(context.resolver_version.as_bytes());
        preimage.field(context.configuration_hash.as_bytes());
        preimage.field(context.environment_hash.as_bytes());
        preimage.field(context.environment_summary.as_bytes());
        preimage.finish()
    }

    /// The identity of the ledger of `caller`'s call sites.
    pub fn call_sites(caller: EntityId) -> Self {
        let mut preimage = IdPreimage::new(b"call_sites");
        preimage.field(caller.0.as_bytes());
        preimage.finish()
    }

    /// The identity of the dispatch set over `scope` proven under `context`.
    pub fn dispatch_set(scope: &DispatchScope, context: ResolutionRecordId) -> Self {
        let mut preimage = IdPreimage::new(b"dispatch_set");
        match scope {
            DispatchScope::Declaration { declaration } => {
                preimage.field(b"declaration");
                preimage.field(declaration.0.as_bytes());
            }
            DispatchScope::Site {
                caller,
                offset,
                length,
            } => {
                preimage.field(b"site");
                preimage.field(caller.0.as_bytes());
                preimage.field(&offset.to_le_bytes());
                preimage.field(&length.to_le_bytes());
            }
        }
        preimage.field(context.0.as_bytes());
        preimage.finish()
    }

    /// The identity of the one record saying which proof context `language`'s
    /// call-site ledgers are current under.
    pub fn context_validation(language: LanguageId) -> Self {
        let mut preimage = IdPreimage::new(b"context_validation");
        preimage.field(language.to_string().as_bytes());
        preimage.finish()
    }

    /// The evidence token a proven edge carries to name this proof context:
    /// `ctx:<uuid>`.
    pub fn context_token(&self) -> String {
        format!("{PROOF_CONTEXT_TOKEN_PREFIX}{}", self.0)
    }

    /// The proof context an evidence token names, when it names one.
    pub fn from_context_token(token: &str) -> Option<Self> {
        let uuid = token.strip_prefix(PROOF_CONTEXT_TOKEN_PREFIX)?;
        Uuid::parse_str(uuid).ok().map(Self)
    }
}

impl fmt::Display for ResolutionRecordId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

/// A length-prefixed, domain-separated identity preimage.
struct IdPreimage(Vec<u8>);

impl IdPreimage {
    fn new(kind: &[u8]) -> Self {
        let mut preimage = Self(Vec::with_capacity(128));
        preimage.0.extend_from_slice(RESOLUTION_RECORD_ID_DOMAIN_V1);
        preimage.field(kind);
        preimage
    }

    fn field(&mut self, value: &[u8]) {
        self.0
            .extend_from_slice(&(value.len() as u64).to_le_bytes());
        self.0.extend_from_slice(value);
    }

    fn finish(self) -> ResolutionRecordId {
        ResolutionRecordId(Uuid::new_v5(&RESOLUTION_RECORD_ID_NAMESPACE_V1, &self.0))
    }
}

/// Which resolver proved something, and under what.
///
/// Two proofs made under equal contexts were made by the same resolver at the
/// same version, configured the same way, against the same toolchain and
/// dependency versions. A proof whose context is no longer the one the
/// resolver runs under is stale.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProofContext {
    /// The language the resolver answered for.
    pub language: LanguageId,
    /// The resolver, as `<kind>:<name>`: `lsp:pyright`, `lsp:tsserver`,
    /// `scip:scip-typescript`, `tsc-api`, `go-vta`.
    pub resolver: String,
    /// The resolver's own version, as it reported it.
    pub resolver_version: String,
    /// A hash over everything the resolver was configured with: initialize
    /// options, workspace configuration answers, the adapter's own settings and
    /// the repository-relative workspace folders.
    pub configuration_hash: Hash256,
    /// The identity of the environment it answered against: the toolchain and
    /// the dependency versions the repository's lock names.
    pub environment_hash: Hash256,
    /// The environment in a few words, for a reader. Never a local path.
    pub environment_summary: String,
}

impl ProofContext {
    fn validate(&self) -> Result<()> {
        validate_resolver(&self.resolver)?;
        validate_text(
            "proof-context resolver version",
            &self.resolver_version,
            MAX_VERSION_BYTES,
            false,
        )?;
        validate_text(
            "proof-context environment summary",
            &self.environment_summary,
            MAX_SUMMARY_BYTES,
            true,
        )
    }
}

/// The state of every call site inside one caller, as one resolver left it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CallSiteLedger {
    /// The entity whose body holds the sites.
    pub caller: EntityId,
    /// The caller's behavior hash when the ledger was written.
    pub behavior_hash: Hash256,
    /// The body of the caller's file when the ledger was written.
    pub body_hash: Hash256,
    /// The proof context every proven site in the ledger was proven under.
    pub context: ResolutionRecordId,
    /// How many call expressions the parser reads in the caller.
    pub census: u32,
    /// Exactly `census` sites, sorted by callee token and unique.
    pub sites: Vec<CallSite>,
}

impl CallSiteLedger {
    fn validate(&self) -> Result<()> {
        if self.sites.len() as u64 != u64::from(self.census) {
            return Err(ModelError::InvalidOperation(format!(
                "call-site ledger of {} counts {} call expressions and holds {} sites",
                self.caller,
                self.census,
                self.sites.len()
            )));
        }
        if self
            .sites
            .windows(2)
            .any(|pair| pair[0].key() >= pair[1].key())
        {
            return Err(ModelError::InvalidOperation(format!(
                "call-site ledger of {} is not in canonical unique site order",
                self.caller
            )));
        }
        for site in &self.sites {
            if site.length == 0 {
                return Err(ModelError::InvalidOperation(format!(
                    "call-site ledger of {} holds an empty callee token at offset {}",
                    self.caller, site.offset
                )));
            }
            site.state.validate()?;
        }
        Ok(())
    }

    /// The site keyed by `(offset, length)`, when the ledger holds one.
    pub fn site(&self, offset: u32, length: u32) -> Option<&CallSite> {
        self.sites
            .binary_search_by_key(&(offset, length), CallSite::key)
            .ok()
            .map(|at| &self.sites[at])
    }

    /// Check the ledger against the `Calls` edges its caller holds.
    ///
    /// Every site whose state proves a target must be carried by a
    /// language-server `Calls` edge from the caller to that target, with an
    /// evidence record at exactly that site in `file` whose token names this
    /// ledger's proof context. A recursive call proves its own caller and is
    /// the one proof no edge carries, since the graph keeps no edge from an
    /// entity to itself.
    ///
    /// `caller_start_byte` is where the caller's own text starts in `file`,
    /// the origin the ledger's offsets are counted from, and `calls` are the
    /// caller's outgoing edges; any other edge is ignored.
    pub fn validate_backing<'r>(
        &self,
        caller_start_byte: usize,
        file: &str,
        calls: impl IntoIterator<Item = &'r crate::Relation>,
    ) -> Result<()> {
        let token = self.context.context_token();
        let caller = GraphNodeId::Entity(self.caller);
        let mut carried: HashSet<(GraphNodeId, u32, u32)> = HashSet::new();
        for relation in calls {
            if relation.kind != crate::RelationKind::Calls
                || relation.origin != crate::RelationOrigin::Lsp
                || relation.src != caller
            {
                continue;
            }
            for evidence in &relation.evidence {
                let Some(span) = evidence.source_span.as_ref() else {
                    continue;
                };
                if span.file.0 != file || evidence.token.as_deref() != Some(token.as_str()) {
                    continue;
                }
                if let Some(key) = site_key(caller_start_byte, span.start_byte, span.end_byte) {
                    carried.insert((relation.dst, key.0, key.1));
                }
            }
        }
        for site in &self.sites {
            let Some(target) = site.state.proven_node() else {
                continue;
            };
            if target == caller {
                continue;
            }
            if !carried.contains(&(target, site.offset, site.length)) {
                return Err(ModelError::InvalidOperation(format!(
                    "call-site ledger of {} proves {} at offset {} length {} and no call edge \
                     carries that site under proof context {}",
                    self.caller, target, site.offset, site.length, self.context
                )));
            }
        }
        Ok(())
    }
}

/// The key a ledger gives the token at `start..end` of a file, counted from
/// the caller's first byte at `caller_start`: its offset within the caller
/// and its length. `None` for an empty token, one before the caller, or one
/// whose position does not fit the key.
pub fn site_key(caller_start: usize, start: usize, end: usize) -> Option<(u32, u32)> {
    if end <= start || start < caller_start {
        return None;
    }
    let offset = u32::try_from(start - caller_start).ok()?;
    let length = u32::try_from(end - start).ok()?;
    Some((offset, length))
}

/// One call expression inside a caller, keyed by its callee token.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CallSite {
    /// Byte offset of the callee token within the caller's own text.
    pub offset: u32,
    /// Byte length of the callee token.
    pub length: u32,
    pub state: CallSiteState,
}

impl CallSite {
    /// The site's key: its offset within the caller, then its length.
    pub fn key(&self) -> (u32, u32) {
        (self.offset, self.length)
    }
}

/// What is known about the declaration one call site reaches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum CallSiteState {
    /// The call names this repository declaration.
    ProvenTarget { target: EntityId },
    /// The call names this symbol outside the repository.
    ProvenExternal { target: ExternalReferenceId },
    /// The call names a declaration outside the repository that could not be
    /// named as a symbol. It still refutes every in-repository guess.
    ProvenOutside,
    /// The call names a declaration that dispatches at run time, and `set`
    /// lists what it may reach when that is known.
    ProvenDeclaration {
        declaration: EntityId,
        set: Option<ResolutionRecordId>,
    },
    /// The callee is a value binding. `may_call` lists what it may hold when
    /// that is known. Never a proof.
    Binding {
        may_call: Option<ResolutionRecordId>,
    },
    /// No build of the repository compiles the caller.
    NotInBuild { reason: String },
    /// The resolver timed out, crashed or broke protocol at this site.
    ServerFailed { reason: ServerFailure },
    /// The resolver answered and the answer proves nothing.
    Unresolved { reason: UnresolvedReason },
}

impl CallSiteState {
    fn validate(&self) -> Result<()> {
        if let Self::NotInBuild { reason } = self {
            validate_text("not-in-build reason", reason, MAX_REASON_BYTES, false)?;
        }
        Ok(())
    }

    /// The node a proven state says the call reaches, which a `Calls` edge
    /// must carry the site to. `None` for every state that proves no target.
    pub fn proven_node(&self) -> Option<GraphNodeId> {
        match self {
            Self::ProvenTarget { target } => Some(GraphNodeId::Entity(*target)),
            Self::ProvenExternal { target } => Some(GraphNodeId::ExternalReference(*target)),
            Self::ProvenDeclaration { declaration, .. } => Some(GraphNodeId::Entity(*declaration)),
            Self::ProvenOutside
            | Self::Binding { .. }
            | Self::NotInBuild { .. }
            | Self::ServerFailed { .. }
            | Self::Unresolved { .. } => None,
        }
    }

    /// The state's name, as payloads spell it.
    pub fn wire(&self) -> &'static str {
        match self {
            Self::ProvenTarget { .. } => "proven_target",
            Self::ProvenExternal { .. } => "proven_external",
            Self::ProvenOutside => "proven_outside",
            Self::ProvenDeclaration { .. } => "proven_declaration",
            Self::Binding { .. } => "binding",
            Self::NotInBuild { .. } => "not_in_build",
            Self::ServerFailed { .. } => "server_failed",
            Self::Unresolved { .. } => "unresolved",
        }
    }

    /// The graph nodes this state names.
    fn named_nodes(&self, out: &mut Vec<GraphNodeId>) {
        match self {
            Self::ProvenTarget { target } => out.push(GraphNodeId::Entity(*target)),
            Self::ProvenExternal { target } => out.push(GraphNodeId::ExternalReference(*target)),
            Self::ProvenDeclaration { declaration, .. } => {
                out.push(GraphNodeId::Entity(*declaration))
            }
            Self::ProvenOutside
            | Self::Binding { .. }
            | Self::NotInBuild { .. }
            | Self::ServerFailed { .. }
            | Self::Unresolved { .. } => {}
        }
    }

    /// The records this state names.
    fn referenced_records(&self, out: &mut Vec<ResolutionRecordId>) {
        match self {
            Self::ProvenDeclaration { set: Some(set), .. } => out.push(*set),
            Self::Binding {
                may_call: Some(set),
            } => out.push(*set),
            _ => {}
        }
    }
}

/// How a resolver failed at a site.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ServerFailure {
    Timeout,
    Crash,
    ProtocolError,
}

impl ServerFailure {
    /// The failure's name, as payloads spell it.
    pub fn wire(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::Crash => "crash",
            Self::ProtocolError => "protocol_error",
        }
    }
}

impl UnresolvedReason {
    /// The reason's name, as payloads spell it.
    pub fn wire(self) -> &'static str {
        match self {
            Self::NoAnswer => "no_answer",
            Self::AnswersDisagree => "answers_disagree",
            Self::CalleeNotPlaceable => "callee_not_placeable",
            Self::OutsideTheGraph => "outside_the_graph",
            Self::Reflective => "reflective",
        }
    }
}

/// Why an answer proves nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum UnresolvedReason {
    NoAnswer,
    AnswersDisagree,
    CalleeNotPlaceable,
    OutsideTheGraph,
    Reflective,
}

/// The declarations one dynamic call may reach.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DispatchSet {
    pub scope: DispatchScope,
    /// What the call may reach, repository entities or external symbols,
    /// sorted by their node spelling and unique.
    pub members: Vec<GraphNodeId>,
    pub world: DispatchWorld,
    pub soundness: DispatchSoundness,
    pub provenance: DispatchProvenance,
    /// The proof context the set was computed under.
    pub context: ResolutionRecordId,
    /// A digest over the resolver's program the set was computed from.
    pub scope_digest: Hash256,
}

impl DispatchSet {
    fn validate(&self) -> Result<()> {
        if self
            .members
            .windows(2)
            .any(|pair| pair[0].to_string() >= pair[1].to_string())
        {
            return Err(ModelError::InvalidOperation(
                "dispatch set members are not in canonical unique order".to_string(),
            ));
        }
        if self.provenance == DispatchProvenance::Model
            && self.soundness != DispatchSoundness::Candidate
        {
            return Err(ModelError::InvalidOperation(
                "a dispatch set a model proposed is only ever a candidate".to_string(),
            ));
        }
        if self.world == DispatchWorld::Closed && self.soundness == DispatchSoundness::Candidate {
            return Err(ModelError::InvalidOperation(
                "a candidate dispatch set cannot close its world".to_string(),
            ));
        }
        if let DispatchScope::Site { length: 0, .. } = self.scope {
            return Err(ModelError::InvalidOperation(
                "a site-scoped dispatch set names an empty callee token".to_string(),
            ));
        }
        Ok(())
    }

    /// Sort and deduplicate the members into their canonical order.
    pub fn canonicalize(&mut self) {
        self.members.sort_by_key(ToString::to_string);
        self.members.dedup();
    }
}

/// What a dispatch set is about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum DispatchScope {
    /// Every call of one declaration.
    Declaration { declaration: EntityId },
    /// One call site, keyed by its callee token within the caller.
    Site {
        caller: EntityId,
        offset: u32,
        length: u32,
    },
}

/// Whether the resolver saw every declaration that could join the set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DispatchWorld {
    Closed,
    Open,
}

/// How far a dispatch set may be trusted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DispatchSoundness {
    /// Every member is reachable and nothing else is.
    Sound,
    /// Every member the resolver enumerated, with no claim about the rest.
    Enumerated,
    /// A guess. Rendered only as candidates, never as proof.
    Candidate,
}

/// Where a dispatch set's members came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DispatchProvenance {
    Implementation,
    TypeHierarchy,
    WriteReferences,
    GoVta,
    TsChecker,
    ParserHierarchy,
    /// A model proposed the members, which makes the set a candidate.
    Model,
}

/// Which proof context a language's call-site ledgers are current under, as
/// the last sweep that checked settled it. A store holds at most one per
/// language, written in the same publication as the ledgers that sweep
/// proved, so every reader, with or without a daemon, judges a ledger by the
/// same durable answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ContextValidation {
    pub language: LanguageId,
    pub state: ContextValidationState,
}

/// What the sweep that last checked a language settled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum ContextValidationState {
    /// The server this host would start, or started, proves under this
    /// context: a ledger proven under it is current.
    Validated { context: ProofContext },
    /// No server could be started or identified to settle it, for `reason`:
    /// no ledger of the language is current until one is.
    Unverified { reason: String },
}

impl ContextValidation {
    /// The longest reason an unverified validation carries.
    pub const MAX_REASON_LEN: usize = 512;

    pub fn validate(&self) -> Result<()> {
        match &self.state {
            ContextValidationState::Validated { context } => {
                if context.language != self.language {
                    return Err(ModelError::InvalidOperation(format!(
                        "a {} context validation names a {} proof context",
                        self.language, context.language
                    )));
                }
                context.validate()
            }
            ContextValidationState::Unverified { reason } => {
                if reason.trim().is_empty() || reason.len() > Self::MAX_REASON_LEN {
                    return Err(ModelError::InvalidOperation(format!(
                        "an unverified {} context validation needs a reason of 1 to {} bytes",
                        self.language,
                        Self::MAX_REASON_LEN
                    )));
                }
                Ok(())
            }
        }
    }

    /// The identity of the context a current ledger names, when the language
    /// is validated.
    pub fn current_context(&self) -> Option<ResolutionRecordId> {
        match &self.state {
            ContextValidationState::Validated { context } => {
                Some(ResolutionRecordId::proof_context(context))
            }
            ContextValidationState::Unverified { .. } => None,
        }
    }
}

/// One resolution record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
#[allow(clippy::large_enum_variant)]
pub enum ResolutionRecord {
    ProofContext(ProofContext),
    CallSites(CallSiteLedger),
    DispatchSet(DispatchSet),
    ContextValidation(ContextValidation),
}

impl ResolutionRecord {
    /// This record's identity, derived from what it is.
    pub fn id(&self) -> ResolutionRecordId {
        match self {
            Self::ProofContext(context) => ResolutionRecordId::proof_context(context),
            Self::CallSites(ledger) => ResolutionRecordId::call_sites(ledger.caller),
            Self::DispatchSet(set) => ResolutionRecordId::dispatch_set(&set.scope, set.context),
            Self::ContextValidation(validation) => {
                ResolutionRecordId::context_validation(validation.language)
            }
        }
    }

    /// The record's kind, as payloads spell it.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::ProofContext(_) => "proof_context",
            Self::CallSites(_) => "call_sites",
            Self::DispatchSet(_) => "dispatch_set",
            Self::ContextValidation(_) => "context_validation",
        }
    }

    /// Validate the record's own shape. Whether the nodes and records it names
    /// exist is the store's to check.
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::ProofContext(context) => context.validate(),
            Self::CallSites(ledger) => ledger.validate(),
            Self::DispatchSet(set) => set.validate(),
            Self::ContextValidation(validation) => validation.validate(),
        }
    }

    /// Every graph node the record names, which must exist while it does.
    pub fn named_nodes(&self) -> Vec<GraphNodeId> {
        let mut nodes = Vec::new();
        match self {
            Self::ProofContext(_) | Self::ContextValidation(_) => {}
            Self::CallSites(ledger) => {
                nodes.push(GraphNodeId::Entity(ledger.caller));
                for site in &ledger.sites {
                    site.state.named_nodes(&mut nodes);
                }
            }
            Self::DispatchSet(set) => {
                match set.scope {
                    DispatchScope::Declaration { declaration } => {
                        nodes.push(GraphNodeId::Entity(declaration))
                    }
                    DispatchScope::Site { caller, .. } => nodes.push(GraphNodeId::Entity(caller)),
                }
                nodes.extend(set.members.iter().copied());
            }
        }
        let mut seen = HashSet::with_capacity(nodes.len());
        nodes.retain(|node| seen.insert(*node));
        nodes
    }

    /// Every other record this record names, which must exist while it does.
    pub fn referenced_records(&self) -> Vec<ResolutionRecordId> {
        let mut records = Vec::new();
        match self {
            // A validation embeds the context it names, so it depends on no
            // other record being held.
            Self::ProofContext(_) | Self::ContextValidation(_) => {}
            Self::CallSites(ledger) => {
                records.push(ledger.context);
                for site in &ledger.sites {
                    site.state.referenced_records(&mut records);
                }
            }
            Self::DispatchSet(set) => records.push(set.context),
        }
        records.sort_unstable();
        records.dedup();
        records
    }

    pub fn as_proof_context(&self) -> Option<&ProofContext> {
        match self {
            Self::ProofContext(context) => Some(context),
            _ => None,
        }
    }

    pub fn as_call_sites(&self) -> Option<&CallSiteLedger> {
        match self {
            Self::CallSites(ledger) => Some(ledger),
            _ => None,
        }
    }

    pub fn as_dispatch_set(&self) -> Option<&DispatchSet> {
        match self {
            Self::DispatchSet(set) => Some(set),
            _ => None,
        }
    }

    pub fn as_context_validation(&self) -> Option<&ContextValidation> {
        match self {
            Self::ContextValidation(validation) => Some(validation),
            _ => None,
        }
    }
}

/// Exact, self-inverting transitions of resolution records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
#[allow(clippy::large_enum_variant)]
pub enum ResolutionRecordDelta {
    Added {
        new: ResolutionRecord,
    },
    Modified {
        old: ResolutionRecord,
        new: ResolutionRecord,
    },
    Removed {
        old: ResolutionRecord,
    },
}

impl ResolutionRecordDelta {
    pub fn target_id(&self) -> ResolutionRecordId {
        match self {
            Self::Added { new } | Self::Modified { new, .. } => new.id(),
            Self::Removed { old } => old.id(),
        }
    }

    pub fn old_state(&self) -> Option<&ResolutionRecord> {
        match self {
            Self::Added { .. } => None,
            Self::Modified { old, .. } | Self::Removed { old } => Some(old),
        }
    }

    pub fn new_state(&self) -> Option<&ResolutionRecord> {
        match self {
            Self::Added { new } | Self::Modified { new, .. } => Some(new),
            Self::Removed { .. } => None,
        }
    }

    pub fn inverse(&self) -> Self {
        match self {
            Self::Added { new } => Self::Removed { old: new.clone() },
            Self::Modified { old, new } => Self::Modified {
                old: new.clone(),
                new: old.clone(),
            },
            Self::Removed { old } => Self::Added { new: old.clone() },
        }
    }

    /// Validate the delta's own shape: each state is valid, and a
    /// modification keeps its identity and changes something.
    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Added { new } => new.validate(),
            Self::Removed { old } => old.validate(),
            Self::Modified { old, new } => {
                old.validate()?;
                new.validate()?;
                if old.id() != new.id() {
                    return Err(ModelError::InvalidOperation(format!(
                        "resolution record modification changes identity from {} to {}",
                        old.id(),
                        new.id()
                    )));
                }
                if old == new {
                    return Err(ModelError::InvalidOperation(format!(
                        "resolution record {} modification is a no-op",
                        old.id()
                    )));
                }
                Ok(())
            }
        }
    }
}

/// A graph's resolution records and the index that finds the ones a
/// transaction retires.
///
/// The one implementation of how records move with the graph. The live graph,
/// history replay and the model's own replay each hold one, so the three agree
/// about which records survive a transaction.
#[derive(Debug, Clone, Default)]
pub struct ResolutionRecordSet {
    records: HashMap<ResolutionRecordId, ResolutionRecord>,
    /// Records by every graph node they name.
    naming: HashMap<GraphNodeId, BTreeSet<ResolutionRecordId>>,
    /// Records by every other record they name.
    referencing: HashMap<ResolutionRecordId, BTreeSet<ResolutionRecordId>>,
}

impl PartialEq for ResolutionRecordSet {
    fn eq(&self, other: &Self) -> bool {
        self.records == other.records
    }
}

impl Eq for ResolutionRecordSet {}

impl ResolutionRecordSet {
    /// A set holding exactly `records`, keyed as they are. The keys are not
    /// checked here; [`Self::validate`] checks them.
    pub fn from_records(records: HashMap<ResolutionRecordId, ResolutionRecord>) -> Self {
        let mut set = Self {
            records: HashMap::with_capacity(records.len()),
            naming: HashMap::new(),
            referencing: HashMap::new(),
        };
        for (id, record) in records {
            set.insert(id, record);
        }
        set
    }

    pub fn records(&self) -> &HashMap<ResolutionRecordId, ResolutionRecord> {
        &self.records
    }

    pub fn into_records(self) -> HashMap<ResolutionRecordId, ResolutionRecord> {
        self.records
    }

    pub fn get(&self, id: &ResolutionRecordId) -> Option<&ResolutionRecord> {
        self.records.get(id)
    }

    pub fn contains(&self, id: &ResolutionRecordId) -> bool {
        self.records.contains_key(id)
    }

    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// The ledger of `caller`'s call sites, when the graph holds one.
    pub fn ledger_of(&self, caller: EntityId) -> Option<&CallSiteLedger> {
        self.records
            .get(&ResolutionRecordId::call_sites(caller))
            .and_then(ResolutionRecord::as_call_sites)
    }

    /// The records that name `node`.
    pub fn naming(&self, node: &GraphNodeId) -> impl Iterator<Item = &ResolutionRecordId> {
        self.naming.get(node).into_iter().flatten()
    }

    fn insert(&mut self, id: ResolutionRecordId, record: ResolutionRecord) {
        if let Some(previous) = self.records.remove(&id) {
            self.unindex(id, &previous);
        }
        for node in record.named_nodes() {
            self.naming.entry(node).or_default().insert(id);
        }
        for referenced in record.referenced_records() {
            self.referencing.entry(referenced).or_default().insert(id);
        }
        self.records.insert(id, record);
    }

    fn remove(&mut self, id: &ResolutionRecordId) -> Option<ResolutionRecord> {
        let record = self.records.remove(id)?;
        self.unindex(*id, &record);
        Some(record)
    }

    fn unindex(&mut self, id: ResolutionRecordId, record: &ResolutionRecord) {
        for node in record.named_nodes() {
            if let Some(ids) = self.naming.get_mut(&node) {
                ids.remove(&id);
                if ids.is_empty() {
                    self.naming.remove(&node);
                }
            }
        }
        for referenced in record.referenced_records() {
            if let Some(ids) = self.referencing.get_mut(&referenced) {
                ids.remove(&id);
                if ids.is_empty() {
                    self.referencing.remove(&referenced);
                }
            }
        }
    }

    /// What `delta` does to these records: the explicit transitions it names,
    /// checked against what the set holds, and the records its entity and
    /// external-reference transitions retire without naming them.
    ///
    /// A record is retired when:
    ///
    /// - it is the ledger of a caller the transaction modifies or removes;
    /// - it names a node the transaction removes.
    ///
    /// A record the transaction itself writes is never retired: a writer that
    /// modifies a caller and records its new ledger in the same transaction
    /// keeps that ledger, and one that writes a record naming a node it also
    /// removes is refused by [`Self::check_references`] instead.
    ///
    /// Nothing is changed; [`Self::apply`] applies the plan.
    pub fn plan(&self, delta: &TransactionDelta) -> Result<ResolutionRecordPlan> {
        self.plan_parts(
            &delta.entity_deltas,
            &delta.external_reference_deltas,
            &delta.resolution_record_deltas,
        )
    }

    /// [`Self::plan`] over a transaction's deltas where they are.
    pub fn plan_parts(
        &self,
        entity_deltas: &[EntityDelta],
        external_reference_deltas: &[ExternalReferenceDelta],
        record_deltas: &[ResolutionRecordDelta],
    ) -> Result<ResolutionRecordPlan> {
        let mut explicit: BTreeMap<ResolutionRecordId, &ResolutionRecordDelta> = BTreeMap::new();
        for record_delta in record_deltas {
            record_delta.validate()?;
            let id = record_delta.target_id();
            if explicit.insert(id, record_delta).is_some() {
                return Err(ModelError::InvalidOperation(format!(
                    "transaction contains more than one delta for resolution record {id}"
                )));
            }
            match record_delta {
                ResolutionRecordDelta::Added { .. } => {
                    if self.records.contains_key(&id) {
                        return Err(ModelError::Conflict(format!(
                            "transaction adds existing resolution record {id}"
                        )));
                    }
                }
                ResolutionRecordDelta::Modified { old, .. }
                | ResolutionRecordDelta::Removed { old } => {
                    if self.records.get(&id) != Some(old) {
                        return Err(ModelError::Conflict(format!(
                            "transaction has stale old payload for resolution record {id}"
                        )));
                    }
                }
            }
        }

        let written: HashSet<ResolutionRecordId> = record_deltas
            .iter()
            .filter(|record_delta| record_delta.new_state().is_some())
            .map(ResolutionRecordDelta::target_id)
            .collect();
        let mut retired: BTreeSet<ResolutionRecordId> = BTreeSet::new();
        let consider = |id: ResolutionRecordId, retired: &mut BTreeSet<ResolutionRecordId>| {
            if written.contains(&id) || explicit.contains_key(&id) {
                return;
            }
            if self.records.contains_key(&id) {
                retired.insert(id);
            }
        };
        for entity_delta in entity_deltas {
            let entity = entity_delta.target_id();
            match entity_delta {
                EntityDelta::Added { .. } => {}
                EntityDelta::Modified { .. } => {
                    consider(ResolutionRecordId::call_sites(entity), &mut retired);
                }
                EntityDelta::Removed { .. } => {
                    consider(ResolutionRecordId::call_sites(entity), &mut retired);
                    for id in self.naming(&GraphNodeId::Entity(entity)) {
                        consider(*id, &mut retired);
                    }
                }
            }
        }
        for reference_delta in external_reference_deltas {
            if let ExternalReferenceDelta::Removed { old } = reference_delta {
                for id in self.naming(&GraphNodeId::ExternalReference(old.id)) {
                    consider(*id, &mut retired);
                }
            }
        }

        let mut effective: Vec<ResolutionRecordDelta> = record_deltas.to_vec();
        for id in &retired {
            let old = self
                .records
                .get(id)
                .cloned()
                .expect("retired records are held");
            effective.push(ResolutionRecordDelta::Removed { old });
        }
        effective.sort_by_key(ResolutionRecordDelta::target_id);
        Ok(ResolutionRecordPlan {
            effective,
            retired: retired.into_iter().collect(),
        })
    }

    /// Refuse a plan that leaves a record naming a node or another record the
    /// successor does not hold.
    ///
    /// Given that every record held before the plan named only what existed,
    /// only the records the plan writes and the records it removes can break
    /// that, so only those are examined. `node_exists` answers for the
    /// successor graph.
    pub fn check_references(
        &self,
        plan: &ResolutionRecordPlan,
        node_exists: impl Fn(&GraphNodeId) -> bool,
    ) -> Result<()> {
        let removed: HashSet<ResolutionRecordId> = plan
            .effective
            .iter()
            .filter(|record_delta| record_delta.new_state().is_none())
            .map(ResolutionRecordDelta::target_id)
            .collect();
        let written: HashMap<ResolutionRecordId, &ResolutionRecord> = plan
            .effective
            .iter()
            .filter_map(ResolutionRecordDelta::new_state)
            .map(|record| (record.id(), record))
            .collect();
        let exists_after = |id: &ResolutionRecordId| {
            written.contains_key(id) || (self.records.contains_key(id) && !removed.contains(id))
        };
        for record in plan
            .effective
            .iter()
            .filter_map(ResolutionRecordDelta::new_state)
        {
            let id = record.id();
            for node in record.named_nodes() {
                if !node_exists(&node) {
                    return Err(ModelError::InvalidOperation(format!(
                        "resolution record {id} names {node}, which the graph does not hold"
                    )));
                }
            }
            for referenced in record.referenced_records() {
                if !exists_after(&referenced) {
                    return Err(ModelError::InvalidOperation(format!(
                        "resolution record {id} names resolution record {referenced}, which the \
                         graph does not hold"
                    )));
                }
            }
        }
        for id in &removed {
            let Some(referrers) = self.referencing.get(id) else {
                continue;
            };
            // The reverse index describes the predecessor. A surviving ledger
            // may move to a new context in this same transaction, so its old
            // reference does not prevent collecting the retired context.
            if let Some(referrer) = referrers.iter().find(|referrer| {
                let referrer = *referrer;
                !removed.contains(referrer)
                    && written
                        .get(referrer)
                        .copied()
                        .or_else(|| self.records.get(referrer))
                        .is_some_and(|record| record.referenced_records().contains(id))
            }) {
                return Err(ModelError::InvalidOperation(format!(
                    "resolution record {id} is removed while resolution record {referrer} still \
                     names it"
                )));
            }
        }
        Ok(())
    }

    /// Apply a plan made by [`Self::plan`] against this exact set.
    pub fn apply(&mut self, plan: &ResolutionRecordPlan) {
        for record_delta in &plan.effective {
            let id = record_delta.target_id();
            match record_delta.new_state() {
                Some(new) => self.insert(id, new.clone()),
                None => {
                    self.remove(&id);
                }
            }
        }
    }

    /// Validate every record: its shape, that its key is its identity, and
    /// that every node and record it names exists.
    pub fn validate(&self, node_exists: impl Fn(&GraphNodeId) -> bool) -> Result<()> {
        validate_resolution_records(&self.records, node_exists)
    }
}

/// Validate a graph's records without indexing them: each record's shape,
/// that its key is its identity, and that every node and record it names
/// exists. `node_exists` answers for the graph the records belong to.
pub fn validate_resolution_records<S: std::hash::BuildHasher>(
    records: &HashMap<ResolutionRecordId, ResolutionRecord, S>,
    node_exists: impl Fn(&GraphNodeId) -> bool,
) -> Result<()> {
    for (id, record) in records {
        validate_keyed_record(id, record)?;
        for node in record.named_nodes() {
            if !node_exists(&node) {
                return Err(ModelError::InvalidOperation(format!(
                    "resolution record {id} names {node}, which the graph does not hold"
                )));
            }
        }
        for referenced in record.referenced_records() {
            if !records.contains_key(&referenced) {
                return Err(ModelError::InvalidOperation(format!(
                    "resolution record {id} names resolution record {referenced}, which the \
                     graph does not hold"
                )));
            }
        }
    }
    Ok(())
}

/// Validate one stored record: its shape, and that its key is its identity.
pub fn validate_keyed_record(id: &ResolutionRecordId, record: &ResolutionRecord) -> Result<()> {
    record.validate()?;
    let derived = record.id();
    if *id != derived {
        return Err(ModelError::InvalidOperation(format!(
            "resolution record key {id} does not match record identity {derived}"
        )));
    }
    Ok(())
}

/// What one transaction does to a graph's resolution records.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolutionRecordPlan {
    /// Every transition, explicit or implied, sorted by record identity.
    pub effective: Vec<ResolutionRecordDelta>,
    /// The records the transaction retires without naming them.
    pub retired: Vec<ResolutionRecordId>,
}

impl ResolutionRecordPlan {
    pub fn is_empty(&self) -> bool {
        self.effective.is_empty()
    }
}

fn validate_resolver(value: &str) -> Result<()> {
    validate_text("proof-context resolver", value, MAX_RESOLVER_BYTES, false)?;
    let valid = value.bytes().enumerate().all(|(index, byte)| match byte {
        b'a'..=b'z' | b'0'..=b'9' => true,
        b'.' | b'_' | b'-' | b':' | b'+' => index > 0,
        _ => false,
    });
    if !valid {
        return Err(ModelError::InvalidOperation(format!(
            "proof-context resolver {value:?} must match [a-z0-9][a-z0-9._:+-]*"
        )));
    }
    Ok(())
}

fn validate_text(label: &str, value: &str, max_bytes: usize, may_be_empty: bool) -> Result<()> {
    if value.is_empty() && !may_be_empty {
        return Err(ModelError::InvalidOperation(format!(
            "{label} must not be empty"
        )));
    }
    if value.len() > max_bytes {
        return Err(ModelError::InvalidOperation(format!(
            "{label} must not exceed {max_bytes} bytes"
        )));
    }
    if value.trim() != value {
        return Err(ModelError::InvalidOperation(format!(
            "{label} must already be trimmed"
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(ModelError::InvalidOperation(format!(
            "{label} must not contain control characters"
        )));
    }
    Ok(())
}

/// A digest over `parts`, each length-prefixed, under `domain`. For the
/// configuration and environment hashes of a [`ProofContext`].
pub fn proof_context_digest(domain: &str, parts: &[&[u8]]) -> Hash256 {
    let mut hasher = Sha256::new();
    hasher.update((domain.len() as u64).to_le_bytes());
    hasher.update(domain.as_bytes());
    for part in parts {
        hasher.update((part.len() as u64).to_le_bytes());
        hasher.update(part);
    }
    Hash256::from_bytes(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::external_reference::ExternalReference;

    fn context() -> ProofContext {
        ProofContext {
            language: LanguageId::TypeScript,
            resolver: "lsp:tsserver".to_string(),
            resolver_version: "5.6.3".to_string(),
            configuration_hash: Hash256::from_bytes([0x11; 32]),
            environment_hash: Hash256::from_bytes([0x22; 32]),
            environment_summary: "typescript 5.6.3; node_modules locked by pnpm-lock.yaml"
                .to_string(),
        }
    }

    fn entity(value: u128) -> EntityId {
        EntityId(Uuid::from_u128(value))
    }

    fn ledger(caller: EntityId, context: ResolutionRecordId) -> CallSiteLedger {
        CallSiteLedger {
            caller,
            behavior_hash: Hash256::from_bytes([0x33; 32]),
            body_hash: Hash256::from_bytes([0x44; 32]),
            context,
            census: 2,
            sites: vec![
                CallSite {
                    offset: 10,
                    length: 3,
                    state: CallSiteState::ProvenTarget { target: entity(9) },
                },
                CallSite {
                    offset: 20,
                    length: 4,
                    state: CallSiteState::Unresolved {
                        reason: UnresolvedReason::NoAnswer,
                    },
                },
            ],
        }
    }

    #[test]
    fn identities_and_wire_have_pinned_fixtures() {
        assert_eq!(
            RESOLUTION_RECORD_ID_NAMESPACE_V1,
            Uuid::new_v5(
                &Uuid::NAMESPACE_URL,
                b"https://kin.dev/namespaces/resolution-record-id/v1",
            )
        );
        let context = ResolutionRecord::ProofContext(context());
        assert_eq!(
            context.id().to_string(),
            "2f7184c5-8185-5681-87d6-e04857efff2b"
        );
        assert_eq!(
            ResolutionRecordId::call_sites(entity(1)).to_string(),
            "46c2eb41-7b82-56de-8309-a01a98e6899b"
        );
        assert_eq!(
            ResolutionRecordId::dispatch_set(
                &DispatchScope::Declaration {
                    declaration: entity(2)
                },
                context.id()
            )
            .to_string(),
            "0bf40130-9e7c-5231-9408-ba064a559d23"
        );
        let bytes = rmp_serde::to_vec(&context).unwrap();
        assert_eq!(
            hex::encode(&bytes),
            "81ad70726f6f665f636f6e7465787496aa54797065536372697074ac6c73703a747373657276\
             6572a5352e362e33dc0020111111111111111111111111111111111111111111111111111111\
             1111111111dc002022222222222222222222222222222222222222222222222222222222222222\
             22d9377479706573637269707420352e362e333b206e6f64655f6d6f64756c6573206c6f636b\
             656420627920706e706d2d6c6f636b2e79616d6c"
        );
        assert_eq!(
            rmp_serde::from_slice::<ResolutionRecord>(&bytes).unwrap(),
            context
        );
        let ledger = ResolutionRecord::CallSites(ledger(entity(1), context.id()));
        let bytes = rmp_serde::to_vec(&ledger).unwrap();
        assert_eq!(
            rmp_serde::from_slice::<ResolutionRecord>(&bytes).unwrap(),
            ledger
        );
        let json = serde_json::to_value(&ledger).unwrap();
        assert_eq!(
            json["call_sites"]["sites"][0]["state"]["proven_target"]["target"],
            "00000000-0000-0000-0000-000000000009"
        );
        assert_eq!(
            json["call_sites"]["sites"][1]["state"]["unresolved"]["reason"],
            "no_answer"
        );
    }

    #[test]
    fn context_tokens_round_trip_and_refuse_other_tokens() {
        let id = ResolutionRecord::ProofContext(context()).id();
        let token = id.context_token();
        assert!(token.starts_with("ctx:"));
        assert_eq!(ResolutionRecordId::from_context_token(&token), Some(id));
        assert_eq!(ResolutionRecordId::from_context_token("digest:abc"), None);
        assert_eq!(
            ResolutionRecordId::from_context_token("ctx:not-a-uuid"),
            None
        );
    }

    #[test]
    fn every_field_of_a_context_moves_its_identity() {
        let base = ResolutionRecordId::proof_context(&context());
        let mut variants = Vec::new();
        let mut changed = context();
        changed.language = LanguageId::JavaScript;
        variants.push(changed);
        let mut changed = context();
        changed.resolver = "lsp:tsserverx".to_string();
        variants.push(changed);
        let mut changed = context();
        changed.resolver_version = "5.6.4".to_string();
        variants.push(changed);
        let mut changed = context();
        changed.configuration_hash = Hash256::from_bytes([0x12; 32]);
        variants.push(changed);
        let mut changed = context();
        changed.environment_hash = Hash256::from_bytes([0x23; 32]);
        variants.push(changed);
        let mut changed = context();
        changed.environment_summary.push('!');
        variants.push(changed);
        for variant in variants {
            assert_ne!(
                ResolutionRecordId::proof_context(&variant),
                base,
                "{variant:?}"
            );
        }
    }

    #[test]
    fn shapes_are_validated() {
        let context_id = ResolutionRecord::ProofContext(context()).id();
        let mut bad = ledger(entity(1), context_id);
        bad.census = 3;
        assert!(ResolutionRecord::CallSites(bad).validate().is_err());
        let mut bad = ledger(entity(1), context_id);
        bad.sites.swap(0, 1);
        assert!(ResolutionRecord::CallSites(bad).validate().is_err());
        let mut bad = ledger(entity(1), context_id);
        bad.sites[0].length = 0;
        assert!(ResolutionRecord::CallSites(bad).validate().is_err());

        let mut bad = context();
        bad.resolver = "LSP:Pyright".to_string();
        assert!(ResolutionRecord::ProofContext(bad).validate().is_err());
        let mut bad = context();
        bad.resolver_version = " 1".to_string();
        assert!(ResolutionRecord::ProofContext(bad).validate().is_err());

        let set = DispatchSet {
            scope: DispatchScope::Declaration {
                declaration: entity(2),
            },
            members: vec![GraphNodeId::Entity(entity(3))],
            world: DispatchWorld::Open,
            soundness: DispatchSoundness::Enumerated,
            provenance: DispatchProvenance::Model,
            context: context_id,
            scope_digest: Hash256::from_bytes([0; 32]),
        };
        assert!(
            ResolutionRecord::DispatchSet(set.clone())
                .validate()
                .is_err(),
            "a model's set is a candidate"
        );
        let mut closed = set.clone();
        closed.provenance = DispatchProvenance::Implementation;
        closed.soundness = DispatchSoundness::Candidate;
        closed.world = DispatchWorld::Closed;
        assert!(ResolutionRecord::DispatchSet(closed).validate().is_err());
        let mut unsorted = set;
        unsorted.provenance = DispatchProvenance::Implementation;
        unsorted.members = vec![
            GraphNodeId::Entity(entity(4)),
            GraphNodeId::Entity(entity(3)),
        ];
        assert!(ResolutionRecord::DispatchSet(unsorted.clone())
            .validate()
            .is_err());
        unsorted.canonicalize();
        ResolutionRecord::DispatchSet(unsorted).validate().unwrap();
    }

    #[test]
    fn deltas_are_exact_and_self_inverting() {
        let context_id = ResolutionRecord::ProofContext(context()).id();
        let old = ResolutionRecord::CallSites(ledger(entity(1), context_id));
        let mut changed = ledger(entity(1), context_id);
        changed.behavior_hash = Hash256::from_bytes([0x55; 32]);
        let new = ResolutionRecord::CallSites(changed);
        let modified = ResolutionRecordDelta::Modified {
            old: old.clone(),
            new: new.clone(),
        };
        modified.validate().unwrap();
        assert_eq!(modified.inverse().inverse(), modified);
        assert_eq!(
            modified.target_id(),
            ResolutionRecordId::call_sites(entity(1))
        );
        assert!(ResolutionRecordDelta::Modified {
            old: old.clone(),
            new: old.clone(),
        }
        .validate()
        .is_err());
        assert!(ResolutionRecordDelta::Modified {
            old: old.clone(),
            new: ResolutionRecord::CallSites(ledger(entity(2), context_id)),
        }
        .validate()
        .is_err());
        let json =
            serde_json::to_value(ResolutionRecordDelta::Removed { old: old.clone() }).unwrap();
        assert_eq!(json["operation"], "removed");
    }

    struct World {
        set: ResolutionRecordSet,
        context: ResolutionRecord,
        nodes: HashSet<GraphNodeId>,
    }

    fn world() -> World {
        let context = ResolutionRecord::ProofContext(context());
        let mut set = ResolutionRecordSet::default();
        let plan = set
            .plan_parts(
                &[],
                &[],
                &[ResolutionRecordDelta::Added {
                    new: context.clone(),
                }],
            )
            .unwrap();
        set.apply(&plan);
        let nodes = [1, 2, 3, 9]
            .into_iter()
            .map(|value| GraphNodeId::Entity(entity(value)))
            .collect();
        World {
            set,
            context,
            nodes,
        }
    }

    fn some_entity(id: EntityId) -> crate::Entity {
        crate::Entity {
            id,
            kind: crate::EntityKind::Function,
            name: "f".to_string(),
            language: LanguageId::TypeScript,
            fingerprint: crate::SemanticFingerprint {
                algorithm: crate::FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0; 32]),
                signature_hash: Hash256::from_bytes([0; 32]),
                behavior_hash: Hash256::from_bytes([0; 32]),
                equivalence_hash: Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: None,
            span: None,
            signature: String::new(),
            visibility: crate::Visibility::Public,
            role: crate::EntityRole::Source,
            doc_summary: None,
            metadata: crate::EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    fn add(world: &mut World, record: ResolutionRecord) {
        let plan = world
            .set
            .plan_parts(&[], &[], &[ResolutionRecordDelta::Added { new: record }])
            .unwrap();
        world
            .set
            .check_references(&plan, |node| world.nodes.contains(node))
            .unwrap();
        world.set.apply(&plan);
    }

    fn calls_edge(
        caller: EntityId,
        dst: GraphNodeId,
        sites: &[(usize, usize, Option<String>)],
    ) -> crate::Relation {
        crate::Relation {
            id: crate::RelationId::resolver(
                crate::RelationKind::Calls,
                &GraphNodeId::Entity(caller),
                &dst,
            ),
            kind: crate::RelationKind::Calls,
            src: GraphNodeId::Entity(caller),
            dst,
            confidence: 0.95,
            origin: crate::RelationOrigin::Lsp,
            created_in: None,
            import_source: None,
            evidence: sites
                .iter()
                .map(|(start, end, token)| crate::RelationEvidence {
                    source_span: Some(crate::SourceSpan {
                        file: crate::FilePathId::new("src/a.ts"),
                        start_byte: *start,
                        end_byte: *end,
                        start_line: 0,
                        start_col: 0,
                        end_line: 0,
                        end_col: 0,
                    }),
                    parser_rule: Some("lsp_definition".to_string()),
                    token: token.clone(),
                    ..Default::default()
                })
                .collect(),
        }
    }

    #[test]
    fn a_proven_site_is_backed_by_an_edge_carrying_it_under_the_ledgers_context() {
        let context_id = ResolutionRecord::ProofContext(context()).id();
        let token = Some(context_id.context_token());
        // The caller starts at byte 100, so the site at offset 10, length 3,
        // is bytes 110..113 of the file.
        let ledger = ledger(entity(1), context_id);
        let target = GraphNodeId::Entity(entity(9));
        let backed = calls_edge(entity(1), target, &[(110, 113, token.clone())]);
        ledger
            .validate_backing(100, "src/a.ts", [&backed])
            .expect("the edge carries the site under the ledger's context");
        assert_eq!(
            ledger.site(10, 3).map(|site| site.state.wire()),
            Some("proven_target")
        );
        assert!(ledger.site(10, 4).is_none());

        for (why, edge, file) in [
            ("no edge", None, "src/a.ts"),
            (
                "another site",
                Some(calls_edge(entity(1), target, &[(111, 114, token.clone())])),
                "src/a.ts",
            ),
            (
                "no context",
                Some(calls_edge(entity(1), target, &[(110, 113, None)])),
                "src/a.ts",
            ),
            (
                "another context",
                Some(calls_edge(
                    entity(1),
                    target,
                    &[(110, 113, Some(format!("ctx:{}", Uuid::from_u128(7))))],
                )),
                "src/a.ts",
            ),
            (
                "another target",
                Some(calls_edge(
                    entity(1),
                    GraphNodeId::Entity(entity(8)),
                    &[(110, 113, token.clone())],
                )),
                "src/a.ts",
            ),
            ("another file", Some(backed.clone()), "src/b.ts"),
        ] {
            assert!(
                ledger.validate_backing(100, file, edge.as_ref()).is_err(),
                "{why} does not back the proof"
            );
        }

        // A recursive call proves its own caller and needs no edge.
        let mut recursive = ledger.clone();
        recursive.sites[0].state = CallSiteState::ProvenTarget { target: entity(1) };
        recursive
            .validate_backing(100, "src/a.ts", std::iter::empty())
            .unwrap();
        // A state that proves no target needs none either.
        let mut unproven = ledger;
        unproven.sites[0].state = CallSiteState::ProvenOutside;
        unproven
            .validate_backing(100, "src/a.ts", std::iter::empty())
            .unwrap();
        assert_eq!(site_key(100, 110, 113), Some((10, 3)));
        assert_eq!(site_key(100, 90, 93), None, "before the caller");
        assert_eq!(site_key(100, 110, 110), None, "empty");
    }

    #[test]
    fn a_ledger_is_retired_when_its_caller_changes_or_is_removed_unless_rewritten() {
        let mut world = world();
        let ledger_record = ResolutionRecord::CallSites(ledger(entity(1), world.context.id()));
        add(&mut world, ledger_record.clone());
        let ledger_id = ledger_record.id();

        let old = some_entity(entity(1));
        let mut new = old.clone();
        new.name = "g".to_string();
        let modified = [EntityDelta::Modified {
            old: old.clone(),
            new: new.clone(),
        }];
        let plan = world.set.plan_parts(&modified, &[], &[]).unwrap();
        assert_eq!(
            plan.retired,
            vec![ledger_id],
            "a changed caller retires its ledger"
        );
        assert_eq!(
            plan.effective,
            vec![ResolutionRecordDelta::Removed {
                old: ledger_record.clone()
            }]
        );

        // Rewritten in the same transaction, the new ledger stands.
        let mut rewritten = ledger(entity(1), world.context.id());
        rewritten.behavior_hash = Hash256::from_bytes([0x66; 32]);
        let plan = world
            .set
            .plan_parts(
                &modified,
                &[],
                &[ResolutionRecordDelta::Modified {
                    old: ledger_record.clone(),
                    new: ResolutionRecord::CallSites(rewritten),
                }],
            )
            .unwrap();
        assert!(plan.retired.is_empty());

        // A caller's removal retires its ledger too.
        let removed = [EntityDelta::Removed { old }];
        let plan = world.set.plan_parts(&removed, &[], &[]).unwrap();
        assert_eq!(plan.retired, vec![ledger_id]);

        // An unrelated entity's change retires nothing.
        let other = some_entity(entity(2));
        let mut other_new = other.clone();
        other_new.name = "h".to_string();
        let plan = world
            .set
            .plan_parts(
                &[EntityDelta::Modified {
                    old: other,
                    new: other_new,
                }],
                &[],
                &[],
            )
            .unwrap();
        assert!(plan.is_empty());
    }

    #[test]
    fn a_record_is_retired_when_a_node_it_names_is_removed() {
        let mut world = world();
        let external =
            ExternalReference::new_resolved("kin-scip-v1", "npm typescript 5.6.3", "Array#map().")
                .unwrap();
        world
            .nodes
            .insert(GraphNodeId::ExternalReference(external.id));
        let set = DispatchSet {
            scope: DispatchScope::Declaration {
                declaration: entity(2),
            },
            members: {
                let mut members = vec![
                    GraphNodeId::Entity(entity(3)),
                    GraphNodeId::ExternalReference(external.id),
                ];
                members.sort_by_key(ToString::to_string);
                members
            },
            world: DispatchWorld::Open,
            soundness: DispatchSoundness::Enumerated,
            provenance: DispatchProvenance::Implementation,
            context: world.context.id(),
            scope_digest: Hash256::from_bytes([7; 32]),
        };
        let set_record = ResolutionRecord::DispatchSet(set);
        add(&mut world, set_record.clone());

        let plan = world
            .set
            .plan_parts(
                &[],
                &[ExternalReferenceDelta::Removed {
                    old: external.clone(),
                }],
                &[],
            )
            .unwrap();
        assert_eq!(plan.retired, vec![set_record.id()]);

        let plan = world
            .set
            .plan_parts(
                &[EntityDelta::Removed {
                    old: some_entity(entity(3)),
                }],
                &[],
                &[],
            )
            .unwrap();
        assert_eq!(plan.retired, vec![set_record.id()]);
        world.set.apply(&plan);
        assert!(!world.set.contains(&set_record.id()));
        assert_eq!(world.set.naming(&GraphNodeId::Entity(entity(3))).count(), 0);
    }

    #[test]
    fn context_replacement_checks_the_successor_ledger_references() {
        let mut world = world();
        let old = ResolutionRecord::CallSites(ledger(entity(1), world.context.id()));
        add(&mut world, old.clone());
        let replacement = ResolutionRecord::ProofContext(ProofContext {
            environment_hash: Hash256::from_bytes([0x55; 32]),
            ..context()
        });
        let context_deltas = vec![
            ResolutionRecordDelta::Removed {
                old: world.context.clone(),
            },
            ResolutionRecordDelta::Added {
                new: replacement.clone(),
            },
        ];
        let plan = world.set.plan_parts(&[], &[], &context_deltas).unwrap();
        assert!(
            world
                .set
                .check_references(&plan, |node| world.nodes.contains(node))
                .is_err(),
            "a surviving unchanged ledger still needs its old context"
        );

        let mut still_old = ledger(entity(1), world.context.id());
        still_old.body_hash = Hash256::from_bytes([0x66; 32]);
        let mut deltas = context_deltas.clone();
        deltas.push(ResolutionRecordDelta::Modified {
            old: old.clone(),
            new: ResolutionRecord::CallSites(still_old),
        });
        let plan = world.set.plan_parts(&[], &[], &deltas).unwrap();
        assert!(
            world
                .set
                .check_references(&plan, |node| world.nodes.contains(node))
                .is_err(),
            "a rewritten ledger which keeps the old reference still needs it"
        );

        let new = ResolutionRecord::CallSites(ledger(entity(1), replacement.id()));
        let mut deltas = context_deltas;
        deltas.push(ResolutionRecordDelta::Modified {
            old: old.clone(),
            new: new.clone(),
        });
        let plan = world.set.plan_parts(&[], &[], &deltas).unwrap();
        world
            .set
            .check_references(&plan, |node| world.nodes.contains(node))
            .expect("the replacement ledger names only the new context");
        world.set.apply(&plan);
        assert!(!world.set.contains(&world.context.id()));
        assert_eq!(world.set.get(&new.id()), Some(&new));
        assert_eq!(world.set.get(&replacement.id()), Some(&replacement));
        world
            .set
            .validate(|node| world.nodes.contains(node))
            .unwrap();
    }

    #[test]
    fn references_to_missing_nodes_and_records_are_refused() {
        let mut world = world();
        let orphan_context = ResolutionRecordId::proof_context(&ProofContext {
            resolver: "lsp:pyright".to_string(),
            ..context()
        });
        let plan = world
            .set
            .plan_parts(
                &[],
                &[],
                &[ResolutionRecordDelta::Added {
                    new: ResolutionRecord::CallSites(ledger(entity(1), orphan_context)),
                }],
            )
            .unwrap();
        assert!(world
            .set
            .check_references(&plan, |node| world.nodes.contains(node))
            .is_err());

        let plan = world
            .set
            .plan_parts(
                &[],
                &[],
                &[ResolutionRecordDelta::Added {
                    new: ResolutionRecord::CallSites(ledger(entity(7), world.context.id())),
                }],
            )
            .unwrap();
        assert!(
            world
                .set
                .check_references(&plan, |node| world.nodes.contains(node))
                .is_err(),
            "a ledger of a caller the graph does not hold"
        );

        let ledger_record = ResolutionRecord::CallSites(ledger(entity(1), world.context.id()));
        add(&mut world, ledger_record);
        let plan = world
            .set
            .plan_parts(
                &[],
                &[],
                &[ResolutionRecordDelta::Removed {
                    old: world.context.clone(),
                }],
            )
            .unwrap();
        assert!(
            world
                .set
                .check_references(&plan, |node| world.nodes.contains(node))
                .is_err(),
            "a context a ledger still names cannot be removed"
        );

        let stale = world.set.plan_parts(
            &[],
            &[],
            &[ResolutionRecordDelta::Added {
                new: world.context.clone(),
            }],
        );
        assert!(stale.is_err(), "adding a held record is a conflict");
        world
            .set
            .validate(|node| world.nodes.contains(node))
            .unwrap();
    }
}

/// The positional wire of every persisted type that gained a resolution-record
/// field. Each one keeps the exact bytes and JSON it had while it carries no
/// record, and with records keeps every earlier field in its own place.
#[cfg(test)]
mod wire_tests {
    use super::*;
    use crate::change::{ChangeOrigin, SemanticChange};
    use crate::external_reference::ExternalReference;
    use crate::graph::ResolvedGraphState;
    use crate::repository::WorkspaceSemanticDelta;
    use crate::{
        compute_semantic_change_id, AuthorId, EnrichmentMarksDelta, RelationDelta,
        SemanticChangeId, Timestamp, TreeDelta,
    };
    use chrono::TimeZone;

    fn messagepack_array_len(bytes: &[u8]) -> usize {
        match bytes {
            [tag @ 0x90..=0x9f, ..] => usize::from(*tag & 0x0f),
            [0xdc, high, low, ..] => usize::from(u16::from_be_bytes([*high, *low])),
            _ => panic!("expected a MessagePack array"),
        }
    }

    fn context_record() -> ResolutionRecord {
        ResolutionRecord::ProofContext(ProofContext {
            language: LanguageId::Python,
            resolver: "lsp:pyright".to_string(),
            resolver_version: "1.1.390".to_string(),
            configuration_hash: Hash256::from_bytes([0x61; 32]),
            environment_hash: Hash256::from_bytes([0x62; 32]),
            environment_summary: "python 3.12; locked by uv.lock".to_string(),
        })
    }

    fn records() -> Vec<ResolutionRecordDelta> {
        vec![ResolutionRecordDelta::Added {
            new: context_record(),
        }]
    }

    fn change() -> SemanticChange {
        SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0x71; 32])),
            origin: ChangeOrigin::Native,
            parents: Vec::new(),
            timestamp: Timestamp::from(
                chrono::Utc
                    .timestamp_millis_opt(1_700_000_000_000)
                    .single()
                    .unwrap(),
            ),
            author: AuthorId::new("wire-test"),
            message: "records".to_string(),
            entity_deltas: Vec::new(),
            relation_deltas: Vec::new(),
            tree_deltas: Vec::new(),
            admission_policy_delta: None,
            projected_files: Vec::new(),
            spec_link: None,
            evidence: Vec::new(),
            risk_summary: None,
            external_reference_deltas: Vec::new(),
            resolution_record_deltas: Vec::new(),
        }
    }

    /// `SemanticChange` as the derive wrote it before resolution records.
    #[derive(Serialize)]
    struct LegacyChange<'a> {
        id: &'a SemanticChangeId,
        origin: &'a ChangeOrigin,
        parents: &'a [SemanticChangeId],
        timestamp: &'a Timestamp,
        author: &'a AuthorId,
        message: &'a str,
        entity_deltas: &'a [EntityDelta],
        relation_deltas: &'a [RelationDelta],
        tree_deltas: &'a [TreeDelta],
        admission_policy_delta: &'a Option<crate::AdmissionPolicyDelta>,
        projected_files: &'a [crate::FilePathId],
        spec_link: &'a Option<crate::SpecId>,
        evidence: &'a [crate::EvidenceId],
        risk_summary: &'a Option<crate::RiskSummary>,
        #[serde(skip_serializing_if = "<[_]>::is_empty")]
        external_reference_deltas: &'a [ExternalReferenceDelta],
    }

    impl<'a> LegacyChange<'a> {
        fn of(change: &'a SemanticChange) -> Self {
            Self {
                id: &change.id,
                origin: &change.origin,
                parents: &change.parents,
                timestamp: &change.timestamp,
                author: &change.author,
                message: &change.message,
                entity_deltas: &change.entity_deltas,
                relation_deltas: &change.relation_deltas,
                tree_deltas: &change.tree_deltas,
                admission_policy_delta: &change.admission_policy_delta,
                projected_files: &change.projected_files,
                spec_link: &change.spec_link,
                evidence: &change.evidence,
                risk_summary: &change.risk_summary,
                external_reference_deltas: &change.external_reference_deltas,
            }
        }
    }

    #[test]
    fn a_change_without_records_keeps_its_bytes_json_and_identity() {
        let plain = change();
        let mut referencing = change();
        referencing.external_reference_deltas = vec![ExternalReferenceDelta::Added {
            new: ExternalReference::new_resolved("kin-scip-v1", "npm lodash 4.17.21", "map().")
                .unwrap(),
        }];
        for change in [&plain, &referencing] {
            assert_eq!(
                rmp_serde::to_vec(change).unwrap(),
                rmp_serde::to_vec(&LegacyChange::of(change)).unwrap()
            );
            assert_eq!(
                serde_json::to_vec(change).unwrap(),
                serde_json::to_vec(&LegacyChange::of(change)).unwrap()
            );
        }
        assert_eq!(
            messagepack_array_len(&rmp_serde::to_vec(&plain).unwrap()),
            14
        );
        assert_eq!(
            messagepack_array_len(&rmp_serde::to_vec(&referencing).unwrap()),
            15
        );
    }

    #[test]
    fn a_change_with_records_keeps_every_field_in_place_and_moves_its_identity() {
        let plain = change();
        let mut recorded = change();
        recorded.resolution_record_deltas = records();
        let wire = rmp_serde::to_vec(&recorded).unwrap();
        assert_eq!(
            messagepack_array_len(&wire),
            16,
            "the external references are written, empty, ahead of the records"
        );
        let decoded: SemanticChange = rmp_serde::from_slice(&wire).unwrap();
        assert_eq!(decoded, recorded);
        let json = serde_json::to_value(&recorded).unwrap();
        assert!(
            json.get("external_reference_deltas").is_none(),
            "a name-keyed format omits each empty field on its own"
        );
        let decoded: SemanticChange = serde_json::from_value(json).unwrap();
        assert_eq!(decoded, recorded);
        assert_ne!(
            compute_semantic_change_id(&plain).unwrap(),
            compute_semantic_change_id(&recorded).unwrap(),
            "records are identity-bearing"
        );
        // A reader older than records decodes the first fifteen elements at a
        // fixed length and refuses the sixteenth; the snapshot and frame
        // versions keep it from ever being asked to.
        assert!(rmp_serde::from_slice::<LegacyDecode>(&wire).is_err());
    }

    /// The shape an older reader decodes a change into.
    #[derive(Deserialize)]
    #[allow(dead_code)]
    struct LegacyDecode {
        id: SemanticChangeId,
        origin: ChangeOrigin,
        parents: Vec<SemanticChangeId>,
        timestamp: Timestamp,
        author: AuthorId,
        message: String,
        entity_deltas: Vec<EntityDelta>,
        relation_deltas: Vec<RelationDelta>,
        tree_deltas: Vec<TreeDelta>,
        admission_policy_delta: Option<crate::AdmissionPolicyDelta>,
        projected_files: Vec<crate::FilePathId>,
        spec_link: Option<crate::SpecId>,
        evidence: Vec<crate::EvidenceId>,
        risk_summary: Option<crate::RiskSummary>,
        #[serde(default)]
        external_reference_deltas: Vec<ExternalReferenceDelta>,
    }

    #[test]
    fn a_transaction_delta_keeps_its_bytes_until_it_carries_records() {
        #[derive(Serialize)]
        struct Legacy<'a> {
            entity_deltas: &'a [EntityDelta],
            relation_deltas: &'a [RelationDelta],
            tree_deltas: &'a [TreeDelta],
            admission_policy_delta: &'a Option<crate::AdmissionPolicyDelta>,
            #[serde(skip_serializing_if = "<[_]>::is_empty")]
            external_reference_deltas: &'a [ExternalReferenceDelta],
        }
        let plain = TransactionDelta::default();
        let legacy = Legacy {
            entity_deltas: &[],
            relation_deltas: &[],
            tree_deltas: &[],
            admission_policy_delta: &None,
            external_reference_deltas: &[],
        };
        assert_eq!(
            rmp_serde::to_vec(&plain).unwrap(),
            rmp_serde::to_vec(&legacy).unwrap()
        );
        assert_eq!(
            serde_json::to_vec(&plain).unwrap(),
            serde_json::to_vec(&legacy).unwrap()
        );
        let recorded = TransactionDelta {
            resolution_record_deltas: records(),
            ..TransactionDelta::default()
        };
        let wire = rmp_serde::to_vec(&recorded).unwrap();
        assert_eq!(messagepack_array_len(&wire), 6);
        assert_eq!(
            rmp_serde::from_slice::<TransactionDelta>(&wire).unwrap(),
            recorded
        );
        assert_eq!(recorded.inverse().inverse(), recorded);
        assert_ne!(
            crate::content_identity_from_deltas(&plain).unwrap(),
            crate::content_identity_from_deltas(&recorded).unwrap()
        );
    }

    #[test]
    fn a_workspace_delta_carries_records_after_its_marks() {
        let recorded = WorkspaceSemanticDelta::default()
            .with_resolution_records(records())
            .unwrap();
        let wire = rmp_serde::to_vec(&recorded).unwrap();
        assert_eq!(
            messagepack_array_len(&wire),
            6,
            "external references and marks are written, empty, ahead of the records"
        );
        let positions: (
            u32,
            Vec<EntityDelta>,
            Vec<RelationDelta>,
            Vec<ExternalReferenceDelta>,
            EnrichmentMarksDelta,
            Vec<ResolutionRecordDelta>,
        ) = rmp_serde::from_slice(&wire).unwrap();
        assert!(positions.3.is_empty());
        assert!(positions.4.is_empty());
        assert_eq!(positions.5, records());
        assert_eq!(
            rmp_serde::from_slice::<WorkspaceSemanticDelta>(&wire).unwrap(),
            recorded
        );
        let json = serde_json::to_value(&recorded).unwrap();
        assert!(json.get("enrichment_marks").is_none());
        assert_eq!(
            serde_json::from_value::<WorkspaceSemanticDelta>(json).unwrap(),
            recorded
        );
        assert!(!recorded.is_empty());
        assert_ne!(
            recorded.identity_hash().unwrap(),
            WorkspaceSemanticDelta::default().identity_hash().unwrap()
        );
        assert_eq!(
            recorded.transaction_delta().resolution_record_deltas,
            records()
        );
    }

    #[test]
    fn a_resolved_state_keeps_its_bytes_until_it_carries_records() {
        let plain = ResolvedGraphState::default();
        let wire = rmp_serde::to_vec(&plain).unwrap();
        assert_eq!(messagepack_array_len(&wire), 6);
        let mut recorded = ResolvedGraphState::default();
        let record = context_record();
        recorded.resolution_records.insert(record.id(), record);
        let wire = rmp_serde::to_vec(&recorded).unwrap();
        assert_eq!(messagepack_array_len(&wire), 8);
        let decoded: ResolvedGraphState = rmp_serde::from_slice(&wire).unwrap();
        assert_eq!(decoded.resolution_records, recorded.resolution_records);
        assert!(decoded.external_references.is_empty());
    }
}
