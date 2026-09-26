// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Settling the linker's call edges against what a language server proved at
//! the same call site.
//!
//! The linker binds a call through an import, a receiver type or a same-file
//! name when it can, and otherwise by the callee's bare name, keeping every
//! same-named declaration as a candidate. The file-level enrichment pass asks
//! the language server for the definition at every call's callee token, and
//! call hierarchy reports the range of every call it resolves. Those answers
//! used to be recorded beside the linker's edges without touching them, so a
//! call was proven only when call hierarchy happened to list it under the
//! caller Kin asked about, and the graph kept serving a candidate the server
//! had just contradicted.
//!
//! A site is one caller, one call expression the linker recorded, and the
//! callee token inside it, read from the admitted source. A proof is a definite
//! answer at exactly that token. When the proof names a graph entity, a `Calls`
//! edge to it carries the proof, whatever the linker bound there. A linker edge
//! whose destination the proof contradicts loses the site, whether the linker
//! bound it confidently or by name; the contradiction is read only where the
//! token spells that destination's own name. When the proof names a
//! declaration outside the repository, every linker edge at the site loses it,
//! and when the server's answer names that declaration as an external symbol
//! (see `kin_lsp::external_symbols`), a `Calls` edge to the symbol carries the
//! proof, with the proof context it was made under. An answer outside the
//! repository that names no symbol still refutes, and mints nothing. An edge
//! that loses every site it was recorded at is retired; one that keeps others
//! is narrowed to them.
//!
//! What is never a proof: no answer, a declined or timed-out query, answers
//! that disagree, a token this module cannot place, or a site whose edge names
//! a declaration the call may still reach at run time: an override, an
//! implementation of the interface or trait method the server named, or
//! another declaration of the same overloaded function. Those edges stay
//! exactly as the linker left them.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use kin_index::RelationResolution;
use kin_lsp::call_sites::{self, ExternalNames, SiteAnswer, SiteTarget};
use kin_model::{
    Entity, EntityId, EntityKind, EntityStore, ExternalReference, ExternalReferenceId,
    ExternalSymbol, GraphNodeId, LanguageId, Relation, RelationEvidence, RelationKind,
    RelationOrigin, ResolutionRecordId,
};

/// What the proofs at one file's call sites settle.
#[derive(Debug, Default, Clone, PartialEq)]
pub(crate) struct Settlement {
    /// `Calls` edges the proofs establish, one per proven destination, each
    /// carrying the sites that proved it and no site an existing language
    /// server `Calls` edge already records.
    pub(crate) proven: Vec<Relation>,
    /// Linker edges that keep some of their sites and lose the ones a proof
    /// contradicted.
    pub(crate) narrowed: Vec<Relation>,
    /// Linker edges a proof contradicted at every site they were recorded at.
    pub(crate) retired: Vec<Relation>,
    /// `Calls` edges to symbols outside the repository, one per proven
    /// symbol, each carrying the sites that proved it under the proof context.
    pub(crate) proven_external: Vec<Relation>,
    /// The external symbols `proven_external` names, which must be in the
    /// graph before those edges are.
    pub(crate) external_nodes: Vec<ExternalReference>,
    /// What the settlement did, by the tier the linker bound each edge at.
    pub(crate) counts: SettlementCounts,
}

/// What a settlement needs beyond the answers to prove a call outside the
/// repository: the names of the declarations those answers landed on, and the
/// proof context the server answered under.
#[derive(Debug, Clone, Copy)]
pub(crate) struct OutsideProof<'a> {
    pub(crate) names: &'a ExternalNames,
    /// `None` when no proof context is known, which proves no external call:
    /// the answers still refute, and mint nothing.
    pub(crate) context: Option<ResolutionRecordId>,
}

impl OutsideProof<'_> {
    /// Nothing to name outside answers with: they refute and mint nothing.
    #[cfg(test)]
    pub(crate) fn none() -> OutsideProof<'static> {
        static NONE: std::sync::OnceLock<ExternalNames> = std::sync::OnceLock::new();
        OutsideProof {
            names: NONE.get_or_init(ExternalNames::new),
            context: None,
        }
    }
}

/// The counts one settlement reports.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SettlementCounts {
    /// Sites a new proof was minted at.
    pub(crate) proven_sites: usize,
    /// Name-only guesses retired and narrowed.
    pub(crate) retired_name_only: usize,
    pub(crate) narrowed_name_only: usize,
    /// Edges the linker bound confidently, through an import, a receiver type
    /// or a same-file name, retired and narrowed.
    pub(crate) retired_confident: usize,
    pub(crate) narrowed_confident: usize,
    /// Linker sites an answer outside the repository contradicted.
    pub(crate) refuted_outside: usize,
    /// Sites a new proof of an external symbol was minted at.
    pub(crate) proven_external_sites: usize,
    /// Sites whose answer lay outside the repository in a declaration that
    /// could not be named: they refute, and prove no target.
    pub(crate) outside_unnamed_sites: usize,
    /// Sites a contradicted edge kept because it carries occurrence
    /// certificates this module cannot narrow.
    pub(crate) certified_kept: usize,
}

impl Settlement {
    pub(crate) fn is_empty(&self) -> bool {
        self.proven.is_empty()
            && self.narrowed.is_empty()
            && self.retired.is_empty()
            && self.proven_external.is_empty()
    }
}

/// What every answer about one callee token proves it names.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ProofTarget {
    Entity(EntityId),
    /// A declaration outside the repository, and the symbol it was named as
    /// when every answer that named one named the same.
    Outside {
        symbol: Option<ExternalSymbol>,
    },
}

impl ProofTarget {
    fn of(target: &SiteTarget, names: &ExternalNames) -> Self {
        match target {
            SiteTarget::Entity(entity) => Self::Entity(*entity),
            SiteTarget::Outside(location) => Self::Outside {
                symbol: names.get(location).cloned(),
            },
        }
    }

    /// The target two answers about one token agree on, or `None` when they
    /// disagree. Two answers outside the repository agree that the call leaves
    /// it; they name one symbol only when every one of them that named a
    /// symbol named the same.
    fn merge(held: &Self, other: &Self) -> Option<Self> {
        match (held, other) {
            (Self::Entity(left), Self::Entity(right)) => {
                (left == right).then_some(Self::Entity(*left))
            }
            (Self::Outside { symbol: left }, Self::Outside { symbol: right }) => {
                let symbol = match (left, right) {
                    (Some(left), Some(right)) => (left == right).then(|| left.clone()),
                    (Some(named), None) | (None, Some(named)) => Some(named.clone()),
                    (None, None) => None,
                };
                Some(Self::Outside { symbol })
            }
            _ => None,
        }
    }
}

/// What every answer about one callee token proves, as a call-site ledger
/// reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SiteProof {
    /// The call names this repository entity.
    Entity(EntityId),
    /// The call names this symbol outside the repository.
    External(ExternalReference),
    /// The call leaves the repository for a declaration no symbol names.
    Outside,
    /// The answers about the token disagree, which proves nothing.
    Disagree,
}

/// What the answers in `file` prove at each callee token, keyed by the
/// entity whose body holds the token and its byte range, merged exactly as
/// [`settle_with`] merges them.
pub(crate) fn site_proofs(
    file: &str,
    answers: &[SiteAnswer],
    names: &ExternalNames,
) -> HashMap<(EntityId, usize, usize), SiteProof> {
    let mut merged: HashMap<(EntityId, usize, usize), (Option<ProofTarget>, bool)> = HashMap::new();
    for answer in answers {
        if answer.site.file.0 != file {
            continue;
        }
        let key = (answer.source, answer.site.start_byte, answer.site.end_byte);
        let target = ProofTarget::of(&answer.target, names);
        match merged.get_mut(&key) {
            None => {
                merged.insert(key, (Some(target), false));
            }
            Some((held, conflict)) => {
                if let (
                    Some(ProofTarget::Outside { symbol: Some(left) }),
                    ProofTarget::Outside {
                        symbol: Some(right),
                    },
                ) = (&*held, &target)
                {
                    *conflict |= left != right;
                }
                *held = held
                    .as_ref()
                    .and_then(|held| ProofTarget::merge(held, &target));
                if *conflict {
                    *held = Some(ProofTarget::Outside { symbol: None });
                }
            }
        }
    }
    merged
        .into_iter()
        .map(|(key, (target, _))| {
            let proof = match target {
                Some(ProofTarget::Entity(entity)) => SiteProof::Entity(entity),
                Some(ProofTarget::Outside {
                    symbol: Some(symbol),
                }) => match symbol.to_reference() {
                    Ok(reference) => SiteProof::External(reference),
                    Err(_) => SiteProof::Outside,
                },
                Some(ProofTarget::Outside { symbol: None }) => SiteProof::Outside,
                None => SiteProof::Disagree,
            };
            (key, proof)
        })
        .collect()
}

/// Every answer about one callee token.
struct Proof {
    /// `None` when two answers about the token disagree, which proves nothing.
    target: Option<ProofTarget>,
    /// Whether two named outside answers named different symbols, which
    /// leaves the site outside and unnamed.
    names_conflict: bool,
    evidence: Vec<RelationEvidence>,
}

/// How one recorded site of a linker edge comes out.
enum SiteOutcome {
    Kept,
    Contradicted { outside: bool },
}

/// The prefix of every evidence rule the linker reserves for its per-site
/// occurrence certificates: span-free records that each vouch for one of a
/// parser edge's sites, and fail validation for the whole edge once their
/// site is gone.
const OCCURRENCE_CERTIFICATE_RULE_PREFIX: &str = "parser_occurrence_resolution_";

fn is_occurrence_certificate(record: &RelationEvidence) -> bool {
    record.source_span.is_none()
        && record
            .parser_rule
            .as_deref()
            .is_some_and(|rule| rule.starts_with(OCCURRENCE_CERTIFICATE_RULE_PREFIX))
}

/// Settle the linker's call edges from every caller `answers` names in `file`,
/// whose admitted text is `text`, against those answers.
///
/// Pure over the store: it reads the callers' relations and the entities they
/// name and returns what should change, and writes nothing. The same store and
/// the same answers always produce the same settlement, and a store the
/// settlement was already applied to produces one with nothing in it.
#[cfg(test)]
pub(crate) fn settle<S: EntityStore + ?Sized>(
    store: &S,
    file: &str,
    text: &str,
    answers: &[SiteAnswer],
) -> Result<Settlement, S::Error> {
    settle_with(store, file, text, answers, OutsideProof::none())
}

/// [`settle`], also proving calls into symbols outside the repository that
/// `outside` can name.
pub(crate) fn settle_with<S: EntityStore + ?Sized>(
    store: &S,
    file: &str,
    text: &str,
    answers: &[SiteAnswer],
    outside: OutsideProof<'_>,
) -> Result<Settlement, S::Error> {
    let mut proofs: HashMap<(EntityId, usize, usize), Proof> = HashMap::new();
    for answer in answers {
        if answer.site.file.0 != file {
            continue;
        }
        let key = (answer.source, answer.site.start_byte, answer.site.end_byte);
        let record = call_sites::site_evidence(answer.rule, answer.site.clone());
        let target = ProofTarget::of(&answer.target, outside.names);
        match proofs.get_mut(&key) {
            None => {
                proofs.insert(
                    key,
                    Proof {
                        target: Some(target),
                        names_conflict: false,
                        evidence: vec![record],
                    },
                );
            }
            Some(proof) => {
                let merged = proof
                    .target
                    .as_ref()
                    .and_then(|held| ProofTarget::merge(held, &target));
                if let (
                    Some(ProofTarget::Outside { symbol: Some(held) }),
                    ProofTarget::Outside {
                        symbol: Some(other),
                    },
                ) = (&proof.target, &target)
                {
                    proof.names_conflict |= held != other;
                }
                proof.target = merged;
                if proof.names_conflict {
                    proof.target = Some(ProofTarget::Outside { symbol: None });
                }
                if !proof.evidence.contains(&record) {
                    proof.evidence.push(record);
                }
            }
        }
    }
    let callers: BTreeSet<EntityId> = proofs.keys().map(|(caller, _, _)| *caller).collect();

    let mut entities = EntityCache::default();
    let mut settlement = Settlement::default();
    // caller -> proven destination -> the sites that proved it.
    let mut proven: BTreeMap<EntityId, BTreeMap<EntityId, Vec<RelationEvidence>>> = BTreeMap::new();
    // caller -> proven external symbol -> its node and the sites that proved it.
    let mut proven_external: ProvenExternal = BTreeMap::new();
    let context_token = outside.context.map(|context| context.context_token());
    for caller in callers {
        let mut outgoing: Vec<Relation> = store
            .get_all_relations_for_entity(&caller)?
            .into_iter()
            .filter(|relation| {
                relation.kind == RelationKind::Calls && relation.src == GraphNodeId::Entity(caller)
            })
            .collect();
        outgoing.sort_by_key(|relation| relation.id);
        // The call sites a language-server `Calls` edge already records, so a
        // proof it already carries is not minted a second time.
        let mut already_proven: HashMap<EntityId, BTreeSet<(usize, usize)>> = HashMap::new();
        for relation in &outgoing {
            let GraphNodeId::Entity(target) = relation.dst else {
                continue;
            };
            if relation.origin != RelationOrigin::Lsp {
                continue;
            }
            already_proven.entry(target).or_default().extend(
                relation
                    .evidence
                    .iter()
                    .filter_map(|evidence| evidence.source_span.as_ref())
                    .map(|span| (span.start_byte, span.end_byte)),
            );
        }
        // The sites a language-server edge to an external symbol already
        // records, for the same reason.
        let mut already_external: HashMap<ExternalReferenceId, BTreeSet<(usize, usize)>> =
            HashMap::new();
        if context_token.is_some() {
            for relation in store.get_external_relations_for_entity(&caller)? {
                let GraphNodeId::ExternalReference(target) = relation.dst else {
                    continue;
                };
                if relation.origin != RelationOrigin::Lsp {
                    continue;
                }
                already_external.entry(target).or_default().extend(
                    relation
                        .evidence
                        .iter()
                        .filter_map(|evidence| evidence.source_span.as_ref())
                        .map(|span| (span.start_byte, span.end_byte)),
                );
            }
        }

        for edge in &outgoing {
            if matches!(edge.origin, RelationOrigin::Lsp | RelationOrigin::Manual)
                || kin_index::is_external_import_placeholder(edge)
            {
                continue;
            }
            let GraphNodeId::Entity(bound) = edge.dst else {
                continue;
            };
            // Only an edge to a repository declaration is settled here. The
            // linker's placeholder for a symbol an import brings in from
            // outside names a declaration with no file in the repository, and
            // an answer outside the repository agrees with it rather than
            // refuting it.
            let Some(bound_entity) = entities
                .get(store, bound)?
                .filter(|entity| entity.file_origin.is_some())
            else {
                continue;
            };
            let name = kin_index::bare_entity_name(&bound_entity.name).to_string();
            let name_only = RelationResolution::of(edge) == RelationResolution::NameOnly;

            let mut kept = Vec::with_capacity(edge.evidence.len());
            let mut kept_sites = 0usize;
            let mut contradicted = 0usize;
            let mut outside = 0usize;
            for record in &edge.evidence {
                let Some(span) = record.source_span.as_ref() else {
                    // A marker or a certificate, not a site.
                    kept.push(record.clone());
                    continue;
                };
                if span.file.0 != file {
                    kept.push(record.clone());
                    kept_sites += 1;
                    continue;
                }
                let outcome = settle_site(
                    store,
                    &mut entities,
                    SiteInput {
                        caller,
                        file,
                        text,
                        span,
                        name: &name,
                        bound: &bound_entity,
                        proofs: &proofs,
                        already_proven: &already_proven,
                        already_external: &already_external,
                        context_token: context_token.as_deref(),
                    },
                    &mut proven,
                    &mut proven_external,
                    &mut settlement.counts,
                )?;
                match outcome {
                    SiteOutcome::Kept => {
                        kept.push(record.clone());
                        kept_sites += 1;
                    }
                    SiteOutcome::Contradicted { outside: out } => {
                        contradicted += 1;
                        outside += usize::from(out);
                    }
                }
            }
            if contradicted == 0 {
                continue;
            }
            if kept_sites == 0 {
                settlement.retired.push(edge.clone());
                if name_only {
                    settlement.counts.retired_name_only += 1;
                } else {
                    settlement.counts.retired_confident += 1;
                }
            } else if edge.evidence.iter().any(is_occurrence_certificate) {
                // Each certificate vouches for one site, and one left behind
                // for a site narrowing removed fails validation for every
                // site the edge keeps. Which certificate is whose is the
                // linker's to say, so the edge stays whole.
                settlement.counts.certified_kept += contradicted;
                continue;
            } else {
                let mut narrowed = edge.clone();
                narrowed.evidence = kept;
                settlement.narrowed.push(narrowed);
                if name_only {
                    settlement.counts.narrowed_name_only += 1;
                } else {
                    settlement.counts.narrowed_confident += 1;
                }
            }
            settlement.counts.refuted_outside += outside;
        }
    }

    for (caller, targets) in proven {
        for (target, mut evidence) in targets {
            evidence.sort_by_key(|record| {
                let span = record.source_span.as_ref();
                (
                    span.map_or(0, |span| span.start_byte),
                    record.parser_rule.clone().unwrap_or_default(),
                )
            });
            evidence.dedup();
            evidence.truncate(kin_lsp::enrichment::MAX_SITES_PER_EDGE);
            settlement.counts.proven_sites += evidence
                .iter()
                .filter_map(|record| record.source_span.as_ref())
                .map(|span| (span.start_byte, span.end_byte))
                .collect::<BTreeSet<_>>()
                .len();
            settlement
                .proven
                .push(call_sites::proven_call(caller, target, evidence));
        }
    }
    let mut external_nodes: BTreeMap<ExternalReferenceId, ExternalReference> = BTreeMap::new();
    for (caller, targets) in proven_external {
        for (target, (node, mut evidence)) in targets {
            // One record per site. A definition answer and a call-hierarchy
            // answer at one callee token prove the same site, and the
            // definition's record is the one kept.
            evidence.sort_by_key(|record| {
                let span = record.source_span.as_ref();
                (
                    span.map_or(0, |span| span.start_byte),
                    span.map_or(0, |span| span.end_byte),
                    record.parser_rule.as_deref() != Some(call_sites::DEFINITION_RULE),
                    record.parser_rule.clone().unwrap_or_default(),
                )
            });
            evidence.dedup_by_key(|record| {
                record
                    .source_span
                    .as_ref()
                    .map(|span| (span.start_byte, span.end_byte))
            });
            evidence.truncate(kin_lsp::enrichment::MAX_SITES_PER_EDGE);
            settlement.counts.proven_external_sites += evidence
                .iter()
                .filter_map(|record| record.source_span.as_ref())
                .map(|span| (span.start_byte, span.end_byte))
                .collect::<BTreeSet<_>>()
                .len();
            external_nodes.insert(target, node);
            settlement
                .proven_external
                .push(call_sites::proven_external_call(caller, target, evidence));
        }
    }
    settlement.external_nodes = external_nodes.into_values().collect();
    if !settlement.is_empty() {
        let counts = settlement.counts;
        tracing::debug!(
            file,
            proven_sites = counts.proven_sites,
            retired_name_only = counts.retired_name_only,
            narrowed_name_only = counts.narrowed_name_only,
            retired_confident = counts.retired_confident,
            narrowed_confident = counts.narrowed_confident,
            refuted_outside = counts.refuted_outside,
            certified_kept = counts.certified_kept,
            proven_external_sites = counts.proven_external_sites,
            outside_unnamed_sites = counts.outside_unnamed_sites,
            "settled the linker's call edges against language-server answers"
        );
    }
    Ok(settlement)
}

struct SiteInput<'a> {
    caller: EntityId,
    file: &'a str,
    text: &'a str,
    span: &'a kin_model::SourceSpan,
    /// The bound destination's own name, which the callee token must spell for
    /// a proof to contradict the edge.
    name: &'a str,
    bound: &'a Entity,
    proofs: &'a HashMap<(EntityId, usize, usize), Proof>,
    already_proven: &'a HashMap<EntityId, BTreeSet<(usize, usize)>>,
    already_external: &'a HashMap<ExternalReferenceId, BTreeSet<(usize, usize)>>,
    /// The `ctx:<id>` evidence token of the proof context, when one is known.
    context_token: Option<&'a str>,
}

/// caller -> proven external symbol -> its node and the sites that proved it.
type ProvenExternal =
    BTreeMap<EntityId, BTreeMap<ExternalReferenceId, (ExternalReference, Vec<RelationEvidence>)>>;

fn settle_site<S: EntityStore + ?Sized>(
    store: &S,
    entities: &mut EntityCache,
    site: SiteInput<'_>,
    proven: &mut BTreeMap<EntityId, BTreeMap<EntityId, Vec<RelationEvidence>>>,
    proven_external: &mut ProvenExternal,
    counts: &mut SettlementCounts,
) -> Result<SiteOutcome, S::Error> {
    let Some(token) = call_sites::callee_token(site.file, site.text, site.span) else {
        return Ok(SiteOutcome::Kept);
    };
    let Some(proof) = site
        .proofs
        .get(&(site.caller, token.start_byte, token.end_byte))
    else {
        return Ok(SiteOutcome::Kept);
    };
    let Some(target) = proof.target.as_ref() else {
        return Ok(SiteOutcome::Kept);
    };
    // The answer at a recorded call's callee token proves that call, whatever
    // the linker bound there. It contradicts the bound destination only where
    // the token spells that destination's own name: an alias, or a call the
    // linker recorded under another name, keeps its edge.
    let spells_bound_name = token.name == site.name;
    match target {
        ProofTarget::Entity(target) => {
            let target = *target;
            let recorded = site
                .already_proven
                .get(&target)
                .is_some_and(|sites| sites.contains(&(token.start_byte, token.end_byte)));
            if target != site.caller && !recorded {
                proven
                    .entry(site.caller)
                    .or_default()
                    .entry(target)
                    .or_default()
                    .extend(proof.evidence.iter().cloned());
            }
            if target == site.bound.id || !spells_bound_name {
                return Ok(SiteOutcome::Kept);
            }
            let proven_entity = entities.get(store, target)?;
            if may_dispatch_to(
                store,
                entities,
                site.bound,
                proven_entity.as_ref(),
                true,
                token.through_member,
            )? {
                return Ok(SiteOutcome::Kept);
            }
            Ok(SiteOutcome::Contradicted { outside: false })
        }
        ProofTarget::Outside { symbol } => {
            // The answer proves the call names this symbol, whatever the
            // linker bound there, as an answer naming an entity does.
            match (
                symbol.as_ref().map(ExternalSymbol::to_reference),
                site.context_token,
            ) {
                (Some(Ok(node)), Some(context_token)) => {
                    let recorded = site
                        .already_external
                        .get(&node.id)
                        .is_some_and(|sites| sites.contains(&(token.start_byte, token.end_byte)));
                    if !recorded {
                        let evidence = proof.evidence.iter().cloned().map(|mut record| {
                            record.token = Some(context_token.to_string());
                            record
                        });
                        proven_external
                            .entry(site.caller)
                            .or_default()
                            .entry(node.id)
                            .or_insert_with(|| (node, Vec::new()))
                            .1
                            .extend(evidence);
                    }
                }
                _ => counts.outside_unnamed_sites += 1,
            }
            if !spells_bound_name
                || may_dispatch_to(
                    store,
                    entities,
                    site.bound,
                    None,
                    false,
                    token.through_member,
                )?
            {
                return Ok(SiteOutcome::Kept);
            }
            Ok(SiteOutcome::Contradicted { outside: true })
        }
    }
}

/// Whether a call the server resolved statically to `proven` (or, with
/// `in_graph` false, to a declaration outside the repository) may still run
/// `bound`'s body.
///
/// The body that runs can differ from the declaration a definition answer
/// names in these ways, and an edge to such a body stays a candidate:
///
/// - `bound` and `proven` declare the same function: Python keeps each
///   `@overload` stub as an entity of its own, under the implementation's
///   name in the same file;
/// - `proven` is a method of an interface or trait, which any implementation
///   of it can answer, through a receiver or a path such as
///   `T::from_request(..)`;
///
/// and, only for a call through a member access, where the receiver's
/// runtime type chooses the body:
///
/// - `bound` itself overrides or implements some declaration, by an edge the
///   graph holds (a Python method over an in-repository or imported base);
/// - `bound`'s owner extends or implements a type the graph does not hold, so
///   the declaration the server named may be the external base's;
/// - the proven declaration is outside the repository and `bound` is a Go or
///   Rust method, which can satisfy an external interface or trait without any
///   edge the graph could hold.
fn may_dispatch_to<S: EntityStore + ?Sized>(
    store: &S,
    entities: &mut EntityCache,
    bound: &Entity,
    proven: Option<&Entity>,
    in_graph: bool,
    through_member: bool,
) -> Result<bool, S::Error> {
    if let Some(proven) = proven {
        if proven.name == bound.name && proven.file_origin == bound.file_origin {
            return Ok(true);
        }
        if owner_of(store, entities, proven)?
            .is_some_and(|owner| matches!(owner.kind, EntityKind::Interface | EntityKind::TraitDef))
        {
            return Ok(true);
        }
    }
    if !through_member {
        return Ok(false);
    }
    let relations = store.get_all_relations_for_entity(&bound.id)?;
    if relations.iter().any(|relation| {
        relation.src == GraphNodeId::Entity(bound.id)
            && matches!(
                relation.kind,
                RelationKind::Overrides | RelationKind::Implements
            )
    }) {
        return Ok(true);
    }
    if let Some(owner) = owner_of(store, entities, bound)? {
        for relation in store.get_all_relations_for_entity(&owner.id)? {
            if relation.src != GraphNodeId::Entity(owner.id)
                || !matches!(
                    relation.kind,
                    RelationKind::Extends | RelationKind::Implements
                )
            {
                continue;
            }
            let held = match relation.dst {
                GraphNodeId::Entity(base) => entities.get(store, base)?.is_some(),
                _ => false,
            };
            if !held {
                return Ok(true);
            }
        }
    }
    Ok(!in_graph
        && bound.kind == EntityKind::Method
        && matches!(bound.language, LanguageId::Go | LanguageId::Rust))
}

/// The type that declares `member`, read off the `Contains` edge into it.
fn owner_of<S: EntityStore + ?Sized>(
    store: &S,
    entities: &mut EntityCache,
    member: &Entity,
) -> Result<Option<Entity>, S::Error> {
    let mut owners: Vec<EntityId> = store
        .get_all_relations_for_entity(&member.id)?
        .into_iter()
        .filter(|relation| {
            relation.kind == RelationKind::Contains
                && relation.dst == GraphNodeId::Entity(member.id)
        })
        .filter_map(|relation| relation.src.as_entity())
        .collect();
    owners.sort();
    owners.dedup();
    for owner in owners {
        if let Some(entity) = entities.get(store, owner)? {
            if matches!(
                entity.kind,
                EntityKind::Class
                    | EntityKind::Interface
                    | EntityKind::TraitDef
                    | EntityKind::TypeAlias
                    | EntityKind::EnumDef
            ) {
                return Ok(Some(entity));
            }
        }
    }
    Ok(None)
}

#[derive(Default)]
struct EntityCache {
    held: HashMap<EntityId, Option<Entity>>,
}

impl EntityCache {
    fn get<S: EntityStore + ?Sized>(
        &mut self,
        store: &S,
        id: EntityId,
    ) -> Result<Option<Entity>, S::Error> {
        if let Some(held) = self.held.get(&id) {
            return Ok(held.clone());
        }
        let entity = store.get_entity(&id)?;
        self.held.insert(id, entity.clone());
        Ok(entity)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_lsp::call_sites::{CALL_HIERARCHY_RULE, DEFINITION_RULE};
    use kin_model::{
        EntityMetadata, EntityRole, FilePathId, FingerprintAlgorithm, Hash256, RelationId,
        SemanticFingerprint, SourceSpan, Visibility,
    };

    const FILE: &str = "app/run.py";
    /// `run` calls `send` through a receiver the linker cannot type, so it
    /// guessed every method named `send`. Two call sites, so a guess can lose
    /// one and keep the other.
    const TEXT: &str = "def run(self):\n    self.adapter.send(x)\n    self.other.send(y)\n";

    fn entity(name: &str, file: &str, kind: EntityKind) -> Entity {
        Entity {
            id: EntityId::new(),
            kind,
            name: name.to_string(),
            language: LanguageId::Python,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([1; 32]),
                signature_hash: Hash256::from_bytes([2; 32]),
                behavior_hash: Hash256::from_bytes([3; 32]),
                equivalence_hash: Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new(file)),
            span: None,
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

    fn span(expression: &str, nth: usize) -> SourceSpan {
        let start = TEXT
            .match_indices(expression)
            .nth(nth)
            .expect("the expression is in the fixture")
            .0;
        let line = TEXT[..start].matches('\n').count() as u32;
        let column = (start - TEXT[..start].rfind('\n').map_or(0, |at| at + 1)) as u32;
        SourceSpan {
            file: FilePathId::new(FILE),
            start_byte: start,
            end_byte: start + expression.len(),
            start_line: line,
            start_col: column,
            end_line: line,
            end_col: column + expression.len() as u32,
        }
    }

    /// The callee token `send` inside the `nth` call.
    fn send_token(nth: usize) -> SourceSpan {
        let call = span(["self.adapter.send(x)", "self.other.send(y)"][nth], 0);
        let offset = TEXT[call.start_byte..call.end_byte].find("send").unwrap();
        SourceSpan {
            start_byte: call.start_byte + offset,
            end_byte: call.start_byte + offset + 4,
            start_col: call.start_col + offset as u32,
            end_col: call.start_col + offset as u32 + 4,
            ..call
        }
    }

    /// A receiver fan-out guess, the weakest tier the linker persists.
    fn guess(caller: &Entity, callee: &Entity, sites: &[usize]) -> Relation {
        Relation {
            id: RelationId::new(),
            kind: RelationKind::Calls,
            src: GraphNodeId::Entity(caller.id),
            dst: GraphNodeId::Entity(callee.id),
            confidence: kin_index::resolution::RECEIVER_NAME_FANOUT_CONFIDENCE,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: None,
            evidence: sites
                .iter()
                .map(|nth| RelationEvidence {
                    source_span: Some(span(
                        ["self.adapter.send(x)", "self.other.send(y)"][*nth],
                        0,
                    )),
                    ..Default::default()
                })
                .collect(),
        }
    }

    /// A place outside the workspace an answer landed, the `nth` of several.
    fn outside(nth: u32) -> SiteTarget {
        SiteTarget::Outside(kin_lsp::call_sites::OutsideLocation {
            uri: "file:///opt/lib/python3.12/typeshed/stdlib/socket.pyi".to_string(),
            range: kin_lsp::call_sites::LocationRange {
                start_line: 40 + nth,
                start_character: 8,
                end_line: 40 + nth,
                end_character: 12,
            },
        })
    }

    fn named(
        nth: u32,
        symbol: &ExternalSymbol,
    ) -> (kin_lsp::call_sites::OutsideLocation, ExternalSymbol) {
        let SiteTarget::Outside(location) = outside(nth) else {
            unreachable!()
        };
        (location, symbol.clone())
    }

    fn socket_send() -> ExternalSymbol {
        ExternalSymbol::new(
            kin_model::ScipPackage::new("python", "python-stdlib", "3.12").unwrap(),
            vec![
                kin_model::ScipDescriptor::namespace("socket"),
                kin_model::ScipDescriptor::type_("socket"),
                kin_model::ScipDescriptor::method("send"),
            ],
        )
        .unwrap()
    }

    fn context_id() -> ResolutionRecordId {
        ResolutionRecordId(uuid::Uuid::from_u128(0x0c0f_fee0))
    }

    fn answer(caller: &Entity, nth: usize, target: SiteTarget) -> SiteAnswer {
        SiteAnswer {
            source: caller.id,
            site: send_token(nth),
            target,
            rule: DEFINITION_RULE,
        }
    }

    struct Fixture {
        graph: kin_db::InMemoryGraph,
        run: Entity,
        alpha: Entity,
        target: Entity,
        alpha_guess: Relation,
        beta_guess: Relation,
    }

    fn fixture() -> Fixture {
        let graph = kin_db::InMemoryGraph::new();
        let run = entity("run", FILE, EntityKind::Function);
        let alpha = entity("Alpha.send", "app/alpha.py", EntityKind::Method);
        let beta = entity("Beta.send", "app/beta.py", EntityKind::Method);
        let target = entity("Transport.send", "app/transport.py", EntityKind::Method);
        for held in [&run, &alpha, &beta, &target] {
            graph.upsert_entity(held).unwrap();
        }
        let alpha_guess = guess(&run, &alpha, &[0, 1]);
        let beta_guess = guess(&run, &beta, &[0, 1]);
        graph.upsert_relation(&alpha_guess).unwrap();
        graph.upsert_relation(&beta_guess).unwrap();
        Fixture {
            graph,
            run,
            alpha,
            target,
            alpha_guess,
            beta_guess,
        }
    }

    fn apply(graph: &kin_db::InMemoryGraph, settlement: &Settlement) {
        for relation in settlement.proven.iter().chain(&settlement.narrowed) {
            graph.upsert_relation(relation).unwrap();
        }
        for relation in &settlement.retired {
            graph.remove_relation(&relation.id).unwrap();
        }
    }

    fn ids(relations: &[Relation]) -> Vec<RelationId> {
        let mut ids: Vec<_> = relations.iter().map(|relation| relation.id).collect();
        ids.sort();
        ids
    }

    fn sorted(mut ids: Vec<RelationId>) -> Vec<RelationId> {
        ids.sort();
        ids
    }

    #[test]
    fn a_definition_naming_another_entity_retires_the_guesses_and_proves_the_call() {
        let f = fixture();
        let answers = [
            answer(&f.run, 0, SiteTarget::Entity(f.target.id)),
            answer(&f.run, 1, SiteTarget::Entity(f.target.id)),
        ];
        let settlement = settle(&f.graph, FILE, TEXT, &answers).unwrap();
        assert_eq!(
            ids(&settlement.retired),
            sorted(vec![f.alpha_guess.id, f.beta_guess.id]),
            "both candidates were contradicted at both of their sites"
        );
        assert!(settlement.narrowed.is_empty());
        assert_eq!(settlement.proven.len(), 1);
        let proven = &settlement.proven[0];
        assert_eq!(
            (proven.kind, proven.src, proven.dst, proven.origin),
            (
                RelationKind::Calls,
                GraphNodeId::Entity(f.run.id),
                GraphNodeId::Entity(f.target.id),
                RelationOrigin::Lsp
            )
        );
        let sites: Vec<_> = proven
            .evidence
            .iter()
            .map(|record| {
                let site = record.source_span.as_ref().unwrap();
                (
                    &TEXT[site.start_byte..site.end_byte],
                    site.start_line,
                    record.parser_rule.as_deref(),
                )
            })
            .collect();
        assert_eq!(
            sites,
            [
                ("send", 1, Some(DEFINITION_RULE)),
                ("send", 2, Some(DEFINITION_RULE))
            ],
            "the proven edge carries the proof at each callee token"
        );
    }

    #[test]
    fn a_definition_outside_the_repository_retires_the_guesses_and_mints_nothing() {
        let f = fixture();
        let answers = [answer(&f.run, 0, outside(0)), answer(&f.run, 1, outside(0))];
        let settlement = settle(&f.graph, FILE, TEXT, &answers).unwrap();
        assert_eq!(
            ids(&settlement.retired),
            sorted(vec![f.alpha_guess.id, f.beta_guess.id])
        );
        assert!(
            settlement.proven.is_empty(),
            "no edge names a declaration the repository lacks"
        );
        assert!(settlement.narrowed.is_empty());
    }

    /// An answer outside the repository that the server's own symbols name
    /// proves the call names that symbol: the guesses it contradicts go, and a
    /// `Calls` edge to the symbol carries the proof at each callee token,
    /// under the proof context's token.
    #[test]
    fn a_named_outside_definition_proves_a_call_into_the_symbol() {
        let f = fixture();
        let names: ExternalNames = [named(0, &socket_send())].into_iter().collect();
        let answers = [answer(&f.run, 0, outside(0)), answer(&f.run, 1, outside(0))];
        let settlement = settle_with(
            &f.graph,
            FILE,
            TEXT,
            &answers,
            OutsideProof {
                names: &names,
                context: Some(context_id()),
            },
        )
        .unwrap();
        assert_eq!(
            ids(&settlement.retired),
            sorted(vec![f.alpha_guess.id, f.beta_guess.id]),
            "the refutation is today's"
        );
        assert!(settlement.proven.is_empty());
        let node = socket_send().to_reference().unwrap();
        assert_eq!(settlement.external_nodes, vec![node.clone()]);
        assert_eq!(settlement.proven_external.len(), 1);
        let edge = &settlement.proven_external[0];
        assert_eq!(
            (edge.kind, edge.src, edge.dst, edge.origin),
            (
                RelationKind::Calls,
                GraphNodeId::Entity(f.run.id),
                GraphNodeId::ExternalReference(node.id),
                RelationOrigin::Lsp
            )
        );
        assert_eq!(
            edge.id,
            kin_model::RelationId::resolver(RelationKind::Calls, &edge.src, &edge.dst)
        );
        let sites: Vec<_> = edge
            .evidence
            .iter()
            .map(|record| {
                let site = record.source_span.as_ref().unwrap();
                (
                    &TEXT[site.start_byte..site.end_byte],
                    record.parser_rule.as_deref(),
                    record.token.clone(),
                )
            })
            .collect();
        let token = Some(context_id().context_token());
        assert_eq!(
            sites,
            [
                ("send", Some(DEFINITION_RULE), token.clone()),
                ("send", Some(DEFINITION_RULE), token)
            ]
        );
        assert_eq!(settlement.counts.proven_external_sites, 2);

        // Installed, the proof is not minted a second time.
        f.graph
            .apply_transaction_delta(&kin_model::TransactionDelta {
                external_reference_deltas: vec![kin_model::ExternalReferenceDelta::Added {
                    new: node,
                }],
                ..Default::default()
            })
            .unwrap();
        apply(&f.graph, &settlement);
        for relation in &settlement.proven_external {
            f.graph.upsert_relation(relation).unwrap();
        }
        let again = settle_with(
            &f.graph,
            FILE,
            TEXT,
            &answers,
            OutsideProof {
                names: &names,
                context: Some(context_id()),
            },
        )
        .unwrap();
        assert!(again.is_empty(), "{again:?}");
    }

    /// A definition answer and a call-hierarchy answer at one callee token
    /// prove one site, so the edge into the symbol records the site once,
    /// under the definition rule, rather than once for each query that
    /// answered. A site only call hierarchy answered keeps that rule.
    #[test]
    fn an_external_proof_records_each_site_once() {
        let f = fixture();
        let names: ExternalNames = [named(0, &socket_send())].into_iter().collect();
        let hierarchy = |nth| SiteAnswer {
            rule: CALL_HIERARCHY_RULE,
            ..answer(&f.run, nth, outside(0))
        };
        let answers = [hierarchy(0), answer(&f.run, 0, outside(0)), hierarchy(1)];
        let settlement = settle_with(
            &f.graph,
            FILE,
            TEXT,
            &answers,
            OutsideProof {
                names: &names,
                context: Some(context_id()),
            },
        )
        .unwrap();
        assert_eq!(settlement.proven_external.len(), 1);
        let sites: Vec<_> = settlement.proven_external[0]
            .evidence
            .iter()
            .map(|record| {
                let site = record.source_span.as_ref().unwrap();
                (site.start_line, record.parser_rule.as_deref())
            })
            .collect();
        assert_eq!(
            sites,
            [(1, Some(DEFINITION_RULE)), (2, Some(CALL_HIERARCHY_RULE))]
        );
        assert_eq!(settlement.counts.proven_external_sites, 2);
    }

    /// Without a name, or without a proof context, an outside answer refutes
    /// exactly as before and mints nothing; two answers naming different
    /// symbols at one token name none.
    #[test]
    fn an_unnamed_outside_answer_refutes_and_proves_no_symbol() {
        let f = fixture();
        let answers = [answer(&f.run, 0, outside(0)), answer(&f.run, 1, outside(0))];
        let unnamed = ExternalNames::new();
        let settlement = settle_with(
            &f.graph,
            FILE,
            TEXT,
            &answers,
            OutsideProof {
                names: &unnamed,
                context: Some(context_id()),
            },
        )
        .unwrap();
        assert_eq!(settlement.retired.len(), 2);
        assert!(settlement.proven_external.is_empty());
        assert!(settlement.external_nodes.is_empty());
        assert!(settlement.counts.outside_unnamed_sites > 0);

        let names: ExternalNames = [named(0, &socket_send())].into_iter().collect();
        let no_context = settle_with(
            &f.graph,
            FILE,
            TEXT,
            &answers,
            OutsideProof {
                names: &names,
                context: None,
            },
        )
        .unwrap();
        assert_eq!(no_context.retired.len(), 2);
        assert!(no_context.proven_external.is_empty());

        let mut other = socket_send();
        other.descriptors.last_mut().unwrap().name = "sendall".to_string();
        let names: ExternalNames = [named(0, &socket_send()), named(1, &other)]
            .into_iter()
            .collect();
        let conflicting = [answer(&f.run, 0, outside(0)), answer(&f.run, 0, outside(1))];
        let settlement = settle_with(
            &f.graph,
            FILE,
            TEXT,
            &conflicting,
            OutsideProof {
                names: &names,
                context: Some(context_id()),
            },
        )
        .unwrap();
        assert!(
            settlement.proven_external.is_empty(),
            "two symbols at one token prove neither"
        );
        assert_eq!(
            ids(&settlement.narrowed),
            sorted(vec![f.alpha_guess.id, f.beta_guess.id]),
            "they still agree the call leaves the repository"
        );
    }

    #[test]
    fn no_answer_retires_nothing() {
        let f = fixture();
        assert!(settle(&f.graph, FILE, TEXT, &[]).unwrap().is_empty());
        // An answer about another identifier on the same line is not an
        // answer about the callee.
        let receiver = SiteAnswer {
            site: span("adapter", 0),
            ..answer(&f.run, 0, outside(0))
        };
        assert!(settle(&f.graph, FILE, TEXT, &[receiver])
            .unwrap()
            .is_empty());
        // Neither is an answer asked in another caller.
        let elsewhere = SiteAnswer {
            source: f.target.id,
            ..answer(&f.run, 0, outside(0))
        };
        assert!(settle(&f.graph, FILE, TEXT, &[elsewhere])
            .unwrap()
            .is_empty());
    }

    #[test]
    fn answers_that_disagree_prove_nothing() {
        let f = fixture();
        let answers = [
            answer(&f.run, 0, SiteTarget::Entity(f.target.id)),
            SiteAnswer {
                rule: CALL_HIERARCHY_RULE,
                ..answer(&f.run, 0, SiteTarget::Entity(f.alpha.id))
            },
        ];
        assert!(settle(&f.graph, FILE, TEXT, &answers).unwrap().is_empty());
    }

    #[test]
    fn a_definition_confirming_a_guess_keeps_it_and_retires_only_the_others() {
        let f = fixture();
        let answers = [
            answer(&f.run, 0, SiteTarget::Entity(f.alpha.id)),
            answer(&f.run, 1, SiteTarget::Entity(f.alpha.id)),
        ];
        let settlement = settle(&f.graph, FILE, TEXT, &answers).unwrap();
        assert_eq!(ids(&settlement.retired), vec![f.beta_guess.id]);
        assert!(
            settlement.narrowed.is_empty(),
            "the confirmed guess keeps every site: {:?}",
            settlement.narrowed
        );
        assert_eq!(
            settlement.proven.len(),
            1,
            "one proven edge, not one per site"
        );
        assert_eq!(settlement.proven[0].dst, GraphNodeId::Entity(f.alpha.id));

        // Applied, the confirmed destination has one parser guess and one
        // proven edge under a deterministic id, and settling again adds none.
        apply(&f.graph, &settlement);
        let again = settle(&f.graph, FILE, TEXT, &answers).unwrap();
        assert!(
            again.is_empty(),
            "a settled graph settles to nothing: {again:?}"
        );
        let to_alpha: Vec<_> = f
            .graph
            .get_all_relations_for_entity(&f.run.id)
            .unwrap()
            .into_iter()
            .filter(|relation| {
                relation.kind == RelationKind::Calls
                    && relation.dst == GraphNodeId::Entity(f.alpha.id)
            })
            .map(|relation| relation.origin)
            .collect();
        assert_eq!(
            sorted_origins(to_alpha),
            sorted_origins(vec![RelationOrigin::Parsed, RelationOrigin::Lsp])
        );
    }

    fn sorted_origins(mut origins: Vec<RelationOrigin>) -> Vec<String> {
        let mut named: Vec<String> = origins
            .drain(..)
            .map(|origin| format!("{origin:?}"))
            .collect();
        named.sort();
        named
    }

    #[test]
    fn a_guess_contradicted_at_one_site_keeps_the_other() {
        let f = fixture();
        let answers = [answer(&f.run, 0, outside(0))];
        let settlement = settle(&f.graph, FILE, TEXT, &answers).unwrap();
        assert!(settlement.retired.is_empty());
        assert_eq!(
            ids(&settlement.narrowed),
            sorted(vec![f.alpha_guess.id, f.beta_guess.id])
        );
        for narrowed in &settlement.narrowed {
            let lines: Vec<_> = narrowed
                .evidence
                .iter()
                .filter_map(|record| record.source_span.as_ref())
                .map(|site| site.start_line)
                .collect();
            assert_eq!(lines, [2], "only the unanswered site remains");
        }
    }

    #[test]
    fn settling_twice_changes_nothing_the_second_time() {
        let f = fixture();
        let answers = [
            answer(&f.run, 0, SiteTarget::Entity(f.target.id)),
            answer(&f.run, 1, outside(0)),
        ];
        let first = settle(&f.graph, FILE, TEXT, &answers).unwrap();
        assert!(!first.is_empty());
        apply(&f.graph, &first);
        let second = settle(&f.graph, FILE, TEXT, &answers).unwrap();
        assert!(second.is_empty(), "{second:?}");
    }

    #[test]
    fn a_method_that_overrides_something_stays_a_dispatch_candidate() {
        let f = fixture();
        let base = entity("Base.send", "app/base.py", EntityKind::Method);
        f.graph.upsert_entity(&base).unwrap();
        f.graph
            .upsert_relation(&Relation {
                id: RelationId::new(),
                kind: RelationKind::Overrides,
                src: GraphNodeId::Entity(f.alpha.id),
                dst: GraphNodeId::Entity(base.id),
                confidence: 1.0,
                origin: RelationOrigin::Parsed,
                created_in: None,
                import_source: None,
                evidence: Vec::new(),
            })
            .unwrap();
        let answers = [
            answer(&f.run, 0, SiteTarget::Entity(base.id)),
            answer(&f.run, 1, SiteTarget::Entity(base.id)),
        ];
        let settlement = settle(&f.graph, FILE, TEXT, &answers).unwrap();
        assert_eq!(
            ids(&settlement.retired),
            vec![f.beta_guess.id],
            "a call the server resolved to a base may still run an override of it"
        );
        assert_eq!(settlement.proven.len(), 1);
    }

    #[test]
    fn a_call_through_an_interface_method_keeps_every_implementation() {
        let f = fixture();
        let contract = entity("Sender", "app/contract.py", EntityKind::Interface);
        let method = entity("Sender.send", "app/contract.py", EntityKind::Method);
        f.graph.upsert_entity(&contract).unwrap();
        f.graph.upsert_entity(&method).unwrap();
        f.graph
            .upsert_relation(&Relation {
                id: RelationId::new(),
                kind: RelationKind::Contains,
                src: GraphNodeId::Entity(contract.id),
                dst: GraphNodeId::Entity(method.id),
                confidence: 1.0,
                origin: RelationOrigin::Parsed,
                created_in: None,
                import_source: None,
                evidence: Vec::new(),
            })
            .unwrap();
        let answers = [answer(&f.run, 0, SiteTarget::Entity(method.id))];
        let settlement = settle(&f.graph, FILE, TEXT, &answers).unwrap();
        assert!(settlement.retired.is_empty() && settlement.narrowed.is_empty());
        assert_eq!(
            settlement.proven.len(),
            1,
            "the static call itself is still proven"
        );
    }

    #[test]
    fn a_go_method_survives_an_answer_outside_the_repository() {
        let f = fixture();
        let mut writer = entity("buffer.Write", "buf/buffer.go", EntityKind::Method);
        writer.language = LanguageId::Go;
        f.graph.upsert_entity(&writer).unwrap();
        let text = "func run(w io.Writer) {\n\tw.Write(p)\n}\n";
        let call = text.find("w.Write(p)").unwrap();
        let site = |start: usize, len: usize| SourceSpan {
            file: FilePathId::new("run.go"),
            start_byte: start,
            end_byte: start + len,
            start_line: 1,
            start_col: (start - text.find('\n').unwrap() - 1) as u32,
            end_line: 1,
            end_col: (start - text.find('\n').unwrap() - 1 + len) as u32,
        };
        let mut guess = guess(&f.run, &writer, &[]);
        guess.evidence = vec![RelationEvidence {
            source_span: Some(site(call, "w.Write(p)".len())),
            ..Default::default()
        }];
        f.graph.upsert_relation(&guess).unwrap();
        let answers = [SiteAnswer {
            source: f.run.id,
            site: site(call + 2, 5),
            target: outside(0),
            rule: DEFINITION_RULE,
        }];
        assert!(
            settle(&f.graph, "run.go", text, &answers)
                .unwrap()
                .is_empty(),
            "a Go method can satisfy an interface the graph cannot see"
        );
    }

    /// An edge the linker bound above the name-only floor is no longer left
    /// alone: contradicted at every site, it is retired like a guess, and
    /// counted apart from the guesses.
    #[test]
    fn an_edge_above_the_name_only_floor_is_retired_when_every_site_is_contradicted() {
        let f = fixture();
        let mut scoped = f.alpha_guess.clone();
        scoped.confidence = 0.9;
        f.graph.upsert_relation(&scoped).unwrap();
        f.graph.remove_relation(&f.beta_guess.id).unwrap();
        let answers = [answer(&f.run, 0, outside(0)), answer(&f.run, 1, outside(0))];
        let settlement = settle(&f.graph, FILE, TEXT, &answers).unwrap();
        assert_eq!(ids(&settlement.retired), vec![scoped.id]);
        assert_eq!(
            (
                settlement.counts.retired_confident,
                settlement.counts.retired_name_only,
                settlement.counts.refuted_outside
            ),
            (1, 0, 2)
        );
    }

    /// A caller's source with a plain call and a path call, each a site the
    /// linker can bind confidently through an import or a same-file name.
    const PLAIN: &str = "def build(self):\n    helper(z)\n    T::from_request(parts)\n";
    const PLAIN_FILE: &str = "app/build.py";

    /// The span of `expression` in [`PLAIN`], and of the callee token `name`
    /// inside it.
    fn plain_site(expression: &str, name: &str) -> (SourceSpan, SourceSpan) {
        let start = PLAIN.find(expression).expect("the call is in the fixture");
        let line = PLAIN[..start].matches('\n').count() as u32;
        let line_start = PLAIN[..start].rfind('\n').map_or(0, |at| at + 1);
        let span = |from: usize, len: usize| SourceSpan {
            file: FilePathId::new(PLAIN_FILE),
            start_byte: from,
            end_byte: from + len,
            start_line: line,
            start_col: (from - line_start) as u32,
            end_line: line,
            end_col: (from - line_start + len) as u32,
        };
        let token = start + expression.find(name).expect("the callee is in the call");
        (span(start, expression.len()), span(token, name.len()))
    }

    /// A parser edge the linker bound at `confidence`, recorded at `site`.
    fn bound(caller: &Entity, callee: &Entity, confidence: f32, site: SourceSpan) -> Relation {
        Relation {
            id: RelationId::new(),
            kind: RelationKind::Calls,
            src: GraphNodeId::Entity(caller.id),
            dst: GraphNodeId::Entity(callee.id),
            confidence,
            origin: if confidence >= 1.0 {
                RelationOrigin::Parsed
            } else {
                RelationOrigin::Inferred
            },
            created_in: None,
            import_source: None,
            evidence: vec![RelationEvidence {
                source_span: Some(site),
                ..Default::default()
            }],
        }
    }

    fn defined(caller: &Entity, token: SourceSpan, target: SiteTarget) -> SiteAnswer {
        SiteAnswer {
            source: caller.id,
            site: token,
            target,
            rule: DEFINITION_RULE,
        }
    }

    fn contains(graph: &kin_db::InMemoryGraph, owner: &Entity, member: &Entity) {
        graph
            .upsert_relation(&Relation {
                id: RelationId::new(),
                kind: RelationKind::Contains,
                src: GraphNodeId::Entity(owner.id),
                dst: GraphNodeId::Entity(member.id),
                confidence: 1.0,
                origin: RelationOrigin::Parsed,
                created_in: None,
                import_source: None,
                evidence: Vec::new(),
            })
            .unwrap();
    }

    /// A confidently bound call whose definition answer names that same
    /// callee is proven at its site, and the parser's own edge stays as it
    /// was. Only name-only guesses used to be visited, so a confident call was
    /// proven only when call hierarchy happened to list it.
    #[test]
    fn a_definition_confirming_a_confident_call_proves_it() {
        let graph = kin_db::InMemoryGraph::new();
        let build = entity("build", PLAIN_FILE, EntityKind::Function);
        let helper = entity("helper", "app/util.py", EntityKind::Function);
        for held in [&build, &helper] {
            graph.upsert_entity(held).unwrap();
        }
        let (call, token) = plain_site("helper(z)", "helper");
        let edge = bound(&build, &helper, 0.95, call);
        graph.upsert_relation(&edge).unwrap();

        let answers = [defined(
            &build,
            token.clone(),
            SiteTarget::Entity(helper.id),
        )];
        let settlement = settle(&graph, PLAIN_FILE, PLAIN, &answers).unwrap();
        assert!(settlement.retired.is_empty() && settlement.narrowed.is_empty());
        assert_eq!(settlement.proven.len(), 1, "{settlement:?}");
        let proven = &settlement.proven[0];
        assert_eq!(
            (proven.src, proven.dst, proven.origin),
            (
                GraphNodeId::Entity(build.id),
                GraphNodeId::Entity(helper.id),
                RelationOrigin::Lsp
            )
        );
        assert_eq!(
            proven.evidence[0].source_span.as_ref(),
            Some(&token),
            "the proof is recorded at the callee token it was asked at"
        );
        assert_eq!(settlement.counts.proven_sites, 1);
    }

    /// A confidently bound call the server resolves outside the repository is
    /// refuted there: the parser's edge is retired and nothing is minted. On
    /// axum rust-analyzer resolves 10 of 537 confident edges outside the
    /// repository, and none of them used to be touched.
    #[test]
    fn an_outside_answer_retires_a_confident_call() {
        let graph = kin_db::InMemoryGraph::new();
        let build = entity("build", PLAIN_FILE, EntityKind::Function);
        let helper = entity("helper", "app/util.py", EntityKind::Function);
        for held in [&build, &helper] {
            graph.upsert_entity(held).unwrap();
        }
        let (call, token) = plain_site("helper(z)", "helper");
        let edge = bound(&build, &helper, 0.95, call);
        graph.upsert_relation(&edge).unwrap();

        let answers = [defined(&build, token, outside(0))];
        let settlement = settle(&graph, PLAIN_FILE, PLAIN, &answers).unwrap();
        assert_eq!(ids(&settlement.retired), vec![edge.id]);
        assert!(settlement.proven.is_empty() && settlement.narrowed.is_empty());
        assert_eq!(
            (
                settlement.counts.retired_confident,
                settlement.counts.retired_name_only,
                settlement.counts.refuted_outside
            ),
            (1, 0, 1)
        );
    }

    /// A confident call the server resolves to another same-named declaration
    /// in the repository is retired, and the declaration it named is proven.
    #[test]
    fn a_definition_naming_another_declaration_retires_a_confident_call() {
        let graph = kin_db::InMemoryGraph::new();
        let build = entity("build", PLAIN_FILE, EntityKind::Function);
        let bound_to = entity("helper", "app/util.py", EntityKind::Function);
        let named = entity("helper", "app/other.py", EntityKind::Function);
        for held in [&build, &bound_to, &named] {
            graph.upsert_entity(held).unwrap();
        }
        let (call, token) = plain_site("helper(z)", "helper");
        let edge = bound(&build, &bound_to, 0.95, call);
        graph.upsert_relation(&edge).unwrap();

        let answers = [defined(&build, token, SiteTarget::Entity(named.id))];
        let settlement = settle(&graph, PLAIN_FILE, PLAIN, &answers).unwrap();
        assert_eq!(ids(&settlement.retired), vec![edge.id]);
        assert_eq!(settlement.proven.len(), 1);
        assert_eq!(settlement.proven[0].dst, GraphNodeId::Entity(named.id));
        assert_eq!(settlement.counts.retired_confident, 1);
    }

    /// `T::from_request(parts)` is a path call, not a member call, and yet the
    /// body that runs is whichever implementation `T` is. The server names the
    /// trait's declaration, so the implementation the parser bound stays a
    /// candidate while the trait method is proven.
    #[test]
    fn a_path_call_resolved_to_a_trait_method_keeps_the_implementation() {
        let graph = kin_db::InMemoryGraph::new();
        let build = entity("build", PLAIN_FILE, EntityKind::Function);
        let contract = entity("FromRequest", "src/extract.rs", EntityKind::TraitDef);
        let declared = entity(
            "FromRequest::from_request",
            "src/extract.rs",
            EntityKind::Method,
        );
        let implementation = entity("Json<T>::from_request", "src/json.rs", EntityKind::Method);
        for held in [&build, &contract, &declared, &implementation] {
            graph.upsert_entity(held).unwrap();
        }
        contains(&graph, &contract, &declared);
        let (call, token) = plain_site("T::from_request(parts)", "from_request");
        let edge = bound(&build, &implementation, 0.95, call);
        graph.upsert_relation(&edge).unwrap();

        let answers = [defined(&build, token, SiteTarget::Entity(declared.id))];
        let settlement = settle(&graph, PLAIN_FILE, PLAIN, &answers).unwrap();
        assert!(
            settlement.retired.is_empty() && settlement.narrowed.is_empty(),
            "an implementation of the trait method the server named may run: {settlement:?}"
        );
        assert_eq!(settlement.proven.len(), 1);
        assert_eq!(settlement.proven[0].dst, GraphNodeId::Entity(declared.id));
    }

    /// Python keeps each `@overload` stub as an entity of its own, under the
    /// same name as the implementation. A server that names one of them has
    /// not contradicted a guess naming another: they declare one function.
    #[test]
    fn an_answer_on_an_overload_sibling_keeps_the_guess() {
        let f = fixture();
        let stub = entity("Alpha.send", "app/alpha.py", EntityKind::Method);
        f.graph.upsert_entity(&stub).unwrap();
        let answers = [
            answer(&f.run, 0, SiteTarget::Entity(stub.id)),
            answer(&f.run, 1, SiteTarget::Entity(stub.id)),
        ];
        let settlement = settle(&f.graph, FILE, TEXT, &answers).unwrap();
        assert_eq!(
            ids(&settlement.retired),
            vec![f.beta_guess.id],
            "the guess naming another declaration of the same function stays"
        );
    }

    /// Narrowing drops some of a guess's sites. A span-free record the linker
    /// reserves for per-site occurrence certificates binds to one of those
    /// sites, and one left behind for a site that is gone fails validation
    /// for every site the edge keeps. This module cannot tell which
    /// certificate is whose, so it does not narrow such a guess; retiring it
    /// whole takes its certificates with it.
    #[test]
    fn a_guess_carrying_occurrence_certificates_is_not_narrowed() {
        let f = fixture();
        let mut certified = f.alpha_guess.clone();
        certified.evidence.push(RelationEvidence {
            parser_rule: Some("parser_occurrence_resolution_v1".into()),
            token: Some("{}".into()),
            occurrence_count: 0,
            ..Default::default()
        });
        f.graph.upsert_relation(&certified).unwrap();

        let one_site = [answer(&f.run, 0, outside(0))];
        let settlement = settle(&f.graph, FILE, TEXT, &one_site).unwrap();
        assert_eq!(
            ids(&settlement.narrowed),
            vec![f.beta_guess.id],
            "only the guess without certificates is narrowed: {settlement:?}"
        );
        assert!(settlement.retired.is_empty());

        let both_sites = [answer(&f.run, 0, outside(0)), answer(&f.run, 1, outside(0))];
        let settlement = settle(&f.graph, FILE, TEXT, &both_sites).unwrap();
        assert_eq!(
            ids(&settlement.retired),
            sorted(vec![f.alpha_guess.id, f.beta_guess.id]),
            "a guess contradicted at every site is retired, certificates and all"
        );
    }

    /// The linker's placeholder for `express.Router()`, an imported getter
    /// from a package outside the repository, names a declaration with no file
    /// in it. The server answering outside the repository agrees with it, and
    /// the placeholder stays.
    #[test]
    fn an_outside_answer_keeps_a_placeholder_for_an_imported_symbol() {
        let graph = kin_db::InMemoryGraph::new();
        let build = entity("build", PLAIN_FILE, EntityKind::Function);
        let mut imported = entity("helper", "app/util.py", EntityKind::Module);
        imported.file_origin = None;
        for held in [&build, &imported] {
            graph.upsert_entity(held).unwrap();
        }
        let (call, token) = plain_site("helper(z)", "helper");
        let mut placeholder = bound(&build, &imported, 0.2, call);
        placeholder.import_source = Some("helpers".into());
        graph.upsert_relation(&placeholder).unwrap();

        let answers = [defined(&build, token, outside(0))];
        let settlement = settle(&graph, PLAIN_FILE, PLAIN, &answers).unwrap();
        assert!(settlement.is_empty(), "{settlement:?}");
    }

    #[test]
    fn a_call_hierarchy_edge_already_carrying_the_site_is_not_minted_again() {
        let f = fixture();
        let hierarchy = kin_lsp::call_sites::proven_call(
            f.run.id,
            f.target.id,
            vec![kin_lsp::call_sites::site_evidence(
                CALL_HIERARCHY_RULE,
                send_token(0),
            )],
        );
        f.graph.upsert_relation(&hierarchy).unwrap();
        let answers = kin_lsp::call_sites::call_hierarchy_answers(&[hierarchy]);
        let settlement = settle(&f.graph, FILE, TEXT, &answers).unwrap();
        assert!(settlement.proven.is_empty(), "{:?}", settlement.proven);
        assert_eq!(
            ids(&settlement.narrowed),
            sorted(vec![f.alpha_guess.id, f.beta_guess.id]),
            "call hierarchy proves the first site, and the guesses keep the second"
        );
    }
}
