// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! One state for every call site in every caller a sweep finishes.
//!
//! When the sweep finishes a file, each entity with source text in it gets a
//! [`CallSiteLedger`]: the number of call expressions the parser reads in its
//! body (its census) and one [`CallSiteState`] for each of them, keyed by the
//! callee token's offset and length inside the entity. An entity that makes no
//! call gets a ledger with a census of zero, so a caller with no ledger is
//! always one whose enrichment is owed.
//!
//! The census comes from parsing the admitted text again with the parser that
//! derived the file, so it counts the call expressions the linker recorded its
//! sites at, including calls whose callee the parser could not name. Each
//! expression belongs to the entity a language server's answer about it is
//! attributed to: the innermost entity holding the line of its callee token.
//!
//! A site's state is, in order:
//!
//! - not in build, when no build of the repository compiles the file;
//! - unresolved (callee not placeable), when the text names no callee token;
//! - what every answer at its callee token proves, merged as settlement merges
//!   them: a repository entity, a named external symbol, a declaration
//!   outside the repository no symbol names, or answers that disagree;
//! - otherwise what the question came to: a value binding, an answer outside
//!   the graph, no answer, a refusal, or a timeout, crash or protocol error;
//! - otherwise what ended the pass before the question was asked.
//!
//! Then the file's `Calls` proofs are made to agree with its ledgers. A
//! proven site is carried by an edge to its target under the ledger's proof
//! context, with an evidence record added where no edge carried it yet. When
//! the file's passes all finished, a proof the ledger does not hold is
//! retracted: evidence under another context or under none, at a site this
//! pass settled differently or did not prove, leaves its edge, and an edge
//! left with no site is retired. A file whose passes failed is never
//! retracted; its proofs are only stamped and completed.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

use kin_lsp::call_sites::{
    self, CalleeToken, ExternalNames, SiteAnswer, UnprovenAnswer, UnprovenSite,
};
use kin_model::{
    site_key, CallSite, CallSiteLedger, CallSiteState, Entity, EntityId, ExternalReference,
    ExternalReferenceId, GraphNodeId, Hash256, Relation, RelationEvidence, RelationKind,
    RelationOrigin, ResolutionRecordId, ServerFailure, SourceSpan, UnresolvedReason,
};

use crate::call_site_settlement::{site_proofs, SiteProof};

/// One call expression Kin's parser reads in a file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CallExpression {
    /// Byte offsets of the whole expression in the file.
    pub(crate) start_byte: usize,
    pub(crate) end_byte: usize,
    /// Its callee token, when the text names one plainly (see
    /// [`call_sites::callee_token`]).
    pub(crate) callee: Option<CalleeToken>,
    /// The zero-based line of the callee token, or of the expression when it
    /// has none: the line a server was asked at, and so the line its caller
    /// is found at.
    pub(crate) line: u32,
}

/// Every call expression Kin's parser reads in `file`, whose admitted text is
/// `text`, in source order and each once. `None` when no adapter parses the
/// file or the parse fails.
///
/// The parser is the one that derived the file's entities and the linker's
/// call edges, run again over the same bytes, so the expressions are the ones
/// the linker recorded its call sites at: every `Calls` relation's site, and
/// every call the parser could not represent as a relation and recorded as a
/// gap in its caller's call coverage instead.
#[cfg(test)]
pub(crate) fn call_expressions(file: &str, text: &str) -> Option<Vec<CallExpression>> {
    call_expressions_with(file, text, &[])
}

/// [`call_expressions`], with the call sites the graph's own call edges record
/// in the file as well: `recorded` holds each one's byte range and first line.
///
/// The linker records calls the parser's relations do not carry, such as a
/// call it infers inside a macro's token tree. A site the graph serves a call
/// edge at is a call site whatever produced it, so it has a state too.
pub(crate) fn call_expressions_with(
    file: &str,
    text: &str,
    recorded: &[(usize, usize, u32)],
) -> Option<Vec<CallExpression>> {
    static REGISTRY: std::sync::OnceLock<kin_parser::AdapterRegistry> = std::sync::OnceLock::new();
    let registry = REGISTRY.get_or_init(kin_parser::AdapterRegistry::new);
    let ext = Path::new(file).extension()?.to_str()?;
    let adapter = registry.get_by_extension_and_content(ext, text.as_bytes())?;
    let tree = adapter.parse(text.as_bytes()).ok()?;
    let output = adapter
        .extract(&tree, text.as_bytes(), &kin_model::FilePathId::new(file))
        .ok()?;
    let mut sites: BTreeMap<(usize, usize), u32> = BTreeMap::new();
    for relation in &output.relations {
        let is_call = relation.kind == RelationKind::Calls
            || kin_parser::is_scoped_call_extraction_incomplete_marker(relation);
        if !is_call {
            continue;
        }
        let Some(site) = relation.site.as_ref() else {
            continue;
        };
        if site.end_byte <= site.start_byte || site.end_byte > text.len() {
            continue;
        }
        sites.insert((site.start_byte, site.end_byte), site.start_line);
    }
    for (start_byte, end_byte, start_line) in recorded {
        if *end_byte <= *start_byte || *end_byte > text.len() {
            continue;
        }
        sites.entry((*start_byte, *end_byte)).or_insert(*start_line);
    }
    let lines = LineStarts::new(text);
    Some(
        sites
            .into_iter()
            .map(|((start_byte, end_byte), start_line)| {
                let span = SourceSpan {
                    file: kin_model::FilePathId::new(file),
                    start_byte,
                    end_byte,
                    start_line,
                    start_col: 0,
                    end_line: start_line,
                    end_col: 0,
                };
                let callee = call_sites::callee_token(file, text, &span);
                let line = callee
                    .as_ref()
                    .map_or(start_line, |token| lines.line_of(token.start_byte));
                CallExpression {
                    start_byte,
                    end_byte,
                    callee,
                    line,
                }
            })
            .collect(),
    )
}

/// The byte offset each line of a text starts at.
struct LineStarts(Vec<usize>);

impl LineStarts {
    fn new(text: &str) -> Self {
        let mut starts = vec![0];
        starts.extend(
            text.bytes()
                .enumerate()
                .filter(|(_, byte)| *byte == b'\n')
                .map(|(at, _)| at + 1),
        );
        Self(starts)
    }

    /// The zero-based line holding byte `offset`.
    fn line_of(&self, offset: usize) -> u32 {
        let line = self.0.partition_point(|start| *start <= offset);
        line.saturating_sub(1) as u32
    }
}

/// How the passes over a file ended, for the sites they left unanswered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PassEnding {
    /// The definitions pass asked about every identifier it planned to.
    Complete,
    /// The pass stopped before asking about every identifier, or never
    /// answered, for this reason.
    Stopped(ServerFailure),
    /// The server declined the pass as a whole: an answer with nothing in it.
    Declined,
    /// The server answered none of the file's questions, which is how a
    /// server reports a file no package it loaded holds.
    NothingAnswered,
}

/// The reason a site in a file no build compiles carries.
pub(crate) const NOT_IN_BUILD_REASON: &str =
    "no build of the repository compiles this file, so no configuration of its resolver answers for it";

/// The reason a site in a file whose server answered nothing carries.
const NOTHING_ANSWERED_REASON: &str =
    "the resolver answered none of this file's questions, which is how it reports a file no package it loaded holds";

/// Everything one file's passes left that its ledgers are built from.
#[derive(Clone, Copy)]
pub(crate) struct FilePass<'a> {
    pub(crate) file: &'a str,
    pub(crate) text: &'a str,
    /// The file's URI as the entity index knows it.
    pub(crate) uri: &'a str,
    pub(crate) index: &'a kin_lsp::EntityIndex,
    /// The entities the file declares.
    pub(crate) entities: &'a [&'a Entity],
    /// Every definite answer the passes gave at an identifier or a call range.
    pub(crate) answers: &'a [SiteAnswer],
    pub(crate) names: &'a ExternalNames,
    /// Every identifier the definitions pass asked about and could not prove.
    pub(crate) unproven: &'a [UnprovenSite],
    /// The call sites the graph's call edges of other origins record in the
    /// file, as byte range and first line (see [`call_expressions_with`]).
    pub(crate) recorded: &'a [(usize, usize, u32)],
    /// The language-server `References` relations this pass produced, which a
    /// retraction keeps.
    pub(crate) produced_references: &'a std::collections::HashSet<kin_model::RelationId>,
    pub(crate) ending: PassEnding,
    /// Whether no build of the repository compiles the file.
    pub(crate) not_in_build: bool,
    /// The proof context the server answered under.
    pub(crate) context: ResolutionRecordId,
    /// The body of the file the passes were asked about.
    pub(crate) body: Hash256,
}

/// How many sites of one file's ledgers came to each state, and what the
/// census could not attribute.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct LedgerCounts {
    /// Call expressions the parser read in the file.
    pub(crate) expressions: usize,
    /// Of those, the ones no entity with source text holds at their line, or
    /// whose key would fall before their caller's text.
    pub(crate) unattributed: usize,
    /// Sites by state, spelled as payloads spell it.
    pub(crate) by_state: BTreeMap<&'static str, usize>,
}

/// One file's ledgers, with what a proven site's edge carries it with.
#[derive(Debug, Clone, Default)]
pub(crate) struct FileLedgers {
    /// One ledger for each entity with source text in the file.
    pub(crate) ledgers: BTreeMap<EntityId, CallSiteLedger>,
    /// The external symbols a proven site names, which must be in the graph
    /// before an edge or a ledger names them.
    pub(crate) external: BTreeMap<ExternalReferenceId, ExternalReference>,
    /// For every proven site, by caller and key, the evidence record an edge
    /// carries it with: the answer's own span and rule.
    evidence: HashMap<(EntityId, u32, u32), RelationEvidence>,
    /// What this pass proved at every span it answered, by caller and byte
    /// range: the node the call reaches.
    answered: HashMap<(EntityId, usize, usize), GraphNodeId>,
    pub(crate) counts: LedgerCounts,
}

/// The order a site's evidence rule is preferred in: a definition answer,
/// then one through an alias, then a call range.
fn rule_rank(rule: &str) -> u8 {
    match rule {
        call_sites::DEFINITION_RULE => 0,
        call_sites::DEFINITION_ALIAS_RULE => 1,
        _ => 2,
    }
}

/// The state a question that proved nothing leaves its site in.
fn unproven_state(answer: UnprovenAnswer) -> CallSiteState {
    match answer {
        UnprovenAnswer::NoAnswer | UnprovenAnswer::Refused => CallSiteState::Unresolved {
            reason: UnresolvedReason::NoAnswer,
        },
        UnprovenAnswer::Binding => CallSiteState::Binding { may_call: None },
        UnprovenAnswer::OutsideTheGraph => CallSiteState::Unresolved {
            reason: UnresolvedReason::OutsideTheGraph,
        },
        UnprovenAnswer::AnswersDisagree => CallSiteState::Unresolved {
            reason: UnresolvedReason::AnswersDisagree,
        },
        UnprovenAnswer::Timeout => CallSiteState::ServerFailed {
            reason: ServerFailure::Timeout,
        },
        UnprovenAnswer::Crash => CallSiteState::ServerFailed {
            reason: ServerFailure::Crash,
        },
        UnprovenAnswer::ProtocolError => CallSiteState::ServerFailed {
            reason: ServerFailure::ProtocolError,
        },
    }
}

/// Whether one unproven answer outranks another at the same site: a failure
/// to answer outranks an answer, since the site was not settled.
fn outranks(new: UnprovenAnswer, held: UnprovenAnswer) -> bool {
    let failed = |answer| {
        matches!(
            answer,
            UnprovenAnswer::Timeout | UnprovenAnswer::Crash | UnprovenAnswer::ProtocolError
        )
    };
    failed(new) && !failed(held)
}

/// Build one ledger for every entity with source text in `pass.file`.
///
/// `None` when the parser cannot read the file again, which leaves every
/// caller in it owed.
pub(crate) fn build_ledgers(pass: &FilePass<'_>) -> Option<FileLedgers> {
    let expressions = call_expressions_with(pass.file, pass.text, pass.recorded)?;
    let proofs = site_proofs(pass.file, pass.answers, pass.names);
    let mut unproven: HashMap<(EntityId, usize, usize), UnprovenAnswer> = HashMap::new();
    for site in pass.unproven {
        let key = (site.source, site.start_byte, site.end_byte);
        match unproven.get(&key) {
            Some(held) if !outranks(site.answer, *held) => {}
            _ => {
                unproven.insert(key, site.answer);
            }
        }
    }
    // The answer each proven span's evidence is recorded from.
    let mut answer_at: HashMap<(EntityId, usize, usize), &SiteAnswer> = HashMap::new();
    for answer in pass.answers {
        if answer.site.file.0 != pass.file {
            continue;
        }
        let key = (answer.source, answer.site.start_byte, answer.site.end_byte);
        match answer_at.get(&key) {
            Some(held) if rule_rank(held.rule) <= rule_rank(answer.rule) => {}
            _ => {
                answer_at.insert(key, answer);
            }
        }
    }
    let starts: HashMap<EntityId, usize> = pass
        .entities
        .iter()
        .filter_map(|entity| Some((entity.id, entity.span.as_ref()?.start_byte)))
        .collect();

    let mut ledgers = FileLedgers::default();
    for (key, proof) in &proofs {
        let node = match proof {
            SiteProof::Entity(target) => GraphNodeId::Entity(*target),
            SiteProof::External(reference) => GraphNodeId::ExternalReference(reference.id),
            SiteProof::Outside | SiteProof::Disagree => continue,
        };
        ledgers.answered.insert(*key, node);
    }
    ledgers.counts.expressions = expressions.len();
    let mut sites: BTreeMap<EntityId, BTreeMap<(u32, u32), CallSiteState>> = BTreeMap::new();
    for expression in &expressions {
        let caller = pass
            .index
            .find_at(pass.uri, expression.line)
            .map(|found| found.id)
            .filter(|id| starts.contains_key(id));
        let Some(caller) = caller else {
            ledgers.counts.unattributed += 1;
            continue;
        };
        let (start, end) = expression
            .callee
            .as_ref()
            .map_or((expression.start_byte, expression.end_byte), |token| {
                (token.start_byte, token.end_byte)
            });
        let Some((offset, length)) = site_key(starts[&caller], start, end) else {
            ledgers.counts.unattributed += 1;
            continue;
        };
        let lookup = (caller, start, end);
        let state = if pass.not_in_build {
            CallSiteState::NotInBuild {
                reason: NOT_IN_BUILD_REASON.to_string(),
            }
        } else if expression.callee.is_none() {
            CallSiteState::Unresolved {
                reason: UnresolvedReason::CalleeNotPlaceable,
            }
        } else if let Some(proof) = proofs.get(&lookup) {
            let state = match proof {
                SiteProof::Entity(target) => CallSiteState::ProvenTarget { target: *target },
                SiteProof::External(reference) => {
                    ledgers.external.insert(reference.id, reference.clone());
                    CallSiteState::ProvenExternal {
                        target: reference.id,
                    }
                }
                SiteProof::Outside => CallSiteState::ProvenOutside,
                SiteProof::Disagree => CallSiteState::Unresolved {
                    reason: UnresolvedReason::AnswersDisagree,
                },
            };
            if state.proven_node().is_some() {
                if let Some(answer) = answer_at.get(&lookup) {
                    ledgers.evidence.insert(
                        (caller, offset, length),
                        RelationEvidence {
                            token: Some(pass.context.context_token()),
                            ..call_sites::site_evidence(answer.rule, answer.site.clone())
                        },
                    );
                }
            }
            state
        } else if let Some(answer) = unproven.get(&lookup) {
            unproven_state(*answer)
        } else {
            match pass.ending {
                PassEnding::Complete => CallSiteState::Unresolved {
                    reason: UnresolvedReason::CalleeNotPlaceable,
                },
                PassEnding::Stopped(failure) => CallSiteState::ServerFailed { reason: failure },
                PassEnding::Declined => CallSiteState::Unresolved {
                    reason: UnresolvedReason::NoAnswer,
                },
                PassEnding::NothingAnswered => CallSiteState::NotInBuild {
                    reason: NOTHING_ANSWERED_REASON.to_string(),
                },
            }
        };
        sites
            .entry(caller)
            .or_default()
            .entry((offset, length))
            .or_insert(state);
    }
    for entity in pass.entities {
        if entity.span.is_none() {
            continue;
        }
        let held = sites.remove(&entity.id).unwrap_or_default();
        let sites: Vec<CallSite> = held
            .into_iter()
            .map(|((offset, length), state)| {
                *ledgers.counts.by_state.entry(state.wire()).or_insert(0) += 1;
                CallSite {
                    offset,
                    length,
                    state,
                }
            })
            .collect();
        ledgers.ledgers.insert(
            entity.id,
            CallSiteLedger {
                caller: entity.id,
                behavior_hash: entity.fingerprint.behavior_hash,
                body_hash: pass.body,
                context: pass.context,
                census: sites.len() as u32,
                sites,
            },
        );
    }
    Some(ledgers)
}

/// What making one file's `Calls` proofs agree with its ledgers changes.
#[derive(Debug, Clone, Default, PartialEq)]
pub(crate) struct ProofRewrite {
    /// Edges written as they now stand: stamped with the ledger's context,
    /// completed with a site no edge carried, or narrowed by a retraction.
    pub(crate) written: Vec<Relation>,
    /// Edges left with no site, retired.
    pub(crate) retired: Vec<Relation>,
    /// Evidence records a retraction removed.
    pub(crate) retracted_records: usize,
    /// Proven sites no edge carried, now carried.
    pub(crate) completed_sites: usize,
}

/// Make the language-server `Calls` edges from the file's callers agree with
/// their ledgers.
///
/// `held` are the edges the graph holds from the file's callers, of every
/// origin; only language-server `Calls` edges are touched. With `retract`,
/// the file's passes all finished and a proof the ledger does not hold
/// leaves: evidence at a census site the ledger settled otherwise, or at a
/// span this pass did not prove, under any other context or none. Without
/// it, nothing is removed.
pub(crate) fn rewrite_proofs(
    ledgers: &FileLedgers,
    pass: &FilePass<'_>,
    held: &[Relation],
    retract: bool,
) -> ProofRewrite {
    let token = pass.context.context_token();
    let starts: HashMap<EntityId, usize> = pass
        .entities
        .iter()
        .filter_map(|entity| Some((entity.id, entity.span.as_ref()?.start_byte)))
        .collect();
    let mut rewrite = ProofRewrite::default();
    // Every edge as it stands after the rewrite, by caller and destination.
    let mut edges: HashMap<(EntityId, GraphNodeId), Relation> = HashMap::new();
    let mut original: HashMap<kin_model::RelationId, &Relation> = HashMap::new();
    let mut carried: HashSet<(EntityId, GraphNodeId, u32, u32)> = HashSet::new();
    for edge in held {
        if edge.kind != RelationKind::Calls || edge.origin != RelationOrigin::Lsp {
            continue;
        }
        let GraphNodeId::Entity(caller) = edge.src else {
            continue;
        };
        let (Some(ledger), Some(start)) = (ledgers.ledgers.get(&caller), starts.get(&caller))
        else {
            continue;
        };
        original.insert(edge.id, edge);
        let mut kept = Vec::with_capacity(edge.evidence.len());
        for record in &edge.evidence {
            let Some(span) = record
                .source_span
                .as_ref()
                .filter(|span| span.file.0 == pass.file)
            else {
                kept.push(record.clone());
                continue;
            };
            let key = site_key(*start, span.start_byte, span.end_byte);
            let site = key.and_then(|(offset, length)| ledger.site(offset, length));
            let proves_here = match site {
                Some(site) => site.state.proven_node() == Some(edge.dst),
                None => {
                    ledgers
                        .answered
                        .get(&(caller, span.start_byte, span.end_byte))
                        == Some(&edge.dst)
                }
            };
            if proves_here {
                let mut stamped = record.clone();
                stamped.token = Some(token.clone());
                if let (Some((offset, length)), Some(_)) = (key, site) {
                    carried.insert((caller, edge.dst, offset, length));
                }
                kept.push(stamped);
            } else if retract {
                rewrite.retracted_records += 1;
            } else {
                kept.push(record.clone());
            }
        }
        let mut edge = edge.clone();
        edge.evidence = kept;
        edges.insert((caller, edge.dst), edge);
    }
    // A proven site no edge carries yet gets its answer's record, on the edge
    // to its target.
    for (caller, ledger) in &ledgers.ledgers {
        for site in &ledger.sites {
            let Some(target) = site.state.proven_node() else {
                continue;
            };
            if target == GraphNodeId::Entity(*caller)
                || carried.contains(&(*caller, target, site.offset, site.length))
            {
                continue;
            }
            let Some(record) = ledgers
                .evidence
                .get(&(*caller, site.offset, site.length))
                .cloned()
            else {
                continue;
            };
            rewrite.completed_sites += 1;
            carried.insert((*caller, target, site.offset, site.length));
            match edges.get_mut(&(*caller, target)) {
                Some(edge) => edge.evidence.push(record),
                None => {
                    let edge = match target {
                        GraphNodeId::Entity(entity) => {
                            call_sites::proven_call(*caller, entity, vec![record])
                        }
                        GraphNodeId::ExternalReference(reference) => {
                            call_sites::proven_external_call(*caller, reference, vec![record])
                        }
                        _ => continue,
                    };
                    edges.insert((*caller, target), edge);
                }
            }
        }
    }
    let mut edges: Vec<Relation> = edges.into_values().collect();
    edges.sort_by_key(|edge| edge.id);
    for edge in edges {
        let mut edge = edge;
        if original.get(&edge.id).is_some_and(|held| **held == edge) {
            continue;
        }
        // A changed edge takes the order the site union keeps evidence in, so
        // the next union of the same sites merges back to it and writes
        // nothing: a record with no span first, then by file, line, column
        // and rule.
        edge.evidence.sort_by_key(union_order);
        edge.evidence.dedup();
        match original.get(&edge.id) {
            Some(held) if **held == edge => {}
            _ if !edge
                .evidence
                .iter()
                .any(|record| record.source_span.is_some()) =>
            {
                if let Some(held) = original.get(&edge.id) {
                    rewrite.retired.push((*held).clone());
                }
            }
            _ => rewrite.written.push(edge),
        }
    }
    rewrite
}

/// The rules a file's definitions pass records a `References` edge under,
/// at an identifier in the file it asked about.
const DEFINITION_PASS_RULES: [&str; 3] = [
    call_sites::DEFINITION_RULE,
    call_sites::DEFINITION_ALIAS_RULE,
    "lsp_member_on_module",
];

/// The `References` proofs a file proven again no longer holds.
///
/// A file's definitions pass records a `References` edge from a caller in the
/// file at each identifier whose answer names a declaration. When the file is
/// proven again and this pass did not produce an edge it held, the records
/// that pass left on it (in the file, under a definitions-pass rule) no longer
/// hold: the identifier's answer names another declaration now. Those records
/// leave the edge. What another file's references query recorded on the same
/// edge is that file's to settle and stays, so the edge is narrowed to it, or
/// retired when nothing is left. Only a file whose passes all finished
/// retracts, so without `retract` both lists are empty.
///
/// Returns the edges to retire and the edges narrowed.
pub(crate) fn stale_references(
    pass: &FilePass<'_>,
    held: &[Relation],
    retract: bool,
) -> (Vec<Relation>, Vec<Relation>) {
    let mut retired = Vec::new();
    let mut narrowed = Vec::new();
    if !retract {
        return (retired, narrowed);
    }
    let callers: HashSet<EntityId> = pass
        .entities
        .iter()
        .filter(|entity| entity.span.is_some())
        .map(|entity| entity.id)
        .collect();
    let from_this_pass = |record: &RelationEvidence| {
        record
            .source_span
            .as_ref()
            .is_some_and(|span| span.file.0 == pass.file)
            && record
                .parser_rule
                .as_deref()
                .is_some_and(|rule| DEFINITION_PASS_RULES.contains(&rule))
    };
    for edge in held {
        if edge.kind != RelationKind::References
            || edge.origin != RelationOrigin::Lsp
            || !matches!(edge.src, GraphNodeId::Entity(caller) if callers.contains(&caller))
            || pass.produced_references.contains(&edge.id)
            || !edge.evidence.iter().any(from_this_pass)
        {
            continue;
        }
        let kept: Vec<RelationEvidence> = edge
            .evidence
            .iter()
            .filter(|record| !from_this_pass(record))
            .cloned()
            .collect();
        if kept.iter().any(|record| record.source_span.is_some()) {
            let mut edge = edge.clone();
            edge.evidence = kept;
            narrowed.push(edge);
        } else {
            retired.push(edge.clone());
        }
    }
    (retired, narrowed)
}

/// The key the daemon's site union orders an edge's evidence by.
fn union_order(record: &RelationEvidence) -> (String, u32, u32, u32, u32, String) {
    let span = record.source_span.as_ref();
    (
        span.map(|span| span.file.0.clone()).unwrap_or_default(),
        span.map_or(0, |span| span.start_line),
        span.map_or(0, |span| span.start_col),
        span.map_or(0, |span| span.end_line),
        span.map_or(0, |span| span.end_col),
        record.parser_rule.clone().unwrap_or_default(),
    )
}

/// Check every ledger against the edges its caller holds once `rewrite` is
/// applied to `held`, and keep only the ledgers that hold.
///
/// A ledger that does not hold proves a site no edge carries under its
/// context, which only a write the graph refused leaves behind. It is not
/// recorded, so its caller stays owed and the next sweep proves it again.
pub(crate) fn backed_ledgers(
    ledgers: &FileLedgers,
    pass: &FilePass<'_>,
    held: &[Relation],
    rewrite: &ProofRewrite,
) -> (Vec<CallSiteLedger>, Vec<(EntityId, String)>) {
    let mut after: BTreeMap<kin_model::RelationId, &Relation> =
        held.iter().map(|edge| (edge.id, edge)).collect();
    for edge in &rewrite.retired {
        after.remove(&edge.id);
    }
    for edge in &rewrite.written {
        after.insert(edge.id, edge);
    }
    let mut by_caller: HashMap<EntityId, Vec<&Relation>> = HashMap::new();
    for edge in after.values() {
        if let GraphNodeId::Entity(caller) = edge.src {
            by_caller.entry(caller).or_default().push(edge);
        }
    }
    let starts: HashMap<EntityId, usize> = pass
        .entities
        .iter()
        .filter_map(|entity| Some((entity.id, entity.span.as_ref()?.start_byte)))
        .collect();
    let mut backed = Vec::with_capacity(ledgers.ledgers.len());
    let mut refused = Vec::new();
    for (caller, ledger) in &ledgers.ledgers {
        let edges = by_caller.get(caller).map(Vec::as_slice).unwrap_or(&[]);
        let start = starts.get(caller).copied().unwrap_or(0);
        match kin_model::ResolutionRecord::CallSites(ledger.clone())
            .validate()
            .and_then(|()| ledger.validate_backing(start, pass.file, edges.iter().copied()))
        {
            Ok(()) => backed.push(ledger.clone()),
            Err(error) => refused.push((*caller, error.to_string())),
        }
    }
    (backed, refused)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_lsp::call_sites::{SiteTarget, CALL_HIERARCHY_RULE, DEFINITION_RULE};
    use kin_model::{
        EntityKind, EntityMetadata, EntityRole, FilePathId, FingerprintAlgorithm,
        SemanticFingerprint, Visibility,
    };

    const FILE: &str = "app/run.py";
    /// `run` makes four calls: `send` through a receiver, `helper`, a call
    /// through a subscript with no callee token, and `cb`, a parameter.
    const TEXT: &str = "def run(self, cb):\n    self.adapter.send(x)\n    helper(y)\n    handlers[k](z)\n    cb()\n\ndef helper(y):\n    return y\n";

    fn entity(name: &str, text_of: &str, kind: EntityKind) -> Entity {
        let start = TEXT.find(text_of).expect("the declaration is in the text");
        let end = TEXT[start..]
            .find("\n\n")
            .map_or(TEXT.len(), |offset| start + offset);
        let start_line = TEXT[..start].matches('\n').count() as u32;
        let end_line = TEXT[..end].matches('\n').count() as u32;
        Entity {
            id: EntityId::new(),
            kind,
            name: name.to_string(),
            language: kin_model::LanguageId::Python,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([1; 32]),
                signature_hash: Hash256::from_bytes([2; 32]),
                behavior_hash: Hash256::from_bytes([3; 32]),
                equivalence_hash: Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new(FILE)),
            span: Some(SourceSpan {
                file: FilePathId::new(FILE),
                start_byte: start,
                end_byte: end,
                start_line,
                start_col: 0,
                end_line,
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

    fn token(name: &str, nth: usize) -> SourceSpan {
        let start = TEXT
            .match_indices(&format!("{name}("))
            .nth(nth)
            .map(|(at, _)| at)
            .expect("the call is in the text");
        let line = TEXT[..start].matches('\n').count() as u32;
        SourceSpan {
            file: FilePathId::new(FILE),
            start_byte: start,
            end_byte: start + name.len(),
            start_line: line,
            start_col: 0,
            end_line: line,
            end_col: 0,
        }
    }

    struct World {
        run: Entity,
        helper: Entity,
        send: Entity,
        index: kin_lsp::EntityIndex,
        root: std::path::PathBuf,
        context: ResolutionRecordId,
    }

    fn world() -> World {
        let run = entity("run", "def run", EntityKind::Function);
        let helper = entity("helper", "def helper", EntityKind::Function);
        let mut send = entity("Adapter.send", "def helper", EntityKind::Method);
        send.file_origin = Some(FilePathId::new("app/adapter.py"));
        if let Some(span) = send.span.as_mut() {
            span.file = FilePathId::new("app/adapter.py");
        }
        let root = std::path::PathBuf::from("/work/repo");
        let refs: Vec<kin_lsp::EntityRef> = [&run, &helper]
            .into_iter()
            .map(|entity| crate::daemon::lsp_entity_ref(entity, FILE).expect("a spanned entity"))
            .collect();
        World {
            index: kin_lsp::EntityIndex::new(refs, &root),
            run,
            helper,
            send,
            root,
            context: ResolutionRecordId(uuid::Uuid::from_u128(77)),
        }
    }

    fn uri(world: &World) -> String {
        kin_lsp::protocol::path_to_uri(&world.root.join(FILE))
    }

    fn pass<'a>(
        world: &'a World,
        uri: &'a str,
        entities: &'a [&'a Entity],
        answers: &'a [SiteAnswer],
        unproven: &'a [UnprovenSite],
        ending: PassEnding,
    ) -> FilePass<'a> {
        static NAMES: std::sync::OnceLock<ExternalNames> = std::sync::OnceLock::new();
        static NO_REFERENCES: std::sync::OnceLock<HashSet<kin_model::RelationId>> =
            std::sync::OnceLock::new();
        FilePass {
            file: FILE,
            text: TEXT,
            uri,
            index: &world.index,
            entities,
            answers,
            names: NAMES.get_or_init(ExternalNames::new),
            unproven,
            recorded: &[],
            produced_references: NO_REFERENCES.get_or_init(Default::default),
            ending,
            not_in_build: false,
            context: world.context,
            body: Hash256::from_bytes([9; 32]),
        }
    }

    fn states(ledger: &CallSiteLedger) -> Vec<(String, &'static str)> {
        ledger
            .sites
            .iter()
            .map(|site| {
                let start = site.offset as usize;
                let at = TEXT.find("def run").unwrap() + start;
                (
                    TEXT[at..at + site.length as usize].to_string(),
                    site.state.wire(),
                )
            })
            .collect()
    }

    #[test]
    fn the_census_reads_every_call_expression_the_parser_reads_once() {
        let text =
            "def run(self):\n    self.adapter.send(x)\n    helper(send(y))\n    handlers[k](z)\n";
        let calls = call_expressions("app/run.py", text).expect("python parses");
        let named: Vec<(Option<String>, u32)> = calls
            .iter()
            .map(|call| {
                (
                    call.callee.as_ref().map(|token| token.name.clone()),
                    call.line,
                )
            })
            .collect();
        assert!(
            named.contains(&(Some("send".to_string()), 1)),
            "the member call is read with its callee: {named:?}"
        );
        assert!(
            named.contains(&(Some("helper".to_string()), 2)),
            "{named:?}"
        );
        assert!(
            named.contains(&(Some("send".to_string()), 2)),
            "a call inside another call's arguments is its own expression: {named:?}"
        );
        let mut keys: Vec<(usize, usize)> = calls
            .iter()
            .map(|call| (call.start_byte, call.end_byte))
            .collect();
        let before = keys.len();
        keys.dedup();
        assert_eq!(keys.len(), before, "each expression is read once");
        for call in &calls {
            if let Some(token) = &call.callee {
                assert_eq!(&text[token.start_byte..token.end_byte], token.name);
                assert!(call.start_byte <= token.start_byte && token.end_byte <= call.end_byte);
            }
        }

        let text = "export function main(): void {\n  const r = build(1);\n  r.run();\n  new Thing();\n}\n";
        let calls = call_expressions("src/main.ts", text).expect("typescript parses");
        let names: Vec<String> = calls
            .iter()
            .filter_map(|call| call.callee.as_ref().map(|token| token.name.clone()))
            .collect();
        assert!(names.contains(&"build".to_string()), "{names:?}");
        assert!(names.contains(&"run".to_string()), "{names:?}");

        let text = "fn main() {\n    let v = compute(2);\n    v.apply();\n}\n";
        let calls = call_expressions("src/main.rs", text).expect("rust parses");
        assert!(
            calls.iter().any(|call| call
                .callee
                .as_ref()
                .is_some_and(|token| token.name == "compute")),
            "{calls:?}"
        );

        assert_eq!(call_expressions("README", "text"), None, "no adapter");
    }

    #[test]
    fn the_reading_names_the_parsers_call_site_count_by_its_own_key() {
        assert_eq!(
            kin_model::call_site_reading::FILE_PARSED_CALL_SITES_KEY,
            kin_parser::FILE_PARSED_CALL_SITES_KEY
        );
    }

    #[test]
    fn a_reference_only_an_earlier_definitions_pass_produced_is_stale() {
        let world = world();
        let uri = uri(&world);
        let entities = [&world.run, &world.helper];
        let other = entity("Other.send", "def helper", EntityKind::Method);
        let reference = |target: &Entity, rule: &str, file: &str| {
            let mut span = token("send", 0);
            span.file = FilePathId::new(file);
            let mut edge = lsp_edge(&world.run, target, &[(span, rule, None)]);
            edge.kind = RelationKind::References;
            edge.id =
                kin_model::RelationId::resolver(RelationKind::References, &edge.src, &edge.dst);
            edge
        };
        let old = reference(&other, DEFINITION_RULE, FILE);
        let current = reference(&world.send, DEFINITION_RULE, FILE);
        let queried = reference(&other, kin_model::LSP_REFERENCES_RULE, FILE);
        let produced = HashSet::from([current.id]);
        let mut complete = pass(&world, &uri, &entities, &[], &[], PassEnding::Complete);
        complete.produced_references = &produced;
        let mut mixed = reference(&other, DEFINITION_RULE, FILE);
        mixed.src = GraphNodeId::Entity(world.helper.id);
        mixed.id =
            kin_model::RelationId::resolver(RelationKind::References, &mixed.src, &mixed.dst);
        mixed.evidence.push(queried.evidence[0].clone());
        let held = [old.clone(), current, queried, mixed.clone()];
        let (retired, narrowed) = stale_references(&complete, &held, true);
        assert_eq!(
            retired,
            [old],
            "the definitions pass's own edge that this pass did not produce is retired"
        );
        assert_eq!(
            narrowed.len(),
            1,
            "an edge another pass also recorded is narrowed"
        );
        assert_eq!(narrowed[0].id, mixed.id);
        assert_eq!(
            narrowed[0].evidence,
            [mixed.evidence[1].clone()],
            "to what the other pass recorded"
        );
        let (retired, narrowed) = stale_references(&complete, &held, false);
        assert!(retired.is_empty() && narrowed.is_empty());
    }

    #[test]
    fn a_call_site_the_graph_records_is_counted_whatever_recorded_it() {
        // `name()` inside a macro's token tree is no call the parser's
        // relations carry, and the linker records one there.
        let text = "fn build() {\n    quote! { async fn #name() {} };\n}\n";
        let at = text.find("name()").unwrap();
        let plain = call_expressions("src/lib.rs", text).unwrap();
        assert!(plain.iter().all(|call| call.start_byte != at), "{plain:?}");
        let with = call_expressions_with("src/lib.rs", text, &[(at, at + 6, 1)]).unwrap();
        let call = with
            .iter()
            .find(|call| call.start_byte == at)
            .expect("the recorded site is counted");
        assert_eq!(
            call.callee.as_ref().map(|token| token.name.as_str()),
            Some("name")
        );
        assert_eq!(call.line, 1);
        let again =
            call_expressions_with("src/lib.rs", text, &[(at, at + 6, 1), (at, at + 6, 1)]).unwrap();
        assert_eq!(again.len(), with.len(), "a site recorded twice is one site");
    }

    #[test]
    fn every_call_expression_in_a_caller_has_exactly_one_state() {
        let world = world();
        let uri = uri(&world);
        let entities = [&world.run, &world.helper];
        let answers = [SiteAnswer {
            source: world.run.id,
            site: token("send", 0),
            target: SiteTarget::Entity(world.send.id),
            rule: DEFINITION_RULE,
        }];
        let cb = token("cb", 0);
        let unproven = [
            UnprovenSite {
                source: world.run.id,
                start_byte: cb.start_byte,
                end_byte: cb.end_byte,
                answer: UnprovenAnswer::Binding,
            },
            UnprovenSite {
                source: world.run.id,
                start_byte: token("helper", 0).start_byte,
                end_byte: token("helper", 0).end_byte,
                answer: UnprovenAnswer::Timeout,
            },
        ];
        let pass = pass(
            &world,
            &uri,
            &entities,
            &answers,
            &unproven,
            PassEnding::Complete,
        );
        let ledgers = build_ledgers(&pass).expect("the file parses");
        let run = &ledgers.ledgers[&world.run.id];
        assert_eq!(run.census as usize, run.sites.len());
        assert_eq!(
            states(run),
            [
                ("send".to_string(), "proven_target"),
                ("helper".to_string(), "server_failed"),
                ("handlers[k](z)".to_string(), "unresolved"),
                ("cb".to_string(), "binding"),
            ]
        );
        let helper = &ledgers.ledgers[&world.helper.id];
        assert_eq!(helper.census, 0, "a caller with no call has a ledger too");
        assert_eq!(ledgers.counts.expressions, 4);
        assert_eq!(ledgers.counts.unattributed, 0);
        kin_model::ResolutionRecord::CallSites(run.clone())
            .validate()
            .expect("keys sorted and unique, census equals sites");

        // The pass that stopped early leaves the sites it never asked at
        // server-failed, and a file no build compiles is not in build.
        let stopped = self::pass(
            &world,
            &uri,
            &entities,
            &[],
            &[],
            PassEnding::Stopped(ServerFailure::Timeout),
        );
        let ledgers = build_ledgers(&stopped).unwrap();
        assert_eq!(
            states(&ledgers.ledgers[&world.run.id])
                .iter()
                .map(|(_, state)| *state)
                .collect::<Vec<_>>(),
            [
                "server_failed",
                "server_failed",
                "unresolved",
                "server_failed"
            ]
        );
        let mut outside_build = self::pass(&world, &uri, &entities, &[], &[], PassEnding::Complete);
        outside_build.not_in_build = true;
        let ledgers = build_ledgers(&outside_build).unwrap();
        assert!(ledgers.ledgers[&world.run.id]
            .sites
            .iter()
            .all(|site| site.state.wire() == "not_in_build"));
    }

    fn lsp_edge(
        caller: &Entity,
        target: &Entity,
        sites: &[(SourceSpan, &str, Option<String>)],
    ) -> Relation {
        call_sites::proven_call(
            caller.id,
            target.id,
            sites
                .iter()
                .map(|(span, rule, token)| RelationEvidence {
                    token: token.clone(),
                    ..call_sites::site_evidence(rule, span.clone())
                })
                .collect(),
        )
    }

    #[test]
    fn a_file_proven_again_keeps_only_the_proofs_its_ledgers_hold() {
        let world = world();
        let uri = uri(&world);
        let entities = [&world.run, &world.helper];
        let other = entity("Other.send", "def helper", EntityKind::Method);
        // This pass proves `send` goes to `Adapter.send`, and says `helper`
        // got no answer.
        let answers = [SiteAnswer {
            source: world.run.id,
            site: token("send", 0),
            target: SiteTarget::Entity(world.send.id),
            rule: DEFINITION_RULE,
        }];
        let helper_token = token("helper", 0);
        let unproven = [UnprovenSite {
            source: world.run.id,
            start_byte: helper_token.start_byte,
            end_byte: helper_token.end_byte,
            answer: UnprovenAnswer::NoAnswer,
        }];
        // The graph holds an older proof of `send` into `Other.send` under
        // another context, a legacy proof of `helper` with no context, and a
        // call-hierarchy record of `send` into `Adapter.send` with no context.
        let stale = lsp_edge(
            &world.run,
            &other,
            &[(
                token("send", 0),
                DEFINITION_RULE,
                Some(format!("ctx:{}", uuid::Uuid::from_u128(5))),
            )],
        );
        let legacy = lsp_edge(
            &world.run,
            &world.helper,
            &[(helper_token.clone(), CALL_HIERARCHY_RULE, None)],
        );
        let current = lsp_edge(
            &world.run,
            &world.send,
            &[(token("send", 0), CALL_HIERARCHY_RULE, None)],
        );
        let held = [stale.clone(), legacy.clone(), current.clone()];

        let complete = pass(
            &world,
            &uri,
            &entities,
            &answers,
            &unproven,
            PassEnding::Complete,
        );
        let ledgers = build_ledgers(&complete).unwrap();
        let rewrite = rewrite_proofs(&ledgers, &complete, &held, true);
        let retired: Vec<_> = rewrite.retired.iter().map(|edge| edge.id).collect();
        assert!(
            retired.contains(&stale.id),
            "the other context's proof is retracted"
        );
        assert!(
            retired.contains(&legacy.id),
            "so is the legacy proof the pass settled otherwise"
        );
        let written = rewrite
            .written
            .iter()
            .find(|edge| edge.id == current.id)
            .expect("the current proof is stamped");
        assert!(written
            .evidence
            .iter()
            .all(|record| record.token == Some(world.context.context_token())));
        let (backed, refused) = backed_ledgers(&ledgers, &complete, &held, &rewrite);
        assert!(refused.is_empty(), "{refused:?}");
        assert_eq!(backed.len(), 2);

        // A file whose passes failed is never retracted: the proofs are only
        // stamped and completed.
        let failed = pass(
            &world,
            &uri,
            &entities,
            &answers,
            &unproven,
            PassEnding::Stopped(ServerFailure::Timeout),
        );
        let ledgers = build_ledgers(&failed).unwrap();
        let rewrite = rewrite_proofs(&ledgers, &failed, &held, false);
        assert!(rewrite.retired.is_empty());
        assert_eq!(rewrite.retracted_records, 0);

        // A proven site no edge carries is completed on a new edge.
        let rewrite = rewrite_proofs(&ledgers, &failed, &[], false);
        assert_eq!(rewrite.completed_sites, 1);
        let minted = &rewrite.written[0];
        assert_eq!(minted.dst, GraphNodeId::Entity(world.send.id));
        assert_eq!(
            minted.evidence[0].token,
            Some(world.context.context_token())
        );
        let (backed, refused) = backed_ledgers(&ledgers, &failed, &[], &rewrite);
        assert!(refused.is_empty(), "{refused:?}");
        assert_eq!(backed.len(), 2);
        // Without the completion the proof is unbacked and its ledger is
        // not recorded.
        let (backed, refused) = backed_ledgers(&ledgers, &failed, &[], &ProofRewrite::default());
        assert_eq!(backed.len(), 1);
        assert_eq!(refused[0].0, world.run.id);
    }
}
