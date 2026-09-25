// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Per-occurrence parser authority, without changing persisted relation identity or layout.
//! Scalar confidence proves that some occurrence reaches the target, not every site.

use crate::resolution::{RelationResolution, RECEIVER_NAME_FANOUT_CONFIDENCE};
use kin_model::{
    GraphNodeId, Relation, RelationEvidence, RelationId, RelationKind, RelationOrigin, SourceSpan,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const OCCURRENCE_RULE: &str = "parser_occurrence_resolution_v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Proof {
    relation_id: RelationId,
    src: GraphNodeId,
    dst: GraphNodeId,
    kind: RelationKind,
    evidence_sha256: String,
    confidence: f32,
    origin: RelationOrigin,
}

pub(crate) fn reserved(record: &RelationEvidence) -> bool {
    record
        .parser_rule
        .as_deref()
        .is_some_and(|rule| rule.starts_with("parser_occurrence_resolution_"))
}

fn evidence_digest(record: &RelationEvidence) -> String {
    let mut record = record.clone();
    // Multiplicity is merged separately. Normalize exactly as the linker does.
    record.occurrence_count = 1;
    if let Some(shape) = &mut record.call_shape {
        shape.keywords.sort();
        shape.keywords.dedup();
    }
    hex::encode(Sha256::digest(
        serde_json::to_vec(&record).expect("evidence serializes"),
    ))
}

/// Called only by the fresh single-occurrence parser relation factory, never by
/// the accumulator: an accumulator also accepts already merged per-file edges.
pub(crate) fn stamp_fresh(relation: &mut Relation) {
    if relation.kind != RelationKind::Calls
        || !matches!(
            relation.origin,
            RelationOrigin::Parsed | RelationOrigin::Inferred
        )
    {
        return;
    }
    let mut seen = BTreeSet::new();
    let proofs: Vec<_> = relation
        .evidence
        .iter()
        .filter(|record| record.source_span.is_some() && !reserved(record))
        .filter_map(|record| {
            let digest = evidence_digest(record);
            if !seen.insert(digest.clone()) {
                return None;
            }
            Some(RelationEvidence {
                parser_rule: Some(OCCURRENCE_RULE.into()),
                token: Some(
                    serde_json::to_string(&Proof {
                        relation_id: relation.id,
                        src: relation.src,
                        dst: relation.dst,
                        kind: relation.kind,
                        evidence_sha256: digest,
                        confidence: relation.confidence,
                        origin: relation.origin,
                    })
                    .expect("proof serializes"),
                ),
                occurrence_count: 0,
                ..RelationEvidence::default()
            })
        })
        .collect();
    relation.evidence.extend(proofs);
    crate::linker::canonicalize_call_evidence(&mut relation.evidence);
}

/// The self-dispatch factory amends its own fresh occurrence token. It must
/// refresh that evidence binding before the occurrence enters an accumulator.
pub(crate) fn remove_fresh_proofs(relation: &mut Relation) {
    relation.evidence.retain(|record| !reserved(record));
}

/// Whether `record` is a parser occurrence certificate: span-free metadata that
/// qualifies one original site, never a site or a producer marker itself.
/// Code that merges or bounds a relation's evidence uses this to keep
/// certificates out of its site handling.
pub fn is_certificate(record: &RelationEvidence) -> bool {
    reserved(record)
}

/// Remove the certificates of the sites a consumer just trimmed from
/// `relation`, and nothing else.
///
/// A consumer that bounds how many sites an edge keeps drops sites whose
/// certificates stay behind, and one certificate naming a site the relation no
/// longer carries fails validation for the whole relation, so every site it
/// kept would read as unproven. `trimmed` is the evidence that consumer removed.
///
/// A certificate goes only when it passes the validation every reader applies,
/// checked against its own trimmed site, and no other certificate for that site
/// disagrees with it. Everything else stays: a malformed certificate, one of an
/// unknown version, one bound to a site the relation never carried, or a
/// contested pair keeps failing validation exactly as before, so a proof set
/// that was invalid cannot turn into certified sites. With nothing trimmed the
/// relation is untouched. Records are only removed, never added, rewritten or
/// reordered.
pub fn remove_proofs_of_trimmed_sites(relation: &mut Relation, trimmed: &[RelationEvidence]) {
    let trimmed: Vec<_> = trimmed
        .iter()
        .filter(|record| record.source_span.is_some() && !reserved(record))
        .collect();
    if trimmed.is_empty() || !relation.evidence.iter().any(reserved) {
        return;
    }
    let kept: BTreeSet<_> = relation
        .evidence
        .iter()
        .filter(|record| record.source_span.is_some() && !reserved(record))
        .map(evidence_digest)
        .collect();
    // A trimmed record that a kept record still matches took nothing away.
    let trimmed: BTreeMap<_, _> = trimmed
        .into_iter()
        .map(|record| (evidence_digest(record), record))
        .filter(|(digest, _)| !kept.contains(digest))
        .collect();
    if trimmed.is_empty() {
        return;
    }
    let proof_of = |record: &RelationEvidence| -> Option<Proof> {
        if !reserved(record) {
            return None;
        }
        serde_json::from_str(record.token.as_deref()?).ok()
    };
    // Two different proofs for one site already fail validation, and removing
    // both would hide that, so a contested site keeps its certificates.
    let mut first: BTreeMap<String, Proof> = BTreeMap::new();
    let mut contested = BTreeSet::new();
    for proof in relation.evidence.iter().filter_map(proof_of) {
        match first.get(&proof.evidence_sha256) {
            Some(previous) if *previous != proof => {
                contested.insert(proof.evidence_sha256.clone());
            }
            Some(_) => {}
            None => {
                first.insert(proof.evidence_sha256.clone(), proof);
            }
        }
    }
    let mut probe = relation.clone();
    relation.evidence.retain(|record| {
        let Some(proof) = proof_of(record) else {
            return true;
        };
        let Some(site) = trimmed.get(&proof.evidence_sha256) else {
            return true;
        };
        if contested.contains(&proof.evidence_sha256) {
            return true;
        }
        // Valid by the same test every reader applies, alone with its site.
        probe.evidence = vec![RelationEvidence::clone(site), record.clone()];
        validated_proofs(&probe).is_err()
    });
}

fn validated_proofs(relation: &Relation) -> Result<BTreeMap<String, Proof>, ()> {
    let originals: BTreeSet<_> = relation
        .evidence
        .iter()
        .filter(|record| record.source_span.is_some() && !reserved(record))
        .map(evidence_digest)
        .collect();
    let mut proofs = BTreeMap::new();
    for record in relation.evidence.iter().filter(|record| reserved(record)) {
        if record.parser_rule.as_deref() != Some(OCCURRENCE_RULE)
            || record.source_span.is_some()
            || record.source_path.is_some()
            || record.resolved_path.is_some()
            || record.call_shape.is_some()
            || record.occurrence_count != 0
        {
            return Err(());
        }
        let proof: Proof =
            serde_json::from_str(record.token.as_deref().ok_or(())?).map_err(|_| ())?;
        if relation.kind != RelationKind::Calls
            || !matches!(
                relation.origin,
                RelationOrigin::Parsed | RelationOrigin::Inferred
            )
            || proof.relation_id != relation.id
            || proof.src != relation.src
            || proof.dst != relation.dst
            || proof.kind != relation.kind
            || !proof.confidence.is_finite()
            || !(0.0..=1.0).contains(&proof.confidence)
            || !crate::resolution::RESOLUTION_TIER_LADDER
                .iter()
                .any(|(tier, _)| tier.to_bits() == proof.confidence.to_bits())
            || proof.origin
                != if proof.confidence >= 1.0 {
                    RelationOrigin::Parsed
                } else {
                    RelationOrigin::Inferred
                }
            || !originals.contains(&proof.evidence_sha256)
        {
            return Err(());
        }
        if let Some(previous) = proofs.insert(proof.evidence_sha256.clone(), proof.clone()) {
            if previous != proof {
                return Err(());
            }
        }
    }
    Ok(proofs)
}

/// Retain per-site authority when admission maps freshly resolved endpoints to
/// already-proven stable identities. This rewrites bindings, never confidence or
/// original evidence. Invalid input refuses before changing any field.
pub fn rebind_identity(
    relation: &mut Relation,
    id: RelationId,
    src: GraphNodeId,
    dst: GraphNodeId,
) -> Result<(), String> {
    validated_proofs(relation)
        .map_err(|_| "invalid parser occurrence evidence before identity mapping".to_string())?;
    for record in relation
        .evidence
        .iter_mut()
        .filter(|record| reserved(record))
    {
        let mut proof: Proof =
            serde_json::from_str(record.token.as_deref().expect("validated")).expect("validated");
        proof.relation_id = id;
        proof.src = src;
        proof.dst = dst;
        record.token = Some(serde_json::to_string(&proof).expect("proof serializes"));
    }
    relation.id = id;
    relation.src = src;
    relation.dst = dst;
    Ok(())
}

/// Merge two fresh resolver views of the same source occurrences. The dispatch
/// resolver may amend an occurrence token. Carry its own certificate with that
/// amendment and drop only certificates for originals it actually replaced.
/// Never stamp the merged scalar onto the resulting occurrence union.
pub fn incorporate_fresh_dispatch(
    parsed: &mut Relation,
    informed: &Relation,
) -> Result<(), String> {
    if (parsed.src, parsed.dst, parsed.kind) != (informed.src, informed.dst, informed.kind) {
        return Err("dispatch evidence endpoint mismatch".into());
    }
    validated_proofs(parsed)
        .map_err(|_| "invalid parser occurrence evidence before dispatch".to_string())?;
    let mut informed = informed.clone();
    rebind_identity(&mut informed, parsed.id, parsed.src, parsed.dst)?;
    let mut originals: Vec<_> = parsed
        .evidence
        .iter()
        .filter(|record| !reserved(record))
        .cloned()
        .collect();
    for record in informed.evidence.iter().filter(|record| !reserved(record)) {
        let corresponding = originals.iter_mut().find(|original| {
            original.source_span == record.source_span
                && original.call_shape == record.call_shape
                && original.parser_rule == record.parser_rule
                && original.source_path == record.source_path
                && original.resolved_path == record.resolved_path
                && original.occurrence_count == record.occurrence_count
                && (original.token == record.token
                    || record.token.as_deref() == Some(crate::SELF_DISPATCH_OVERRIDE_EVIDENCE_V1))
        });
        if let Some(original) = corresponding {
            *original = record.clone();
        } else {
            originals.push(record.clone());
        }
    }
    let retained: BTreeSet<_> = originals
        .iter()
        .filter(|record| record.source_span.is_some())
        .map(evidence_digest)
        .collect();
    let mut proof_records: Vec<_> = parsed
        .evidence
        .iter()
        .chain(&informed.evidence)
        .filter(|record| reserved(record))
        .filter(|record| {
            let proof: Proof = serde_json::from_str(record.token.as_deref().expect("validated"))
                .expect("validated");
            retained.contains(&proof.evidence_sha256)
        })
        .cloned()
        .collect();
    proof_records.sort_by(|a, b| a.token.cmp(&b.token));
    proof_records.dedup();
    originals.extend(proof_records);
    parsed.evidence = originals;
    parsed.confidence = informed.confidence;
    parsed.origin = informed.origin;
    Ok(())
}

/// Original producer records after validating every reserved metadata record.
/// Source-proof factories still verify these records against the admitted parse;
/// this helper never treats a certificate as source or destination authority.
pub fn original_evidence(relation: &Relation) -> Option<Vec<&RelationEvidence>> {
    validated_proofs(relation).ok()?;
    Some(
        relation
            .evidence
            .iter()
            .filter(|record| !reserved(record))
            .collect(),
    )
}

/// Exact-import relocation compares existing source records after mapping paths.
/// A certificate may be ignored there only when it adds no weaker/different
/// occurrence tier to the scalar proof that factory already requires.
pub fn uniform_original_evidence(relation: &Relation) -> Option<Vec<&RelationEvidence>> {
    let proofs = validated_proofs(relation).ok()?;
    if proofs.values().any(|proof| {
        proof.confidence.to_bits() != relation.confidence.to_bits()
            || proof.origin != relation.origin
    }) {
        return None;
    }
    original_evidence(relation)
}

/// Shape proofs use the same qualification as reference sites. Metadata is
/// ignored only after full validation, and a held occurrence cannot license a
/// whole-caller rename proof.
pub fn call_shape_records(relation: &Relation) -> Option<Vec<&RelationEvidence>> {
    validated_proofs(relation).ok()?;
    if groups(relation).iter().any(|group| {
        group.qualification_missing || !group.resolution.is_proven() || group.receiver_name_guess
    }) {
        return None;
    }
    Some(
        relation
            .evidence
            .iter()
            .filter(|record| !reserved(record))
            .collect(),
    )
}

/// Read-only occurrence groups. These are not graph relations and have no view
/// identity: callers remain deduplicated by their original entity/relation IDs.
#[derive(Debug, Clone)]
pub struct OccurrenceGroup {
    pub resolution: RelationResolution,
    pub receiver_name_guess: bool,
    pub sites: Vec<SourceSpan>,
    pub qualification_missing: bool,
}

pub fn groups(relation: &Relation) -> Vec<OccurrenceGroup> {
    let scalar = RelationResolution::of(relation);
    let guess = crate::resolution::is_receiver_name_guess(relation);
    let records: Vec<_> = relation
        .evidence
        .iter()
        .filter(|record| !reserved(record) && record.source_span.is_some())
        .collect();
    let has_metadata = relation.evidence.iter().any(reserved);
    if !has_metadata
        && (relation.kind != RelationKind::Calls
            || matches!(
                relation.origin,
                RelationOrigin::Lsp | RelationOrigin::Manual
            ))
    {
        return vec![OccurrenceGroup {
            resolution: scalar,
            receiver_name_guess: guess,
            sites: records
                .iter()
                .filter_map(|record| record.source_span.clone())
                .collect(),
            qualification_missing: false,
        }];
    }
    let unique_sites: BTreeSet<_> = records
        .iter()
        .map(|record| serde_json::to_string(&record.source_span).expect("span serializes"))
        .collect();
    if !has_metadata && unique_sites.len() <= 1 {
        return vec![OccurrenceGroup {
            resolution: scalar,
            receiver_name_guess: guess,
            sites: records
                .iter()
                .filter_map(|record| record.source_span.clone())
                .collect(),
            qualification_missing: false,
        }];
    }
    let proofs = validated_proofs(relation);
    let mut groups: BTreeMap<(RelationResolution, bool, bool), Vec<SourceSpan>> = BTreeMap::new();
    for record in &records {
        let proof = proofs
            .as_ref()
            .ok()
            .and_then(|proofs| proofs.get(&evidence_digest(record)));
        let (resolution, receiver_guess, missing) = match proof {
            Some(proof) => (
                RelationResolution::from_confidence(proof.confidence).min(scalar),
                guess || proof.confidence.to_bits() == RECEIVER_NAME_FANOUT_CONFIDENCE.to_bits(),
                false,
            ),
            None => (RelationResolution::NameOnly, true, true),
        };
        groups
            .entry((resolution, receiver_guess, missing))
            .or_default()
            .push(record.source_span.clone().expect("filtered"));
    }
    let mut result: Vec<_> = groups
        .into_iter()
        .map(
            |((resolution, receiver_name_guess, qualification_missing), sites)| OccurrenceGroup {
                resolution,
                receiver_name_guess,
                sites,
                qualification_missing,
            },
        )
        .collect();
    // Legacy or malformed aggregates still establish caller existence at their scalar tier,
    // but cannot attribute that tier to any particular retained occurrence.
    if scalar.is_proven()
        && !guess
        && !result
            .iter()
            .any(|group| group.resolution.is_proven() && !group.receiver_name_guess)
    {
        result.push(OccurrenceGroup {
            resolution: scalar,
            receiver_name_guess: false,
            sites: Vec::new(),
            qualification_missing: true,
        });
    }
    if result.is_empty() {
        result.push(OccurrenceGroup {
            resolution: RelationResolution::NameOnly,
            receiver_name_guess: true,
            sites: Vec::new(),
            qualification_missing: true,
        });
    }
    result
}

/// Trace/path union only proven sites. Keep the disclosure across regrouping.
pub fn proven_sites(relation: &Relation) -> (Vec<SourceSpan>, bool) {
    let mut sites = Vec::new();
    let mut withheld = false;
    for group in groups(relation) {
        if group.resolution.is_proven() && !group.receiver_name_guess {
            sites.extend(group.sites);
            withheld |= group.qualification_missing;
        } else {
            withheld |= !group.sites.is_empty() || group.qualification_missing;
        }
    }
    (sites, withheld)
}

/// Preserve existing occurrence tiers after the partial-source verifier has
/// uniquely mapped each original call to its new coordinates. This admits only
/// same-file span changes, never new evidence, confidence, shape or identity.
pub(crate) fn rebind_verified_spans(original: &Relation, updated: &mut Relation) -> Result<(), ()> {
    let proofs = validated_proofs(original)?;
    let has_metadata = original.evidence.iter().any(reserved);
    let mut old_header = original.clone();
    let mut new_header = updated.clone();
    old_header.evidence.clear();
    new_header.evidence.clear();
    if old_header != new_header || original.evidence.len() != updated.evidence.len() {
        return Err(());
    }
    let mut mapped = BTreeMap::new();
    for (old, new) in original.evidence.iter().zip(&updated.evidence) {
        if reserved(old) {
            if old != new {
                return Err(());
            }
            continue;
        }
        let mut permitted = old.clone();
        permitted.source_span = new.source_span.clone();
        if &permitted != new {
            return Err(());
        }
        match (&old.source_span, &new.source_span) {
            (None, None) => continue,
            (Some(before), Some(after)) if before.file == after.file => {}
            _ => return Err(()),
        }
        let old_digest = evidence_digest(old);
        let new_digest = evidence_digest(new);
        if has_metadata && !proofs.contains_key(&old_digest) {
            return Err(());
        }
        if let Some(prior) = mapped.insert(old_digest, new_digest.clone()) {
            if prior != new_digest {
                return Err(());
            }
        }
    }
    let mut rebound = updated.clone();
    for record in rebound
        .evidence
        .iter_mut()
        .filter(|record| reserved(record))
    {
        let mut proof: Proof =
            serde_json::from_str(record.token.as_deref().ok_or(())?).map_err(|_| ())?;
        proof.evidence_sha256 = mapped.get(&proof.evidence_sha256).ok_or(())?.clone();
        record.token = Some(serde_json::to_string(&proof).map_err(|_| ())?);
    }
    validated_proofs(&rebound)?;
    crate::linker::canonicalize_call_evidence(&mut rebound.evidence);
    *updated = rebound;
    Ok(())
}

#[cfg(test)]
mod span_rebinding_tests {
    use super::*;

    fn parsed_call() -> Relation {
        let source = b"int target(void) { return 1; }\nint caller(void) { return target(); }\n";
        crate::IndexPipeline::new()
            .index_file_content_with_tests(
                &kin_model::FilePathId::new("fixture.c"),
                source,
                kin_blobs::digest(source),
            )
            .unwrap()
            .indexed_file
            .relations
            .into_iter()
            .find(|relation| relation.kind == RelationKind::Calls)
            .unwrap()
    }

    #[test]
    fn verified_span_mapping_preserves_tier_and_refuses_other_evidence_changes() {
        let original = parsed_call();
        let index = original
            .evidence
            .iter()
            .position(|record| record.source_span.is_some())
            .unwrap();
        assert!(original.evidence.iter().any(reserved));
        let mut moved = original.clone();
        let span = moved.evidence[index].source_span.as_mut().unwrap();
        span.start_line += 1;
        span.end_line += 1;
        span.start_byte += 1;
        span.end_byte += 1;
        rebind_verified_spans(&original, &mut moved).unwrap();
        assert_eq!(moved.confidence, original.confidence);
        assert_eq!(moved.origin, original.origin);
        let (sites, held) = proven_sites(&moved);
        assert!(!held);
        assert_eq!(sites[0].start_line, 2);
        for case in 0..4 {
            let mut bad = original.clone();
            match case {
                0 => bad.evidence[index].token = Some("different call".into()),
                1 => {
                    bad.evidence[index].call_shape =
                        Some(kin_model::CallArgShape::new(99, vec![], false, false))
                }
                2 => bad.confidence = 0.3,
                _ => bad.dst = GraphNodeId::Entity(kin_model::EntityId::new()),
            }
            let untouched = bad.clone();
            assert!(rebind_verified_spans(&original, &mut bad).is_err());
            assert_eq!(bad, untouched, "refusal must not publish a partial mapping");
        }
        // One old digest cannot choose between two incompatible new locations.
        let mut duplicate = original.clone();
        duplicate.evidence.push(original.evidence[index].clone());
        let mut ambiguous = duplicate.clone();
        ambiguous
            .evidence
            .last_mut()
            .unwrap()
            .source_span
            .as_mut()
            .unwrap()
            .start_line += 1;
        assert!(rebind_verified_spans(&duplicate, &mut ambiguous).is_err());
    }
}

#[cfg(test)]
mod trimmed_site_proof_tests {
    use super::*;

    /// A parser `Calls` edge with `calls` certified sites, one call per line.
    fn parsed_calls(calls: usize) -> Relation {
        let source = format!(
            "int target(void) {{ return 1; }}\nint caller(void) {{\n    int total = 0;\n{}    \
             return total;\n}}\n",
            "    total += target();\n".repeat(calls)
        );
        let relation = crate::IndexPipeline::new()
            .index_file_content_with_tests(
                &kin_model::FilePathId::new("fixture.c"),
                source.as_bytes(),
                kin_blobs::digest(source.as_bytes()),
            )
            .unwrap()
            .indexed_file
            .relations
            .into_iter()
            .find(|relation| relation.kind == RelationKind::Calls)
            .unwrap();
        assert!(validated_proofs(&relation).is_ok(), "{relation:?}");
        assert_eq!(certificates(&relation), calls, "{relation:?}");
        relation
    }

    fn certificates(relation: &Relation) -> usize {
        relation
            .evidence
            .iter()
            .filter(|r| is_certificate(r))
            .count()
    }

    /// `relation` without its last site, and that site.
    fn trim_last_site(relation: &Relation) -> (Relation, RelationEvidence) {
        let mut bounded = relation.clone();
        let last = bounded
            .evidence
            .iter()
            .rposition(|record| record.source_span.is_some() && !reserved(record))
            .unwrap();
        let site = bounded.evidence.remove(last);
        (bounded, site)
    }

    #[test]
    fn certificates_are_told_apart_from_sites() {
        let relation = parsed_calls(2);
        assert_eq!(certificates(&relation), 2);
        assert!(relation
            .evidence
            .iter()
            .filter(|record| record.source_span.is_some())
            .all(|record| !is_certificate(record)));
        let unknown = RelationEvidence {
            parser_rule: Some("parser_occurrence_resolution_v2".into()),
            ..RelationEvidence::default()
        };
        assert!(
            is_certificate(&unknown),
            "every reserved version is a certificate"
        );
    }

    #[test]
    fn a_trimmed_sites_certificate_goes_and_the_kept_sites_stay_proven() {
        let intact = parsed_calls(3);
        let (mut bounded, site) = trim_last_site(&intact);
        assert!(
            validated_proofs(&bounded).is_err(),
            "the trimmed site's certificate fails the whole relation"
        );
        remove_proofs_of_trimmed_sites(&mut bounded, std::slice::from_ref(&site));
        assert!(validated_proofs(&bounded).is_ok(), "{bounded:?}");
        assert_eq!(certificates(&bounded), 2);
        let (sites, withheld) = proven_sites(&bounded);
        assert_eq!(sites.len(), 2);
        assert!(!withheld);
        assert!(!sites.contains(site.source_span.as_ref().unwrap()));
        let mut rest = intact.evidence.iter();
        assert!(
            bounded
                .evidence
                .iter()
                .all(|kept| rest.any(|record| record == kept)),
            "records are only removed, never rewritten or reordered"
        );
    }

    #[test]
    fn nothing_trimmed_leaves_the_relation_byte_identical() {
        let intact = parsed_calls(3);
        let mut relation = intact.clone();
        remove_proofs_of_trimmed_sites(&mut relation, &[]);
        assert_eq!(relation, intact);
        // A trimmed copy of a site the relation still carries took nothing.
        let kept = intact
            .evidence
            .iter()
            .find(|record| record.source_span.is_some())
            .unwrap()
            .clone();
        remove_proofs_of_trimmed_sites(&mut relation, &[kept]);
        assert_eq!(relation, intact);
        // An invalid relation with nothing trimmed is left exactly as it was.
        let (mut stranded, _) = trim_last_site(&intact);
        let before = stranded.clone();
        remove_proofs_of_trimmed_sites(&mut stranded, &[]);
        assert_eq!(stranded, before);
        assert!(validated_proofs(&stranded).is_err());
    }

    #[test]
    fn malformed_and_unknown_certificates_stay_and_keep_failing_closed() {
        let (mut bounded, site) = trim_last_site(&parsed_calls(3));
        let unknown: Vec<_> = bounded
            .evidence
            .iter()
            .filter(|record| reserved(record))
            .map(|record| RelationEvidence {
                parser_rule: Some("parser_occurrence_resolution_v2".into()),
                ..record.clone()
            })
            .collect();
        let malformed = RelationEvidence {
            parser_rule: Some(OCCURRENCE_RULE.into()),
            token: Some("not a proof".into()),
            occurrence_count: 0,
            ..RelationEvidence::default()
        };
        bounded.evidence.extend(unknown.iter().cloned());
        bounded.evidence.push(malformed.clone());
        remove_proofs_of_trimmed_sites(&mut bounded, std::slice::from_ref(&site));
        assert!(unknown
            .iter()
            .all(|record| bounded.evidence.contains(record)));
        assert!(bounded.evidence.contains(&malformed));
        assert_eq!(
            bounded
                .evidence
                .iter()
                .filter(|record| record.parser_rule.as_deref() == Some(OCCURRENCE_RULE))
                .count(),
            3,
            "only the trimmed site's valid certificate went: {bounded:?}"
        );
        assert!(validated_proofs(&bounded).is_err());
        assert!(proven_sites(&bounded).0.is_empty());
    }

    #[test]
    fn a_certificate_for_a_site_the_relation_never_carried_stays() {
        let (stranded, _) = trim_last_site(&parsed_calls(3));
        let (mut bounded, site) = trim_last_site(&stranded);
        remove_proofs_of_trimmed_sites(&mut bounded, std::slice::from_ref(&site));
        assert_eq!(
            certificates(&bounded),
            2,
            "only the trimmed site's certificate went"
        );
        assert!(
            validated_proofs(&bounded).is_err(),
            "the stranded certificate keeps the relation failing closed"
        );
        assert!(proven_sites(&bounded).0.is_empty());
    }

    #[test]
    fn a_contested_trimmed_site_keeps_its_certificates() {
        let (mut bounded, site) = trim_last_site(&parsed_calls(2));
        let digest = evidence_digest(&site);
        let index = bounded
            .evidence
            .iter()
            .position(|record| {
                reserved(record)
                    && record
                        .token
                        .as_deref()
                        .and_then(|token| serde_json::from_str::<Proof>(token).ok())
                        .is_some_and(|proof| proof.evidence_sha256 == digest)
            })
            .unwrap();
        let mut proof: Proof =
            serde_json::from_str(bounded.evidence[index].token.as_deref().unwrap()).unwrap();
        proof.confidence = 0.95;
        proof.origin = RelationOrigin::Inferred;
        let rival = RelationEvidence {
            token: Some(serde_json::to_string(&proof).unwrap()),
            ..bounded.evidence[index].clone()
        };
        let alone = Relation {
            evidence: vec![site.clone(), rival.clone()],
            ..bounded.clone()
        };
        assert!(
            validated_proofs(&alone).is_ok(),
            "the rival is a valid proof on its own"
        );
        bounded.evidence.insert(index + 1, rival);
        let before = bounded.clone();
        remove_proofs_of_trimmed_sites(&mut bounded, std::slice::from_ref(&site));
        assert_eq!(bounded, before, "a contested site keeps both certificates");
        assert!(validated_proofs(&bounded).is_err());
    }
}
