// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Source binding is an observation about admitted bytes and parser evidence.
//! It does not prove that every declaration, import, dispatch or answer is complete.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use kin_db::SourceDerivationFacts;
use kin_model::{ArtifactId, GraphNodeId, Hash256, Relation, RepoPath, TreeEntry};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceBinding {
    Current,
    Stale,
    Unproven,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DerivationCoverage {
    Complete,
    Incomplete,
    Unproven,
}

/// Absence of recorded prior-local debt is not proof of general resolution.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PriorLocalBindingStatus {
    NoRecordedDebt,
    Outstanding,
    #[default]
    Unproven,
}

pub(crate) enum ExactBindingRecord<'a> {
    Unavailable,
    Absent,
    Present(&'a Relation),
}

pub(crate) struct LocalBindingObservation {
    pub status: PriorLocalBindingStatus,
    pub count: Option<usize>,
    pub reason: Option<String>,
}

impl LocalBindingObservation {
    fn unproven(reason: &str) -> Self {
        Self {
            status: PriorLocalBindingStatus::Unproven,
            count: None,
            reason: Some(reason.chars().take(256).collect()),
        }
    }
}

/// Exact lookup and source-owned claims are both needed: neither an unrelated
/// reserved-ID occupant nor a malformed wrong-ID claim may become absence.
pub(crate) fn inspect_local_binding(
    file: &str,
    artifact: ArtifactId,
    body: Hash256,
    relations: &[&Relation],
    exact: ExactBindingRecord<'_>,
    history: &kin_model::BindingHistoryObservation,
) -> LocalBindingObservation {
    let reserved = kin_index::binding_debt::local_binding_debt_id(artifact);
    let occupant = match exact {
        ExactBindingRecord::Unavailable => {
            return LocalBindingObservation::unproven("exact binding identity lookup unavailable");
        }
        ExactBindingRecord::Absent => None,
        ExactBindingRecord::Present(relation) if relation.id == reserved => Some(relation),
        ExactBindingRecord::Present(_) => {
            return LocalBindingObservation::unproven(
                "exact lookup returned another binding identity",
            );
        }
    };
    let node = GraphNodeId::Artifact(artifact);
    let mut candidates: Vec<_> = relations
        .iter()
        .copied()
        .filter(|relation| relation.src == node || relation.id == reserved)
        .collect();
    let adjacent: Vec<_> = candidates
        .iter()
        .copied()
        .filter(|relation| relation.id == reserved)
        .collect();
    match adjacent.as_slice() {
        [] => {
            if let Some(occupant) = occupant {
                candidates.push(occupant);
            }
        }
        [found] if occupant == Some(*found) => {}
        _ => {
            return LocalBindingObservation::unproven(
                "exact binding identity disagrees with source evidence",
            )
        }
    }
    match kin_index::binding_debt::inspect_local_binding_debt(
        &kin_model::FilePathId::new(file),
        artifact,
        body,
        &candidates,
    ) {
        Ok(None)
            if !matches!(
                history,
                kin_model::BindingHistoryObservation::Checked { .. }
            ) =>
        {
            LocalBindingObservation::unproven(
                "prior binding history has no checked authority-bound witness",
            )
        }
        Ok(None) => LocalBindingObservation {
            status: PriorLocalBindingStatus::NoRecordedDebt,
            count: Some(0),
            reason: None,
        },
        Ok(Some(debt)) => LocalBindingObservation {
            status: PriorLocalBindingStatus::Outstanding,
            count: Some(debt.obligations.len()),
            reason: Some("prior local bindings remain outstanding".into()),
        },
        Err(error) => LocalBindingObservation::unproven(&error),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceDerivationIssue {
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceDerivationReport {
    pub inventory: String,
    pub body_binding: SourceBinding,
    pub parse_coverage: DerivationCoverage,
    pub call_extraction: DerivationCoverage,
    pub import_resolution: DerivationCoverage,
    /// A missing field from an older reader is unproven, never no-debt evidence.
    #[serde(default)]
    pub prior_local_binding: PriorLocalBindingStatus,
    pub outstanding_local_binding_obligations: Option<usize>,
    /// Null when inspection did not complete; zero is a measured empty inventory.
    pub full_adapter_sources: Option<usize>,
    pub excluded_artifacts: Option<usize>,
    pub issue_count: usize,
    pub issues: Vec<SourceDerivationIssue>,
    /// The old live call-shape proof, preserved independently of import resolution.
    pub call_shape_parse_coverage_complete: bool,
}

pub(crate) struct FileDerivation {
    pub binding: SourceBinding,
    pub parse: DerivationCoverage,
    pub extraction: DerivationCoverage,
    pub imports: DerivationCoverage,
    pub complete: bool,
}

pub(crate) fn full_adapter_path(path: &RepoPath) -> Result<bool, ()> {
    let path =
        kin_index::host_path_from_repo_path(std::path::Path::new(""), path).map_err(|_| ())?;
    Ok(matches!(
        kin_index::FileClassifier::classify(&path),
        kin_index::FileClassification::EntitySource
    ))
}

/// Shared proof for both the old impact predicate and bounded MCP observations.
/// A legacy certificate needs a nonempty unanimous current entity body; an empty
/// file needs the explicit factory-validated binding.
pub(crate) fn inspect_file(
    file: &str,
    artifact: ArtifactId,
    body: Hash256,
    digests: &[Option<Hash256>],
    relations: &[&Relation],
) -> FileDerivation {
    use DerivationCoverage::{Complete, Incomplete, Unproven};
    let mut binding = SourceBinding::Current;
    if digests.iter().flatten().any(|digest| *digest != body) {
        binding = SourceBinding::Stale;
    } else if digests.iter().any(Option::is_none) {
        binding = SourceBinding::Unproven;
    }
    let unanimous_current =
        !digests.is_empty() && digests.iter().all(|digest| *digest == Some(body));
    let node = GraphNodeId::Artifact(artifact);
    let mut recognized = Vec::new();
    let mut incomplete_marker = false;
    for relation in relations
        .iter()
        .copied()
        .filter(|relation| relation.src == node)
    {
        let has_rule = relation.evidence.iter().any(|evidence| {
            matches!(
                evidence.parser_rule.as_deref(),
                Some(
                    kin_index::CALL_SHAPE_PARSE_COVERAGE_FULL_V1
                        | kin_index::CALL_SHAPE_PARSE_COVERAGE_INCOMPLETE_V1
                        | kin_index::CALL_SHAPE_EXTRACTION_COVERAGE_INCOMPLETE_V1
                )
            )
        });
        incomplete_marker |= relation.evidence.iter().any(|evidence| {
            matches!(
                evidence.parser_rule.as_deref(),
                Some(
                    kin_index::CALL_SHAPE_PARSE_COVERAGE_INCOMPLETE_V1
                        | kin_index::CALL_SHAPE_EXTRACTION_COVERAGE_INCOMPLETE_V1
                )
            )
        });
        if has_rule {
            recognized.push(relation);
        }
    }
    let mut result = FileDerivation {
        binding,
        parse: Unproven,
        extraction: Unproven,
        imports: Unproven,
        complete: false,
    };
    let [certificate] = recognized.as_slice() else {
        if result.binding != SourceBinding::Stale {
            result.binding = SourceBinding::Unproven;
        }
        return result;
    };
    if !kin_index::is_parse_coverage_relation(certificate, file, artifact) {
        if result.binding != SourceBinding::Stale {
            result.binding = SourceBinding::Unproven;
        }
        return result;
    }
    // Located by label, never by position: the certificate grew a
    // base-resolution entry between the call and source-digest ones, and a
    // positional read would answer about the wrong entry the day it did.
    let is_full =
        kin_index::coverage_evidence(certificate, kin_index::CALL_SHAPE_PARSE_COVERAGE_FULL_V1)
            .is_some();
    let certificate_current = match kin_index::parse_coverage_source_digest(certificate) {
        Some(digest) if digest == body => true,
        Some(_) => {
            result.binding = SourceBinding::Stale;
            false
        }
        None if is_full && unanimous_current => true,
        None => {
            if result.binding != SourceBinding::Stale {
                result.binding = SourceBinding::Unproven;
            }
            false
        }
    };
    if certificate_current {
        if is_full {
            result.parse = Complete;
            result.extraction = Complete;
        } else if kin_index::coverage_evidence(
            certificate,
            kin_index::CALL_SHAPE_PARSE_COVERAGE_INCOMPLETE_V1,
        )
        .is_some()
        {
            result.parse = Incomplete;
            result.extraction = Unproven;
        } else if kin_index::coverage_evidence(
            certificate,
            kin_index::CALL_SHAPE_EXTRACTION_COVERAGE_INCOMPLETE_V1,
        )
        .is_some()
        {
            result.extraction = Incomplete;
        }
        let Some(imports) =
            kin_index::coverage_evidence(certificate, kin_index::IMPORT_RESOLUTION_COVERAGE_V1)
        else {
            return result;
        };
        result.imports = if imports
            .token
            .as_deref()
            .and_then(|token| token.parse::<u32>().ok())
            == Some(imports.occurrence_count)
        {
            Complete
        } else {
            Incomplete
        };
    }
    result.complete = result.binding == SourceBinding::Current
        && certificate_current
        && is_full
        && !incomplete_marker;
    result
}

impl SourceDerivationReport {
    pub fn unproven(reason: &str) -> Self {
        let mut report = Self::empty();
        report.body_binding = SourceBinding::Unproven;
        report.full_adapter_sources = None;
        report.excluded_artifacts = None;
        report.parse_coverage = DerivationCoverage::Unproven;
        report.call_extraction = DerivationCoverage::Unproven;
        report.import_resolution = DerivationCoverage::Unproven;
        report.prior_local_binding = PriorLocalBindingStatus::Unproven;
        report.outstanding_local_binding_obligations = None;
        report.call_shape_parse_coverage_complete = false;
        report.issue(reason, None);
        report
    }
    fn empty() -> Self {
        Self {
            inventory: "graph_admitted_full_adapter_sources".into(),
            body_binding: SourceBinding::Current,
            parse_coverage: DerivationCoverage::Complete,
            call_extraction: DerivationCoverage::Complete,
            import_resolution: DerivationCoverage::Complete,
            prior_local_binding: PriorLocalBindingStatus::NoRecordedDebt,
            outstanding_local_binding_obligations: Some(0),
            full_adapter_sources: Some(0),
            excluded_artifacts: Some(0),
            issue_count: 0,
            issues: Vec::new(),
            call_shape_parse_coverage_complete: true,
        }
    }
    fn issue(&mut self, reason: &str, path: Option<&str>) {
        self.issue_count += 1;
        if self.issues.len() < 4 {
            self.issues.push(SourceDerivationIssue {
                reason: reason.into(),
                path: path.map(|path| path.chars().take(256).collect()),
            });
        }
    }
}

fn merge_coverage(left: DerivationCoverage, right: DerivationCoverage) -> DerivationCoverage {
    use DerivationCoverage::*;
    match (left, right) {
        (Incomplete, _) | (_, Incomplete) => Incomplete,
        (Unproven, _) | (_, Unproven) => Unproven,
        _ => Complete,
    }
}

/// Evaluate already bounded graph facts. The producer states whether these facts
/// cover the whole inventory or selected paths; a clean subset is not a whole
/// repository assertion.
pub fn inspect_source_derivation(facts: &SourceDerivationFacts) -> SourceDerivationReport {
    let mut report = SourceDerivationReport::empty();
    let mut entities: BTreeMap<&str, Vec<Option<Hash256>>> = BTreeMap::new();
    for entity in &facts.entities {
        entities
            .entry(&entity.file.0)
            .or_default()
            .push(entity.digest);
    }
    let opaque: BTreeMap<_, _> = facts
        .opaque
        .iter()
        .map(|fact| (fact.file.0.as_str(), fact.hash))
        .collect();
    let mut sources = BTreeSet::new();
    let mut relations: HashMap<_, Vec<_>> = HashMap::new();
    for relation in &facts.relations {
        relations.entry(relation.src).or_default().push(relation);
    }
    let mut reservations_by_artifact: HashMap<_, Vec<_>> = HashMap::new();
    for reserved in &facts.reserved_relations {
        reservations_by_artifact
            .entry(reserved.artifact)
            .or_default()
            .push(reserved);
    }
    for artifact in &facts.artifacts {
        let TreeEntry::Blob { hash, .. } = artifact.entry else {
            if let Some(count) = &mut report.excluded_artifacts {
                *count += 1;
            }
            continue;
        };
        match full_adapter_path(&artifact.path) {
            Ok(false) => {
                if let Some(count) = &mut report.excluded_artifacts {
                    *count += 1;
                }
                continue;
            }
            Err(()) => {
                report.full_adapter_sources = None;
                report.excluded_artifacts = None;
                if report.body_binding != SourceBinding::Stale {
                    report.body_binding = SourceBinding::Unproven;
                }
                report.parse_coverage =
                    merge_coverage(report.parse_coverage, DerivationCoverage::Unproven);
                report.call_extraction =
                    merge_coverage(report.call_extraction, DerivationCoverage::Unproven);
                report.import_resolution =
                    merge_coverage(report.import_resolution, DerivationCoverage::Unproven);
                report.call_shape_parse_coverage_complete = false;
                report.prior_local_binding = merge_binding(
                    report.prior_local_binding,
                    PriorLocalBindingStatus::Unproven,
                );
                report.outstanding_local_binding_obligations = None;
                report.issue("source_path_unrepresentable", None);
                continue;
            }
            Ok(true) => {}
        }
        let Some(file) = artifact.path.as_utf8() else {
            if let Some(count) = &mut report.full_adapter_sources {
                *count += 1;
            }
            if report.body_binding != SourceBinding::Stale {
                report.body_binding = SourceBinding::Unproven;
            }
            report.parse_coverage =
                merge_coverage(report.parse_coverage, DerivationCoverage::Unproven);
            report.call_extraction =
                merge_coverage(report.call_extraction, DerivationCoverage::Unproven);
            report.import_resolution =
                merge_coverage(report.import_resolution, DerivationCoverage::Unproven);
            report.call_shape_parse_coverage_complete = false;
            report.prior_local_binding = merge_binding(
                report.prior_local_binding,
                PriorLocalBindingStatus::Unproven,
            );
            report.outstanding_local_binding_obligations = None;
            report.issue("source_path_not_utf8", None);
            continue;
        };
        if opaque.get(file) == Some(&hash) {
            if let Some(count) = &mut report.excluded_artifacts {
                *count += 1;
            }
            continue;
        }
        if let Some(count) = &mut report.full_adapter_sources {
            *count += 1;
        }
        sources.insert(file);
        let empty = Vec::new();
        let inspected = inspect_file(
            file,
            artifact.artifact_id,
            hash,
            entities.get(file).map(Vec::as_slice).unwrap_or_default(),
            relations
                .get(&GraphNodeId::Artifact(artifact.artifact_id))
                .unwrap_or(&empty),
        );
        let exact = match reservations_by_artifact
            .get(&artifact.artifact_id)
            .map(Vec::as_slice)
            .unwrap_or_default()
        {
            [reserved]
                if reserved.id
                    == kin_index::binding_debt::local_binding_debt_id(artifact.artifact_id) =>
            {
                match &reserved.relation {
                    Some(relation) => ExactBindingRecord::Present(relation),
                    None => ExactBindingRecord::Absent,
                }
            }
            _ => ExactBindingRecord::Unavailable,
        };
        let binding = inspect_local_binding(
            file,
            artifact.artifact_id,
            hash,
            relations
                .get(&GraphNodeId::Artifact(artifact.artifact_id))
                .unwrap_or(&empty),
            exact,
            &facts.binding_history,
        );
        report.prior_local_binding = merge_binding(report.prior_local_binding, binding.status);
        report.outstanding_local_binding_obligations = report
            .outstanding_local_binding_obligations
            .zip(binding.count)
            .and_then(|(left, right)| left.checked_add(right));
        if let Some(reason) = binding.reason {
            report.issue(
                &format!(
                    "local_binding_{}: {reason}",
                    if binding.status == PriorLocalBindingStatus::Outstanding {
                        "outstanding"
                    } else {
                        "unproven"
                    }
                ),
                Some(file),
            );
        }
        if inspected.binding != SourceBinding::Current {
            if report.body_binding != SourceBinding::Stale {
                report.body_binding = inspected.binding;
            }
            report.issue(
                if inspected.binding == SourceBinding::Stale {
                    "derived_source_digest_mismatch"
                } else {
                    "derived_source_binding_unproven"
                },
                Some(file),
            );
        }
        report.parse_coverage = merge_coverage(report.parse_coverage, inspected.parse);
        report.call_extraction = merge_coverage(report.call_extraction, inspected.extraction);
        report.import_resolution = merge_coverage(report.import_resolution, inspected.imports);
        report.call_shape_parse_coverage_complete &= inspected.complete;
    }
    for file in entities
        .keys()
        .copied()
        .chain(facts.layouts.iter().map(|layout| layout.file.0.as_str()))
    {
        if !sources.contains(file) {
            report.body_binding = SourceBinding::Stale;
            report.parse_coverage =
                merge_coverage(report.parse_coverage, DerivationCoverage::Unproven);
            report.call_extraction =
                merge_coverage(report.call_extraction, DerivationCoverage::Unproven);
            report.import_resolution =
                merge_coverage(report.import_resolution, DerivationCoverage::Unproven);
            report.call_shape_parse_coverage_complete = false;
            report.prior_local_binding = merge_binding(
                report.prior_local_binding,
                PriorLocalBindingStatus::Unproven,
            );
            report.outstanding_local_binding_obligations = None;
            report.issue("held_source_outside_admitted_inventory", Some(file));
        }
    }
    if facts.layouts.iter().any(|layout| !layout.full) {
        report.parse_coverage = DerivationCoverage::Incomplete;
        report.call_shape_parse_coverage_complete = false;
    }
    for path in &facts.missing_paths {
        if let Ok(true) = full_adapter_path(path) {
            if report.body_binding != SourceBinding::Stale {
                report.body_binding = SourceBinding::Unproven;
            }
            report.parse_coverage =
                merge_coverage(report.parse_coverage, DerivationCoverage::Unproven);
            report.call_extraction =
                merge_coverage(report.call_extraction, DerivationCoverage::Unproven);
            report.import_resolution =
                merge_coverage(report.import_resolution, DerivationCoverage::Unproven);
            report.call_shape_parse_coverage_complete = false;
            report.prior_local_binding = merge_binding(
                report.prior_local_binding,
                PriorLocalBindingStatus::Unproven,
            );
            report.outstanding_local_binding_obligations = None;
            report.issue("selected_source_not_admitted", path.as_utf8());
        }
    }
    if report.full_adapter_sources == Some(0)
        && !matches!(
            facts.binding_history,
            kin_model::BindingHistoryObservation::Checked { .. }
        )
    {
        report.prior_local_binding = PriorLocalBindingStatus::Unproven;
        report.outstanding_local_binding_obligations = None;
        report.issue(
            "prior binding history has no checked authority-bound witness",
            None,
        );
    }
    report
}

fn merge_binding(
    left: PriorLocalBindingStatus,
    right: PriorLocalBindingStatus,
) -> PriorLocalBindingStatus {
    use PriorLocalBindingStatus::*;
    match (left, right) {
        (Outstanding, _) | (_, Outstanding) => Outstanding,
        (Unproven, _) | (_, Unproven) => Unproven,
        _ => NoRecordedDebt,
    }
}
