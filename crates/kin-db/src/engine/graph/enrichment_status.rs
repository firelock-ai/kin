// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Finite, metadata-only enrichment observations from one entity-store lock.
//! Runtime progress and host resolver readiness are deliberately not evidence.

use std::collections::{BTreeMap, BTreeSet};

use kin_model::call_site_reading::{
    language_of_path, read_caller_sites, CallSiteFacts, CallSiteTally,
};
use kin_model::{
    CallSiteLedger, ContextValidationState, EnrichmentMark, Entity, EntityId, FilePathId,
    LanguageId, RepoPath, ResolutionRecordId, TreeEntry,
};
use serde::Serialize;

use super::{EntityData, InMemoryGraph, SourceEntityBinding};

const MAX_ITEMS: usize = 1_000_000;
const MAX_BYTES: usize = 8 * 1024 * 1024;

#[derive(Debug, Clone, thiserror::Error)]
pub enum EnrichmentStatusError {
    #[error("enrichment metadata exceeds the deterministic {kind} limit ({limit})")]
    Limit { kind: &'static str, limit: usize },
    #[error("{0}")]
    Invalid(String),
}

/// A path is a projection label for an admitted artifact, not a source read.
#[derive(Debug, Clone, Serialize)]
pub struct FileEnrichmentStatus {
    pub projection_path: RepoPath,
    pub artifact_id: Option<String>,
    pub body_digest: Option<String>,
    pub admitted: bool,
    pub parse: String,
    pub source: String,
    pub source_reason: Option<String>,
    pub contexts: Vec<EnrichmentContextStatus>,
    /// A legacy marker records only source bytes and record identities.
    pub recorded_source_observation: String,
    /// Only a matching version-eight published proof-input marker attests this.
    pub current_completion: String,
    pub current_completion_reason: String,
    pub completion_version: Option<u32>,
    /// Scope: the selected file's recorded call-site census only.
    pub proof: String,
    pub call_sites: serde_json::Value,
    pub clauses: Vec<String>,
    pub outstanding_binding_obligations: Option<usize>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EnrichmentContextStatus {
    pub language: LanguageId,
    pub state: String,
    pub context_id: Option<String>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone)]
pub struct EnrichmentStatusFacts {
    pub files: Vec<FileEnrichmentStatus>,
    pub tally: CallSiteTally,
    pub owed_files: BTreeMap<String, u64>,
}

struct Facts<'a> {
    data: &'a EntityData,
}

impl CallSiteFacts for Facts<'_> {
    fn ledger(&self, id: EntityId) -> Option<CallSiteLedger> {
        self.data
            .resolution_records
            .get(&ResolutionRecordId::call_sites(id))?
            .as_call_sites()
            .cloned()
    }

    fn current_context(&self, language: LanguageId) -> Option<ResolutionRecordId> {
        self.data
            .resolution_records
            .get(&ResolutionRecordId::context_validation(language))?
            .as_context_validation()?
            .current_context()
    }

    fn context_unverified_reason(&self, language: LanguageId) -> String {
        match self
            .data
            .resolution_records
            .get(&ResolutionRecordId::context_validation(language))
            .and_then(|record| record.as_context_validation())
        {
            Some(validation) => match &validation.state {
                ContextValidationState::Unverified { reason } => reason.clone(),
                _ => "the selected graph's context validation is unavailable".into(),
            },
            None => "the selected graph has no recorded proof-context validation".into(),
        }
    }

    fn derivation_owed(&self, entity: &Entity) -> bool {
        let Some(binding) = SourceEntityBinding::from_entity(entity) else {
            return false;
        };
        let Ok(path) = RepoPath::from_utf8(binding.file.0) else {
            return true;
        };
        !matches!(self.data.resolved_tree.artifact_at_path(&path).map(|a| a.entry),
            Some(TreeEntry::Blob { hash, .. }) if Some(hash) == binding.digest)
    }
}

impl InMemoryGraph {
    /// Capture requested artifacts, or the entire inventory when none are
    /// requested. Missing requested paths remain explicit rows. Marks must come from
    /// the caller's held selected authority; `None` means that authority has no
    /// applicable workspace marks (in particular a historical revision).
    ///
    /// The caller fences source authority and selected-graph identity across
    /// this operation. This method itself reads all graph facts under one lock.
    /// It performs no CAS, filesystem, model, index, or language-server reads.
    pub fn enrichment_status_facts(
        &self,
        requested: &[RepoPath],
        marks: Option<&[EnrichmentMark]>,
        version_covers: impl Fn(u32, &str) -> bool,
    ) -> Result<EnrichmentStatusFacts, EnrichmentStatusError> {
        let data = self.entities.read();
        if data.entities.len() > MAX_ITEMS
            || data.relations.len() > MAX_ITEMS
            || data.resolution_records.records().len() > MAX_ITEMS
            || data.resolved_tree.len() > MAX_ITEMS
            || requested.len() > MAX_ITEMS
        {
            return Err(EnrichmentStatusError::Limit {
                kind: "records",
                limit: MAX_ITEMS,
            });
        }
        let selected: BTreeSet<_> = requested.iter().cloned().collect();
        let selected_utf8: BTreeSet<_> = selected.iter().filter_map(RepoPath::as_utf8).collect();
        let includes = |path: &RepoPath| selected.is_empty() || selected.contains(path);
        let mut path_bytes = 0usize;
        for path in data
            .resolved_tree
            .artifacts()
            .map(|artifact| &artifact.path)
            .filter(|path| includes(path))
            .chain(requested.iter())
        {
            path_bytes = path_bytes
                .checked_add(path.as_bytes().len())
                .filter(|bytes| *bytes <= MAX_BYTES)
                .ok_or(EnrichmentStatusError::Limit {
                    kind: "path_bytes",
                    limit: MAX_BYTES,
                })?;
        }
        let facts = Facts { data: &data };
        let mut paths: BTreeSet<RepoPath> = data
            .resolved_tree
            .artifacts()
            .filter(|artifact| includes(&artifact.path))
            .map(|artifact| artifact.path.clone())
            .collect();
        paths.extend(requested.iter().cloned());
        // Entity-only paths are gaps, not silently excluded source inventory.
        let mut by_file: BTreeMap<RepoPath, Vec<&Entity>> = BTreeMap::new();
        for entity in data.entities.values() {
            if let Some(file) = entity
                .span
                .as_ref()
                .map(|span| &span.file)
                .or(entity.file_origin.as_ref())
            {
                if let Ok(path) = RepoPath::from_utf8(file.0.clone()) {
                    if !includes(&path) {
                        continue;
                    }
                    paths.insert(path.clone());
                    by_file.entry(path).or_default().push(entity);
                }
            }
        }
        let entity_file = |id: &EntityId| {
            data.entities
                .get(id)
                .and_then(|entity| entity.file_origin.as_ref())
                .filter(|file| selected.is_empty() || selected_utf8.contains(file.0.as_str()))
                .map(|file| file.0.as_str())
        };
        let relations =
            kin_model::enrichment_relations_by_owner_file(data.relations.values(), entity_file);
        let ledgers = kin_model::enrichment_ledgers_by_file(
            data.resolution_records.records().values(),
            entity_file,
        );
        let marks: Option<BTreeMap<&str, &EnrichmentMark>> = marks.map(|marks| {
            marks
                .iter()
                .filter(|mark| selected.is_empty() || selected_utf8.contains(mark.path.as_str()))
                .map(|mark| (mark.path.as_str(), mark))
                .collect()
        });
        let proof_inputs = kin_model::enrichment_proof_inputs_by_file(
            marks
                .as_ref()
                .into_iter()
                .flat_map(|marks| marks.values())
                .filter(|mark| mark.version == kin_model::ENRICHMENT_PROOF_MARK_VERSION)
                .map(|mark| mark.path.as_str()),
            data.entities.values(),
            data.relations.values(),
            data.resolution_records.records().values(),
        )
        .map_err(|error| EnrichmentStatusError::Invalid(error.to_string()))?;
        let mut files = Vec::new();
        let mut total = CallSiteTally::default();
        let mut owed_files = BTreeMap::new();
        for entity in data.entities.values() {
            let mut caller = CallSiteTally::default();
            caller.add(&read_caller_sites(&facts, entity));
            let owed = caller.callers_owed() + caller.callers_stale + caller.callers_unverified;
            if owed > 0 {
                if let Some(file) = entity
                    .span
                    .as_ref()
                    .map(|span| &span.file)
                    .or(entity.file_origin.as_ref())
                {
                    *owed_files.entry(file.0.clone()).or_default() += owed;
                }
            }
            total.merge(&caller);
        }
        let mut bytes = 0usize;
        for path in paths {
            let artifact = data.resolved_tree.artifact_at_path(&path);
            let body = artifact.and_then(|artifact| match artifact.entry {
                TreeEntry::Blob { hash, .. } => Some(hash),
                _ => None,
            });
            let file = path.as_utf8().map(|path| FilePathId::new(path.to_owned()));
            let entities = by_file.get(&path).map(Vec::as_slice).unwrap_or(&[]);
            let parse = file
                .as_ref()
                .and_then(|file| data.file_layouts.get(file))
                .map(|layout| layout.parse_completeness.bucket())
                .unwrap_or("unrecorded");
            let source_current = body.is_some()
                && parse == "full"
                && !entities.is_empty()
                && entities.iter().all(|entity| {
                    SourceEntityBinding::from_entity(entity).is_some()
                        && !facts.derivation_owed(entity)
                });
            let mut languages: Vec<LanguageId> = entities.iter().map(|e| e.language).collect();
            if let Some(language) = path.as_utf8().and_then(language_of_path) {
                languages.push(language);
            }
            languages.sort_by_key(ToString::to_string);
            languages.dedup();
            let contexts = languages
                .into_iter()
                .map(|language| {
                    let current = facts.current_context(language);
                    EnrichmentContextStatus {
                        language,
                        state: if current.is_some() {
                            "validated"
                        } else {
                            "unverified"
                        }
                        .into(),
                        context_id: current.map(|context| context.to_string()),
                        reason: current
                            .is_none()
                            .then(|| facts.context_unverified_reason(language)),
                    }
                })
                .collect::<Vec<_>>();
            let mut tally = CallSiteTally::default();
            for entity in entities {
                tally.add(&read_caller_sites(&facts, entity));
            }
            let mark = path
                .as_utf8()
                .and_then(|path| marks.as_ref()?.get(path).copied());
            let recorded = mark.is_some_and(|mark| {
                if Some(mark.body) != body {
                    return false;
                }
                match mark.version {
                    kin_model::ENRICHMENT_PROOF_MARK_VERSION => {
                        proof_inputs.get(&mark.path) == Some(&mark.relations)
                    }
                    1..=7 => {
                        kin_model::enrichment_relations_digest(
                            &mark.path,
                            relations.get(&mark.path).into_iter().flatten().copied(),
                            entity_file,
                            ledgers.get(&mark.path).into_iter().flatten().copied(),
                        ) == mark.relations
                    }
                    _ => false,
                }
            });
            let recorded_source_observation = if marks.is_none() {
                "unavailable_in_selected_scope"
            } else if recorded {
                "matches_marker_inputs"
            } else {
                "not_recorded_for_selected_inputs"
            };
            let (current_completion, completion_reason) = if marks.is_none() {
                (
                    "unavailable_in_selected_scope",
                    "the selected revision has no applicable workspace completion marker",
                )
            } else if mark
                .is_some_and(|mark| mark.version < kin_model::ENRICHMENT_PROOF_MARK_VERSION)
            {
                ("unverified_legacy_marker", "legacy marker identities do not attest exact ledger and context payload publication")
            } else if recorded
                && mark.is_some_and(|mark| version_covers(mark.version, &mark.path))
                && source_current
                && tally.callers_owed() == 0
                && tally.callers_stale == 0
                && tally.callers_unverified == 0
            {
                ("recorded", "a successfully published marker matches the selected current source and complete proof inputs")
            } else {
                ("owed", "no applicable published marker matches the selected current source and complete proof inputs")
            };
            let obligations = match (artifact, file.as_ref(), body) {
                (Some(artifact), Some(file), Some(body)) => {
                    match data
                        .relations
                        .get(&kin_model::binding_debt::local_binding_debt_id(
                            artifact.artifact_id,
                        )) {
                        None => Some(0),
                        Some(relation) => kin_model::binding_debt::decode_local_binding_debt(
                            file,
                            artifact.artifact_id,
                            relation,
                        )
                        .ok()
                        .flatten()
                        .filter(|debt| debt.observed_source_digest == body)
                        .map(|debt| debt.obligations.len()),
                    }
                }
                _ => None,
            };
            let proof =
                if !source_current || tally.callers_stale > 0 || tally.callers_unverified > 0 {
                    "unverified"
                } else if tally.callers_owed() > 0 {
                    "owed"
                } else if tally.is_settled() {
                    "settled"
                } else {
                    "unverified"
                };
            let row = FileEnrichmentStatus {
                projection_path: path,
                artifact_id: artifact.map(|artifact| artifact.artifact_id.0.to_string()),
                body_digest: body.map(|body| body.to_string()),
                admitted: artifact.is_some(),
                parse: parse.into(),
                source: if source_current {
                    "current"
                } else {
                    "unverified"
                }
                .into(),
                source_reason: if source_current {
                    None
                } else {
                    Some(
                        if artifact.is_none() {
                            "not_admitted"
                        } else if body.is_none() {
                            "not_source_blob"
                        } else if file.is_none() {
                            "non_utf8_projection_path"
                        } else if file
                            .as_ref()
                            .is_some_and(|file| data.opaque_artifacts.contains_key(file))
                        {
                            "unsupported_source"
                        } else if parse != "full" {
                            "parse_not_complete"
                        } else if entities.is_empty() {
                            "no_recorded_entity_census"
                        } else {
                            "source_seal_mismatch"
                        }
                        .into(),
                    )
                },
                contexts,
                recorded_source_observation: recorded_source_observation.into(),
                current_completion: current_completion.into(),
                current_completion_reason: completion_reason.into(),
                completion_version: mark.map(|mark| mark.version),
                proof: proof.into(),
                call_sites: tally.to_json(),
                clauses: tally.clauses("this file's recorded call-site census"),
                outstanding_binding_obligations: obligations,
            };
            bytes = bytes
                .checked_add(
                    serde_json::to_vec(&row)
                        .map_err(|e| EnrichmentStatusError::Invalid(e.to_string()))?
                        .len(),
                )
                .filter(|bytes| *bytes <= MAX_BYTES)
                .ok_or(EnrichmentStatusError::Limit {
                    kind: "bytes",
                    limit: MAX_BYTES,
                })?;
            files.push(row);
        }
        Ok(EnrichmentStatusFacts {
            files,
            tally: total,
            owed_files,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{
        ArtifactId, CallSite, CallSiteState, ContextValidation, EntityKind, EntityMetadata,
        EntityRole, FingerprintAlgorithm, Hash256, ImportSection, ParseCompleteness, ProofContext,
        ResolutionRecord, ResolutionRecordSet, ResolvedArtifact, ResolvedTree, SemanticFingerprint,
        SourceSpan, Visibility,
    };

    fn fixture() -> (InMemoryGraph, Entity, ProofContext, EnrichmentMark) {
        let graph = InMemoryGraph::new();
        let file = FilePathId::new("src/a.py");
        let hash = Hash256::from_bytes([7; 32]);
        let mut metadata = EntityMetadata::default();
        metadata
            .extra
            .insert("blob_hash".into(), serde_json::json!(hash.to_string()));
        let entity = Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: "caller".into(),
            language: LanguageId::Python,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: hash,
                signature_hash: hash,
                behavior_hash: hash,
                equivalence_hash: hash,
                stability_score: 1.0,
            },
            file_origin: Some(file.clone()),
            span: Some(SourceSpan {
                file: file.clone(),
                start_byte: 0,
                end_byte: 30,
                start_line: 1,
                start_col: 0,
                end_line: 2,
                end_col: 15,
            }),
            signature: "def caller():".into(),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata,
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        };
        let context = ProofContext {
            language: LanguageId::Python,
            resolver: "lsp:test".into(),
            resolver_version: "1".into(),
            configuration_hash: hash,
            environment_hash: hash,
            environment_summary: "fixture".into(),
        };
        let ledger = CallSiteLedger {
            caller: entity.id,
            behavior_hash: hash,
            body_hash: Hash256::from_bytes([9; 32]),
            context: ResolutionRecordId::proof_context(&context),
            census: 1,
            sites: vec![CallSite {
                offset: 20,
                length: 4,
                state: CallSiteState::ProvenTarget { target: entity.id },
            }],
        };
        let mark = EnrichmentMark {
            path: file.0.clone(),
            body: hash,
            version: 7,
            relations: kin_model::enrichment_relations_digest(
                &file.0,
                std::iter::empty(),
                |_| None,
                [ResolutionRecordId::call_sites(entity.id)],
            ),
        };
        {
            let mut data = graph.entities.write();
            data.entities.insert(entity.id, entity.clone());
            data.resolved_tree = ResolvedTree::from_artifacts([ResolvedArtifact::new(
                ArtifactId::new(),
                RepoPath::from_utf8(file.0.clone()).unwrap(),
                TreeEntry::blob(hash, false),
            )])
            .unwrap();
            data.file_layouts.insert(
                file.clone(),
                kin_model::FileLayout {
                    file_id: file,
                    parse_completeness: ParseCompleteness::Full,
                    imports: ImportSection {
                        byte_range: 0..0,
                        items: vec![],
                    },
                    regions: vec![],
                },
            );
            data.resolution_records = ResolutionRecordSet::from_records(
                [
                    (
                        ResolutionRecordId::proof_context(&context),
                        ResolutionRecord::ProofContext(context.clone()),
                    ),
                    (
                        ResolutionRecordId::context_validation(LanguageId::Python),
                        ResolutionRecord::ContextValidation(ContextValidation {
                            language: LanguageId::Python,
                            state: ContextValidationState::Validated {
                                context: context.clone(),
                            },
                        }),
                    ),
                    (
                        ResolutionRecordId::call_sites(entity.id),
                        ResolutionRecord::CallSites(ledger),
                    ),
                ]
                .into_iter()
                .collect(),
            );
        }
        (graph, entity, context, mark)
    }

    #[test]
    fn enrichment_status_joins_source_context_and_completion_without_certifying_unresolved_sites() {
        let (graph, entity, _, mark) = fixture();
        let read = || {
            graph
                .enrichment_status_facts(&[], Some(std::slice::from_ref(&mark)), |v, _| v == 7)
                .unwrap()
        };
        let observed = read();
        assert_eq!(
            observed.files[0].recorded_source_observation,
            "matches_marker_inputs"
        );
        assert_eq!(
            observed.files[0].current_completion,
            "unverified_legacy_marker"
        );
        assert_eq!(observed.files[0].proof, "settled");
        {
            let mut data = graph.entities.write();
            let mut records = data.resolution_records.records().clone();
            let ResolutionRecord::CallSites(ledger) = records
                .get_mut(&ResolutionRecordId::call_sites(entity.id))
                .unwrap()
            else {
                panic!()
            };
            ledger.sites[0].state = CallSiteState::Binding { may_call: None };
            data.resolution_records = ResolutionRecordSet::from_records(records);
        }
        let observed = read();
        assert_eq!(
            observed.files[0].recorded_source_observation,
            "matches_marker_inputs"
        );
        assert_eq!(
            observed.files[0].current_completion,
            "unverified_legacy_marker"
        );
        assert_eq!(observed.files[0].proof, "unverified");
        assert_eq!(
            observed.files[0].call_sites["by_state"]["binding"].as_u64(),
            Some(1)
        );
        assert!(!observed.files[0].clauses.is_empty());
    }

    #[test]
    fn enrichment_status_current_completion_requires_full_published_proof_inputs() {
        let (graph, entity, _, mut mark) = fixture();
        mark.version = kin_model::ENRICHMENT_PROOF_MARK_VERSION;
        {
            let data = graph.entities.read();
            mark.relations = kin_model::enrichment_proof_inputs_by_file(
                [mark.path.as_str()],
                data.entities.values(),
                data.relations.values(),
                data.resolution_records.records().values(),
            )
            .unwrap()[&mark.path];
        }
        let read = || {
            graph
                .enrichment_status_facts(&[], Some(std::slice::from_ref(&mark)), |version, _| {
                    version == kin_model::ENRICHMENT_PROOF_MARK_VERSION
                })
                .unwrap()
        };
        assert_eq!(read().files[0].current_completion, "recorded");
        {
            let mut data = graph.entities.write();
            let mut records = data.resolution_records.records().clone();
            let ResolutionRecord::CallSites(ledger) = records
                .get_mut(&ResolutionRecordId::call_sites(entity.id))
                .unwrap()
            else {
                panic!()
            };
            ledger.sites[0].state = CallSiteState::Binding { may_call: None };
            data.resolution_records = ResolutionRecordSet::from_records(records);
        }
        let changed = read();
        assert_eq!(
            changed.files[0].current_completion, "owed",
            "same record ID cannot hide an unpublished payload change"
        );
        assert_eq!(changed.files[0].proof, "unverified");
        // A successful published observation of unresolved evidence can be
        // complete work without being a settled semantic proof.
        {
            let data = graph.entities.read();
            mark.relations = kin_model::enrichment_proof_inputs_by_file(
                [mark.path.as_str()],
                data.entities.values(),
                data.relations.values(),
                data.resolution_records.records().values(),
            )
            .unwrap()[&mark.path];
        }
        let recorded = graph
            .enrichment_status_facts(&[], Some(&[mark]), |_, _| true)
            .unwrap();
        assert_eq!(recorded.files[0].current_completion, "recorded");
        assert_eq!(recorded.files[0].proof, "unverified");
    }

    #[test]
    fn enrichment_status_missing_stale_context_and_body_cannot_be_completed() {
        for state in [
            None,
            Some(ContextValidationState::Unverified {
                reason: "environment not checked".into(),
            }),
        ] {
            let (graph, _, _, mark) = fixture();
            {
                let mut data = graph.entities.write();
                let mut records = data.resolution_records.records().clone();
                let id = ResolutionRecordId::context_validation(LanguageId::Python);
                records.remove(&id);
                if let Some(state) = state {
                    records.insert(
                        id,
                        ResolutionRecord::ContextValidation(ContextValidation {
                            language: LanguageId::Python,
                            state,
                        }),
                    );
                }
                data.resolution_records = ResolutionRecordSet::from_records(records);
            }
            let facts = graph
                .enrichment_status_facts(&[], Some(&[mark]), |_, _| true)
                .unwrap();
            assert_eq!(facts.files[0].proof, "unverified");
            assert_eq!(
                facts.files[0].recorded_source_observation,
                "matches_marker_inputs"
            );
            assert_eq!(
                facts.files[0].current_completion,
                "unverified_legacy_marker"
            );
            assert_eq!(facts.files[0].contexts[0].state, "unverified");
        }
        let (graph, entity, mut context, mark) = fixture();
        context.resolver_version = "2".into();
        {
            let mut data = graph.entities.write();
            let mut records = data.resolution_records.records().clone();
            records.insert(
                ResolutionRecordId::context_validation(LanguageId::Python),
                ResolutionRecord::ContextValidation(ContextValidation {
                    language: LanguageId::Python,
                    state: ContextValidationState::Validated { context },
                }),
            );
            data.resolution_records = ResolutionRecordSet::from_records(records);
        }
        assert_eq!(
            graph
                .enrichment_status_facts(&[], Some(&[mark]), |_, _| true)
                .unwrap()
                .files[0]
                .proof,
            "unverified"
        );
        graph
            .entities
            .write()
            .entities
            .get_mut(&entity.id)
            .unwrap()
            .metadata
            .extra
            .insert(
                "blob_hash".into(),
                serde_json::json!(Hash256::from_bytes([8; 32]).to_string()),
            );
        let facts = graph
            .enrichment_status_facts(&[], None, |_, _| true)
            .unwrap();
        assert_eq!(facts.files[0].source, "unverified");
        assert_eq!(
            facts.files[0].recorded_source_observation,
            "unavailable_in_selected_scope"
        );
    }

    #[test]
    fn enrichment_status_keeps_missing_empty_unsupported_and_raw_paths_explicit() {
        let (graph, _, _, mark) = fixture();
        let paths = [
            RepoPath::from_utf8("empty.py").unwrap(),
            RepoPath::from_utf8("asset.bin").unwrap(),
            RepoPath::from_bytes(b"raw/\xff.py".to_vec()).unwrap(),
        ];
        {
            let mut data = graph.entities.write();
            let mut artifacts = data.resolved_tree.artifacts().cloned().collect::<Vec<_>>();
            artifacts.extend(paths.iter().cloned().map(|path| {
                ResolvedArtifact::new(
                    ArtifactId::new(),
                    path,
                    TreeEntry::blob(Hash256::from_bytes([3; 32]), false),
                )
            }));
            data.resolved_tree = ResolvedTree::from_artifacts(artifacts).unwrap();
        }
        let missing = RepoPath::from_utf8("missing.py").unwrap();
        let requested = paths
            .iter()
            .chain(std::iter::once(&missing))
            .cloned()
            .collect::<Vec<_>>();
        let facts = graph
            .enrichment_status_facts(&requested, Some(&[mark]), |_, _| true)
            .unwrap();
        assert_eq!(facts.files.len(), 4);
        for path in paths.iter().chain(std::iter::once(&missing)) {
            let row = facts
                .files
                .iter()
                .find(|row| &row.projection_path == path)
                .unwrap();
            assert_eq!(row.proof, "unverified");
            assert_ne!(row.recorded_source_observation, "matches_marker_inputs");
        }
        assert!(
            !facts
                .files
                .iter()
                .find(|row| row.projection_path == missing)
                .unwrap()
                .admitted
        );
    }

    #[test]
    fn enrichment_status_narrows_before_the_inventory_byte_limit_and_keeps_global_debt() {
        let (graph, entity, _, mark) = fixture();
        {
            let mut data = graph.entities.write();
            let mut artifacts = data.resolved_tree.artifacts().cloned().collect::<Vec<_>>();
            // Real compact rows, not a raised or injected byte ceiling.
            artifacts.extend((0..10_000).map(|index| {
                ResolvedArtifact::new(
                    ArtifactId::new(),
                    RepoPath::from_utf8(format!("unrelated/{index:05}.py")).unwrap(),
                    TreeEntry::blob(Hash256::from_bytes([3; 32]), false),
                )
            }));
            data.resolved_tree = ResolvedTree::from_artifacts(artifacts).unwrap();
            let mut other = entity.clone();
            other.id = EntityId::new();
            other.file_origin = Some(FilePathId::new("unrelated/00000.py"));
            other.span.as_mut().unwrap().file = other.file_origin.clone().unwrap();
            data.entities.insert(other.id, other);
        }
        assert!(matches!(
            graph.enrichment_status_facts(&[], Some(std::slice::from_ref(&mark)), |_, _| true),
            Err(EnrichmentStatusError::Limit {
                kind: "bytes",
                limit: MAX_BYTES
            })
        ));
        let paths = [
            RepoPath::from_utf8("src/a.py").unwrap(),
            RepoPath::from_utf8("missing.py").unwrap(),
        ];
        let selected = graph
            .enrichment_status_facts(&paths, Some(&[mark]), |_, _| true)
            .unwrap();
        assert_eq!(selected.files.len(), 2);
        assert_eq!(
            selected
                .files
                .iter()
                .map(|row| &row.projection_path)
                .collect::<BTreeSet<_>>(),
            paths.iter().collect()
        );
        assert_eq!(
            selected
                .files
                .iter()
                .find(|row| row.projection_path == paths[0])
                .unwrap()
                .proof,
            "settled"
        );
        assert!(
            !selected
                .files
                .iter()
                .find(|row| row.projection_path == paths[1])
                .unwrap()
                .admitted
        );
        assert_eq!(selected.tally.callers, 2);
        assert_eq!(selected.owed_files.get("unrelated/00000.py"), Some(&1));
    }

    #[test]
    fn enrichment_status_historical_read_uses_its_own_context_and_no_head_marks() {
        let (graph, _, _, _) = fixture();
        let before = graph
            .enrichment_status_facts(&[], None, |_, _| true)
            .unwrap();
        assert_eq!(before.files[0].proof, "settled");
        assert_eq!(
            before.files[0].recorded_source_observation,
            "unavailable_in_selected_scope"
        );
        let unrelated = InMemoryGraph::new();
        assert!(unrelated
            .enrichment_status_facts(&[], None, |_, _| true)
            .unwrap()
            .files
            .is_empty());
        assert_eq!(
            serde_json::to_value(&before.files).unwrap(),
            serde_json::to_value(
                graph
                    .enrichment_status_facts(&[], None, |_, _| true)
                    .unwrap()
                    .files
            )
            .unwrap()
        );
    }
}
