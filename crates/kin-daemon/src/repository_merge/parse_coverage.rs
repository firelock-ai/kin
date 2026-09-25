// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Parser certificates are derived from the selected source, not a separate
//! authored merge choice. Only exact, current factory values enter this path.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use anyhow::{Context, Result};
use kin_model::{
    ArtifactId, GraphNodeId, MergeConflictEntry, MergeConflictSubject, MergeSideValue, Relation,
    RelationId, ResolvedTree, TreeEntry,
};

use kin_model::graph::ResolvedGraphState;

use super::{compose, merge_conflict, ActiveLocalRepositoryAuthority, DaemonState};

fn owned_artifact(relation: &Relation, side: &ResolvedGraphState) -> Option<ArtifactId> {
    let GraphNodeId::Artifact(artifact) = relation.src else {
        return None;
    };
    let source = side.tree.get(&artifact)?;
    let path = source.path.as_utf8()?;
    let TreeEntry::Blob { hash, .. } = source.entry else {
        return None;
    };
    (kin_index::is_parse_coverage_relation(relation, path, artifact)
        && kin_index::parse_coverage_source_digest(relation) == Some(hash))
    .then_some(artifact)
}

/// Existing durable conflict subjects retain their exact resolution protocol.
/// New merges defer only conflicts owned by this factory on all three sides.
/// Cleanly composed certificates keep their existing merge behavior and cost.
pub(super) fn compose_relations(
    inputs: [&ResolvedGraphState; 3],
    recorded: &BTreeSet<RelationId>,
    conflicts: &mut Vec<MergeConflictEntry>,
) -> Result<(
    HashMap<RelationId, Relation>,
    BTreeMap<RelationId, ArtifactId>,
)> {
    let start = conflicts.len();
    let merged = compose(
        &inputs[0].relations,
        &inputs[1].relations,
        &inputs[2].relations,
        |relation| MergeConflictSubject::Relation {
            relation: *relation,
        },
        MergeSideValue::relation,
        |_| None,
        |left, right| left == right,
        conflicts,
    )?;
    let mut deferred = BTreeMap::new();
    for entry in &conflicts[start..] {
        let MergeConflictSubject::Relation { relation: id } = entry.subject else {
            continue;
        };
        if recorded.contains(&id) {
            continue;
        }
        let mut owner = None;
        let mut valid = true;
        for side in inputs {
            if let Some(relation) = side.relations.get(&id) {
                let artifact = owned_artifact(relation, side);
                if relation.id != id
                    || artifact.is_none()
                    || owner.is_some_and(|old| Some(old) != artifact)
                {
                    valid = false;
                    break;
                }
                owner = artifact;
            } else {
                // Absence can be an explicit withdrawal. This increment only
                // repairs one existing certificate changed on both branches.
                valid = false;
                break;
            }
        }
        if valid {
            if let Some(artifact) = owner {
                deferred.insert(id, artifact);
            }
        }
    }
    conflicts.retain(|entry| !matches!(entry.subject, MergeConflictSubject::Relation { relation } if deferred.contains_key(&relation)));
    Ok((merged, deferred))
}

/// Recompute only the deferred certificate, after final artifact projection.
/// This is ingestion from immutable graph-owned CAS, never a working-copy read.
/// It does not reauthor settled calls, manual edges, or local-binding debt.
pub(super) fn rederive(
    state: &DaemonState,
    authority: &ActiveLocalRepositoryAuthority,
    inputs: [&ResolvedGraphState; 3],
    deferred: &BTreeMap<RelationId, ArtifactId>,
    tree: &ResolvedTree,
    relations: &mut HashMap<RelationId, Relation>,
) -> Result<()> {
    if deferred.is_empty() {
        return Ok(());
    }
    // Match history/linker's semantic file universe. A source-looking path can
    // hold opaque bytes, so neither a filename nor a generic tree blob proves
    // that an import resolves to a semantic source. Read one candidate at a
    // time; this scan happens only for a deferred certificate conflict.
    let mut known_files = HashSet::new();
    for artifact in tree.artifacts() {
        let (Some(path), TreeEntry::Blob { hash, .. }) = (artifact.path.as_utf8(), &artifact.entry)
        else {
            continue;
        };
        if kin_index::FileClassifier::classify(std::path::Path::new(path))
            != kin_index::FileClassification::EntitySource
        {
            continue;
        }
        let source = super::read_publishable_source(&state.blobs, &authority.manager, *hash)
            .with_context(|| format!("read merged import-universe source: {path}"))?;
        if kin_blobs::digest(source.body()).0 != *hash.as_bytes() {
            return Err(merge_conflict(
                "merged import-universe source body does not match its tree digest",
            ));
        }
        if kin_index::FileClassifier::classify_with_content(
            std::path::Path::new(path),
            source.body(),
        ) == kin_index::FileClassification::EntitySource
        {
            known_files.insert(path.to_string());
        }
    }
    let pipeline = kin_index::IndexPipeline::new();
    for (id, artifact) in deferred {
        let Some(source) = tree.get(artifact) else {
            continue;
        };
        let Some(path) = source.path.as_utf8() else {
            return Err(merge_conflict(
                "merged parser coverage has an unsupported non-UTF8 source path",
            ));
        };
        if relations
            .get(id)
            .is_some_and(|held| !kin_index::is_parse_coverage_relation(held, path, *artifact))
        {
            return Err(merge_conflict(
                "merged parser coverage identity is occupied by a noncanonical relation",
            ));
        }
        let TreeEntry::Blob { hash, .. } = source.entry else {
            relations.remove(id);
            continue;
        };
        let body = super::read_publishable_source(&state.blobs, &authority.manager, hash)
            .with_context(|| format!("read merged source for parser coverage: {path}"))?;
        let indexed = pipeline
            .index_any_content(
                &kin_model::FilePathId::new(path),
                body.body(),
                kin_blobs::Hash256::from_bytes(*hash.as_bytes()),
            )
            .with_context(|| format!("derive merged parser coverage: {path}"))?;
        let kin_index::IndexedAny::EntitySource(indexed) = indexed else {
            relations.remove(id);
            continue;
        };
        let mut fresh = kin_index::build_parse_coverage_relation(
            &kin_index::FileParseData {
                file_path: path.to_string(),
                entities: indexed.entities,
                relations: indexed.extracted_relations,
                imports: indexed.imports,
            },
            *artifact,
            &kin_model::ParseCompleteness::from_parse_state(&indexed.parse_state),
            &known_files,
        );
        kin_index::bind_parse_coverage_source(&mut fresh, path, hash);
        if fresh.id != *id || !kin_index::is_parse_coverage_relation(&fresh, path, *artifact) {
            return Err(merge_conflict(
                "merged parser coverage does not match its deferred factory identity",
            ));
        }
        // Preserve the exact lifecycle stamp only where the complete proof is
        // unchanged. New evidence is authored by this merge's ordinary delta.
        for held in relations
            .get(id)
            .into_iter()
            .chain(inputs.iter().filter_map(|side| side.relations.get(id)))
        {
            fresh.created_in = held.created_in;
            if fresh == *held {
                break;
            }
            fresh.created_in = None;
        }
        relations.insert(*id, fresh);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{
        FilePathId, Hash256, RelationEvidence, RelationKind, RelationOrigin, RepoPath,
        ResolvedArtifact,
    };

    fn side(artifact: ArtifactId, body: &[u8]) -> ResolvedGraphState {
        side_at(artifact, "app.py", body)
    }

    fn side_at(artifact: ArtifactId, path: &str, body: &[u8]) -> ResolvedGraphState {
        let digest = kin_blobs::digest(body);
        let indexed = kin_index::IndexPipeline::new()
            .index_file_content_with_tests(&FilePathId::new(path), body, digest)
            .unwrap()
            .indexed_file;
        let mut relation = kin_index::build_parse_coverage_relation(
            &kin_index::FileParseData {
                file_path: path.into(),
                entities: indexed.entities,
                relations: indexed.extracted_relations,
                imports: indexed.imports,
            },
            artifact,
            &kin_model::ParseCompleteness::from_parse_state(&indexed.parse_state),
            &HashSet::<String>::new(),
        );
        kin_index::bind_parse_coverage_source(&mut relation, path, Hash256::from_bytes(digest.0));
        ResolvedGraphState {
            relations: [(relation.id, relation)].into(),
            tree: ResolvedTree::from_artifacts([ResolvedArtifact::new(
                artifact,
                RepoPath::from_utf8(path).unwrap(),
                TreeEntry::blob(Hash256::from_bytes(digest.0), false),
            )])
            .unwrap(),
            ..Default::default()
        }
    }

    fn sides() -> [ResolvedGraphState; 3] {
        let artifact = ArtifactId::new();
        [
            b"def run():\n    return 1\n".as_slice(),
            b"def run():\n    return 2\n",
            b"def run():\n    return 3\n",
        ]
        .map(|body| side(artifact, body))
    }

    #[test]
    fn authored_malformed_legacy_stale_and_unknown_relations_still_conflict() {
        for case in [
            "manual",
            "extra evidence",
            "legacy",
            "stale",
            "wrong path",
            "wrong endpoint",
            "unknown",
        ] {
            let mut inputs = sides();
            for (i, input) in inputs.iter_mut().enumerate() {
                let relation = input.relations.values_mut().next().unwrap();
                match case {
                    "manual" => relation.origin = RelationOrigin::Manual,
                    "extra evidence" => relation.evidence.push(RelationEvidence {
                        token: Some(i.to_string()),
                        ..Default::default()
                    }),
                    "legacy" => {
                        relation.evidence.pop();
                        relation.created_in = Some(kin_model::SemanticChangeId::from_hash(
                            Hash256::from_bytes([i as u8; 32]),
                        ));
                    }
                    "stale" => {
                        relation.evidence[2].token =
                            Some(Hash256::from_bytes([i as u8; 32]).to_string())
                    }
                    "wrong path" => relation.evidence[0].source_path = Some("elsewhere.py".into()),
                    "wrong endpoint" => relation.dst = GraphNodeId::Artifact(ArtifactId::new()),
                    "unknown" => {
                        relation.evidence[0].parser_rule = Some("future_coverage_v99".into())
                    }
                    _ => unreachable!(),
                }
            }
            let mut conflicts = vec![];
            let (merged, deferred) = compose_relations(
                [&inputs[0], &inputs[1], &inputs[2]],
                &BTreeSet::new(),
                &mut conflicts,
            )
            .unwrap();
            assert!(deferred.is_empty(), "{case}");
            assert!(merged.is_empty(), "{case}");
            assert_eq!(conflicts.len(), 1, "{case}");
        }
    }

    #[test]
    fn removed_or_concurrently_added_certificates_keep_exact_conflicts() {
        for absent in [0, 1, 2] {
            let mut inputs = sides();
            inputs[absent].relations.clear();
            let mut conflicts = vec![];
            let (_, deferred) = compose_relations(
                [&inputs[0], &inputs[1], &inputs[2]],
                &BTreeSet::new(),
                &mut conflicts,
            )
            .unwrap();
            assert!(deferred.is_empty());
            assert_eq!(conflicts.len(), 1);
        }
    }

    #[test]
    fn one_unowned_side_prevents_automatic_ownership() {
        let mut inputs = sides();
        inputs[1].relations.values_mut().next().unwrap().origin = RelationOrigin::Manual;
        let mut conflicts = vec![];
        let (_, deferred) = compose_relations(
            [&inputs[0], &inputs[1], &inputs[2]],
            &BTreeSet::new(),
            &mut conflicts,
        )
        .unwrap();
        assert!(deferred.is_empty());
        assert_eq!(conflicts.len(), 1);
    }

    #[test]
    fn recorded_certificate_conflicts_keep_the_exact_old_side_bindings() {
        let inputs = sides();
        let refs = [&inputs[0], &inputs[1], &inputs[2]];
        let mut old = vec![];
        compose(
            &inputs[0].relations,
            &inputs[1].relations,
            &inputs[2].relations,
            |relation| MergeConflictSubject::Relation {
                relation: *relation,
            },
            MergeSideValue::relation,
            |_| None,
            |left, right| left == right,
            &mut old,
        )
        .unwrap();
        let recorded = inputs[0].relations.keys().copied().collect();
        let mut current = vec![];
        let (_, deferred) = compose_relations(refs, &recorded, &mut current).unwrap();
        assert_eq!(
            current, old,
            "a persisted record's content digests and exact subject cannot change after upgrade"
        );
        assert!(deferred.is_empty());
        // Legacy explicit side choices are not silently rewritten. They still
        // need the existing live source-binding check: selecting an unrelated
        // certificate side cannot prove the selected body current.
        let chosen = inputs[2].relations.values().next().unwrap();
        let ours = inputs[1].tree.artifacts().next().unwrap();
        let TreeEntry::Blob { hash, .. } = ours.entry else {
            unreachable!()
        };
        assert_ne!(kin_index::parse_coverage_source_digest(chosen), Some(hash));
    }

    #[test]
    fn actual_binding_debt_is_not_treated_as_parser_coverage() {
        use kin_index::binding_debt::{
            build_local_binding_debt, LocalBindingDebt, LocalBindingObligation,
        };
        let mut inputs = sides();
        let artifact = inputs[0].tree.artifacts().next().unwrap().artifact_id;
        let retired = Relation {
            id: RelationId::new(),
            kind: RelationKind::Calls,
            src: GraphNodeId::Entity(kin_model::EntityId::new()),
            dst: GraphNodeId::Entity(kin_model::EntityId::new()),
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: Some("local".into()),
            evidence: vec![],
        };
        let target_artifact = ArtifactId::new();
        for input in &mut inputs {
            let digest =
                kin_index::parse_coverage_source_digest(input.relations.values().next().unwrap())
                    .unwrap();
            let debt = build_local_binding_debt(
                artifact,
                LocalBindingDebt {
                    source_file: FilePathId::new("app.py"),
                    observed_source_digest: digest,
                    obligations: vec![LocalBindingObligation {
                        retired_relation: retired.clone(),
                        source_name: "run".into(),
                        source_digest: digest,
                        prior_source_file: None,
                        target_artifact,
                        target_file: FilePathId::new("local.py"),
                        target_name: "work".into(),
                    }],
                },
            )
            .unwrap();
            input.relations.insert(debt.id, debt);
        }
        let mut conflicts = vec![];
        let (_, deferred) = compose_relations(
            [&inputs[0], &inputs[1], &inputs[2]],
            &BTreeSet::new(),
            &mut conflicts,
        )
        .unwrap();
        assert_eq!(deferred.len(), 1);
        assert_eq!(conflicts.len(), 1);
        assert_eq!(
            conflicts[0].subject,
            MergeConflictSubject::Relation {
                relation: kin_index::binding_debt::local_binding_debt_id(artifact)
            }
        );
    }

    #[test]
    fn derivation_uses_final_body_and_final_import_universe_and_refuses_missing_cas() {
        let root = tempfile::tempdir().unwrap();
        let init = kin_core::init(root.path()).unwrap();
        let state = DaemonState::open(init.layout).unwrap();
        let authority = ActiveLocalRepositoryAuthority::open(&state).unwrap();
        let artifact = ArtifactId::new();
        let body = b"from local import work\n\ndef run():\n    return work()\n";
        let input = side(artifact, body);
        let refs = [&input, &input, &input];
        let mut relations = HashMap::new();
        let deferred = input.relations.keys().map(|id| (*id, artifact)).collect();
        let empty = relations.clone();
        assert!(rederive(
            &state,
            &authority,
            refs,
            &deferred,
            &input.tree,
            &mut relations
        )
        .is_err());
        assert_eq!(relations, empty);
        state.blobs.write(body).unwrap();
        rederive(
            &state,
            &authority,
            refs,
            &deferred,
            &input.tree,
            &mut relations,
        )
        .unwrap();
        assert_eq!(
            relations.values().next().unwrap().evidence[1]
                .token
                .as_deref(),
            Some("0")
        );
        let local = ResolvedArtifact::new(
            ArtifactId::new(),
            RepoPath::from_utf8("local.py").unwrap(),
            TreeEntry::blob(
                Hash256::from_bytes(state.blobs.write(b"def work():\n    return 1\n").unwrap().0),
                false,
            ),
        );
        let tree =
            ResolvedTree::from_artifacts(input.tree.artifacts().cloned().chain([local])).unwrap();
        rederive(&state, &authority, refs, &deferred, &tree, &mut relations).unwrap();
        assert_eq!(
            relations.values().next().unwrap().evidence[1]
                .token
                .as_deref(),
            Some("1"),
            "do not copy old import counts from a selected branch"
        );
        assert_eq!(
            relations.values().next().unwrap().evidence[1].occurrence_count,
            1
        );
        for (path, body, expected) in [
            ("local.py", b"\0opaque python suffix".as_slice(), "0"),
            ("local.py", b"".as_slice(), "1"),
        ] {
            let other = ResolvedArtifact::new(
                ArtifactId::new(),
                RepoPath::from_utf8(path).unwrap(),
                TreeEntry::blob(
                    Hash256::from_bytes(state.blobs.write(body).unwrap().0),
                    false,
                ),
            );
            let tree = ResolvedTree::from_artifacts(input.tree.artifacts().cloned().chain([other]))
                .unwrap();
            rederive(&state, &authority, refs, &deferred, &tree, &mut relations).unwrap();
            assert_eq!(
                relations.values().next().unwrap().evidence[1]
                    .token
                    .as_deref(),
                Some(expected),
                "content classification must distinguish opaque from empty semantic {path}"
            );
        }
        // Syntax failure is observed as incomplete, never promoted from held Full.
        let broken = b"def run(\n";
        let hash = Hash256::from_bytes(state.blobs.write(broken).unwrap().0);
        let tree = ResolvedTree::from_artifacts([ResolvedArtifact::new(
            artifact,
            RepoPath::from_utf8("app.py").unwrap(),
            TreeEntry::blob(hash, false),
        )])
        .unwrap();
        rederive(&state, &authority, refs, &deferred, &tree, &mut relations).unwrap();
        let certificate = relations.values().next().unwrap();
        assert_ne!(
            certificate.evidence[0].parser_rule.as_deref(),
            Some(kin_index::CALL_SHAPE_PARSE_COVERAGE_FULL_V1)
        );
        assert_eq!(
            kin_index::parse_coverage_source_digest(certificate),
            Some(hash)
        );
    }
    #[test]
    fn javascript_explicit_non_source_import_is_not_counted_as_semantic_resolution() {
        let root = tempfile::tempdir().unwrap();
        let state = DaemonState::open(kin_core::init(root.path()).unwrap().layout).unwrap();
        let authority = ActiveLocalRepositoryAuthority::open(&state).unwrap();
        let artifact = ArtifactId::new();
        let body = b"const data = require('./local.json');\nfunction run() { return data(); }\n";
        state.blobs.write(body).unwrap();
        let input = side_at(artifact, "app.js", body);
        let deferred = input.relations.keys().map(|id| (*id, artifact)).collect();
        let other = ResolvedArtifact::new(
            ArtifactId::new(),
            RepoPath::from_utf8("local.json").unwrap(),
            TreeEntry::blob(
                Hash256::from_bytes(state.blobs.write(b"{}").unwrap().0),
                false,
            ),
        );
        let tree =
            ResolvedTree::from_artifacts(input.tree.artifacts().cloned().chain([other])).unwrap();
        let mut relations = HashMap::new();
        rederive(
            &state,
            &authority,
            [&input, &input, &input],
            &deferred,
            &tree,
            &mut relations,
        )
        .unwrap();
        let imports = &relations.values().next().unwrap().evidence[1];
        assert_eq!(imports.occurrence_count, 1);
        assert_eq!(imports.token.as_deref(), Some("0"));
    }
}
