// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use kin_index::{FileParseData, IncrementalLinker, IndexPipeline};
use kin_model::{ArtifactId, FilePathId, Relation, RelationKind, RelationOrigin};
use std::collections::HashMap;

fn parse(file: &str, body: &str) -> FileParseData {
    let indexed = IndexPipeline::new()
        .index_file_content_with_tests(
            &FilePathId::new(file),
            body.as_bytes(),
            kin_blobs::digest(body.as_bytes()),
        )
        .unwrap()
        .indexed_file;
    FileParseData {
        file_path: file.into(),
        entities: indexed.entities,
        relations: indexed.extracted_relations,
        imports: indexed.imports,
    }
}

fn fixture() -> (FileParseData, Relation, Relation) {
    let caller = parse("caller.py", "from local import work as left, work as right\ndef run():\n    return left(value=1) + right(value=2)\n");
    let target = parse("local.py", "def work(value):\n    return value\n");
    let files = vec![caller.clone(), target];
    let artifacts = files
        .iter()
        .map(|f| (f.file_path.clone(), ArtifactId::new()))
        .collect::<HashMap<_, _>>();
    let mut universe = IncrementalLinker::new();
    for file in &files {
        universe.add_file(&file.file_path, artifacts[&file.file_path], &file.entities);
    }
    // This is the actual declaration-only reconstruction used by move planning.
    let plain = kin_index::link_cross_file_incremental(std::slice::from_ref(&caller), &universe)
        .unwrap()
        .into_iter()
        .find(|r| r.kind == RelationKind::Calls)
        .unwrap();
    let canonical = kin_index::link_cross_file(&files, &artifacts)
        .unwrap()
        .into_iter()
        .find(|r| r.kind == RelationKind::Calls)
        .unwrap();
    assert_eq!(plain.id, canonical.id);
    let plain_records = kin_index::occurrence::uniform_original_evidence(&plain).unwrap();
    let canonical_records = kin_index::occurrence::uniform_original_evidence(&canonical).unwrap();
    assert_eq!(plain_records.len(), 2);
    assert!(plain_records.iter().all(|e| e.token.is_none()));
    assert!(canonical_records.iter().all(|e| e.token.is_some()));
    (caller, plain, canonical)
}

#[test]
fn named_import_reproduction_restores_only_exact_source_occurrences() {
    let (caller, plain, canonical) = fixture();
    assert_eq!(
        kin_index::linker::reproduce_named_import_evidence(
            &caller,
            &FilePathId::new("caller.py"),
            &plain,
            "local.py"
        ),
        Some(canonical.clone())
    );
    assert_eq!(
        kin_index::linker::reproduce_named_import_evidence(
            &caller,
            &FilePathId::new("caller.py"),
            &canonical,
            "local.py"
        ),
        Some(canonical)
    );
}

#[test]
fn named_import_reproduction_preserves_explicit_relocated_spans_and_prior_target_path() {
    let (caller, mut plain, mut canonical) = fixture();
    for relation in [&mut plain, &mut canonical] {
        // This legacy relocation control predates occurrence certificates.
        relation.evidence = kin_index::occurrence::original_evidence(relation)
            .unwrap()
            .into_iter()
            .cloned()
            .collect();
        for evidence in &mut relation.evidence {
            evidence.source_span.as_mut().unwrap().file = FilePathId::new("moved/caller.py");
        }
    }
    assert_eq!(
        kin_index::linker::reproduce_named_import_evidence(
            &caller,
            &FilePathId::new("moved/caller.py"),
            &plain,
            "local.py"
        ),
        Some(canonical)
    );
    // This factory takes no target inventory: matching source syntax is not a
    // present-day destination proof. The caller must retain that separate gate.
}

#[test]
fn named_import_reproduction_refuses_foreign_or_mutated_evidence() {
    let (caller, plain, canonical) = fixture();
    for mutation in [
        "token",
        "module",
        "target",
        "count",
        "span",
        "rule",
        "duplicate",
        "manual",
        "lsp",
        "identity",
        "confidence",
    ] {
        let mut bad = plain.clone();
        // Mutate an original occurrence, not a span-free metadata record.
        bad.evidence
            .sort_by_key(|record| record.source_span.is_none());
        match mutation {
            "token" => bad.evidence[0].token = Some("other".into()),
            "module" => bad.evidence[0].source_path = Some("other".into()),
            "target" => {
                bad = canonical.clone();
                bad.evidence
                    .sort_by_key(|record| record.source_span.is_none());
                bad.evidence[0].resolved_path = Some("other.py".into());
            }
            "count" => bad.evidence[0].occurrence_count += 1,
            "span" => bad.evidence[0].source_span.as_mut().unwrap().start_byte += 1,
            "rule" => bad.evidence[0].parser_rule = Some("foreign".into()),
            "duplicate" => bad.evidence.push(bad.evidence[0].clone()),
            "manual" => bad.origin = RelationOrigin::Manual,
            "lsp" => bad.origin = RelationOrigin::Lsp,
            "identity" => bad.id = kin_model::RelationId::new(),
            "confidence" => bad.confidence = 0.7,
            _ => unreachable!(),
        }
        assert!(
            kin_index::linker::reproduce_named_import_evidence(
                &caller,
                &FilePathId::new("caller.py"),
                &bad,
                "local.py"
            )
            .is_none(),
            "{mutation}"
        );
    }
}

#[test]
fn named_import_reproduction_refuses_missing_duplicate_stale_or_shadowed_source_pins() {
    let (caller, plain, _) = fixture();
    for mutation in ["missing", "duplicate", "stale", "shadowed"] {
        let mut bad = caller.clone();
        match mutation {
            "missing" => bad.relations.retain(|r| !kin_parser::import_witness::claims_import_witness(r)),
            "duplicate" => bad.relations.push(bad.relations.iter().find(|r| kin_parser::import_witness::claims_import_witness(r)).unwrap().clone()),
            "stale" => { bad.entities[0].metadata.extra.insert("blob_hash".into(), serde_json::json!("0".repeat(64))); }
            "shadowed" => bad = parse("caller.py", "from local import work as left, work as right\ndef run(left, right):\n    return left(value=1) + right(value=2)\n"),
            _ => unreachable!(),
        }
        assert!(
            kin_index::linker::reproduce_named_import_evidence(
                &bad,
                &FilePathId::new("caller.py"),
                &plain,
                "local.py"
            )
            .is_none(),
            "{mutation}"
        );
    }
}
