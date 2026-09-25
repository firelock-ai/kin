// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use kin_blobs::BlobStore;
use kin_index::key_domain::{
    analyze_imported_keys, ExhaustiveKeyDomain, KeyDomainAssumptions, KeyDomainCondition,
    KeyDomainLimits, RefusalKind, WitnessRole,
};
use kin_model::{ArtifactId, RepoPath, ResolvedArtifact, ResolvedTree, TreeEntry};

const EXPORT: &str = "const names = ['ALPHA', 'MiXeD', 'ALPHA']; exports.names = names;";
const IMPORT: &str = "const keys = require('./keys').names; const owner = {}; const lowered = keys.map(item => item.toLowerCase()); lowered.forEach(function(key) { owner[key] = function(value) { return value; }; });";

fn assumptions() -> KeyDomainAssumptions {
    KeyDomainAssumptions::new([
        KeyDomainCondition::StandardArrayMap,
        KeyDomainCondition::StandardAsciiStringLowercase,
        KeyDomainCondition::StandardArrayForEach,
        KeyDomainCondition::StandardCommonJsLoader,
        KeyDomainCondition::ClosedInspectedCommonJsExecution,
    ])
}

struct Fixture {
    temp: tempfile::TempDir,
    store: BlobStore,
    tree: ResolvedTree,
    importer: ArtifactId,
}

impl Fixture {
    fn new(extra: &[(&str, &str)]) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let store = BlobStore::new(temp.path().join("blobs")).unwrap();
        let mut artifacts = Vec::new();
        let importer = ArtifactId::new();
        for (path, source) in [("src/keys.js", EXPORT), ("src/use.js", IMPORT)]
            .into_iter()
            .chain(extra.iter().copied())
        {
            artifacts.push(ResolvedArtifact::new(
                if path == "src/use.js" {
                    importer
                } else {
                    ArtifactId::new()
                },
                RepoPath::from_utf8(path).unwrap(),
                TreeEntry::blob(store.write(source.as_bytes()).unwrap(), false),
            ));
        }
        Self {
            temp,
            store,
            tree: ResolvedTree::from_artifacts(artifacts).unwrap(),
            importer,
        }
    }

    fn replace(&mut self, path: &str, source: &str) {
        let mut artifacts: Vec<_> = self.tree.artifacts().cloned().collect();
        artifacts
            .iter_mut()
            .find(|item| item.path.as_utf8() == Some(path))
            .unwrap()
            .entry = TreeEntry::blob(self.store.write(source.as_bytes()).unwrap(), false);
        self.tree = ResolvedTree::from_artifacts(artifacts).unwrap();
    }

    fn analyze(&self) -> Result<ExhaustiveKeyDomain, kin_index::key_domain::KeyDomainRefusal> {
        analyze_imported_keys(
            &self.tree,
            &self.store,
            self.importer,
            "keys",
            KeyDomainLimits::default(),
            &assumptions(),
        )
    }
}

#[test]
fn conditional_domain_binds_exact_cas_spans_and_serialized_tree_reopen() {
    let fixture = Fixture::new(&[
        ("README.md", "not JavaScript"),
        ("package.json", "{\"type\":\"commonjs\"}"),
        ("src/inert.js", "module.exports = {};"),
    ]);
    let result = fixture.analyze().unwrap();
    assert_eq!(result.keys(), ["alpha", "mixed"]);
    assert_eq!(result.javascript_modules(), 3);
    assert_eq!(result.excluded_artifacts(), 1);
    assert_eq!(result.conditions().len(), 5);
    assert_eq!(result.witnesses().len(), 4);
    for witness in result.witnesses() {
        let artifact = fixture.tree.get(&witness.artifact).unwrap();
        assert_eq!(artifact.path, witness.path);
        assert_eq!(artifact.entry.blob_identity(), Some(witness.body_digest));
        let source = fixture.store.read(&witness.body_digest).unwrap();
        for span in &witness.spans {
            assert_eq!(span.file.0, witness.path.as_utf8().unwrap());
            assert!(span.start_byte < span.end_byte && span.end_byte <= source.len());
        }
        if matches!(
            witness.role,
            WitnessRole::Export | WitnessRole::ImportIteration
        ) {
            assert!(!witness.spans.is_empty());
        }
    }
    let wire = serde_json::to_value(&result).unwrap();
    assert_eq!(wire["analyzer_version"], 1);
    assert!(wire.get("conditions").is_some());
    assert!(
        wire.get("exhaustive").is_none(),
        "no unqualified exhaustive flag"
    );
    let reopened_tree: ResolvedTree =
        serde_json::from_slice(&serde_json::to_vec(&fixture.tree).unwrap()).unwrap();
    let reopened_store = BlobStore::new(fixture.temp.path().join("blobs")).unwrap();
    let reopened = analyze_imported_keys(
        &reopened_tree,
        &reopened_store,
        fixture.importer,
        "keys",
        KeyDomainLimits::default(),
        &assumptions(),
    )
    .unwrap();
    assert_eq!(
        serde_json::to_value(result).unwrap(),
        serde_json::to_value(reopened).unwrap()
    );
}

#[test]
fn no_implicit_intrinsic_or_loader_assumptions() {
    let fixture = Fixture::new(&[]);
    for conditions in [
        KeyDomainAssumptions::default(),
        KeyDomainAssumptions::new([
            KeyDomainCondition::StandardArrayMap,
            KeyDomainCondition::StandardAsciiStringLowercase,
            KeyDomainCondition::StandardArrayForEach,
        ]),
        KeyDomainAssumptions::new([
            KeyDomainCondition::StandardCommonJsLoader,
            KeyDomainCondition::ClosedInspectedCommonJsExecution,
            KeyDomainCondition::StandardArrayForEach,
        ]),
    ] {
        let failure = analyze_imported_keys(
            &fixture.tree,
            &fixture.store,
            fixture.importer,
            "keys",
            KeyDomainLimits::default(),
            &conditions,
        )
        .unwrap_err();
        assert_eq!(failure.kind, RefusalKind::MissingAssumption);
    }
}

#[test]
fn export_mapping_and_empty_domain_are_source_proved_not_candidate_defaults() {
    let mut fixture = Fixture::new(&[]);
    fixture.replace(
        "src/keys.js",
        "const names = ['A', 'b']; exports.names = names.map(key => key.toLowerCase());",
    );
    fixture.replace(
        "src/use.js",
        &IMPORT
            .replace("const lowered = keys.map(item => item.toLowerCase()); ", "")
            .replace("lowered.forEach", "keys.forEach"),
    );
    assert_eq!(fixture.analyze().unwrap().keys(), ["a", "b"]);
    fixture.replace("src/keys.js", "const names = []; exports.names = names;");
    let empty = fixture.analyze().unwrap();
    assert!(empty.keys().is_empty());
    assert_eq!(empty.conditions().len(), 3);
    fixture.replace(
        "src/keys.js",
        "const names = unknown; exports.names = names;",
    );
    assert_eq!(
        fixture.analyze().unwrap_err().kind,
        RefusalKind::UnsupportedSource
    );
}

#[test]
fn current_tree_bytes_choose_domain_and_reject_mutated_or_escaped_bindings() {
    let mut fixture = Fixture::new(&[]);
    let before = fixture.analyze().unwrap();
    fixture.replace(
        "src/keys.js",
        "const names = ['CHANGED']; exports.names = names;",
    );
    let after = fixture.analyze().unwrap();
    assert_eq!(after.keys(), ["changed"]);
    assert_ne!(before.tree_digest(), after.tree_digest());
    for source in [
        "const names = ['A']; names.push('router'); exports.names = names;",
        "const names = ['A']; exports.names = names; exports.names = other;",
        "const names = ['A']; globalThis.leaked = names; exports.names = names;",
        "const names = [,]; exports.names = names;",
    ] {
        fixture.replace("src/keys.js", source);
        assert_eq!(
            fixture.analyze().unwrap_err().kind,
            RefusalKind::UnsupportedSource,
            "{source}"
        );
    }
    fixture.replace("src/keys.js", EXPORT);
    for source in [
        IMPORT.replace("return value;", "return keys;"),
        IMPORT.replace("owner[key] =", "key = 'router'; owner[key] ="),
        IMPORT.replace(
            "const owner = {};",
            "const owner = {}; keys.push('router');",
        ),
        IMPORT.replace("function(key)", "function(keys)"),
    ] {
        fixture.replace("src/use.js", &source);
        assert_eq!(
            fixture.analyze().unwrap_err().kind,
            RefusalKind::UnsupportedSource,
            "{source}"
        );
    }
}

#[test]
fn unknown_ambiguous_and_additional_consumers_never_yield_partial_domains() {
    for source in [
        "const copied = require('./keys').names; copied.push('router');",
        "function later() { return require('./keys'); }",
    ] {
        let fixture = Fixture::new(&[("src/other.js", source)]);
        assert_eq!(
            fixture.analyze().unwrap_err().kind,
            RefusalKind::AdditionalConsumer
        );
    }
    for source in [
        "const load = require; load('./keys');",
        "require(someName);",
        "module.require('./keys');",
        "import('./keys');",
        "const load = ({}).constructor.constructor(code);",
        "holder['require']('./keys');",
    ] {
        let fixture = Fixture::new(&[("src/other.js", source)]);
        assert_eq!(
            fixture.analyze().unwrap_err().kind,
            RefusalKind::UnsupportedSource,
            "{source}"
        );
    }
    for source in [
        "require('./missing');",
        "require('external');",
        "require('../../outside');",
    ] {
        let fixture = Fixture::new(&[("src/other.js", source)]);
        assert_eq!(
            fixture.analyze().unwrap_err().kind,
            RefusalKind::ModuleResolution,
            "{source}"
        );
    }
    let fixture = Fixture::new(&[("src/keys/index.js", "module.exports = {};")]);
    assert_eq!(
        fixture.analyze().unwrap_err().kind,
        RefusalKind::ModuleResolution
    );
}

#[test]
fn inventory_refuses_visible_intrinsic_mutation_in_another_module() {
    for source in ["Array = custom;", "Object.getPrototypeOf([]).map = custom;"] {
        let fixture = Fixture::new(&[("src/other.js", source)]);
        assert_eq!(
            fixture.analyze().unwrap_err().kind,
            RefusalKind::UnsupportedSource,
            "{source}"
        );
    }
}

#[test]
fn inventory_refuses_computed_loader_escape_in_another_module() {
    for source in [
        r#"(function() { this['ev' + 'al']("process.mainModule.require('./keys').names.push('router')"); })();"#,
        r#"(function() { const load = this['ev' + 'al']; load("process.mainModule.require('./keys')"); })();"#,
        r#"const { ['con' + 'structor']: make } = function() {}; make(code)();"#,
    ] {
        let fixture = Fixture::new(&[("src/other.js", source)]);
        assert_eq!(
            fixture.analyze().unwrap_err().kind,
            RefusalKind::UnsupportedSource,
            "{source}"
        );
    }
}

#[test]
fn inventory_limits_refuse_before_a_partial_success() {
    let fixture = Fixture::new(&[]);
    let defaults = KeyDomainLimits::default();
    for limits in [
        KeyDomainLimits {
            tree_artifacts: 1,
            ..defaults
        },
        KeyDomainLimits {
            tree_path_bytes: 1,
            ..defaults
        },
        KeyDomainLimits {
            javascript_modules: 1,
            ..defaults
        },
        KeyDomainLimits {
            body_bytes: 1,
            ..defaults
        },
        KeyDomainLimits {
            total_body_bytes: 1,
            ..defaults
        },
        KeyDomainLimits {
            require_sites: 0,
            ..defaults
        },
        KeyDomainLimits {
            keys: 1,
            ..defaults
        },
    ] {
        let failure = analyze_imported_keys(
            &fixture.tree,
            &fixture.store,
            fixture.importer,
            "keys",
            limits,
            &assumptions(),
        )
        .unwrap_err();
        assert_eq!(failure.kind, RefusalKind::Limit, "{limits:?}: {failure}");
    }
    assert!(
        fixture.analyze().is_ok(),
        "refused analysis does not mutate evidence"
    );
}

#[test]
fn unsupported_source_classes_and_nonregular_inventory_refuse() {
    for (path, source) in [
        ("src/hidden.mjs", "export {};"),
        ("src/hidden.ts", ""),
        ("bin/runner", ""),
        ("package.json", "{\"type\":\"module\"}"),
        ("package.json", "{"),
    ] {
        let fixture = Fixture::new(&[(path, source)]);
        assert_eq!(
            fixture.analyze().unwrap_err().kind,
            RefusalKind::UnsupportedInventory,
            "{path}"
        );
    }
    let mut fixture = Fixture::new(&[]);
    let mut artifacts: Vec<_> = fixture.tree.artifacts().cloned().collect();
    artifacts.push(ResolvedArtifact::new(
        ArtifactId::new(),
        RepoPath::from_utf8("src/unknown.js").unwrap(),
        TreeEntry::symlink(fixture.store.write(b"../other.js").unwrap()),
    ));
    fixture.tree = ResolvedTree::from_artifacts(artifacts).unwrap();
    assert_eq!(
        fixture.analyze().unwrap_err().kind,
        RefusalKind::UnsupportedInventory
    );
}

#[test]
fn identity_missing_body_and_corrupt_cas_refuse_without_projection_fallback() {
    let mut fixture = Fixture::new(&[]);
    assert_eq!(
        analyze_imported_keys(
            &fixture.tree,
            &fixture.store,
            ArtifactId::new(),
            "keys",
            KeyDomainLimits::default(),
            &assumptions()
        )
        .unwrap_err()
        .kind,
        RefusalKind::MissingArtifact
    );
    let producer_path = RepoPath::from_utf8("src/keys.js").unwrap();
    let producer = fixture
        .tree
        .artifact_at_path(&producer_path)
        .unwrap()
        .clone();
    let original_hash = producer.entry.blob_identity().unwrap();
    let mut artifacts: Vec<_> = fixture.tree.artifacts().cloned().collect();
    artifacts
        .iter_mut()
        .find(|item| item.artifact_id == producer.artifact_id)
        .unwrap()
        .entry = TreeEntry::blob(kin_blobs::digest(b"not written"), false);
    fixture.tree = ResolvedTree::from_artifacts(artifacts).unwrap();
    assert_eq!(
        fixture.analyze().unwrap_err().kind,
        RefusalKind::UnavailableBody
    );
    let mut artifacts: Vec<_> = fixture.tree.artifacts().cloned().collect();
    artifacts
        .iter_mut()
        .find(|item| item.artifact_id == producer.artifact_id)
        .unwrap()
        .entry = producer.entry;
    fixture.tree = ResolvedTree::from_artifacts(artifacts).unwrap();
    // Deliberate CAS corruption is test IO, not an alternate source reader.
    let hex = original_hash.to_string();
    let blob = fixture.store.root().join(&hex[..2]).join(&hex[2..]);
    std::fs::write(&blob, b"corrupt bytes").unwrap();
    assert_eq!(
        fixture.analyze().unwrap_err().kind,
        RefusalKind::UnavailableBody
    );
    assert!(
        !blob.exists(),
        "BlobStore preserves corrupt evidence in quarantine"
    );
}
