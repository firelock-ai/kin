// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use kin_index::{
    linker::{link_cross_file_with_rust_project, named_import_observations, ArtifactIdentityMap},
    rust_project::{RustProjectAuthority, RustProjectLimits},
    FileParseCompletenessMap, FileParseData, IncrementalLinker, IndexPipeline,
};
use kin_model::{
    ArtifactId, Entity, FilePathId, Hash256, RepoPath, ResolvedArtifact, ResolvedTree, TreeEntry,
};
use std::collections::BTreeMap;

const MANIFEST: &str = "[package]\nname='fixture'\nedition='2021'\n";

struct Fixture {
    tree: ResolvedTree,
    blobs: BTreeMap<Hash256, Vec<u8>>,
    entities: Vec<Entity>,
    parsed: Vec<FileParseData>,
    completeness: FileParseCompletenessMap,
    identities: ArtifactIdentityMap,
}

fn fixture(files: &[(&str, &str)]) -> Fixture {
    let mut artifacts = Vec::new();
    let mut blobs = BTreeMap::new();
    let mut entities = Vec::new();
    let mut parsed = Vec::new();
    let mut completeness = FileParseCompletenessMap::new();
    let mut identities = ArtifactIdentityMap::new();
    for (file, source) in files {
        let bytes = source.as_bytes().to_vec();
        let hash = kin_blobs::digest(&bytes);
        blobs.insert(hash, bytes.clone());
        let id = ArtifactId::new();
        identities.insert((*file).to_owned(), id);
        artifacts.push(ResolvedArtifact::new(
            id,
            RepoPath::from_utf8(*file).unwrap(),
            TreeEntry::Blob {
                hash,
                executable: false,
            },
        ));
        if file.ends_with(".rs") {
            let indexed = IndexPipeline::new()
                .index_file_content_with_tests(&FilePathId::new(*file), &bytes, hash)
                .unwrap()
                .indexed_file;
            completeness.insert((*file).into(), indexed.file_layout.parse_completeness);
            parsed.push(FileParseData {
                file_path: (*file).into(),
                entities: indexed.entities.clone(),
                relations: indexed.extracted_relations,
                imports: indexed.imports,
            });
            entities.extend(indexed.entities);
        }
    }
    Fixture {
        tree: ResolvedTree::from_artifacts(artifacts).unwrap(),
        blobs,
        entities,
        parsed,
        completeness,
        identities,
    }
}

impl Fixture {
    fn authority(&self) -> Result<RustProjectAuthority, String> {
        let mut result = RustProjectAuthority::from_admitted_tree(
            &self.tree,
            RustProjectLimits::default(),
            |hash| {
                self.blobs
                    .get(&hash)
                    .cloned()
                    .ok_or("missing test CAS".into())
            },
        )?;
        result.bind_entities(&self.entities)?;
        Ok(result)
    }
    fn id(&self, file: &str, name: &str) -> kin_model::EntityId {
        let found: Vec<_> = self
            .entities
            .iter()
            .filter(|e| {
                e.name == name && e.file_origin.as_ref().map(|f| f.0.as_str()) == Some(file)
            })
            .collect();
        assert_eq!(found.len(), 1);
        found[0].id
    }
}

#[test]
fn admitted_custom_root_resolves_exact_owner_and_retains_decoy_refusal() {
    let caller = "use crate::owner::work; pub fn run() { work(); }";
    let f = fixture(&[("Cargo.toml", "[package]\nname='fixture'\nedition='2021'\nautolib=false\nautobins=false\n[lib]\npath='app.rs'\n"),
        ("app.rs", "pub mod owner; #[path=\"leaf/user.rs\"] pub mod user;"),
        ("owner.rs", "pub fn work() {}"), ("leaf/user.rs", caller),
        ("leaf/owner.rs", "pub fn work() {}"), ("src/lib.rs", "pub mod owner;"), ("src/owner.rs", "pub fn work() {}")]);
    let authority = f.authority().unwrap();
    assert_eq!(authority.targets().len(), 1);
    assert_eq!(authority.targets()[0].root, "app.rs");
    assert_eq!(
        authority.resolve_entity(
            "leaf/user.rs",
            caller.find("work();").unwrap(),
            "crate::owner",
            "work"
        ),
        Some((f.id("owner.rs", "work"), "owner.rs".into()))
    );
    assert!(!authority.contains_source("leaf/owner.rs"));
    assert!(!authority.contains_source("src/lib.rs"));
}

#[test]
fn nested_main_is_a_module_and_empty_use_only_hops_have_body_authority() {
    let caller = "use crate::bridge::work; pub fn run() { work(); }";
    let f = fixture(&[
        ("Cargo.toml", MANIFEST),
        (
            "src/lib.rs",
            "pub mod outer; pub mod bridge; pub mod user; pub mod empty;",
        ),
        ("src/outer.rs", "pub mod main;"),
        ("src/outer/main.rs", "pub mod target;"),
        ("src/outer/main/target.rs", "pub fn work() {}"),
        ("src/outer/target.rs", "pub fn work() {}"),
        ("src/bridge.rs", "pub use crate::outer::main::target::work;"),
        ("src/empty.rs", ""),
        ("src/user.rs", caller),
    ]);
    let authority = f.authority().unwrap();
    assert_eq!(
        authority.resolve_entity(
            "src/user.rs",
            caller.find("work();").unwrap(),
            "crate::bridge",
            "work"
        ),
        Some((
            f.id("src/outer/main/target.rs", "work"),
            "src/outer/main/target.rs".into()
        ))
    );
    for path in ["src/bridge.rs", "src/empty.rs", "Cargo.toml"] {
        assert!(authority.source_bindings().contains_key(path));
    }
}

#[test]
fn all_target_memberships_must_agree_on_exact_entity() {
    let caller = "use crate::target::work; pub fn run() { work(); }";
    let f = fixture(&[("Cargo.toml", "[package]\nname='fixture'\nedition='2021'\nautobins=false\nautolib=false\n[[bin]]\nname='a'\npath='one/main.rs'\n[[bin]]\nname='b'\npath='two/main.rs'\n"),
        ("one/main.rs", "pub mod target; #[path=\"../shared.rs\"] pub mod shared;"),
        ("two/main.rs", "pub mod target; #[path=\"../shared.rs\"] pub mod shared;"),
        ("one/target.rs", "pub fn work() {}"), ("two/target.rs", "pub fn work() {}"), ("shared.rs", caller)]);
    let authority = f.authority().unwrap();
    assert_eq!(authority.targets().len(), 2);
    assert!(authority
        .resolve_entity(
            "shared.rs",
            caller.find("work();").unwrap(),
            "crate::target",
            "work"
        )
        .is_none());
}

#[test]
fn build_script_is_an_independent_target_and_can_disagree_with_library() {
    let caller = "use crate::target::work; pub fn run() { work(); }";
    let files = [
        ("Cargo.toml", MANIFEST),
        (
            "src/lib.rs",
            "pub mod target; #[path=\"../shared.rs\"] pub mod shared;",
        ),
        (
            "build.rs",
            "pub mod target; #[path=\"shared.rs\"] pub mod shared; fn main() {}",
        ),
        ("src/target.rs", "pub fn work() {}"),
        ("target.rs", "pub fn work() {}"),
        ("shared.rs", caller),
    ];
    let f = fixture(&files);
    let authority = f.authority().unwrap();
    assert!(authority
        .targets()
        .iter()
        .any(|target| target.kind == "build" && target.root == "build.rs"));
    assert!(authority
        .resolve_entity(
            "shared.rs",
            caller.find("work();").unwrap(),
            "crate::target",
            "work"
        )
        .is_none());
    let mut disabled = files;
    disabled[0].1 = "[package]\nname='fixture'\nedition='2021'\nbuild=false\n";
    let f = fixture(&disabled);
    let authority = f.authority().unwrap();
    assert_eq!(authority.targets().len(), 1);
    assert_eq!(
        authority.resolve_entity(
            "shared.rs",
            caller.find("work();").unwrap(),
            "crate::target",
            "work"
        ),
        Some((f.id("src/target.rs", "work"), "src/target.rs".into()))
    );
}

#[test]
fn inline_targets_aliases_variants_and_visibility_use_exact_module_context() {
    let caller = "use crate::bridge::Ready; pub fn run() { Ready(1); }";
    let f = fixture(&[("Cargo.toml", MANIFEST), ("src/lib.rs", "pub mod shapes { pub enum Status { Ready(u32) } fn secret() {} } pub mod bridge { pub use crate::shapes::Status::Ready; } pub mod user;"), ("src/user.rs", caller)]);
    let authority = f.authority().unwrap();
    assert_eq!(
        authority.resolve_entity(
            "src/user.rs",
            caller.find("Ready(1)").unwrap(),
            "crate::bridge",
            "Ready"
        ),
        Some((f.id("src/lib.rs", "Status::Ready"), "src/lib.rs".into()))
    );
    assert!(authority
        .resolve_entity(
            "src/user.rs",
            caller.find("Ready(1)").unwrap(),
            "crate::shapes",
            "secret"
        )
        .is_none());
}

#[test]
fn alias_rhs_is_checked_at_declaration_and_cannot_widen_private_visibility() {
    let caller = "use crate::owner::alias; pub fn run() { alias(); } fn work() {}";
    let bad = fixture(&[
        ("Cargo.toml", MANIFEST),
        ("src/lib.rs", "mod owner;"),
        ("src/owner.rs", "mod child; use self::child::work as alias;"),
        ("src/owner/child.rs", caller),
    ]);
    assert!(bad
        .authority()
        .unwrap()
        .resolve_entity(
            "src/owner/child.rs",
            caller.find("alias();").unwrap(),
            "crate::owner",
            "alias"
        )
        .is_none());
    let caller = "use crate::owner::alias; pub fn run() { alias(); }";
    for (leaf, expected) in [
        ("pub fn work() {}", true),
        ("pub(crate) fn work() {}", false),
    ] {
        let f = fixture(&[
            ("Cargo.toml", MANIFEST),
            ("src/lib.rs", "mod owner; mod user;"),
            (
                "src/owner.rs",
                "mod child; pub use self::child::work as alias;",
            ),
            ("src/owner/child.rs", leaf),
            ("src/user.rs", caller),
        ]);
        assert_eq!(
            f.authority()
                .unwrap()
                .resolve_entity(
                    "src/user.rs",
                    caller.find("alias();").unwrap(),
                    "crate::owner",
                    "alias"
                )
                .is_some(),
            expected
        );
    }
}

#[test]
fn ambiguous_modules_cycles_configuration_and_missing_bodies_refuse() {
    for files in [
        vec![
            ("Cargo.toml", MANIFEST),
            ("src/lib.rs", "pub mod owner;"),
            ("src/owner.rs", "pub fn work() {}"),
            ("src/owner/mod.rs", "pub fn work() {}"),
        ],
        vec![
            ("Cargo.toml", MANIFEST),
            ("src/lib.rs", "#[path=\"lib.rs\"] mod recursive;"),
        ],
        vec![
            ("Cargo.toml", MANIFEST),
            ("src/lib.rs", "#[cfg(feature=\"x\")] mod owner;"),
            ("src/owner.rs", "pub fn work() {}"),
        ],
        vec![("Cargo.toml", MANIFEST), ("src/lib.rs", "make_modules!();")],
    ] {
        assert!(fixture(&files).authority().is_err(), "{files:?}");
    }
    let mut f = fixture(&[("Cargo.toml", MANIFEST), ("src/lib.rs", "pub fn work() {}")]);
    let hash = f
        .tree
        .artifact_at_path(&RepoPath::from_utf8("Cargo.toml").unwrap())
        .unwrap()
        .entry
        .blob_identity()
        .unwrap();
    f.blobs.remove(&hash);
    assert!(f.authority().is_err());
    f.blobs
        .insert(hash, b"[package]\nname='different'".to_vec());
    assert!(f.authority().is_err());
}

#[test]
fn manifest_membership_changes_rebuild_context_and_entity_bindings() {
    let caller = "use crate::owner::work; pub fn run() { work(); }";
    let first = fixture(&[
        ("Cargo.toml", MANIFEST),
        ("src/lib.rs", "pub mod owner; pub mod user;"),
        ("src/owner.rs", "pub fn work() {}"),
        ("src/user.rs", caller),
    ]);
    let old = first.authority().unwrap();
    assert!(old
        .resolve_entity(
            "src/user.rs",
            caller.find("work();").unwrap(),
            "crate::owner",
            "work"
        )
        .is_some());
    let changed = fixture(&[("Cargo.toml", "[package]\nname='fixture'\nedition='2021'\nautolib=false\n[lib]\npath='replacement.rs'\n"), ("replacement.rs", "pub fn other() {}"), ("src/lib.rs", "pub mod owner; pub mod user;"), ("src/owner.rs", "pub fn work() {}"), ("src/user.rs", caller)]);
    let new = changed.authority().unwrap();
    assert_ne!(old.tree_digest(), new.tree_digest());
    assert!(new
        .resolve_entity(
            "src/user.rs",
            caller.find("work();").unwrap(),
            "crate::owner",
            "work"
        )
        .is_none());
    let mut stale = old;
    let mut entities = first.entities.clone();
    entities
        .iter_mut()
        .find(|e| e.name == "work")
        .unwrap()
        .metadata
        .extra
        .insert("blob_hash".into(), serde_json::json!("00".repeat(32)));
    assert!(stale.bind_entities(&entities).is_err());
    assert!(stale
        .resolve_entity(
            "src/user.rs",
            caller.find("work();").unwrap(),
            "crate::owner",
            "work"
        )
        .is_none());
}

#[test]
fn workspace_edition_and_all_automatic_target_classes_are_inventory_bound() {
    let f = fixture(&[
        (
            "Cargo.toml",
            "[workspace]\nmembers=['crates/*']\n[workspace.package]\nedition='2021'\n",
        ),
        (
            "crates/demo/Cargo.toml",
            "[package]\nname='demo'\nedition.workspace=true\n",
        ),
        ("crates/demo/src/lib.rs", ""),
        ("crates/demo/src/main.rs", "fn main() {}"),
        ("crates/demo/src/bin/tool.rs", "fn main() {}"),
        ("crates/demo/examples/demo.rs", "fn main() {}"),
        ("crates/demo/tests/smoke.rs", "fn main() {}"),
        ("crates/demo/benches/speed.rs", "fn main() {}"),
    ]);
    let authority = f.authority().unwrap();
    assert_eq!(authority.targets().len(), 6);
    assert!(authority.targets().iter().all(|t| t.edition == "2021"));
    assert_eq!(
        authority
            .targets()
            .iter()
            .map(|t| t.kind.as_str())
            .collect::<std::collections::BTreeSet<_>>(),
        ["lib", "bin", "example", "test", "bench"]
            .into_iter()
            .collect()
    );
}

#[test]
fn budget_exhaustion_never_returns_partial_target_or_module_inventory() {
    let f = fixture(&[("Cargo.toml", MANIFEST), ("src/lib.rs", "pub fn work() {}")]);
    for limits in [
        RustProjectLimits {
            artifacts: 1,
            ..Default::default()
        },
        RustProjectLimits {
            targets: 0,
            ..Default::default()
        },
        RustProjectLimits {
            module_contexts: 0,
            ..Default::default()
        },
    ] {
        assert!(
            RustProjectAuthority::from_admitted_tree(&f.tree, limits, |hash| Ok(
                f.blobs[&hash].clone()
            ))
            .is_err()
        );
    }
}

#[test]
fn admitted_crate_use_links_identically_in_batch_and_incremental_and_cold_requires_rebuild() {
    let f = fixture(&[
        ("Cargo.toml", MANIFEST),
        ("src/lib.rs", "pub mod owner; pub mod user;"),
        ("src/owner.rs", "pub fn work() {}"),
        (
            "src/user.rs",
            "use crate::owner::work; pub fn run() { work(); }",
        ),
        ("other/owner.rs", "pub fn work() {}"),
    ]);
    let authority = f.authority().unwrap();
    let files: Vec<_> = f.parsed.iter().collect();
    let entities: Vec<_> = f.entities.iter().collect();
    let batch = link_cross_file_with_rust_project(
        &files,
        &entities,
        &f.identities,
        &f.completeness,
        &authority,
    )
    .unwrap();
    let source = f.id("src/user.rs", "run");
    let target = f.id("src/owner.rs", "work");
    let calls = |relations: Vec<kin_model::Relation>| -> Vec<kin_model::Relation> {
        relations
            .into_iter()
            .filter(|r| {
                r.kind == kin_model::RelationKind::Calls && r.src.as_entity() == Some(source)
            })
            .collect()
    };
    let expected = calls(batch);
    assert_eq!(expected.len(), 1);
    assert_eq!(expected[0].dst.as_entity(), Some(target));
    assert_eq!(expected[0].confidence, 0.95);
    let mut incremental = IncrementalLinker::new();
    for file in &f.parsed {
        incremental.add_file(
            &file.file_path,
            f.identities[&file.file_path],
            &file.entities,
        );
    }
    incremental
        .install_rust_project(authority.clone(), &f.entities)
        .unwrap();
    let actual = calls(
        kin_index::link_cross_file_incremental_with_completeness(
            &f.parsed,
            &incremental,
            &f.completeness,
        )
        .unwrap(),
    );
    assert_eq!(actual, expected);
    let observations = named_import_observations(&f.parsed, &incremental);
    let observed = observations.iter().find(|o| o.source == source).unwrap();
    assert_eq!(observed.target, Some(target));
    assert_eq!(observed.rust_project_tree, Some(authority.tree_digest()));
    assert!(observed.source_bindings.contains_key("Cargo.toml"));
    let mut cold = IncrementalLinker::from_checkpoint_v1(incremental.to_checkpoint_v1()).unwrap();
    let cold_calls = calls(
        kin_index::link_cross_file_incremental_with_completeness(&f.parsed, &cold, &f.completeness)
            .unwrap(),
    );
    assert_eq!(cold_calls.len(), 1);
    assert!(kin_index::is_external_import_placeholder(&cold_calls[0]));
    assert_ne!(cold_calls[0].dst.as_entity(), Some(target));
    cold.install_rust_project(authority, &f.entities).unwrap();
    assert_eq!(
        calls(
            kin_index::link_cross_file_incremental_with_completeness(
                &f.parsed,
                &cold,
                &f.completeness
            )
            .unwrap()
        ),
        expected
    );
    cold.remove_file("src/owner.rs");
    let removed_calls = calls(
        kin_index::link_cross_file_incremental_with_completeness(
            &f.parsed[2..3],
            &cold,
            &f.completeness,
        )
        .unwrap(),
    );
    assert_eq!(removed_calls.len(), 1);
    assert!(kin_index::is_external_import_placeholder(&removed_calls[0]));
    assert_ne!(removed_calls[0].dst.as_entity(), Some(target));
    assert!(cold
        .install_rust_project(f.authority().unwrap(), &f.entities)
        .is_err());
}

#[test]
fn module_alias_must_not_lend_private_scope_to_the_callers_remaining_path() {
    let caller = "use crate::owner::alias::private::work; pub fn run(){work();}";
    let f = fixture(&[
        ("Cargo.toml", MANIFEST),
        ("src/lib.rs", "pub mod owner; pub mod user;"),
        (
            "src/owner.rs",
            "mod private; pub use crate::owner as alias;",
        ),
        ("src/user.rs", caller),
        ("src/owner/private.rs", "pub fn work() {}"),
    ]);
    let authority = f.authority().unwrap();
    assert!(
        authority
            .resolve_entity(
                "src/user.rs",
                caller.find("work();").unwrap(),
                "crate::owner::alias::private",
                "work"
            )
            .is_none(),
        "a public module alias does not expose that module's private child to outsiders"
    );
}

#[test]
fn observation_distinguishes_unsupported_source_from_integrity_and_processing_refusal() {
    let f = fixture(&[("Cargo.toml", MANIFEST), ("src/lib.rs", "pub fn work() {}")]);
    let read = |hash| f.blobs.get(&hash).cloned().ok_or("missing CAS".into());
    let limits = RustProjectLimits {
        targets: 0,
        ..Default::default()
    };
    assert!(RustProjectAuthority::observe_admitted_tree(&f.tree, limits, read).is_err());
    assert!(RustProjectAuthority::observe_admitted_tree(
        &f.tree,
        RustProjectLimits::default(),
        |_| Err("CAS unavailable".into())
    )
    .is_err());
    let huge = " ".repeat(300_000) + "pub fn work() {}";
    let big = fixture(&[("Cargo.toml", MANIFEST), ("src/lib.rs", &huge)]);
    assert!(RustProjectAuthority::observe_admitted_tree(
        &big.tree,
        RustProjectLimits {
            body_bytes: 256 * 1024,
            ..Default::default()
        },
        |hash| big.blobs.get(&hash).cloned().ok_or("missing CAS".into())
    )
    .is_err());
    let unsupported = fixture(&[
        ("Cargo.toml", MANIFEST),
        (
            "src/lib.rs",
            "#[cfg(feature=\"optional\")] pub fn work() {}",
        ),
    ]);
    assert!(matches!(
        RustProjectAuthority::observe_admitted_tree(
            &unsupported.tree,
            RustProjectLimits::default(),
            |hash| unsupported
                .blobs
                .get(&hash)
                .cloned()
                .ok_or("missing CAS".into())
        )
        .unwrap(),
        kin_index::rust_project::RustProjectObservation::Unproven { .. }
    ));
}

#[test]
fn explicit_path_module_children_are_siblings_not_filename_stem_decoys() {
    let caller = "use crate::owner::leaf::work; pub fn run() { work(); }";
    let f = fixture(&[
        ("Cargo.toml", MANIFEST),
        (
            "src/lib.rs",
            "#[path=\"alt.rs\"] pub mod owner; pub mod caller;",
        ),
        ("src/alt.rs", "pub mod leaf;"),
        ("src/leaf.rs", "pub fn work() {}"),
        ("src/alt/leaf.rs", "pub fn work() {}"),
        ("src/caller.rs", caller),
    ]);
    let authority = f.authority().unwrap();
    assert_eq!(
        authority.resolve_entity(
            "src/caller.rs",
            caller.find("work();").unwrap(),
            "crate::owner::leaf",
            "work"
        ),
        Some((f.id("src/leaf.rs", "work"), "src/leaf.rs".into()))
    );
    assert!(!authority.contains_source("src/alt/leaf.rs"));
}

#[test]
fn explicit_path_file_inline_descendants_keep_the_same_directory_ownership() {
    let caller = "use crate::owner::inner::leaf::work; pub fn run() { work(); }";
    let f = fixture(&[
        ("Cargo.toml", MANIFEST),
        (
            "src/lib.rs",
            "#[path=\"alt.rs\"] pub mod owner; pub mod caller;",
        ),
        ("src/alt.rs", "pub mod inner { pub mod leaf; }"),
        ("src/inner/leaf.rs", "pub fn work() {}"),
        ("src/alt/inner/leaf.rs", "pub fn work() {}"),
        ("src/caller.rs", caller),
    ]);
    let authority = f.authority().unwrap();
    assert_eq!(
        authority.resolve_entity(
            "src/caller.rs",
            caller.find("work();").unwrap(),
            "crate::owner::inner::leaf",
            "work"
        ),
        Some((
            f.id("src/inner/leaf.rs", "work"),
            "src/inner/leaf.rs".into()
        ))
    );
    assert!(!authority.contains_source("src/alt/inner/leaf.rs"));
}

/// A current Rust source at a path no name can carry refuses the batch.
///
/// Nomination answers in file names, and a byte path has none, so the helper
/// cannot say which sources a caller owes rederivation for. It refuses rather
/// than nominate the rest and let a caller read a short list as a complete one.
/// The refusal is a real one a caller meets: a session that moves a Rust source
/// onto a byte path reaches it before its own byte-path guard, which is why
/// that guard's check keeps its destination off the Rust project input list.
#[test]
fn rust_invalidation_refuses_a_current_source_whose_path_is_not_utf8() {
    use kin_index::rust_project::{affected_source_batch, RustProjectInvalidationError};
    let f = fixture(&[("Cargo.toml", MANIFEST), ("app.rs", "pub fn work() {}")]);
    let moved = ResolvedTree::from_artifacts(f.tree.artifacts().cloned().map(|mut artifact| {
        if artifact.path.as_bytes() == b"app.rs" {
            artifact.path = RepoPath::from_bytes(b"opaque-\xff.rs".to_vec()).unwrap();
        }
        artifact
    }))
    .unwrap();
    assert!(matches!(
        affected_source_batch(&f.tree, &moved, Default::default()),
        Err(RustProjectInvalidationError::InvalidSourcePath(_))
    ));
    // The control: the same move onto a byte path that is not a Rust project
    // input nominates instead of refusing, so the refusal above is the
    // unnameable Rust source and not the byte path by itself.
    let opaque = ResolvedTree::from_artifacts(f.tree.artifacts().cloned().map(|mut artifact| {
        if artifact.path.as_bytes() == b"app.rs" {
            artifact.path = RepoPath::from_bytes(b"opaque-\xff".to_vec()).unwrap();
        }
        artifact
    }))
    .unwrap();
    assert!(affected_source_batch(&f.tree, &opaque, Default::default())
        .unwrap()
        .is_some());
}

#[test]
fn cargo_invalidation_nominates_single_empty_and_use_only_sources_without_entities() {
    use kin_index::rust_project::affected_source_batch;
    let f = fixture(&[
        ("Cargo.toml", MANIFEST),
        ("src/lib.rs", ""),
        ("src/empty.rs", ""),
        ("src/use_only.rs", "pub use crate::empty::item;"),
    ]);
    let change = |path: &str| {
        kin_model::ResolvedTree::from_artifacts(f.tree.artifacts().cloned().map(|mut artifact| {
            if artifact.path.as_bytes() == path.as_bytes() {
                artifact.entry =
                    TreeEntry::blob(kin_blobs::digest(b"changed admitted bytes"), false);
            }
            artifact
        }))
        .unwrap()
    };
    for changed in [
        "Cargo.toml",
        "src/lib.rs",
        "src/empty.rs",
        "src/use_only.rs",
    ] {
        let current = change(changed);
        let plan = affected_source_batch(&f.tree, &current, Default::default())
            .unwrap()
            .unwrap();
        assert_eq!(
            plan.affected_sources,
            ["src/empty.rs", "src/lib.rs", "src/use_only.rs"].map(FilePathId::new)
        );
        assert_eq!(
            plan.previous_tree_digest,
            kin_index::rust_project::selected_tree_digest(&f.tree).unwrap()
        );
        assert_eq!(
            plan.current_tree_digest,
            kin_index::rust_project::selected_tree_digest(&current).unwrap()
        );
        assert_ne!(plan.previous_tree_digest, plan.current_tree_digest);
    }
    let one = fixture(&[("Cargo.toml", MANIFEST), ("src/lib.rs", "")]);
    let no_manifest = ResolvedTree::from_artifacts(
        one.tree
            .artifacts()
            .filter(|a| a.path.as_bytes() != b"Cargo.toml")
            .cloned(),
    )
    .unwrap();
    assert_eq!(
        affected_source_batch(&one.tree, &no_manifest, Default::default())
            .unwrap()
            .unwrap()
            .affected_sources,
        vec![FilePathId::new("src/lib.rs")]
    );
    let empty = ResolvedTree::default();
    assert!(affected_source_batch(&one.tree, &empty, Default::default())
        .unwrap()
        .unwrap()
        .affected_sources
        .is_empty());
}

#[test]
fn rust_invalidation_compares_exact_id_path_and_blob_but_ignores_unrelated_assets() {
    use kin_index::rust_project::{affected_source_batch, RustProjectInvalidationError};
    let f = fixture(&[
        ("Cargo.toml", MANIFEST),
        ("app.rs", "pub fn work() {}"),
        ("readme.txt", "old"),
    ]);
    for field in ["identity", "path", "blob"] {
        let current = ResolvedTree::from_artifacts(f.tree.artifacts().cloned().map(|mut a| {
            if a.path.as_bytes() == b"app.rs" {
                match field {
                    "identity" => a.artifact_id = ArtifactId::new(),
                    "path" => a.path = RepoPath::from_utf8("custom.rs").unwrap(),
                    _ => a.entry = TreeEntry::blob(kin_blobs::digest(b"new"), false),
                }
            }
            a
        }))
        .unwrap();
        assert!(affected_source_batch(&f.tree, &current, Default::default())
            .unwrap()
            .is_some());
    }
    let asset = ResolvedTree::from_artifacts(f.tree.artifacts().cloned().map(|mut a| {
        if a.path.as_bytes() == b"readme.txt" {
            a.entry = TreeEntry::blob(kin_blobs::digest(b"new"), false);
        }
        a
    }))
    .unwrap();
    assert!(affected_source_batch(&f.tree, &asset, Default::default())
        .unwrap()
        .is_none());
    assert!(matches!(
        affected_source_batch(
            &f.tree,
            &asset,
            RustProjectLimits {
                artifacts: 1,
                ..Default::default()
            }
        ),
        Err(RustProjectInvalidationError::Limit(_))
    ));
    assert!(matches!(
        affected_source_batch(
            &f.tree,
            &asset,
            RustProjectLimits {
                path_bytes: 1,
                ..Default::default()
            }
        ),
        Err(RustProjectInvalidationError::Limit(_))
    ));
}

fn assert_non_rs_support_is_explicitly_unproven(files: &[(&str, &str)]) {
    use kin_index::rust_project::RustProjectObservation;
    let f = fixture(files);
    let observed =
        RustProjectAuthority::observe_admitted_tree(&f.tree, Default::default(), |hash| {
            f.blobs
                .get(&hash)
                .cloned()
                .ok_or_else(|| "missing test CAS".into())
        })
        .unwrap();
    match observed {
        RustProjectObservation::Unproven { reason, .. } => assert!(reason.contains("non-.rs"), "{reason}"),
        RustProjectObservation::Current(_) => panic!("non-.rs membership cannot be certified while invalidation covers only Cargo and .rs sources"),
    }
}

#[test]
fn non_rs_cargo_root_is_unproven_until_support_invalidation_is_available() {
    assert_non_rs_support_is_explicitly_unproven(&[
        (
            "Cargo.toml",
            "[package]\nname='fixture'\nedition='2021'\n[lib]\npath='root.inc'\n",
        ),
        ("root.inc", "pub mod owner; pub mod caller;"),
        ("owner.rs", "pub fn work() {}"),
        (
            "caller.rs",
            "use crate::owner::work; pub fn run() { work(); }",
        ),
    ]);
}

#[test]
fn non_rs_path_module_is_unproven_until_support_invalidation_is_available() {
    assert_non_rs_support_is_explicitly_unproven(&[
        ("Cargo.toml", MANIFEST),
        (
            "src/lib.rs",
            "#[path=\"owner.inc\"] pub mod owner; pub mod caller;",
        ),
        ("src/owner.inc", "pub mod leaf;"),
        ("src/leaf.rs", "pub fn work() {}"),
        (
            "src/caller.rs",
            "use crate::owner::leaf::work; pub fn run() { work(); }",
        ),
    ]);
}
