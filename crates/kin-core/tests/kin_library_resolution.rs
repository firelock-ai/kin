// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Every Kin library resolves from this workspace, never from the registry.
//!
//! The Kin libraries are developed here, in `crates/`, and published from here.
//! A workspace member that resolves one of them from the Kin registry instead
//! is building against a copy nobody in this tree can edit, and nothing about
//! that is visible in a diff: the manifest still says `{ workspace = true }`,
//! the build is green, and the only record is one `source =` line in the lock.
//! Worse, a graph carrying both copies carries two types with the same name,
//! and the error that eventually surfaces names neither the registry nor the
//! path.
//!
//! So the subject here is the LOCK, which is the resolution of record, not the
//! root manifest, which is only a request. Every lock the tree tracks is read,
//! because a workspace can carry more than one and a re-lock of the root leaves
//! the others on whatever they had: `fuzz/` is a detached workspace with its
//! own `Cargo.lock`, and it reaches kin-model through kin-parser.
//!
//! Two things fail this test. A Kin library with a `source`, unless it is named
//! in `TRANSITIONAL_REGISTRY_LIBRARIES` below. And the same Kin library
//! appearing twice in one lock, which is the two-copies case stated directly.
//!
//! `TRANSITIONAL_REGISTRY_LIBRARIES` shrinks to nothing. An entry that no lock
//! needs is reported too, so the list cannot quietly outlive the import it was
//! written for.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

/// Kin libraries this tree still resolves from the Kin registry, and why.
///
/// Each is a library whose import has not landed yet. While one is here, the
/// root manifest's `[patch.kin]` table points ITS Kin dependencies back at
/// `crates/`, so the registry copy of, say, kin-db still builds against the
/// kin-model in this tree rather than dragging a second one in. Empty is the
/// end state, and the pull request that imports a library deletes its row.
const TRANSITIONAL_REGISTRY_LIBRARIES: &[(&str, &str)] = &[];

#[derive(serde::Deserialize)]
struct Lock {
    #[serde(default)]
    package: Vec<LockedPackage>,
}

#[derive(serde::Deserialize)]
struct LockedPackage {
    name: String,
    version: String,
    #[serde(default)]
    source: Option<String>,
}

fn is_kin_library(name: &str) -> bool {
    name.starts_with("kin-")
}

/// Every way `lock_text` violates the rule, as sentences a reader can act on.
///
/// Pure, so the controls below can hand it a lock that does not exist.
fn audit(lock_label: &str, lock_text: &str, transitional: &[&str]) -> Vec<String> {
    let lock: Lock = match toml::from_str(lock_text) {
        Ok(lock) => lock,
        Err(err) => return vec![format!("{lock_label}: not parseable as a lock: {err}")],
    };

    let mut findings = Vec::new();
    let mut seen: BTreeMap<&str, Vec<String>> = BTreeMap::new();

    for package in &lock.package {
        if !is_kin_library(&package.name) {
            continue;
        }
        seen.entry(package.name.as_str())
            .or_default()
            .push(match &package.source {
                Some(source) => format!("{} from {source}", package.version),
                None => format!("{} from this workspace", package.version),
            });

        if let Some(source) = &package.source {
            if !transitional.contains(&package.name.as_str()) {
                findings.push(format!(
                    "{lock_label}: {} {} resolves from {source}. It is a Kin library and must \
                     resolve from crates/{}. Give the root manifest a `path` beside its \
                     `version`, re-lock, and commit the lock.",
                    package.name, package.version, package.name,
                ));
            }
        }
    }

    for (name, copies) in seen {
        if copies.len() > 1 {
            findings.push(format!(
                "{lock_label}: {name} appears {} times ({}). Two packages with one name are two \
                 distinct types, and code that passes a value of one where the other is expected \
                 fails to compile for a reason that names neither.",
                copies.len(),
                copies.join(", "),
            ));
        }
    }

    findings
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

/// Every `Cargo.lock` the tree carries, found rather than listed.
///
/// The fuzz lock was already missed once by a pin move that re-locked only the
/// root, so the set is discovered. `target` directories hold locks belonging to
/// vendored builds and are not this tree's.
fn tracked_locks(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if path.is_dir() {
                if name == "target" || name == ".git" || name == "node_modules" {
                    continue;
                }
                stack.push(path);
            } else if name == "Cargo.lock" {
                found.push(path);
            }
        }
    }
    found.sort();
    found
}

#[test]
fn every_kin_library_resolves_from_this_workspace() {
    let root = workspace_root();

    // Packaged single-crate context: the sibling crates and the workspace lock
    // are not there to read. Mirrors the skip in kin-core's environment scans.
    if !root.join("crates/kin-cli/src").is_dir() {
        eprintln!("workspace crates not present; skipping the Kin library resolution audit");
        return;
    }

    let locks = tracked_locks(&root);
    assert!(
        locks
            .iter()
            .any(|lock| lock.parent() == Some(root.as_path())),
        "found no workspace-root Cargo.lock under {}; the audit would have graded nothing and \
         passed. Found: {locks:?}",
        root.display(),
    );

    let transitional: Vec<&str> = TRANSITIONAL_REGISTRY_LIBRARIES
        .iter()
        .map(|(name, _)| *name)
        .collect();

    let mut findings = Vec::new();
    let mut needed: BTreeMap<&str, bool> = transitional.iter().map(|name| (*name, false)).collect();
    let mut kin_libraries_seen = 0usize;

    for lock in &locks {
        let label = lock
            .strip_prefix(&root)
            .unwrap_or(lock)
            .to_string_lossy()
            .into_owned();
        let text = std::fs::read_to_string(lock)
            .unwrap_or_else(|err| panic!("cannot read {}: {err}", lock.display()));
        findings.extend(audit(&label, &text, &transitional));

        let parsed: Lock = toml::from_str(&text)
            .unwrap_or_else(|err| panic!("cannot parse {}: {err}", lock.display()));
        for package in &parsed.package {
            if !is_kin_library(&package.name) {
                continue;
            }
            kin_libraries_seen += 1;
            if package.source.is_some() {
                if let Some(used) = needed.get_mut(package.name.as_str()) {
                    *used = true;
                }
            }
        }
    }

    // The positive control. A lock the parse silently read as empty would let
    // every rule above pass over nothing at all.
    assert!(
        kin_libraries_seen > 20,
        "only {kin_libraries_seen} kin-* entries across {} lock(s); this workspace has more than \
         twenty, so the locks were not read",
        locks.len(),
    );

    for (name, used) in needed {
        if !used {
            let why = TRANSITIONAL_REGISTRY_LIBRARIES
                .iter()
                .find(|(entry, _)| *entry == name)
                .map(|(_, why)| *why)
                .unwrap_or("");
            findings.push(format!(
                "TRANSITIONAL_REGISTRY_LIBRARIES still lists {name} ({why}), but no lock resolves \
                 it from a registry any more. Delete the row.",
            ));
        }
    }

    assert!(
        findings.is_empty(),
        "Kin libraries must resolve from this workspace:\n  {}",
        findings.join("\n  "),
    );
}

// The controls. `audit` is pure, so each of these is the shape of a real lock
// rather than a mock of one, and the clean case is what proves the others are
// not simply reporting everything handed to them.

const CLEAN: &str = r#"
[[package]]
name = "kin-model"
version = "0.7.28"
dependencies = ["kin-blobs"]

[[package]]
name = "kin-blobs"
version = "0.1.5"

[[package]]
name = "serde"
version = "1.0.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
"#;

#[test]
fn a_clean_lock_reports_nothing() {
    assert_eq!(audit("Cargo.lock", CLEAN, &[]), Vec::<String>::new());
}

#[test]
fn a_registry_kin_library_is_reported() {
    let text = CLEAN.replace(
        "name = \"kin-blobs\"\nversion = \"0.1.5\"",
        "name = \"kin-blobs\"\nversion = \"0.1.5\"\nsource = \"sparse+https://kinlab.ai/registry/cargo/\"",
    );
    let findings = audit("Cargo.lock", &text, &[]);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert!(findings[0].contains("kin-blobs"), "{findings:?}");
    assert!(findings[0].contains("kinlab.ai"), "{findings:?}");
}

#[test]
fn a_transitional_library_is_allowed_and_only_that_one() {
    let text = CLEAN.replace(
        "name = \"kin-blobs\"\nversion = \"0.1.5\"",
        "name = \"kin-blobs\"\nversion = \"0.1.5\"\nsource = \"sparse+https://kinlab.ai/registry/cargo/\"",
    );
    assert_eq!(
        audit("Cargo.lock", &text, &["kin-blobs"]),
        Vec::<String>::new()
    );
    // Naming a DIFFERENT library does not cover this one.
    assert_eq!(audit("Cargo.lock", &text, &["kin-db"]).len(), 1);
}

#[test]
fn two_copies_of_one_library_are_reported() {
    let text = format!(
        "{CLEAN}\n[[package]]\nname = \"kin-model\"\nversion = \"0.7.27\"\n\
         source = \"sparse+https://kinlab.ai/registry/cargo/\"\n"
    );
    let findings = audit("Cargo.lock", &text, &["kin-model"]);
    assert_eq!(findings.len(), 1, "{findings:?}");
    assert!(findings[0].contains("appears 2 times"), "{findings:?}");
    assert!(findings[0].contains("0.7.28"), "{findings:?}");
    assert!(findings[0].contains("0.7.27"), "{findings:?}");
}

#[test]
fn a_non_kin_package_from_a_registry_is_not_reported() {
    // serde carries a registry source in CLEAN and must stay unreported, or the
    // rule would be "nothing resolves from a registry", which is not the rule.
    assert!(CLEAN.contains("crates.io-index"));
    assert_eq!(audit("Cargo.lock", CLEAN, &[]), Vec::<String>::new());
}
