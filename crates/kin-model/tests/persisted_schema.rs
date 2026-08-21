// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Enforcement for the crate-level positional-wire rule.
//!
//! `kin-db` persists these types through a compact MessagePack encoding that
//! writes a struct as an array, so a field is addressed by position. A field
//! that skips serialization shortens that array and moves every field after
//! it, which is why `skip_serializing_if` is only ever safe on a trailing
//! field. The failure is silent in the worst way: the type still round-trips
//! for values that serialize the field, and only breaks for the values that
//! skip it, so an ordinary unit test that builds a fully populated fixture
//! reports green while a real store decodes into the wrong slots.
//!
//! Two independent checks live here. [`skip_serializing_if_is_trailing_only`]
//! scans the source so a violation is caught at the type, before anything is
//! written. The round-trips below exercise the skipping values themselves, so
//! the rule is proven on bytes and not only on syntax.
//!
//! A second rule shares the same scanner, from FIR-2549. Every identity this
//! crate derives is hashed over bytes produced by `canonical_json_bytes`, whose
//! object encoder sorts keys, so field ORDER is normalized away before the hash
//! exists. A differential that compares hashes therefore cannot see a field a
//! serialization wrote in the wrong place, which is precisely how a
//! serialization written or mirrored by hand goes wrong. Demonstrated by
//! sabotage on the transaction canonicalization: swapping two fields in a
//! mirror view kept all 64 permutations of its hash differential green.
//! [`every_hand_written_serialization_has_a_positional_differential`] and
//! [`every_hand_kept_mirror_is_still_real_and_still_guarded`] are what refuse a
//! new one arriving without a differential that CAN see order.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use kin_model::merge::{
    MergeConflictEntry, MergeConflictSubject, MergeDivergence, MergeEntryResolution, MergeSideValue,
};
use kin_model::ArtifactId;
use uuid::Uuid;

/// Types serialized only into human-readable, name-keyed formats (TOML/JSON),
/// where a skipped field is addressed by name and omitting it moves nothing.
///
/// This list is deliberately an explicit carve-out rather than a pattern: the
/// scan denies by default, so a type reaches this list only by a reviewer
/// deciding it can never be embedded in a persisted record. Nesting one of
/// these inside a snapshot, delta, or operation record means removing it from
/// this list first, and the scan then demands the trailing-field layout.
const HUMAN_READABLE_ONLY: &[(&str, &str)] = &[
    (
        "PolicyOverrides",
        "reconcile preset overrides, serialized to TOML/JSON config only",
    ),
    (
        "DirectoryPreset",
        "per-directory preset override, serialized to TOML/JSON config only",
    ),
];

/// Persisted types the scan must actually observe.
///
/// A source scan fails open when its parser drifts: a rename or a formatting
/// change it cannot follow silently drops types from the scan and reports
/// green over an unchecked surface. Naming the types that must be found turns
/// that silence into a failure.
const MUST_BE_SCANNED: &[&str] = &[
    "MergeConflictEntry",
    "MergeTransactionRecord",
    "RepositoryOperationRecord",
    "TransactionDelta",
    "SemanticChange",
    "ResolvedGraphState",
    "SubGraph",
    "WorkspaceSemanticDelta",
];

/// Types in `src/` whose `Serialize` is written by hand, and what gives each
/// one a POSITIONAL differential.
///
/// The scan below denies by default: an `impl Serialize for T` that reaches
/// this crate without an entry here fails the test that reads this list. That
/// is the point. A derive keeps field order in step with the struct by
/// construction; a hand-written encoder does not, and no hash comparison in
/// this crate can tell you it drifted.
///
/// An entry carries exactly one disposition. Either it names the test that
/// diffs the type's bytes through a serializer that can see order, or it states
/// why the type has no element order to get wrong. A named test is checked to
/// exist, so an entry cannot point at a fiction.
const HAND_WRITTEN_SERIALIZATIONS: &[(&str, &str, &str)] = &[
    (
        "RepositoryTransaction",
        "the_canonical_view_serializes_positionally_identical_bytes",
        "",
    ),
    (
        "CanonicalTransaction",
        "the_canonical_view_serializes_positionally_identical_bytes",
        "",
    ),
    (
        "CanonicalChange",
        "the_canonical_view_serializes_positionally_identical_bytes",
        "",
    ),
    (
        "CanonicalWorkspaceMutation",
        "the_canonical_view_serializes_positionally_identical_bytes",
        "",
    ),
    (
        "CanonicalWorkspaceSemanticDelta",
        "the_canonical_view_serializes_positionally_identical_bytes",
        "",
    ),
    (
        "ResolvedTree",
        "",
        "delegates to ResolvedTreeWire, a one-field struct, so there is no element order to get \
         wrong; its content is pinned by compute_resolved_tree_hash's callers",
    ),
    ("RepositoryId", "", "serializes as a single string"),
    (
        "RepoPath",
        "",
        "serializes as a single-field hex wire struct",
    ),
    (
        "RefName",
        "",
        "serializes as a single-field hex wire struct",
    ),
    (
        "GitTreeEntryName",
        "",
        "serializes as a single-field hex wire struct",
    ),
];

/// Structs whose field list is a mirror of another type's, kept in step by
/// hand.
///
/// These derive `Serialize`, so no scan can find them by syntax: a mirror looks
/// exactly like an ordinary struct. The list is maintained by review, and every
/// entry is checked against the source, so a rename or a deletion fails here
/// rather than quietly shrinking the audit.
///
/// A mirror can drift in two ways the identity hash cannot see. It can miss a
/// field the mirrored type grew, in which case two values differing only in
/// that field collide on one identity while every digest already on disk keeps
/// verifying. And it can be reordered, which is invisible because the identity
/// encodes through the key-sorting encoder. Both are checked here from the
/// source, by requiring a mirror's fields to be a subsequence of the mirrored
/// type's, and the guards named below check the same thing again on bytes.
///
/// The fourth column is for a mirror that genuinely needs no positional guard,
/// with the reason. One of the two columns is filled, never both.
const HAND_KEPT_MIRRORS: &[(&str, &str, &str, &str)] = &[
    (
        "RepositoryOperationIdentity",
        "RepositoryOperationRecord",
        "operation_identity_mirrors_every_record_field_positionally",
        "",
    ),
    (
        "MergeTransactionIdentity",
        "MergeTransactionRecord",
        "merge_identity_mirrors_every_record_field_positionally",
        "",
    ),
    (
        "WorkspaceSemanticDeltaWire",
        "WorkspaceSemanticDelta",
        "workspace_semantic_delta_wire_mirror_is_positionally_exact",
        "",
    ),
    (
        "SharedAdmissionPolicyIdentity",
        "SharedAdmissionPolicy",
        "",
        "hashed through admission.rs's hash_json, which streams serde_json::to_vec and therefore \
         already fails on a reorder, as the_admission_identity_encoder_preserves_field_order \
         proves; the subsequence check here covers the field it could miss instead",
    ),
    (
        "LocalOverlayIdentity",
        "FrozenLocalOverlay",
        "",
        "hashed through admission.rs's hash_json, which streams serde_json::to_vec and therefore \
         already fails on a reorder, as the_admission_identity_encoder_preserves_field_order \
         proves; the subsequence check here covers the field it could miss instead",
    ),
    (
        "RepositoryTransactionHumanReadable",
        "RepositoryTransaction",
        "",
        "reached only through is_human_readable, where fields are addressed by name and order \
         moves nothing; its field SET is diffed as a serde_json::Value by \
         the_canonical_view_matches_across_every_optional_tail_combination",
    ),
];

#[derive(Debug)]
struct Field {
    name: String,
    line: usize,
    skips_serializing: bool,
}

#[derive(Debug)]
struct StructDef {
    name: String,
    file: String,
    /// Whether values of this type are ever decoded back from bytes.
    ///
    /// Position only decides a mapping on the way in. A serialize-only mirror
    /// (a hashing identity, a human-readable projection) has no slot to shift,
    /// so the rule applies exactly to the types something deserializes. Wire
    /// twins are still covered: the twin that carries the `Deserialize` is the
    /// one that has to hold the layout.
    deserialized: bool,
    fields: Vec<Field>,
}

fn src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn rust_sources(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        for entry in fs::read_dir(&current).expect("src/ must be readable") {
            let path = entry.expect("directory entry must be readable").path();
            if path.is_dir() {
                stack.push(path);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                found.push(path);
            }
        }
    }
    found.sort();
    found
}

/// Name of the struct a `struct ... {` line declares, if it declares one.
///
/// Only brace-bodied structs carry positional field layout worth checking;
/// tuple and unit structs have no field names to reorder.
fn struct_name(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    let rest = trimmed
        .strip_prefix("pub struct ")
        .or_else(|| trimmed.strip_prefix("struct "))
        .or_else(|| {
            trimmed
                .strip_prefix("pub(crate) struct ")
                .or_else(|| trimmed.strip_prefix("pub(super) struct "))
        })?;
    if !line.trim_end().ends_with('{') {
        return None;
    }
    let name: String = rest
        .chars()
        .take_while(|c| c.is_alphanumeric() || *c == '_')
        .collect();
    (!name.is_empty()).then_some(name)
}

/// Name of the field a struct-body line declares, if it declares one.
fn field_name(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    if trimmed.starts_with("//") || trimmed.starts_with('#') {
        return None;
    }
    let rest = trimmed
        .strip_prefix("pub ")
        .or_else(|| trimmed.strip_prefix("pub(crate) "))
        .or_else(|| trimmed.strip_prefix("pub(super) "))
        .unwrap_or(trimmed);
    let (candidate, tail) = rest.split_once(':')?;
    // A path separator, not a field: `Self::Variant => ...`.
    if tail.starts_with(':') {
        return None;
    }
    let candidate = candidate.trim();
    if candidate.is_empty()
        || !candidate
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
    {
        return None;
    }
    Some(candidate.to_string())
}

/// Parse every brace-bodied struct in a Rust source file.
///
/// This is a line scanner rather than a syntax tree on purpose: pulling a
/// proc-macro parser into the dependency graph of the crate every other Kin
/// crate depends on costs more than it buys for a check this shape. The
/// `MUST_BE_SCANNED` assertion covers the risk that the scanner drifts.
fn parse_structs(path: &Path) -> Vec<StructDef> {
    let text = fs::read_to_string(path).expect("source file must be readable");
    let file = path
        .strip_prefix(Path::new(env!("CARGO_MANIFEST_DIR")))
        .unwrap_or(path)
        .display()
        .to_string();

    // A hand-written `impl Deserialize for T` counts the same as a derive: the
    // type is decoded, so its layout is load-bearing. `WorkspaceSemanticDelta`
    // is exactly this case, delegating to a positional wire twin.
    let manually_deserialized: BTreeSet<String> = text
        .lines()
        .filter_map(|line| {
            let rest = line
                .trim_start()
                .strip_prefix("impl<'de> Deserialize<'de> for ")?;
            Some(
                rest.chars()
                    .take_while(|c| c.is_alphanumeric() || *c == '_')
                    .collect(),
            )
        })
        .collect();

    let mut structs = Vec::new();
    let mut current: Option<StructDef> = None;
    let mut depth = 0usize;
    let mut pending_skip = false;
    let mut derives_deserialize = false;

    for (index, line) in text.lines().enumerate() {
        let number = index + 1;

        if current.is_none() {
            if line.trim_start().starts_with("#[derive(") {
                derives_deserialize = line.contains("Deserialize");
            } else if line.trim().is_empty() {
                derives_deserialize = false;
            }
            if let Some(name) = struct_name(line) {
                let deserialized = derives_deserialize || manually_deserialized.contains(&name);
                current = Some(StructDef {
                    name,
                    file: file.clone(),
                    deserialized,
                    fields: Vec::new(),
                });
                depth = 1;
                pending_skip = false;
                derives_deserialize = false;
            }
            continue;
        }

        let opens = line.matches('{').count();
        let closes = line.matches('}').count();

        if depth == 1 {
            if line.contains("skip_serializing_if") {
                pending_skip = true;
            } else if let Some(name) = field_name(line) {
                let definition = current.as_mut().expect("inside a struct body");
                definition.fields.push(Field {
                    name,
                    line: number,
                    skips_serializing: pending_skip,
                });
                pending_skip = false;
            }
        }

        depth = depth + opens - closes.min(depth);
        if depth == 0 {
            structs.push(current.take().expect("inside a struct body"));
        }
    }

    structs
}

fn all_structs() -> Vec<StructDef> {
    rust_sources(&src_dir())
        .iter()
        .flat_map(|path| parse_structs(path))
        .collect()
}

/// A `skip_serializing_if` field must be the last field of its struct.
///
/// Falsify this by moving any skipping field above a following field: the scan
/// reports the type, the field, and its source location, and fails.
#[test]
fn skip_serializing_if_is_trailing_only() {
    let structs = all_structs();

    // Fail-loud guards against a scanner that quietly stops seeing anything.
    assert!(
        structs.len() > 100,
        "source scan found only {} structs, so it is no longer scanning the crate",
        structs.len()
    );
    let scanned: BTreeSet<&str> = structs.iter().map(|item| item.name.as_str()).collect();
    for required in MUST_BE_SCANNED {
        assert!(
            scanned.contains(required),
            "source scan never saw `{required}`, so the scan is not covering the persisted types"
        );
        assert!(
            structs
                .iter()
                .any(|item| item.name == *required && item.deserialized),
            "source scan read `{required}` as serialize-only and skipped it; the derive scan drifted"
        );
    }
    assert!(
        structs
            .iter()
            .any(|item| item.name == "MergeConflictEntry" && item.fields.len() == 7),
        "source scan misread MergeConflictEntry's fields, so its field order is unchecked"
    );
    // The other direction: a serialize-only mirror must stay out of scope, or
    // the flag is simply always true and the exclusion means nothing.
    assert!(
        structs
            .iter()
            .any(|item| item.name == "RepositoryOperationIdentity" && !item.deserialized),
        "source scan read the serialize-only hashing mirror as deserialized; the derive scan drifted"
    );

    let exempt: BTreeSet<&str> = HUMAN_READABLE_ONLY.iter().map(|(name, _)| *name).collect();
    let mut violations = Vec::new();

    for definition in &structs {
        if !definition.deserialized || exempt.contains(definition.name.as_str()) {
            continue;
        }
        let Some(last) = definition.fields.last() else {
            continue;
        };
        for field in &definition.fields {
            if field.skips_serializing && field.name != last.name {
                violations.push(format!(
                    "{}:{} `{}::{}` skips serialization but `{}` follows it",
                    definition.file, field.line, definition.name, field.name, last.name
                ));
            }
        }
    }

    assert!(
        violations.is_empty(),
        "a non-trailing field skips serialization, which shifts every field after it in the \
         persisted positional encoding. Move the field last, drop the skip, or, if the type is \
         only ever serialized to a name-keyed human-readable format, add it to \
         HUMAN_READABLE_ONLY with the reason.\n  {}",
        violations.join("\n  ")
    );
}

/// Every skipping field must also carry `#[serde(default)]`.
///
/// A shortened array is only additive if the missing trailing element has a
/// default to fall back on; without one the decode fails outright.
#[test]
fn skipping_fields_carry_a_default() {
    let exempt: BTreeSet<&str> = HUMAN_READABLE_ONLY.iter().map(|(name, _)| *name).collect();
    let mut missing = Vec::new();

    for path in rust_sources(&src_dir()) {
        let text = fs::read_to_string(&path).expect("source file must be readable");
        let file = path
            .strip_prefix(Path::new(env!("CARGO_MANIFEST_DIR")))
            .unwrap_or(path.as_path())
            .display()
            .to_string();
        for definition in parse_structs(&path) {
            if !definition.deserialized || exempt.contains(definition.name.as_str()) {
                continue;
            }
            for field in &definition.fields {
                if !field.skips_serializing {
                    continue;
                }
                let attribute = text
                    .lines()
                    .nth(field.line.saturating_sub(2))
                    .unwrap_or_default();
                if !attribute.contains("default") {
                    missing.push(format!(
                        "{}:{} `{}::{}`",
                        file, field.line, definition.name, field.name
                    ));
                }
            }
        }
    }

    assert!(
        missing.is_empty(),
        "a field that skips serialization must also carry #[serde(default)], otherwise the \
         shortened record fails to decode instead of taking the default:\n  {}",
        missing.join("\n  ")
    );
}

fn tests_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests")
}

/// Every type in `src/` that hand-writes its `Serialize`.
///
/// Matches how this crate writes them, `impl Serialize for T` with an optional
/// lifetime list. A spelling the pattern cannot follow would shrink this set
/// silently, which is what the count and the derived-type control in
/// [`every_hand_written_serialization_has_a_positional_differential`] exist to
/// catch.
fn hand_written_serialize_impls() -> BTreeSet<String> {
    let mut found = BTreeSet::new();
    for path in rust_sources(&src_dir()) {
        let text = fs::read_to_string(&path).expect("source file must be readable");
        for line in text.lines() {
            let Some(rest) = line.trim_start().strip_prefix("impl") else {
                continue;
            };
            let Some((_, tail)) = rest.split_once(" Serialize for ") else {
                continue;
            };
            let name: String = tail
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            if !name.is_empty() {
                found.insert(name);
            }
        }
    }
    found
}

/// Whether some source file in this crate declares a function by this name.
fn declares_fn(name: &str) -> bool {
    let needle = format!("fn {name}(");
    rust_sources(&src_dir())
        .into_iter()
        .chain(rust_sources(&tests_dir()))
        .any(|path| {
            fs::read_to_string(&path)
                .expect("source file must be readable")
                .contains(&needle)
        })
}

/// A registry entry carries exactly one disposition, and a named guard must be
/// real.
fn assert_disposition(kind: &str, name: &str, guard: &str, reason: &str) {
    assert!(
        guard.is_empty() != reason.is_empty(),
        "{kind} `{name}` must carry exactly one of a guarding test or a reason it needs none, \
         and carries {}",
        if guard.is_empty() { "neither" } else { "both" }
    );
    if !guard.is_empty() {
        assert!(
            declares_fn(guard),
            "{kind} `{name}` names `{guard}` as its positional differential, but no `fn {guard}(` \
             exists in src/ or tests/. The guard was renamed or deleted and the registration now \
             points at nothing, so this type is unguarded while reading as covered."
        );
    }
}

/// A hand-written `Serialize` must be registered, with a differential that can
/// see field order.
///
/// The scan denies by default. A type reaching this crate with its own
/// `Serialize` impl and no entry in `HAND_WRITTEN_SERIALIZATIONS` fails here,
/// which is the whole mechanism: a derive keeps field order in step with the
/// struct by construction, a hand-written encoder does not, and the hash cannot
/// tell you it drifted because `canonical_json_bytes` sorts object keys before
/// anything is hashed.
///
/// Falsify this by deleting any entry below: the scan still finds the impl and
/// names it. Falsify the disposition check by renaming a guarding test.
#[test]
fn every_hand_written_serialization_has_a_positional_differential() {
    let found = hand_written_serialize_impls();

    assert!(
        found.len() >= 10,
        "the scan found only {} hand-written Serialize impls, so it is no longer following how \
         this crate writes them and its silence means nothing",
        found.len()
    );
    // The control that matters: the scan must distinguish hand-written from
    // derived. Without it a scan that matched everything, or nothing, would
    // satisfy every assertion below.
    assert!(
        !found.contains("MergeConflictEntry"),
        "the scan reported a type that derives Serialize as hand-writing it, so its result does \
         not separate the two populations"
    );

    let registered: BTreeSet<&str> = HAND_WRITTEN_SERIALIZATIONS
        .iter()
        .map(|(name, _, _)| *name)
        .collect();
    let unregistered: Vec<&str> = found
        .iter()
        .map(String::as_str)
        .filter(|name| !registered.contains(name))
        .collect();
    assert!(
        unregistered.is_empty(),
        "these types hand-write their Serialize and are not registered in \
         HAND_WRITTEN_SERIALIZATIONS: {}. A hand-written encoder can put a field in the wrong \
         place, and no hash differential built on canonical_json_bytes can see that, because its \
         object encoder sorts keys. Give each one a differential that encodes through a \
         non-human-readable serializer, where a struct is an ordered array, and register the test \
         here. If the type has no element order to get wrong, register the reason instead.",
        unregistered.join(", ")
    );

    for (name, guard, reason) in HAND_WRITTEN_SERIALIZATIONS {
        assert!(
            found.contains(*name),
            "HAND_WRITTEN_SERIALIZATIONS names `{name}`, but no `impl Serialize for {name}` is in \
             src/. The type was renamed or its impl was replaced by a derive; drop the entry or \
             fix the name, because a stale entry hides a real one."
        );
        assert_disposition("hand-written serialization", name, guard, reason);
    }
}

/// A hand-kept mirror must still name real types, and its fields must still be
/// a subsequence of the type it mirrors.
///
/// The subsequence rule is the source-level half of the same guard the named
/// tests apply to bytes. A mirror that dropped a field is still a subsequence,
/// which is why the named tests exist; a mirror that MOVED a field is not, and
/// this catches it without a fixture. Both halves are needed and neither is
/// redundant.
///
/// Falsify by swapping two fields in any registered mirror: this names the
/// field and the type. Falsify the existence half by renaming a mirror.
#[test]
fn every_hand_kept_mirror_is_still_real_and_still_guarded() {
    let structs = all_structs();
    let by_name: std::collections::BTreeMap<&str, &StructDef> = structs
        .iter()
        .map(|item| (item.name.as_str(), item))
        .collect();

    // Controls, in both directions: the scan must find a struct that exists
    // and must not invent one that does not.
    assert!(
        by_name.contains_key("MergeConflictEntry"),
        "the struct scan is not reading this crate, so nothing below can fail"
    );
    assert!(
        !by_name.contains_key("NoSuchStructIsDeclaredInThisCrate"),
        "the struct scan reports structs that do not exist, so a hit from it proves nothing"
    );

    for (mirror, mirrored, guard, reason) in HAND_KEPT_MIRRORS {
        let mirror_def = by_name.get(mirror).unwrap_or_else(|| {
            panic!(
                "HAND_KEPT_MIRRORS names `{mirror}`, which no longer exists. A renamed or deleted \
                 mirror must leave this list, or the list stops describing the crate."
            )
        });
        let mirrored_def = by_name.get(mirrored).unwrap_or_else(|| {
            panic!("HAND_KEPT_MIRRORS says `{mirror}` mirrors `{mirrored}`, which no longer exists")
        });
        assert_disposition("mirror", mirror, guard, reason);

        assert!(
            !mirror_def.fields.is_empty(),
            "the scan read `{mirror}` as having no fields, so the subsequence check below is \
             trivially true and proves nothing"
        );

        let mut remaining = mirrored_def.fields.iter();
        for field in &mirror_def.fields {
            assert!(
                remaining.any(|candidate| candidate.name == field.name),
                "`{mirror}::{}` is not where `{mirrored}` puts it: the mirror's fields are no \
                 longer a subsequence of the type it mirrors, so either a field moved or it names \
                 one `{mirrored}` does not have.\n  this mirror's disposition: {}\n  {} \
                 declares: {}\n  {} declares: {}",
                field.name,
                if guard.is_empty() {
                    format!("needs no positional differential, because {reason}")
                } else {
                    format!("guarded by {guard}")
                },
                mirror,
                mirror_def
                    .fields
                    .iter()
                    .map(|item| item.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
                mirrored,
                mirrored_def
                    .fields
                    .iter()
                    .map(|item| item.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }
}

fn conflict_entry(label: Option<&str>) -> MergeConflictEntry {
    MergeConflictEntry {
        subject: MergeConflictSubject::Artifact {
            artifact: ArtifactId(Uuid::from_u128(2)),
        },
        divergence: MergeDivergence::ChangedOursRemovedTheirs,
        base: MergeSideValue::Absent,
        ours: MergeSideValue::Absent,
        theirs: MergeSideValue::Absent,
        label: label.map(str::to_string),
        resolution: MergeEntryResolution::Unresolved,
    }
}

/// A conflict entry with no label must survive the positional encoding.
///
/// Before the label field dropped its `skip_serializing_if`, this wrote a
/// six-element array and decoded the resolution into the label slot, failing
/// with `invalid type: sequence, expected a string`. The labelled case round
/// -tripped throughout, which is exactly why the defect stayed invisible.
#[test]
fn unlabelled_conflict_entry_round_trips() {
    let value = conflict_entry(None);
    let bytes = rmp_serde::to_vec(&value).expect("entry must encode");
    let decoded: MergeConflictEntry =
        rmp_serde::from_slice(&bytes).expect("an unlabelled entry must decode");
    assert_eq!(decoded, value);
}

#[test]
fn labelled_conflict_entry_round_trips() {
    let value = conflict_entry(Some("README.md"));
    let bytes = rmp_serde::to_vec(&value).expect("entry must encode");
    let decoded: MergeConflictEntry =
        rmp_serde::from_slice(&bytes).expect("a labelled entry must decode");
    assert_eq!(decoded, value);
}

/// The labelled encoding is unchanged by the label fix.
///
/// These bytes were captured from the released layout, where the label already
/// serialized because it was `Some`. Dropping `skip_serializing_if` only adds a
/// null for the absent case, so every record that could previously be read must
/// still read identically, and the array stays seven elements wide.
#[test]
fn released_labelled_encoding_still_decodes() {
    const RELEASED: &[u8] = &[
        151, 146, 168, 97, 114, 116, 105, 102, 97, 99, 116, 196, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 2, 145, 187, 99, 104, 97, 110, 103, 101, 100, 95, 111, 117, 114, 115, 95,
        114, 101, 109, 111, 118, 101, 100, 95, 116, 104, 101, 105, 114, 115, 145, 166, 97, 98, 115,
        101, 110, 116, 145, 166, 97, 98, 115, 101, 110, 116, 145, 166, 97, 98, 115, 101, 110, 116,
        169, 82, 69, 65, 68, 77, 69, 46, 109, 100, 145, 170, 117, 110, 114, 101, 115, 111, 108,
        118, 101, 100,
    ];

    let expected = conflict_entry(Some("README.md"));
    let decoded: MergeConflictEntry =
        rmp_serde::from_slice(RELEASED).expect("the released labelled encoding must still decode");
    assert_eq!(decoded, expected);
    assert_eq!(
        rmp_serde::to_vec(&expected).expect("entry must encode"),
        RELEASED,
        "the labelled encoding moved, which rewrites identity for every existing merge record"
    );
}
