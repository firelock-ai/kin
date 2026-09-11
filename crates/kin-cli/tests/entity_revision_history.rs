// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! `kin history` and `kin blame` over a change that touches more than one entity.
//!
//! Resolving an entity's revisions from the entity-filtered change list replays
//! only the changes that mention that entity, but validates every delta those
//! changes carry. A refactor commit that edits the queried function while
//! removing a helper and adding its replacement is then checked against a state
//! the helper's own history was filtered out of, so both commands failed with a
//! "stale old payload" conflict naming an entity the operator never asked
//! about, before printing a single revision.

use std::sync::Arc;

use kin_cli::commands::blame::{execute_blame_request, BlameRequest};
use kin_cli::commands::history::{execute_history_request, HistoryRequest};
use kin_model::{
    AuthorId, ChangeOrigin, ChangeStore, Entity, EntityDelta, EntityId, EntityKind, EntityMetadata,
    EntityRole, FilePathId, FingerprintAlgorithm, Hash256, LanguageId, SemanticChange,
    SemanticChangeId, SemanticFingerprint, Timestamp, Visibility,
};

/// One version of an entity. `marker` varies the fingerprint so two versions of
/// the same entity are distinguishable revisions rather than a repeated one.
fn entity(id: EntityId, name: &str, marker: u8) -> Entity {
    Entity {
        id,
        kind: EntityKind::Function,
        name: name.to_string(),
        language: LanguageId::Rust,
        fingerprint: SemanticFingerprint {
            algorithm: FingerprintAlgorithm::V1TreeSitter,
            ast_hash: Hash256::from_bytes([marker; 32]),
            signature_hash: Hash256::from_bytes([marker; 32]),
            behavior_hash: Hash256::from_bytes([marker; 32]),
            equivalence_hash: Hash256::from_bytes([0; 32]),
            stability_score: 1.0,
        },
        file_origin: Some(FilePathId::new("src/lib.rs")),
        span: None,
        signature: format!("fn {name}(v{marker})"),
        visibility: Visibility::Public,
        role: EntityRole::Source,
        doc_summary: None,
        metadata: EntityMetadata::default(),
        lineage_parent: None,
        created_in: None,
        superseded_by: None,
    }
}

/// A change whose declared identity recomputes from its own payload, the way
/// repository authority requires.
fn change(
    parents: Vec<SemanticChangeId>,
    message: &str,
    entity_deltas: Vec<EntityDelta>,
) -> SemanticChange {
    let mut change = SemanticChange {
        id: SemanticChangeId::from_hash(Hash256::from_bytes([0; 32])),
        origin: ChangeOrigin::Native,
        parents,
        timestamp: Timestamp::now(),
        author: AuthorId::new("Test Author <test@example.com>"),
        message: message.to_string(),
        entity_deltas,
        relation_deltas: Vec::new(),
        tree_deltas: Vec::new(),
        admission_policy_delta: None,
        projected_files: Vec::new(),
        spec_link: None,
        evidence: Vec::new(),
        risk_summary: None,
        external_reference_deltas: Vec::new(),
    };
    change.id = kin_core::compute_semantic_change_id(&change).expect("derive change identity");
    change
}

fn absent_binding() -> kin_core::LocalRepositoryAuthorityBinding {
    let layout = kin_core::KinLayout::new(std::path::PathBuf::from("/absent/.kin"));
    kin_core::LocalRepositoryAuthorityBinding::from_parts(
        kin_model::RepositoryId::new("absent-entity-revision-history").unwrap(),
        kin_model::WorkspaceId::new(),
        Arc::new(kin_db::LocalFileBackend::new(layout.kindb_dir())),
    )
}

/// The head of the fixture history plus the two changes that revise `alpha`.
struct MixedShapeHistory {
    graph: kin_db::InMemoryGraph,
    head: SemanticChangeId,
    introduced_alpha: SemanticChangeId,
    revised_alpha: SemanticChangeId,
    added_beta: SemanticChangeId,
}

/// Three commits, the last of which carries a mixed add/remove shape:
///
/// 1. adds `alpha`, the entity under query
/// 2. adds `beta`, and does not mention `alpha` at all, so filtering the change
///    list to `alpha` drops the only change that introduces `beta`
/// 3. modifies `alpha`, removes `beta`, and adds `gamma` in its place
///
/// Replaying only changes 1 and 3 leaves change 3's `Removed { beta }` delta
/// checked against a state that never saw `beta` added.
fn mixed_shape_history() -> MixedShapeHistory {
    let graph = kin_db::InMemoryGraph::new();

    let alpha_id = EntityId::new();
    let beta_id = EntityId::new();
    let gamma_id = EntityId::new();

    let alpha_v1 = entity(alpha_id, "alpha", 1);
    let alpha_v2 = entity(alpha_id, "alpha", 2);
    let beta_v1 = entity(beta_id, "beta", 1);
    let gamma_v1 = entity(gamma_id, "gamma", 1);

    let introduce_alpha = change(
        Vec::new(),
        "Add alpha",
        vec![EntityDelta::Added {
            new: alpha_v1.clone(),
        }],
    );
    let introduce_beta = change(
        vec![introduce_alpha.id],
        "Add beta helper",
        vec![EntityDelta::Added {
            new: beta_v1.clone(),
        }],
    );
    let revise_alpha = change(
        vec![introduce_beta.id],
        "Replace the beta helper with gamma\n\nThe body is not a subject line.",
        vec![
            EntityDelta::Modified {
                old: alpha_v1,
                new: alpha_v2,
            },
            EntityDelta::Removed { old: beta_v1 },
            EntityDelta::Added { new: gamma_v1 },
        ],
    );

    for entry in [&introduce_alpha, &introduce_beta, &revise_alpha] {
        graph.create_change(entry).expect("store change");
    }

    MixedShapeHistory {
        graph,
        head: revise_alpha.id,
        introduced_alpha: introduce_alpha.id,
        revised_alpha: revise_alpha.id,
        added_beta: introduce_beta.id,
    }
}

fn abbreviated(id: &SemanticChangeId) -> String {
    id.to_string().chars().take(12).collect()
}

#[test]
fn history_reports_both_revisions_across_a_mixed_add_remove_change() {
    let fixture = mixed_shape_history();
    let request = HistoryRequest {
        entity: "alpha".to_string(),
        reference: Some(format!("kin:{}", fixture.head)),
        // The DEFAULT, deliberately. These two tests exist for a change that
        // also touches another entity, which is exactly the shape the trim
        // reasons about, so they must hold under the default rather than be
        // exempted from it.
        all_revisions: false,
    };

    let response = execute_history_request(&absent_binding(), &fixture.graph, &request)
        .expect("history must not fail on a change that also touches another entity");
    let rendered = response.lines.join("\n");

    assert!(
        !rendered.contains("No history recorded"),
        "alpha has two revisions, got:\n{rendered}"
    );
    // Header plus exactly one row per revision of alpha.
    assert_eq!(
        response.lines.len(),
        3,
        "expected a header and two revision rows, got:\n{rendered}"
    );
    for change_id in [&fixture.introduced_alpha, &fixture.revised_alpha] {
        assert!(
            rendered.contains(&abbreviated(change_id)),
            "revision introduced by {change_id} is missing from:\n{rendered}"
        );
    }
    assert!(
        !rendered.contains(&abbreviated(&fixture.added_beta)),
        "the change that only touches beta is not a revision of alpha:\n{rendered}"
    );
    assert!(
        rendered.contains("Test Author") && !rendered.contains("test@example.com"),
        "the author column keeps the name and drops the address:\n{rendered}"
    );
    assert!(
        rendered.contains("Replace the beta helper with gamma")
            && !rendered.contains("The body is not a subject line."),
        "each row carries the subject line only:\n{rendered}"
    );
}

#[test]
fn blame_reports_both_revisions_across_a_mixed_add_remove_change() {
    let fixture = mixed_shape_history();
    let request = BlameRequest {
        entity: "alpha".to_string(),
        reference: Some(format!("kin:{}", fixture.head)),
        // The DEFAULT, deliberately. These two tests exist for a change that
        // also touches another entity, which is exactly the shape the trim
        // reasons about, so they must hold under the default rather than be
        // exempted from it.
        all_revisions: false,
    };

    let response = execute_blame_request(&absent_binding(), &fixture.graph, &request)
        .expect("blame must not fail on a change that also touches another entity");
    let rendered = response.lines.join("\n");

    assert!(
        !rendered.contains("No history recorded"),
        "alpha has two revisions, got:\n{rendered}"
    );
    assert!(
        rendered.contains("2 version(s) found."),
        "both revisions of alpha must be counted:\n{rendered}"
    );
    for change_id in [&fixture.introduced_alpha, &fixture.revised_alpha] {
        assert!(
            rendered.contains(&change_id.to_string()),
            "revision introduced by {change_id} is missing from:\n{rendered}"
        );
    }
    assert!(
        !rendered.contains(&fixture.added_beta.to_string()),
        "the change that only touches beta is not a revision of alpha:\n{rendered}"
    );
    assert!(
        rendered.contains("Signature: fn alpha(v2)"),
        "blame reports the state at the requested head:\n{rendered}"
    );
    assert!(
        rendered.contains("Replace the beta helper with gamma")
            && !rendered.contains("The body is not a subject line."),
        "each blame row carries the subject line only, as history's does:\n{rendered}"
    );
}

/// Two functions named `alpha` in two files, each with its own history.
struct TwinHistory {
    graph: kin_db::InMemoryGraph,
    head: SemanticChangeId,
    lib_alpha: EntityId,
    other_alpha: EntityId,
    lib_changes: [SemanticChangeId; 2],
    other_change: SemanticChangeId,
}

fn twin_history() -> TwinHistory {
    let graph = kin_db::InMemoryGraph::new();
    let lib_alpha = EntityId::new();
    let other_alpha = EntityId::new();
    let mut other_v1 = entity(other_alpha, "alpha", 7);
    other_v1.file_origin = Some(FilePathId::new("src/other.rs"));

    let add_lib = change(
        Vec::new(),
        "Add alpha to lib",
        vec![EntityDelta::Added {
            new: entity(lib_alpha, "alpha", 1),
        }],
    );
    let add_other = change(
        vec![add_lib.id],
        "Add alpha to other",
        vec![EntityDelta::Added { new: other_v1 }],
    );
    let revise_lib = change(
        vec![add_other.id],
        "Revise lib alpha",
        vec![EntityDelta::Modified {
            old: entity(lib_alpha, "alpha", 1),
            new: entity(lib_alpha, "alpha", 2),
        }],
    );
    for entry in [&add_lib, &add_other, &revise_lib] {
        graph.create_change(entry).expect("store change");
    }

    TwinHistory {
        graph,
        head: revise_lib.id,
        lib_alpha,
        other_alpha,
        lib_changes: [add_lib.id, revise_lib.id],
        other_change: add_other.id,
    }
}

/// At a ref, blame and history resolve a name the way every read command does:
/// twins answer about the first by the one ranking rule and list every candidate
/// by id, a pin reaches the twin it names and only that twin's revisions, and a
/// pin that excludes every twin is refused naming them, never called absent.
#[test]
fn blame_and_history_at_a_ref_pin_one_twin_and_list_the_others() {
    let fixture = twin_history();
    let head = format!("kin:{}", fixture.head);
    let history = |entity: &str| {
        execute_history_request(
            &absent_binding(),
            &fixture.graph,
            &HistoryRequest {
                entity: entity.to_string(),
                reference: Some(head.clone()),
                all_revisions: false,
            },
        )
    };

    let unpinned = history("alpha").expect("twins answer").lines;
    assert!(
        unpinned[0].contains("@ src/lib.rs"),
        "an unpinned name answers about the first twin by path: {unpinned:#?}"
    );
    assert!(
        unpinned
            .iter()
            .any(|line| line.contains("'alpha' names 2 entities")),
        "the answer must say it chose: {unpinned:#?}"
    );
    for id in [fixture.lib_alpha, fixture.other_alpha] {
        assert!(
            unpinned.iter().any(|line| line.contains(&id.to_string())),
            "every candidate is listed by id: {unpinned:#?}"
        );
    }

    let pinned = history("alpha@src/other.rs")
        .expect("a pinned twin answers")
        .lines;
    assert!(
        pinned[0].contains("@ src/other.rs"),
        "the pin reaches src/other.rs's twin: {pinned:#?}"
    );
    let rows = &pinned[1..];
    assert!(
        rows.iter()
            .any(|line| line.contains(&abbreviated(&fixture.other_change))),
        "the pinned twin's own revision is listed: {pinned:#?}"
    );
    for change_id in &fixture.lib_changes {
        assert!(
            !rows
                .iter()
                .any(|line| line.contains(&abbreviated(change_id))),
            "only the pinned twin's revisions are listed: {pinned:#?}"
        );
    }
    assert!(
        !pinned.iter().any(|line| line.contains("names 2 entities")),
        "a pinned answer made no choice: {pinned:#?}"
    );

    let blame = execute_blame_request(
        &absent_binding(),
        &fixture.graph,
        &BlameRequest {
            entity: "alpha#function@src/other.rs".to_string(),
            reference: Some(head.clone()),
            all_revisions: false,
        },
    )
    .expect("a pinned twin answers blame")
    .lines
    .join("\n");
    assert!(
        blame
            .lines()
            .next()
            .unwrap_or_default()
            .contains("@ src/other.rs"),
        "{blame}"
    );
    assert!(blame.contains("1 version(s) found."), "{blame}");

    let error = history("alpha@src/nowhere.rs")
        .expect_err("a pin that excludes every twin is refused, not answered");
    let refusal = kin_cli::commands::ref_lookup::entity_query_refusal(&error)
        .expect("the refusal is typed so the daemon answers it as the caller's news");
    assert!(!refusal.absent, "the name reaches two entities: {error:#}");
    let message = error.to_string();
    assert!(
        message.contains("src/lib.rs") && message.contains("src/other.rs"),
        "the refusal names every twin the pin excluded: {message}"
    );
}
