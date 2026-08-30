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
}
