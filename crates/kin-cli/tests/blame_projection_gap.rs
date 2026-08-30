// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! `kin blame` and `kin history` when the live graph cannot replay to the head.
//!
//! Built as a HANDLER-LEVEL test that constructs the projection state directly,
//! deliberately, rather than by driving a real merge.
//!
//! The rc062j stranger run found that a published merge never reached the
//! running daemon's live graph, so every read that replays to it failed. That is
//! fixed elsewhere (kin#1287 installs the published change into the live graph
//! on both merge publish paths, with the rollback install behind it), and the
//! moment it lands the merge scenario stops reproducing. A test that drove a
//! real merge would then pass while asserting nothing, which is the shape this
//! repository catalogues as a check that cannot fail.
//!
//! So the state is built here: a graph that holds a change whose PARENT it does
//! not, which is exactly what the replay walks into. That state is reachable
//! whenever a projection is incomplete, whatever produced it, so these assertions
//! outlive the specific defect that motivated them.
//!
//! What they pin:
//!
//! * the failure is classified, not an internal fault, because a lookup miss
//!   raised after `resolve_ref` succeeded was reaching `internal_error` and
//!   surfacing as an HTTP 500;
//! * the message names the ref the CALLER typed, which the 500 never did: it
//!   printed only the missing id, and the missing id is a different change from
//!   the resolved one, so a reader concluded their ref resolved to nothing;
//! * it names a remedy that works, since the message it replaces named
//!   `kin status`, measured on 2026-08-30 not to clear this state.

use std::sync::Arc;

use kin_cli::commands::blame::{execute_blame_request, BlameRequest};
use kin_cli::commands::history::{execute_history_request, HistoryRequest};
use kin_cli::commands::ref_lookup::is_graph_projection_error;
use kin_model::{
    AuthorId, ChangeOrigin, ChangeStore, Entity, EntityDelta, EntityId, EntityKind, EntityMetadata,
    EntityRole, FilePathId, FingerprintAlgorithm, Hash256, LanguageId, SemanticChange,
    SemanticChangeId, SemanticFingerprint, Timestamp, Visibility,
};

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
        kin_model::RepositoryId::new("absent-blame-projection-gap").unwrap(),
        kin_model::WorkspaceId::new(),
        Arc::new(kin_db::LocalFileBackend::new(layout.kindb_dir())),
    )
}

/// A graph holding a head whose parent it does not, plus the two ids.
///
/// Returns `(graph, head, missing_ancestor)`. The head is present, so
/// `resolve_ref` succeeds and the failure is downstream of resolution, which is
/// the whole reason the old error named an id the caller never asked for.
fn graph_missing_an_ancestor() -> (kin_db::InMemoryGraph, SemanticChangeId, SemanticChangeId) {
    let graph = kin_db::InMemoryGraph::new();
    let alpha_id = EntityId::new();

    let introduce = change(
        vec![],
        "introduce alpha",
        vec![EntityDelta::Added {
            new: entity(alpha_id, "alpha", 1),
        }],
    );
    let revise = change(
        vec![introduce.id],
        "revise alpha",
        vec![EntityDelta::Modified {
            old: entity(alpha_id, "alpha", 1),
            new: entity(alpha_id, "alpha", 2),
        }],
    );

    // ONLY the head is admitted. Its parent is deliberately absent, which is the
    // state a projection is in when it holds a publication whose history it never
    // received.
    graph.create_change(&revise).expect("admit the head change");

    (graph, revise.id, introduce.id)
}

/// The precondition every assertion below rests on, asserted rather than assumed.
///
/// If the head were absent the failure would come from `resolve_ref` instead,
/// which is a different code path with a different classification, and every test
/// here would pass for the wrong reason.
#[test]
fn the_fixture_holds_the_head_and_not_its_parent() {
    let (graph, head, missing) = graph_missing_an_ancestor();
    assert!(
        graph.get_change(&head).expect("read head").is_some(),
        "the head must be present, or the failure comes from ref resolution instead"
    );
    assert!(
        graph.get_change(&missing).expect("read parent").is_none(),
        "the parent must be absent, or there is no projection gap to grade"
    );
    assert_ne!(
        head, missing,
        "the resolved change and the missing one must differ, which is the fact the old 500 hid"
    );
}

#[test]
fn blame_classifies_a_projection_gap_instead_of_failing_internally() {
    let (graph, head, missing) = graph_missing_an_ancestor();
    let request = BlameRequest {
        entity: "alpha".to_string(),
        reference: Some(format!("kin:{head}")),
        all_revisions: false,
    };

    let error = execute_blame_request(&absent_binding(), &graph, &request)
        .expect_err("a graph that cannot replay to the head must not answer");

    assert!(
        is_graph_projection_error(&error),
        "the failure must be typed so the daemon classifies it as the caller's news rather \
         than returning a 500; got: {error:#}"
    );

    let rendered = format!("{error:#}");
    assert!(
        rendered.contains(&head.to_string()),
        "the message must name the change the ref resolved to; got: {rendered}"
    );
    assert!(
        rendered.contains(&missing.to_string()),
        "the message must name the MISSING ancestor as the cause, which is a different change \
         from the resolved head and is the distinction the old 500 destroyed; got: {rendered}"
    );
    assert!(
        rendered.contains("kin daemon stop"),
        "the message must name a remedy that clears this state; got: {rendered}"
    );
    assert!(
        !rendered.contains("run `kin status`"),
        "the message must not name `kin status`, measured on 2026-08-30 not to clear it; \
         got: {rendered}"
    );
}

#[test]
fn history_classifies_the_same_gap_the_same_way() {
    let (graph, head, missing) = graph_missing_an_ancestor();
    let request = HistoryRequest {
        entity: "alpha".to_string(),
        reference: Some(format!("kin:{head}")),
        all_revisions: false,
    };

    let error = execute_history_request(&absent_binding(), &graph, &request)
        .expect_err("a graph that cannot replay to the head must not answer");

    assert!(
        is_graph_projection_error(&error),
        "history must classify the same gap blame does, or a fix reaches one surface only; \
         got: {error:#}"
    );
    let rendered = format!("{error:#}");
    assert!(
        rendered.contains(&head.to_string()) && rendered.contains(&missing.to_string()),
        "history's message must carry the same two ids blame's does; got: {rendered}"
    );
}

/// The caller's own spelling survives into the message, not just the resolved id.
///
/// Separate from the test above because that one passes a `kin:<id>` ref, where
/// the typed text and the resolved id are the same string. rc062j reported every
/// ref form naming the same change, so the case that matters is a ref whose
/// spelling is NOT the id.
#[test]
fn the_message_names_the_ref_the_caller_typed_not_only_what_it_resolved_to() {
    let (graph, head, _) = graph_missing_an_ancestor();
    let request = BlameRequest {
        entity: "alpha".to_string(),
        reference: Some(format!("change:{head}")),
        all_revisions: false,
    };

    let error = execute_blame_request(&absent_binding(), &graph, &request)
        .expect_err("a graph that cannot replay to the head must not answer");
    let rendered = format!("{error:#}");
    assert!(
        rendered.contains("change:"),
        "the message must echo the ref as the caller spelled it, since a reader who typed \
         `change:<id>` cannot match a bare id back to their own command; got: {rendered}"
    );
}
