// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Graphs holding call-site ledgers, for the command tests that render them.

use kin_db::InMemoryGraph;
use kin_model::entity::{EntityMetadata, SourceSpan};
use kin_model::{
    CallSite, CallSiteLedger, CallSiteState, Entity, EntityId, EntityKind, EntityRole, EntityStore,
    FilePathId, FingerprintAlgorithm, Hash256, LanguageId, ProofContext, ResolutionRecord,
    ResolutionRecordDelta, SemanticFingerprint, TransactionDelta, Visibility,
};

/// A Python function whose own text is `body`, starting at byte `start` of
/// `file`. `file_origin` is left unset so no command reads a body for it.
pub(crate) fn spanned(name: &str, file: &str, start: usize, body: &str) -> Entity {
    Entity {
        id: EntityId::from_content(file, name, "Function", start as u32),
        kind: EntityKind::Function,
        name: name.to_string(),
        language: LanguageId::Python,
        fingerprint: SemanticFingerprint {
            algorithm: FingerprintAlgorithm::V1TreeSitter,
            ast_hash: Hash256::from_bytes([0; 32]),
            signature_hash: Hash256::from_bytes([0; 32]),
            behavior_hash: Hash256::from_bytes([9; 32]),
            equivalence_hash: Hash256::from_bytes([0; 32]),
            stability_score: 1.0,
        },
        file_origin: None,
        span: Some(SourceSpan {
            file: FilePathId::new(file),
            start_byte: start,
            end_byte: start + body.len(),
            start_line: 4,
            start_col: 0,
            end_line: 4 + body.matches('\n').count() as u32,
            end_col: 0,
        }),
        signature: format!("def {name}()"),
        visibility: Visibility::Public,
        role: EntityRole::Source,
        doc_summary: None,
        metadata: EntityMetadata::default(),
        lineage_parent: None,
        created_in: None,
        superseded_by: None,
    }
}

/// Put `entities` in the graph, then one proof context and a ledger for each
/// `(caller, body, sites)`, each site's token found in the body in order.
pub(crate) fn admit(
    graph: &InMemoryGraph,
    entities: &[&Entity],
    ledgers: Vec<(&Entity, &str, Vec<(&str, CallSiteState)>)>,
) {
    for entity in entities {
        graph.upsert_entity(entity).unwrap();
    }
    let context = ResolutionRecord::ProofContext(ProofContext {
        language: LanguageId::Python,
        resolver: "lsp:pyright".to_string(),
        resolver_version: "1.1.400".to_string(),
        configuration_hash: Hash256::from_bytes([0x41; 32]),
        environment_hash: Hash256::from_bytes([0x42; 32]),
        environment_summary: "python 3.12".to_string(),
    });
    let context_id = context.id();
    let mut records = vec![context];
    for (caller, body, sites) in ledgers {
        let mut from = 0usize;
        let sites: Vec<CallSite> = sites
            .into_iter()
            .map(|(token, state)| {
                let offset = from + body[from..].find(token).expect("the token is in the body");
                from = offset + token.len();
                CallSite {
                    offset: offset as u32,
                    length: token.len() as u32,
                    state,
                }
            })
            .collect();
        records.push(ResolutionRecord::CallSites(CallSiteLedger {
            caller: caller.id,
            behavior_hash: caller.fingerprint.behavior_hash,
            body_hash: Hash256::from_bytes([0x43; 32]),
            context: context_id,
            census: sites.len() as u32,
            sites,
        }));
    }
    graph
        .apply_transaction_delta(&TransactionDelta {
            resolution_record_deltas: records
                .into_iter()
                .map(|new| ResolutionRecordDelta::Added { new })
                .collect(),
            ..TransactionDelta::default()
        })
        .expect("the fixture's records are admitted");
}
