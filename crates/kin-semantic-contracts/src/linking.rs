// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use tracing::debug;

use kin_model::{
    Contract, ContractKind, Entity, EntityId, EntityKind, GraphStore, Relation, RelationId,
    RelationKind, RelationOrigin,
};

use crate::error::{ContractError, Result};

/// Result of linking a contract to producers and consumers.
#[derive(Debug)]
pub struct LinkResult {
    pub contract_id: EntityId,
    pub producers: Vec<EntityId>,
    pub consumers: Vec<EntityId>,
    pub relations_created: usize,
}

/// Link a contract to its producers and consumers in the graph.
///
/// Producers are entities that define/implement the contract schema.
/// Consumers are entities that reference/use the contract schema.
pub fn link_contract<G: GraphStore>(contract: &Contract, graph: &G) -> Result<LinkResult> {
    let all_entities = graph
        .list_all_entities()
        .map_err(|e| ContractError::Graph(e.to_string()))?;

    let mut producers = Vec::new();
    let mut consumers = Vec::new();
    let mut relations_created = 0;

    for entity in &all_entities {
        if is_producer(entity, contract) {
            producers.push(entity.id);

            let relation = Relation {
                id: RelationId::new(),
                kind: RelationKind::DefinesContract,
                src: entity.id,
                dst: contract.id,
                confidence: 0.8,
                origin: RelationOrigin::Inferred,
                created_in: None,
                import_source: None,
            };
            graph
                .upsert_relation(&relation)
                .map_err(|e| ContractError::Graph(e.to_string()))?;
            relations_created += 1;

            debug!(
                entity = %entity.name,
                contract = %contract.name,
                "linked producer"
            );
        }

        if is_consumer(entity, contract) {
            consumers.push(entity.id);

            let relation = Relation {
                id: RelationId::new(),
                kind: RelationKind::ConsumesContract,
                src: entity.id,
                dst: contract.id,
                confidence: 0.7,
                origin: RelationOrigin::Inferred,
                created_in: None,
                import_source: None,
            };
            graph
                .upsert_relation(&relation)
                .map_err(|e| ContractError::Graph(e.to_string()))?;
            relations_created += 1;

            debug!(
                entity = %entity.name,
                contract = %contract.name,
                "linked consumer"
            );
        }
    }

    Ok(LinkResult {
        contract_id: contract.id,
        producers,
        consumers,
        relations_created,
    })
}

/// Find all entities impacted by a contract change (cross-language propagation).
///
/// This traverses `ConsumesContract` and `DefinesContract` edges to find all
/// direct participants, then follows downstream impact transitively. Because
/// contracts are language-agnostic nodes, this naturally crosses language
/// boundaries — a TypeScript consumer and a Go producer of the same contract
/// will both appear in the result.
pub fn propagate_contract_impact<G: GraphStore>(
    contract_id: &EntityId,
    graph: &G,
) -> Result<Vec<Entity>> {
    // Get all relations pointing to or from this contract
    let relations = graph
        .get_all_relations_for_entity(contract_id)
        .map_err(|e| ContractError::Graph(e.to_string()))?;

    let mut impacted = Vec::new();
    let mut seen_ids = std::collections::HashSet::new();

    // Collect direct producers and consumers (all languages)
    for rel in &relations {
        let entity_id = match rel.kind {
            RelationKind::ConsumesContract | RelationKind::DefinesContract => &rel.src,
            _ => continue,
        };
        if seen_ids.contains(entity_id) {
            continue;
        }
        if let Some(entity) = graph
            .get_entity(entity_id)
            .map_err(|e| ContractError::Graph(e.to_string()))?
        {
            seen_ids.insert(entity.id);
            impacted.push(entity);
        }
    }

    // Propagate downstream from each consumer across all languages.
    // We collect consumer IDs first to avoid borrow issues.
    let consumer_ids: Vec<EntityId> = relations
        .iter()
        .filter(|r| r.kind == RelationKind::ConsumesContract)
        .map(|r| r.src)
        .collect();

    for consumer_id in &consumer_ids {
        let downstream = graph
            .get_downstream_impact(consumer_id, 3)
            .map_err(|e| ContractError::Graph(e.to_string()))?;
        for entity in downstream {
            if seen_ids.insert(entity.id) {
                impacted.push(entity);
            }
        }
    }

    debug!(
        contract_id = %contract_id,
        impacted = impacted.len(),
        languages = ?count_languages(&impacted),
        "propagated contract impact (cross-language)"
    );

    Ok(impacted)
}

/// Count distinct languages among impacted entities (for debug logging).
fn count_languages(entities: &[Entity]) -> usize {
    let mut langs = std::collections::HashSet::new();
    for e in entities {
        langs.insert(e.language);
    }
    langs.len()
}

/// Heuristic: check if an entity produces (defines/implements) this contract.
fn is_producer(entity: &Entity, contract: &Contract) -> bool {
    match contract.kind {
        ContractKind::OpenApi => {
            // API endpoints and route handlers are producers
            matches!(entity.kind, EntityKind::ApiEndpoint | EntityKind::Function)
                && (entity.name.contains("handler")
                    || entity.name.contains("route")
                    || entity.name.contains("endpoint")
                    || entity.signature.contains("Request")
                    || entity.signature.contains("Response"))
        }
        ContractKind::Protobuf => {
            // Generated message types and service implementations
            entity.signature.contains(&contract.name) || entity.name.contains(&contract.name)
        }
        ContractKind::GraphQL => {
            // Resolver functions are producers
            entity.name.contains("resolver")
                || entity.name.contains("Resolver")
                || (matches!(entity.kind, EntityKind::Function | EntityKind::Method)
                    && entity.signature.contains("GraphQL"))
        }
        ContractKind::DbSchema => {
            // Functions that write to or migrate the schema
            entity.name.contains("migrate")
                || entity.name.contains("schema")
                || entity.signature.contains("CREATE")
                || entity.signature.contains("ALTER")
        }
        ContractKind::EventSchema => {
            // Functions that emit events
            entity.name.contains("emit")
                || entity.name.contains("publish")
                || entity.name.contains("send")
                || entity.signature.contains(&contract.name)
        }
        ContractKind::TypedInterface => {
            // Implementors of typed interfaces
            entity.signature.contains(&contract.name)
        }
    }
}

/// Heuristic: check if an entity consumes (references/uses) this contract.
fn is_consumer(entity: &Entity, contract: &Contract) -> bool {
    match contract.kind {
        ContractKind::OpenApi => {
            // HTTP client calls, API consumers
            entity.name.contains("client")
                || entity.name.contains("fetch")
                || entity.name.contains("api")
                || entity.signature.contains("fetch")
                || entity.signature.contains("axios")
        }
        ContractKind::Protobuf => {
            // Code referencing protobuf message types
            entity.signature.contains(&contract.name) && !entity.name.contains(&contract.name)
        }
        ContractKind::GraphQL => {
            // Query/mutation callers
            entity.name.contains("query")
                || entity.name.contains("mutation")
                || entity.signature.contains("gql")
                || entity.signature.contains("graphql")
        }
        ContractKind::DbSchema => {
            // Functions that query/read from the schema
            entity.name.contains("query")
                || entity.name.contains("find")
                || entity.name.contains("get")
                || entity.signature.contains("SELECT")
        }
        ContractKind::EventSchema => {
            // Event handlers/subscribers
            entity.name.contains("handle")
                || entity.name.contains("subscribe")
                || entity.name.contains("on_")
                || entity.name.contains("listener")
        }
        ContractKind::TypedInterface => {
            // Callers that use the interface type
            entity.signature.contains(&contract.name)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{
        EntityMetadata, FingerprintAlgorithm, Hash256, LanguageId, SemanticFingerprint, Visibility,
    };

    fn test_entity(name: &str, sig: &str) -> Entity {
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::TypeScript,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0; 32]),
                signature_hash: Hash256::from_bytes([0; 32]),
                behavior_hash: Hash256::from_bytes([0; 32]),
                stability_score: 0.9,
            },
            file_origin: None,
            span: None,
            signature: sig.to_string(),
            visibility: Visibility::Public,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    fn test_contract() -> Contract {
        Contract {
            id: EntityId::new(),
            kind: ContractKind::OpenApi,
            name: "PetStore".to_string(),
            schema_hash: Hash256::from_bytes([0; 32]),
            producers: Vec::new(),
            consumers: Vec::new(),
            version: Some("1.0".to_string()),
        }
    }

    #[test]
    fn is_producer_detects_handler() {
        let entity = test_entity("handleGetPets", "handleGetPets(req: Request): Response");
        let contract = test_contract();
        assert!(is_producer(&entity, &contract));
    }

    #[test]
    fn is_consumer_detects_client() {
        let entity = test_entity("fetchPets", "fetchPets(): Promise<Pet[]>");
        let contract = test_contract();
        assert!(is_consumer(&entity, &contract));
    }

    #[test]
    fn non_related_entity_is_neither() {
        let entity = test_entity("calculateSum", "calculateSum(a: number, b: number): number");
        let contract = test_contract();
        assert!(!is_producer(&entity, &contract));
        assert!(!is_consumer(&entity, &contract));
    }
}
