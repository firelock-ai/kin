use std::collections::HashSet;

use kin_model::entity::{Entity, EntityKind};
use kin_model::graph::GraphStore;
use kin_model::ids::EntityId;
use kin_model::relation::RelationKind;
use serde::{Deserialize, Serialize};

use crate::diff::SemanticDiff;
use crate::error::ReviewError;

/// Structured impact report for a set of changed entities.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ImpactReport {
    /// Entities that call into changed entities.
    pub affected_callers: Vec<Entity>,
    /// Entities that depend on changed entities.
    pub affected_dependents: Vec<Entity>,
    /// Contract consumers affected by changed entities.
    pub affected_contract_consumers: Vec<Entity>,
    /// Tests that cover changed entities.
    pub affected_tests: Vec<Entity>,
    /// Entity IDs that were directly changed (for cross-referencing).
    pub changed_ids: Vec<EntityId>,
}

impl ImpactReport {
    pub fn is_empty(&self) -> bool {
        self.affected_callers.is_empty()
            && self.affected_dependents.is_empty()
            && self.affected_contract_consumers.is_empty()
            && self.affected_tests.is_empty()
    }

    /// Total number of affected entities (deduplicated).
    pub fn total_affected(&self) -> usize {
        let mut seen = HashSet::new();
        for e in &self.affected_callers {
            seen.insert(e.id);
        }
        for e in &self.affected_dependents {
            seen.insert(e.id);
        }
        for e in &self.affected_contract_consumers {
            seen.insert(e.id);
        }
        for e in &self.affected_tests {
            seen.insert(e.id);
        }
        seen.len()
    }
}

/// Analyze the impact of changes described in a `SemanticDiff` by walking
/// the graph for each changed entity.
pub fn analyze_impact<G: GraphStore>(
    store: &G,
    diff: &SemanticDiff,
) -> Result<ImpactReport, ReviewError> {
    let changed_ids = diff.changed_entity_ids();
    let changed_set: HashSet<EntityId> = changed_ids.iter().copied().collect();

    let mut callers = Vec::new();
    let mut dependents = Vec::new();
    let mut contract_consumers = Vec::new();
    let mut tests = Vec::new();

    let mut seen_callers = HashSet::new();
    let mut seen_dependents = HashSet::new();
    let mut seen_consumers = HashSet::new();
    let mut seen_tests = HashSet::new();

    for &entity_id in &changed_ids {
        // Find relations pointing TO this entity (callers, dependents, etc.)
        let relations = store
            .get_relations(&entity_id, &[
                RelationKind::Calls,
                RelationKind::DependsOn,
                RelationKind::ConsumesContract,
                RelationKind::Tests,
                RelationKind::References,
            ])
            .map_err(ReviewError::graph)?;

        for rel in &relations {
            // We want entities that reference the changed entity.
            // Relations where dst == entity_id mean src depends on entity_id.
            let affected_id = if rel.dst == entity_id {
                rel.src
            } else if rel.src == entity_id {
                rel.dst
            } else {
                continue;
            };

            // Skip if the affected entity is itself a changed entity
            if changed_set.contains(&affected_id) {
                continue;
            }

            if let Some(entity) = store
                .get_entity(&affected_id)
                .map_err(ReviewError::graph)?
            {
                match rel.kind {
                    RelationKind::Calls => {
                        if seen_callers.insert(affected_id) {
                            callers.push(entity);
                        }
                    }
                    RelationKind::DependsOn | RelationKind::References => {
                        if seen_dependents.insert(affected_id) {
                            dependents.push(entity);
                        }
                    }
                    RelationKind::ConsumesContract => {
                        if seen_consumers.insert(affected_id) {
                            contract_consumers.push(entity);
                        }
                    }
                    RelationKind::Tests => {
                        if seen_tests.insert(affected_id) {
                            tests.push(entity);
                        }
                    }
                    _ => {}
                }
            }
        }

        // Also use get_downstream_impact for transitive effects
        let downstream = store
            .get_downstream_impact(&entity_id, 2)
            .map_err(ReviewError::graph)?;

        for entity in downstream {
            if changed_set.contains(&entity.id) {
                continue;
            }
            if entity.kind == EntityKind::Test {
                if seen_tests.insert(entity.id) {
                    tests.push(entity);
                }
            } else if seen_dependents.insert(entity.id) {
                dependents.push(entity);
            }
        }
    }

    Ok(ImpactReport {
        affected_callers: callers,
        affected_dependents: dependents,
        affected_contract_consumers: contract_consumers,
        affected_tests: tests,
        changed_ids,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_impact_report() {
        let report = ImpactReport::default();
        assert!(report.is_empty());
        assert_eq!(report.total_affected(), 0);
    }
}
