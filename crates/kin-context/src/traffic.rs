// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Advisory traffic against observed, directed dependencies in the selected graph.
//! This does not change lease overlap or certify that the graph is complete.

use std::collections::{HashMap, HashSet, VecDeque};

use kin_model::{
    Entity, FilePathId, GraphNodeId, GraphStore, Intent, IntentScope, IntentSummary, Timestamp,
    TrafficEntry, TrafficProximity,
};

use crate::{builder::is_dependency_edge, ContextError, Result};

/// A live coordination snapshot retaining the scopes absent from a display summary.
/// Callers supply only intents whose owning session is still present.
#[derive(Debug, Clone)]
pub struct ScopedTrafficIntent {
    pub intent: Intent,
    pub vendor: String,
}

impl ScopedTrafficIntent {
    fn summary(&self) -> IntentSummary {
        IntentSummary {
            intent_id: self.intent.intent_id,
            session_id: self.intent.session_id,
            vendor: self.vendor.clone(),
            task_description: self.intent.task_description.clone(),
            lock_type: self.intent.lock_type,
            registered_at: self.intent.registered_at.clone(),
        }
    }
}

const MAX_TRAFFIC_NODES: usize = 4096;
const MAX_TRAFFIC_EDGES: usize = 32768;

fn rank(proximity: TrafficProximity) -> u8 {
    match proximity {
        TrafficProximity::Direct => 0,
        TrafficProximity::SameFile => 1,
        TrafficProximity::Downstream => 2,
    }
}

/// Strongest scope wins; within a class, the shortest observed path wins.
/// Only outgoing code-dependency edges count. Non-entity targets are matched as
/// explicit terminal contract/artifact scopes; no UUID-to-entity coercion is used.
pub(crate) fn classify<G: GraphStore>(
    graph: &G,
    focal: &Entity,
    depth: u32,
    intents: &[ScopedTrafficIntent],
) -> Result<Vec<TrafficEntry>> {
    let mut distances = HashMap::from([(GraphNodeId::Entity(focal.id), 0u32)]);
    let mut files: HashMap<FilePathId, u32> = HashMap::new();
    let mut entities = HashMap::from([(focal.id, Some(focal.clone()))]);
    let mut queue = VecDeque::from([(focal.id, 0u32)]);
    let mut examined_edges = 0usize;
    while let Some((id, distance)) = queue.pop_front() {
        if distance >= depth {
            continue;
        }
        for relation in graph
            .traverse(&GraphNodeId::Entity(id), &[], 1)
            .map_err(|e| ContextError::Graph(e.to_string()))?
            .relations
        {
            examined_edges += 1;
            if examined_edges > MAX_TRAFFIC_EDGES {
                return Err(ContextError::Other(
                    "traffic proximity edge budget exceeded".into(),
                ));
            }
            if relation.src != GraphNodeId::Entity(id) || !is_dependency_edge(&relation.kind) {
                continue;
            }
            if distances.contains_key(&relation.dst) {
                continue;
            }
            if distances.len() >= MAX_TRAFFIC_NODES {
                return Err(ContextError::Other(
                    "traffic proximity node budget exceeded".into(),
                ));
            }
            let next = distance + 1;
            if let GraphNodeId::Entity(target) = relation.dst {
                let entity = graph
                    .get_entity(&target)
                    .map_err(|e| ContextError::Graph(e.to_string()))?;
                // A dangling endpoint does not establish a current entity scope.
                let Some(entity) = entity else {
                    continue;
                };
                if let Some(file) = &entity.file_origin {
                    files.entry(file.clone()).or_insert(next);
                }
                entities.insert(target, Some(entity));
                queue.push_back((target, next));
            }
            distances.insert(relation.dst, next);
        }
    }

    let now = Timestamp::now();
    let mut seen = HashSet::new();
    let mut rows = Vec::new();
    let mut examined_scopes = 0usize;
    for input in intents {
        if input
            .intent
            .expires_at
            .as_ref()
            .is_some_and(|expiry| expiry < &now)
            || !seen.insert(input.intent.intent_id)
        {
            continue;
        }
        let mut best: Option<(u8, u32, TrafficProximity)> = None;
        for scope in &input.intent.scopes {
            examined_scopes += 1;
            if examined_scopes > MAX_TRAFFIC_EDGES {
                return Err(ContextError::Other(
                    "traffic proximity scope budget exceeded".into(),
                ));
            }
            let mut same_file = false;
            let distance = match scope {
                IntentScope::Entity(id) => {
                    if !entities.contains_key(id) {
                        if entities.len() >= MAX_TRAFFIC_NODES {
                            return Err(ContextError::Other(
                                "traffic proximity scope entity budget exceeded".into(),
                            ));
                        }
                        let entity = graph
                            .get_entity(id)
                            .map_err(|e| ContextError::Graph(e.to_string()))?;
                        entities.insert(*id, entity);
                    }
                    same_file = entities
                        .get(id)
                        .and_then(Option::as_ref)
                        .is_some_and(|entity| {
                            focal.file_origin.is_some() && entity.file_origin == focal.file_origin
                        });
                    distances.get(&GraphNodeId::Entity(*id)).copied()
                }
                IntentScope::Artifact(file) => {
                    same_file = focal.file_origin.as_ref() == Some(file);
                    if same_file {
                        None
                    } else {
                        let explicit = kin_model::RepoPath::try_from(file.0.as_str())
                            .ok()
                            .and_then(|path| graph.artifact_id_at_path(&path))
                            .and_then(|id| distances.get(&GraphNodeId::Artifact(id)).copied());
                        files.get(file).copied().into_iter().chain(explicit).min()
                    }
                }
                IntentScope::Contract(id) => distances.get(&GraphNodeId::Contract(*id)).copied(),
            };
            let proximity = match distance {
                Some(distance @ (0 | 1)) => Some((TrafficProximity::Direct, distance)),
                _ if same_file => Some((TrafficProximity::SameFile, 0)),
                Some(distance) => Some((TrafficProximity::Downstream, distance)),
                None => None,
            };
            if let Some((proximity, distance)) = proximity {
                let candidate = (rank(proximity), distance, proximity);
                if best
                    .as_ref()
                    .is_none_or(|old| (candidate.0, candidate.1) < (old.0, old.1))
                {
                    best = Some(candidate);
                }
            }
        }
        if let Some((rank, distance, proximity)) = best {
            rows.push((
                rank,
                distance,
                input.intent.intent_id.to_string(),
                TrafficEntry {
                    intent: input.summary(),
                    proximity,
                },
            ));
        }
    }
    rows.sort_by(|left, right| (&left.0, &left.1, &left.2).cmp(&(&right.0, &right.1, &right.2)));
    Ok(rows.into_iter().map(|(_, _, _, entry)| entry).collect())
}
