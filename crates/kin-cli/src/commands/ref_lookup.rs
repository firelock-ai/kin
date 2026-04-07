// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{Result, anyhow, bail};
use kin_model::{BranchName, Entity, EntityFilter, GraphStore};
use kin_model::{Hash256, SemanticChangeId};

pub(crate) fn parse_change_id(input: &str) -> Result<SemanticChangeId> {
    Ok(SemanticChangeId::from_hash(
        Hash256::from_hex(input).map_err(|err| anyhow!("invalid change hash: {}", err))?,
    ))
}

pub fn resolve_ref<G>(
    graph: &G,
    layout: &kin_core::KinLayout,
    reference: Option<&str>,
) -> Result<SemanticChangeId>
where
    G: GraphStore,
    <G as GraphStore>::Error: std::fmt::Display + Send + Sync + 'static,
{
    match reference {
        Some(reference) => resolve_explicit_ref(graph, layout, reference),
        None => {
            let current = kin_core::read_current_branch(layout)?;
            let branch = graph
                .get_branch(&current)
                .map_err(|err| anyhow!(err.to_string()))?
                .ok_or_else(|| anyhow!("branch '{}' not found", current))?;
            Ok(branch.head)
        }
    }
}

pub(crate) fn resolve_entity_query<G>(graph: &G, entity_query: &str) -> Result<Entity>
where
    G: GraphStore,
    <G as GraphStore>::Error: std::fmt::Display + Send + Sync + 'static,
{
    let filter = EntityFilter {
        name_pattern: Some(entity_query.to_string()),
        ..Default::default()
    };
    let entities = graph
        .query_entities(&filter)
        .map_err(|err| anyhow!(err.to_string()))?;
    choose_entity_match(entities, entity_query).or_else(|_| {
        let all = graph
            .list_all_entities()
            .map_err(|err| anyhow!(err.to_string()))?;
        choose_entity_match(all, entity_query)
    })
}

pub(crate) fn resolve_entity_query_at_ref<G>(
    graph: &G,
    entity_query: &str,
    head: &SemanticChangeId,
) -> Result<Entity>
where
    G: GraphStore,
    <G as GraphStore>::Error: std::fmt::Display + Send + Sync + 'static,
{
    let state = graph
        .resolve_graph_at(head)
        .map_err(|err| anyhow!(err.to_string()))?;
    let entities = state
        .entities
        .into_values()
        .filter(|entity| entity_matches_query(entity, entity_query))
        .collect();
    choose_entity_match(entities, entity_query)
}

fn resolve_explicit_ref<G>(
    graph: &G,
    layout: &kin_core::KinLayout,
    reference: &str,
) -> Result<SemanticChangeId>
where
    G: GraphStore,
    <G as GraphStore>::Error: std::fmt::Display + Send + Sync + 'static,
{
    if let Some(suffix) = reference.strip_prefix("HEAD") {
        let current = kin_core::read_current_branch(layout)?;
        let branch = graph
            .get_branch(&current)
            .map_err(|err| anyhow!(err.to_string()))?
            .ok_or_else(|| anyhow!("branch '{}' not found", current))?;
        let mut head = branch.head;
        if let Some(tilde_part) = suffix.strip_prefix('~') {
            let distance = tilde_part
                .parse::<usize>()
                .map_err(|_| anyhow!("invalid HEAD~N syntax: {}", reference))?;
            for _ in 0..distance {
                let change = graph
                    .get_change(&head)
                    .map_err(|err| anyhow!(err.to_string()))?
                    .ok_or_else(|| anyhow!("change {} not found in history", head))?;
                head = *change
                    .parents
                    .first()
                    .ok_or_else(|| anyhow!("{} exceeds history depth", reference))?;
            }
        } else if !suffix.is_empty() {
            bail!("unknown ref syntax: {}", reference);
        }
        return Ok(head);
    }

    if let Some(branch_name) = reference.strip_prefix("branch:") {
        return resolve_branch_head(graph, branch_name);
    }

    if let Some(git_oid) = reference.strip_prefix("git:") {
        return resolve_imported_git_ref(graph, git_oid);
    }

    if let Some(change_ref) = reference
        .strip_prefix("kin:")
        .or_else(|| reference.strip_prefix("change:"))
    {
        return resolve_semantic_change(graph, change_ref);
    }

    if let Some(branch) = graph
        .get_branch(&BranchName::new(reference))
        .map_err(|err| anyhow!(err.to_string()))?
    {
        return Ok(branch.head);
    }

    if reference.len() == 40 {
        if let Ok(imported_change_id) = resolve_imported_git_ref(graph, reference) {
            return Ok(imported_change_id);
        }
    }

    if parse_change_id(reference).is_ok() {
        return resolve_semantic_change(graph, reference);
    }

    bail!("unknown ref '{}'", reference)
}

fn resolve_branch_head<G>(graph: &G, branch_name: &str) -> Result<SemanticChangeId>
where
    G: GraphStore,
    <G as GraphStore>::Error: std::fmt::Display + Send + Sync + 'static,
{
    if let Some(branch) = graph
        .get_branch(&BranchName::new(branch_name))
        .map_err(|err| anyhow!(err.to_string()))?
    {
        return Ok(branch.head);
    }

    bail!("branch '{}' not found", branch_name);
}

fn resolve_imported_git_ref<G>(graph: &G, git_oid: &str) -> Result<SemanticChangeId>
where
    G: GraphStore,
    <G as GraphStore>::Error: std::fmt::Display + Send + Sync + 'static,
{
    let imported_change_id = kin_git::semantic_change_id_from_git_oid_hex(git_oid)?;
    if graph
        .get_change(&imported_change_id)
        .map_err(|err| anyhow!(err.to_string()))?
        .is_some()
    {
        Ok(imported_change_id)
    } else {
        bail!("imported Git commit '{}' not found", git_oid);
    }
}

fn resolve_semantic_change<G>(graph: &G, change_ref: &str) -> Result<SemanticChangeId>
where
    G: GraphStore,
    <G as GraphStore>::Error: std::fmt::Display + Send + Sync + 'static,
{
    let change_id = parse_change_id(change_ref)?;
    if graph
        .get_change(&change_id)
        .map_err(|err| anyhow!(err.to_string()))?
        .is_some()
    {
        Ok(change_id)
    } else {
        bail!("change {} not found", change_id);
    }
}

fn choose_entity_match(mut entities: Vec<Entity>, entity_query: &str) -> Result<Entity> {
    if entities.is_empty() {
        bail!("No entity matching '{}' found.", entity_query);
    }

    entities.sort_by(|left, right| {
        left.name
            .cmp(&right.name)
            .then_with(|| left.id.to_string().cmp(&right.id.to_string()))
    });

    if let Some(exact) = entities
        .iter()
        .find(|entity| entity.id.to_string() == entity_query || entity.name == entity_query)
    {
        return Ok(exact.clone());
    }

    if let Some(case_insensitive) = entities
        .iter()
        .find(|entity| entity.name.eq_ignore_ascii_case(entity_query))
    {
        return Ok(case_insensitive.clone());
    }

    match entities.as_slice() {
        [entity] => Ok(entity.clone()),
        many => {
            let preview = many
                .iter()
                .take(5)
                .map(|entity| entity.name.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            bail!(
                "Multiple entities match '{}': {}. Use a more exact name.",
                entity_query,
                preview
            );
        }
    }
}

fn entity_matches_query(entity: &Entity, entity_query: &str) -> bool {
    entity.id.to_string() == entity_query || name_matches_pattern(&entity.name, entity_query)
}

fn name_matches_pattern(name: &str, pattern: &str) -> bool {
    let name = name.to_lowercase();
    let pattern = pattern.to_lowercase();
    if let Some(suffix) = pattern.strip_prefix('*') {
        name.ends_with(suffix)
    } else if let Some(prefix) = pattern.strip_suffix('*') {
        name.starts_with(prefix)
    } else {
        name.contains(&pattern)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_db::InMemoryGraph;
    use kin_model::{AuthorId, Branch, ChangeStore, SemanticChange, Timestamp};

    fn temp_layout() -> kin_core::KinLayout {
        let temp = tempfile::tempdir().unwrap();
        let kin_dir = temp.path().join(".kin");
        std::fs::create_dir_all(&kin_dir).unwrap();
        // Keep the tempdir alive by leaking it for the test process lifetime.
        let leaked = temp.keep();
        kin_core::KinLayout::new(leaked.join(".kin"))
    }

    #[test]
    fn resolve_ref_accepts_imported_git_commit_sha() {
        let graph = InMemoryGraph::new();
        let layout = temp_layout();
        let git_oid = "1111111111111111111111111111111111111111";
        let imported_id = kin_git::semantic_change_id_from_git_oid_hex(git_oid).unwrap();
        graph
            .create_change(&SemanticChange {
                id: imported_id,
                parents: vec![],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "imported git commit".to_string(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                artifact_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let resolved = resolve_ref(&graph, &layout, Some(git_oid)).unwrap();
        assert_eq!(resolved, imported_id);
    }

    #[test]
    fn resolve_ref_accepts_prefixed_git_commit_sha() {
        let graph = InMemoryGraph::new();
        let layout = temp_layout();
        let git_oid = "1111111111111111111111111111111111111111";
        let imported_id = kin_git::semantic_change_id_from_git_oid_hex(git_oid).unwrap();
        graph
            .create_change(&SemanticChange {
                id: imported_id,
                parents: vec![],
                timestamp: Timestamp::now(),
                author: AuthorId::new("test"),
                message: "imported git commit".to_string(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                artifact_deltas: vec![],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            })
            .unwrap();

        let resolved = resolve_ref(&graph, &layout, Some(&format!("git:{git_oid}"))).unwrap();
        assert_eq!(resolved, imported_id);
    }

    #[test]
    fn resolve_ref_accepts_prefixed_change_id() {
        let graph = InMemoryGraph::new();
        let layout = temp_layout();
        let change = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0x41; 32])),
            parents: vec![],
            timestamp: Timestamp::now(),
            author: AuthorId::new("test"),
            message: "kin change".to_string(),
            entity_deltas: vec![],
            relation_deltas: vec![],
            artifact_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            authored_on: None,
        };
        graph.create_change(&change).unwrap();

        let resolved = resolve_ref(&graph, &layout, Some(&format!("kin:{}", change.id))).unwrap();
        assert_eq!(resolved, change.id);
    }

    #[test]
    fn resolve_ref_accepts_prefixed_branch_name() {
        let graph = InMemoryGraph::new();
        let layout = temp_layout();
        let change = SemanticChange {
            id: SemanticChangeId::from_hash(Hash256::from_bytes([0x52; 32])),
            parents: vec![],
            timestamp: Timestamp::now(),
            author: AuthorId::new("test"),
            message: "branch tip".to_string(),
            entity_deltas: vec![],
            relation_deltas: vec![],
            artifact_deltas: vec![],
            projected_files: vec![],
            spec_link: None,
            evidence: vec![],
            risk_summary: None,
            authored_on: None,
        };
        graph.create_change(&change).unwrap();
        let branch = Branch {
            name: BranchName::new("feature/history"),
            head: change.id,
        };
        graph.create_branch(&branch).unwrap();

        let resolved = resolve_ref(&graph, &layout, Some("branch:feature/history")).unwrap();
        assert_eq!(resolved, branch.head);
    }
}
