// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::{anyhow, bail, Result};
use kin_model::{Entity, EntityFilter, GraphStore, Hash256, SemanticChangeId};

use super::repository_authority::{parse_git_object_id, parse_ref_name, ActiveRepositoryAuthority};

/// A reference did not resolve through repository-v6 authority.
#[derive(Debug)]
pub struct RefResolutionError {
    reference: String,
    reason: String,
}

impl std::fmt::Display for RefResolutionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "cannot resolve ref '{}': {}",
            self.reference, self.reason
        )
    }
}

impl std::error::Error for RefResolutionError {}

fn ref_error(reference: impl Into<String>, reason: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(RefResolutionError {
        reference: reference.into(),
        reason: reason.into(),
    })
}

pub fn is_ref_resolution_error(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.downcast_ref::<RefResolutionError>().is_some())
}

pub(crate) fn parse_change_id(input: &str) -> Result<SemanticChangeId> {
    Ok(SemanticChangeId::from_hash(
        Hash256::from_hex(input).map_err(|error| anyhow!("invalid change hash: {error}"))?,
    ))
}

pub fn resolve_ref<G>(
    graph: &G,
    binding: &kin_core::LocalRepositoryAuthorityBinding,
    reference: Option<&str>,
) -> Result<SemanticChangeId>
where
    G: GraphStore,
    <G as GraphStore>::Error: std::fmt::Display + Send + Sync + 'static,
{
    let reference = reference.unwrap_or("HEAD");
    if reference.contains("@{") {
        return Err(ref_error(
            reference,
            "reflog/upstream '@{...}' syntax is not supported",
        ));
    }

    let (core, hops) = split_relative_hops(reference)?;
    let head = resolve_ref_core(graph, binding, reference, core)?;
    apply_parent_hops(graph, reference, head, &hops)
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
        .map_err(|error| anyhow!(error.to_string()))?;
    choose_entity_match(entities, entity_query).or_else(|_| {
        let all = graph
            .list_all_entities()
            .map_err(|error| anyhow!(error.to_string()))?;
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
        .map_err(|error| anyhow!(error.to_string()))?;
    let entities = state
        .entities
        .into_values()
        .filter(|entity| entity_matches_query(entity, entity_query))
        .collect();
    choose_entity_match(entities, entity_query)
}

#[derive(Debug, Clone, Copy)]
struct ParentHop(usize);

fn split_relative_hops(reference: &str) -> Result<(&str, Vec<ParentHop>)> {
    let mut hops = Vec::new();
    let mut rest = reference;
    while let Some(&last) = rest.as_bytes().last() {
        if last == b'^' || last == b'~' {
            hops.push(ParentHop(1));
            rest = &rest[..rest.len() - 1];
            continue;
        }
        if last.is_ascii_digit() {
            let digits_start = rest
                .rfind(|character: char| !character.is_ascii_digit())
                .map(|index| index + 1)
                .unwrap_or(0);
            if digits_start == 0 {
                break;
            }
            let marker = rest.as_bytes()[digits_start - 1];
            if marker != b'^' && marker != b'~' {
                break;
            }
            let count: usize = rest[digits_start..]
                .parse()
                .map_err(|_| ref_error(reference, "parent index is out of range"))?;
            if marker == b'^' {
                if count == 0 {
                    break;
                }
                hops.push(ParentHop(count));
            } else {
                hops.extend(std::iter::repeat_n(ParentHop(1), count));
            }
            rest = &rest[..digits_start - 1];
            continue;
        }
        break;
    }
    Ok((rest, hops))
}

fn apply_parent_hops<G>(
    graph: &G,
    original: &str,
    mut head: SemanticChangeId,
    hops: &[ParentHop],
) -> Result<SemanticChangeId>
where
    G: GraphStore,
    <G as GraphStore>::Error: std::fmt::Display + Send + Sync + 'static,
{
    for hop in hops {
        let change = graph
            .get_change(&head)
            .map_err(|error| anyhow!(error.to_string()))?
            .ok_or_else(|| ref_error(original, format!("change {head} not found in history")))?;
        head = *change.parents.get(hop.0 - 1).ok_or_else(|| {
            ref_error(
                original,
                format!(
                    "{head} has {} parent(s), no parent #{}",
                    change.parents.len(),
                    hop.0
                ),
            )
        })?;
    }
    Ok(head)
}

fn resolve_ref_core<G>(
    graph: &G,
    binding: &kin_core::LocalRepositoryAuthorityBinding,
    original: &str,
    core: &str,
) -> Result<SemanticChangeId>
where
    G: GraphStore,
    <G as GraphStore>::Error: std::fmt::Display + Send + Sync + 'static,
{
    if let Some(change_ref) = core
        .strip_prefix("kin:")
        .or_else(|| core.strip_prefix("change:"))
    {
        return resolve_semantic_change(graph, original, change_ref);
    }

    // A full semantic change id is unambiguous when that change is present.
    if core.len() == 64 {
        if let Ok(change_id) = parse_change_id(core) {
            if graph
                .get_change(&change_id)
                .map_err(|error| anyhow!(error.to_string()))?
                .is_some()
            {
                return Ok(change_id);
            }
        }
    }

    let authority = ActiveRepositoryAuthority::open(binding).map_err(|error| {
        ref_error(
            original,
            format!("repository-v6 authority is unavailable: {error:#}"),
        )
    })?;

    let resolved = if core == "HEAD" {
        authority
            .current_change_id()
            .map_err(|error| {
                ref_error(
                    original,
                    format!("repository-v6 workspace head is invalid: {error:#}"),
                )
            })?
            .ok_or_else(|| ref_error(original, "repository-v6 workspace head is unborn"))?
    } else if let Some(branch_name) = core.strip_prefix("branch:") {
        resolve_named_authority_ref(&authority, original, branch_name)?
    } else if let Some(git_oid) = core.strip_prefix("git:") {
        resolve_imported_git_ref(&authority, original, git_oid)?
    } else if matches!(core.len(), 40 | 64) && core.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        resolve_imported_git_ref(&authority, original, core)?
    } else if is_abbreviated_git_hex(core) {
        return Err(ref_error(
            original,
            format!(
                "Git commit prefix '{core}' cannot be resolved from exact alias authority; use a full object ID"
            ),
        ));
    } else {
        resolve_named_authority_ref(&authority, original, core)?
    };

    if graph
        .get_change(&resolved)
        .map_err(|error| anyhow!(error.to_string()))?
        .is_none()
    {
        return Err(ref_error(
            original,
            format!(
                "repository-v6 authority resolves to semantic change {resolved}, but the active graph projection does not contain it"
            ),
        ));
    }
    Ok(resolved)
}

fn resolve_named_authority_ref(
    authority: &ActiveRepositoryAuthority,
    original: &str,
    value: &str,
) -> Result<SemanticChangeId> {
    let name = parse_ref_name(value)
        .map_err(|error| ref_error(original, format!("invalid repository ref: {error:#}")))?;
    authority
        .resolve_named_ref(&name)
        .map_err(|error| ref_error(original, error.to_string()))
}

fn resolve_imported_git_ref(
    authority: &ActiveRepositoryAuthority,
    original: &str,
    value: &str,
) -> Result<SemanticChangeId> {
    let oid = parse_git_object_id(value)
        .map_err(|error| ref_error(original, format!("invalid Git object ID: {error:#}")))?;
    authority
        .resolve_git_oid(&oid)
        .map_err(|error| ref_error(original, error.to_string()))
}

fn resolve_semantic_change<G>(graph: &G, original: &str, value: &str) -> Result<SemanticChangeId>
where
    G: GraphStore,
    <G as GraphStore>::Error: std::fmt::Display + Send + Sync + 'static,
{
    let change_id =
        parse_change_id(value).map_err(|error| ref_error(original, error.to_string()))?;
    if graph
        .get_change(&change_id)
        .map_err(|error| anyhow!(error.to_string()))?
        .is_some()
    {
        Ok(change_id)
    } else {
        Err(ref_error(
            original,
            format!("change {change_id} not found in graph authority"),
        ))
    }
}

fn is_abbreviated_git_hex(value: &str) -> bool {
    (4..40).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn choose_entity_match(mut entities: Vec<Entity>, entity_query: &str) -> Result<Entity> {
    if entities.is_empty() {
        bail!("No entity matching '{entity_query}' found.");
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
            bail!("Multiple entities match '{entity_query}': {preview}. Use a more exact name.")
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
    use std::sync::Arc;

    use kin_db::LocalFileBackend;
    use kin_model::{AuthorId, ChangeOrigin, ChangeStore, SemanticChange, Timestamp};

    /// Build a change whose declared identity matches its immutable payload.
    ///
    /// Repository authority rejects a change whose id does not recompute from
    /// its own content, so the identity is derived rather than invented.
    fn change(parents: Vec<SemanticChangeId>) -> SemanticChange {
        let mut change = change_with_id(change_id(0), parents);
        change.id = kin_core::compute_semantic_change_id(&change).unwrap();
        change
    }

    fn change_with_id(id: SemanticChangeId, parents: Vec<SemanticChangeId>) -> SemanticChange {
        SemanticChange {
            id,
            origin: ChangeOrigin::Native,
            parents,
            timestamp: Timestamp::now(),
            author: AuthorId::new("test"),
            message: "test change".to_string(),
            entity_deltas: Vec::new(),
            relation_deltas: Vec::new(),
            tree_deltas: Vec::new(),
            admission_policy_delta: None,
            projected_files: Vec::new(),
            spec_link: None,
            evidence: Vec::new(),
            risk_summary: None,
        }
    }

    fn change_id(byte: u8) -> SemanticChangeId {
        SemanticChangeId::from_hash(Hash256::from_bytes([byte; 32]))
    }

    fn absent_binding(layout: &kin_core::KinLayout) -> kin_core::LocalRepositoryAuthorityBinding {
        kin_core::LocalRepositoryAuthorityBinding::from_parts(
            kin_model::RepositoryId::new("absent-ref-lookup").unwrap(),
            kin_model::WorkspaceId::new(),
            Arc::new(LocalFileBackend::new(layout.kindb_dir())),
        )
    }

    #[test]
    fn explicit_semantic_change_and_parent_hops_need_no_file_or_git_fallback() {
        let graph = kin_db::InMemoryGraph::new();
        let parent_change = change(Vec::new());
        let head_change = change(vec![parent_change.id]);
        let parent = parent_change.id;
        let head = head_change.id;
        graph.create_change(&parent_change).unwrap();
        graph.create_change(&head_change).unwrap();
        let layout = kin_core::KinLayout::new(std::path::PathBuf::from("/absent/.kin"));
        let binding = absent_binding(&layout);

        assert_eq!(
            resolve_ref(&graph, &binding, Some(&format!("kin:{head}^"))).unwrap(),
            parent
        );
    }

    #[test]
    fn head_without_repository_authority_is_a_classified_failure() {
        let graph = kin_db::InMemoryGraph::new();
        let layout = kin_core::KinLayout::new(std::path::PathBuf::from("/absent/.kin"));
        let binding = absent_binding(&layout);
        let error = resolve_ref(&graph, &binding, None).unwrap_err();
        assert!(is_ref_resolution_error(&error));
        assert!(error.to_string().contains("repository-v6 authority"));
    }

    #[test]
    fn full_git_oid_is_not_converted_into_a_synthetic_change_id() {
        let graph = kin_db::InMemoryGraph::new();
        let layout = kin_core::KinLayout::new(std::path::PathBuf::from("/absent/.kin"));
        let binding = absent_binding(&layout);
        let error = resolve_ref(
            &graph,
            &binding,
            Some("1111111111111111111111111111111111111111"),
        )
        .unwrap_err();
        assert!(is_ref_resolution_error(&error));
        // The object ID must reach exact alias authority and be refused there.
        // Silently widening it into a semantic change id would invent history.
        assert!(
            error
                .to_string()
                .contains("has no imported repository-v6 alias"),
            "{error:#}"
        );
    }
}
