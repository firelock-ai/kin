// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! What the graph still has to say about an entity whose incoming relations
//! came back empty.
//!
//! `kin refs` and `kin impact` both resolve a name to one entity and then read
//! that entity's incoming relations. When the entity owns none, a bare empty
//! answer reads as "nothing depends on this", and for a type declaration that is
//! false in a way a reader cannot detect. A Rust `struct`'s only graph edge is an
//! outgoing `Contains` to its same-file members, so `kin refs Error` on `anyhow`
//! reported no callers while the graph held callers for `Error::msg`,
//! `Error::from`, and the rest, and the answer gave the reader no way to know.
//!
//! Two facts close that gap, and both are read out of graph truth: the entities
//! the graph holds under the declaration's name, and the other graph identities
//! carrying the same name that resolution did not choose. Nothing here consults
//! the filesystem.
//!
//! Members are gathered by name qualification, not by edge, and the wording of
//! every line built from them says so. The `Contains` edge a declaration owns
//! reaches only its same-file members: the linker keys containment against a
//! declaration in the same file, and a cross-file `impl` block has none, so
//! `Error::chain` in `src/error.rs` is tied to `Error` in `src/lib.rs` by name
//! alone. Collecting from edges would therefore drop exactly the members this
//! exists to surface. The cost of the name is that two same-named declarations
//! cannot be told apart, so a listing here is a claim about which entities share
//! a name prefix and never a claim about which declaration owns them.

use anyhow::Result;
use kin_model::{Entity, EntityFilter, GraphStore, RelationKind};

/// An entity whose name is qualified by the declaration's name, paired with how
/// many distinct entities reference it. The count is the one `kin refs` reports
/// for that member, so the note and the command it suggests cannot disagree.
#[derive(Debug, Clone)]
pub struct MemberSummary {
    pub name: String,
    pub kind: String,
    pub location: String,
    pub referencing_entities: usize,
}

/// Another entity in the graph carrying the queried name.
#[derive(Debug, Clone)]
pub struct SiblingSummary {
    pub name: String,
    pub kind: String,
    pub location: String,
}

#[derive(Debug, Clone, Default)]
pub struct DeclarationNeighbors {
    /// Every `Name::member` the graph holds, most-referenced first.
    pub members: Vec<MemberSummary>,
    /// Same-name identities other than the one resolution chose.
    pub siblings: Vec<SiblingSummary>,
}

impl DeclarationNeighbors {
    /// Members that actually carry references. A member nothing points at adds
    /// nothing to an answer explaining where the references went.
    pub fn referenced_members(&self) -> impl Iterator<Item = &MemberSummary> {
        self.members
            .iter()
            .filter(|member| member.referencing_entities > 0)
    }

    /// Members the graph places in `file`. A location is `path` or `path:line`,
    /// so both spellings have to match.
    pub fn members_in_file<'a>(
        &'a self,
        file: &str,
    ) -> impl Iterator<Item = &'a MemberSummary> + 'a {
        let exact = file.to_string();
        let prefix = format!("{file}:");
        self.members
            .iter()
            .filter(move |member| member.location == exact || member.location.starts_with(&prefix))
    }
}

/// `path:line` for an entity, or just the path when the graph carries no span.
///
/// Location is projection metadata for the human reading the listing; the
/// analysis itself is keyed on graph identity, never on paths.
///
/// The line is 1-based, through the same seam every other presentation surface
/// converts at. A `path:line` string is read straight into an editor, so the
/// raw graph row this used to emit put the reader one line above the entity.
pub fn entity_location(entity: &Entity) -> Option<String> {
    let path = entity.file_origin.as_ref().map(|f| f.0.clone())?;
    Some(
        match kin_mcp::handlers::common::entity_presentation_start_line(entity) {
            Some(line) => format!("{path}:{line}"),
            None => path,
        },
    )
}

fn entity_kind_label(entity: &Entity) -> String {
    format!("{:?}", entity.kind)
}

/// Read an entity's members and same-name siblings out of the graph.
///
/// `relation_kinds` is the kind set the caller's own answer was computed over,
/// so a member's count means the same thing the caller's empty result did.
pub fn collect(
    graph: &impl GraphStore,
    target: &Entity,
    relation_kinds: &[RelationKind],
) -> Result<DeclarationNeighbors> {
    Ok(DeclarationNeighbors {
        members: collect_members(graph, target, relation_kinds)?,
        siblings: collect_siblings(graph, target)?,
    })
}

fn collect_members(
    graph: &impl GraphStore,
    target: &Entity,
    relation_kinds: &[RelationKind],
) -> Result<Vec<MemberSummary>> {
    // The graph's name query is a case-insensitive substring match, so it also
    // returns `OtherError::foo` for a `Error::` pattern. Requiring an exact
    // prefix drops those. What survives is every entity the name `Error::`
    // qualifies, which is not the same set as the members this declaration owns
    // when another declaration shares its name.
    let prefix = format!("{}::", target.name);
    let candidates = graph.query_entities(&EntityFilter {
        name_pattern: Some(prefix.clone()),
        ..Default::default()
    })?;

    let mut members = Vec::new();
    for entity in candidates {
        if entity.id == target.id || !entity.name.starts_with(&prefix) {
            continue;
        }
        if kin_index::is_external_reference_target(&entity) {
            continue;
        }
        members.push(MemberSummary {
            referencing_entities: crate::commands::refs::distinct_referencing_entities(
                graph,
                &entity.id,
                relation_kinds,
            )?,
            kind: entity_kind_label(&entity),
            location: entity_location(&entity).unwrap_or_else(|| "unknown".to_string()),
            name: entity.name,
        });
    }
    members.sort_by(|left, right| {
        right
            .referencing_entities
            .cmp(&left.referencing_entities)
            .then_with(|| left.name.cmp(&right.name))
            .then_with(|| left.location.cmp(&right.location))
    });
    Ok(members)
}

fn collect_siblings(graph: &impl GraphStore, target: &Entity) -> Result<Vec<SiblingSummary>> {
    let candidates = graph.query_entities(&EntityFilter {
        name_pattern: Some(target.name.clone()),
        ..Default::default()
    })?;

    let mut siblings: Vec<SiblingSummary> = candidates
        .into_iter()
        .filter(|entity| {
            entity.id != target.id
                && entity.name == target.name
                && !kin_index::is_external_reference_target(entity)
        })
        .map(|entity| SiblingSummary {
            kind: entity_kind_label(&entity),
            location: entity_location(&entity).unwrap_or_else(|| "unknown".to_string()),
            name: entity.name,
        })
        .collect();
    siblings.sort_by(|left, right| left.location.cmp(&right.location));
    Ok(siblings)
}

/// How many members a note lists before summarizing the rest.
pub const MAX_LISTED: usize = 5;

/// Render `count` of `total` listed, or nothing when they are the same.
pub fn and_more_suffix(listed: usize, total: usize) -> Option<String> {
    (total > listed).then(|| format!("... and {} more", total - listed))
}
