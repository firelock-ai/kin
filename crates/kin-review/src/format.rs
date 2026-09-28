// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Human-readable review text.
//!
//! A review leads with what a reviewer decides on: the overall risk, how much
//! changed, how far the change reaches, and the findings. The detail follows.
//!
//! Relation changes are counted by origin and kind rather than printed one per
//! line. The first commit after an import can absorb thousands of edges from
//! language-server enrichment, and a line per edge buried the summary under
//! them. Where relation changes are listed, both ends are named; a node id is
//! never printed as though it were a name.

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write;

use kin_model::entity::Entity;
use kin_model::graph::EntityStore;
use kin_model::ids::EntityId;
use kin_model::provenance::ActorKind;
use kin_model::relation::{GraphNodeId, Relation, RelationOrigin};
use kin_model::review::{RiskLevel, RiskSummary};

use crate::diff::{EntityChangeKind, RelationChange, RelationChangeKind, SemanticDiff};
use crate::impact::ImpactReport;
use crate::inline::{group_by_file, InlineComment};
use crate::review::Review;

/// How many relation changes of one origin a review names without being asked.
/// A larger group is counted by kind, and the caller's hint says how to list it.
pub const RELATION_CHANGES_LISTED_BY_DEFAULT: usize = 10;

/// The prefix [`crate::risk::assess_risk`] gives the note it writes for each
/// removed relation. The summary counts those notes rather than repeating them,
/// because the relation section already accounts for every removal.
const RELATION_REMOVED_NOTE_PREFIX: &str = "Relation removed: ";

/// Names a relation endpoint, or answers `None` when it cannot.
pub type NodeNamer<'a> = dyn Fn(&GraphNodeId) -> Option<String> + 'a;

/// How many pending entities the summary names before counting the rest, the
/// same number `kin impact` names, so the two surfaces read alike.
pub const PENDING_ENTITIES_NAMED: usize = 3;

/// One entity whose enrichment is still pending, named for a reader.
#[derive(Clone, Copy, Debug)]
pub struct PendingEntity<'a> {
    /// The entity's name.
    pub name: &'a str,
    /// The entity's projection path. A review never prints a file line for it.
    pub path: &'a str,
}

/// A review answer bounded by enrichment that is still owed.
///
/// This is the renderer's view of the impact report's enrichment block, whose
/// fields are `scope`, `selected_change`, `status` (bounded, or no recorded
/// call-site debt), `limitation`, `pending_entities` (each with `entity_id`,
/// `name`, `projection.path` and `states`), `total_pending_entities` and
/// `entities_withheld`. A caller fills this view only when the status is
/// bounded: `code` from the status, `limitation` as given, `entities` from each
/// pending entity's name and projection path, and `total_pending_entities`
/// as given, which also counts the withheld ones. A block that records no
/// call-site debt, or no block at all, leaves it `None` and the summary prints
/// nothing about it. The block carries no line numbers and neither does this.
#[derive(Clone, Copy, Debug)]
pub struct PendingEnrichment<'a> {
    /// The verdict code that bounds the answer, such as `call_sites_owed`.
    pub code: &'a str,
    /// How many entities are pending in all, named or not.
    pub total_pending_entities: usize,
    /// What the pending work limits, in plain text, when the block says.
    pub limitation: Option<&'a str>,
    /// The pending entities the block names. The summary shows the first
    /// [`PENDING_ENTITIES_NAMED`] and counts the rest.
    pub entities: &'a [PendingEntity<'a>],
}

/// How a caller wants a review rendered.
#[derive(Clone, Copy, Default)]
pub struct ReviewRenderOptions<'a> {
    /// Names the relation endpoints the diff does not carry itself, usually by
    /// reading the graph through [`graph_node_name`]. Without it, only the
    /// entities the diff carries are named.
    pub node_names: Option<&'a NodeNamer<'a>>,
    /// List every relation change by name, however many there are.
    pub list_all_relations: bool,
    /// The line that tells a reader how to list the relation changes this
    /// rendering only counted, such as the flag that does it.
    pub relation_list_hint: Option<&'a str>,
    /// The enrichment the answer still owes, when the review's enrichment
    /// block reports it as bounded. `None` uses the observation already held
    /// by `review.impact`, so all callers render the selected graph's limits.
    pub pending_enrichment: Option<PendingEnrichment<'a>>,
}

/// A relation endpoint's name read from a graph store, for
/// [`ReviewRenderOptions::node_names`].
///
/// An entity reads as `name [file]` and a symbol outside the repository as
/// `symbol [source]`. Any other node, or one the store does not hold, answers
/// `None`.
pub fn graph_node_name<S: EntityStore + ?Sized>(store: &S, node: &GraphNodeId) -> Option<String> {
    match node {
        GraphNodeId::Entity(id) => store
            .get_entity(id)
            .ok()
            .flatten()
            .map(|entity| entity_label(&entity)),
        GraphNodeId::ExternalReference(id) => store
            .lookup_external_reference(id)
            .ok()
            .flatten()
            .map(|reference| format!("{} [{}]", reference.symbol, reference.canonical_source)),
        _ => None,
    }
}

/// Format a full review for display, naming only what the review carries.
pub fn format_review(review: &Review) -> String {
    format_review_with(review, &ReviewRenderOptions::default())
}

/// Format a full review for display.
///
/// The summary comes first. Entity changes, relation changes, inline comments
/// and the impact analysis follow it as detail.
pub fn format_review_with(review: &Review, options: &ReviewRenderOptions<'_>) -> String {
    let labels = diff_entity_labels(&review.diff);
    let mut out = String::new();

    writeln!(out, "=== Semantic Review ===").unwrap();
    if let Some(base) = &review.base {
        writeln!(out, "Base: {}", base).unwrap();
    }
    if let Some(head) = &review.head {
        writeln!(out, "Head: {}", head).unwrap();
    }
    writeln!(out).unwrap();

    out.push_str(&render_summary(review, options.pending_enrichment));
    out.push_str(&render_diff(&review.diff, &labels, options));
    if !review.inline_comments.is_empty() {
        out.push_str(&format_inline_comments(&review.inline_comments));
    }
    out.push_str(&render_impact(&review.impact, &|id: &EntityId| {
        node_label(&GraphNodeId::Entity(*id), &labels, options)
    }));

    out
}

/// The summary a review leads with: the overall risk, how much changed, how
/// far it reaches, and the findings a reviewer decides on.
pub fn format_summary(review: &Review) -> String {
    render_summary(review, None)
}

fn render_summary(review: &Review, pending: Option<PendingEnrichment<'_>>) -> String {
    // Render the observation that produced this impact report. Re-reading the
    // caller's live graph here would mix HEAD debt with a historical review.
    let observation = review
        .impact
        .enrichment
        .as_ref()
        .filter(|observation| observation.bounds_answer());
    let entities: Vec<_> = observation
        .into_iter()
        .flat_map(|observation| observation.pending_entities.iter())
        .take(PENDING_ENTITIES_NAMED)
        .map(|entity| PendingEntity {
            name: &entity.name,
            path: entity.projection.path.as_deref().unwrap_or("unavailable"),
        })
        .collect();
    let recorded_pending = observation.map(|observation| PendingEnrichment {
        code: &observation.status,
        total_pending_entities: observation.total_pending_entities,
        limitation: observation.limitation.as_deref(),
        entities: &entities,
    });
    let mut out = String::new();
    writeln!(out, "--- Summary ---").unwrap();
    writeln!(
        out,
        "Overall risk: {}",
        risk_level_label(review.risk.overall_risk)
    )
    .unwrap();
    writeln!(out, "Entities: {}", entity_counts(&review.diff)).unwrap();
    writeln!(out, "Relations: {}", relation_counts(&review.diff)).unwrap();
    match review.impact.total_affected() {
        0 => writeln!(out, "Downstream: no affected entities found").unwrap(),
        affected => writeln!(
            out,
            "Downstream: {affected} affected {}, direct and transitive, listed under Impact \
             Analysis",
            plural(affected, "entity", "entities")
        )
        .unwrap(),
    }
    if let Some(pending) = pending {
        write_pending_enrichment(&mut out, &pending, &not_settled_line(&pending));
    } else if let Some(pending) = recorded_pending {
        let include_sweep_hint = observation.is_some_and(|observation| {
            matches!(
                observation.scope.as_str(),
                "selected_graph_repository" | "selected_graph_impact"
            ) && observation.selected_change.is_none()
        });
        write_pending_enrichment(
            &mut out,
            &pending,
            &not_settled_line_with_hint(&pending, include_sweep_hint),
        );
    }
    write_risk_findings(&mut out, &review.risk, true);
    writeln!(out).unwrap();
    out
}

/// The `not settled:` line a bounded answer prints, the convention `kin refs`
/// follows, then up to [`PENDING_ENTITIES_NAMED`] pending entities by name and
/// path, and a count of the rest.
fn write_pending_enrichment(out: &mut String, pending: &PendingEnrichment<'_>, line: &str) {
    writeln!(out, "{line}").unwrap();
    let named = pending.entities.len().min(PENDING_ENTITIES_NAMED);
    for entity in &pending.entities[..named] {
        writeln!(out, "  {} (path: {})", entity.name, entity.path).unwrap();
    }
    let more = pending.total_pending_entities.saturating_sub(named);
    if more > 0 {
        writeln!(out, "  and {more} more").unwrap();
    }
}

/// The one line that says a review's answer is not settled: the verdict code,
/// how many entities are pending, what that limits, and the command that
/// settles them.
pub fn not_settled_line(pending: &PendingEnrichment<'_>) -> String {
    let mut line = not_settled_line_with_hint(pending, false);
    line.push_str(" Run `kin daemon sweep` to settle ");
    line.push_str(plural(pending.total_pending_entities, "it.", "them."));
    line
}

fn not_settled_line_with_hint(pending: &PendingEnrichment<'_>, include_sweep_hint: bool) -> String {
    let count = pending.total_pending_entities;
    let mut line = format!(
        "not settled: {}: {count} {} still pending enrichment.",
        pending.code,
        plural(count, "entity", "entities"),
    );
    if let Some(limitation) = pending
        .limitation
        .map(str::trim)
        .filter(|text| !text.is_empty())
    {
        line.push(' ');
        line.push_str(limitation);
        if !limitation.ends_with(['.', '!', '?']) {
            line.push('.');
        }
    }
    // A sweep retries the current graph's analysis; it cannot settle every
    // unsupported site or alter evidence recorded by an older selected revision.
    if include_sweep_hint {
        line.push_str(" Run `kin daemon sweep` to retry analysis.");
    }
    line
}

fn risk_level_label(level: RiskLevel) -> &'static str {
    match level {
        RiskLevel::Low => "LOW",
        RiskLevel::Medium => "MEDIUM",
        RiskLevel::High => "HIGH",
        RiskLevel::Critical => "CRITICAL",
    }
}

fn plural<'a>(count: usize, one: &'a str, many: &'a str) -> &'a str {
    if count == 1 {
        one
    } else {
        many
    }
}

/// `3 added, 1 removed`, leaving out every zero.
fn counted_parts(parts: &[(usize, &str)]) -> String {
    parts
        .iter()
        .filter(|(count, _)| *count > 0)
        .map(|(count, what)| format!("{count} {what}"))
        .collect::<Vec<_>>()
        .join(", ")
}

fn entity_counts(diff: &SemanticDiff) -> String {
    let (mut added, mut modified, mut removed) = (0, 0, 0);
    for change in &diff.entity_changes {
        match change.kind {
            EntityChangeKind::Added(_) => added += 1,
            EntityChangeKind::Modified { .. } => modified += 1,
            EntityChangeKind::Removed { .. } => removed += 1,
        }
    }
    let parts = counted_parts(&[
        (added, "added"),
        (modified, "modified"),
        (removed, "removed"),
    ]);
    if parts.is_empty() {
        "none changed".to_string()
    } else {
        parts
    }
}

fn relation_counts(diff: &SemanticDiff) -> String {
    let total = diff.relation_changes.len();
    if total == 0 {
        return "none changed".to_string();
    }
    let enrichment = diff
        .relation_changes
        .iter()
        .filter(|change| changed_relation(change).origin == RelationOrigin::Lsp)
        .count();
    match enrichment {
        0 => format!("{total} changed"),
        all if all == total => {
            format!("{total} changed, all of them from language-server enrichment")
        }
        some => format!("{total} changed, {some} of them from language-server enrichment"),
    }
}

/// The findings of a risk summary, one list per class, each under its heading.
///
/// `count_relation_removals` folds the note written for each removed relation
/// into one line that counts them.
fn write_risk_findings(out: &mut String, risk: &RiskSummary, count_relation_removals: bool) {
    write_list(out, "Breaking changes", "!", &risk.breaking_changes);
    write_list(out, "Test coverage gaps", "?", &risk.test_coverage_gaps);
    write_list(out, "Contract violations", "!!", &risk.contract_violations);
    write_list(out, "Work item risks", "@", &risk.work_risks);

    if !count_relation_removals {
        write_list(out, "Notes", "-", &risk.notes);
        return;
    }
    let (removals, mut notes): (Vec<String>, Vec<String>) = risk
        .notes
        .iter()
        .cloned()
        .partition(|note| note.starts_with(RELATION_REMOVED_NOTE_PREFIX));
    if !removals.is_empty() {
        notes.push(format!(
            "{} {} removed, counted under Relation Changes",
            removals.len(),
            plural(removals.len(), "relation", "relations"),
        ));
    }
    write_list(out, "Notes", "-", &notes);
}

fn write_list(out: &mut String, heading: &str, marker: &str, items: &[String]) {
    if items.is_empty() {
        return;
    }
    writeln!(out, "\n{heading}:").unwrap();
    for item in items {
        writeln!(out, "  {marker} {item}").unwrap();
    }
}

/// Convert a graph-owned 0-based line index to the 1-based line number every
/// editor, `file:line` reference, and diff hunk uses.
///
/// A review renders locations a reader clicks or greps, so emitting the raw
/// graph row sends them one line above the declaration. The agent-facing
/// surfaces convert at one seam per surface for this reason; this is that seam
/// for the review renderers.
pub(crate) fn presentation_line(graph_line: u32) -> u32 {
    graph_line.saturating_add(1)
}

/// `file:line` for an entity, or just the file when no span was captured.
fn entity_location(entity: &kin_model::entity::Entity) -> Option<String> {
    if let Some(span) = entity.span.as_ref() {
        return Some(format!(
            "{}:{}",
            span.file,
            presentation_line(span.start_line)
        ));
    }
    entity.file_origin.as_ref().map(|origin| origin.to_string())
}

/// `name [file]` for a relation endpoint, or the bare name when the entity
/// records no file.
fn entity_label(entity: &Entity) -> String {
    let file = entity
        .span
        .as_ref()
        .map(|span| span.file.to_string())
        .or_else(|| entity.file_origin.as_ref().map(ToString::to_string));
    match file {
        Some(file) => format!("{} [{}]", entity.name, file),
        None => entity.name.clone(),
    }
}

/// Labels for the entities the diff carries, on both sides of a modification
/// and for the base-side record of a removal, which the live graph no longer
/// holds.
fn diff_entity_labels(diff: &SemanticDiff) -> HashMap<EntityId, String> {
    let mut labels = HashMap::new();
    for change in &diff.entity_changes {
        match &change.kind {
            EntityChangeKind::Added(entity) => {
                labels.insert(change.entity_id, entity_label(entity));
            }
            EntityChangeKind::Modified { old, new } => {
                labels.insert(change.entity_id, entity_label(new));
                labels.entry(old.id).or_insert_with(|| entity_label(old));
            }
            EntityChangeKind::Removed { old: Some(entity) } => {
                labels.insert(change.entity_id, entity_label(entity));
            }
            EntityChangeKind::Removed { old: None } => {}
        }
    }
    labels
}

/// A relation endpoint by name: the diff's own record first, then the caller's
/// namer, and for a node neither can name, its kind and a short id marked as
/// unnamed.
fn node_label(
    node: &GraphNodeId,
    labels: &HashMap<EntityId, String>,
    options: &ReviewRenderOptions<'_>,
) -> String {
    if let Some(label) = node.as_entity().and_then(|id| labels.get(&id)) {
        return label.clone();
    }
    if let Some(label) = options.node_names.and_then(|name| name(node)) {
        return label;
    }
    unnamed_node(node)
}

/// A node no record names: `unnamed <kind> <first 8 characters of its id>`,
/// enough to tell two unnamed nodes apart without passing an id off as a name.
fn unnamed_node(node: &GraphNodeId) -> String {
    let text = node.to_string();
    let (kind, id) = text.split_once(':').unwrap_or(("node", text.as_str()));
    let short: String = id.chars().take(8).collect();
    format!("unnamed {kind} {short}")
}

/// Format entity-level diff, naming only what the diff carries.
pub fn format_diff(diff: &SemanticDiff) -> String {
    format_diff_with(diff, &ReviewRenderOptions::default())
}

/// Format entity-level diff.
pub fn format_diff_with(diff: &SemanticDiff, options: &ReviewRenderOptions<'_>) -> String {
    render_diff(diff, &diff_entity_labels(diff), options)
}

fn render_diff(
    diff: &SemanticDiff,
    labels: &HashMap<EntityId, String>,
    options: &ReviewRenderOptions<'_>,
) -> String {
    let mut out = String::new();

    // The provenance note comes before the empty check on purpose. A change
    // that re-emitted a whole file and edited nothing in it is exactly the case
    // where a bare "No entity changes." would look like the review had read
    // nothing, so the line that explains the discrepancy has to survive it.
    let provenance_note = if diff.provenance_only_entity_changes > 0 {
        Some(format!(
            "{} entity record(s) in the touched file(s) advanced only their span or source-blob \
             provenance and are not listed as modified.",
            diff.provenance_only_entity_changes,
        ))
    } else {
        None
    };

    if diff.is_empty() {
        writeln!(out, "No entity changes.").unwrap();
        if let Some(note) = provenance_note {
            writeln!(out, "{note}").unwrap();
        }
        return out;
    }

    writeln!(out, "--- Entity Changes ---").unwrap();

    let added = diff.added_entities();
    let modified = diff.modified_entities();
    let removed = diff.removed_entities();

    if !added.is_empty() {
        writeln!(out, "\nAdded ({}):", added.len()).unwrap();
        for entity in &added {
            writeln!(
                out,
                "  + {} ({:?}): {}",
                entity.name, entity.kind, entity.signature,
            )
            .unwrap();
            if let Some(file) = &entity.file_origin {
                writeln!(out, "    file: {}", file).unwrap();
            }
        }
    }

    if let Some(note) = provenance_note {
        writeln!(out, "\n{note}").unwrap();
    }

    if !modified.is_empty() {
        writeln!(out, "\nModified ({}):", modified.len()).unwrap();
        for (old, new) in &modified {
            writeln!(out, "  ~ {} ({:?})", new.name, new.kind).unwrap();
            if old.signature != new.signature {
                writeln!(out, "    signature: {} -> {}", old.signature, new.signature).unwrap();
            }
            if old.name != new.name {
                writeln!(out, "    renamed: {} -> {}", old.name, new.name).unwrap();
            }
            if old.visibility != new.visibility {
                writeln!(
                    out,
                    "    visibility: {:?} -> {:?}",
                    old.visibility, new.visibility,
                )
                .unwrap();
            }
        }
    }

    if !removed.is_empty() {
        writeln!(out, "\nRemoved ({}):", removed.len()).unwrap();
        for (id, entity) in &removed {
            match entity {
                Some(entity) => {
                    writeln!(
                        out,
                        "  - {} ({:?}): {}",
                        entity.name, entity.kind, entity.signature,
                    )
                    .unwrap();
                    if let Some(location) = entity_location(entity) {
                        writeln!(out, "    file: {}", location).unwrap();
                    }
                }
                // An unresolved removal is reported as one. Printing the id
                // alone would read as a name and hide that the base-side record
                // was unrecoverable.
                None => {
                    writeln!(out, "  - <unresolved removal> id {}", id).unwrap();
                    writeln!(
                        out,
                        "    no base-side record for this entity; its name, kind and location are unknown"
                    )
                    .unwrap();
                }
            }
        }
    }

    write_relation_changes(&mut out, diff, labels, options);

    writeln!(out).unwrap();
    out
}

/// The relation a change leaves in effect: the new side of an addition or a
/// modification, and the base side of a removal.
fn changed_relation(change: &RelationChange) -> &Relation {
    match &change.kind {
        RelationChangeKind::Added(relation) => relation,
        RelationChangeKind::Modified { new, .. } => new,
        RelationChangeKind::Removed { old } => old,
    }
}

/// The order origins are reported in: what the change's own source produced
/// first, language-server enrichment last.
fn origin_rank(origin: RelationOrigin) -> u8 {
    match origin {
        RelationOrigin::Parsed => 0,
        RelationOrigin::Inferred => 1,
        RelationOrigin::Manual => 2,
        RelationOrigin::Lsp => 3,
    }
}

fn origin_heading(origin: RelationOrigin) -> &'static str {
    match origin {
        RelationOrigin::Parsed => "Parsed from source",
        RelationOrigin::Inferred => "Inferred by the resolver",
        RelationOrigin::Manual => "Recorded by hand",
        RelationOrigin::Lsp => "From language-server enrichment",
    }
}

fn origin_word(origin: RelationOrigin) -> &'static str {
    match origin {
        RelationOrigin::Parsed => "parsed",
        RelationOrigin::Inferred => "inferred",
        RelationOrigin::Manual => "manual",
        RelationOrigin::Lsp => "language server",
    }
}

/// Relation changes grouped by where they came from, then counted by kind.
///
/// Edges from language-server enrichment are their own group, apart from what
/// parsing the change produced, because the first commit after an import can
/// carry thousands of them that nobody wrote. A group is listed by name when it
/// is small or when the caller asks for every change; otherwise it is counted
/// and the caller's hint says how to list it.
fn write_relation_changes(
    out: &mut String,
    diff: &SemanticDiff,
    labels: &HashMap<EntityId, String>,
    options: &ReviewRenderOptions<'_>,
) {
    if diff.relation_changes.is_empty() {
        return;
    }
    writeln!(out, "\n--- Relation Changes ---").unwrap();

    type ByKind<'r> = BTreeMap<String, Vec<&'r RelationChange>>;
    let mut groups: BTreeMap<u8, (RelationOrigin, ByKind<'_>)> = BTreeMap::new();
    for change in &diff.relation_changes {
        let relation = changed_relation(change);
        groups
            .entry(origin_rank(relation.origin))
            .or_insert_with(|| (relation.origin, BTreeMap::new()))
            .1
            .entry(format!("{:?}", relation.kind))
            .or_default()
            .push(change);
    }

    let mut counted_only = false;
    for (origin, by_kind) in groups.values() {
        let total: usize = by_kind.values().map(Vec::len).sum();
        let listed = options.list_all_relations || total <= RELATION_CHANGES_LISTED_BY_DEFAULT;
        counted_only |= !listed;
        writeln!(out, "{} ({}):", origin_heading(*origin), total).unwrap();

        let mut rows: Vec<(&String, &Vec<&RelationChange>)> = by_kind.iter().collect();
        rows.sort_by(|a, b| b.1.len().cmp(&a.1.len()).then_with(|| a.0.cmp(b.0)));
        for (kind, changes) in rows {
            let (mut added, mut modified, mut removed) = (0, 0, 0);
            for change in changes {
                match change.kind {
                    RelationChangeKind::Added(_) => added += 1,
                    RelationChangeKind::Modified { .. } => modified += 1,
                    RelationChangeKind::Removed { .. } => removed += 1,
                }
            }
            writeln!(
                out,
                "  {kind}: {}",
                counted_parts(&[
                    (added, "added"),
                    (modified, "modified"),
                    (removed, "removed")
                ])
            )
            .unwrap();
            if listed {
                for change in changes {
                    writeln!(
                        out,
                        "    {}",
                        describe_relation_change(change, labels, options)
                    )
                    .unwrap();
                }
            }
        }
    }

    if counted_only {
        if let Some(hint) = options.relation_list_hint {
            writeln!(out, "{hint}").unwrap();
        }
    }
}

/// One relation change by name, under the kind row it is counted in.
fn describe_relation_change(
    change: &RelationChange,
    labels: &HashMap<EntityId, String>,
    options: &ReviewRenderOptions<'_>,
) -> String {
    let name = |node: &GraphNodeId| node_label(node, labels, options);
    match &change.kind {
        RelationChangeKind::Added(relation) => {
            format!("+ {} -> {}", name(&relation.src), name(&relation.dst))
        }
        RelationChangeKind::Removed { old } => {
            format!("- {} -> {}", name(&old.src), name(&old.dst))
        }
        RelationChangeKind::Modified { old, new } => {
            let mut line = format!("~ {} -> {}", name(&new.src), name(&new.dst));
            if old.kind != new.kind || old.src != new.src || old.dst != new.dst {
                write!(
                    line,
                    " (was {:?}: {} -> {})",
                    old.kind,
                    name(&old.src),
                    name(&old.dst)
                )
                .unwrap();
            } else if old.origin != new.origin {
                write!(line, " (origin was {})", origin_word(old.origin)).unwrap();
            }
            line
        }
    }
}

/// Format impact summary.
pub fn format_impact(impact: &ImpactReport) -> String {
    let labels = HashMap::new();
    let options = ReviewRenderOptions::default();
    render_impact(impact, &|id: &EntityId| {
        node_label(&GraphNodeId::Entity(*id), &labels, &options)
    })
}

fn render_impact(impact: &ImpactReport, entity_name: &dyn Fn(&EntityId) -> String) -> String {
    let mut out = String::new();

    if impact.is_empty() {
        writeln!(out, "No downstream impact detected.").unwrap();
        return out;
    }

    writeln!(out, "--- Impact Analysis ---").unwrap();
    let changed = impact.changed_ids.len();
    writeln!(
        out,
        "Total affected entities: {}, direct and transitive, across {} changed {}",
        impact.total_affected(),
        changed,
        plural(changed, "entity", "entities"),
    )
    .unwrap();

    write_direct_consumers(&mut out, impact, entity_name);

    if !impact.affected_callers.is_empty() {
        writeln!(
            out,
            "\nAffected callers ({}):",
            impact.affected_callers.len()
        )
        .unwrap();
        for entity in &impact.affected_callers {
            writeln!(out, "  {} ({:?})", entity.name, entity.kind).unwrap();
        }
    }

    if !impact.affected_dependents.is_empty() {
        writeln!(
            out,
            "\nAffected dependents ({}):",
            impact.affected_dependents.len(),
        )
        .unwrap();
        for entity in &impact.affected_dependents {
            writeln!(out, "  {} ({:?})", entity.name, entity.kind).unwrap();
        }
    }

    if !impact.affected_contract_consumers.is_empty() {
        writeln!(
            out,
            "\nAffected contract consumers ({}):",
            impact.affected_contract_consumers.len(),
        )
        .unwrap();
        for entity in &impact.affected_contract_consumers {
            writeln!(out, "  {} ({:?})", entity.name, entity.kind).unwrap();
        }
    }

    if !impact.affected_tests.is_empty() {
        writeln!(out, "\nAffected tests ({}):", impact.affected_tests.len(),).unwrap();
        for entity in &impact.affected_tests {
            writeln!(out, "  {} ({:?})", entity.name, entity.kind).unwrap();
        }
    }

    if !impact.affected_work_items.is_empty() {
        writeln!(
            out,
            "\nAffected work items ({}):",
            impact.affected_work_items.len(),
        )
        .unwrap();
        for item in &impact.affected_work_items {
            writeln!(out, "  [{}] {} ({})", item.kind, item.title, item.status).unwrap();
        }
    }

    if !impact.affected_annotations.is_empty() {
        writeln!(
            out,
            "\nAffected annotations ({}):",
            impact.affected_annotations.len(),
        )
        .unwrap();
        for ann in &impact.affected_annotations {
            // Cut on a character boundary: a byte slice panics inside a
            // multi-byte character.
            let preview = if ann.body.chars().count() > 60 {
                format!("{}...", ann.body.chars().take(60).collect::<String>())
            } else {
                ann.body.clone()
            };
            writeln!(out, "  [{}] {}: \"{}\"", ann.kind, ann.staleness, preview).unwrap();
        }
    }

    if !impact.unreviewed_agent_changes.is_empty() {
        writeln!(out, "\n--- Agent Changes Pending Review ---").unwrap();
        for entity_id in &impact.unreviewed_agent_changes {
            // Look up the actor kind from attribution if available.
            let actor_kind = impact
                .actor_attribution
                .iter()
                .find(|(eid, _)| eid == entity_id)
                .map(|(_, kind)| *kind)
                .unwrap_or(ActorKind::Assistant);
            writeln!(
                out,
                "  {} changed by {} (not yet approved)",
                entity_name(entity_id),
                actor_kind,
            )
            .unwrap();
        }
    }

    writeln!(out).unwrap();
    out
}

/// Each changed entity's direct consumers, by class.
///
/// A breaking-change finding counts one changed entity's direct external
/// consumers, while the impact total spans every changed entity and reaches
/// past direct consumers. This block names the entity each count belongs to,
/// so the finding's number can be found here and read against the total.
fn write_direct_consumers(
    out: &mut String,
    impact: &ImpactReport,
    entity_name: &dyn Fn(&EntityId) -> String,
) {
    let mut rows: Vec<(usize, String, String)> = impact
        .entity_impacts
        .iter()
        .filter_map(|row| {
            let external = row.external_consumers();
            let (tests, derived) = if row.classes_account_for_total() {
                (row.test_consumer_count, row.derived_consumer_count)
            } else {
                (0, 0)
            };
            let migrated = row.consumers_migrated_in_diff;
            let parts = counted_parts(&[
                (external, "external"),
                (tests, plural(tests, "test", "tests")),
                (derived, plural(derived, "derived copy", "derived copies")),
                (migrated, "updated in this change"),
            ]);
            (!parts.is_empty()).then(|| (external, entity_name(&row.entity_id), parts))
        })
        .collect();
    if rows.is_empty() {
        return;
    }
    rows.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    writeln!(
        out,
        "\nDirect consumers of each changed entity (external means outside this change, not a \
         test and not a derived copy):"
    )
    .unwrap();
    for (_, name, parts) in rows {
        writeln!(out, "  {name}: {parts}").unwrap();
    }
}

/// Format risk highlights from a review.
pub fn format_risk_highlights(review: &Review) -> String {
    let mut out = String::new();
    writeln!(out, "--- Risk Assessment ---").unwrap();
    writeln!(
        out,
        "Overall risk: {}",
        risk_level_label(review.risk.overall_risk)
    )
    .unwrap();
    write_risk_findings(&mut out, &review.risk, false);
    out
}

/// Format line-level inline comments grouped by file.
pub fn format_inline_comments(comments: &[InlineComment]) -> String {
    let mut out = String::new();

    writeln!(out, "--- Inline Comments ---").unwrap();

    let grouped = group_by_file(comments);
    for (file, file_comments) in &grouped {
        writeln!(out, "\n{}:", file).unwrap();
        for comment in file_comments {
            let prefix = comment.kind.prefix();
            if comment.start_line == comment.end_line {
                writeln!(
                    out,
                    "  L{}: {} {}",
                    comment.start_line, prefix, comment.message,
                )
                .unwrap();
            } else {
                writeln!(
                    out,
                    "  L{}-{}: {} {}",
                    comment.start_line, comment.end_line, prefix, comment.message,
                )
                .unwrap();
            }
        }
    }

    writeln!(out).unwrap();
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diff::{EntityChange, EntityChangeKind};
    use crate::inline::{InlineComment, InlineCommentKind};
    use kin_model::entity::{
        Entity, EntityKind, EntityMetadata, EntityRole, FingerprintAlgorithm, SemanticFingerprint,
        Visibility,
    };
    use kin_model::ids::*;
    use kin_model::review::RiskSummary;

    fn test_entity(name: &str) -> Entity {
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0; 32]),
                signature_hash: Hash256::from_bytes([0; 32]),
                behavior_hash: Hash256::from_bytes([0; 32]),
                equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
                stability_score: 1.0,
            },
            file_origin: None,
            span: None,
            signature: format!("fn {}()", name),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    #[test]
    fn format_empty_review() {
        let review = Review {
            base: None,
            head: None,
            diff: SemanticDiff::default(),
            impact: ImpactReport::default(),
            risk: RiskSummary {
                overall_risk: RiskLevel::Low,
                breaking_changes: vec![],
                test_coverage_gaps: vec![],
                contract_violations: vec![],
                work_risks: vec![],
                notes: vec![],
            },
            inline_comments: vec![],
        };

        let output = format_review(&review);
        assert!(output.contains("Semantic Review"));
        assert!(output.contains("LOW"));
        assert!(output.contains("No entity changes"));
    }

    #[test]
    fn format_review_with_changes() {
        let entity = test_entity("handle_request");

        let diff = SemanticDiff {
            entity_changes: vec![EntityChange {
                entity_id: entity.id,
                kind: EntityChangeKind::Added(entity.clone()),
            }],
            ..Default::default()
        };

        let review = Review {
            base: None,
            head: None,
            diff,
            impact: ImpactReport::default(),
            risk: RiskSummary {
                overall_risk: RiskLevel::Low,
                breaking_changes: vec![],
                test_coverage_gaps: vec![],
                contract_violations: vec![],
                work_risks: vec![],
                notes: vec![],
            },
            inline_comments: vec![],
        };

        let output = format_review(&review);
        assert!(output.contains("handle_request"));
        assert!(output.contains("Added (1)"));
    }

    #[test]
    fn format_risk_shows_critical() {
        let review = Review {
            base: None,
            head: None,
            diff: SemanticDiff::default(),
            impact: ImpactReport::default(),
            risk: RiskSummary {
                overall_risk: RiskLevel::Critical,
                breaking_changes: vec!["API changed".into()],
                test_coverage_gaps: vec![],
                contract_violations: vec!["Schema v2 incompatible".into()],
                work_risks: vec![],
                notes: vec![],
            },
            inline_comments: vec![],
        };

        let output = format_risk_highlights(&review);
        assert!(output.contains("CRITICAL"));
        assert!(output.contains("API changed"));
        assert!(output.contains("Schema v2 incompatible"));
    }

    #[test]
    fn format_inline_comments_groups_by_file() {
        let comments = vec![
            InlineComment {
                file: "src/api.rs".to_string(),
                start_line: 10,
                end_line: 25,
                kind: InlineCommentKind::Added,
                message: "New Function `handle_request`".to_string(),
            },
            InlineComment {
                file: "src/api.rs".to_string(),
                start_line: 10,
                end_line: 25,
                kind: InlineCommentKind::CoverageGap,
                message: "No test coverage".to_string(),
            },
            InlineComment {
                file: "src/core.rs".to_string(),
                start_line: 5,
                end_line: 5,
                kind: InlineCommentKind::SignatureChange,
                message: "Signature changed".to_string(),
            },
        ];

        let output = format_inline_comments(&comments);
        assert!(output.contains("--- Inline Comments ---"));
        assert!(output.contains("src/api.rs:"));
        assert!(output.contains("src/core.rs:"));
        assert!(output.contains("L10-25: +"));
        assert!(output.contains("L5: ~"));
    }

    #[test]
    fn format_review_includes_inline_comments() {
        let comments = vec![InlineComment {
            file: "src/lib.rs".to_string(),
            start_line: 1,
            end_line: 10,
            kind: InlineCommentKind::Breaking,
            message: "Breaking: signature change".to_string(),
        }];

        let review = Review {
            base: None,
            head: None,
            diff: SemanticDiff::default(),
            impact: ImpactReport::default(),
            risk: RiskSummary {
                overall_risk: RiskLevel::High,
                breaking_changes: vec!["sig change".into()],
                test_coverage_gaps: vec![],
                contract_violations: vec![],
                work_risks: vec![],
                notes: vec![],
            },
            inline_comments: comments,
        };

        let output = format_review(&review);
        assert!(output.contains("--- Inline Comments ---"));
        assert!(output.contains("L1-10: !! Breaking: signature change"));
    }

    #[test]
    fn format_review_omits_inline_section_when_empty() {
        let review = Review {
            base: None,
            head: None,
            diff: SemanticDiff::default(),
            impact: ImpactReport::default(),
            risk: RiskSummary {
                overall_risk: RiskLevel::Low,
                breaking_changes: vec![],
                test_coverage_gaps: vec![],
                contract_violations: vec![],
                work_risks: vec![],
                notes: vec![],
            },
            inline_comments: vec![],
        };

        let output = format_review(&review);
        assert!(!output.contains("Inline Comments"));
    }

    fn located_entity(name: &str, file: &str) -> Entity {
        let mut entity = test_entity(name);
        entity.span = Some(kin_model::entity::SourceSpan {
            file: FilePathId::new(file),
            start_byte: 0,
            end_byte: 10,
            start_line: 4,
            start_col: 0,
            end_line: 9,
            end_col: 0,
        });
        entity
    }

    fn relation(
        kind: kin_model::relation::RelationKind,
        origin: RelationOrigin,
        src: &Entity,
        dst: &Entity,
    ) -> Relation {
        Relation {
            id: RelationId::new(),
            kind,
            src: GraphNodeId::Entity(src.id),
            dst: GraphNodeId::Entity(dst.id),
            confidence: 1.0,
            origin,
            created_in: None,
            import_source: None,
            evidence: vec![],
        }
    }

    fn added(relation: Relation) -> RelationChange {
        RelationChange {
            kind: RelationChangeKind::Added(relation),
        }
    }

    fn quiet_risk(level: RiskLevel) -> RiskSummary {
        RiskSummary {
            overall_risk: level,
            breaking_changes: vec![],
            test_coverage_gaps: vec![],
            contract_violations: vec![],
            work_risks: vec![],
            notes: vec![],
        }
    }

    fn review_of(diff: SemanticDiff, impact: ImpactReport, risk: RiskSummary) -> Review {
        Review {
            base: None,
            head: None,
            diff,
            impact,
            risk,
            inline_comments: vec![],
        }
    }

    /// The shape of the review that buried its summary: a one-file rename
    /// committed right after an import, carrying thousands of edges that
    /// language-server enrichment added and a handful the parser produced.
    fn rename_after_import() -> (Review, Vec<Entity>) {
        use kin_model::relation::RelationKind;

        let old = located_entity("load_dotenv", "src/flask/cli.py");
        let mut new = old.clone();
        new.signature = "fn load_dotenv(use_defaults)".into();
        let caller = located_entity("Flask.run", "src/flask/app.py");
        let others: Vec<Entity> = (0..40)
            .map(|i| located_entity(&format!("helper_{i}"), "src/flask/helpers.py"))
            .collect();

        let mut relation_changes = vec![
            added(relation(
                RelationKind::Calls,
                RelationOrigin::Parsed,
                &caller,
                &new,
            )),
            RelationChange {
                kind: RelationChangeKind::Removed {
                    old: relation(
                        RelationKind::References,
                        RelationOrigin::Parsed,
                        &new,
                        &caller,
                    ),
                },
            },
        ];
        for (i, other) in others.iter().enumerate() {
            let kind = if i % 4 == 0 {
                RelationKind::Calls
            } else {
                RelationKind::UsesType
            };
            relation_changes.push(added(relation(kind, RelationOrigin::Lsp, other, &caller)));
        }

        let mut row = crate::impact::EntityImpact::empty(new.id);
        row.consumer_count = 4;
        row.external_consumer_count = 1;
        row.test_consumer_count = 3;

        let diff = SemanticDiff {
            entity_changes: vec![EntityChange {
                entity_id: new.id,
                kind: EntityChangeKind::Modified {
                    old: old.clone(),
                    new: new.clone(),
                },
            }],
            relation_changes,
            ..Default::default()
        };
        let impact = ImpactReport {
            affected_callers: vec![caller.clone()],
            affected_dependents: others[..5].to_vec(),
            changed_ids: vec![new.id],
            entity_impacts: vec![row],
            ..Default::default()
        };
        let mut risk = quiet_risk(RiskLevel::High);
        risk.breaking_changes
            .push("Signature change on `load_dotenv`: `a` -> `b`".into());

        let mut graph_entities = vec![caller, new];
        graph_entities.extend(others);
        (review_of(diff, impact, risk), graph_entities)
    }

    fn graph_namer(entities: &[Entity]) -> impl Fn(&GraphNodeId) -> Option<String> + '_ {
        move |node| {
            let id = node.as_entity()?;
            entities
                .iter()
                .find(|entity| entity.id == id)
                .map(entity_label)
        }
    }

    fn position(text: &str, needle: &str) -> usize {
        text.find(needle)
            .unwrap_or_else(|| panic!("`{needle}` missing from:\n{text}"))
    }

    #[test]
    fn the_summary_and_breaking_changes_lead_the_review() {
        let (review, _) = rename_after_import();
        let output = format_review(&review);

        let summary = position(&output, "--- Summary ---");
        let risk = position(&output, "Overall risk: HIGH");
        let breaking = position(&output, "! Signature change on `load_dotenv`");
        let entities = position(&output, "--- Entity Changes ---");
        let relations = position(&output, "--- Relation Changes ---");
        let impact = position(&output, "--- Impact Analysis ---");
        assert!(
            summary < risk && risk < breaking && breaking < entities,
            "{output}"
        );
        assert!(entities < relations && relations < impact, "{output}");
        assert!(
            output.contains("Relations: 42 changed, 40 of them from language-server enrichment\n"),
            "{output}"
        );
        assert!(output.contains("Entities: 1 modified\n"), "{output}");
        assert!(
            output.contains(
                "Downstream: 6 affected entities, direct and transitive, listed under Impact \
                 Analysis\n"
            ),
            "{output}"
        );
        assert!(!output.contains("Risk Assessment"), "{output}");
    }

    #[test]
    fn relation_changes_are_counted_by_origin_and_kind_and_never_print_an_id() {
        let (review, entities) = rename_after_import();
        let namer = graph_namer(&entities);
        let output = format_review_with(
            &review,
            &ReviewRenderOptions {
                node_names: Some(&namer),
                relation_list_hint: Some("Add --relations to list each one."),
                ..Default::default()
            },
        );

        // The two parsed edges are few enough to name; the forty from
        // enrichment are their own group and only counted.
        assert!(output.contains("Parsed from source (2):\n"), "{output}");
        assert!(
            output.contains(
                "  Calls: 1 added\n    + Flask.run [src/flask/app.py] -> load_dotenv [src/flask/cli.py]\n"
            ),
            "{output}"
        );
        assert!(
            output.contains(
                "  References: 1 removed\n    - load_dotenv [src/flask/cli.py] -> Flask.run [src/flask/app.py]\n"
            ),
            "{output}"
        );
        assert!(
            output.contains(
                "From language-server enrichment (40):\n  UsesType: 30 added\n  Calls: 10 added\n"
            ),
            "{output}"
        );
        assert!(
            output.contains("Add --relations to list each one.\n"),
            "{output}"
        );
        assert!(!output.contains("[src/flask/helpers.py] ->"), "{output}");
        for entity in &entities {
            assert!(
                !output.contains(&entity.id.to_string()),
                "an id reached the review text:\n{output}"
            );
        }
    }

    #[test]
    fn listing_every_relation_names_each_one_and_drops_the_hint() {
        let (review, entities) = rename_after_import();
        let namer = graph_namer(&entities);
        let output = format_review_with(
            &review,
            &ReviewRenderOptions {
                node_names: Some(&namer),
                list_all_relations: true,
                relation_list_hint: Some("Add --relations to list each one."),
                ..Default::default()
            },
        );

        for i in 0..40 {
            assert!(
                output.contains(&format!(
                    "    + helper_{i} [src/flask/helpers.py] -> Flask.run [src/flask/app.py]\n"
                )),
                "helper_{i} missing:\n{output}"
            );
        }
        assert!(!output.contains("Add --relations"), "{output}");
        assert!(!output.contains("entity:"), "{output}");
    }

    #[test]
    fn an_endpoint_nobody_can_name_is_marked_unnamed_with_a_short_id() {
        use kin_model::relation::RelationKind;

        let known = test_entity("known");
        let stranger = test_entity("stranger");
        let diff = SemanticDiff {
            entity_changes: vec![EntityChange {
                entity_id: known.id,
                kind: EntityChangeKind::Added(known.clone()),
            }],
            relation_changes: vec![added(relation(
                RelationKind::Calls,
                RelationOrigin::Parsed,
                &known,
                &stranger,
            ))],
            ..Default::default()
        };

        let output = format_diff(&diff);
        let full = stranger.id.to_string();
        let short: String = full.chars().take(8).collect();
        assert!(
            output.contains(&format!("    + known -> unnamed entity {short}\n")),
            "{output}"
        );
        assert!(!output.contains(&full), "{output}");
    }

    #[test]
    fn a_modified_relation_says_what_moved() {
        use kin_model::relation::RelationKind;

        let a = test_entity("a");
        let b = test_entity("b");
        let old = relation(RelationKind::References, RelationOrigin::Parsed, &a, &b);
        let mut kind_moved = old.clone();
        kind_moved.kind = RelationKind::Calls;
        let mut origin_moved = old.clone();
        origin_moved.origin = RelationOrigin::Lsp;
        let diff = SemanticDiff {
            entity_changes: vec![
                EntityChange {
                    entity_id: a.id,
                    kind: EntityChangeKind::Added(a.clone()),
                },
                EntityChange {
                    entity_id: b.id,
                    kind: EntityChangeKind::Added(b.clone()),
                },
            ],
            relation_changes: vec![
                RelationChange {
                    kind: RelationChangeKind::Modified {
                        old: old.clone(),
                        new: kind_moved,
                    },
                },
                RelationChange {
                    kind: RelationChangeKind::Modified {
                        old,
                        new: origin_moved,
                    },
                },
            ],
            ..Default::default()
        };

        let output = format_diff(&diff);
        assert!(
            output.contains("  Calls: 1 modified\n    ~ a -> b (was References: a -> b)\n"),
            "{output}"
        );
        assert!(
            output.contains(
                "From language-server enrichment (1):\n  References: 1 modified\n    ~ a -> b (origin was parsed)\n"
            ),
            "{output}"
        );
    }

    #[test]
    fn the_summary_counts_removed_relation_notes_instead_of_repeating_them() {
        use kin_model::relation::RelationKind;

        let a = test_entity("a");
        let b = test_entity("b");
        let removals: Vec<RelationChange> = (0..3)
            .map(|_| RelationChange {
                kind: RelationChangeKind::Removed {
                    old: relation(RelationKind::Calls, RelationOrigin::Parsed, &a, &b),
                },
            })
            .collect();
        let diff = SemanticDiff {
            relation_changes: removals,
            ..Default::default()
        };
        // The notes come from the rule that writes them, so a change to their
        // wording that the summary no longer recognizes fails here.
        let risk = crate::risk::assess_risk(&diff, &ImpactReport::default());
        assert_eq!(
            risk.notes
                .iter()
                .filter(|note| note.starts_with(RELATION_REMOVED_NOTE_PREFIX))
                .count(),
            3,
            "{:?}",
            risk.notes
        );
        let mut review = review_of(diff, ImpactReport::default(), risk);
        review.risk.notes.push("Another note".into());

        let summary = format_summary(&review);
        assert!(
            summary.contains("\nNotes:\n  - Another note\n  - 3 relations removed, counted under Relation Changes\n"),
            "{summary}"
        );
        assert!(!summary.contains(RELATION_REMOVED_NOTE_PREFIX), "{summary}");

        // The stand-alone risk section still lists each note.
        let highlights = format_risk_highlights(&review);
        assert_eq!(
            highlights.matches(RELATION_REMOVED_NOTE_PREFIX).count(),
            3,
            "{highlights}"
        );
    }

    #[test]
    fn direct_consumers_name_the_entity_a_breaking_count_belongs_to() {
        let (review, _) = rename_after_import();
        let output = format_review(&review);

        assert!(
            output.contains(
                "Total affected entities: 6, direct and transitive, across 1 changed entity\n"
            ),
            "{output}"
        );
        assert!(
            output.contains("  load_dotenv [src/flask/cli.py]: 1 external, 3 tests\n"),
            "{output}"
        );
    }

    #[test]
    fn a_bounded_answer_prints_one_not_settled_line_and_names_three_entities() {
        let (review, _) = rename_after_import();
        let names = [
            "run",
            "main",
            "load_app",
            "find_app",
            "locate_app",
            "cli_main",
        ];
        let entities: Vec<PendingEntity<'_>> = names
            .iter()
            .map(|name| PendingEntity {
                name,
                path: "src/flask/cli.py",
            })
            .collect();
        let output = format_review_with(
            &review,
            &ReviewRenderOptions {
                pending_enrichment: Some(PendingEnrichment {
                    code: "call_sites_owed",
                    total_pending_entities: 8,
                    limitation: Some("Callers in these files may be missing from the counts"),
                    entities: &entities,
                }),
                ..Default::default()
            },
        );

        assert_eq!(output.matches("not settled:").count(), 1, "{output}");
        assert!(
            output.contains(
                "not settled: call_sites_owed: 8 entities still pending enrichment. Callers in \
                 these files may be missing from the counts. Run `kin daemon sweep` to settle \
                 them.\n  run (path: src/flask/cli.py)\n  main (path: src/flask/cli.py)\n  \
                 load_app (path: src/flask/cli.py)\n  and 5 more\n"
            ),
            "{output}"
        );
        assert!(!output.contains("find_app"), "{output}");
        // It qualifies the counts it follows and comes before the findings.
        assert!(
            position(&output, "Downstream:") < position(&output, "not settled:")
                && position(&output, "not settled:") < position(&output, "Breaking changes"),
            "{output}"
        );
    }

    #[test]
    fn review_enrichment_uses_selected_observation_and_bounds_pending_names() {
        use crate::enrichment::{
            EnrichmentObservation, EnrichmentProjection, PendingEnrichmentEntity,
        };
        let (mut review, _) = rename_after_import();
        let selected = SemanticChangeId::from_hash(Hash256::from_bytes([91; 32]));
        let pending_entities: Vec<_> = (0..5)
            .map(|index| PendingEnrichmentEntity {
                entity_id: EntityId::new(),
                name: format!("historical_pending_{index}"),
                projection: EnrichmentProjection {
                    path: (index != 1).then(|| format!("old/{index}.py")),
                },
                states: vec!["owed".into()],
                validation_reason: None,
            })
            .collect();
        let ids: Vec<_> = pending_entities
            .iter()
            .map(|entity| entity.entity_id)
            .collect();
        review.impact.enrichment = Some(EnrichmentObservation {
            scope: "committed_graph".into(),
            selected_change: Some(selected),
            status: "bounded".into(),
            basis: "persisted_call_site_ledgers".into(),
            limitation: Some("The selected revision still owes call-site evidence.".into()),
            total_pending_entities: 7,
            pending_entities,
            entities_withheld: 2,
        });
        for output in [format_review(&review), format_summary(&review)] {
            assert_eq!(output.matches("not settled:").count(), 1, "{output}");
            assert!(position(&output, "--- Summary ---") < position(&output, "not settled:"));
            assert_eq!(output.matches("(path:").count(), 3, "{output}");
            assert!(output.contains("historical_pending_0 (path: old/0.py)"));
            assert!(output.contains("historical_pending_1 (path: unavailable)"));
            assert!(output.contains("historical_pending_2 (path: old/2.py)"));
            assert!(!output.contains("historical_pending_3"));
            assert!(!output.contains("historical_pending_4"));
            assert!(output.contains("and 4 more"));
            assert!(output.contains("The selected revision still owes call-site evidence."));
            assert!(!output.contains("kin daemon sweep"), "{output}");
            for id in &ids {
                assert!(
                    !output.contains(&id.to_string()),
                    "pending identities must be named"
                );
            }
        }
        // The current graph can acquire evidence through a sweep. Changing
        // only the recorded scope must not remove that useful guidance.
        let observation = review.impact.enrichment.as_mut().unwrap();
        observation.scope = "selected_graph_repository".into();
        observation.selected_change = None;
        for output in [format_review(&review), format_summary(&review)] {
            assert!(
                output.contains("Run `kin daemon sweep` to retry analysis."),
                "{output}"
            );
            assert!(!output.contains("to settle"), "{output}");
            assert_eq!(output.matches("not settled:").count(), 1, "{output}");
        }
        // Absence of recorded call-site debt is not a new claim that all
        // language-server enrichment is complete.
        let observation = review.impact.enrichment.as_mut().unwrap();
        observation.status = "no_recorded_call_site_debt".into();
        observation.total_pending_entities = 0;
        observation.pending_entities.clear();
        observation.entities_withheld = 0;
        observation.limitation = None;
        assert!(!format_review(&review).contains("not settled:"));
        assert!(!format_summary(&review).contains("kin daemon sweep"));
    }

    #[test]
    fn a_settled_answer_prints_nothing_about_enrichment() {
        let (review, _) = rename_after_import();
        assert!(review.impact.enrichment.is_none());
        let output = format_review(&review);
        assert!(!output.contains("not settled"), "{output}");
        assert!(!output.contains("kin daemon sweep"), "{output}");
    }

    #[test]
    fn a_single_pending_entity_reads_in_the_singular() {
        let pending = PendingEnrichment {
            code: "call_sites_owed",
            total_pending_entities: 1,
            limitation: None,
            entities: &[],
        };
        assert_eq!(
            not_settled_line(&pending),
            "not settled: call_sites_owed: 1 entity still pending enrichment. Run `kin daemon \
             sweep` to settle it."
        );
    }

    #[test]
    fn graph_node_name_reads_the_entity_from_the_store() {
        use kin_model::graph::EntityStore as _;

        let graph = kin_db::InMemoryGraph::new();
        let held = located_entity("held", "src/lib.rs");
        graph.upsert_entity(&held).unwrap();

        assert_eq!(
            graph_node_name(&graph, &GraphNodeId::Entity(held.id)).as_deref(),
            Some("held [src/lib.rs]")
        );
        assert_eq!(
            graph_node_name(&graph, &GraphNodeId::Entity(EntityId::new())),
            None
        );
    }

    #[test]
    fn an_annotation_preview_cuts_on_a_character_boundary() {
        use kin_model::{
            Annotation, AnnotationId, AnnotationKind, IdentityRef, StalenessState, WorkScope,
        };

        let text = "é".repeat(80);
        let impact = ImpactReport {
            affected_annotations: vec![Annotation {
                annotation_id: AnnotationId::new(),
                scopes: vec![WorkScope::Entity(EntityId::new())],
                kind: AnnotationKind::Warning,
                body: text,
                anchored_fingerprint: None,
                authored_by: IdentityRef::human("dev"),
                created_at: kin_model::timestamp::Timestamp::now(),
                staleness: StalenessState::Fresh,
            }],
            ..Default::default()
        };
        let output = format_impact(&impact);
        assert!(
            output.contains(&format!("{}...", "é".repeat(60))),
            "{output}"
        );
    }
}
