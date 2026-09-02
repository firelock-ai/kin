// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The consumer-facing projection of the live graph.
//!
//! `kin graph viz` built a render payload by reading a snapshot off disk and
//! serving it once, so every outside consumer that wanted to draw or follow a
//! repository had to start that server and scrape it. The payload had no line,
//! no signature and no cap, and each consumer wrote its own sampling rule, so
//! two clients drawing "the graph" drew different graphs.
//!
//! This module holds the payload shape and the sampling rule in one place, as
//! pure functions over what the graph reported. The daemon serves them at
//! `GET /graph/export` against the live graph it already holds, and the CLI
//! asks that same route, so there is one answer and one sample.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use kin_model::{Entity, EntityStore, GraphNodeId};
use serde::{Deserialize, Serialize};

/// Node cap applied when a caller names none.
///
/// A caller that asks for no cap gets none: the whole graph is a legitimate
/// request and the export must be able to answer it. This is the default a
/// drawing client inherits, chosen because it is the largest node count the
/// existing force-directed renderers stay interactive at.
pub const DEFAULT_NODE_LIMIT: usize = 1_400;

/// One drawable node.
///
/// `line` and `signature` are absent unless the caller asked for them through
/// `include`, so the default payload carries exactly the fields the current
/// renderers read and nothing that would grow it for no drawn pixel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphExportNode {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub file: Option<String>,
    pub degree: usize,
    /// 1-based presentation start line, when the caller asked for it and the
    /// entity carries a span. A spanless entity has no line to report and
    /// reporting 0 or 1 for one would be a fabricated position.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

/// One drawable edge. Both endpoints are ids present in `nodes`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphExportLink {
    pub source: String,
    pub target: String,
    pub kind: String,
}

/// The export envelope.
///
/// The counts describe the population the sample was drawn from, so a client
/// can say how much of the graph it is showing rather than implying it drew
/// all of it. `root_hash` names the graph this payload came from, which is what
/// pairs an export with the delta stream: an event whose root no longer matches
/// means re-export rather than patch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GraphExportPayload {
    /// Hex Merkle root of the graph this payload was built from.
    pub root_hash: String,
    /// Position in the delta stream this payload was cut at.
    ///
    /// The resync key. A client exports, subscribes to `/graph/events`, and
    /// discards every event whose `seq` is at or below this one; what is left is
    /// exactly what happened after the cut. The root hash cannot do this job on
    /// its own, because a working-tree edit changes the graph without advancing
    /// the root, so a client reconnecting between commits would see a matching
    /// hash and a stale picture.
    pub seq: u64,
    /// Entities matching `kinds` and `path`, before the node cap.
    pub entity_count: usize,
    /// Drawable links among those entities, before the node cap.
    pub relation_count: usize,
    /// Relations withheld because an endpoint is not an entity in this graph at
    /// all. An import of an external crate resolves to a placeholder that is no
    /// entity here, and a link naming an absent node is not a drawable edge.
    pub unresolved_links: usize,
    /// Relations withheld because an endpoint was excluded by `kinds`, `path`
    /// or the node cap. Counted apart from `unresolved_links` because one is a
    /// property of the graph and the other is a property of this request.
    pub filtered_links: usize,
    /// Whether the node cap dropped anything. False means `nodes` is every
    /// entity that matched.
    pub sampled: bool,
    /// The cap actually applied, absent when the caller asked for no cap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<usize>,
    pub nodes: Vec<GraphExportNode>,
    pub links: Vec<GraphExportLink>,
}

/// Which optional node fields a caller asked for.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IncludeFields {
    pub line: bool,
    pub signature: bool,
}

impl IncludeFields {
    /// Parse a comma-separated `include` value. Unknown names are ignored
    /// rather than refused, so a newer client naming a field this build does
    /// not have still gets its export.
    pub fn parse(raw: &str) -> Self {
        let mut fields = Self::default();
        for token in raw.split(',') {
            match token.trim().to_ascii_lowercase().as_str() {
                "line" | "lines" => fields.line = true,
                "signature" | "signatures" => fields.signature = true,
                _ => {}
            }
        }
        fields
    }
}

/// A resolved export request.
#[derive(Debug, Clone, Default)]
pub struct ExportOptions {
    /// `None` means no cap: emit every matching entity.
    pub limit: Option<usize>,
    /// Normalized entity-kind names. Empty means every kind.
    pub kinds: Vec<String>,
    /// Repository path prefix a node's file must start with.
    pub path_prefix: Option<String>,
    pub include: IncludeFields,
}

/// Normalize a kind name so `TraitDef`, `trait_def` and `traitdef` are one key.
///
/// The payload emits the graph's own `Debug` spelling because that is what the
/// existing renderers already switch on. A query parameter typed by a human or
/// a JSON client should not have to guess which spelling this build uses.
fn normalize_kind(raw: &str) -> String {
    raw.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// Parse a comma-separated `kinds` value into normalized names.
pub fn parse_kinds(raw: &str) -> Vec<String> {
    raw.split(',')
        .map(normalize_kind)
        .filter(|k| !k.is_empty())
        .collect()
}

/// One node's graph-owned identity, split out from the store so payload
/// assembly is a pure function over what the graph reported.
#[derive(Debug, Clone)]
pub struct NodeMeta {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub file: Option<String>,
    pub line: Option<u32>,
    pub signature: Option<String>,
}

impl NodeMeta {
    /// Project one graph entity into the export's node identity.
    pub fn from_entity(entity: &Entity) -> Self {
        Self {
            id: entity.id.to_string(),
            name: entity.name.clone(),
            kind: format!("{:?}", entity.kind),
            file: entity.file_origin.as_ref().map(|f| f.0.clone()),
            line: entity
                .span
                .as_ref()
                .map(|span| span.start_line.saturating_add(1)),
            signature: if entity.signature.is_empty() {
                None
            } else {
                Some(entity.signature.clone())
            },
        }
    }

    fn matches(&self, options: &ExportOptions) -> bool {
        if !options.kinds.is_empty() && !options.kinds.contains(&normalize_kind(&self.kind)) {
            return false;
        }
        if let Some(prefix) = options.path_prefix.as_deref() {
            let Some(file) = self.file.as_deref() else {
                // A node with no file cannot satisfy a path prefix. Keeping it
                // would answer "under this directory" with something that is
                // under no directory at all.
                return false;
            };
            if !file.starts_with(prefix) {
                return false;
            }
        }
        true
    }
}

/// The module a node is sampled within.
///
/// A faithful port of the rule the demo renderer already applies client side
/// (`kin-demo/server/graph-sampling.ts:moduleOf`), moved here so kin serves one
/// sample instead of every consumer inventing its own. Two clients drawing "the
/// graph" were drawing different graphs; now they draw the same one.
///
/// The two-level case is why the rule is not just "first path segment". A Rust
/// workspace keeps every crate under `crates/`, a pnpm workspace keeps every
/// app under `packages/`, and collapsing those into one bucket hands the whole
/// quota to whichever crate happens to be densest while every other crate
/// disappears from the picture.
fn module_of(file: Option<&str>) -> String {
    let Some(raw) = file.filter(|value| !value.is_empty()) else {
        // Entities the graph placed in no file are real and are under no
        // module. They share one bucket rather than vanishing.
        return UNKNOWN_MODULE.to_string();
    };
    let normalized = raw.replace('\\', "/");
    let normalized = normalized.strip_prefix("./").unwrap_or(&normalized);
    let parts: Vec<&str> = normalized.split('/').filter(|p| !p.is_empty()).collect();
    if parts.len() <= 1 {
        // A file at the repository root is its own module for this purpose.
        return ROOT_MODULE.to_string();
    }
    if CONTAINER_DIRS.contains(&parts[0]) && parts.len() > 2 {
        return format!("{}/{}", parts[0], parts[1]);
    }
    parts[0].to_string()
}

/// Directories that hold modules rather than being one.
const CONTAINER_DIRS: &[&str] = &[
    "app", "apps", "cmd", "crates", "internal", "lib", "modules", "packages", "pkg", "services",
    "src",
];

const UNKNOWN_MODULE: &str = "(unknown)";
const ROOT_MODULE: &str = "(root)";

/// Share of the node cap handed out as per-module quotas.
///
/// The rest is filled globally by degree, so the sample is neither "the
/// densest module only" nor "an even slice of everything". Ported from the
/// demo's rule rather than re-derived, because matching an already-shipped
/// picture is worth more here than a marginally better one nobody has seen.
const QUOTA_SHARE_PERCENT: usize = 60;

/// Rank key within a module: highest degree first, then a stable tiebreak.
///
/// The id tiebreak is what makes the sample deterministic, and it is the one
/// place this deviates from the demo's rule. Degree and name alone leave every
/// zero-degree same-name node tied, and which of them survived would then
/// depend on the order the store happened to enumerate entities in, so two
/// exports of one unchanged graph could disagree.
fn rank_key(node: &(NodeMeta, usize)) -> (std::cmp::Reverse<usize>, &str, &str) {
    (
        std::cmp::Reverse(node.1),
        node.0.name.as_str(),
        node.0.id.as_str(),
    )
}

/// Reduce `ranked` to at most `limit` nodes: a per-module quota by degree,
/// then a global fill by degree for whatever budget the quotas left.
///
/// Returns the surviving nodes in canonical id order, so the payload's node
/// order does not leak the order the sample was assembled in.
fn sample(ranked: Vec<(NodeMeta, usize)>, limit: usize) -> Vec<(NodeMeta, usize)> {
    if limit == 0 || ranked.len() <= limit {
        let mut kept = ranked;
        kept.sort_by(|a, b| a.0.id.cmp(&b.0.id));
        return kept;
    }

    // BTreeMap, not a hash map: module iteration order decides who gets the
    // quota when the budget runs out mid-pass, so it has to be the same order
    // every time rather than whatever the hasher produced.
    let mut by_module: BTreeMap<String, Vec<usize>> = BTreeMap::new();
    for (index, node) in ranked.iter().enumerate() {
        by_module
            .entry(module_of(node.0.file.as_deref()))
            .or_default()
            .push(index);
    }
    for indices in by_module.values_mut() {
        indices.sort_by(|a, b| rank_key(&ranked[*a]).cmp(&rank_key(&ranked[*b])));
    }

    let share = std::cmp::max(
        1,
        limit.saturating_mul(QUOTA_SHARE_PERCENT) / 100 / by_module.len(),
    );
    let mut chosen: HashSet<usize> = HashSet::with_capacity(limit);
    'quota: for indices in by_module.values() {
        for index in indices.iter().take(share) {
            if chosen.len() >= limit {
                break 'quota;
            }
            chosen.insert(*index);
        }
    }

    if chosen.len() < limit {
        let mut rest: Vec<usize> = (0..ranked.len())
            .filter(|index| !chosen.contains(index))
            .collect();
        rest.sort_by(|a, b| rank_key(&ranked[*a]).cmp(&rank_key(&ranked[*b])));
        for index in rest {
            if chosen.len() >= limit {
                break;
            }
            chosen.insert(index);
        }
    }

    let mut kept: Vec<(NodeMeta, usize)> = ranked
        .into_iter()
        .enumerate()
        .filter_map(|(index, node)| chosen.contains(&index).then_some(node))
        .collect();
    kept.sort_by(|a, b| a.0.id.cmp(&b.0.id));
    kept
}

/// Assemble the export payload from what the graph reported.
///
/// `all_entity_ids` is every entity id in the graph, unfiltered: it is what
/// separates a relation pointing outside the graph from one pointing at a node
/// this request excluded. `edges` are the graph's relations as
/// (source, target, kind) with both endpoints already resolved to entity ids.
pub fn assemble_payload(
    root_hash: String,
    seq: u64,
    node_meta: Vec<NodeMeta>,
    all_entity_ids: &HashSet<String>,
    edges: impl IntoIterator<Item = (String, String, String)>,
    options: &ExportOptions,
) -> GraphExportPayload {
    let matched: Vec<NodeMeta> = node_meta
        .into_iter()
        .filter(|meta| meta.matches(options))
        .collect();
    let matched_ids: HashSet<&str> = matched.iter().map(|meta| meta.id.as_str()).collect();

    // Collapse to undirected (a, b, kind) keys BEFORE classifying anything.
    // `read_graph` walks every entity and asks for its relations, so an edge
    // between two entities is reported twice, once from each end. Classifying
    // first counted one graph edge as two withheld ones, and the render payload
    // has always drawn such a pair as a single line anyway.
    let mut distinct_edges: BTreeSet<(String, String, String)> = BTreeSet::new();
    for (a, b, kind) in edges {
        let (a, b) = if a <= b { (a, b) } else { (b, a) };
        distinct_edges.insert((a, b, kind));
    }

    let mut link_keys: BTreeSet<(String, String, String)> = BTreeSet::new();
    let mut unresolved_links = 0usize;
    let mut filtered_links = 0usize;
    for (a, b, kind) in distinct_edges {
        if !all_entity_ids.contains(a.as_str()) || !all_entity_ids.contains(b.as_str()) {
            unresolved_links += 1;
            continue;
        }
        if !matched_ids.contains(a.as_str()) || !matched_ids.contains(b.as_str()) {
            filtered_links += 1;
            continue;
        }
        link_keys.insert((a, b, kind));
    }

    let mut degrees: HashMap<&str, usize> = HashMap::with_capacity(matched.len());
    for (a, b, _kind) in &link_keys {
        *degrees.entry(a.as_str()).or_insert(0) += 1;
        *degrees.entry(b.as_str()).or_insert(0) += 1;
    }

    let entity_count = matched.len();
    let relation_count = link_keys.len();

    let ranked: Vec<(NodeMeta, usize)> = matched
        .into_iter()
        .map(|meta| {
            let degree = degrees.get(meta.id.as_str()).copied().unwrap_or(0);
            (meta, degree)
        })
        .collect();

    let (kept, sampled) = match options.limit {
        Some(limit) if ranked.len() > limit => (sample(ranked, limit), true),
        _ => {
            let mut kept = ranked;
            kept.sort_by(|a, b| a.0.id.cmp(&b.0.id));
            (kept, false)
        }
    };

    let kept_ids: HashSet<&str> = kept.iter().map(|(meta, _)| meta.id.as_str()).collect();
    let mut links: Vec<GraphExportLink> = Vec::new();
    for (source, target, kind) in link_keys {
        if !kept_ids.contains(source.as_str()) || !kept_ids.contains(target.as_str()) {
            filtered_links += 1;
            continue;
        }
        links.push(GraphExportLink {
            source,
            target,
            kind,
        });
    }

    let nodes: Vec<GraphExportNode> = kept
        .into_iter()
        .map(|(meta, degree)| GraphExportNode {
            id: meta.id,
            name: meta.name,
            kind: meta.kind,
            file: meta.file,
            degree,
            line: if options.include.line {
                meta.line
            } else {
                None
            },
            signature: if options.include.signature {
                meta.signature
            } else {
                None
            },
        })
        .collect();

    GraphExportPayload {
        root_hash,
        seq,
        entity_count,
        relation_count,
        unresolved_links,
        filtered_links,
        sampled,
        limit: options.limit,
        nodes,
        links,
    }
}

/// Read the entities and relations an export needs out of a graph store.
///
/// Split from [`assemble_payload`] so the shaping and sampling rules can be
/// graded without a store, and so the daemon and any offline reader produce the
/// same payload from the same graph.
pub fn read_graph<S>(
    store: &S,
) -> anyhow::Result<(
    Vec<NodeMeta>,
    HashSet<String>,
    Vec<(String, String, String)>,
)>
where
    S: EntityStore,
{
    let entities = store
        .list_all_entities()
        .map_err(|error| anyhow::anyhow!("list graph entities: {error}"))?;

    let all_entity_ids: HashSet<String> = entities.iter().map(|e| e.id.to_string()).collect();

    let mut edges: Vec<(String, String, String)> = Vec::new();
    for entity in &entities {
        let src_id = entity.id.to_string();
        let relations = store
            .get_all_relations_for_entity(&entity.id)
            .map_err(|error| anyhow::anyhow!("read relations for {src_id}: {error}"))?;
        for relation in relations {
            let other_id = match (&relation.src, &relation.dst) {
                (GraphNodeId::Entity(s), GraphNodeId::Entity(d)) => {
                    if *s == entity.id {
                        d.to_string()
                    } else {
                        s.to_string()
                    }
                }
                _ => continue,
            };
            edges.push((src_id.clone(), other_id, format!("{:?}", relation.kind)));
        }
    }

    let node_meta = entities.iter().map(NodeMeta::from_entity).collect();
    Ok((node_meta, all_entity_ids, edges))
}

/// How a caller asked for the export on the command line.
#[derive(Debug, Clone, Default)]
pub struct ExportArgs {
    /// `None` uses [`DEFAULT_NODE_LIMIT`]; `Some(0)` means no cap at all.
    pub limit: Option<usize>,
    pub kinds: Option<String>,
    pub path: Option<String>,
    pub include: Option<String>,
    pub out: Option<std::path::PathBuf>,
    pub json: bool,
}

/// Build the `/graph/export` query string for these arguments.
///
/// Split out so the encoding is graded without a daemon: a `path` prefix
/// holding a space or an `&` has to survive the trip, and a caller who asked
/// for no cap has to be distinguishable from one who named none.
pub fn export_query_string(args: &ExportArgs) -> String {
    let mut parts: Vec<String> = Vec::new();
    // An explicit 0 is the request for the whole graph. It has to reach the
    // daemon as a value, because omitting the parameter means "use the default
    // cap" and those are opposite requests.
    if let Some(limit) = args.limit {
        parts.push(format!("limit={limit}"));
    }
    for (key, value) in [
        ("kinds", args.kinds.as_deref()),
        ("path", args.path.as_deref()),
        ("include", args.include.as_deref()),
    ] {
        if let Some(value) = value.filter(|v| !v.trim().is_empty()) {
            parts.push(format!(
                "{key}={}",
                crate::daemon_client::urlencoding::encode(value)
            ));
        }
    }
    parts.join("&")
}

/// `kin graph export`: the drawable projection of the live graph, as JSON.
pub async fn export(args: ExportArgs) -> anyhow::Result<()> {
    let layout = crate::commands::require_repository_layout()?;
    let client =
        crate::daemon_client::DaemonClient::connect_for_command("graph export", &layout).await?;
    let payload = client.graph_export(&export_query_string(&args)).await?;

    let body = serde_json::to_string_pretty(&payload)
        .map_err(|error| anyhow::anyhow!("serialize graph export: {error}"))?;

    if let Some(path) = args.out.as_ref() {
        std::fs::write(path, format!("{body}\n"))
            .map_err(|error| anyhow::anyhow!("write {}: {error}", path.display()))?;
        if !args.json {
            println!("{}", export_summary_line(&payload, Some(path)));
        }
        return Ok(());
    }

    if args.json {
        println!("{body}");
    } else {
        println!("{}", export_summary_line(&payload, None));
    }
    Ok(())
}

/// One line saying what the export actually contains.
///
/// It reports the drawn counts against the population they came from, because
/// a sampled export that reported only its own size would read as the whole
/// graph. `sampled` alone does not say how much was left out.
pub fn export_summary_line(
    payload: &GraphExportPayload,
    written_to: Option<&std::path::Path>,
) -> String {
    let scope = if payload.sampled {
        format!(
            "{} of {} entities and {} of {} relations (sampled)",
            payload.nodes.len(),
            payload.entity_count,
            payload.links.len(),
            payload.relation_count
        )
    } else {
        format!(
            "{} entities and {} relations (complete)",
            payload.nodes.len(),
            payload.links.len()
        )
    };
    match written_to {
        Some(path) => format!(
            "Wrote {scope} at root {} seq {} to {}",
            payload.root_hash,
            payload.seq,
            path.display()
        ),
        None => format!("{scope} at root {} seq {}", payload.root_hash, payload.seq),
    }
}

/// How a caller asked to watch the graph on the command line.
#[derive(Debug, Clone, Default)]
pub struct WatchArgs {
    /// Event type names to keep. Empty means every type.
    pub types: Option<String>,
    pub json: bool,
}

/// Build the `/graph/events` query string for these arguments.
pub fn watch_query_string(args: &WatchArgs) -> String {
    match args.types.as_deref().filter(|v| !v.trim().is_empty()) {
        Some(types) => format!("types={}", crate::daemon_client::urlencoding::encode(types)),
        None => String::new(),
    }
}

/// Pull the JSON payloads out of one chunk of an SSE body.
///
/// SSE frames are separated by a blank line and a frame may arrive split across
/// TCP reads, so the caller keeps a buffer and hands back whatever tail did not
/// terminate. Comment lines (the heartbeat) carry no payload and are dropped.
pub fn drain_sse_frames(buffer: &mut String) -> Vec<String> {
    let mut payloads = Vec::new();
    while let Some(end) = buffer.find("\n\n") {
        let frame: String = buffer.drain(..end + 2).collect();
        for line in frame.lines() {
            let line = line.trim_end_matches('\r');
            if let Some(rest) = line.strip_prefix("data:") {
                let payload = rest.trim();
                if !payload.is_empty() {
                    payloads.push(payload.to_string());
                }
            }
        }
    }
    payloads
}

/// `kin graph watch`: follow the live graph, one event per line.
pub async fn watch(args: WatchArgs) -> anyhow::Result<()> {
    use std::io::Write as _;

    let layout = crate::commands::require_repository_layout()?;
    let client =
        crate::daemon_client::DaemonClient::connect_for_command("graph watch", &layout).await?;
    let mut response = client.graph_events(&watch_query_string(&args)).await?;

    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let mut buffer = String::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| anyhow::anyhow!("read graph event stream: {error}"))?
    {
        buffer.push_str(&String::from_utf8_lossy(&chunk));
        for payload in drain_sse_frames(&mut buffer) {
            if args.json {
                writeln!(out, "{payload}")?;
            } else {
                writeln!(out, "{}", watch_human_line(&payload))?;
            }
            // Flushed per event, not per buffer. A watch piped into another
            // process is useless if its output arrives in 8 KiB batches minutes
            // after the change it describes.
            out.flush()?;
        }
    }
    Ok(())
}

/// One human-readable line for an event payload.
///
/// Falls back to the raw JSON rather than dropping an event whose shape this
/// build does not know. A watch that silently swallowed a newer daemon's event
/// would be worse than one that printed something ugly.
pub fn watch_human_line(payload: &str) -> String {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(payload) else {
        return payload.to_string();
    };
    let event_type = value
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("event");
    let field = |name: &str| value.get(name).and_then(|v| v.as_str()).map(str::to_string);
    match event_type {
        "EntityChanged" => format!(
            "entity {} {} {}",
            field("change_type").unwrap_or_else(|| "changed".to_string()),
            field("entity_id").unwrap_or_default(),
            field("file_path").unwrap_or_default()
        )
        .trim_end()
        .to_string(),
        "RelationChanged" => format!(
            "relation {} {} {} -> {}",
            field("change_type").unwrap_or_else(|| "changed".to_string()),
            field("kind").unwrap_or_default(),
            field("source").unwrap_or_default(),
            field("target").unwrap_or_default()
        ),
        "GraphRootChanged" => format!(
            "graph root -> {}",
            field("new_root_hash").unwrap_or_default()
        ),
        _ => payload.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(id: &str, name: &str, kind: &str, file: Option<&str>) -> NodeMeta {
        NodeMeta {
            id: id.to_string(),
            name: name.to_string(),
            kind: kind.to_string(),
            file: file.map(str::to_string),
            line: Some(7),
            signature: Some(format!("fn {name}()")),
        }
    }

    fn ids(payload: &GraphExportPayload) -> Vec<&str> {
        payload.nodes.iter().map(|n| n.id.as_str()).collect()
    }

    fn all_ids(metas: &[NodeMeta]) -> HashSet<String> {
        metas.iter().map(|m| m.id.clone()).collect()
    }

    /// A file at the repository root, a file one level down, and a file under a
    /// container directory are three different module answers.
    ///
    /// The container case is the one that matters: a Rust workspace keeps every
    /// crate under `crates/`, so collapsing that to one bucket gives the whole
    /// quota to the densest crate and erases the rest from the picture.
    #[test]
    fn a_container_directory_is_split_one_level_deeper() {
        assert_eq!(module_of(Some("main.c")), "(root)");
        assert_eq!(module_of(Some("src/net.c")), "src");
        assert_eq!(
            module_of(Some("crates/kin-db/src/graph.rs")),
            "crates/kin-db"
        );
        assert_eq!(module_of(Some("deps/hiredis/net.c")), "deps");
        assert_eq!(module_of(None), "(unknown)");
        // A Windows path names the same module as its POSIX spelling.
        assert_eq!(module_of(Some("src\\modules\\vector.c")), "src/modules");
        // A leading "./" is not a module.
        assert_eq!(module_of(Some("./src/net.c")), "src");
    }

    /// The same graph exports the same sample no matter what order the store
    /// enumerated it in.
    ///
    /// This is the property the demo's client-side rule did not have: it broke
    /// degree ties on name alone, so two same-name zero-degree entities were
    /// tied and whichever the store happened to list first survived.
    #[test]
    fn the_sample_does_not_depend_on_enumeration_order() {
        let build = |order: &[usize]| {
            let pool: Vec<NodeMeta> = (0..40)
                .map(|i| {
                    meta(
                        &format!("id-{i:03}"),
                        // Deliberately colliding names, so only the id can
                        // break the tie.
                        "same",
                        "Function",
                        Some(if i % 2 == 0 { "src/a.rs" } else { "lib/b.rs" }),
                    )
                })
                .collect();
            let reordered: Vec<NodeMeta> = order.iter().map(|i| pool[*i].clone()).collect();
            let known = all_ids(&pool);
            assemble_payload(
                "root".to_string(),
                0,
                reordered,
                &known,
                Vec::new(),
                &ExportOptions {
                    limit: Some(10),
                    ..Default::default()
                },
            )
        };

        let forward: Vec<usize> = (0..40).collect();
        let backward: Vec<usize> = (0..40).rev().collect();
        let shuffled: Vec<usize> = (0..40).map(|i| (i * 17) % 40).collect();

        let a = build(&forward);
        let b = build(&backward);
        let c = build(&shuffled);
        assert_eq!(
            ids(&a),
            ids(&b),
            "reversing the input must not move the sample"
        );
        assert_eq!(
            ids(&a),
            ids(&c),
            "shuffling the input must not move the sample"
        );
        assert_eq!(a.nodes.len(), 10);
        assert!(a.sampled);
    }

    /// A small module is not erased by a large dense one.
    ///
    /// Ranking the whole graph by degree hands the entire budget to whichever
    /// directory happens to be densest. Measured on redis, `utils` holds 97 of
    /// 23,098 entities; a reader looking for it has to find something drawn.
    #[test]
    fn a_small_module_survives_a_dense_one() {
        let mut metas = Vec::new();
        let mut edges = Vec::new();
        // A dense module: 200 entities, all wired to one hub.
        for i in 0..200 {
            metas.push(meta(
                &format!("big-{i:03}"),
                &format!("big{i}"),
                "Function",
                Some("src/big.rs"),
            ));
            if i > 0 {
                edges.push((
                    "big-000".to_string(),
                    format!("big-{i:03}"),
                    "Calls".to_string(),
                ));
            }
        }
        // A small module: 3 entities, no edges at all, so every one of them
        // ranks below every node in the dense module on degree.
        for i in 0..3 {
            metas.push(meta(
                &format!("small-{i}"),
                &format!("small{i}"),
                "Function",
                Some("utils/tiny.rs"),
            ));
        }

        let known = all_ids(&metas);
        let payload = assemble_payload(
            "root".to_string(),
            0,
            metas,
            &known,
            edges,
            &ExportOptions {
                limit: Some(20),
                ..Default::default()
            },
        );

        assert_eq!(payload.nodes.len(), 20);
        let small_kept = payload
            .nodes
            .iter()
            .filter(|n| n.id.starts_with("small-"))
            .count();
        assert_eq!(
            small_kept, 3,
            "every entity of a 3-entity module fits inside its quota and must be drawn"
        );
    }

    /// An edge to something that is not an entity, and an edge to an entity
    /// this request excluded, are different news and are counted apart.
    #[test]
    fn an_absent_endpoint_and_an_excluded_one_are_counted_separately() {
        let metas = vec![
            meta("a", "alpha", "Function", Some("src/a.rs")),
            meta("b", "beta", "Class", Some("src/b.rs")),
        ];
        let mut known = all_ids(&metas);
        // An entity that exists in the graph but is not in this payload's
        // population, because the caller filtered it out by kind.
        known.insert("c".to_string());
        let edges = vec![
            ("a".to_string(), "b".to_string(), "Calls".to_string()),
            // Endpoint is no entity at all: an import of an external crate.
            ("a".to_string(), "outside".to_string(), "Calls".to_string()),
        ];

        let payload = assemble_payload(
            "root".to_string(),
            0,
            metas,
            &known,
            edges,
            &ExportOptions {
                kinds: vec!["function".to_string()],
                ..Default::default()
            },
        );

        assert_eq!(
            payload.nodes.len(),
            1,
            "only the Function survives the filter"
        );
        assert_eq!(
            payload.unresolved_links, 1,
            "the external endpoint is unresolved, a property of the graph"
        );
        assert_eq!(
            payload.filtered_links, 1,
            "the a->b edge lost its target to the kind filter, a property of this request"
        );
        assert!(payload.links.is_empty());
    }

    /// One graph edge is one edge, however many times the store reported it.
    ///
    /// `read_graph` asks every entity for its relations, so an edge between two
    /// entities comes back twice, once from each end. Counting withheld edges
    /// before collapsing that pair reported a single dropped edge as two, which
    /// is how a consumer would have been told a filtered export hid twice as
    /// much of the graph as it did.
    #[test]
    fn an_edge_reported_from_both_ends_is_one_edge() {
        let metas = vec![
            meta("a", "alpha", "Function", Some("src/a.rs")),
            meta("b", "beta", "Function", Some("vendor/b.rs")),
        ];
        let known = all_ids(&metas);
        // Exactly what the store hands back: the same edge, from each end.
        let edges = vec![
            ("a".to_string(), "b".to_string(), "Calls".to_string()),
            ("b".to_string(), "a".to_string(), "Calls".to_string()),
        ];

        let drawn = assemble_payload(
            "root".to_string(),
            0,
            metas.clone(),
            &known,
            edges.clone(),
            &ExportOptions::default(),
        );
        assert_eq!(drawn.links.len(), 1, "one edge draws one line");
        assert_eq!(drawn.relation_count, 1);
        assert_eq!(drawn.nodes[0].degree, 1, "and counts once toward degree");

        let filtered = assemble_payload(
            "root".to_string(),
            0,
            metas,
            &known,
            edges,
            &ExportOptions {
                path_prefix: Some("src/".to_string()),
                ..Default::default()
            },
        );
        assert_eq!(
            filtered.filtered_links, 1,
            "and is withheld once, not once per end"
        );
    }

    /// The default payload carries exactly the fields the existing renderers
    /// read, and nothing that would grow it for no drawn pixel.
    #[test]
    fn optional_fields_are_absent_until_asked_for() {
        let metas = vec![meta("a", "alpha", "Function", Some("src/a.rs"))];
        let known = all_ids(&metas);

        let plain = assemble_payload(
            "root".to_string(),
            0,
            metas.clone(),
            &known,
            Vec::new(),
            &ExportOptions::default(),
        );
        assert_eq!(plain.nodes[0].line, None);
        assert_eq!(plain.nodes[0].signature, None);
        let json = serde_json::to_string(&plain.nodes[0]).unwrap();
        assert!(
            !json.contains("line"),
            "an absent field is not on the wire: {json}"
        );
        assert!(
            !json.contains("signature"),
            "an absent field is not on the wire: {json}"
        );

        let rich = assemble_payload(
            "root".to_string(),
            0,
            metas,
            &known,
            Vec::new(),
            &ExportOptions {
                include: IncludeFields::parse("signature,line"),
                ..Default::default()
            },
        );
        assert_eq!(rich.nodes[0].line, Some(7));
        assert_eq!(rich.nodes[0].signature.as_deref(), Some("fn alpha()"));
    }

    /// An unknown `include` name is ignored rather than refused, so a newer
    /// client naming a field this build does not have still gets its export.
    #[test]
    fn an_unknown_include_name_is_ignored() {
        let fields = IncludeFields::parse("signature,embedding,LINE");
        assert!(fields.signature);
        assert!(fields.line);
    }

    /// `kinds` matches whichever spelling the caller typed.
    #[test]
    fn a_kind_filter_matches_every_spelling_of_the_name() {
        for spelling in ["TraitDef", "trait_def", "traitdef", " TRAIT-DEF "] {
            let metas = vec![meta("a", "alpha", "TraitDef", Some("src/a.rs"))];
            let known = all_ids(&metas);
            let payload = assemble_payload(
                "root".to_string(),
                0,
                metas,
                &known,
                Vec::new(),
                &ExportOptions {
                    kinds: parse_kinds(spelling),
                    ..Default::default()
                },
            );
            assert_eq!(
                payload.nodes.len(),
                1,
                "{spelling} must select the TraitDef"
            );
        }
    }

    /// A cap that nothing exceeded is not a sample, and says so.
    #[test]
    fn an_uncrossed_cap_reports_a_complete_export() {
        let metas = vec![meta("a", "alpha", "Function", Some("src/a.rs"))];
        let known = all_ids(&metas);
        let payload = assemble_payload(
            "root".to_string(),
            0,
            metas,
            &known,
            Vec::new(),
            &ExportOptions {
                limit: Some(50),
                ..Default::default()
            },
        );
        assert!(!payload.sampled);
        assert_eq!(payload.entity_count, 1);
        assert_eq!(payload.nodes.len(), 1);
    }

    /// A caller asking for the whole graph and a caller naming no cap are
    /// opposite requests, and the query string has to keep them apart.
    #[test]
    fn an_explicit_zero_limit_reaches_the_daemon_as_a_value() {
        let whole = export_query_string(&ExportArgs {
            limit: Some(0),
            ..Default::default()
        });
        assert_eq!(whole, "limit=0");

        let defaulted = export_query_string(&ExportArgs::default());
        assert_eq!(defaulted, "", "naming no cap sends no parameter");
    }

    /// A path prefix holding a separator survives the trip.
    #[test]
    fn query_parameters_are_percent_encoded() {
        let query = export_query_string(&ExportArgs {
            path: Some("src/a b&c".to_string()),
            include: Some("line".to_string()),
            ..Default::default()
        });
        assert_eq!(query, "path=src%2Fa%20b%26c&include=line");
    }

    /// An SSE frame that arrived split across two reads is still one event.
    #[test]
    fn a_frame_split_across_reads_is_reassembled() {
        let mut buffer = String::new();
        buffer.push_str("data: {\"type\":\"EntityCha");
        assert!(
            drain_sse_frames(&mut buffer).is_empty(),
            "half a frame is not an event"
        );
        buffer.push_str("nged\"}\n\n: heartbeat\n\ndata: {\"type\":\"RelationChanged\"}\n\n");
        let frames = drain_sse_frames(&mut buffer);
        assert_eq!(
            frames,
            vec![
                "{\"type\":\"EntityChanged\"}".to_string(),
                "{\"type\":\"RelationChanged\"}".to_string()
            ],
            "the heartbeat comment carries no payload and is not an event"
        );
        assert!(buffer.is_empty());
    }

    /// A watch prints something for an event type this build does not know,
    /// rather than swallowing it.
    #[test]
    fn an_unknown_event_type_is_printed_rather_than_dropped() {
        let raw = r#"{"type":"SomethingNewer","detail":42}"#;
        assert_eq!(watch_human_line(raw), raw);
    }
}
