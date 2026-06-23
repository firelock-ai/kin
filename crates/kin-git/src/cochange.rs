// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use std::collections::{BTreeSet, HashMap, HashSet};
use std::fmt::Display;
use std::path::Path;

use kin_model::{
    Entity, EntityFilter, EntityId, EntityStore, FilePathId, Relation, RelationId, RelationKind,
    RelationOrigin, SemanticChange,
};
use rayon::prelude::*;
use sha2::{Digest, Sha256};

use crate::error::{GitError, Result};
use crate::genesis::is_genesis_change;
use crate::import::commit_file_deltas;

const MAX_ENTITIES_PER_FILE: usize = 8;

fn cochange_env_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(default)
}

/// Select up to `max_commits` commit ids by a deterministic total order
/// (commit time descending, then id ascending).
///
/// A `ByCommitTime` walk orders commits by time but leaves the order among
/// equal-timestamp commits unspecified and process-dependent, so truncating the
/// raw walk with `take(max_commits)` can select a different boundary set on each
/// run. That shifts per-pair co-change counts — and therefore the `confidence`
/// folded into each relation's content hash — making the mined graph
/// non-deterministic. Sorting by the id tie-break before truncating makes the
/// selected set independent of the walk's emission order.
fn select_commit_oids<Id: Ord>(mut timed: Vec<(i64, Id)>, max_commits: usize) -> Vec<Id> {
    timed.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    if max_commits > 0 {
        timed.truncate(max_commits);
    }
    timed.into_iter().map(|(_, id)| id).collect()
}

pub fn mine_from_change_dag<G>(graph: &G, changes: &[SemanticChange]) -> Result<Vec<Relation>>
where
    G: EntityStore + Sync,
    G::Error: Display,
{
    let _span = tracing::info_span!(
        "kin.git.cochange.mine_from_change_dag",
        changes = changes.len()
    )
    .entered();
    let max_files_per_commit = cochange_env_usize("KIN_COCHANGE_MAX_FILES_PER_COMMIT", 20);
    let change_sets = {
        let _span = tracing::info_span!("kin.git.cochange.collect_change_sets").entered();
        changes
            .iter()
            .filter(|change| !is_genesis_change(change))
            .map(changed_files_from_change)
            .filter(|files| files.len() >= 2 && files.len() <= max_files_per_commit)
            .collect::<Vec<_>>()
    };
    build_relations_from_change_sets(graph, &change_sets)
}

fn open_repo(path: &Path) -> std::result::Result<gix::Repository, gix::open::Error> {
    let dot_git = path.join(".git");
    if dot_git.is_dir() {
        gix::open(dot_git)
    } else {
        gix::open(path)
    }
}

pub fn mine_from_git_log<G>(repo_path: &Path, graph: &G) -> Result<Vec<Relation>>
where
    G: EntityStore + Sync,
    G::Error: Display,
{
    mine_from_git_log_with_limit(repo_path, graph, 0)
}

pub fn mine_from_git_log_with_limit<G>(
    repo_path: &Path,
    graph: &G,
    max_commits: usize,
) -> Result<Vec<Relation>>
where
    G: EntityStore + Sync,
    G::Error: Display,
{
    let _span = tracing::info_span!(
        "kin.git.cochange.mine_from_git_log",
        repo = %repo_path.display(),
        max_commits = max_commits
    )
    .entered();
    let repo = open_repo(repo_path).map_err(|e| GitError::Git(e.to_string()))?;
    let head_id = match repo.head_ref() {
        Ok(Some(head)) => head.id().detach(),
        Ok(None) => {
            // Detached HEAD — resolve via head_id() instead
            match repo.head_id() {
                Ok(id) => id.detach(),
                Err(_) => return Ok(Vec::new()),
            }
        }
        Err(err) => return Err(GitError::Git(err.to_string())),
    };
    let walk = repo
        .rev_walk([head_id])
        .sorting(gix::revision::walk::Sorting::ByCommitTime(
            Default::default(),
        ))
        .all()
        .map_err(|e| GitError::Git(e.to_string()))?;

    // Phase 1: Collect (commit time, OID) for the full walk, then truncate to
    // max_commits under a deterministic total order — see `select_commit_oids`.
    let oids: Vec<gix::ObjectId> = {
        let _span = tracing::info_span!("kin.git.cochange.collect_oids").entered();
        let timed: Vec<(i64, gix::ObjectId)> = walk
            .map(|r| {
                r.map(|info| (info.commit_time.unwrap_or(0), info.id().detach()))
                    .map_err(|e| GitError::Git(e.to_string()))
            })
            .collect::<Result<Vec<_>>>()?;
        select_commit_oids(timed, max_commits)
    };

    // Phase 2: Parallel tree diffs — propagate object/diff errors
    let max_files_per_commit = cochange_env_usize("KIN_COCHANGE_MAX_FILES_PER_COMMIT", 20);
    let thread_safe = repo.into_sync();
    let change_sets: Vec<BTreeSet<String>> = {
        let _span =
            tracing::info_span!("kin.git.cochange.diff_commits", commits = oids.len()).entered();
        oids.par_iter()
            .map(|oid| {
                let local = thread_safe.to_thread_local();
                let commit = local
                    .find_object(*oid)
                    .map_err(|e| GitError::Git(e.to_string()))?
                    .into_commit();
                let files = commit_file_deltas(&local, &commit)?
                    .into_iter()
                    .map(|d| d.path)
                    .collect::<BTreeSet<_>>();
                Ok(files)
            })
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .filter(|files| files.len() >= 2 && files.len() <= max_files_per_commit)
            .collect()
    };

    build_relations_from_change_sets(graph, &change_sets)
}

fn changed_files_from_change(change: &SemanticChange) -> BTreeSet<String> {
    change
        .artifact_deltas
        .iter()
        .map(|delta| delta.file_id.0.clone())
        .collect()
}

fn build_relations_from_change_sets<G>(
    graph: &G,
    change_sets: &[BTreeSet<String>],
) -> Result<Vec<Relation>>
where
    G: EntityStore + Sync,
    G::Error: Display,
{
    let _span = tracing::info_span!(
        "kin.git.cochange.build_relations_from_change_sets",
        change_sets = change_sets.len()
    )
    .entered();
    let (touch_counts, pair_counts) = {
        let _span = tracing::info_span!("kin.git.cochange.count_pairs").entered();
        // Intern file paths to dense u32 indices once, then key the hot pairwise
        // counting loop on Copy integers instead of cloning two Strings per
        // ordered pair. On a deep change-DAG the old String-keyed loop allocated
        // O(commits x files^2) short-lived Strings (the scoped-session set_scope
        // hotspot); interning moves that to one owned String per UNIQUE
        // file/pair at materialization. The per-key counts are identical, so the
        // mined relations are byte-for-byte unchanged.
        let mut interner: HashMap<&str, u32> = HashMap::new();
        let mut file_names: Vec<&str> = Vec::new();
        for files in change_sets {
            for file in files {
                if !interner.contains_key(file.as_str()) {
                    interner.insert(file.as_str(), file_names.len() as u32);
                    file_names.push(file.as_str());
                }
            }
        }
        let indexed_sets: Vec<Vec<u32>> = change_sets
            .iter()
            .map(|files| files.iter().map(|file| interner[file.as_str()]).collect())
            .collect();

        let (touch_idx, pair_idx) = indexed_sets
            .par_iter()
            .fold(
                || {
                    (
                        HashMap::<u32, usize>::new(),
                        HashMap::<(u32, u32), usize>::new(),
                    )
                },
                |(mut tc, mut pc), files| {
                    for &file in files {
                        *tc.entry(file).or_default() += 1;
                    }
                    for &src in files {
                        for &dst in files {
                            if src != dst {
                                *pc.entry((src, dst)).or_default() += 1;
                            }
                        }
                    }
                    (tc, pc)
                },
            )
            .reduce(
                || (HashMap::new(), HashMap::new()),
                |(mut tc1, mut pc1), (tc2, pc2)| {
                    for (k, v) in tc2 {
                        *tc1.entry(k).or_default() += v;
                    }
                    for (k, v) in pc2 {
                        *pc1.entry(k).or_default() += v;
                    }
                    (tc1, pc1)
                },
            );

        // Re-key back to owned Strings for the (unchanged) downstream logic —
        // one allocation per unique file / unique pair, not per commit-pair.
        let touch_counts: HashMap<String, usize> = touch_idx
            .into_iter()
            .map(|(idx, count)| (file_names[idx as usize].to_string(), count))
            .collect();
        let pair_counts: HashMap<(String, String), usize> = pair_idx
            .into_iter()
            .map(|((src, dst), count)| {
                (
                    (
                        file_names[src as usize].to_string(),
                        file_names[dst as usize].to_string(),
                    ),
                    count,
                )
            })
            .collect();
        (touch_counts, pair_counts)
    };

    // Pre-populate entity cache in parallel
    let unique_files: HashSet<String> = pair_counts
        .keys()
        .flat_map(|(s, d)| [s.clone(), d.clone()])
        .collect();

    let entity_cache: HashMap<String, Vec<Entity>> = {
        let _span = tracing::info_span!(
            "kin.git.cochange.preload_entity_cache",
            files = unique_files.len()
        )
        .entered();
        unique_files
            .into_par_iter()
            .map(|file| {
                let filter = EntityFilter {
                    file_path: Some(FilePathId::new(&file)),
                    ..Default::default()
                };
                let mut entities = graph
                    .query_entities(&filter)
                    .map_err(|e| GitError::Graph(e.to_string()))?;
                entities.sort_by(|a, b| {
                    a.lineage_parent
                        .is_some()
                        .cmp(&b.lineage_parent.is_some())
                        .then_with(|| {
                            a.span
                                .as_ref()
                                .map(|s| s.start_line)
                                .unwrap_or(u32::MAX)
                                .cmp(&b.span.as_ref().map(|s| s.start_line).unwrap_or(u32::MAX))
                        })
                        .then_with(|| a.name.cmp(&b.name))
                });
                if entities.len() > MAX_ENTITIES_PER_FILE {
                    entities.truncate(MAX_ENTITIES_PER_FILE);
                }
                Ok((file, entities))
            })
            .collect::<Result<HashMap<_, _>>>()?
    };

    let mut sorted_pairs = pair_counts.into_iter().collect::<Vec<_>>();
    sorted_pairs.sort_by(|a, b| a.0.cmp(&b.0));

    // Filter out hub files that co-change with too many unique partners
    let max_fan_out = cochange_env_usize("KIN_COCHANGE_MAX_FAN_OUT", 15);
    let mut partner_counts: HashMap<String, HashSet<String>> = HashMap::new();
    for ((src, dst), _count) in &sorted_pairs {
        partner_counts
            .entry(src.clone())
            .or_default()
            .insert(dst.clone());
        partner_counts
            .entry(dst.clone())
            .or_default()
            .insert(src.clone());
    }
    let hub_files: HashSet<String> = partner_counts
        .into_iter()
        .filter(|(_, partners)| partners.len() > max_fan_out)
        .map(|(file, _)| file)
        .collect();
    if !hub_files.is_empty() {
        tracing::info!(
            hub_files = hub_files.len(),
            "cochange: filtered hub files with >{max_fan_out} unique partners"
        );
    }
    sorted_pairs.retain(|((src, dst), _)| !hub_files.contains(src) && !hub_files.contains(dst));

    // Generate each file-pair's co-change relations in parallel. The per-pair
    // SHA256 relation-id + struct construction over up to MAX_ENTITIES_PER_FILE^2
    // entity pairs is the dominant cost of mining a deep change-DAG (the
    // scoped-session set_scope re-mine); the count/preload phases are cheap
    // by comparison. rayon's indexed collect preserves `sorted_pairs` order, and
    // each ordered entity-pair belongs to exactly one file-pair (an entity has a
    // single file origin), so the sequential first-wins dedup pass below
    // reproduces the previous sequential output byte-for-byte.
    let per_pair: Vec<Vec<Relation>> = {
        let _span = tracing::info_span!(
            "kin.git.cochange.materialize_relations",
            pairs = sorted_pairs.len()
        )
        .entered();
        sorted_pairs
            .par_iter()
            .map(|((src_file, dst_file), pair_count)| {
                let mut out = Vec::new();
                let Some(src_touch_count) = touch_counts.get(src_file).copied() else {
                    return out;
                };
                if src_touch_count == 0 {
                    return out;
                }
                let (Some(src_entities), Some(dst_entities)) =
                    (entity_cache.get(src_file), entity_cache.get(dst_file))
                else {
                    return out;
                };
                if src_entities.is_empty() || dst_entities.is_empty() {
                    return out;
                }
                let confidence = *pair_count as f32 / src_touch_count as f32;
                for src_entity in src_entities {
                    for dst_entity in dst_entities {
                        if src_entity.id == dst_entity.id {
                            continue;
                        }
                        out.push(Relation {
                            id: cochange_relation_id(src_entity.id, dst_entity.id),
                            kind: RelationKind::CoChanges,
                            src: kin_model::GraphNodeId::Entity(src_entity.id),
                            dst: kin_model::GraphNodeId::Entity(dst_entity.id),
                            confidence,
                            origin: RelationOrigin::Inferred,
                            created_in: None,
                            import_source: None,
                            evidence: Vec::new(),
                        });
                    }
                }
                out
            })
            .collect()
    };

    // Sequential first-wins dedup preserving the original ordering (a safety net:
    // ordered entity-pairs are already unique across file-pairs).
    let mut seen_relation_ids = HashSet::new();
    let mut relations = Vec::with_capacity(per_pair.iter().map(Vec::len).sum());
    for pair_relations in per_pair {
        for relation in pair_relations {
            if seen_relation_ids.insert(relation.id) {
                relations.push(relation);
            }
        }
    }

    Ok(relations)
}

fn cochange_relation_id(src: EntityId, dst: EntityId) -> RelationId {
    let mut hasher = Sha256::new();
    hasher.update(b"kin-cochange-v1:");
    hasher.update(src.0.as_bytes());
    hasher.update(dst.0.as_bytes());
    let digest = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    RelationId::from_bytes(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{
        ArtifactDelta, ArtifactDeltaKind, EntityKind, EntityMetadata, EntityRole,
        FingerprintAlgorithm, GraphNodeId, Hash256, LanguageId, SemanticFingerprint, SourceSpan,
        Visibility,
    };
    use std::process::Command;

    #[test]
    fn select_commit_oids_is_input_order_independent_at_tie_boundary() {
        // A commit-time tie (t=100) straddles the max_commits cutoff. The
        // selected set must depend only on (time desc, id asc), never on the
        // walk's (process-dependent) emission order for the tied commits.
        let base: Vec<(i64, u32)> = vec![
            (300, 0x10),
            (200, 0x20),
            (100, 0x05),
            (100, 0x03),
            (100, 0x09),
            (50, 0x40),
        ];
        let max = 4;
        let expected = select_commit_oids(base.clone(), max);
        // Top two by time, then the two smallest ids within the t=100 tie group.
        assert_eq!(expected, vec![0x10u32, 0x20, 0x03, 0x05]);

        let shuffles: Vec<Vec<(i64, u32)>> = vec![
            base.iter().rev().copied().collect(),
            vec![
                (100, 0x09),
                (300, 0x10),
                (100, 0x03),
                (50, 0x40),
                (200, 0x20),
                (100, 0x05),
            ],
            vec![
                (100, 0x05),
                (100, 0x03),
                (100, 0x09),
                (200, 0x20),
                (300, 0x10),
                (50, 0x40),
            ],
        ];
        for s in shuffles {
            assert_eq!(
                select_commit_oids(s, max),
                expected,
                "truncated commit set must be independent of walk emission order"
            );
        }

        // max_commits == 0 keeps all commits, still in deterministic total order.
        assert_eq!(
            select_commit_oids(base, 0),
            vec![0x10u32, 0x20, 0x03, 0x05, 0x09, 0x40]
        );
    }

    fn test_entity(name: &str, path: &str, line: u32) -> kin_model::Entity {
        kin_model::Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0; 32]),
                signature_hash: Hash256::from_bytes([1; 32]),
                behavior_hash: Hash256::from_bytes([2; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new(path)),
            span: Some(SourceSpan {
                file: FilePathId::new(path),
                start_byte: 0,
                end_byte: 0,
                start_line: line,
                start_col: 1,
                end_line: line,
                end_col: 20,
            }),
            signature: format!("fn {name}()"),
            visibility: Visibility::Public,
            role: EntityRole::Source,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    fn init_git_repo(dir: &std::path::Path) -> bool {
        let git_init = Command::new("git").args(["init"]).current_dir(dir).output();
        match git_init {
            Ok(output) if output.status.success() => {
                let _ = Command::new("git")
                    .args(["config", "user.email", "test@test.com"])
                    .current_dir(dir)
                    .output();
                let _ = Command::new("git")
                    .args(["config", "user.name", "Test"])
                    .current_dir(dir)
                    .output();
                true
            }
            _ => false,
        }
    }

    /// Build a synthetic change-DAG: `num_commits` changes over `num_files`
    /// files, each commit touching `files_per_commit` files chosen by a
    /// deterministic LCG (no wall-clock / RNG, so the DAG is reproducible). Also
    /// registers one entity per file in `graph` so co-change relations
    /// materialize. Returns the change vector.
    fn synthetic_change_dag(
        graph: &kin_db::InMemoryGraph,
        num_commits: usize,
        num_files: usize,
        files_per_commit: usize,
        seed: u64,
    ) -> Vec<SemanticChange> {
        for i in 0..num_files {
            let path = format!("src/f{i}.rs");
            graph
                .upsert_entity(&test_entity(&format!("fn_{i}"), &path, 1))
                .unwrap();
        }
        synthetic_change_dag_no_entities(num_commits, num_files, files_per_commit, seed)
    }

    /// Build the change vector only (caller registers entities). Same windowed
    /// file selection as `synthetic_change_dag`.
    fn synthetic_change_dag_no_entities(
        num_commits: usize,
        num_files: usize,
        files_per_commit: usize,
        seed: u64,
    ) -> Vec<SemanticChange> {
        let mut state = seed | 1;
        let mut next = || {
            // xorshift64* — deterministic, no external RNG.
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
            state.wrapping_mul(0x2545F4914F6CDD1D)
        };
        let mut changes = Vec::with_capacity(num_commits);
        let mut parent: Option<kin_model::SemanticChangeId> = None;
        for c in 0..num_commits {
            // Touch a contiguous window of files starting at a random base, so
            // each file co-changes only with nearby neighbours (bounded fan-out,
            // like files in one module) — otherwise the hub-file filter
            // (KIN_COCHANGE_MAX_FAN_OUT) prunes everything.
            let base = (next() as usize) % num_files;
            let mut files = std::collections::BTreeSet::new();
            for k in 0..files_per_commit {
                files.insert((base + k) % num_files);
            }
            let artifact_deltas = files
                .iter()
                .map(|&f| ArtifactDelta {
                    file_id: FilePathId::new(format!("src/f{f}.rs")),
                    kind: ArtifactDeltaKind::Modified,
                    old_hash: None,
                    new_hash: None,
                })
                .collect();
            let mut id_bytes = [0u8; 32];
            id_bytes[..8].copy_from_slice(&(c as u64 + 1).to_le_bytes());
            let id = kin_model::SemanticChangeId::from_hash(Hash256::from_bytes(id_bytes));
            changes.push(SemanticChange {
                id,
                parents: parent.into_iter().collect(),
                timestamp: kin_model::Timestamp::now(),
                author: kin_model::AuthorId::new("test"),
                message: format!("c{c}"),
                entity_deltas: vec![],
                relation_deltas: vec![],
                artifact_deltas,
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            });
            parent = Some(id);
        }
        changes
    }

    /// Regression guard: mining is deterministic and stable. The interning
    /// optimization must leave the mined relation set byte-identical;
    /// this locks that by asserting two runs over the same synthetic DAG produce
    /// the exact same sorted (src, dst, confidence) set.
    #[test]
    fn change_dag_mining_is_deterministic() {
        let graph = kin_db::InMemoryGraph::new();
        let changes = synthetic_change_dag(&graph, 800, 60, 4, 0xC0FFEE);

        let mut a = mine_from_change_dag(&graph, &changes).unwrap();
        let mut b = mine_from_change_dag(&graph, &changes).unwrap();
        let key = |r: &Relation| format!("{:?}->{:?}@{}", r.src, r.dst, r.confidence.to_bits());
        a.sort_by_key(key);
        b.sort_by_key(key);
        assert!(
            !a.is_empty(),
            "synthetic DAG should yield co-change relations"
        );
        assert_eq!(a.len(), b.len(), "mining must be deterministic");
        for (x, y) in a.iter().zip(b.iter()) {
            assert_eq!(key(x), key(y), "mined relation set must be stable");
        }
    }

    /// Manual timing harness for the interning hotspot (the `set_scope` per-task
    /// cochange re-mine over a deep ancestry). Ignored by default — run with
    /// `cargo test -p kin-git change_dag_mining_deep_timing -- --ignored --nocapture`.
    ///
    /// Mines a deep synthetic DAG via both a naive String-keyed pair counter
    /// (the pre-interning shape) and the production interned path, asserts they
    /// produce identical pair counts, and prints both wall-clocks so the
    /// allocation win is visible.
    #[test]
    #[ignore = "timing harness; run explicitly with --ignored --nocapture"]
    fn change_dag_mining_deep_timing() {
        // Stress BOTH axes: deep ancestry (commits) AND a large graph (many
        // files x entities), so the per-file `query_entities` preload cost is
        // visible — a tiny graph hides it.
        let graph = kin_db::InMemoryGraph::new();
        let num_commits = 25_000;
        let num_files = 3_000;
        let entities_per_file = 8;
        for f in 0..num_files {
            let path = format!("src/f{f}.rs");
            for e in 0..entities_per_file {
                graph
                    .upsert_entity(&test_entity(&format!("fn_{f}_{e}"), &path, e as u32 + 1))
                    .unwrap();
            }
        }
        let changes = synthetic_change_dag_no_entities(num_commits, num_files, 6, 0xABCDEF);

        let change_sets: Vec<BTreeSet<String>> = changes
            .iter()
            .filter(|c| !is_genesis_change(c))
            .map(changed_files_from_change)
            .filter(|f| f.len() >= 2 && f.len() <= 20)
            .collect();

        // Isolate count_pairs (naive String-keyed, pre-optimization shape).
        let t0 = std::time::Instant::now();
        let mut naive_pairs: HashMap<(String, String), usize> = HashMap::new();
        for files in &change_sets {
            let files: Vec<_> = files.iter().collect();
            for src in &files {
                for dst in &files {
                    if src != dst {
                        *naive_pairs
                            .entry(((**src).clone(), (**dst).clone()))
                            .or_default() += 1;
                    }
                }
            }
        }
        let naive_ms = t0.elapsed().as_millis();

        // Isolate the per-file query_entities preload (the suspected real driver).
        let unique_files: HashSet<String> = naive_pairs
            .keys()
            .flat_map(|(s, d)| [s.clone(), d.clone()])
            .collect();
        let t_pre = std::time::Instant::now();
        let mut preloaded = 0usize;
        for file in &unique_files {
            let filter = EntityFilter {
                file_path: Some(FilePathId::new(file)),
                ..Default::default()
            };
            preloaded += graph.query_entities(&filter).unwrap().len();
        }
        let preload_ms = t_pre.elapsed().as_millis();

        // Full production mine.
        let t1 = std::time::Instant::now();
        let relations = mine_from_change_dag(&graph, &changes).unwrap();
        let prod_ms = t1.elapsed().as_millis();

        eprintln!(
            "[cochange-timing] commits={num_commits} files={num_files} entities={} change_sets={} \
             unique_files={} unique_pairs={} relations={} | count_pairs(naive)={naive_ms}ms \
             preload_query_entities={preload_ms}ms (loaded {preloaded}) full_mine={prod_ms}ms",
            num_files * entities_per_file,
            change_sets.len(),
            unique_files.len(),
            naive_pairs.len(),
            relations.len(),
        );
        assert!(!relations.is_empty());
    }

    #[test]
    fn change_dag_mining_emits_directional_file_scope_relations() {
        let graph = kin_db::InMemoryGraph::new();
        let alpha = test_entity("alpha", "src/a.rs", 1);
        let beta = test_entity("beta", "src/b.rs", 2);
        let gamma = test_entity("gamma", "src/c.rs", 3);
        graph.upsert_entity(&alpha).unwrap();
        graph.upsert_entity(&beta).unwrap();
        graph.upsert_entity(&gamma).unwrap();

        let changes = vec![
            SemanticChange {
                id: kin_model::SemanticChangeId::from_hash(Hash256::from_bytes([1; 32])),
                parents: vec![],
                timestamp: kin_model::Timestamp::now(),
                author: kin_model::AuthorId::new("test"),
                message: "first".into(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                artifact_deltas: vec![
                    ArtifactDelta {
                        file_id: FilePathId::new("src/a.rs"),
                        kind: ArtifactDeltaKind::Modified,
                        old_hash: None,
                        new_hash: None,
                    },
                    ArtifactDelta {
                        file_id: FilePathId::new("src/b.rs"),
                        kind: ArtifactDeltaKind::Modified,
                        old_hash: None,
                        new_hash: None,
                    },
                ],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            },
            SemanticChange {
                id: kin_model::SemanticChangeId::from_hash(Hash256::from_bytes([2; 32])),
                parents: vec![kin_model::SemanticChangeId::from_hash(Hash256::from_bytes(
                    [1; 32],
                ))],
                timestamp: kin_model::Timestamp::now(),
                author: kin_model::AuthorId::new("test"),
                message: "second".into(),
                entity_deltas: vec![],
                relation_deltas: vec![],
                artifact_deltas: vec![
                    ArtifactDelta {
                        file_id: FilePathId::new("src/a.rs"),
                        kind: ArtifactDeltaKind::Modified,
                        old_hash: None,
                        new_hash: None,
                    },
                    ArtifactDelta {
                        file_id: FilePathId::new("src/c.rs"),
                        kind: ArtifactDeltaKind::Modified,
                        old_hash: None,
                        new_hash: None,
                    },
                ],
                projected_files: vec![],
                spec_link: None,
                evidence: vec![],
                risk_summary: None,
                authored_on: None,
            },
        ];

        let relations = mine_from_change_dag(&graph, &changes).unwrap();
        let a_to_b = relations
            .iter()
            .find(|relation| {
                relation.src == GraphNodeId::Entity(alpha.id)
                    && relation.dst == GraphNodeId::Entity(beta.id)
            })
            .unwrap();
        let a_to_c = relations
            .iter()
            .find(|relation| {
                relation.src == GraphNodeId::Entity(alpha.id)
                    && relation.dst == GraphNodeId::Entity(gamma.id)
            })
            .unwrap();
        let b_to_a = relations
            .iter()
            .find(|relation| {
                relation.src == GraphNodeId::Entity(beta.id)
                    && relation.dst == GraphNodeId::Entity(alpha.id)
            })
            .unwrap();

        assert_eq!(a_to_b.kind, RelationKind::CoChanges);
        assert!((a_to_b.confidence - 0.5).abs() < f32::EPSILON);
        assert!((a_to_c.confidence - 0.5).abs() < f32::EPSILON);
        assert!((b_to_a.confidence - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn git_log_fallback_uses_real_changed_files() {
        let dir = tempfile::tempdir().unwrap();
        if !init_git_repo(dir.path()) {
            eprintln!("git not available, skipping co-change git fallback test");
            return;
        }

        std::fs::create_dir_all(dir.path().join("src")).unwrap();
        std::fs::write(dir.path().join("src/a.rs"), "fn alpha() {}\n").unwrap();
        std::fs::write(dir.path().join("src/b.rs"), "fn beta() {}\n").unwrap();
        Command::new("git")
            .args(["add", "."])
            .current_dir(dir.path())
            .output()
            .unwrap();
        Command::new("git")
            .args(["commit", "-m", "initial"])
            .current_dir(dir.path())
            .output()
            .unwrap();

        std::fs::write(
            dir.path().join("src/a.rs"),
            "fn alpha() { println!(\"a\"); }\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("src/c.rs"), "fn gamma() {}\n").unwrap();
        Command::new("git")
            .args(["add", "."])
            .current_dir(dir.path())
            .output()
            .unwrap();
        Command::new("git")
            .args(["commit", "-m", "followup"])
            .current_dir(dir.path())
            .output()
            .unwrap();

        let graph = kin_db::InMemoryGraph::new();
        let alpha = test_entity("alpha", "src/a.rs", 1);
        let beta = test_entity("beta", "src/b.rs", 2);
        let gamma = test_entity("gamma", "src/c.rs", 3);
        graph.upsert_entity(&alpha).unwrap();
        graph.upsert_entity(&beta).unwrap();
        graph.upsert_entity(&gamma).unwrap();

        let relations = mine_from_git_log(dir.path(), &graph).unwrap();
        assert!(relations.iter().any(|relation| {
            relation.src == GraphNodeId::Entity(alpha.id)
                && relation.dst == GraphNodeId::Entity(beta.id)
        }));
        assert!(relations.iter().any(|relation| {
            relation.src == GraphNodeId::Entity(alpha.id)
                && relation.dst == GraphNodeId::Entity(gamma.id)
        }));
        assert!(!relations.iter().any(|relation| {
            relation.src == GraphNodeId::Entity(beta.id)
                && relation.dst == GraphNodeId::Entity(gamma.id)
        }));
    }

    #[test]
    fn git_log_limit_restricts_cochange_to_recent_commits() {
        let dir = tempfile::tempdir().unwrap();
        if !init_git_repo(dir.path()) {
            eprintln!("git not available, skipping co-change git limit test");
            return;
        }

        std::fs::create_dir_all(dir.path().join("src")).unwrap();
        std::fs::write(dir.path().join("src/a.rs"), "fn alpha() {}\n").unwrap();
        std::fs::write(dir.path().join("src/b.rs"), "fn beta() {}\n").unwrap();
        Command::new("git")
            .args(["add", "."])
            .current_dir(dir.path())
            .output()
            .unwrap();
        Command::new("git")
            .args(["commit", "-m", "initial"])
            .current_dir(dir.path())
            .output()
            .unwrap();

        std::fs::write(dir.path().join("src/c.rs"), "fn gamma() {}\n").unwrap();
        Command::new("git")
            .args(["add", "."])
            .current_dir(dir.path())
            .output()
            .unwrap();
        Command::new("git")
            .args(["commit", "-m", "middle"])
            .current_dir(dir.path())
            .output()
            .unwrap();

        std::fs::write(
            dir.path().join("src/a.rs"),
            "fn alpha() { println!(\"latest\"); }\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("src/d.rs"), "fn delta() {}\n").unwrap();
        Command::new("git")
            .args(["add", "."])
            .current_dir(dir.path())
            .output()
            .unwrap();
        Command::new("git")
            .args(["commit", "-m", "latest"])
            .current_dir(dir.path())
            .output()
            .unwrap();

        let graph = kin_db::InMemoryGraph::new();
        let alpha = test_entity("alpha", "src/a.rs", 1);
        let beta = test_entity("beta", "src/b.rs", 2);
        let gamma = test_entity("gamma", "src/c.rs", 3);
        let delta = test_entity("delta", "src/d.rs", 4);
        graph.upsert_entity(&alpha).unwrap();
        graph.upsert_entity(&beta).unwrap();
        graph.upsert_entity(&gamma).unwrap();
        graph.upsert_entity(&delta).unwrap();

        let relations = mine_from_git_log_with_limit(dir.path(), &graph, 1).unwrap();
        assert!(relations.iter().any(|relation| {
            relation.src == GraphNodeId::Entity(alpha.id)
                && relation.dst == GraphNodeId::Entity(delta.id)
        }));
        assert!(!relations.iter().any(|relation| {
            relation.src == GraphNodeId::Entity(alpha.id)
                && relation.dst == GraphNodeId::Entity(beta.id)
        }));
        assert!(!relations.iter().any(|relation| {
            relation.src == GraphNodeId::Entity(alpha.id)
                && relation.dst == GraphNodeId::Entity(gamma.id)
        }));
    }
}
