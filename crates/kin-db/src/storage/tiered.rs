// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use memmap2::Mmap;
use parking_lot::RwLock;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::engine::InMemoryGraph;
use crate::error::KinDbError;
use crate::storage::format::GraphSnapshot;
use crate::storage::mmap;
use crate::store::GraphStore;
use crate::types::*;

/// System memory information used to configure tier sizes.
#[derive(Debug, Clone, Copy)]
pub struct SystemMemInfo {
    /// Total physical RAM in bytes.
    pub total_ram: u64,
    /// Available (free + reclaimable) RAM in bytes.
    pub available_ram: u64,
}

impl SystemMemInfo {
    /// Detect current system memory using sysinfo.
    pub fn detect() -> Self {
        use sysinfo::System;
        let sys = System::new_with_specifics(
            sysinfo::RefreshKind::nothing().with_memory(sysinfo::MemoryRefreshKind::everything()),
        );
        Self {
            total_ram: sys.total_memory(),
            available_ram: sys.available_memory(),
        }
    }
}

/// Configuration for the tiered storage engine.
#[derive(Debug, Clone)]
pub struct TieredConfig {
    /// Maximum bytes for the hot (in-memory) tier.
    /// If None, auto-detected from available RAM (50% of free).
    pub max_hot_bytes: Option<usize>,
    /// Estimated bytes per entity (used for capacity decisions).
    /// Default: 200 bytes (conservative for typical code entities).
    pub bytes_per_entity: usize,
}

impl Default for TieredConfig {
    fn default() -> Self {
        Self {
            max_hot_bytes: None,
            bytes_per_entity: 200,
        }
    }
}

impl TieredConfig {
    /// Compute the effective hot tier budget in bytes.
    pub fn effective_hot_bytes(&self) -> usize {
        self.max_hot_bytes.unwrap_or_else(|| {
            let info = SystemMemInfo::detect();
            // Use 50% of available RAM for the hot tier
            (info.available_ram / 2) as usize
        })
    }

    /// How many entities fit in the hot tier?
    pub fn hot_capacity(&self) -> usize {
        self.effective_hot_bytes() / self.bytes_per_entity
    }
}

/// Strategy for loading graph data based on available memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadStrategy {
    /// Graph fits in memory — load everything into InMemoryGraph.
    FullLoad,
    /// Graph too large — keep mmap open, InMemoryGraph holds hot subset.
    MmapBacked,
}

/// Tiered graph storage: hot in-memory tier + cold mmap tier.
///
/// For graphs that fit in RAM, this behaves identically to InMemoryGraph.
/// For oversized graphs, the mmap remains open and the OS page cache
/// transparently pages cold data in/out — no manual eviction needed.
///
/// # How it works
///
/// 1. On open, we check the snapshot file size vs available RAM.
/// 2. If it fits (< 50% of free RAM), we fully deserialize into InMemoryGraph.
/// 3. If it doesn't fit, we keep the mmap open. The OS virtual memory subsystem
///    acts as our tiering engine — recently accessed pages stay in RAM,
///    cold pages get evicted to disk automatically.
///
/// The key insight: mmap + OS page cache IS memory/disk tiering.
/// We don't need a separate eviction policy — the kernel already has one.
pub struct TieredGraph {
    /// Hot tier: in-memory graph for fast indexed access.
    hot: Arc<InMemoryGraph>,
    /// Cold tier: memory-mapped snapshot file (if graph exceeds hot budget).
    /// The Mmap is kept alive so the OS can page data in/out.
    _cold_mmap: RwLock<Option<Mmap>>,
    /// The deserialized cold snapshot (lazily loaded from mmap).
    /// This is only populated when strategy is MmapBacked.
    cold_snapshot: RwLock<Option<GraphSnapshot>>,
    /// The hot subset we own authoritatively for mmap-backed save reconciliation.
    managed_scope: RwLock<Option<ManagedHotScope>>,
    /// What strategy was selected.
    strategy: LoadStrategy,
    /// Path to the snapshot file.
    path: PathBuf,
    /// Configuration.
    config: TieredConfig,
    /// System memory info at startup (for diagnostics).
    mem_info: SystemMemInfo,
}

#[derive(Debug, Clone, Default)]
struct ManagedHotScope {
    entity_ids: HashSet<EntityId>,
    relation_ids: HashSet<RelationId>,
    branch_names: HashSet<BranchName>,
}

impl ManagedHotScope {
    fn from_snapshot(snapshot: &GraphSnapshot) -> Self {
        let mut scope = Self::default();
        scope.record_snapshot(snapshot);
        scope
    }

    fn record_snapshot(&mut self, snapshot: &GraphSnapshot) {
        self.entity_ids.extend(snapshot.entities.keys().copied());
        self.relation_ids.extend(snapshot.relations.keys().copied());
        self.branch_names.extend(snapshot.branches.keys().cloned());
    }
}

impl TieredGraph {
    /// Open a tiered graph from a snapshot file.
    ///
    /// Auto-detects available RAM and chooses the appropriate loading strategy.
    pub fn open(path: impl Into<PathBuf>, config: TieredConfig) -> Result<Self, KinDbError> {
        let path = path.into();
        let mem_info = SystemMemInfo::detect();
        ensure_recoverable_snapshot_file(&path)?;

        if !path.exists() {
            // No snapshot file — start with an empty graph
            return Ok(Self {
                hot: Arc::new(InMemoryGraph::new()),
                _cold_mmap: RwLock::new(None),
                cold_snapshot: RwLock::new(None),
                managed_scope: RwLock::new(None),
                strategy: LoadStrategy::FullLoad,
                path,
                config,
                mem_info,
            });
        }

        // Check file size to decide strategy
        let file_size = std::fs::metadata(&path)
            .map_err(|e| {
                KinDbError::StorageError(format!("failed to stat {}: {e}", path.display()))
            })?
            .len();

        let hot_budget = config.effective_hot_bytes() as u64;

        // Heuristic: the deserialized graph is ~2-4x larger than the JSON on disk.
        // Use 4x as a conservative multiplier.
        let estimated_in_memory = file_size * 4;

        if estimated_in_memory <= hot_budget {
            // Fits in memory — full load
            let snapshot = load_snapshot_from_disk(&path)?;
            let graph = hydrate_graph(snapshot);
            Ok(Self {
                hot: Arc::new(graph),
                _cold_mmap: RwLock::new(None),
                cold_snapshot: RwLock::new(None),
                managed_scope: RwLock::new(None),
                strategy: LoadStrategy::FullLoad,
                path,
                config,
                mem_info,
            })
        } else {
            // Too large — use mmap-backed strategy
            let file = File::open(&path).map_err(|e| {
                KinDbError::StorageError(format!("failed to open {}: {e}", path.display()))
            })?;
            let mmap = unsafe {
                Mmap::map(&file).map_err(|e| {
                    KinDbError::StorageError(format!("failed to mmap {}: {e}", path.display()))
                })?
            };

            // Advise the kernel that we'll access this randomly
            #[cfg(unix)]
            {
                mmap.advise(memmap2::Advice::Random).ok();
            }

            // Deserialize the snapshot from the mmap.
            // The OS page cache handles which pages are resident.
            let snapshot = GraphSnapshot::from_bytes(&mmap)?;

            // Load a hot subset into InMemoryGraph for indexed queries.
            // Take the first N entities that fit in our budget.
            let hot_capacity = config.hot_capacity();
            let graph = hydrate_graph_partial(&snapshot, hot_capacity)?;
            let hot_snapshot = graph.to_snapshot();

            Ok(Self {
                hot: Arc::new(graph),
                _cold_mmap: RwLock::new(Some(mmap)),
                cold_snapshot: RwLock::new(Some(snapshot)),
                managed_scope: RwLock::new(Some(ManagedHotScope::from_snapshot(&hot_snapshot))),
                strategy: LoadStrategy::MmapBacked,
                path,
                config,
                mem_info,
            })
        }
    }

    /// Open with default configuration (auto-detect everything).
    pub fn open_auto(path: impl Into<PathBuf>) -> Result<Self, KinDbError> {
        Self::open(path, TieredConfig::default())
    }

    /// Which loading strategy was chosen?
    pub fn strategy(&self) -> LoadStrategy {
        self.strategy
    }

    /// System memory info detected at startup.
    pub fn mem_info(&self) -> &SystemMemInfo {
        &self.mem_info
    }

    /// Get the hot tier graph for direct access.
    pub fn hot_graph(&self) -> &Arc<InMemoryGraph> {
        &self.hot
    }

    /// Number of entities in the hot tier.
    pub fn hot_entity_count(&self) -> usize {
        self.hot.entity_count()
    }

    /// Total number of entities (hot + cold).
    pub fn total_entity_count(&self) -> usize {
        match &*self.cold_snapshot.read() {
            Some(snap) => snap.entities.len(),
            None => self.hot.entity_count(),
        }
    }

    /// Total number of relations (hot + cold).
    pub fn total_relation_count(&self) -> usize {
        match &*self.cold_snapshot.read() {
            Some(snap) => snap.relations.len(),
            None => self.hot.relation_count(),
        }
    }

    /// Look up an entity, checking hot tier first, then cold.
    pub fn get_entity(&self, id: &EntityId) -> Result<Option<Entity>, KinDbError> {
        // Hot path: check in-memory graph first
        if let Some(entity) = self.hot.get_entity(id)? {
            return Ok(Some(entity));
        }

        // Cold path: check mmap-backed snapshot
        if let Some(snap) = self.cold_snapshot.read().as_ref() {
            if let Some(entity) = snap.entities.get(id) {
                return Ok(Some(entity.clone()));
            }
        }

        Ok(None)
    }

    /// Look up a relation by ID, checking cold snapshot directly.
    /// (The GraphStore trait has no single-relation getter, so this
    /// is only available when using TieredGraph directly.)
    pub fn get_relation_by_id(&self, id: &RelationId) -> Option<Relation> {
        if let Some(snap) = self.cold_snapshot.read().as_ref() {
            snap.relations.get(id).cloned()
        } else {
            // FullLoad mode — no cold snapshot, relations are in hot tier.
            // We'd need to scan all entities' relations, which is expensive.
            // For FullLoad, callers should use get_relations() on the hot graph.
            None
        }
    }

    /// Get outgoing relations for an entity from both tiers.
    pub fn get_relations(
        &self,
        entity_id: &EntityId,
        kinds: &[RelationKind],
    ) -> Result<Vec<Relation>, KinDbError> {
        let mut results = self.hot.get_relations(entity_id, kinds)?;

        // Check cold tier for additional relations
        if let Some(snap) = self.cold_snapshot.read().as_ref() {
            if let Some(rel_ids) = snap.outgoing.get(entity_id) {
                for rel_id in rel_ids {
                    // Skip if already in hot results
                    if results.iter().any(|r| r.id == *rel_id) {
                        continue;
                    }
                    if let Some(rel) = snap.relations.get(rel_id) {
                        if kinds.is_empty() || kinds.contains(&rel.kind) {
                            results.push(rel.clone());
                        }
                    }
                }
            }
        }

        Ok(results)
    }

    /// Search entities by name pattern across both tiers.
    pub fn query_entities_by_name(&self, pattern: &str) -> Result<Vec<Entity>, KinDbError> {
        let filter = EntityFilter {
            name_pattern: Some(pattern.to_string()),
            ..Default::default()
        };
        let mut results = self.hot.query_entities(&filter)?;

        // Also search cold tier
        if let Some(snap) = self.cold_snapshot.read().as_ref() {
            let pattern_lower = pattern.to_lowercase();
            for entity in snap.entities.values() {
                if entity.name.to_lowercase().contains(&pattern_lower) {
                    // Skip duplicates from hot tier
                    if !results.iter().any(|e| e.id == entity.id) {
                        results.push(entity.clone());
                    }
                }
            }
        }

        Ok(results)
    }

    /// Get the snapshot file path.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Save the current hot graph to disk atomically.
    ///
    /// For MmapBacked strategy, this merges hot changes with cold data
    /// before writing.
    pub fn save(&self) -> Result<(), KinDbError> {
        let hot_snapshot = self.hot.to_snapshot();
        let snapshot = if self.strategy == LoadStrategy::MmapBacked {
            let cold = load_snapshot_from_disk(&self.path)?;
            let scope = self
                .managed_scope
                .read()
                .clone()
                .unwrap_or_else(|| ManagedHotScope::from_snapshot(&hot_snapshot));
            merge_hot_into_cold(cold, hot_snapshot.clone(), &scope)
        } else {
            hot_snapshot.clone()
        };

        // Ensure parent directory exists
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                KinDbError::StorageError(format!(
                    "failed to create directory {}: {e}",
                    parent.display()
                ))
            })?;
        }

        mmap::atomic_write(&self.path, &snapshot)?;

        if self.strategy == LoadStrategy::MmapBacked {
            self.refresh_cold_state()?;
            let mut scope = self.managed_scope.write();
            scope
                .get_or_insert_with(ManagedHotScope::default)
                .record_snapshot(&hot_snapshot);
        }

        Ok(())
    }

    fn refresh_cold_state(&self) -> Result<(), KinDbError> {
        let (mmap, snapshot) = mmap_snapshot_file(&self.path)?;
        *self._cold_mmap.write() = Some(mmap);
        *self.cold_snapshot.write() = Some(snapshot);
        Ok(())
    }
}

/// Hydrate a full InMemoryGraph from a snapshot.
fn hydrate_graph(snapshot: GraphSnapshot) -> InMemoryGraph {
    InMemoryGraph::from_snapshot(snapshot)
}

/// Hydrate a partial InMemoryGraph with at most `max_entities` entities.
///
/// Loads entities and their connected relations up to the capacity limit.
fn hydrate_graph_partial(
    snapshot: &GraphSnapshot,
    max_entities: usize,
) -> Result<InMemoryGraph, KinDbError> {
    let graph = InMemoryGraph::new();

    for (loaded, entity) in snapshot.entities.values().enumerate() {
        if loaded >= max_entities {
            break;
        }
        graph.upsert_entity(entity)?;
    }

    // Load relations where both endpoints are in the hot set
    for relation in snapshot.relations.values() {
        let src_hot = graph.get_entity(&relation.src)?.is_some();
        let dst_hot = graph.get_entity(&relation.dst)?.is_some();
        if src_hot && dst_hot {
            graph.upsert_relation(relation)?;
        }
    }

    for branch in snapshot.branches.values() {
        graph.create_branch(branch)?;
    }

    Ok(graph)
}

fn merge_hot_into_cold(
    mut cold: GraphSnapshot,
    hot: GraphSnapshot,
    scope: &ManagedHotScope,
) -> GraphSnapshot {
    cold.version = GraphSnapshot::CURRENT_VERSION;
    let hot_entity_ids: HashSet<_> = hot.entities.keys().copied().collect();
    let deleted_managed_entities: HashSet<_> = scope
        .entity_ids
        .difference(&hot_entity_ids)
        .copied()
        .collect();

    cold.entities
        .retain(|entity_id, _| !scope.entity_ids.contains(entity_id));
    cold.relations.retain(|relation_id, relation| {
        !scope.relation_ids.contains(relation_id)
            && !deleted_managed_entities.contains(&relation.src)
            && !deleted_managed_entities.contains(&relation.dst)
    });
    cold.branches
        .retain(|branch_name, _| !scope.branch_names.contains(branch_name));

    cold.entities.extend(hot.entities);
    cold.relations
        .extend(hot.relations.into_iter().filter(|(_, relation)| {
            !deleted_managed_entities.contains(&relation.src)
                && !deleted_managed_entities.contains(&relation.dst)
        }));
    cold.changes.extend(hot.changes);
    cold.change_children.extend(hot.change_children);
    cold.branches.extend(hot.branches);
    cold.work_items.extend(hot.work_items);
    cold.annotations.extend(hot.annotations);

    // Merge Vec fields by deduplicating instead of replacing
    if !hot.work_links.is_empty() {
        for link in hot.work_links {
            if !cold.work_links.contains(&link) {
                cold.work_links.push(link);
            }
        }
    }

    cold.test_cases.extend(hot.test_cases);
    cold.assertions.extend(hot.assertions);
    cold.verification_runs.extend(hot.verification_runs);

    // Merge tuple-Vec fields by deduplicating
    if !hot.test_covers_entity.is_empty() {
        let existing: HashSet<_> = cold.test_covers_entity.iter().cloned().collect();
        cold.test_covers_entity.extend(
            hot.test_covers_entity
                .into_iter()
                .filter(|t| !existing.contains(t)),
        );
    }
    if !hot.test_covers_contract.is_empty() {
        let existing: HashSet<_> = cold.test_covers_contract.iter().cloned().collect();
        cold.test_covers_contract.extend(
            hot.test_covers_contract
                .into_iter()
                .filter(|t| !existing.contains(t)),
        );
    }
    if !hot.test_verifies_work.is_empty() {
        let existing: HashSet<_> = cold.test_verifies_work.iter().cloned().collect();
        cold.test_verifies_work.extend(
            hot.test_verifies_work
                .into_iter()
                .filter(|t| !existing.contains(t)),
        );
    }
    if !hot.run_proves_entity.is_empty() {
        let existing: HashSet<_> = cold.run_proves_entity.iter().cloned().collect();
        cold.run_proves_entity.extend(
            hot.run_proves_entity
                .into_iter()
                .filter(|t| !existing.contains(t)),
        );
    }
    if !hot.run_proves_work.is_empty() {
        let existing: HashSet<_> = cold.run_proves_work.iter().cloned().collect();
        cold.run_proves_work.extend(
            hot.run_proves_work
                .into_iter()
                .filter(|t| !existing.contains(t)),
        );
    }
    if !hot.mock_hints.is_empty() {
        let existing: HashSet<_> = cold.mock_hints.iter().map(|m| m.hint_id).collect();
        cold.mock_hints.extend(
            hot.mock_hints
                .into_iter()
                .filter(|m| !existing.contains(&m.hint_id)),
        );
    }

    cold.contracts.extend(hot.contracts);
    cold.actors.extend(hot.actors);

    if !hot.delegations.is_empty() {
        let existing: HashSet<_> = cold.delegations.iter().map(|d| d.delegation_id).collect();
        cold.delegations.extend(
            hot.delegations
                .into_iter()
                .filter(|d| !existing.contains(&d.delegation_id)),
        );
    }
    if !hot.approvals.is_empty() {
        let existing: HashSet<_> = cold.approvals.iter().map(|a| a.approval_id).collect();
        cold.approvals.extend(
            hot.approvals
                .into_iter()
                .filter(|a| !existing.contains(&a.approval_id)),
        );
    }
    if !hot.audit_events.is_empty() {
        let existing: HashSet<_> = cold.audit_events.iter().map(|e| e.event_id).collect();
        cold.audit_events.extend(
            hot.audit_events
                .into_iter()
                .filter(|e| !existing.contains(&e.event_id)),
        );
    }
    if !hot.shallow_files.is_empty() {
        let existing: HashSet<_> = cold
            .shallow_files
            .iter()
            .map(|f| f.file_id.clone())
            .collect();
        cold.shallow_files.extend(
            hot.shallow_files
                .into_iter()
                .filter(|f| !existing.contains(&f.file_id)),
        );
    }

    cold.file_hashes.extend(hot.file_hashes);
    cold.sessions.extend(hot.sessions);
    cold.intents.extend(hot.intents);

    if !hot.downstream_warnings.is_empty() {
        let existing: HashSet<_> = cold.downstream_warnings.iter().cloned().collect();
        cold.downstream_warnings.extend(
            hot.downstream_warnings
                .into_iter()
                .filter(|w| !existing.contains(w)),
        );
    }
    rebuild_relation_indexes(&mut cold);
    cold
}

fn rebuild_relation_indexes(snapshot: &mut GraphSnapshot) {
    let mut outgoing = HashMap::<EntityId, Vec<RelationId>>::new();
    let mut incoming = HashMap::<EntityId, Vec<RelationId>>::new();

    for relation in snapshot.relations.values() {
        outgoing.entry(relation.src).or_default().push(relation.id);
        incoming.entry(relation.dst).or_default().push(relation.id);
    }

    snapshot.outgoing = outgoing;
    snapshot.incoming = incoming;
}

fn promote_recovery_snapshot(
    path: &Path,
    primary_error: Option<&KinDbError>,
) -> Result<(), KinDbError> {
    let tmp_path = mmap::recovery_tmp_path(path);
    if !tmp_path.exists() {
        return Err(match primary_error {
            Some(err) => KinDbError::StorageError(format!(
                "failed to open {} and no recovery snapshot exists: {err}",
                path.display()
            )),
            None => KinDbError::StorageError(format!(
                "snapshot {} is missing and recovery snapshot {} is not present",
                path.display(),
                tmp_path.display()
            )),
        });
    }

    mmap::load_recovery_candidate(path).map_err(|tmp_err| {
        let prefix = match primary_error {
            Some(primary_err) => format!(
                "failed to open primary snapshot {}: {primary_err}; ",
                path.display()
            ),
            None => format!("primary snapshot {} is missing; ", path.display()),
        };
        KinDbError::StorageError(format!(
            "{prefix}recovery snapshot {} is invalid: {tmp_err}",
            tmp_path.display()
        ))
    })?;

    mmap::promote_recovery_candidate(path).map_err(|err| {
        KinDbError::StorageError(format!(
            "loaded recovery snapshot {} but failed to promote it to {}: {err}",
            tmp_path.display(),
            path.display()
        ))
    })?;

    Ok(())
}

fn ensure_recoverable_snapshot_file(path: &Path) -> Result<(), KinDbError> {
    if path.exists() {
        match mmap::MmapReader::open(path) {
            Ok(_) => Ok(()),
            Err(err) => promote_recovery_snapshot(path, Some(&err)),
        }
    } else {
        let tmp_path = mmap::recovery_tmp_path(path);
        if tmp_path.exists() {
            promote_recovery_snapshot(path, None)
        } else {
            Ok(())
        }
    }
}

fn load_snapshot_from_disk(path: &Path) -> Result<GraphSnapshot, KinDbError> {
    ensure_recoverable_snapshot_file(path)?;
    if !path.exists() {
        return Ok(GraphSnapshot::empty());
    }
    mmap::MmapReader::open(path)
}

fn mmap_snapshot_file(path: &Path) -> Result<(Mmap, GraphSnapshot), KinDbError> {
    ensure_recoverable_snapshot_file(path)?;
    let file = File::open(path)
        .map_err(|e| KinDbError::StorageError(format!("failed to open {}: {e}", path.display())))?;
    let mmap = unsafe {
        Mmap::map(&file).map_err(|e| {
            KinDbError::StorageError(format!("failed to mmap {}: {e}", path.display()))
        })?
    };

    #[cfg(unix)]
    {
        mmap.advise(memmap2::Advice::Random).ok();
    }

    let snapshot = GraphSnapshot::from_bytes(&mmap)?;
    Ok((mmap, snapshot))
}

/// Diagnostic: print tiered storage status.
impl std::fmt::Display for TieredGraph {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let total_gb = self.mem_info.total_ram as f64 / (1024.0 * 1024.0 * 1024.0);
        let avail_gb = self.mem_info.available_ram as f64 / (1024.0 * 1024.0 * 1024.0);
        let hot_mb = self.config.effective_hot_bytes() as f64 / (1024.0 * 1024.0);

        write!(
            f,
            "TieredGraph(strategy={:?}, hot={}/{} entities, RAM={:.1}GB total/{:.1}GB free, hot_budget={:.0}MB)",
            self.strategy,
            self.hot_entity_count(),
            self.total_entity_count(),
            total_gb,
            avail_gb,
            hot_mb,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};
    use tempfile::TempDir;

    use crate::storage::{build_entity_hash_map, compute_graph_root_hash, verify_subgraph};
    #[cfg(feature = "vector")]
    use crate::vector::VectorIndex;

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
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new("src/main.rs")),
            span: None,
            signature: format!("fn {name}()"),
            visibility: Visibility::Public,
            doc_summary: None,
            metadata: EntityMetadata::default(),
            lineage_parent: None,
            created_in: None,
            superseded_by: None,
        }
    }

    fn test_entity_with_language(name: &str, path: &str, language: LanguageId) -> Entity {
        Entity {
            file_origin: Some(FilePathId::new(path)),
            language,
            signature: format!("fn {name}()"),
            ..test_entity(name)
        }
    }

    fn test_relation(src: EntityId, dst: EntityId) -> Relation {
        Relation {
            id: RelationId::new(),
            kind: RelationKind::Calls,
            src,
            dst,
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
        }
    }

    fn force_mmap_config_with_full_hot(path: &Path) -> TieredConfig {
        let file_size = std::fs::metadata(path).unwrap().len() as usize;
        TieredConfig {
            max_hot_bytes: Some(file_size.saturating_mul(4).saturating_sub(1).max(1)),
            bytes_per_entity: 1,
        }
    }

    fn test_branch(name: &str) -> Branch {
        Branch {
            name: BranchName::new(name),
            head: SemanticChangeId::from_hash(Hash256::from_bytes([1; 32])),
        }
    }

    #[test]
    fn system_mem_info_detects() {
        let info = SystemMemInfo::detect();
        // Sanity checks — any real machine has > 0 RAM
        assert!(info.total_ram > 0);
        assert!(info.available_ram > 0);
        assert!(info.available_ram <= info.total_ram);
    }

    #[test]
    fn tiered_config_defaults() {
        let config = TieredConfig::default();
        assert_eq!(config.bytes_per_entity, 200);
        assert!(config.effective_hot_bytes() > 0);
        assert!(config.hot_capacity() > 0);
    }

    #[test]
    fn tiered_config_explicit_budget() {
        let config = TieredConfig {
            max_hot_bytes: Some(1_000_000), // 1MB
            bytes_per_entity: 200,
        };
        assert_eq!(config.effective_hot_bytes(), 1_000_000);
        assert_eq!(config.hot_capacity(), 5_000);
    }

    #[test]
    fn open_nonexistent_creates_empty() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");
        let tiered = TieredGraph::open_auto(&path).unwrap();
        assert_eq!(tiered.strategy(), LoadStrategy::FullLoad);
        assert_eq!(tiered.total_entity_count(), 0);
        assert_eq!(tiered.hot_entity_count(), 0);
    }

    #[test]
    fn full_load_small_graph() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");

        // Write a small snapshot
        let e1 = test_entity("alpha");
        let e2 = test_entity("beta");
        let mut snap = GraphSnapshot::empty();
        snap.entities = [(e1.id, e1.clone()), (e2.id, e2.clone())]
            .into_iter()
            .collect();
        mmap::atomic_write(&path, &snap).unwrap();

        // Open — should full-load since it's tiny
        let tiered = TieredGraph::open_auto(&path).unwrap();
        assert_eq!(tiered.strategy(), LoadStrategy::FullLoad);
        assert_eq!(tiered.total_entity_count(), 2);

        // Entity lookup works
        let found = tiered.get_entity(&e1.id).unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "alpha");
    }

    #[test]
    fn mmap_backed_with_tiny_budget() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");

        // Write a snapshot with several entities
        let entities: Vec<Entity> = (0..100)
            .map(|i| test_entity(&format!("entity_{i}")))
            .collect();
        let entity_map: HashMap<EntityId, Entity> =
            entities.iter().map(|e| (e.id, e.clone())).collect();

        let mut snap = GraphSnapshot::empty();
        snap.entities = entity_map;
        mmap::atomic_write(&path, &snap).unwrap();

        // Force MmapBacked by setting an impossibly small budget (1 byte)
        let config = TieredConfig {
            max_hot_bytes: Some(1),
            bytes_per_entity: 200,
        };
        let tiered = TieredGraph::open(&path, config).unwrap();
        assert_eq!(tiered.strategy(), LoadStrategy::MmapBacked);

        // Total count sees all entities via cold tier
        assert_eq!(tiered.total_entity_count(), 100);

        // Hot tier has 0 entities (budget = 1 byte / 200 = 0 capacity)
        assert_eq!(tiered.hot_entity_count(), 0);

        // But we can still look up any entity via cold tier
        let first = &entities[0];
        let found = tiered.get_entity(&first.id).unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, first.name);
    }

    #[test]
    fn mmap_backed_partial_hot_load() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");

        // Write 50 entities
        let entities: Vec<Entity> = (0..50).map(|i| test_entity(&format!("fn_{i}"))).collect();
        let entity_map: HashMap<EntityId, Entity> =
            entities.iter().map(|e| (e.id, e.clone())).collect();

        let mut snap = GraphSnapshot::empty();
        snap.entities = entity_map;
        mmap::atomic_write(&path, &snap).unwrap();

        // Budget: 10 entities worth (10 * 200 = 2000 bytes budget, but file is bigger)
        // We need to trick the heuristic: file_size * 4 > budget
        // The file is ~10KB+, so budget needs to be < file_size * 4
        let config = TieredConfig {
            max_hot_bytes: Some(10), // Very small — forces mmap
            bytes_per_entity: 1,     // So hot_capacity = 10 entities
        };
        let tiered = TieredGraph::open(&path, config).unwrap();
        assert_eq!(tiered.strategy(), LoadStrategy::MmapBacked);

        // Hot tier loaded at most 10 entities
        assert!(tiered.hot_entity_count() <= 10);

        // Total count is still 50
        assert_eq!(tiered.total_entity_count(), 50);
    }

    #[test]
    fn mmap_backed_open_recovers_from_valid_tmp_when_primary_is_corrupted() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");
        let tmp_path = mmap::recovery_tmp_path(&path);

        let entity = test_entity("recover_mmap");
        let mut snapshot = GraphSnapshot::empty();
        snapshot.entities = [(entity.id, entity.clone())].into_iter().collect();
        mmap::atomic_write(&path, &snapshot).unwrap();
        mmap::write_recovery_candidate(&path, &snapshot).unwrap();

        let mut corrupt_bytes = std::fs::read(&path).unwrap();
        let mid = corrupt_bytes.len() / 2;
        corrupt_bytes[mid] ^= 0xFF;
        std::fs::write(&path, corrupt_bytes).unwrap();

        let tiered = TieredGraph::open(
            &path,
            TieredConfig {
                max_hot_bytes: Some(1),
                bytes_per_entity: 200,
            },
        )
        .unwrap();

        assert_eq!(tiered.strategy(), LoadStrategy::MmapBacked);
        let recovered = tiered.get_entity(&entity.id).unwrap().unwrap();
        assert_eq!(recovered.name, "recover_mmap");
        assert!(path.exists(), "primary snapshot should be promoted");
        assert!(!tmp_path.exists(), "recovery tmp should be consumed");
    }

    #[test]
    fn mmap_backed_open_recovers_from_valid_tmp_when_primary_is_missing() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");
        let tmp_path = mmap::recovery_tmp_path(&path);

        let entity = test_entity("recover_missing_primary");
        let mut snapshot = GraphSnapshot::empty();
        snapshot.entities = [(entity.id, entity.clone())].into_iter().collect();
        mmap::write_recovery_candidate(&path, &snapshot).unwrap();

        let tiered = TieredGraph::open(
            &path,
            TieredConfig {
                max_hot_bytes: Some(1),
                bytes_per_entity: 200,
            },
        )
        .unwrap();

        assert_eq!(tiered.strategy(), LoadStrategy::MmapBacked);
        let recovered = tiered.get_entity(&entity.id).unwrap().unwrap();
        assert_eq!(recovered.name, "recover_missing_primary");
        assert!(
            path.exists(),
            "missing primary snapshot should be recreated from tmp"
        );
        assert!(!tmp_path.exists(), "recovery tmp should be consumed");
    }

    #[test]
    fn mmap_backed_open_rejects_unproven_tmp_when_primary_is_missing() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");
        let tmp_path = mmap::recovery_tmp_path(&path);

        let entity = test_entity("unproven_recovery");
        let mut snapshot = GraphSnapshot::empty();
        snapshot.entities = [(entity.id, entity)].into_iter().collect();
        std::fs::write(&tmp_path, snapshot.to_bytes().unwrap()).unwrap();

        let err = match TieredGraph::open(
            &path,
            TieredConfig {
                max_hot_bytes: Some(1),
                bytes_per_entity: 200,
            },
        ) {
            Ok(_) => panic!("expected unproven recovery snapshot to fail tiered open"),
            Err(err) => err,
        };
        assert!(err.to_string().contains("unproven without a valid marker"));
    }

    #[test]
    #[cfg(feature = "vector")]
    fn mmap_backed_reopen_preserves_mixed_language_truth_and_vector_mappings() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");
        let vector_path = dir.path().join("vectors.usearch");

        let graph = InMemoryGraph::new();
        let rust_entity = test_entity_with_language("compileRust", "src/lib.rs", LanguageId::Rust);
        let ts_entity = test_entity_with_language("renderTs", "web/app.ts", LanguageId::TypeScript);
        let py_entity = test_entity_with_language("trainPy", "tools/train.py", LanguageId::Python);
        let relation = test_relation(rust_entity.id, ts_entity.id);

        graph.upsert_entity(&rust_entity).unwrap();
        graph.upsert_entity(&ts_entity).unwrap();
        graph.upsert_entity(&py_entity).unwrap();
        graph.upsert_relation(&relation).unwrap();

        let snapshot = graph.to_snapshot();
        let root_before = compute_graph_root_hash(&snapshot);
        mmap::atomic_write(&path, &snapshot).unwrap();

        let vectors = VectorIndex::new(4).unwrap();
        vectors
            .upsert(rust_entity.id, &[1.0, 0.0, 0.0, 0.0])
            .unwrap();
        vectors
            .upsert(ts_entity.id, &[0.92, 0.08, 0.0, 0.0])
            .unwrap();
        vectors.upsert(py_entity.id, &[0.0, 1.0, 0.0, 0.0]).unwrap();
        let results_before = vectors.search_similar(&[1.0, 0.0, 0.0, 0.0], 2).unwrap();
        vectors.save(&vector_path).unwrap();

        let reopened = TieredGraph::open(&path, force_mmap_config_with_full_hot(&path)).unwrap();
        assert_eq!(reopened.strategy(), LoadStrategy::MmapBacked);
        assert_eq!(reopened.hot_entity_count(), reopened.total_entity_count());

        let reopened_snapshot = reopened.hot.to_snapshot();
        let root_after = compute_graph_root_hash(&reopened_snapshot);
        assert_eq!(root_before, root_after);

        let filter = EntityFilter {
            languages: Some(vec![LanguageId::Rust, LanguageId::TypeScript]),
            ..Default::default()
        };
        let filtered = reopened.hot.query_entities(&filter).unwrap();
        let filtered_ids: HashSet<_> = filtered.into_iter().map(|entity| entity.id).collect();
        assert_eq!(filtered_ids.len(), 2);
        assert!(filtered_ids.contains(&rust_entity.id));
        assert!(filtered_ids.contains(&ts_entity.id));
        assert!(!filtered_ids.contains(&py_entity.id));

        let hashes = build_entity_hash_map(&reopened_snapshot);
        let report = verify_subgraph(&rust_entity.id, &reopened_snapshot, &hashes).unwrap();
        assert!(report.is_valid);
        assert!(report.tampered.is_empty());

        let relations = reopened
            .get_relations(&rust_entity.id, &[RelationKind::Calls])
            .unwrap();
        assert_eq!(relations.len(), 1);
        assert_eq!(relations[0].dst, ts_entity.id);
        assert_eq!(
            reopened.get_entity(&py_entity.id).unwrap().unwrap().name,
            "trainPy"
        );

        let loaded_vectors = VectorIndex::load(&vector_path, 4).unwrap();
        let results_after = loaded_vectors
            .search_similar(&[1.0, 0.0, 0.0, 0.0], 2)
            .unwrap();
        assert_eq!(results_after, results_before);
        assert_eq!(results_after[0].0, rust_entity.id);
        assert_eq!(results_after[1].0, ts_entity.id);
    }

    #[test]
    fn save_and_reload_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");

        // Create tiered graph, add entities, save
        let tiered = TieredGraph::open_auto(&path).unwrap();
        let e = test_entity("roundtrip");
        let id = e.id;
        tiered.hot.upsert_entity(&e).unwrap();
        tiered.save().unwrap();

        // Reload
        let tiered2 = TieredGraph::open_auto(&path).unwrap();
        let found = tiered2.get_entity(&id).unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().name, "roundtrip");
    }

    #[test]
    fn mmap_backed_save_persists_entity_deletion_and_refreshes_current_view() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");

        let e1 = test_entity("alpha");
        let e2 = test_entity("beta");
        let mut snap = GraphSnapshot::empty();
        snap.entities = [(e1.id, e1.clone()), (e2.id, e2.clone())]
            .into_iter()
            .collect();
        mmap::atomic_write(&path, &snap).unwrap();

        let config = force_mmap_config_with_full_hot(&path);
        let tiered = TieredGraph::open(&path, config.clone()).unwrap();
        assert_eq!(tiered.strategy(), LoadStrategy::MmapBacked);

        tiered.hot.remove_entity(&e1.id).unwrap();
        tiered.save().unwrap();

        assert!(tiered.get_entity(&e1.id).unwrap().is_none());
        assert!(tiered.get_entity(&e2.id).unwrap().is_some());

        let reopened = TieredGraph::open(&path, config).unwrap();
        assert!(reopened.get_entity(&e1.id).unwrap().is_none());
        assert!(reopened.get_entity(&e2.id).unwrap().is_some());
    }

    #[test]
    fn mmap_backed_save_persists_relation_deletion() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");

        let e1 = test_entity("caller");
        let e2 = test_entity("callee");
        let rel = test_relation(e1.id, e2.id);
        let mut snap = GraphSnapshot::empty();
        snap.entities = [(e1.id, e1.clone()), (e2.id, e2.clone())]
            .into_iter()
            .collect();
        snap.relations = [(rel.id, rel.clone())].into_iter().collect();
        rebuild_relation_indexes(&mut snap);
        mmap::atomic_write(&path, &snap).unwrap();

        let config = force_mmap_config_with_full_hot(&path);
        let tiered = TieredGraph::open(&path, config.clone()).unwrap();
        assert_eq!(tiered.strategy(), LoadStrategy::MmapBacked);

        tiered.hot.remove_relation(&rel.id).unwrap();
        tiered.save().unwrap();

        assert!(tiered.get_relation_by_id(&rel.id).is_none());
        let reopened = TieredGraph::open(&path, config).unwrap();
        assert!(reopened.get_relation_by_id(&rel.id).is_none());
        assert!(reopened
            .get_relations(&e1.id, &[RelationKind::Calls])
            .unwrap()
            .is_empty());
    }

    #[test]
    fn mmap_backed_save_persists_entity_updates_without_resurrecting_old_state() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");

        let mut entity = test_entity("before");
        let mut snap = GraphSnapshot::empty();
        snap.entities = [(entity.id, entity.clone())].into_iter().collect();
        mmap::atomic_write(&path, &snap).unwrap();

        let config = force_mmap_config_with_full_hot(&path);
        let tiered = TieredGraph::open(&path, config.clone()).unwrap();
        assert_eq!(tiered.strategy(), LoadStrategy::MmapBacked);

        entity.name = "after".to_string();
        entity.signature = "fn after()".to_string();
        tiered.hot.upsert_entity(&entity).unwrap();
        tiered.save().unwrap();

        let current = tiered.get_entity(&entity.id).unwrap().unwrap();
        assert_eq!(current.name, "after");
        assert!(tiered.query_entities_by_name("before").unwrap().is_empty());

        let reopened = TieredGraph::open(&path, config).unwrap();
        let reloaded = reopened.get_entity(&entity.id).unwrap().unwrap();
        assert_eq!(reloaded.name, "after");
        assert!(reopened
            .query_entities_by_name("before")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn mmap_backed_save_rebuilds_cross_scope_adjacency_after_partial_save() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");

        let entities: Vec<Entity> = (0..6).map(|i| test_entity(&format!("node_{i}"))).collect();
        let mut snap = GraphSnapshot::empty();
        snap.entities = entities
            .iter()
            .map(|entity| (entity.id, entity.clone()))
            .collect();
        for src in &entities {
            for dst in &entities {
                if src.id != dst.id {
                    let rel = test_relation(src.id, dst.id);
                    snap.relations.insert(rel.id, rel);
                }
            }
        }
        rebuild_relation_indexes(&mut snap);
        mmap::atomic_write(&path, &snap).unwrap();

        let tiered = TieredGraph::open(
            &path,
            TieredConfig {
                max_hot_bytes: Some(3),
                bytes_per_entity: 1,
            },
        )
        .unwrap();
        assert_eq!(tiered.strategy(), LoadStrategy::MmapBacked);
        assert_eq!(tiered.hot_entity_count(), 3);

        let loaded = tiered.hot.list_all_entities().unwrap();
        let probe = loaded.first().unwrap();
        let expected = snap.outgoing.get(&probe.id).unwrap().len();
        assert_eq!(
            tiered
                .get_relations(&probe.id, &[RelationKind::Calls])
                .unwrap()
                .len(),
            expected
        );

        tiered.save().unwrap();

        let reopened = TieredGraph::open(
            &path,
            TieredConfig {
                max_hot_bytes: Some(3),
                bytes_per_entity: 1,
            },
        )
        .unwrap();
        assert_eq!(
            reopened
                .get_relations(&probe.id, &[RelationKind::Calls])
                .unwrap()
                .len(),
            expected
        );
    }

    #[test]
    fn mmap_backed_save_persists_branch_deletion() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");

        let main = test_branch("main");
        let feature = test_branch("feature/demo");
        let mut snap = GraphSnapshot::empty();
        snap.branches = [
            (main.name.clone(), main.clone()),
            (feature.name.clone(), feature.clone()),
        ]
        .into_iter()
        .collect();
        mmap::atomic_write(&path, &snap).unwrap();

        let config = force_mmap_config_with_full_hot(&path);
        let tiered = TieredGraph::open(&path, config.clone()).unwrap();
        assert_eq!(tiered.strategy(), LoadStrategy::MmapBacked);

        tiered.hot.delete_branch(&feature.name).unwrap();
        tiered.save().unwrap();

        assert!(tiered.hot.get_branch(&feature.name).unwrap().is_none());
        let reopened = TieredGraph::open(&path, config).unwrap();
        assert!(reopened.hot.get_branch(&feature.name).unwrap().is_none());
        assert!(reopened.hot.get_branch(&main.name).unwrap().is_some());
    }

    #[test]
    fn mmap_backed_save_removes_cold_relations_for_deleted_loaded_entity() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");

        let entities: Vec<Entity> = (0..4)
            .map(|i| test_entity(&format!("entity_{i}")))
            .collect();
        let mut snap = GraphSnapshot::empty();
        snap.entities = entities
            .iter()
            .map(|entity| (entity.id, entity.clone()))
            .collect();
        for src in &entities {
            for dst in &entities {
                if src.id != dst.id {
                    let rel = test_relation(src.id, dst.id);
                    snap.relations.insert(rel.id, rel);
                }
            }
        }
        rebuild_relation_indexes(&mut snap);
        let original_relation_count = snap.relations.len();
        mmap::atomic_write(&path, &snap).unwrap();

        let config = TieredConfig {
            max_hot_bytes: Some(2),
            bytes_per_entity: 1,
        };
        let tiered = TieredGraph::open(&path, config.clone()).unwrap();
        assert_eq!(tiered.strategy(), LoadStrategy::MmapBacked);
        assert_eq!(tiered.hot_entity_count(), 2);

        let deleted = tiered.hot.list_all_entities().unwrap()[0].id;
        tiered.hot.remove_entity(&deleted).unwrap();
        tiered.save().unwrap();

        let reopened = TieredGraph::open(&path, config).unwrap();
        assert!(reopened.get_entity(&deleted).unwrap().is_none());
        assert!(reopened.get_relations(&deleted, &[]).unwrap().is_empty());
        assert_eq!(reopened.total_relation_count(), original_relation_count - 6);
        assert!(reopened
            .cold_snapshot
            .read()
            .as_ref()
            .unwrap()
            .relations
            .values()
            .all(|relation| relation.src != deleted && relation.dst != deleted));
    }

    #[test]
    fn display_shows_diagnostics() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");
        let tiered = TieredGraph::open_auto(&path).unwrap();
        let display = format!("{tiered}");
        assert!(display.contains("FullLoad"));
        assert!(display.contains("hot=0/0"));
        assert!(display.contains("RAM="));
    }

    #[test]
    fn search_spans_both_tiers() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("graph.kndb");

        // Create 20 entities — only load 5 hot
        let entities: Vec<Entity> = (0..20)
            .map(|i| test_entity(&format!("searchable_fn_{i}")))
            .collect();
        let entity_map: HashMap<EntityId, Entity> =
            entities.iter().map(|e| (e.id, e.clone())).collect();

        let mut snap = GraphSnapshot::empty();
        snap.entities = entity_map;
        mmap::atomic_write(&path, &snap).unwrap();

        let config = TieredConfig {
            max_hot_bytes: Some(1), // Force mmap
            bytes_per_entity: 1,
        };
        let tiered = TieredGraph::open(&path, config).unwrap();

        // Search should find entities from cold tier
        let results = tiered.query_entities_by_name("searchable_fn_1").unwrap();
        // Should find searchable_fn_1, searchable_fn_10-19
        assert!(!results.is_empty());
        assert!(results.iter().any(|e| e.name == "searchable_fn_1"));
    }
}
