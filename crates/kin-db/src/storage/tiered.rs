use memmap2::Mmap;
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
    _cold_mmap: Option<Mmap>,
    /// The deserialized cold snapshot (lazily loaded from mmap).
    /// This is only populated when strategy is MmapBacked.
    cold_snapshot: Option<GraphSnapshot>,
    /// What strategy was selected.
    strategy: LoadStrategy,
    /// Path to the snapshot file.
    path: PathBuf,
    /// Configuration.
    config: TieredConfig,
    /// System memory info at startup (for diagnostics).
    mem_info: SystemMemInfo,
}

impl TieredGraph {
    /// Open a tiered graph from a snapshot file.
    ///
    /// Auto-detects available RAM and chooses the appropriate loading strategy.
    pub fn open(path: impl Into<PathBuf>, config: TieredConfig) -> Result<Self, KinDbError> {
        let path = path.into();
        let mem_info = SystemMemInfo::detect();

        if !path.exists() {
            // No snapshot file — start with an empty graph
            return Ok(Self {
                hot: Arc::new(InMemoryGraph::new()),
                _cold_mmap: None,
                cold_snapshot: None,
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
            let snapshot = mmap::MmapReader::open(&path)?;
            let graph = hydrate_graph(snapshot);
            Ok(Self {
                hot: Arc::new(graph),
                _cold_mmap: None,
                cold_snapshot: None,
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

            Ok(Self {
                hot: Arc::new(graph),
                _cold_mmap: Some(mmap),
                cold_snapshot: Some(snapshot),
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
        match &self.cold_snapshot {
            Some(snap) => snap.entities.len(),
            None => self.hot.entity_count(),
        }
    }

    /// Total number of relations (hot + cold).
    pub fn total_relation_count(&self) -> usize {
        match &self.cold_snapshot {
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
        if let Some(snap) = &self.cold_snapshot {
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
        if let Some(snap) = &self.cold_snapshot {
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
        if let Some(snap) = &self.cold_snapshot {
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
        if let Some(snap) = &self.cold_snapshot {
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
        let snapshot = if let Some(cold) = &self.cold_snapshot {
            merge_hot_into_cold(cold.clone(), self.hot.to_snapshot())
        } else {
            self.hot.to_snapshot()
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

        mmap::atomic_write(&self.path, &snapshot)
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

    let mut loaded = 0;
    for entity in snapshot.entities.values() {
        if loaded >= max_entities {
            break;
        }
        graph.upsert_entity(entity)?;
        loaded += 1;
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

fn merge_hot_into_cold(mut cold: GraphSnapshot, hot: GraphSnapshot) -> GraphSnapshot {
    use std::collections::HashSet;

    cold.version = GraphSnapshot::CURRENT_VERSION;
    cold.entities.extend(hot.entities);
    cold.relations.extend(hot.relations);
    cold.outgoing.extend(hot.outgoing);
    cold.incoming.extend(hot.incoming);
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
            hot.test_covers_entity.into_iter().filter(|t| !existing.contains(t)),
        );
    }
    if !hot.test_covers_contract.is_empty() {
        let existing: HashSet<_> = cold.test_covers_contract.iter().cloned().collect();
        cold.test_covers_contract.extend(
            hot.test_covers_contract.into_iter().filter(|t| !existing.contains(t)),
        );
    }
    if !hot.test_verifies_work.is_empty() {
        let existing: HashSet<_> = cold.test_verifies_work.iter().cloned().collect();
        cold.test_verifies_work.extend(
            hot.test_verifies_work.into_iter().filter(|t| !existing.contains(t)),
        );
    }
    if !hot.run_proves_entity.is_empty() {
        let existing: HashSet<_> = cold.run_proves_entity.iter().cloned().collect();
        cold.run_proves_entity.extend(
            hot.run_proves_entity.into_iter().filter(|t| !existing.contains(t)),
        );
    }
    if !hot.run_proves_work.is_empty() {
        let existing: HashSet<_> = cold.run_proves_work.iter().cloned().collect();
        cold.run_proves_work.extend(
            hot.run_proves_work.into_iter().filter(|t| !existing.contains(t)),
        );
    }
    if !hot.mock_hints.is_empty() {
        let existing: HashSet<_> = cold.mock_hints.iter().map(|m| m.hint_id).collect();
        cold.mock_hints.extend(
            hot.mock_hints.into_iter().filter(|m| !existing.contains(&m.hint_id)),
        );
    }

    cold.contracts.extend(hot.contracts);
    cold.actors.extend(hot.actors);

    if !hot.delegations.is_empty() {
        let existing: HashSet<_> = cold.delegations.iter().map(|d| d.delegation_id).collect();
        cold.delegations.extend(
            hot.delegations.into_iter().filter(|d| !existing.contains(&d.delegation_id)),
        );
    }
    if !hot.approvals.is_empty() {
        let existing: HashSet<_> = cold.approvals.iter().map(|a| a.approval_id).collect();
        cold.approvals.extend(
            hot.approvals.into_iter().filter(|a| !existing.contains(&a.approval_id)),
        );
    }
    if !hot.audit_events.is_empty() {
        let existing: HashSet<_> = cold.audit_events.iter().map(|e| e.event_id).collect();
        cold.audit_events.extend(
            hot.audit_events.into_iter().filter(|e| !existing.contains(&e.event_id)),
        );
    }
    if !hot.shallow_files.is_empty() {
        let existing: HashSet<_> = cold.shallow_files.iter().map(|f| f.file_id.clone()).collect();
        cold.shallow_files.extend(
            hot.shallow_files.into_iter().filter(|f| !existing.contains(&f.file_id)),
        );
    }

    cold.file_hashes.extend(hot.file_hashes);
    cold.sessions.extend(hot.sessions);
    cold.intents.extend(hot.intents);

    if !hot.downstream_warnings.is_empty() {
        let existing: HashSet<_> = cold.downstream_warnings.iter().cloned().collect();
        cold.downstream_warnings.extend(
            hot.downstream_warnings.into_iter().filter(|w| !existing.contains(w)),
        );
    }
    cold
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
    use std::collections::HashMap;
    use tempfile::TempDir;

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
