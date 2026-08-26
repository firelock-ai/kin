// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Store-backed spine backend.
//!
//! [`FirestoreSpineBackend`] keeps every read on a fast in-memory cache and
//! mirrors writes through to a durable [`SpineStore`]. On startup it hydrates
//! that cache as a warm-start hint. Persisted rows are not proof authority: an
//! edge snapshot stays incomplete until graph-authoritative registration and
//! refresh covers every hydrated repo. The store seam is the only component
//! that talks to an external system, which keeps hydrate and write-through logic
//! testable against an in-memory fake.
//!
//! The production store is [`FirestoreStore`] (behind the `firestore` feature),
//! which talks to the Firestore v1 REST API authenticated via the GCE metadata
//! server (Workload Identity on GKE).
//!
//! Firestore collections:
//! ```text
//! spine_entities/{repo_id}_{entity_id}
//!   repo_id, name, kind, signature, file_path, root_hash, payload
//!
//! spine_edges/{auto_id}
//!   src_repo, dst_repo, confidence, payload
//! ```
//!
//! `payload` carries the JSON-serialized `EntityEntry` / `CrossRepoEdge` and is
//! the authoritative copy used to rebuild the cache; the sibling fields stay
//! human-readable for the Firestore console and back the by-repo delete queries.

use std::collections::{BTreeMap, HashSet};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use kin_model::{Entity, EntityId, EntityKind, Relation, SemanticFingerprint};
use parking_lot::Mutex as ParkingMutex;
use tracing::{debug, error, info, warn};

use crate::backend::{InMemorySpineBackend, SpineBackend, SpineError};
use crate::federation::FederatedImpact;
use crate::index::{CrossRepoEdge, CrossRepoEdgesSnapshot, EntityEntry};
use crate::store::SpineStore;

/// Spine backend that reads from an in-memory cache and writes through to a
/// durable [`SpineStore`].
///
/// Strategy: write-through to the store, read from the local cache. On startup,
/// [`hydrate`](FirestoreSpineBackend::hydrate) repopulates the cache from the
/// store. This keeps the hot path (resolve, lookup, federated impact) in memory
/// while writes propagate to durable storage for cross-pod visibility.
pub struct FirestoreSpineBackend {
    /// Local in-memory cache — all reads go here.
    cache: InMemorySpineBackend,
    /// Whether the initial hydration from the store has completed.
    hydrated: AtomicBool,
    /// Keep cache replacement and its durable mirror in one serialized refresh
    /// lane. The cache has its own serializer as well; this outer lock extends
    /// the guarantee through Firestore delete-and-rewrite persistence.
    refresh_write_lock: ParkingMutex<()>,
    /// Durable backing store; the only seam that touches an external system.
    store: Arc<dyn SpineStore>,
}

impl FirestoreSpineBackend {
    /// Create a Firestore-backed spine backend.
    ///
    /// `project_id`: GCP project ID.
    /// `database_id`: Firestore database (typically "(default)").
    #[cfg(feature = "firestore")]
    pub fn new(project_id: String, database_id: Option<String>) -> Self {
        Self::with_store(Arc::new(FirestoreStore::new(project_id, database_id)))
    }

    /// Create a backend over an arbitrary durable store.
    ///
    /// This is the seam used both by the Firestore constructor and by tests that
    /// inject an in-memory store.
    pub fn with_store(store: Arc<dyn SpineStore>) -> Self {
        Self {
            cache: InMemorySpineBackend::new(),
            hydrated: AtomicBool::new(false),
            refresh_write_lock: ParkingMutex::new(()),
            store,
        }
    }

    /// Hydrate the local cache from the durable store.
    ///
    /// Loads every persisted repo and edge into the in-memory cache. Idempotent:
    /// once hydration succeeds, later calls are no-ops. A failed load leaves the
    /// backend un-hydrated so a caller can retry.
    pub fn hydrate(&self) -> Result<(), SpineError> {
        if self.hydrated.load(Ordering::Acquire) {
            return Ok(());
        }

        info!("hydrating spine cache from durable store...");

        let repos = self.store.load_repos()?;
        let edges = self.store.load_edges()?;

        let repo_count = repos.len();
        let entity_count: usize = repos.iter().map(|r| r.entries.len()).sum();
        let loaded_edge_count = edges.len();

        // Populate the inner cache directly (not via `self`) so hydration does
        // not write the loaded data straight back to the store.
        for repo in repos {
            self.cache
                .register_repo(&repo.repo_id, repo.entries, &repo.root_hash);
        }
        // Hydration is a bulk install, not a stream of authority publications.
        // Rebuild the global incident projection/revision once after all rows
        // are resident; doing it once per edge is O(E^2 log E).
        let edge_count = self.cache.index().add_cross_repo_edges(edges);

        self.hydrated.store(true, Ordering::Release);
        info!(
            repos = repo_count,
            entities = entity_count,
            edges = edge_count,
            rejected_edges = loaded_edge_count - edge_count,
            "spine cache hydration complete"
        );
        Ok(())
    }
}

impl SpineBackend for FirestoreSpineBackend {
    fn register_repo(&self, repo_id: &str, entries: Vec<EntityEntry>, root_hash: &str) {
        // Write-through: update the local cache first (fast path).
        self.cache
            .register_repo(repo_id, entries.clone(), root_hash);

        // Replace the repo's persisted entities in the store.
        if let Err(e) = self.store.delete_repo_entities(repo_id) {
            error!(repo_id, error = %e, "failed to delete old entities from store");
        }

        let mut write_errors = 0;
        for entry in &entries {
            if let Err(e) = self.store.write_entity(entry, root_hash) {
                write_errors += 1;
                if write_errors <= 3 {
                    error!(error = %e, "failed to write entity to store");
                }
            }
        }
        if write_errors > 0 {
            warn!(
                repo_id,
                errors = write_errors,
                total = entries.len(),
                "some entities failed to write to store"
            );
        } else {
            debug!(repo_id, count = entries.len(), "wrote entities to store");
        }
    }

    fn resolve(
        &self,
        name: &str,
        kind: Option<EntityKind>,
        reference_fingerprint: Option<&SemanticFingerprint>,
    ) -> Vec<EntityEntry> {
        // Always read from the local cache (populated by write-through + hydrate).
        self.cache.resolve(name, kind, reference_fingerprint)
    }

    fn lookup_by_id(&self, repo_id: &str, entity_id: &EntityId) -> Option<EntityEntry> {
        self.cache.lookup_by_id(repo_id, entity_id)
    }

    fn cross_repo_edges_for(&self, repo_id: &str, entity_id: &EntityId) -> Vec<CrossRepoEdge> {
        self.cache.cross_repo_edges_for(repo_id, entity_id)
    }

    fn authority_complete(&self) -> bool {
        // The same fail-closed rule the snapshot below applies, said directly.
        // The trait's default derives this by materializing the whole snapshot,
        // which for this backend clones every cached edge and entity to arrive
        // at a constant. Stating it here keeps the policy in one readable place
        // per backend rather than emergent from what the default happens to
        // read, and a health probe stops paying a full clone for one boolean.
        false
    }

    fn cross_repo_edges_snapshot(&self) -> CrossRepoEdgesSnapshot {
        // Durable rows and this pod's graph refreshes are useful advisory
        // positives, but neither can prove that every other pod observed the
        // same registered roots. Keep completeness fail-closed until the
        // durable backend owns a shared pass/root CAS.
        let mut snapshot = self.cache.cross_repo_edges_snapshot();
        snapshot.complete = false;
        snapshot
    }

    fn cross_repo_xref_response(
        &self,
        repo_id: &str,
        entity_id: &EntityId,
    ) -> crate::SpineXrefResponse {
        let mut response = self.cache.cross_repo_xref_response(repo_id, entity_id);
        response.authority_complete = false;
        response
    }

    fn add_cross_repo_edge(&self, edge: CrossRepoEdge) {
        // Write-through: local cache + durable store.
        if !self.cache.index().add_cross_repo_edge(edge.clone()) {
            return;
        }

        if let Err(e) = self.store.write_edge(&edge) {
            error!(error = %e, "failed to write edge to store");
        }
    }

    fn root_hash(&self, repo_id: &str) -> Option<String> {
        self.cache.root_hash(repo_id)
    }

    fn entity_count(&self) -> usize {
        self.cache.entity_count()
    }

    fn repo_count(&self) -> usize {
        self.cache.repo_count()
    }

    fn edge_count(&self) -> usize {
        self.cache.edge_count()
    }

    fn registered_repo_ids(&self) -> HashSet<String> {
        self.cache.registered_repo_ids()
    }

    fn refresh_cross_repo_edges(
        &self,
        repo_id: &str,
        entities: &[Entity],
        relations: &[Relation],
        registry_repo_ids: &[String],
    ) {
        let _refresh = self.refresh_write_lock.lock();
        // Recompute the repo's outgoing edges in the cache (this replaces the
        // repo's prior edges by source repo).
        self.cache
            .refresh_cross_repo_edges(repo_id, entities, relations, registry_repo_ids);

        // Mirror the replacement into the store: drop the repo's persisted edges,
        // then persist the freshly materialized set.
        if let Err(e) = self.store.delete_repo_edges(repo_id) {
            error!(repo_id, error = %e, "failed to delete old edges from store");
        }
        for edge in self.cache.index().cross_repo_edges_from(repo_id) {
            if let Err(e) = self.store.write_edge(&edge) {
                error!(error = %e, "failed to write refreshed edge to store");
            }
        }
    }

    fn invalidate_cross_repo_edges(&self, repo_id: &str) {
        self.cache.invalidate_cross_repo_edges(repo_id);
    }

    fn begin_cross_repo_refresh_pass(
        &self,
        authority_roots: &BTreeMap<String, String>,
    ) -> Option<u64> {
        self.cache.begin_cross_repo_refresh_pass(authority_roots)
    }

    fn finish_cross_repo_refresh_pass(
        &self,
        token: u64,
        authority_roots: &BTreeMap<String, String>,
        _success: bool,
    ) -> bool {
        // Clear this pod's lease while deliberately retaining its dirty set.
        // A successful local pass cannot be published as globally complete
        // without a shared durable epoch/root compare-and-swap.
        let _ = self
            .cache
            .finish_cross_repo_refresh_pass(token, authority_roots, false);
        false
    }

    fn federated_impact(
        &self,
        start_repo: &str,
        start_entity: &EntityId,
        max_depth: u32,
    ) -> FederatedImpact {
        self.cache
            .federated_impact(start_repo, start_entity, max_depth)
    }
}

/// Firestore-backed [`SpineStore`] using the v1 REST API.
///
/// Authentication is via the GCE metadata server (Workload Identity on GKE).
#[cfg(feature = "firestore")]
pub struct FirestoreStore {
    /// GCP project ID.
    project_id: String,
    /// Firestore database ID (default: "(default)").
    database_id: String,
    /// HTTP client for Firestore REST API calls.
    client: reqwest::Client,
    /// Cached access token + expiry.
    token: parking_lot::RwLock<Option<(String, std::time::Instant)>>,
}

#[cfg(feature = "firestore")]
impl FirestoreStore {
    /// Create a new Firestore store.
    pub fn new(project_id: String, database_id: Option<String>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("failed to create HTTP client");

        Self {
            project_id,
            database_id: database_id.unwrap_or_else(|| "(default)".to_string()),
            client,
            token: parking_lot::RwLock::new(None),
        }
    }

    /// Base URL for the Firestore REST API documents endpoint.
    fn base_url(&self) -> String {
        format!(
            "https://firestore.googleapis.com/v1/projects/{}/databases/{}/documents",
            self.project_id, self.database_id
        )
    }

    /// Get an access token from the GCE metadata server.
    /// Caches the token for its lifetime minus a 60-second buffer.
    fn get_access_token(&self) -> Result<String, SpineError> {
        {
            let cached = self.token.read();
            if let Some((ref token, ref expiry)) = *cached {
                if std::time::Instant::now() < *expiry {
                    return Ok(token.clone());
                }
            }
        }

        let rt = tokio::runtime::Handle::try_current()
            .map_err(|e| SpineError::Auth(format!("no tokio runtime available: {e}")))?;

        let client = self.client.clone();
        let token_result = rt.block_on(async {
            let resp = client
                .get("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token")
                .header("Metadata-Flavor", "Google")
                .send()
                .await
                .map_err(|e| SpineError::Auth(format!("metadata server request failed: {e}")))?;

            if !resp.status().is_success() {
                return Err(SpineError::Auth(format!(
                    "metadata server returned {}",
                    resp.status()
                )));
            }

            let body: serde_json::Value = resp.json().await.map_err(|e| {
                SpineError::Auth(format!("failed to parse token response: {e}"))
            })?;

            let access_token = body["access_token"]
                .as_str()
                .ok_or_else(|| SpineError::Auth("no access_token in response".to_string()))?
                .to_string();

            let expires_in = body["expires_in"].as_u64().unwrap_or(3600);
            let expiry =
                std::time::Instant::now() + std::time::Duration::from_secs(expires_in.saturating_sub(60));

            Ok((access_token, expiry))
        })?;

        let (access_token, expiry) = token_result;
        let mut cached = self.token.write();
        *cached = Some((access_token.clone(), expiry));
        Ok(access_token)
    }

    /// List every document in a collection, following pagination.
    fn list_all_documents(&self, collection: &str) -> Result<Vec<serde_json::Value>, SpineError> {
        let token = self.get_access_token()?;
        let rt = tokio::runtime::Handle::try_current()
            .map_err(|e| SpineError::Backend(format!("no tokio runtime: {e}")))?;

        rt.block_on(async {
            let mut documents = Vec::new();
            let mut page_token: Option<String> = None;

            loop {
                let mut url = format!("{}/{}?pageSize=300", self.base_url(), collection);
                if let Some(ref pt) = page_token {
                    url.push_str("&pageToken=");
                    url.push_str(pt);
                }

                let resp = self
                    .client
                    .get(&url)
                    .bearer_auth(&token)
                    .send()
                    .await
                    .map_err(|e| SpineError::Http(format!("list {collection} failed: {e}")))?;

                if !resp.status().is_success() {
                    let status = resp.status();
                    let body = resp.text().await.unwrap_or_default();
                    return Err(SpineError::Http(format!(
                        "list {collection} failed ({status}): {body}"
                    )));
                }

                let body: serde_json::Value = resp.json().await.map_err(|e| {
                    SpineError::Serialization(format!("failed to parse {collection} list: {e}"))
                })?;

                if let Some(docs) = body.get("documents").and_then(|d| d.as_array()) {
                    documents.extend(docs.iter().cloned());
                }

                match body.get("nextPageToken").and_then(|t| t.as_str()) {
                    Some(next) if !next.is_empty() => page_token = Some(next.to_string()),
                    _ => break,
                }
            }

            Ok(documents)
        })
    }

    /// Delete every document a structured query selects from `collection`,
    /// matching `field` == `value`. A `None` filter deletes the whole collection.
    fn delete_where(
        &self,
        collection: &str,
        filter: Option<(&str, &str)>,
    ) -> Result<(), SpineError> {
        let token = self.get_access_token()?;
        let url = format!("{}:runQuery", self.base_url());

        let mut structured_query = serde_json::json!({
            "from": [{ "collectionId": collection }],
            "select": { "fields": [{ "fieldPath": "__name__" }] }
        });
        if let Some((field, value)) = filter {
            structured_query["where"] = serde_json::json!({
                "fieldFilter": {
                    "field": { "fieldPath": field },
                    "op": "EQUAL",
                    "value": { "stringValue": value }
                }
            });
        }
        let query = serde_json::json!({ "structuredQuery": structured_query });

        let rt = tokio::runtime::Handle::try_current()
            .map_err(|e| SpineError::Backend(format!("no tokio runtime: {e}")))?;

        rt.block_on(async {
            let resp = self
                .client
                .post(&url)
                .bearer_auth(&token)
                .json(&query)
                .send()
                .await
                .map_err(|e| SpineError::Http(format!("query for delete failed: {e}")))?;

            if !resp.status().is_success() {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                return Err(SpineError::Http(format!(
                    "query for delete failed ({status}): {body}"
                )));
            }

            let results: Vec<serde_json::Value> = resp.json().await.map_err(|e| {
                SpineError::Serialization(format!("failed to parse query results: {e}"))
            })?;

            for result in &results {
                if let Some(doc_name) = result
                    .get("document")
                    .and_then(|d| d.get("name"))
                    .and_then(|n| n.as_str())
                {
                    let delete_url = format!("https://firestore.googleapis.com/v1/{doc_name}");
                    let resp = self
                        .client
                        .delete(&delete_url)
                        .bearer_auth(&token)
                        .send()
                        .await
                        .map_err(|e| {
                            SpineError::Http(format!(
                                "delete {collection} document {doc_name} failed: {e}"
                            ))
                        })?;
                    if !resp.status().is_success() {
                        let status = resp.status();
                        let body = resp.text().await.unwrap_or_default();
                        return Err(SpineError::Http(format!(
                            "delete {collection} document {doc_name} failed ({status}): {body}"
                        )));
                    }
                }
            }
            Ok(())
        })
    }
}

#[cfg(feature = "firestore")]
fn doc_payload<T: serde::de::DeserializeOwned>(
    doc: &serde_json::Value,
    what: &str,
) -> Result<T, SpineError> {
    let payload = doc
        .get("fields")
        .and_then(|f| f.get("payload"))
        .and_then(|p| p.get("stringValue"))
        .and_then(|v| v.as_str())
        .ok_or_else(|| SpineError::Serialization(format!("{what} document missing payload")))?;
    serde_json::from_str(payload)
        .map_err(|e| SpineError::Serialization(format!("failed to parse {what} payload: {e}")))
}

#[cfg(feature = "firestore")]
fn loaded_repos_from_documents(
    docs: &[serde_json::Value],
) -> Result<Vec<crate::store::LoadedRepo>, SpineError> {
    use std::collections::hash_map::Entry;
    use std::collections::HashMap;

    let mut by_repo: HashMap<String, (String, Vec<EntityEntry>)> = HashMap::new();
    for doc in docs {
        let entry: EntityEntry = doc_payload(doc, "entity")?;
        let root_hash = doc
            .get("fields")
            .and_then(|f| f.get("root_hash"))
            .and_then(|h| h.get("stringValue"))
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();

        match by_repo.entry(entry.repo_id.clone()) {
            Entry::Vacant(vacant) => {
                vacant.insert((root_hash, vec![entry]));
            }
            Entry::Occupied(mut occupied) => {
                if occupied.get().0 != root_hash {
                    return Err(SpineError::Serialization(format!(
                        "mixed root hashes for repo {} in spine_entities",
                        occupied.key()
                    )));
                }
                occupied.get_mut().1.push(entry);
            }
        }
    }

    let mut repos = by_repo
        .into_iter()
        .map(|(repo_id, (root_hash, entries))| crate::store::LoadedRepo {
            repo_id,
            root_hash,
            entries,
        })
        .collect::<Vec<_>>();
    repos.sort_by(|a, b| a.repo_id.cmp(&b.repo_id));
    Ok(repos)
}

#[cfg(feature = "firestore")]
impl SpineStore for FirestoreStore {
    fn load_repos(&self) -> Result<Vec<crate::store::LoadedRepo>, SpineError> {
        let docs = self.list_all_documents("spine_entities")?;
        loaded_repos_from_documents(&docs)
    }

    fn load_edges(&self) -> Result<Vec<CrossRepoEdge>, SpineError> {
        let docs = self.list_all_documents("spine_edges")?;
        docs.iter().map(|doc| doc_payload(doc, "edge")).collect()
    }

    fn write_entity(&self, entry: &EntityEntry, root_hash: &str) -> Result<(), SpineError> {
        let token = self.get_access_token()?;
        let doc_id = format!("{}_{}", entry.repo_id, entry.entity_id);
        let url = format!("{}/spine_entities/{}", self.base_url(), doc_id);

        let payload = serde_json::to_string(entry)
            .map_err(|e| SpineError::Serialization(format!("failed to serialize entity: {e}")))?;

        let doc = serde_json::json!({
            "fields": {
                "repo_id": { "stringValue": entry.repo_id },
                "name": { "stringValue": entry.name },
                "kind": { "stringValue": format!("{:?}", entry.kind) },
                "signature": { "stringValue": entry.signature },
                "file_path": { "stringValue": entry.file_path.as_deref().unwrap_or("") },
                "root_hash": { "stringValue": root_hash },
                "payload": { "stringValue": payload },
            }
        });

        let rt = tokio::runtime::Handle::try_current()
            .map_err(|e| SpineError::Backend(format!("no tokio runtime: {e}")))?;

        rt.block_on(async {
            let resp = self
                .client
                .patch(&url)
                .bearer_auth(&token)
                .json(&doc)
                .send()
                .await
                .map_err(|e| SpineError::Http(format!("write entity failed: {e}")))?;

            if !resp.status().is_success() {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                return Err(SpineError::Http(format!(
                    "Firestore write failed ({status}): {body}"
                )));
            }
            Ok(())
        })
    }

    fn delete_repo_entities(&self, repo_id: &str) -> Result<(), SpineError> {
        self.delete_where("spine_entities", Some(("repo_id", repo_id)))
    }

    fn write_edge(&self, edge: &CrossRepoEdge) -> Result<(), SpineError> {
        let token = self.get_access_token()?;
        let url = format!("{}/spine_edges", self.base_url());

        let payload = serde_json::to_string(edge)
            .map_err(|e| SpineError::Serialization(format!("failed to serialize edge: {e}")))?;

        let doc = serde_json::json!({
            "fields": {
                "src_repo": { "stringValue": edge.src_repo },
                "dst_repo": { "stringValue": edge.dst_repo },
                "confidence": { "doubleValue": edge.confidence },
                "payload": { "stringValue": payload },
            }
        });

        let rt = tokio::runtime::Handle::try_current()
            .map_err(|e| SpineError::Backend(format!("no tokio runtime: {e}")))?;

        rt.block_on(async {
            let resp = self
                .client
                .post(&url)
                .bearer_auth(&token)
                .json(&doc)
                .send()
                .await
                .map_err(|e| SpineError::Http(format!("write edge failed: {e}")))?;

            if !resp.status().is_success() {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                return Err(SpineError::Http(format!(
                    "Firestore edge write failed ({status}): {body}"
                )));
            }
            Ok(())
        })
    }

    fn delete_repo_edges(&self, repo_id: &str) -> Result<(), SpineError> {
        self.delete_where("spine_edges", Some(("src_repo", repo_id)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::LoadedRepo;
    use kin_model::{
        EntityKind, EntityRole, FingerprintAlgorithm, GraphNodeId, Hash256, LanguageId,
        RelationEvidence, RelationId, RelationKind, RelationOrigin, SemanticFingerprint,
        Visibility,
    };
    use std::collections::HashMap;
    use std::sync::Mutex;

    /// In-memory [`SpineStore`] fake. Mirrors the Firestore semantics (replace
    /// entities/edges by repo) without any network, so hydrate and write-through
    /// can be exercised under default features.
    #[derive(Default)]
    struct FakeSpineStore {
        // (root_hash, entries) keyed by repo_id.
        repos: Mutex<HashMap<String, (String, Vec<EntityEntry>)>>,
        edges: Mutex<Vec<CrossRepoEdge>>,
        fail_next_load_edges: AtomicBool,
    }

    impl SpineStore for FakeSpineStore {
        fn load_repos(&self) -> Result<Vec<LoadedRepo>, SpineError> {
            Ok(self
                .repos
                .lock()
                .unwrap()
                .iter()
                .map(|(repo_id, (root_hash, entries))| LoadedRepo {
                    repo_id: repo_id.clone(),
                    root_hash: root_hash.clone(),
                    entries: entries.clone(),
                })
                .collect())
        }

        fn load_edges(&self) -> Result<Vec<CrossRepoEdge>, SpineError> {
            if self.fail_next_load_edges.swap(false, Ordering::SeqCst) {
                return Err(SpineError::Backend(
                    "injected load_edges failure".to_string(),
                ));
            }
            Ok(self.edges.lock().unwrap().clone())
        }

        fn write_entity(&self, entry: &EntityEntry, root_hash: &str) -> Result<(), SpineError> {
            let mut repos = self.repos.lock().unwrap();
            let bucket = repos
                .entry(entry.repo_id.clone())
                .or_insert_with(|| (root_hash.to_string(), Vec::new()));
            bucket.0 = root_hash.to_string();
            bucket.1.push(entry.clone());
            Ok(())
        }

        fn delete_repo_entities(&self, repo_id: &str) -> Result<(), SpineError> {
            self.repos.lock().unwrap().remove(repo_id);
            Ok(())
        }

        fn write_edge(&self, edge: &CrossRepoEdge) -> Result<(), SpineError> {
            self.edges.lock().unwrap().push(edge.clone());
            Ok(())
        }

        fn delete_repo_edges(&self, repo_id: &str) -> Result<(), SpineError> {
            self.edges.lock().unwrap().retain(|e| e.src_repo != repo_id);
            Ok(())
        }
    }

    fn test_fp() -> SemanticFingerprint {
        SemanticFingerprint {
            ast_hash: Hash256::from_bytes([1; 32]),
            signature_hash: Hash256::from_bytes([2; 32]),
            behavior_hash: Hash256::from_bytes([3; 32]),
            algorithm: FingerprintAlgorithm::V1TreeSitter,
            equivalence_hash: kin_model::Hash256::from_bytes([0; 32]),
            stability_score: 1.0,
        }
    }

    fn test_entry(repo: &str, name: &str, kind: EntityKind) -> EntityEntry {
        EntityEntry {
            repo_id: repo.to_string(),
            entity_id: EntityId::new(),
            name: name.to_string(),
            kind,
            signature: format!("fn {name}()"),
            fingerprint: test_fp(),
            file_path: Some("src/lib.rs".to_string()),
            role: Some(EntityRole::Source),
        }
    }

    fn local_entity(id: EntityId, name: &str) -> Entity {
        use kin_model::EntityMetadata;
        Entity {
            id,
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Python,
            fingerprint: test_fp(),
            file_origin: None,
            span: None,
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

    fn external_call(src: EntityId, dst: EntityId, import_source: &str, token: &str) -> Relation {
        Relation {
            id: RelationId::new(),
            kind: RelationKind::Calls,
            src: GraphNodeId::Entity(src),
            dst: GraphNodeId::Entity(dst),
            confidence: 1.0,
            origin: RelationOrigin::Parsed,
            created_in: None,
            import_source: Some(import_source.to_string()),
            evidence: vec![RelationEvidence {
                token: Some(token.to_string()),
                ..RelationEvidence::default()
            }],
        }
    }

    #[test]
    fn hydrate_restores_entities_and_edges_from_store() {
        let store = Arc::new(FakeSpineStore::default());

        // Populate via a first backend (write-through to the shared store).
        let writer = FirestoreSpineBackend::with_store(store.clone());
        let a = test_entry("kin-db", "query_entities", EntityKind::Function);
        let b = test_entry("kin", "run_search", EntityKind::Function);
        writer.register_repo("kin-db", vec![a.clone()], "h1");
        writer.register_repo("kin", vec![b.clone()], "h2");
        writer.add_cross_repo_edge(CrossRepoEdge {
            src_repo: "kin".to_string(),
            src_entity: b.entity_id,
            dst_repo: "kin-db".to_string(),
            dst_entity: a.entity_id,
            confidence: 0.9,
        });

        // A fresh backend over the same store must rebuild the full index.
        let reader = FirestoreSpineBackend::with_store(store.clone());
        assert_eq!(reader.entity_count(), 0, "cache empty before hydrate");
        reader.hydrate().expect("hydrate");

        assert_eq!(reader.repo_count(), 2);
        assert_eq!(reader.entity_count(), 2);
        assert_eq!(reader.edge_count(), 1);
        assert_eq!(reader.root_hash("kin-db").as_deref(), Some("h1"));
        assert_eq!(reader.root_hash("kin").as_deref(), Some("h2"));

        let resolved = reader.resolve("query_entities", Some(EntityKind::Function), None);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].repo_id, "kin-db");

        let looked_up = reader
            .lookup_by_id("kin", &b.entity_id)
            .expect("entity present after hydrate");
        assert_eq!(looked_up.name, "run_search");

        let edges = reader.cross_repo_edges_for("kin-db", &a.entity_id);
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].src_repo, "kin");
    }

    #[test]
    fn valid_hydration_and_pod_local_refresh_remain_advisory() {
        let store = Arc::new(FakeSpineStore::default());
        let writer = FirestoreSpineBackend::with_store(store.clone());
        let provider = test_entry("provider", "provide", EntityKind::Function);
        let consumer = test_entry("consumer", "consume", EntityKind::Function);
        writer.register_repo("provider", vec![provider.clone()], "provider-root");
        writer.register_repo("consumer", vec![consumer.clone()], "consumer-root");
        writer.add_cross_repo_edge(CrossRepoEdge {
            src_repo: "consumer".to_string(),
            src_entity: consumer.entity_id,
            dst_repo: "provider".to_string(),
            dst_entity: provider.entity_id,
            confidence: 0.95,
        });

        assert!(
            !writer.cross_repo_edges_snapshot().complete,
            "write-through cache alone cannot claim a complete durable snapshot"
        );

        let reader = FirestoreSpineBackend::with_store(store);
        assert!(!reader.cross_repo_edges_snapshot().complete);
        reader.hydrate().expect("hydrate durable cache warm-start");
        let hydrated = reader.cross_repo_edges_snapshot();
        assert!(
            !hydrated.complete,
            "persisted rows are cache input, not graph proof authority"
        );
        assert_eq!(hydrated.edges.len(), 1);

        reader.register_repo("provider", vec![provider.clone()], "provider-root");
        reader.register_repo("consumer", vec![consumer.clone()], "consumer-root");
        let registry = vec!["consumer".to_string(), "provider".to_string()];
        let provider_entity = local_entity(provider.entity_id, "provide");
        let consumer_entity = local_entity(consumer.entity_id, "consume");
        reader.refresh_cross_repo_edges("provider", &[provider_entity], &[], &registry);
        reader.refresh_cross_repo_edges(
            "consumer",
            &[consumer_entity],
            &[external_call(
                consumer.entity_id,
                EntityId::new(),
                "provider",
                "provide",
            )],
            &registry,
        );

        let snapshot = reader.cross_repo_edges_snapshot();
        assert!(
            !snapshot.complete,
            "a pod-local refresh cannot certify shared durable authority"
        );
        assert_eq!(snapshot.repos, vec!["consumer", "provider"]);
        assert_eq!(snapshot.edges.len(), 1);
        assert!(snapshot.revision.starts_with("sha256:"));
        let xref = reader.cross_repo_xref_response("provider", &provider.entity_id);
        assert_eq!(xref.edges.len(), 1, "known positives remain advisory");
        assert!(!xref.authority_complete);
    }

    #[test]
    fn torn_hydration_remains_incomplete_after_pod_local_rebuild() {
        let store = Arc::new(FakeSpineStore::default());
        let writer = FirestoreSpineBackend::with_store(store.clone());
        let provider = test_entry("provider", "provide", EntityKind::Function);
        let consumer = test_entry("consumer", "consume", EntityKind::Function);
        writer.register_repo("provider", vec![provider.clone()], "provider-root");
        writer.register_repo("consumer", vec![consumer.clone()], "consumer-root");
        writer.add_cross_repo_edge(CrossRepoEdge {
            src_repo: "consumer".to_string(),
            src_entity: consumer.entity_id,
            dst_repo: "provider".to_string(),
            dst_entity: EntityId::new(),
            confidence: 0.95,
        });

        let reader = FirestoreSpineBackend::with_store(store);
        reader.hydrate().expect("hydrate torn cache rows");
        let hydrated = reader.cross_repo_edges_snapshot();
        assert!(!hydrated.complete);
        assert_eq!(
            hydrated.edges.len(),
            1,
            "torn row remains visible but unsafe"
        );

        reader.register_repo("provider", vec![provider], "provider-root");
        reader.register_repo("consumer", vec![consumer], "consumer-root");
        let registry = vec!["consumer".to_string(), "provider".to_string()];
        for repo in &registry {
            reader.refresh_cross_repo_edges(repo, &[], &[], &registry);
        }
        let rebuilt = reader.cross_repo_edges_snapshot();
        assert!(
            !rebuilt.complete,
            "a local rebuild cannot establish shared-store completeness"
        );
        assert!(
            rebuilt.edges.is_empty(),
            "authoritative refresh removes torn edge"
        );
    }

    #[test]
    fn failed_hydration_and_local_rebuild_remain_incomplete() {
        let store = Arc::new(FakeSpineStore::default());
        let writer = FirestoreSpineBackend::with_store(store.clone());
        let alpha = test_entry("alpha", "alpha", EntityKind::Function);
        let beta = test_entry("beta", "beta", EntityKind::Function);
        writer.register_repo("alpha", vec![alpha.clone()], "root-a");
        writer.register_repo("beta", vec![beta.clone()], "root-b");
        store.fail_next_load_edges.store(true, Ordering::SeqCst);

        let reader = FirestoreSpineBackend::with_store(store);
        assert!(reader.hydrate().is_err());
        reader.register_repo("alpha", vec![alpha], "root-a");
        reader.register_repo("beta", vec![beta], "root-b");
        let registry = vec!["alpha".to_string(), "beta".to_string()];
        for repo in &registry {
            reader.refresh_cross_repo_edges(repo, &[], &[], &registry);
        }
        assert!(
            !reader.cross_repo_edges_snapshot().complete,
            "shared-store authority needs a durable pass/root CAS even after local recovery"
        );
    }

    #[test]
    fn stale_pod_cannot_certify_shared_store_completeness() {
        let store = Arc::new(FakeSpineStore::default());
        let stale_pod = FirestoreSpineBackend::with_store(store.clone());
        let provider = test_entry("provider", "provide", EntityKind::Function);
        let consumer = test_entry("consumer", "consume", EntityKind::Function);
        stale_pod.register_repo("provider", vec![provider.clone()], "provider-root-v1");
        stale_pod.register_repo("consumer", vec![consumer.clone()], "consumer-root");
        stale_pod.add_cross_repo_edge(CrossRepoEdge {
            src_repo: "consumer".to_string(),
            src_entity: consumer.entity_id,
            dst_repo: "provider".to_string(),
            dst_entity: provider.entity_id,
            confidence: 0.95,
        });

        let fresh_pod = FirestoreSpineBackend::with_store(store.clone());
        fresh_pod.hydrate().expect("hydrate shared durable rows");
        fresh_pod.register_repo(
            "provider",
            vec![test_entry("provider", "provide_v2", EntityKind::Function)],
            "provider-root-v2",
        );

        let stale_roots = BTreeMap::from([
            ("consumer".to_string(), "consumer-root".to_string()),
            ("provider".to_string(), "provider-root-v1".to_string()),
        ]);
        let token = stale_pod
            .begin_cross_repo_refresh_pass(&stale_roots)
            .expect("stale pod can only acquire its local lease");
        assert!(
            !stale_pod.finish_cross_repo_refresh_pass(token, &stale_roots, true),
            "a local pass must never publish shared durable completeness"
        );

        let durable_provider = store
            .load_repos()
            .unwrap()
            .into_iter()
            .find(|repo| repo.repo_id == "provider")
            .expect("provider remains in shared store");
        assert_eq!(durable_provider.root_hash, "provider-root-v2");
        assert_eq!(
            stale_pod.root_hash("provider").as_deref(),
            Some("provider-root-v1"),
            "the first pod is demonstrably stale"
        );

        let snapshot = stale_pod.cross_repo_edges_snapshot();
        assert!(!snapshot.complete);
        let xref = stale_pod.cross_repo_xref_response("provider", &provider.entity_id);
        assert_eq!(xref.edges.len(), 1, "stale known positives stay advisory");
        assert!(!xref.authority_complete);

        let retry_token = stale_pod
            .begin_cross_repo_refresh_pass(&stale_roots)
            .expect("failed publication still clears the pod-local lease");
        assert!(!stale_pod.finish_cross_repo_refresh_pass(retry_token, &stale_roots, false));
    }

    #[test]
    fn hydrate_rejects_legacy_same_repo_edges_from_store() {
        let store = Arc::new(FakeSpineStore::default());
        store
            .write_edge(&CrossRepoEdge {
                src_repo: "kin".to_string(),
                src_entity: EntityId::new(),
                dst_repo: "kin".to_string(),
                dst_entity: EntityId::new(),
                confidence: 0.5,
            })
            .expect("seed legacy invalid edge");

        let reader = FirestoreSpineBackend::with_store(store);
        reader.hydrate().expect("hydrate");

        assert_eq!(reader.edge_count(), 0);
    }

    #[test]
    fn hydrate_is_idempotent_and_guards_against_reload() {
        let store = Arc::new(FakeSpineStore::default());
        let writer = FirestoreSpineBackend::with_store(store.clone());
        writer.register_repo(
            "repo-a",
            vec![test_entry("repo-a", "Config", EntityKind::Class)],
            "h1",
        );

        let reader = FirestoreSpineBackend::with_store(store.clone());
        reader.hydrate().expect("first hydrate");
        assert_eq!(reader.entity_count(), 1);

        // Mutate the store after the first hydrate; a second hydrate is a no-op
        // because the backend is already hydrated.
        writer.register_repo(
            "repo-b",
            vec![test_entry("repo-b", "parse", EntityKind::Function)],
            "h2",
        );
        reader.hydrate().expect("second hydrate");
        assert_eq!(
            reader.entity_count(),
            1,
            "already-hydrated backend must not reload"
        );
    }

    #[test]
    fn register_repo_write_through_replaces_in_store() {
        let store = Arc::new(FakeSpineStore::default());
        let backend = FirestoreSpineBackend::with_store(store.clone());

        backend.register_repo(
            "repo-a",
            vec![test_entry("repo-a", "old_fn", EntityKind::Function)],
            "h1",
        );
        backend.register_repo(
            "repo-a",
            vec![test_entry("repo-a", "new_fn", EntityKind::Function)],
            "h2",
        );

        let repos = store.load_repos().unwrap();
        assert_eq!(repos.len(), 1);
        let repo = &repos[0];
        assert_eq!(repo.repo_id, "repo-a");
        assert_eq!(repo.root_hash, "h2");
        assert_eq!(repo.entries.len(), 1, "re-register replaces, not appends");
        assert_eq!(repo.entries[0].name, "new_fn");
    }

    #[cfg(feature = "firestore")]
    #[test]
    fn firestore_repo_load_rejects_mixed_roots_for_one_repo() {
        fn document(entry: &EntityEntry, root_hash: &str) -> serde_json::Value {
            serde_json::json!({
                "fields": {
                    "root_hash": { "stringValue": root_hash },
                    "payload": {
                        "stringValue": serde_json::to_string(entry).unwrap()
                    }
                }
            })
        }

        let first = test_entry("repo-a", "first", EntityKind::Function);
        let second = test_entry("repo-a", "second", EntityKind::Function);
        let valid =
            loaded_repos_from_documents(&[document(&first, "root-a"), document(&second, "root-a")])
                .expect("one consistent root per repo");
        assert_eq!(valid.len(), 1);
        assert_eq!(valid[0].entries.len(), 2);

        let error = loaded_repos_from_documents(&[
            document(&first, "root-a"),
            document(&second, "root-a-torn"),
        ])
        .expect_err("mixed root rows are a torn cache snapshot");
        assert!(error
            .to_string()
            .contains("mixed root hashes for repo repo-a"));
    }

    #[test]
    fn add_cross_repo_edge_persists_to_store() {
        let store = Arc::new(FakeSpineStore::default());
        let backend = FirestoreSpineBackend::with_store(store.clone());

        let a = test_entry("repo-a", "caller", EntityKind::Function);
        let b = test_entry("repo-b", "callee", EntityKind::Function);
        backend.add_cross_repo_edge(CrossRepoEdge {
            src_repo: "repo-a".to_string(),
            src_entity: a.entity_id,
            dst_repo: "repo-b".to_string(),
            dst_entity: b.entity_id,
            confidence: 0.95,
        });

        let edges = store.load_edges().unwrap();
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].src_repo, "repo-a");
        assert_eq!(edges[0].dst_repo, "repo-b");
    }

    #[test]
    fn add_cross_repo_edge_rejects_same_repo_before_persistence() {
        let store = Arc::new(FakeSpineStore::default());
        let backend = FirestoreSpineBackend::with_store(store.clone());

        backend.add_cross_repo_edge(CrossRepoEdge {
            src_repo: "repo-a".to_string(),
            src_entity: EntityId::new(),
            dst_repo: "repo-a".to_string(),
            dst_entity: EntityId::new(),
            confidence: 0.5,
        });

        assert_eq!(backend.edge_count(), 0);
        assert!(store.load_edges().unwrap().is_empty());
    }

    #[test]
    fn refresh_cross_repo_edges_persists_add_and_remove() {
        let store = Arc::new(FakeSpineStore::default());
        let backend = FirestoreSpineBackend::with_store(store.clone());

        // Two repos both export `Config`; the import_source disambiguates.
        backend.register_repo(
            "repo-a",
            vec![test_entry("repo-a", "Config", EntityKind::Class)],
            "ha",
        );
        backend.register_repo(
            "repo-b",
            vec![test_entry("repo-b", "Config", EntityKind::Class)],
            "hb",
        );

        let registry = vec![
            "app".to_string(),
            "repo-a".to_string(),
            "repo-b".to_string(),
        ];
        let caller = EntityId::new();
        let entities = vec![local_entity(caller, "build")];

        // First refresh resolves app -> repo-a and persists that edge.
        let to_a = vec![external_call(caller, EntityId::new(), "repo-a", "Config")];
        backend.refresh_cross_repo_edges("app", &entities, &to_a, &registry);

        let edges = store.load_edges().unwrap();
        assert_eq!(edges.len(), 1, "refresh persists the materialized edge");
        assert_eq!(edges[0].src_repo, "app");
        assert_eq!(edges[0].dst_repo, "repo-a");

        // Second refresh resolves app -> repo-b; the stale app edge must be gone.
        let to_b = vec![external_call(caller, EntityId::new(), "repo-b", "Config")];
        backend.refresh_cross_repo_edges("app", &entities, &to_b, &registry);

        let edges = store.load_edges().unwrap();
        assert_eq!(edges.len(), 1, "refresh replaces, not appends");
        assert_eq!(edges[0].dst_repo, "repo-b");

        // A fresh backend hydrated from the store must see the replacement.
        let reader = FirestoreSpineBackend::with_store(store.clone());
        reader.hydrate().expect("hydrate");
        assert_eq!(reader.edge_count(), 1);
        let from_app = reader.cache.index().cross_repo_edges_from("app");
        assert_eq!(from_app.len(), 1);
        assert_eq!(from_app[0].dst_repo, "repo-b");
    }
}
