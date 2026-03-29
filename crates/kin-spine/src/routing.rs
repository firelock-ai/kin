// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Repo → daemon routing table.
//!
//! Consistent-hash assignment of repos to daemon pods.
//! The spine IS the router — no separate routing service.

use parking_lot::RwLock;
use std::collections::HashMap;

/// Network endpoint for a daemon pod.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RepoEndpoint {
    /// Base URL for the daemon HTTP API (e.g., "http://kin-daemon-0:4219")
    pub url: String,
    /// Repo IDs served by this endpoint.
    pub repos: Vec<String>,
    /// Whether this endpoint is healthy.
    pub healthy: bool,
    /// Last health check timestamp.
    pub last_check: Option<chrono::DateTime<chrono::Utc>>,
}

/// Routes repos to daemon endpoints.
///
/// In single-node mode (pre-revenue), all repos route to the local daemon.
/// In multi-node mode, consistent hashing assigns repos to daemon pods.
pub struct RoutingTable {
    inner: RwLock<RoutingInner>,
}

struct RoutingInner {
    /// Repo ID → endpoint URL
    assignments: HashMap<String, String>,
    /// Endpoint URL → metadata
    endpoints: HashMap<String, RepoEndpoint>,
}

impl RoutingTable {
    pub fn new() -> Self {
        Self {
            inner: RwLock::new(RoutingInner {
                assignments: HashMap::new(),
                endpoints: HashMap::new(),
            }),
        }
    }

    /// Register a daemon endpoint with its repos.
    pub fn register_endpoint(&self, endpoint: RepoEndpoint) {
        let mut inner = self.inner.write();
        for repo_id in &endpoint.repos {
            inner
                .assignments
                .insert(repo_id.clone(), endpoint.url.clone());
        }
        inner.endpoints.insert(endpoint.url.clone(), endpoint);
    }

    /// Look up which daemon endpoint serves a given repo.
    pub fn route(&self, repo_id: &str) -> Option<String> {
        let inner = self.inner.read();
        inner.assignments.get(repo_id).cloned()
    }

    /// List all known endpoints.
    pub fn endpoints(&self) -> Vec<RepoEndpoint> {
        let inner = self.inner.read();
        inner.endpoints.values().cloned().collect()
    }

    /// Mark an endpoint as unhealthy.
    pub fn mark_unhealthy(&self, url: &str) {
        let mut inner = self.inner.write();
        if let Some(ep) = inner.endpoints.get_mut(url) {
            ep.healthy = false;
        }
    }

    /// Number of registered endpoints.
    pub fn endpoint_count(&self) -> usize {
        let inner = self.inner.read();
        inner.endpoints.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routing_basic() {
        let table = RoutingTable::new();

        table.register_endpoint(RepoEndpoint {
            url: "http://daemon-0:4219".to_string(),
            repos: vec!["kin".to_string(), "kin-db".to_string()],
            healthy: true,
            last_check: None,
        });

        assert_eq!(table.route("kin"), Some("http://daemon-0:4219".to_string()));
        assert_eq!(
            table.route("kin-db"),
            Some("http://daemon-0:4219".to_string())
        );
        assert_eq!(table.route("unknown"), None);
    }

    #[test]
    fn multi_endpoint_routing() {
        let table = RoutingTable::new();

        table.register_endpoint(RepoEndpoint {
            url: "http://daemon-0:4219".to_string(),
            repos: vec!["kin".to_string()],
            healthy: true,
            last_check: None,
        });
        table.register_endpoint(RepoEndpoint {
            url: "http://daemon-1:4219".to_string(),
            repos: vec!["kin-db".to_string()],
            healthy: true,
            last_check: None,
        });

        assert_eq!(table.route("kin"), Some("http://daemon-0:4219".to_string()));
        assert_eq!(
            table.route("kin-db"),
            Some("http://daemon-1:4219".to_string())
        );
        assert_eq!(table.endpoint_count(), 2);
    }
}
