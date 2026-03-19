// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use hashbrown::HashMap;
use rayon::prelude::*;

use crate::types::{EntityId, EntityKind, FilePathId};

/// Secondary indexes for fast entity lookup by name, file, and kind.
#[derive(Debug, Default)]
pub struct IndexSet {
    /// Lowercased entity name → entity IDs.
    pub name: HashMap<String, Vec<EntityId>>,
    /// File path string → entity IDs.
    pub file: HashMap<String, Vec<EntityId>>,
    /// Entity kind → entity IDs.
    pub kind: HashMap<EntityKind, Vec<EntityId>>,
}

impl IndexSet {
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an entity to all applicable indexes.
    pub fn insert(
        &mut self,
        id: EntityId,
        name: &str,
        file: Option<&FilePathId>,
        kind: EntityKind,
    ) {
        self.name.entry(name.to_lowercase()).or_default().push(id);

        if let Some(fp) = file {
            self.file.entry(fp.0.clone()).or_default().push(id);
        }

        self.kind.entry(kind).or_default().push(id);
    }

    /// Remove an entity from all indexes.
    pub fn remove(
        &mut self,
        id: &EntityId,
        name: &str,
        file: Option<&FilePathId>,
        kind: EntityKind,
    ) {
        if let Some(ids) = self.name.get_mut(&name.to_lowercase()) {
            ids.retain(|e| e != id);
            if ids.is_empty() {
                self.name.remove(&name.to_lowercase());
            }
        }

        if let Some(fp) = file {
            if let Some(ids) = self.file.get_mut(&fp.0) {
                ids.retain(|e| e != id);
                if ids.is_empty() {
                    self.file.remove(&fp.0);
                }
            }
        }

        if let Some(ids) = self.kind.get_mut(&kind) {
            ids.retain(|e| e != id);
            if ids.is_empty() {
                self.kind.remove(&kind);
            }
        }
    }

    /// Look up entities by file path.
    pub fn by_file(&self, path: &str) -> &[EntityId] {
        self.file.get(path).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Look up entities by kind.
    pub fn by_kind(&self, kind: EntityKind) -> &[EntityId] {
        self.kind.get(&kind).map(|v| v.as_slice()).unwrap_or(&[])
    }

    /// Pattern match on name (supports `*` wildcard at start/end).
    pub fn by_name_pattern(&self, pattern: &str) -> Vec<EntityId> {
        let pat = pattern.to_lowercase();

        if let Some(suffix) = pat.strip_prefix('*') {
            // *suffix — names ending with suffix
            self.name
                .par_iter()
                .filter(|(k, _)| k.ends_with(suffix))
                .flat_map(|(_, ids)| ids.par_iter().copied())
                .collect()
        } else if let Some(prefix) = pat.strip_suffix('*') {
            // prefix* — names starting with prefix
            self.name
                .par_iter()
                .filter(|(k, _)| k.starts_with(prefix))
                .flat_map(|(_, ids)| ids.par_iter().copied())
                .collect()
        } else {
            // Substring / contains match (matches KuzuDB CONTAINS behavior)
            self.name
                .par_iter()
                .filter(|(k, _)| k.contains(&*pat))
                .flat_map(|(_, ids)| ids.par_iter().copied())
                .collect()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::EntityKind;

    #[test]
    fn insert_and_lookup() {
        let mut idx = IndexSet::new();
        let id = EntityId::new();
        let fp = FilePathId::new("src/main.rs");
        idx.insert(id, "myFunction", Some(&fp), EntityKind::Function);

        assert_eq!(idx.by_name_pattern("myfunction"), vec![id]);
        assert_eq!(idx.by_name_pattern("MYFUNCTION"), vec![id]);
        assert_eq!(idx.by_file("src/main.rs"), &[id]);
        assert_eq!(idx.by_kind(EntityKind::Function), &[id]);
        assert!(idx.by_name_pattern("other").is_empty());
    }

    #[test]
    fn remove_cleans_all_indexes() {
        let mut idx = IndexSet::new();
        let id = EntityId::new();
        let fp = FilePathId::new("src/lib.rs");
        idx.insert(id, "Foo", Some(&fp), EntityKind::Class);
        idx.remove(&id, "Foo", Some(&fp), EntityKind::Class);

        assert!(idx.by_name_pattern("foo").is_empty());
        assert!(idx.by_file("src/lib.rs").is_empty());
        assert!(idx.by_kind(EntityKind::Class).is_empty());
    }

    #[test]
    fn pattern_wildcard() {
        let mut idx = IndexSet::new();
        let id1 = EntityId::new();
        let id2 = EntityId::new();
        idx.insert(id1, "getUser", None, EntityKind::Function);
        idx.insert(id2, "getPost", None, EntityKind::Function);

        let matches = idx.by_name_pattern("get*");
        assert!(matches.contains(&id1));
        assert!(matches.contains(&id2));

        let matches = idx.by_name_pattern("*user");
        assert!(matches.contains(&id1));
        assert!(!matches.contains(&id2));
    }
}
