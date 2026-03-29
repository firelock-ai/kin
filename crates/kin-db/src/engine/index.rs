// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use hashbrown::{HashMap, HashSet};
use kin_search::tokenize;
use rayon::prelude::*;

use crate::types::{EntityId, EntityKind, FilePathId};

const MAX_TOKEN_MATCH_CANDIDATES: usize = 32;

/// Secondary indexes for fast entity lookup by name, file, and kind.
///
/// Uses `HashSet<EntityId>` internally so that `remove()` is O(1) instead
/// of an O(n) linear scan through a Vec.
#[derive(Clone, Debug, Default)]
pub struct IndexSet {
    /// Lowercased entity name → entity IDs.
    pub name: HashMap<String, HashSet<EntityId>>,
    /// Tokenized entity name lexemes → entity IDs.
    pub name_token: HashMap<String, HashSet<EntityId>>,
    /// File path string → entity IDs.
    pub file: HashMap<String, HashSet<EntityId>>,
    /// Entity kind → entity IDs.
    pub kind: HashMap<EntityKind, HashSet<EntityId>>,
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
        let lower_name = name.to_lowercase();
        self.name.entry(lower_name).or_default().insert(id);

        for token in unique_name_tokens(name) {
            self.name_token.entry(token).or_default().insert(id);
        }

        if let Some(fp) = file {
            self.file.entry(fp.0.clone()).or_default().insert(id);
        }

        self.kind.entry(kind).or_default().insert(id);
    }

    /// Remove an entity from all indexes (O(1) per index).
    pub fn remove(
        &mut self,
        id: &EntityId,
        name: &str,
        file: Option<&FilePathId>,
        kind: EntityKind,
    ) {
        let lower_name = name.to_lowercase();
        if let Some(ids) = self.name.get_mut(&lower_name) {
            ids.remove(id);
            if ids.is_empty() {
                self.name.remove(&lower_name);
            }
        }

        for token in unique_name_tokens(name) {
            if let Some(ids) = self.name_token.get_mut(&token) {
                ids.remove(id);
                if ids.is_empty() {
                    self.name_token.remove(&token);
                }
            }
        }

        if let Some(fp) = file {
            if let Some(ids) = self.file.get_mut(&fp.0) {
                ids.remove(id);
                if ids.is_empty() {
                    self.file.remove(&fp.0);
                }
            }
        }

        if let Some(ids) = self.kind.get_mut(&kind) {
            ids.remove(id);
            if ids.is_empty() {
                self.kind.remove(&kind);
            }
        }
    }

    /// Merge another `IndexSet` into this one (used for parallel index build).
    pub fn merge(&mut self, other: IndexSet) {
        for (name, ids) in other.name {
            self.name.entry(name).or_default().extend(ids);
        }
        for (token, ids) in other.name_token {
            self.name_token.entry(token).or_default().extend(ids);
        }
        for (file, ids) in other.file {
            self.file.entry(file).or_default().extend(ids);
        }
        for (kind, ids) in other.kind {
            self.kind.entry(kind).or_default().extend(ids);
        }
    }

    /// Look up entities by file path.
    pub fn by_file(&self, path: &str) -> Vec<EntityId> {
        self.file
            .get(path)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Look up entities by kind.
    pub fn by_kind(&self, kind: EntityKind) -> Vec<EntityId> {
        self.kind
            .get(&kind)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default()
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
            let mut ranked = Vec::new();
            let mut seen = HashSet::new();

            if let Some(ids) = self.name.get(&pat) {
                extend_unique(&mut ranked, &mut seen, ids);
            }

            if let Some(token_ids) = token_intersection(&self.name_token, pattern) {
                if token_ids.len() <= MAX_TOKEN_MATCH_CANDIDATES {
                    extend_unique(&mut ranked, &mut seen, &token_ids);
                }
            }

            if !ranked.is_empty() {
                return ranked;
            }

            // Fallback: substring / contains match (matches KuzuDB CONTAINS behavior)
            self.name
                .par_iter()
                .filter(|(k, _)| k.contains(&*pat))
                .flat_map(|(_, ids)| ids.par_iter().copied())
                .collect()
        }
    }
}

fn unique_name_tokens(name: &str) -> HashSet<String> {
    tokenize(name).into_iter().collect()
}

fn token_intersection(
    token_index: &HashMap<String, HashSet<EntityId>>,
    pattern: &str,
) -> Option<HashSet<EntityId>> {
    let mut tokens = unique_name_tokens(pattern)
        .into_iter()
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>();
    if tokens.is_empty() {
        return None;
    }

    tokens.sort_unstable_by_key(|token| token.len());

    let mut candidates: Option<HashSet<EntityId>> = None;
    for token in tokens {
        let ids = token_index.get(&token)?;
        candidates = Some(match candidates {
            Some(current) => current
                .into_iter()
                .filter(|id| ids.contains(id))
                .collect::<HashSet<_>>(),
            None => ids.iter().copied().collect(),
        });

        if candidates.as_ref().is_some_and(|ids| ids.is_empty()) {
            return None;
        }
    }

    candidates
}

fn extend_unique(
    ranked: &mut Vec<EntityId>,
    seen: &mut HashSet<EntityId>,
    ids: &HashSet<EntityId>,
) {
    let mut sorted: Vec<_> = ids.iter().copied().collect();
    sorted.sort_unstable_by_key(|id| id.0);
    for id in sorted {
        if seen.insert(id) {
            ranked.push(id);
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
    fn tokenized_name_lookup_matches_camel_case_segments() {
        let mut idx = IndexSet::new();
        let id = EntityId::new();
        idx.insert(id, "parseTableFromHtml", None, EntityKind::Function);

        let matches = idx.by_name_pattern("table");
        assert_eq!(matches, vec![id]);
    }

    #[test]
    fn tokenized_name_lookup_matches_snake_case_segments() {
        let mut idx = IndexSet::new();
        let id = EntityId::new();
        idx.insert(id, "extension_registry", None, EntityKind::StaticVar);

        let matches = idx.by_name_pattern("registry");
        assert_eq!(matches, vec![id]);
    }

    #[test]
    fn substring_fallback_still_works_when_token_lookup_misses() {
        let mut idx = IndexSet::new();
        let id = EntityId::new();
        idx.insert(id, "ManagerForExtensions", None, EntityKind::Class);

        let matches = idx.by_name_pattern("extension");
        assert_eq!(matches, vec![id]);
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
