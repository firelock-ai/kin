// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Measure the population a ranked read draws from, and the span-coherence
//! state of every entity in it.
//!
//! `SpanCoherence::Unverified` is the state an entity reaches when it records no
//! `blob_hash`, and today a read in that state slices anyway. Whether that
//! should tighten into a refusal is a decision about a POPULATION, not about a
//! rule. A tightening that refuses a handful of entities is a correctness fix;
//! the same tightening over a population that is mostly unverified takes the
//! product offline. The counts that decision needs were never measured, because
//! nothing enumerated the set a ranked candidate is drawn from.
//!
//! Two populations exist and they are not the same size.
//!
//! `kin init` reports the count from a first-parent replay of the workspace's
//! lineage, which is the set alive AT THE TIP. The graph a daemon serves is
//! built from every semantic change the authority holds, so it also carries
//! every identity the history ever had, including ones a later commit retired.
//! A ranked candidate is drawn from the second, larger set.
//!
//! This harness enumerates both off a real store. It is `#[ignore]`d and reads a
//! fixture path from the environment, so it never runs in CI and needs no corpus
//! checked in:
//!
//! ```text
//! KIN_SPAN_COHERENCE_FIXTURE=/path/to/initialized/repo \
//!   cargo test -p kin-cli --test span_coherence_population -- --ignored --nocapture
//! ```
//!
//! It reads the persisted authority directly, so it neither starts a daemon,
//! nor advances the store generation, nor triggers an embedding pass.

use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;

use kin_model::{EntityDelta, EntityId};

/// One tallied dimension of a population.
#[derive(Default)]
struct Tally {
    counts: BTreeMap<String, usize>,
}

impl Tally {
    fn add(&mut self, key: impl Into<String>) {
        *self.counts.entry(key.into()).or_default() += 1;
    }

    fn report(&self, title: &str, total: usize) {
        println!("  {title}");
        let mut rows: Vec<_> = self.counts.iter().collect();
        rows.sort_by(|left, right| right.1.cmp(left.1).then(left.0.cmp(right.0)));
        for (key, count) in rows.iter().take(12) {
            let share = if total == 0 {
                0.0
            } else {
                (**count as f64 / total as f64) * 100.0
            };
            println!("    {count:>8}  {share:>5.1}%  {key}");
        }
        if rows.len() > 12 {
            println!("    ... {} more keys", rows.len() - 12);
        }
    }
}

#[test]
#[ignore = "measurement harness: set KIN_SPAN_COHERENCE_FIXTURE to an initialized repository"]
fn report_ranked_span_coherence_population() {
    let fixture = PathBuf::from(
        std::env::var("KIN_SPAN_COHERENCE_FIXTURE")
            .expect("set KIN_SPAN_COHERENCE_FIXTURE to a repository that has been `kin init`ed"),
    );
    let layout = kin_core::KinLayout::discover(&fixture)
        .unwrap_or_else(|| panic!("no .kin store found at or above {}", fixture.display()));
    let manifest =
        kin_core::KinManifest::load(&layout.manifest_path()).expect("read the repository manifest");
    let repository_id =
        kin_model::RepositoryId::new(manifest.repo_id.clone()).expect("valid repository identity");

    let backend = Arc::new(kin_db::LocalFileBackend::new(layout.kindb_dir()));
    let (authority, _stats) =
        kin_core::open_persisted_local_repository_authority(repository_id, backend)
            .expect("open the persisted repository authority");
    let lease = authority.read_authority();
    let snapshot = lease.snapshot();

    // Every identity any change ever introduced. This is what a graph built
    // from the whole authority holds, and therefore what a ranked read can
    // surface.
    let mut ever: BTreeMap<EntityId, EntityFacts> = BTreeMap::new();
    let mut deltas_seen = 0_usize;
    for change in snapshot.changes.values() {
        for delta in &change.entity_deltas {
            deltas_seen += 1;
            let entity = match delta {
                EntityDelta::Added { new } | EntityDelta::Modified { new, .. } => new,
                EntityDelta::Removed { old } => old,
            };
            let facts = EntityFacts {
                has_digest: entity.metadata.extra.contains_key("blob_hash"),
                sliceable: entity.span.is_some() && entity.file_origin.is_some(),
                kind: format!("{:?}", entity.kind),
                language: entity.language.to_string(),
                path: entity
                    .file_origin
                    .as_ref()
                    .map(|origin| origin.to_string())
                    .unwrap_or_default(),
            };
            ever.insert(entity.id, facts);
        }
    }

    // The set alive at the workspace tip, replayed exactly the way `kin init`
    // and `kin status` count it.
    let metadata = lease.metadata();
    let workspace = metadata
        .workspaces
        .first()
        .expect("an initialized repository registers a workspace");
    let head = workspace
        .base_target
        .as_ref()
        .and_then(|target| lease.resolve_target_change_id(target).ok());
    let tip = tip_entity_ids(snapshot, head, workspace.semantic_overlay.entity_deltas());

    let mut with_digest = 0_usize;
    let mut sliceable = 0_usize;
    let mut sliceable_unverified = 0_usize;
    let mut retired_sliceable = 0_usize;
    let mut path_live_today = 0_usize;
    let mut kinds = Tally::default();
    let mut languages = Tally::default();
    let mut path_cache: BTreeMap<String, bool> = BTreeMap::new();

    for (id, facts) in &ever {
        if facts.has_digest {
            with_digest += 1;
        }
        if facts.sliceable {
            sliceable += 1;
            if !facts.has_digest {
                sliceable_unverified += 1;
            }
            if !tip.contains(id) {
                retired_sliceable += 1;
                if !facts.path.is_empty() {
                    let live = *path_cache
                        .entry(facts.path.clone())
                        .or_insert_with(|| layout.working_dir().join(&facts.path).exists());
                    if live {
                        path_live_today += 1;
                    }
                }
            }
        }
        if !facts.has_digest {
            kinds.add(facts.kind.clone());
            languages.add(facts.language.clone());
        }
    }

    let total = ever.len();
    let retired = total.saturating_sub(tip.len());
    println!("== span-coherence population ==");
    println!("fixture:            {}", layout.working_dir().display());
    println!("semantic changes:   {}", snapshot.changes.len());
    println!("entity deltas:      {deltas_seen}");
    println!();
    println!("entity identities the history ever held: {total}");
    println!("  alive at the workspace tip:            {}", tip.len());
    println!("  retired by a later change:             {retired}");
    if tip.len() > 0 {
        println!(
            "  ratio (ever / tip):                    {:.2}x",
            total as f64 / tip.len() as f64
        );
    }
    println!();
    println!("span coherence over the whole population:");
    println!("  carrying a blob_hash (verifiable):     {with_digest}");
    println!(
        "  carrying none (Unverified):            {}",
        total - with_digest
    );
    println!("  span + file_origin (reaches slicing):  {sliceable}");
    println!("    of those, Unverified:                {sliceable_unverified}");
    println!();
    println!("the retired remainder, which only the larger population contains:");
    println!("  retired AND sliceable:                 {retired_sliceable}");
    println!("  of those, whose file still exists:     {path_live_today}");
    println!();
    kinds.report("Unverified by kind:", total - with_digest);
    languages.report("Unverified by language:", total - with_digest);

    // This harness reports; it does not gate. The one assertion is that it
    // measured something, so an empty read cannot be mistaken for a population
    // that is entirely coherent.
    assert!(
        total > 0,
        "the fixture authority holds no entity deltas, so nothing was measured"
    );
}

struct EntityFacts {
    has_digest: bool,
    sliceable: bool,
    kind: String,
    language: String,
    path: String,
}

/// Replay the workspace's first-parent lineage into the identity set alive at
/// its tip, which is the count `kin init` and `kin status` publish.
fn tip_entity_ids(
    snapshot: &kin_db::GraphSnapshot,
    head: Option<kin_model::SemanticChangeId>,
    overlay: &[EntityDelta],
) -> HashSet<EntityId> {
    let mut ids = HashSet::new();
    let Some(head) = head else {
        return ids;
    };

    let mut lineage = Vec::new();
    let mut current = Some(head);
    let mut seen = HashSet::new();
    while let Some(change_id) = current {
        if !seen.insert(change_id) {
            break;
        }
        let Some(change) = snapshot.changes.get(&change_id) else {
            break;
        };
        current = change.parents.first().copied();
        lineage.push(change);
    }
    for change in lineage.into_iter().rev() {
        for delta in &change.entity_deltas {
            match delta {
                EntityDelta::Added { new } => {
                    ids.insert(new.id);
                }
                EntityDelta::Removed { old } => {
                    ids.remove(&old.id);
                }
                EntityDelta::Modified { .. } => {}
            }
        }
    }
    for delta in overlay {
        match delta {
            EntityDelta::Added { new } => {
                ids.insert(new.id);
            }
            EntityDelta::Removed { old } => {
                ids.remove(&old.id);
            }
            EntityDelta::Modified { .. } => {}
        }
    }
    ids
}
