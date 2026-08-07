// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Measure the population a ranked read actually draws from, and the
//! span-coherence state of every entity in it.
//!
//! `SpanCoherence::Unverified` is the state an entity reaches when it records no
//! `blob_hash`, and today a read in that state slices anyway. Whether that
//! should tighten into a refusal is a decision about a POPULATION, not about a
//! rule: a tightening that refuses a handful of entities is a correctness fix,
//! and the same tightening over a population that is mostly unverified takes the
//! product offline. The counts that decision needs were never measured, because
//! nothing enumerated the set a ranked candidate is drawn from.
//!
//! This harness enumerates it off a real store. It is `#[ignore]`d and reads a
//! fixture path from the environment, so it never runs in CI and never needs a
//! corpus checked in:
//!
//! ```text
//! KIN_SPAN_COHERENCE_FIXTURE=/path/to/initialized/repo \
//!   cargo test -p kin-cli --test span_coherence_population -- --ignored --nocapture
//! ```
//!
//! It opens the persisted snapshot READ-ONLY through the same local locate path
//! the CLI uses, so it neither starts a daemon, nor advances the store
//! generation, nor triggers an embedding pass.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use kin_db::EntityStore;

/// One tallied dimension of the population.
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
        for (key, count) in rows.iter().take(15) {
            let share = if total == 0 {
                0.0
            } else {
                (**count as f64 / total as f64) * 100.0
            };
            println!("    {count:>8}  {share:>5.1}%  {key}");
        }
        if rows.len() > 15 {
            println!("    ... {} more keys", rows.len() - 15);
        }
    }
}

#[test]
#[ignore = "measurement harness: set KIN_SPAN_COHERENCE_FIXTURE to an initialized repository"]
fn report_ranked_span_coherence_population() {
    let fixture = std::env::var("KIN_SPAN_COHERENCE_FIXTURE")
        .expect("set KIN_SPAN_COHERENCE_FIXTURE to a repository that has been `kin init`ed");
    let fixture = PathBuf::from(fixture);
    let layout = kin_core::KinLayout::discover(&fixture)
        .unwrap_or_else(|| panic!("no .kin store found at or above {}", fixture.display()));

    let snapshot = kin_cli::backend::open_snapshot_local_for_locate(&layout)
        .expect("open the persisted snapshot read-only");
    let graph = snapshot.graph();
    let entities = graph
        .list_all_entities()
        .expect("enumerate every entity the persisted graph holds");

    let total = entities.len();
    let mut with_digest = 0_usize;
    let mut without_digest = 0_usize;
    let mut sliceable = 0_usize;
    let mut sliceable_without_digest = 0_usize;
    let mut superseded = 0_usize;
    let mut path_present_today = 0_usize;
    let mut path_absent_today = 0_usize;
    let mut kinds = Tally::default();
    let mut languages = Tally::default();
    let mut changes = Tally::default();
    let mut path_cache: BTreeMap<String, bool> = BTreeMap::new();

    for entity in &entities {
        let has_digest = entity.metadata.extra.contains_key("blob_hash");
        if has_digest {
            with_digest += 1;
        } else {
            without_digest += 1;
        }
        // A candidate only reaches the slicing seam with both a span to cut and
        // a file to cut it from. Entities without them return "no source" and
        // never consult coherence at all, so they are not part of the population
        // a tightening would change.
        let can_slice = entity.span.is_some() && entity.file_origin.is_some();
        if can_slice {
            sliceable += 1;
            if !has_digest {
                sliceable_without_digest += 1;
            }
        }
        if entity.superseded_by.is_some() {
            superseded += 1;
        }
        if let Some(origin) = entity.file_origin.as_ref() {
            let path = origin.to_string();
            let present = *path_cache
                .entry(path.clone())
                .or_insert_with(|| layout.working_dir().join(Path::new(&path)).exists());
            if present {
                path_present_today += 1;
            } else {
                path_absent_today += 1;
            }
        }
        if !has_digest {
            kinds.add(format!("{:?}", entity.kind));
            languages.add(entity.language.to_string());
            changes.add(match entity.created_in.as_ref() {
                Some(change) => format!("created_in {change}"),
                None => "created_in none".to_string(),
            });
        }
    }

    println!("== span-coherence population ==");
    println!("fixture: {}", layout.working_dir().display());
    println!("store:   {}", layout.root().display());
    println!("entities in persisted graph:      {total}");
    println!("  carrying a blob_hash digest:    {with_digest}");
    println!("  carrying none (Unverified):     {without_digest}");
    println!("  span + file_origin (sliceable): {sliceable}");
    println!("    of those, Unverified:         {sliceable_without_digest}");
    println!("  marked superseded_by:           {superseded}");
    println!("  file_origin present on disk:    {path_present_today}");
    println!("  file_origin absent on disk:     {path_absent_today}");
    println!();
    kinds.report("Unverified entities by kind:", without_digest);
    languages.report("Unverified entities by language:", without_digest);
    changes.report("Unverified entities by introducing change:", without_digest);

    // This harness reports; it does not gate. The single assertion is that it
    // measured something, so an empty store cannot be mistaken for a population
    // that is entirely coherent.
    assert!(
        total > 0,
        "the fixture store holds no entities, so nothing was measured"
    );
}
