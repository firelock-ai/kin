// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! The admission ladder must account for the whole of `init`.
//!
//! A memory profile names a phase by asking which span was open when the peak
//! sample was taken. That question has no answer while `init` is running work
//! no span covers, and the failure is silent: the profile still renders, every
//! phase still reports a number, and the peak is simply charged to nothing.
//!
//! This is not hypothetical. Admitting a 6,733-commit repository peaked in a
//! 5.4 second stretch between `kin.init.commit_bootstrap_transaction` closing
//! and the next span opening, with 41.3 seconds of a 518.9 second run uncovered
//! in total. Only `kin.command` and `kin.init` were open at that instant and
//! both span the entire run, so the reading named nothing and a lever could not
//! be chosen from it. The run had to be thrown away.
//!
//! So the guard is coverage, not duration. It asserts that the top level of the
//! ladder accounts for essentially all of the wall clock that `init_from_git`
//! spends, which is the property a profile needs and the one that was missing.
//! It says nothing about how long any phase takes, because that is a machine
//! fact and this is a structural one.

mod support;

use std::path::Path;
use std::process::Command;
use std::sync::Mutex;
use std::time::Instant;

use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::Layer;

/// Commits in the fixture history. Enough that the phases are separable in
/// wall clock; small enough that this runs in the default suite.
const COMMITS: usize = 12;
const MODULES: usize = 4;
const ITEMS_PER_MODULE: usize = 4;

/// Share of `init_from_git`'s wall clock the top-level ladder must account for.
///
/// Set from measurement rather than taste. With the ladder complete this
/// fixture covers essentially all of the call; the run that motivated the guard
/// covered 92.0 percent and had a 5.4 second hole in it. The bar sits between
/// those, close enough to 1.0 that removing any single ladder span fails it and
/// far enough from 1.0 that span entry and exit bookkeeping does not.
const REQUIRED_COVERAGE: f64 = 0.97;

/// One span boundary, with the time it happened.
struct Edge {
    phase: &'static str,
    entering: bool,
    at_ms: f64,
}

static EDGES: Mutex<Vec<Edge>> = Mutex::new(Vec::new());
static START: Mutex<Option<Instant>> = Mutex::new(None);

fn now_ms() -> f64 {
    let guard = START.lock().expect("clock poisoned");
    match *guard {
        Some(start) => start.elapsed().as_secs_f64() * 1000.0,
        None => 0.0,
    }
}

/// Records when each admission phase opens and closes.
///
/// Deliberately a separate layer from `support::PhaseHeapLayer` rather than a
/// field added to it: the heap probes read a process-wide allocation counter,
/// and adding a clock read to their hot path would change the thing they
/// measure.
struct LadderTimingLayer;

impl<S> Layer<S> for LadderTimingLayer
where
    S: tracing::Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_enter(&self, id: &tracing::span::Id, ctx: Context<'_, S>) {
        if let Some(span) = ctx.span(id) {
            let phase = span.name();
            if phase.starts_with(support::PHASE_PREFIX) {
                let at_ms = now_ms();
                if let Ok(mut edges) = EDGES.lock() {
                    edges.push(Edge { phase, entering: true, at_ms });
                }
            }
        }
    }

    fn on_exit(&self, id: &tracing::span::Id, ctx: Context<'_, S>) {
        if let Some(span) = ctx.span(id) {
            let phase = span.name();
            if phase.starts_with(support::PHASE_PREFIX) {
                let at_ms = now_ms();
                if let Ok(mut edges) = EDGES.lock() {
                    edges.push(Edge { phase, entering: false, at_ms });
                }
            }
        }
    }
}

fn git(repo: &Path, args: &[&str]) {
    let status = Command::new("git")
        .current_dir(repo)
        .args(args)
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .env("GIT_AUTHOR_NAME", "Kin Fixture")
        .env("GIT_AUTHOR_EMAIL", "fixture@firelock.ai")
        .env("GIT_COMMITTER_NAME", "Kin Fixture")
        .env("GIT_COMMITTER_EMAIL", "fixture@firelock.ai")
        .output()
        .unwrap_or_else(|error| panic!("git {args:?} failed to start: {error}"));
    assert!(
        status.status.success(),
        "git {args:?} failed: {}",
        String::from_utf8_lossy(&status.stderr)
    );
}

fn build_history(repo: &Path) {
    std::fs::create_dir_all(repo.join("src")).unwrap();
    git(repo, &["init", "--initial-branch=main"]);
    git(repo, &["config", "user.name", "Kin Fixture"]);
    git(repo, &["config", "user.email", "fixture@firelock.ai"]);
    std::fs::write(repo.join("Cargo.toml"), b"[package]\nname = \"fixture\"\n").unwrap();
    for commit in 0..COMMITS {
        for module in 0..MODULES {
            let mut body = String::new();
            for item in 0..ITEMS_PER_MODULE {
                body.push_str(&format!(
                    "pub struct Item{module}_{item}_{commit} {{ pub field: u32 }}\n\
                     impl Item{module}_{item}_{commit} {{\n\
                     pub fn build() -> Self {{ Self {{ field: {commit} }} }}\n\
                     }}\n"
                ));
            }
            std::fs::write(repo.join(format!("src/mod_{module}.rs")), body.as_bytes()).unwrap();
        }
        git(repo, &["add", "-A"]);
        git(repo, &["commit", "-m", &format!("commit {commit}")]);
    }
}

/// Top-level ladder intervals, reconstructed from the boundary stream.
///
/// A phase is top level when it opens while no other sampled phase is open.
/// Nested phases are folded into their parent, which is what makes this a test
/// of the ladder rather than of every span init happens to emit.
fn top_level_intervals(edges: &[Edge]) -> Vec<(&'static str, f64, f64)> {
    let mut out = Vec::new();
    let mut depth = 0usize;
    let mut open: Option<(&'static str, f64)> = None;
    for edge in edges {
        if edge.entering {
            if depth == 0 {
                open = Some((edge.phase, edge.at_ms));
            }
            depth += 1;
        } else {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                if let Some((phase, start)) = open.take() {
                    out.push((phase, start, edge.at_ms));
                }
            }
        }
    }
    out
}

#[test]
fn the_admission_ladder_accounts_for_the_whole_of_init() {
    let workspace = tempfile::tempdir().unwrap();
    let repo = workspace.path().join("source");
    std::fs::create_dir(&repo).unwrap();
    build_history(&repo);
    let repo = repo.canonicalize().unwrap();

    let _ = tracing_subscriber::registry()
        .with(LadderTimingLayer)
        .try_init();
    *START.lock().unwrap() = Some(Instant::now());
    EDGES.lock().unwrap().clear();

    let started = Instant::now();
    kin_core::init_from_git(&repo).expect("admit the fixture repository");
    let total_ms = started.elapsed().as_secs_f64() * 1000.0;

    let edges = EDGES.lock().expect("edges poisoned");
    let ladder = top_level_intervals(&edges);
    assert!(
        !ladder.is_empty(),
        "no admission phase spans were recorded at all, so this guard proved nothing. \
         Either the ladder stopped emitting `{}` spans or the layer is not installed.",
        support::PHASE_PREFIX
    );

    let covered: f64 = ladder.iter().map(|(_, s, e)| e - s).sum();
    let coverage = covered / total_ms;

    let mut worst = (0.0f64, "start of init", ladder[0].0);
    let mut cursor = 0.0f64;
    for (phase, start, end) in &ladder {
        let gap = start - cursor;
        if gap > worst.0 {
            worst = (gap, "previous phase", phase);
        }
        cursor = cursor.max(*end);
    }

    println!(
        "ladder covered {covered:.0} ms of {total_ms:.0} ms ({:.1}%), {} top-level phases, \
         largest gap {:.0} ms before {}",
        coverage * 100.0,
        ladder.len(),
        worst.0,
        worst.2,
    );
    for (phase, start, end) in &ladder {
        println!("  {phase:<52} {start:>9.0} -> {end:>9.0} ms");
    }

    assert!(
        coverage >= REQUIRED_COVERAGE,
        "the admission ladder accounts for only {:.1}% of init_from_git's {total_ms:.0} ms, \
         under the {:.1}% this guard requires, with the largest unnamed stretch {:.0} ms \
         immediately before `{}`. Work that no span covers is work a memory profile charges \
         to no phase: when this last happened the peak of a real conversion landed in such a \
         stretch and the whole measurement had to be discarded. Wrap the uncovered work in an \
         `info_span!(\"{}...\")` rather than lowering this bar.",
        coverage * 100.0,
        REQUIRED_COVERAGE * 100.0,
        worst.0,
        worst.2,
        support::PHASE_PREFIX,
    );
}
