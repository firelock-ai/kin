// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! What planning a one-file commit holds alive, on a repository a user converts.
//!
//! FIR-2782: a 1.5 KB docstring edit to one file was OOM-killed planning
//! against a 2.1 GiB psf/requests store, the daemon reaching 10 GiB resident in
//! phase `plan_transaction` on a 12 GiB box. The synthetic fixtures cannot
//! price that. FIR-2615's closing measurement showed peak follows the graph,
//! meaning tracked files and CHANGE COUNT, and not bytes on disk, and the one
//! fixture available to it commits exactly one change at any file count, so the
//! change-map half of every whole-graph copy was absent from it at every size.
//! A converted repository carries thousands of changes, which is the axis that
//! was never measured.
//!
//! Live heap, not resident set, for the reason `support` gives: resident set
//! keeps counting memory the allocator has freed, so it credits a phase with
//! allocation it released. The fixes those two need are opposite.
//!
//! Not a gate. It asserts nothing about a ceiling and takes a repository from
//! the environment, so it reports rather than grades.
//!
//! ```text
//! KIN_HEAP_REPO=/path/to/clone cargo test --release -p kin-core \
//!     --test commit_plan_real_repo_heap_attribution -- --ignored --nocapture
//! ```

mod support;

use std::path::{Path, PathBuf};
use std::process::Command;

#[global_allocator]
static ALLOC: support::Counting = support::Counting;

fn mib(bytes: usize) -> f64 {
    bytes as f64 / 1_048_576.0
}

/// One measured span: what it grew the high-water mark by, and what it kept.
struct Term {
    what: &'static str,
    grew: usize,
    retained: usize,
}

/// Measure one closure's live-heap growth and retention.
///
/// `grew` is the peak reached inside the closure above the live heap on entry,
/// which is what an OOM killer sees. `retained` is what is still live once the
/// value is dropped, which is what a resident daemon carries. A term that grows
/// a gigabyte and frees it, and one that grows a gigabyte and holds it, need
/// opposite fixes, so both are reported.
fn measure<T>(what: &'static str, work: impl FnOnce() -> T) -> (Term, T) {
    let before = support::live();
    support::reset_peak();
    let value = work();
    let grew = support::peak().saturating_sub(before);
    let retained = support::live().saturating_sub(before);
    (
        Term {
            what,
            grew,
            retained,
        },
        value,
    )
}

fn stage_copy(source: &Path, into: &Path) -> PathBuf {
    let staged = into.join("source");
    let status = Command::new("cp")
        .args(["-a".as_ref(), source.as_os_str(), staged.as_os_str()])
        .status()
        .expect("cp failed to start");
    assert!(status.success(), "cp -a {source:?} {staged:?} failed");
    staged.canonicalize().expect("canonicalize staged copy")
}

#[test]
#[ignore = "converts a real repository named by KIN_HEAP_REPO and takes minutes"]
fn planning_a_one_file_commit_reports_where_the_peak_is() {
    let Some(source) = std::env::var_os("KIN_HEAP_REPO") else {
        panic!("KIN_HEAP_REPO must name a non-shallow Git clone to convert");
    };
    let source = PathBuf::from(source);
    assert!(
        source.join(".git").exists(),
        "{source:?} is not a Git checkout"
    );

    let workspace = tempfile::tempdir().expect("scratch workspace");

    // Converting takes about eleven minutes on this corpus, so a second arm can
    // point at a store the first one already built. The default is still a
    // fresh conversion, because a reused store is only as trustworthy as
    // whoever last wrote to it.
    let repo = match std::env::var_os("KIN_HEAP_CONVERTED") {
        Some(existing) => PathBuf::from(existing),
        None => {
            let repo = stage_copy(&source, workspace.path());
            // Its own peak is the conversion's, not the plan's, and charging
            // one to the other is the single-process mistake the FIR-2615 lane
            // documented. The counters are re-based afterwards.
            kin_core::init_from_git(&repo).expect("convert the repository");
            repo
        }
    };

    let layout = kin_core::KinLayout::discover(&repo).expect("layout for the converted repo");
    let binding =
        kin_core::LocalRepositoryAuthorityBinding::from_layout(&layout).expect("authority binding");
    let workspace_id = binding.workspace_id();

    // What a daemon holds once the store is merely OPEN. Every term below is
    // reported against this, because FIR-2615 found most of a commit's peak is
    // residency rather than the commit.
    let resident_before_open = support::live();
    let (open_term, manager) = measure("open the authority", || {
        binding.open_manager().expect("open authority manager")
    });
    let lease = manager.read_authority();
    let resident = support::live();
    let mut terms = vec![open_term];

    // Candidate 1: the authority's own workspace graph, one side of the
    // semantic diff. FIR-2651 stopped the workspace COMPARISON bases carrying
    // the change map, but this is a different caller and still asks for a
    // carried base, so it is measured rather than assumed.
    let (term, authority_workspace_graph) = measure("lease.workspace_graph_snapshot", || {
        lease
            .workspace_graph_snapshot(&workspace_id)
            .expect("workspace graph snapshot readable")
            .expect("authority has a graph snapshot for this workspace")
    });
    terms.push(term);

    // Candidate 2: the desired side. The daemon holds a live workspace graph
    // and exports it with `to_snapshot`. The graph is built HERE from the
    // workspace snapshot rather than from `lease.snapshot()`, because those are
    // different surfaces: the authority snapshot carries the change DAG and no
    // entities at all, so an export measured off it prices a graph the planner
    // never diffs and would report the two compared domains as free.
    let (term, graph) = measure("build the workspace graph (probe scaffolding)", || {
        let base = lease
            .workspace_graph_snapshot(&workspace_id)
            .expect("workspace graph snapshot readable")
            .expect("authority has a graph snapshot for this workspace");
        kin_db::InMemoryGraph::from_snapshot_without_text_index(base)
            .expect("build the prospective graph")
    });
    terms.push(term);

    let (term, desired) = measure("graph.to_snapshot (all seven sub-stores)", || {
        graph.to_snapshot()
    });
    terms.push(term);

    // The split that decides the fix: what the two domains the diff reads cost,
    // against what the whole export cost.
    let (term, needed) = measure("only the two domains the diff reads", || {
        (desired.entities.clone(), desired.relations.clone())
    });
    terms.push(term);
    drop(needed);

    let (term, change_map) = measure("only the change map", || {
        (desired.changes.clone(), desired.change_children.clone())
    });
    terms.push(term);
    drop(change_map);

    println!("\nrepository {source:?}");
    println!(
        "authority workspace graph: entities {}  relations {}  changes {}  tree {}",
        authority_workspace_graph.entities.len(),
        authority_workspace_graph.relations.len(),
        authority_workspace_graph.changes.len(),
        authority_workspace_graph.resolved_tree.len(),
    );
    println!(
        "exported desired graph:    entities {}  relations {}  changes {}  tree {}",
        desired.entities.len(),
        desired.relations.len(),
        desired.changes.len(),
        desired.resolved_tree.len(),
    );
    println!(
        "\nlive heap once the store is merely open: {:.1} MiB",
        mib(resident.saturating_sub(resident_before_open))
    );
    println!("\n{:<48} {:>12} {:>12}", "term", "grew MiB", "retained MiB");
    for term in &terms {
        println!(
            "{:<48} {:>12.1} {:>12.1}",
            term.what,
            mib(term.grew),
            mib(term.retained)
        );
    }
    println!("\npeak live heap overall: {:.1} MiB", mib(support::peak()));

    drop(authority_workspace_graph);
    drop(desired);
}
