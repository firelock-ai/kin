//! Convert graph data from KuzuDB to KinDB backend.

use anyhow::Result;
use kin_model::graph::GraphStore;
use std::collections::{HashMap, HashSet};

pub fn run() -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;

    let kuzu = kin_graph::KuzuGraphStore::open_read_only(&layout.graph_dir())?;

    eprintln!("Reading KuzuDB graph...");
    let entities = kuzu.list_all_entities()?;
    eprintln!("  {} entities", entities.len());

    let kindb = kin_db::InMemoryGraph::new();
    let mut rel_count = 0usize;

    for entity in &entities {
        kindb.upsert_entity(entity)?;
        let relations = kuzu.get_all_relations_for_entity(&entity.id)?;
        for rel in &relations {
            // Avoid duplicate relations (they appear on both src and dst)
            if rel.src == entity.id {
                kindb.upsert_relation(rel)?;
                rel_count += 1;
            }
        }
    }

    let branches = kuzu.list_branches()?;
    let changes = collect_reachable_changes(&kuzu, &branches)?;
    for change in &changes {
        kindb.create_change(change)?;
    }
    eprintln!("  {} reachable changes", changes.len());

    // Also copy branches
    for branch in &branches {
        kindb.create_branch(branch)?;
    }
    eprintln!("  {} branches", branches.len());

    // Copy shallow files
    let shallow = kuzu.list_shallow_files()?;
    for sf in &shallow {
        kindb.upsert_shallow_file(sf)?;
    }
    eprintln!("  {} shallow files", shallow.len());

    let work_items = kuzu.list_work_items(&kin_model::WorkFilter::default())?;
    for item in &work_items {
        kindb.create_work_item(item)?;
    }
    let work_link_count = copy_work_links(&kuzu, &kindb, &work_items)?;
    eprintln!(
        "  {} work items, {} reconstructable work links",
        work_items.len(),
        work_link_count
    );

    let annotations = kuzu.list_annotations(&kin_model::AnnotationFilter {
        include_stale: true,
        ..Default::default()
    })?;
    for annotation in &annotations {
        kindb.create_annotation(annotation)?;
    }
    eprintln!("  {} annotations", annotations.len());

    let contracts = kuzu.list_contracts()?;
    for contract in &contracts {
        kindb.create_contract(contract)?;
    }
    eprintln!("  {} contracts", contracts.len());

    let verification = copy_verification(
        &kuzu,
        &kindb,
        &entities,
        &contracts,
        &work_items,
    )?;
    eprintln!(
        "  {} tests, {} runs, {} mock hints",
        verification.tests,
        verification.runs,
        verification.mock_hints
    );

    let actors = kuzu.list_actors()?;
    for actor in &actors {
        kindb.create_actor(actor)?;
    }
    let delegation_count = copy_delegations(&kuzu, &kindb, &actors)?;
    let approval_count = copy_approvals(&kuzu, &kindb, &changes)?;
    let audit_events = kuzu.query_audit_events(None, usize::MAX)?;
    for event in &audit_events {
        kindb.record_audit_event(event)?;
    }
    eprintln!(
        "  {} actors, {} delegations, {} approvals, {} audit events",
        actors.len(),
        delegation_count,
        approval_count,
        audit_events.len()
    );

    let sessions = kuzu.list_sessions()?;
    for session in &sessions {
        kindb.upsert_session(session)?;
    }
    let intents = kuzu.list_all_intents()?;
    for intent in &intents {
        kindb.register_intent(intent)?;
    }
    let downstream_warning_count = copy_downstream_warnings(&kuzu, &kindb, &entities)?;
    eprintln!(
        "  {} sessions, {} intents, {} downstream warnings",
        sessions.len(),
        intents.len(),
        downstream_warning_count
    );

    eprintln!(
        "KinDB graph: {} entities, {} relations",
        kindb.entity_count(),
        rel_count
    );

    let kindb_path = crate::backend::kindb_snapshot_path(&layout);
    if let Some(parent) = kindb_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let snap = kin_db::SnapshotManager::new(&kindb_path);
    snap.swap(kindb);
    snap.save()?;

    eprintln!("Saved KinDB snapshot to {}", kindb_path.display());

    // Generate embeddings for all entities
    eprintln!("Generating embeddings...");
    let embedder = kin_db::CodeEmbedder::new()?;
    let mut vectors: HashMap<String, Vec<f32>> = HashMap::with_capacity(entities.len());

    for entity in &entities {
        let text =
            kin_db::embed::format_entity_text(&entity.name, &entity.signature, "");
        if text.is_empty() {
            continue;
        }
        let embedding = embedder.embed_entity(&entity.name, &entity.signature, "")?;
        vectors.insert(entity.id.to_string(), embedding);
    }
    eprintln!("  {} embeddings generated", vectors.len());

    let vectors_path = crate::backend::kindb_vectors_path(&layout);
    let vectors_json = serde_json::to_vec(&vectors)?;
    std::fs::write(&vectors_path, &vectors_json)?;
    eprintln!("Saved vectors to {}", vectors_path.display());

    eprintln!("KinDB snapshot is ready at {}", kindb_path.display());
    Ok(())
}

fn collect_reachable_changes(
    kuzu: &kin_graph::KuzuGraphStore,
    branches: &[kin_model::Branch],
) -> Result<Vec<kin_model::SemanticChange>> {
    let mut visited = HashSet::new();
    let mut stack: Vec<kin_model::SemanticChangeId> =
        branches.iter().map(|branch| branch.head).collect();
    let mut changes = Vec::new();

    while let Some(change_id) = stack.pop() {
        if !visited.insert(change_id) {
            continue;
        }
        if let Some(change) = kuzu.get_change(&change_id)? {
            stack.extend(change.parents.iter().copied());
            changes.push(change);
        }
    }

    Ok(changes)
}

fn copy_work_links(
    kuzu: &kin_graph::KuzuGraphStore,
    kindb: &kin_db::InMemoryGraph,
    work_items: &[kin_model::WorkItem],
) -> Result<usize> {
    let mut count = 0usize;

    for item in work_items {
        for scope in &item.scopes {
            kindb.create_work_link(&kin_model::WorkLink::Affects {
                work_id: item.work_id,
                scope: scope.clone(),
            })?;
            count += 1;
        }

        for child in kuzu.get_child_work_items(&item.work_id)? {
            kindb.create_work_link(&kin_model::WorkLink::DecomposesTo {
                parent: item.work_id,
                child: child.work_id,
            })?;
            count += 1;
        }

        for scope in kuzu.get_implementors(&item.work_id)? {
            kindb.create_work_link(&kin_model::WorkLink::Implements {
                scope,
                work_id: item.work_id,
            })?;
            count += 1;
        }
    }

    Ok(count)
}

struct VerificationCounts {
    tests: usize,
    runs: usize,
    mock_hints: usize,
}

fn copy_verification(
    kuzu: &kin_graph::KuzuGraphStore,
    kindb: &kin_db::InMemoryGraph,
    entities: &[kin_model::Entity],
    contracts: &[kin_model::Contract],
    work_items: &[kin_model::WorkItem],
) -> Result<VerificationCounts> {
    let mut tests: HashMap<kin_model::TestId, kin_model::TestCase> = HashMap::new();
    let mut entity_links = HashSet::new();
    let mut contract_links = HashSet::new();
    let mut work_links = HashSet::new();

    for entity in entities {
        for test in kuzu.get_tests_for_entity(&entity.id)? {
            entity_links.insert((test.test_id, entity.id));
            tests.entry(test.test_id).or_insert(test);
        }
    }

    for contract in contracts {
        let contract_id = kin_model::ContractId(contract.id.0);
        for test in kuzu.get_tests_covering_contract(&contract_id)? {
            contract_links.insert((test.test_id, contract_id));
            tests.entry(test.test_id).or_insert(test);
        }
    }

    for work_item in work_items {
        for test in kuzu.get_tests_verifying_work(&work_item.work_id)? {
            work_links.insert((test.test_id, work_item.work_id));
            tests.entry(test.test_id).or_insert(test);
        }
    }

    for test in tests.values() {
        kindb.create_test_case(test)?;
    }
    for (test_id, entity_id) in &entity_links {
        kindb.create_test_covers_entity(test_id, entity_id)?;
    }
    for (test_id, contract_id) in &contract_links {
        kindb.create_test_covers_contract(test_id, contract_id)?;
    }
    for (test_id, work_id) in &work_links {
        kindb.create_test_verifies_work(test_id, work_id)?;
    }

    let mut run_ids = HashSet::new();
    let mut runs = 0usize;
    let mut hint_ids = HashSet::new();
    let mut mock_hints = 0usize;
    for test_id in tests.keys() {
        for run in kuzu.list_runs_for_test(test_id)? {
            if run_ids.insert(run.run_id) {
                kindb.create_verification_run(&run)?;
                runs += 1;
            }
        }
        for hint in kuzu.get_mock_hints_for_test(test_id)? {
            if hint_ids.insert(hint.hint_id) {
                kindb.create_mock_hint(&hint)?;
                mock_hints += 1;
            }
        }
    }

    Ok(VerificationCounts {
        tests: tests.len(),
        runs,
        mock_hints,
    })
}

fn copy_delegations(
    kuzu: &kin_graph::KuzuGraphStore,
    kindb: &kin_db::InMemoryGraph,
    actors: &[kin_model::Actor],
) -> Result<usize> {
    let mut seen = HashSet::new();
    let mut count = 0usize;
    for actor in actors {
        for delegation in kuzu.get_delegations_for_actor(&actor.actor_id)? {
            if seen.insert(delegation.delegation_id) {
                kindb.create_delegation(&delegation)?;
                count += 1;
            }
        }
    }
    Ok(count)
}

fn copy_approvals(
    kuzu: &kin_graph::KuzuGraphStore,
    kindb: &kin_db::InMemoryGraph,
    changes: &[kin_model::SemanticChange],
) -> Result<usize> {
    let mut seen = HashSet::new();
    let mut count = 0usize;
    for change in changes {
        for approval in kuzu.get_approvals_for_change(&change.id)? {
            if seen.insert(approval.approval_id) {
                kindb.create_approval(&approval)?;
                count += 1;
            }
        }
    }
    Ok(count)
}

fn copy_downstream_warnings(
    kuzu: &kin_graph::KuzuGraphStore,
    kindb: &kin_db::InMemoryGraph,
    entities: &[kin_model::Entity],
) -> Result<usize> {
    let mut seen = HashSet::new();
    let mut count = 0usize;
    for entity in entities {
        for intent in kuzu.downstream_warnings_for_entity(&entity.id)? {
            let key = (intent.intent_id, entity.id);
            if seen.insert(key) {
                kindb.create_downstream_warning(
                    &intent.intent_id,
                    &entity.id,
                    "migrated from KuzuDB",
                )?;
                count += 1;
            }
        }
    }
    Ok(count)
}
