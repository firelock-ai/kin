use anyhow::{anyhow, bail, Result};
use kin_model::{
    Entity, EntityFilter, FilePathId, GraphStore, Hash256, TestCase, TestRunner, Timestamp,
    VerificationRun, VerificationRunId, VerificationStatus, WorkItem, WorkScope,
};
use kin_runtime::workspace::record_verification_evidence;
use std::collections::HashSet;

/// `kin verify <entity>` — Check verification / test coverage for an entity.
///
/// Shows per-entity test linkage and overall coverage summary.
pub async fn run(entity: String) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow!("not a Kin repository (no .kin/ found)"))?;
    let snap = kin_db::SnapshotManager::open(crate::backend::kindb_snapshot_path(&layout))?;
    let graph = snap.graph();

    let filter = EntityFilter {
        name_pattern: Some(entity.clone()),
        ..Default::default()
    };
    let entities = graph.query_entities(&filter)?;

    if entities.is_empty() {
        println!("No entity matching '{}' found.", entity);
        return Ok(());
    }

    let mut covered_count = 0usize;
    let mut uncovered_count = 0usize;

    for ent in &entities {
        let tests = graph.get_tests_for_entity(&ent.id)?;
        if tests.is_empty() {
            uncovered_count += 1;
            println!("  MISSING  {} ({:?})", ent.name, ent.kind);
        } else {
            covered_count += 1;
            println!(
                "  COVERED  {} ({:?}) — {} test(s)",
                ent.name,
                ent.kind,
                tests.len()
            );
            for test in &tests {
                println!(
                    "           - {} [{}] runner={}",
                    test.name, test.kind, test.runner
                );
            }
        }
    }

    println!();
    println!(
        "Matched {} entity(ies): {} covered, {} missing proof",
        entities.len(),
        covered_count,
        uncovered_count,
    );

    let summary = graph.get_coverage_summary()?;
    println!();
    println!("Repository Coverage:");
    println!(
        "  {}/{} entities covered ({:.1}%)",
        summary.covered_entities,
        summary.total_entities,
        summary.coverage_ratio * 100.0
    );
    if !summary.missing_proof.is_empty() {
        println!("  {} entities missing proof", summary.missing_proof.len());
    }

    Ok(())
}

/// `kin verify --summary` — Show repository-wide coverage summary only.
pub async fn summary() -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow!("not a Kin repository (no .kin/ found)"))?;
    let snap = kin_db::SnapshotManager::open(crate::backend::kindb_snapshot_path(&layout))?;
    let graph = snap.graph();

    let summary = graph.get_coverage_summary()?;

    println!("Repository Coverage:");
    println!(
        "  {}/{} entities covered ({:.1}%)",
        summary.covered_entities,
        summary.total_entities,
        summary.coverage_ratio * 100.0
    );

    if summary.missing_proof.is_empty() {
        println!("  All entities have linked proof.");
    } else {
        println!("  {} entities missing proof:", summary.missing_proof.len());
        for eid in &summary.missing_proof {
            if let Some(entity) = graph.get_entity(eid)? {
                println!("    - {} ({:?})", entity.name, entity.kind);
            } else {
                println!("    - {}", eid);
            }
        }
    }

    Ok(())
}

/// `kin verify --missing` — Show only entities without any linked test.
pub async fn missing() -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow!("not a Kin repository (no .kin/ found)"))?;
    let snap = kin_db::SnapshotManager::open(crate::backend::kindb_snapshot_path(&layout))?;
    let graph = snap.graph();

    let summary = graph.get_coverage_summary()?;

    if summary.missing_proof.is_empty() {
        println!("All {} entities have linked proof.", summary.total_entities);
        return Ok(());
    }

    println!(
        "Entities missing proof ({}/{}):",
        summary.missing_proof.len(),
        summary.total_entities
    );

    for eid in &summary.missing_proof {
        if let Some(entity) = graph.get_entity(eid)? {
            let file = entity
                .file_origin
                .as_ref()
                .map(|f| f.to_string())
                .unwrap_or_else(|| "unknown".to_string());
            println!("  - {} ({:?}) in {}", entity.name, entity.kind, file);
        } else {
            println!("  - {}", eid);
        }
    }

    Ok(())
}

/// `kin verify plan <entity> --depth 2` — Show the targeted proof set Kin would
/// use for verification, widened by downstream semantic impact.
pub async fn plan(entity: String, depth: u32) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow!("not a Kin repository (no .kin/ found)"))?;
    let snap = kin_db::SnapshotManager::open(crate::backend::kindb_snapshot_path(&layout))?;
    let graph = snap.graph();
    let plan = build_verification_plan(graph.as_ref(), &entity, depth)?;

    print_verification_plan(&plan);
    Ok(())
}

/// `kin verify run <entity> --runner cargo` — Execute a targeted runner and
/// record a persisted `VerificationRun`.
///
/// If linked tests exist for the entity, Kin drives the runner from that proof
/// set. Otherwise it falls back to an entity-name filter and still records a
/// proof run for the entity.
pub async fn run_verification(entity: String, runner: String, depth: u32) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow!("not a Kin repository (no .kin/ found)"))?;
    let snap = kin_db::SnapshotManager::open(crate::backend::kindb_snapshot_path(&layout))?;
    let graph = snap.graph();
    let plan = build_verification_plan(graph.as_ref(), &entity, depth)?;
    let test_runner = parse_runner(&runner);
    let cmd_str = build_runner_command(&test_runner, &plan.entity.name, &plan.tests);

    if plan.tests.is_empty() {
        println!(
            "No linked tests found for '{}'; falling back to an entity-scoped runner filter.",
            plan.entity.name
        );
    } else {
        print_verification_plan(&plan);
    }

    println!("Running: {}", cmd_str);

    let started_at = Timestamp::now();
    let start_instant = std::time::Instant::now();
    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(&cmd_str)
        .output();
    let duration = start_instant.elapsed();
    let finished_at = Timestamp::now();

    let (status, exit_code, evidence_text) = match output {
        Ok(out) => {
            let stdout = String::from_utf8_lossy(&out.stdout);
            let stderr = String::from_utf8_lossy(&out.stderr);
            let evidence = format!("=== STDOUT ===\n{}\n=== STDERR ===\n{}", stdout, stderr);
            let exit = out.status.code().unwrap_or(-1);
            let status = if out.status.success() {
                VerificationStatus::Passing
            } else {
                VerificationStatus::Failing
            };
            (status, exit, evidence)
        }
        Err(err) => {
            let evidence = format!("Failed to execute test runner: {}", err);
            (VerificationStatus::Failing, -1, evidence)
        }
    };

    let evidence_blob = store_evidence_blob(&layout, &evidence_text);
    let run_id = VerificationRunId::new();
    let verification_run = VerificationRun {
        run_id,
        test_ids: plan.tests.iter().map(|test| test.test_id).collect(),
        status,
        runner: test_runner,
        started_at,
        finished_at: Some(finished_at),
        duration_ms: Some(duration.as_millis() as u64),
        evidence_blob,
        exit_code: Some(exit_code),
    };
    let proved_work_ids = plan
        .proved_work_items
        .iter()
        .map(|work| work.work_id)
        .collect::<Vec<_>>();
    let proved_entity_ids = plan
        .proved_entities
        .iter()
        .map(|entity| entity.id)
        .collect::<Vec<_>>();

    record_verification_evidence(
        graph.as_ref(),
        &verification_run,
        &proved_entity_ids,
        &proved_work_ids,
    )
    .map_err(|err: Box<dyn std::error::Error>| anyhow!(err.to_string()))?;
    snap.save()?;

    println!();
    println!("VerificationRun recorded:");
    println!("  Run ID:   {}", run_id);
    println!("  Entity:   {} ({:?})", plan.entity.name, plan.entity.kind);
    println!("  Status:   {}", verification_run.status);
    println!("  Duration: {}ms", duration.as_millis());
    println!("  Exit:     {}", exit_code);
    println!("  Tests:    {}", verification_run.test_ids.len());
    println!("  Entities: {}", proved_entity_ids.len());
    println!("  Work:     {}", proved_work_ids.len());
    if let Some(ref blob) = verification_run.evidence_blob {
        println!("  Evidence: {}", blob);
    }

    Ok(())
}

#[derive(Debug, Clone)]
struct VerificationPlan {
    entity: Entity,
    depth: u32,
    direct: EntityProofSlice,
    impacted: Vec<EntityProofSlice>,
    tests: Vec<TestCase>,
    proved_entities: Vec<Entity>,
    proved_work_items: Vec<WorkItem>,
}

#[derive(Debug, Clone)]
struct EntityProofSlice {
    entity: Entity,
    tests: Vec<TestCase>,
    work_items: Vec<WorkItem>,
}

fn build_verification_plan<G>(graph: &G, entity_query: &str, depth: u32) -> Result<VerificationPlan>
where
    G: GraphStore,
    G::Error: std::fmt::Display + Send + Sync + 'static,
{
    let entity = resolve_entity(graph, entity_query)?;
    let direct = build_entity_proof_slice(graph, entity.clone())?;
    let impacted_entities = graph
        .get_downstream_impact(&entity.id, depth)
        .map_err(|err| anyhow!(err.to_string()))?;
    let mut impacted = Vec::new();
    for impacted_entity in impacted_entities {
        impacted.push(build_entity_proof_slice(graph, impacted_entity)?);
    }

    let mut seen_test_ids = HashSet::new();
    let mut tests = Vec::new();
    for test in &direct.tests {
        if seen_test_ids.insert(test.test_id) {
            tests.push(test.clone());
        }
    }
    for slice in &impacted {
        for test in &slice.tests {
            if seen_test_ids.insert(test.test_id) {
                tests.push(test.clone());
            }
        }
    }

    let mut proved_entities = Vec::new();
    let mut seen_entity_ids = HashSet::new();
    if seen_entity_ids.insert(entity.id) {
        proved_entities.push(entity.clone());
    }
    if !direct.tests.is_empty() {
        if seen_entity_ids.insert(direct.entity.id) {
            proved_entities.push(direct.entity.clone());
        }
    }
    for slice in &impacted {
        if !slice.tests.is_empty() && seen_entity_ids.insert(slice.entity.id) {
            proved_entities.push(slice.entity.clone());
        }
    }

    let mut proved_work_items = Vec::new();
    let mut seen_work_ids = HashSet::new();
    let selected_test_ids = tests
        .iter()
        .map(|test| test.test_id)
        .collect::<HashSet<_>>();
    for slice in std::iter::once(&direct).chain(impacted.iter()) {
        for work in &slice.work_items {
            let verifies = graph
                .get_tests_verifying_work(&work.work_id)
                .map_err(|err| anyhow!(err.to_string()))?;
            if verifies
                .iter()
                .any(|linked_test| selected_test_ids.contains(&linked_test.test_id))
                && seen_work_ids.insert(work.work_id)
            {
                proved_work_items.push(work.clone());
            }
        }
    }

    Ok(VerificationPlan {
        entity,
        depth,
        direct,
        impacted,
        tests,
        proved_entities,
        proved_work_items,
    })
}

fn build_entity_proof_slice<G>(graph: &G, entity: Entity) -> Result<EntityProofSlice>
where
    G: GraphStore,
    G::Error: std::fmt::Display + Send + Sync + 'static,
{
    let mut tests = graph
        .get_tests_for_entity(&entity.id)
        .map_err(|err| anyhow!(err.to_string()))?;
    let work_items = graph
        .get_work_for_scope(&WorkScope::Entity(entity.id))
        .map_err(|err| anyhow!(err.to_string()))?;
    let mut seen_test_ids = tests
        .iter()
        .map(|test| test.test_id)
        .collect::<HashSet<_>>();
    for work in &work_items {
        let linked_tests = graph
            .get_tests_verifying_work(&work.work_id)
            .map_err(|err| anyhow!(err.to_string()))?;
        for linked_test in linked_tests {
            if seen_test_ids.insert(linked_test.test_id) {
                tests.push(linked_test);
            }
        }
    }

    Ok(EntityProofSlice {
        entity,
        tests,
        work_items,
    })
}

fn print_verification_plan(plan: &VerificationPlan) {
    println!(
        "Targeted proof plan for {} ({:?})",
        plan.entity.name, plan.entity.kind
    );
    println!("  Impact depth: {}", plan.depth);
    println!("  Planned entities: {}", 1 + plan.impacted.len());
    println!(
        "  Direct scope: {} test(s), {} work item(s)",
        plan.direct.tests.len(),
        plan.direct.work_items.len()
    );

    if !plan.impacted.is_empty() {
        println!("  Impacted dependents:");
        for slice in &plan.impacted {
            println!(
                "    - {} ({:?}) — {} test(s), {} work item(s)",
                slice.entity.name,
                slice.entity.kind,
                slice.tests.len(),
                slice.work_items.len()
            );
        }
    }

    println!("  Selected proof set: {} test(s)", plan.tests.len());
    for test in &plan.tests {
        println!("    - {} [{}] runner={}", test.name, test.kind, test.runner);
    }

    if !plan.proved_work_items.is_empty() {
        println!("  Linked work items:");
        for work in &plan.proved_work_items {
            println!("    - {} ({})", work.title, work.work_id);
        }
    }
}

fn resolve_entity<G>(graph: &G, entity_query: &str) -> Result<Entity>
where
    G: GraphStore,
    G::Error: std::fmt::Display + Send + Sync + 'static,
{
    let filter = EntityFilter {
        name_pattern: Some(entity_query.to_string()),
        ..Default::default()
    };
    let entities = graph
        .query_entities(&filter)
        .map_err(|err| anyhow!(err.to_string()))?;

    match entities.as_slice() {
        [] => bail!("No entity matching '{}' found.", entity_query),
        [entity] => Ok(entity.clone()),
        many => {
            let preview = many
                .iter()
                .take(5)
                .map(|entity| entity.name.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            bail!(
                "Multiple entities match '{}': {}. Use a more exact name.",
                entity_query,
                preview
            );
        }
    }
}

fn parse_runner(runner: &str) -> TestRunner {
    match runner {
        "cargo" => TestRunner::Cargo,
        "jest" => TestRunner::Jest,
        "pytest" => TestRunner::Pytest,
        "go" => TestRunner::Go,
        "junit" => TestRunner::JUnit,
        other => TestRunner::Custom(other.to_string()),
    }
}

fn build_runner_command(test_runner: &TestRunner, entity_name: &str, tests: &[TestCase]) -> String {
    match test_runner {
        TestRunner::Cargo => {
            let filter = if tests.len() == 1 {
                tests[0].name.clone()
            } else {
                entity_name.to_string()
            };
            format!("cargo test {}", shell_quote(&filter))
        }
        TestRunner::Jest => {
            let pattern = if tests.is_empty() {
                entity_name.to_string()
            } else {
                tests
                    .iter()
                    .map(|test| test.name.as_str())
                    .collect::<Vec<_>>()
                    .join("|")
            };
            format!("npx jest --testNamePattern={}", shell_quote(&pattern))
        }
        TestRunner::Pytest => {
            let pattern = if tests.is_empty() {
                entity_name.to_string()
            } else {
                tests
                    .iter()
                    .map(|test| test.name.as_str())
                    .collect::<Vec<_>>()
                    .join(" or ")
            };
            format!("pytest -k {}", shell_quote(&pattern))
        }
        TestRunner::Go => {
            let pattern = if tests.is_empty() {
                entity_name.to_string()
            } else {
                tests
                    .iter()
                    .map(|test| test.name.as_str())
                    .collect::<Vec<_>>()
                    .join("|")
            };
            format!("go test -run {}", shell_quote(&pattern))
        }
        TestRunner::JUnit => {
            let pattern = if tests.is_empty() {
                entity_name.to_string()
            } else {
                tests
                    .iter()
                    .map(|test| test.name.as_str())
                    .collect::<Vec<_>>()
                    .join(",")
            };
            format!("mvn test -Dtest={}", shell_quote(&pattern))
        }
        TestRunner::Custom(command) => format!("{} {}", command, shell_quote(entity_name)),
    }
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn store_evidence_blob(layout: &kin_core::KinLayout, evidence_text: &str) -> Option<Hash256> {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(evidence_text.as_bytes());
    let result = hasher.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&result);
    let hash = Hash256::from_bytes(bytes);

    let blob_dir = layout.objects_dir();
    if blob_dir.exists() {
        let hex = hash.to_string();
        let shard_dir = blob_dir.join(&hex[..2]);
        let _ = std::fs::create_dir_all(&shard_dir);
        let blob_path = shard_dir.join(&hex[2..]);
        let _ = std::fs::write(&blob_path, evidence_text.as_bytes());
    }

    Some(hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kin_model::{
        EntityId, EntityKind, EntityMetadata, FingerprintAlgorithm, IdentityRef, LanguageId,
        Priority, Relation, RelationId, RelationKind, RelationOrigin, SemanticFingerprint,
        TestKind, Visibility, WorkStatus,
    };
    use std::path::{Path, PathBuf};
    use std::sync::{Mutex, OnceLock};

    fn current_dir_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    struct CurrentDirGuard {
        original: PathBuf,
    }

    impl CurrentDirGuard {
        fn enter(path: &Path) -> Self {
            let original = std::env::current_dir().unwrap();
            std::env::set_current_dir(path).unwrap();
            Self { original }
        }
    }

    impl Drop for CurrentDirGuard {
        fn drop(&mut self) {
            let _ = std::env::set_current_dir(&self.original);
        }
    }

    fn make_entity(name: &str, file: &str) -> Entity {
        Entity {
            id: EntityId::new(),
            kind: EntityKind::Function,
            name: name.to_string(),
            language: LanguageId::Rust,
            fingerprint: SemanticFingerprint {
                algorithm: FingerprintAlgorithm::V1TreeSitter,
                ast_hash: Hash256::from_bytes([0; 32]),
                signature_hash: Hash256::from_bytes([1; 32]),
                behavior_hash: Hash256::from_bytes([2; 32]),
                stability_score: 1.0,
            },
            file_origin: Some(FilePathId::new(file)),
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

    #[tokio::test]
    async fn run_verification_persists_targeted_run_and_links_work() {
        let _cwd_guard = current_dir_lock()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let dir = tempfile::tempdir().unwrap();
        kin_core::init(dir.path()).unwrap();
        let layout = kin_core::KinLayout::discover(dir.path()).unwrap();
        let snap =
            kin_db::SnapshotManager::open(crate::backend::kindb_snapshot_path(&layout)).unwrap();
        let graph = snap.graph();

        let entity = make_entity("checkout", "src/checkout.rs");
        graph.upsert_entity(&entity).unwrap();

        let work = WorkItem {
            work_id: kin_model::WorkId::new(),
            kind: kin_model::WorkKind::Feature,
            title: "Implement checkout".into(),
            description: "Ship checkout flow".into(),
            status: WorkStatus::InProgress,
            priority: Priority::High,
            scopes: vec![WorkScope::Entity(entity.id)],
            acceptance_criteria: vec!["passing checkout proof".into()],
            external_refs: vec![],
            created_by: IdentityRef::human("cli-user"),
            created_at: Timestamp::now(),
        };
        graph.create_work_item(&work).unwrap();

        let test = TestCase {
            test_id: kin_model::TestId::new(),
            name: "test_checkout_flow".into(),
            language: "rust".into(),
            kind: TestKind::Unit,
            scopes: vec![WorkScope::Entity(entity.id)],
            runner: TestRunner::Cargo,
            file_origin: Some(FilePathId::new("tests/checkout.rs")),
        };
        graph.create_test_case(&test).unwrap();
        graph
            .create_test_verifies_work(&test.test_id, &work.work_id)
            .unwrap();
        snap.save().unwrap();

        let _dir_guard = CurrentDirGuard::enter(dir.path());
        run_verification("checkout".into(), "printf".into(), 2)
            .await
            .unwrap();

        let reopened =
            kin_db::SnapshotManager::open(crate::backend::kindb_snapshot_path(&layout)).unwrap();
        let graph = reopened.graph();

        let runs = graph.list_runs_for_test(&test.test_id).unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].status, VerificationStatus::Passing);

        let entity_runs = graph.list_runs_proving_entity(&entity.id).unwrap();
        assert_eq!(entity_runs.len(), 1);
        assert_eq!(entity_runs[0].run_id, runs[0].run_id);

        let work_runs = graph.list_runs_proving_work(&work.work_id).unwrap();
        assert_eq!(work_runs.len(), 1);
        assert_eq!(work_runs[0].run_id, runs[0].run_id);
    }

    #[test]
    fn build_verification_plan_includes_impacted_dependents() {
        let dir = tempfile::tempdir().unwrap();
        kin_core::init(dir.path()).unwrap();
        let layout = kin_core::KinLayout::discover(dir.path()).unwrap();
        let snap =
            kin_db::SnapshotManager::open(crate::backend::kindb_snapshot_path(&layout)).unwrap();
        let graph = snap.graph();

        let callee = make_entity("checkout_core", "src/checkout.rs");
        let caller = make_entity("checkout_handler", "src/handler.rs");
        graph.upsert_entity(&callee).unwrap();
        graph.upsert_entity(&caller).unwrap();
        graph
            .upsert_relation(&Relation {
                id: RelationId::new(),
                kind: RelationKind::Calls,
                src: caller.id,
                dst: callee.id,
                confidence: 1.0,
                origin: RelationOrigin::Parsed,
                created_in: None,
            })
            .unwrap();

        let caller_test = TestCase {
            test_id: kin_model::TestId::new(),
            name: "test_checkout_handler".into(),
            language: "rust".into(),
            kind: TestKind::Integration,
            scopes: vec![WorkScope::Entity(caller.id)],
            runner: TestRunner::Cargo,
            file_origin: Some(FilePathId::new("tests/checkout_handler.rs")),
        };
        graph.create_test_case(&caller_test).unwrap();

        let plan = build_verification_plan(graph.as_ref(), "checkout_core", 1).unwrap();

        assert_eq!(plan.direct.entity.id, callee.id);
        assert!(plan.direct.tests.is_empty());
        assert_eq!(plan.impacted.len(), 1);
        assert_eq!(plan.impacted[0].entity.id, caller.id);
        assert_eq!(plan.impacted[0].tests.len(), 1);
        assert_eq!(plan.impacted[0].tests[0].test_id, caller_test.test_id);
        assert_eq!(plan.tests.len(), 1);
        assert_eq!(plan.tests[0].test_id, caller_test.test_id);
        assert_eq!(plan.proved_entities.len(), 2);
        assert!(plan
            .proved_entities
            .iter()
            .any(|entity| entity.id == callee.id));
        assert!(plan
            .proved_entities
            .iter()
            .any(|entity| entity.id == caller.id));
    }
}
