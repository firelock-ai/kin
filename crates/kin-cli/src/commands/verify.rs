use anyhow::Result;
use kin_model::{
    GraphStore, TestRunner, Timestamp, VerificationRun, VerificationRunId, VerificationStatus,
};

/// `kin verify <entity>` — Check verification / test coverage for an entity.
///
/// Shows per-entity test linkage and overall coverage summary.
pub async fn run(entity: String) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let graph = kin_db::SnapshotManager::open(layout.graph_dir().join("kindb"))?.graph();

    // Find entity by name
    let filter = kin_model::EntityFilter {
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

    // Show overall coverage summary
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
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let graph = kin_db::SnapshotManager::open(layout.graph_dir().join("kindb"))?.graph();

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
        // Show uncovered entity names (look up each).
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
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let graph = kin_db::SnapshotManager::open(layout.graph_dir().join("kindb"))?.graph();

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

/// `kin verify run <entity> --runner cargo` — Execute a test runner and record
/// a VerificationRun in the graph with captured evidence.
///
/// Steps:
///   1. Resolve the entity by name
///   2. Execute the test runner (shell out)
///   3. Capture stdout/stderr as evidence
///   4. Store evidence as a blob in the content-addressed store (if available)
///   5. Create a VerificationRun in the graph
///   6. Link the run to the entity via PROVES_ENTITY edge
pub async fn run_verification(entity: String, runner: String) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let graph = kin_db::InMemoryGraph::new()?;

    // Resolve entity
    let filter = kin_model::EntityFilter {
        name_pattern: Some(entity.clone()),
        ..Default::default()
    };
    let entities = graph.query_entities(&filter)?;

    if entities.is_empty() {
        anyhow::bail!("No entity matching '{}' found.", entity);
    }

    let target_entity = &entities[0];

    // Parse runner
    let test_runner = match runner.as_str() {
        "cargo" => TestRunner::Cargo,
        "jest" => TestRunner::Jest,
        "pytest" => TestRunner::Pytest,
        "go" => TestRunner::Go,
        "junit" => TestRunner::JUnit,
        other => TestRunner::Custom(other.to_string()),
    };

    // Build test command
    let cmd_str = match &test_runner {
        TestRunner::Cargo => format!("cargo test {}", entity),
        TestRunner::Jest => format!("npx jest --testNamePattern={}", entity),
        TestRunner::Pytest => format!("pytest -k {}", entity),
        TestRunner::Go => format!("go test -run {}", entity),
        TestRunner::JUnit => format!("mvn test -Dtest={}", entity),
        TestRunner::Custom(c) => format!("{} {}", c, entity),
    };

    println!("Running: {}", cmd_str);

    let started_at = Timestamp::now();
    let start_instant = std::time::Instant::now();

    // Execute the test runner
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
            let st = if out.status.success() {
                VerificationStatus::Passing
            } else {
                VerificationStatus::Failing
            };
            (st, exit, evidence)
        }
        Err(e) => {
            let evidence = format!("Failed to execute test runner: {}", e);
            (VerificationStatus::Failing, -1, evidence)
        }
    };

    // Store evidence as blob (best-effort)
    let evidence_blob = {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(evidence_text.as_bytes());
        let result = hasher.finalize();
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&result);
        let hash = kin_model::Hash256::from_bytes(bytes);

        // Try to write to blob store
        let blob_dir = layout.objects_dir();
        if blob_dir.exists() {
            let hex = hash.to_string();
            let shard_dir = blob_dir.join(&hex[..2]);
            let _ = std::fs::create_dir_all(&shard_dir);
            let blob_path = shard_dir.join(&hex[2..]);
            let _ = std::fs::write(&blob_path, evidence_text.as_bytes());
        }

        Some(hash)
    };

    // Create VerificationRun
    let run_id = VerificationRunId::new();
    let verification_run = VerificationRun {
        run_id,
        test_ids: Vec::new(), // No specific test IDs — running by entity name
        status,
        runner: test_runner,
        started_at,
        finished_at: Some(finished_at),
        duration_ms: Some(duration.as_millis() as u64),
        evidence_blob,
        exit_code: Some(exit_code),
    };

    graph.create_verification_run(&verification_run)?;

    // Link run to entity via PROVES_ENTITY edge
    graph.link_run_proves_entity(&run_id, &target_entity.id)?;

    println!();
    println!("VerificationRun recorded:");
    println!("  Run ID:   {}", run_id);
    println!(
        "  Entity:   {} ({:?})",
        target_entity.name, target_entity.kind
    );
    println!("  Status:   {}", verification_run.status);
    println!("  Duration: {}ms", duration.as_millis());
    println!("  Exit:     {}", exit_code);
    if let Some(ref blob) = verification_run.evidence_blob {
        println!("  Evidence: {}", blob);
    }

    Ok(())
}
