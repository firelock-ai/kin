use anyhow::Result;
use kin_model::{EntityFilter, GraphStore, TokenBudget};

pub async fn run(entity: String, budget: String) -> Result<()> {
    let layout = kin_core::KinLayout::discover(&std::env::current_dir()?)
        .ok_or_else(|| anyhow::anyhow!("not a Kin repository (no .kin/ found)"))?;
    let graph = kin_graph::KuzuGraphStore::open(&layout.graph_dir())?;

    let token_budget = parse_budget(&budget)?;

    // Find the entity
    let filter = EntityFilter {
        name_pattern: Some(entity.clone()),
        ..Default::default()
    };
    let matches = graph.query_entities(&filter)?;

    if matches.is_empty() {
        println!("Entity '{}' not found", entity);
        return Ok(());
    }

    let target = &matches[0];
    let opts = kin_context::ContextOptions {
        budget: token_budget,
        max_depth: 2,
        include_tests: true,
        include_contracts: true,
        include_traffic: false,
    };

    let pack = kin_context::build_context_pack(&graph, &target.id, &opts)?;

    println!("Context pack for '{}' ({:?}):", target.name, target.kind);
    println!(
        "  Budget: {}/{} tokens",
        pack.actual_tokens,
        token_budget.max_tokens()
    );
    println!("  Focal: {} entries", pack.focal_entities.len());
    println!("  Dependencies: {} entries", pack.dependency_signatures.len());
    println!("  Transitive: {} entries", pack.transitive_deps.len());
    println!("  Contracts: {} entries", pack.contracts.len());
    println!("  Tests: {} entries", pack.tests.len());

    // Print the context
    println!("\n--- Context Pack ---");
    for entry in &pack.focal_entities {
        println!("{}", entry.content);
    }
    for entry in &pack.dependency_signatures {
        println!("{}", entry.content);
    }
    for entry in &pack.transitive_deps {
        println!("{}", entry.content);
    }

    Ok(())
}

fn parse_budget(s: &str) -> Result<TokenBudget> {
    match s {
        "8k" => Ok(TokenBudget::Small8k),
        "16k" => Ok(TokenBudget::Medium16k),
        "32k" => Ok(TokenBudget::Large32k),
        _ => {
            let n: usize = s.parse().map_err(|_| {
                anyhow::anyhow!("invalid budget: use '8k', '16k', '32k', or a number")
            })?;
            Ok(TokenBudget::Custom(n))
        }
    }
}
