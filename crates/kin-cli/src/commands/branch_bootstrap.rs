// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

use anyhow::Result;
use kin_model::{Branch, BranchName, GraphStore, SemanticChangeId};
use kin_model::ChangeStore;

#[derive(Debug)]
pub(crate) struct EnsuredBranch {
    pub(crate) head: SemanticChangeId,
    pub(crate) bootstrapped: bool,
}

pub(crate) fn ensure_current_branch<G>(graph: &G, branch_name: &BranchName) -> Result<EnsuredBranch>
where
    G: GraphStore,
{
    if let Some(branch) = graph.get_branch(branch_name)? {
        return Ok(EnsuredBranch {
            head: branch.head,
            bootstrapped: false,
        });
    }

    let existing_branches = graph.list_branches()?;
    if !existing_branches.is_empty() {
        anyhow::bail!("branch '{}' not found in graph", branch_name);
    }

    let genesis = kin_core::build_genesis_change();
    if graph.get_change(&genesis.id)?.is_none() {
        graph.create_change(&genesis)?;
    }

    graph.create_branch(&Branch {
        name: branch_name.clone(),
        head: genesis.id,
    })?;

    Ok(EnsuredBranch {
        head: genesis.id,
        bootstrapped: true,
    })
}

#[cfg(test)]
mod tests {
    use super::ensure_current_branch;
    use kin_db::InMemoryGraph;
    use kin_model::{Branch, BranchName, ChangeStore};

    #[test]
    fn bootstraps_empty_graph_with_genesis_branch() {
        let graph = InMemoryGraph::new();
        let branch_name = BranchName::new("main");

        let ensured = ensure_current_branch(&graph, &branch_name).unwrap();

        assert!(ensured.bootstrapped);
        let branch = graph.get_branch(&branch_name).unwrap().unwrap();
        assert_eq!(branch.head, ensured.head);
        assert!(graph.get_change(&ensured.head).unwrap().is_some());
    }

    #[test]
    fn preserves_existing_branch_head() {
        let graph = InMemoryGraph::new();
        let genesis = kin_core::build_genesis_change();
        graph.create_change(&genesis).unwrap();
        graph
            .create_branch(&Branch {
                name: BranchName::new("main"),
                head: genesis.id,
            })
            .unwrap();

        let ensured = ensure_current_branch(&graph, &BranchName::new("main")).unwrap();

        assert!(!ensured.bootstrapped);
        assert_eq!(ensured.head, genesis.id);
    }

    #[test]
    fn rejects_missing_current_branch_when_other_branches_exist() {
        let graph = InMemoryGraph::new();
        let genesis = kin_core::build_genesis_change();
        graph.create_change(&genesis).unwrap();
        graph
            .create_branch(&Branch {
                name: BranchName::new("dev"),
                head: genesis.id,
            })
            .unwrap();

        let error = ensure_current_branch(&graph, &BranchName::new("main")).unwrap_err();
        assert!(error
            .to_string()
            .contains("branch 'main' not found in graph"));
    }
}
