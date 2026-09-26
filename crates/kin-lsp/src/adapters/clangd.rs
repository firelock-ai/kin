// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! C/C++ LSP adapter (clangd).
//!
//! clangd learns how each file compiles from a compilation database,
//! `compile_commands.json`. Most repositories do not ship one: it is written
//! by configuring the build (CMake, Meson, Bear around `make`), and that runs
//! the repository's build scripts. Kin never runs them, so the project model
//! is read only from a database the repository already holds, at its root or
//! in `build/`, where clangd itself looks. Without one the model is reported
//! missing rather than guessed.

use super::contract::{Environment, ModelState, ProjectModel, Provider};
use super::LspAdapter;
use kin_model::LanguageId;
use std::path::{Path, PathBuf};

pub struct ClangdAdapter;

/// Where a shipped compilation database is looked for, relative to the root.
const DATABASE_LOCATIONS: &[&str] = &["compile_commands.json", "build/compile_commands.json"];

/// The compilation database the repository ships, when it ships one.
pub fn compilation_database(root: &Path) -> Option<PathBuf> {
    DATABASE_LOCATIONS
        .iter()
        .map(|relative| root.join(relative))
        .find(|path| path.is_file())
}

/// The project model: the shipped compilation database, or the model missing.
pub fn project_model_for(root: &Path) -> ProjectModel {
    match compilation_database(root) {
        Some(database) => ProjectModel {
            state: ModelState::Found,
            roots: vec![database],
            ..ProjectModel::default()
        },
        None => ProjectModel::missing(
            "no compile_commands.json at the root or in build/: producing one means \
             configuring the build, which runs repository code, and Kin never does",
        ),
    }
}

impl LspAdapter for ClangdAdapter {
    fn language_id(&self) -> LanguageId {
        LanguageId::C // Covers both C and C++
    }

    fn server_command(&self) -> &str {
        "clangd"
    }

    fn file_extensions(&self) -> &[&str] {
        &["c", "h", "cpp", "hpp", "cc", "cxx"]
    }

    fn initialization_options(&self, _workspace_root: &Path) -> Option<serde_json::Value> {
        Some(serde_json::json!({
            "clangd": {
                "diagnostics": { "onOpen": false, "onChange": false, "onSave": false },
            }
        }))
    }

    fn project_model(&self, workspace_root: &Path) -> ProjectModel {
        project_model_for(workspace_root)
    }

    fn environment(&self, _workspace_root: &Path, model: &ProjectModel) -> Environment {
        let provider = match &model.state {
            ModelState::Found => Provider::UserEnvironment {
                description: "the compiler and system headers the compilation database names"
                    .to_string(),
                checked_against: None,
            },
            ModelState::Missing { .. } => Provider::Missing {
                reason: "no compilation database names the compiler, flags and include paths"
                    .to_string(),
            },
        };
        let kind = provider.kind();
        Environment::from_provider(provider, &["clangd", kind])
    }

    fn requires_workspace_indexing(&self) -> bool {
        true // needs compile_commands.json
    }

    fn estimated_index_time_secs(&self) -> u32 {
        20
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::repo_scan::Fixture;

    /// A shipped database is the model; without one the model is missing and
    /// says why, and the environment is missing with it. CMake is never run.
    #[test]
    fn only_a_shipped_compilation_database_makes_a_model() {
        let repo = Fixture::new("clangd-model");
        repo.write("CMakeLists.txt", "project(x)\n");
        let launch = ClangdAdapter.launch(&repo.root);
        let resolution = launch.resolution.expect("a resolution");
        assert!(resolution
            .project_model_missing()
            .is_some_and(|reason| reason.contains("compile_commands.json")));
        assert!(resolution.environment.missing_reason().is_some());
        assert!(!repo.root.join("build").exists(), "nothing was configured");

        let database = repo.write("build/compile_commands.json", "[]");
        let resolution = ClangdAdapter.launch(&repo.root).resolution.unwrap();
        assert_eq!(resolution.project_model, ModelState::Found);
        assert_eq!(
            ClangdAdapter.project_model(&repo.root).roots,
            vec![database]
        );
    }
}
