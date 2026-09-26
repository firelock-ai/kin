// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Java LSP adapter (Eclipse JDT Language Server).
//!
//! A Maven project's model is its `pom.xml` files, which can be read without
//! running anything, so the project model lists the root POM and the modules
//! it names. Gradle builds its model by running the build scripts
//! (`build.gradle`, `settings.gradle`), and Kin never runs them, so a Gradle
//! project without a POM has its model reported missing.

use super::contract::{Environment, ModelState, ProjectModel, ProjectPackage, Provider};
use super::LspAdapter;
use kin_model::LanguageId;
use std::path::Path;

pub struct JdtlsAdapter;

/// The text of each `<module>` element a POM lists.
fn pom_modules(text: &str) -> Vec<String> {
    let mut modules = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("<module>") {
        rest = &rest[start + "<module>".len()..];
        let Some(end) = rest.find("</module>") else {
            break;
        };
        let module = rest[..end].trim();
        if !module.is_empty() {
            modules.push(module.to_string());
        }
        rest = &rest[end..];
    }
    modules
}

/// The project model: the root POM and its modules, or the model missing.
pub fn project_model_for(root: &Path) -> ProjectModel {
    let pom = root.join("pom.xml");
    if let Ok(text) = std::fs::read_to_string(&pom) {
        let mut roots = vec![pom];
        let packages = pom_modules(&text)
            .into_iter()
            .map(|module| {
                let dir = root.join(&module);
                roots.push(dir.join("pom.xml"));
                ProjectPackage {
                    name: module,
                    source_roots: vec![dir.join("src/main/java"), dir.join("src/test/java")],
                    dir,
                    config: None,
                }
            })
            .collect();
        return ProjectModel {
            state: ModelState::Found,
            roots,
            packages,
            ..ProjectModel::default()
        };
    }
    let gradle = [
        "build.gradle",
        "build.gradle.kts",
        "settings.gradle",
        "settings.gradle.kts",
    ]
    .iter()
    .find(|file| root.join(file).is_file());
    ProjectModel::missing(match gradle {
        Some(file) => format!(
            "{file} without a pom.xml: Gradle builds its project model by running the build \
             scripts, and Kin never runs them"
        ),
        None => "no pom.xml at the root".to_string(),
    })
}

impl LspAdapter for JdtlsAdapter {
    fn language_id(&self) -> LanguageId {
        LanguageId::Java
    }

    fn server_command(&self) -> &str {
        "jdtls"
    }

    fn file_extensions(&self) -> &[&str] {
        &["java"]
    }

    fn initialization_options(&self, _workspace_root: &Path) -> Option<serde_json::Value> {
        None // jdtls uses workspace-level config
    }

    fn project_model(&self, workspace_root: &Path) -> ProjectModel {
        project_model_for(workspace_root)
    }

    fn environment(&self, _workspace_root: &Path, model: &ProjectModel) -> Environment {
        let provider = match &model.state {
            ModelState::Found => Provider::Missing {
                reason: "Kin does not yet provide Maven dependencies, and jdtls would resolve \
                         them by running Maven"
                    .to_string(),
            },
            ModelState::Missing { .. } => Provider::Missing {
                reason: "no project model names the dependencies".to_string(),
            },
        };
        let kind = provider.kind();
        Environment::from_provider(provider, &["jdtls", kind])
    }

    fn requires_workspace_indexing(&self) -> bool {
        true
    }

    fn estimated_index_time_secs(&self) -> u32 {
        20
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adapters::repo_scan::Fixture;

    #[test]
    fn a_maven_pom_is_read_statically_and_gradle_is_reported_missing() {
        let maven = Fixture::new("java-maven");
        maven.write(
            "pom.xml",
            "<project><modules>\n  <module>core</module>\n  <module> web </module>\n</modules></project>",
        );
        let model = JdtlsAdapter.project_model(&maven.root);
        assert_eq!(model.state, ModelState::Found);
        let names: Vec<&str> = model.packages.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["core", "web"]);
        assert_eq!(model.roots[0], maven.root.join("pom.xml"));

        let gradle = Fixture::new("java-gradle");
        gradle.write("build.gradle.kts", "plugins { java }\n");
        let resolution = JdtlsAdapter.launch(&gradle.root).resolution.unwrap();
        assert!(resolution
            .project_model_missing()
            .is_some_and(|reason| reason.contains("Gradle")));
        assert!(resolution.environment.missing_reason().is_some());
    }
}
