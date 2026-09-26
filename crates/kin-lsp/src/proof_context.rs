// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Which resolver proved something, and under what.
//!
//! Every proof Kin records names a [`ProofContext`]: the resolver, its own
//! version, a hash of everything it was configured with, and the identity of
//! the environment it answered against. Two proofs under one context were made
//! the same way; a proof whose context is no longer the one the resolver runs
//! under is stale.
//!
//! The configuration hash covers the initialize options, the answers to
//! `workspace/configuration`, the adapter's environment variables and label,
//! and the workspace folder, each with the workspace root and the home
//! directory written as placeholders, so one repository configured the same
//! way hashes the same on every machine. The environment hash is the resolver
//! contract's environment identity: the toolchain and the dependency versions
//! the repository's lock names.

use std::path::Path;

use kin_model::{Hash256, LanguageId, ProofContext};

use crate::adapters::ServerLaunch;

/// Domain of a proof context's configuration hash.
const CONFIGURATION_DOMAIN: &str = "kin.proof-context.configuration.v1";

/// Domain of the environment hash of a launch that names no environment.
const NO_ENVIRONMENT_DOMAIN: &str = "kin.proof-context.environment.none.v1";

/// What a started server's proofs are made under, apart from the language.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofBasis {
    resolver: String,
    resolver_version: String,
    configuration_hash: Hash256,
    environment_hash: Hash256,
    environment_summary: String,
}

impl ProofBasis {
    /// The basis of a server started from `launch` for `workspace_root`, which
    /// reported `server_name` and `server_version` in its initialize answer.
    /// `command` names the resolver when the server reported no name.
    pub fn of(
        launch: &ServerLaunch,
        workspace_root: &Path,
        command: &str,
        server_name: Option<&str>,
        server_version: Option<&str>,
    ) -> Self {
        let resolver = format!("lsp:{}", resolver_name(server_name, command));
        let resolver_version = server_version
            .map(str::trim)
            .filter(|version| !version.is_empty())
            .map(|version| sanitize(version, 256))
            .unwrap_or_else(|| "unknown".to_string());
        let placeholders = Placeholders::new(workspace_root);
        let json = |value: &Option<serde_json::Value>| {
            value
                .as_ref()
                .map(|value| placeholders.apply(&value.to_string()))
                .unwrap_or_default()
        };
        let mut env: Vec<String> = launch
            .env
            .iter()
            .map(|(name, value)| format!("{name}={}", placeholders.apply(value)))
            .collect();
        env.sort();
        let initialization = json(&launch.initialization_options);
        let settings = json(&launch.settings);
        let env = env.join("\n");
        let label = placeholders.apply(&launch.label);
        let configuration_hash = kin_model::proof_context_digest(
            CONFIGURATION_DOMAIN,
            &[
                label.as_bytes(),
                initialization.as_bytes(),
                settings.as_bytes(),
                env.as_bytes(),
                // The one workspace folder every server is given.
                b"${workspace}",
            ],
        );
        let environment = launch
            .resolution
            .as_ref()
            .map(|resolution| &resolution.environment);
        let environment_hash = environment
            .and_then(|environment| Hash256::from_hex(environment.identity.hex()).ok())
            .unwrap_or_else(|| {
                kin_model::proof_context_digest(NO_ENVIRONMENT_DOMAIN, &[command.as_bytes()])
            });
        let environment_summary = environment
            .map(|environment| {
                let mut summary = environment.provider.kind().to_string();
                if let Some(toolchain) = &environment.toolchain {
                    summary = format!("{} {}; {summary}", toolchain.name, toolchain.version);
                }
                sanitize(&summary, 512)
            })
            .unwrap_or_default();
        Self {
            resolver,
            resolver_version,
            configuration_hash,
            environment_hash,
            environment_summary,
        }
    }

    /// The proof context of this server's answers about `language`.
    pub fn proof_context(&self, language: LanguageId) -> ProofContext {
        ProofContext {
            language,
            resolver: self.resolver.clone(),
            resolver_version: self.resolver_version.clone(),
            configuration_hash: self.configuration_hash,
            environment_hash: self.environment_hash,
            environment_summary: self.environment_summary.clone(),
        }
    }
}

/// The resolver's name as a proof context spells it: lower case, and only the
/// characters a resolver name may carry.
fn resolver_name(server_name: Option<&str>, command: &str) -> String {
    let source = server_name
        .map(str::trim)
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| {
            Path::new(command)
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or(command)
        });
    let mut name: String = source
        .to_lowercase()
        .chars()
        .map(|ch| match ch {
            'a'..='z' | '0'..='9' | '.' | '_' | '-' | '+' => ch,
            _ => '-',
        })
        .collect();
    while name.starts_with(|ch: char| !ch.is_ascii_alphanumeric()) {
        name.remove(0);
    }
    name.truncate(100);
    if name.is_empty() {
        "unnamed".to_string()
    } else {
        name
    }
}

/// `text` without control characters, trimmed, and at most `max` bytes.
fn sanitize(text: &str, max: usize) -> String {
    let mut clean: String = text
        .chars()
        .map(|ch| if ch.is_control() { ' ' } else { ch })
        .collect();
    while clean.len() > max {
        clean.pop();
    }
    clean.trim().to_string()
}

/// The local paths a configuration may carry, written as placeholders.
struct Placeholders {
    replacements: Vec<(String, &'static str)>,
}

impl Placeholders {
    fn new(workspace_root: &Path) -> Self {
        let mut replacements = Vec::new();
        let root = workspace_root.to_string_lossy().into_owned();
        if !root.is_empty() && root != "/" {
            replacements.push((root, "${workspace}"));
        }
        if let Some(home) = std::env::var_os("KIN_HOME") {
            let home = home.to_string_lossy().into_owned();
            if !home.is_empty() && home != "/" {
                replacements.push((home, "${kin_home}"));
            }
        }
        if let Some(home) = std::env::var_os("HOME") {
            let home = home.to_string_lossy().into_owned();
            if !home.is_empty() && home != "/" {
                replacements.push((home, "${home}"));
            }
        }
        // The longest path first, so a root inside the home directory is
        // written as the workspace rather than as a path below the home.
        replacements.sort_by_key(|(path, _)| std::cmp::Reverse(path.len()));
        Self { replacements }
    }

    fn apply(&self, text: &str) -> String {
        let mut text = text.to_string();
        for (path, placeholder) in &self.replacements {
            text = text.replace(path.as_str(), placeholder);
        }
        text
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn launch(root: &Path) -> ServerLaunch {
        ServerLaunch {
            initialization_options: Some(serde_json::json!({
                "linkedProjects": [root.join("Cargo.toml").to_string_lossy()],
            })),
            label: "rust-analyzer, all features".to_string(),
            ..ServerLaunch::default()
        }
    }

    #[test]
    fn one_configuration_hashes_the_same_wherever_the_repository_is() {
        let here = ProofBasis::of(
            &launch(Path::new("/work/a/axum")),
            Path::new("/work/a/axum"),
            "rust-analyzer",
            Some("rust-analyzer"),
            Some("0.3.2600-standalone"),
        );
        let there = ProofBasis::of(
            &launch(Path::new("/elsewhere/axum")),
            Path::new("/elsewhere/axum"),
            "rust-analyzer",
            Some("rust-analyzer"),
            Some("0.3.2600-standalone"),
        );
        assert_eq!(here, there);
        let context = here.proof_context(LanguageId::Rust);
        assert_eq!(context.resolver, "lsp:rust-analyzer");
        assert_eq!(context.resolver_version, "0.3.2600-standalone");
        kin_model::ResolutionRecord::ProofContext(context)
            .validate()
            .unwrap();

        let mut other = launch(Path::new("/work/a/axum"));
        other.label = "rust-analyzer, default features".to_string();
        let changed = ProofBasis::of(
            &other,
            Path::new("/work/a/axum"),
            "rust-analyzer",
            Some("rust-analyzer"),
            Some("0.3.2600-standalone"),
        );
        assert_ne!(
            changed.proof_context(LanguageId::Rust),
            here.proof_context(LanguageId::Rust),
            "another configuration is another context"
        );
    }

    #[test]
    fn a_server_without_a_name_is_named_by_its_command() {
        let basis = ProofBasis::of(
            &ServerLaunch::default(),
            Path::new("/r"),
            "/opt/bin/pyright-langserver",
            None,
            None,
        );
        let context = basis.proof_context(LanguageId::Python);
        assert_eq!(context.resolver, "lsp:pyright-langserver");
        assert_eq!(context.resolver_version, "unknown");
        assert_eq!(resolver_name(Some("Pyright"), "x"), "pyright");
        assert_eq!(
            resolver_name(Some("typescript-language-server"), "x"),
            "typescript-language-server"
        );
        kin_model::ResolutionRecord::ProofContext(context)
            .validate()
            .unwrap();
    }
}
