// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Per-language LSP server adapters.
//!
//! Each adapter knows how to configure and start its language's LSP server,
//! and how to interpret server-specific behaviors or quirks.
//!
//! Every adapter follows the one contract in [`contract`]: it reads a
//! [`ProjectModel`] from the repository's manifests, resolves an
//! [`Environment`] from the first provider that has one, and translates both
//! into one [`ServerLaunch`]: what goes in `initializationOptions`, the
//! settings the server asks for through `workspace/configuration`, the
//! environment it runs with, and, for a choice that can fail to load, the
//! configuration to fall back to. Adapters read the repository to choose it,
//! and they never write into it or run anything from it.

use std::path::Path;

use kin_model::LanguageId;

pub use contract::{Environment, ProjectModel, Resolution};

/// Everything one server is started with, as its adapter chose it for one
/// workspace.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ServerLaunch {
    /// The `initializationOptions` of the initialize request.
    pub initialization_options: Option<serde_json::Value>,
    /// The settings `workspace/configuration` is answered from, keyed by
    /// section the way editors key them (`{"python": {"analysis": {..}}}`
    /// answers both `python` and `python.analysis`). `None` means the client
    /// claims no configuration capability and the server never asks.
    pub settings: Option<serde_json::Value>,
    /// Environment variables set on the server process, beside the inherited
    /// environment.
    pub env: Vec<(String, String)>,
    /// What a proof context records for a variable in [`Self::env`] whose value
    /// names a file Kin wrote for the server, in place of that value: what the
    /// file tells the server, with its paths relative to the workspace. A
    /// proof then follows what the server was told rather than where the file
    /// lives, which is named after the repository's absolute path, so a store
    /// moved or copied elsewhere keeps its proofs. A variable not named here is
    /// recorded as its value.
    pub env_identity: Vec<(String, String)>,
    /// What this configuration is, in a few words, for logs and for the proof
    /// of which configuration answered.
    pub label: String,
    /// How to learn that the server finished loading the project, when the
    /// server can say so.
    pub load_check: Option<LoadCheck>,
    /// The configuration to start instead when the server reports that it
    /// could not load the project under this one.
    pub fallback: Option<Box<ServerLaunch>>,
    /// Text the server's failure message must contain, case aside, for the
    /// fallback to be tried: only some failures are this configuration's
    /// fault. `None` tries the fallback on any failed load.
    pub fallback_trigger: Option<String>,
    /// The project model and environment this launch was chosen from, for
    /// the status every language reports the same way. `None` for a launch
    /// built by hand and for a fallback, which shares its parent's.
    pub resolution: Option<Resolution>,
    /// The text of the server's own report that the backend it fronts has
    /// exited, for a server that outlives its backend (see
    /// [`crate::client::ServerWatch::backend_exit_report`]).
    pub backend_exit_report: Option<String>,
    /// How the server shows it can answer.
    pub readiness: Readiness,
}

/// How a server shows that it can answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Readiness {
    /// It indexes the workspace after it starts, and a workspace-wide request
    /// succeeds once it has.
    #[default]
    WorkspaceIndex,
    /// It loads a project when a document is opened, and answers nothing
    /// workspace-wide before one is. It takes documents as soon as it is
    /// initialized, and it can answer about a document once it answers a
    /// request about that document (see
    /// [`crate::lifecycle::LspServer::wait_for_document`]).
    ///
    /// tsserver is one: asked for workspace symbols before any document is
    /// open, it fails every time with "Could not find file", so a wait for a
    /// workspace answer always ran its whole minute.
    PerDocument,
}

impl ServerLaunch {
    /// A launch that is only initialization options, the whole configuration
    /// a server received before adapters could choose more.
    pub fn with_initialization_options(initialization_options: Option<serde_json::Value>) -> Self {
        Self {
            initialization_options,
            ..Self::default()
        }
    }
}

/// How a launch learns that its server finished loading the project.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadCheck {
    /// rust-analyzer's `experimental/serverStatus`: wait for `quiescent`, and
    /// read a `health` other than `ok` whose message names `cargo metadata` as
    /// a failed project load.
    ServerStatus,
}

/// Trait that each language adapter implements.
///
/// The generic framework handles JSON-RPC transport, message routing, and
/// enrichment conversion. Adapters handle the language-specific parts:
/// how to start the server, what initialization options to send, and
/// how to map language-specific features to graph operations.
pub trait LspAdapter: Send + Sync {
    /// Which language this adapter handles.
    fn language_id(&self) -> LanguageId;

    /// The command to start the LSP server (e.g., "rust-analyzer").
    fn server_command(&self) -> &str;

    /// Arguments to pass to the server command.
    fn server_args(&self) -> Vec<String> {
        Vec::new()
    }

    /// Language-specific initialization options to include in the
    /// `initializationOptions` field of the initialize request.
    fn initialization_options(&self, _workspace_root: &Path) -> Option<serde_json::Value> {
        None
    }

    /// The settings this server asks for through `workspace/configuration`.
    fn workspace_settings(&self, _workspace_root: &Path) -> Option<serde_json::Value> {
        None
    }

    /// Environment variables the server runs with, beside the inherited ones.
    fn server_env(&self, _workspace_root: &Path) -> Vec<(String, String)> {
        Vec::new()
    }

    /// Step one of the contract: what the repository's manifests say about
    /// its code, read without running a build. An adapter that models no
    /// project reports the model missing.
    fn project_model(&self, _workspace_root: &Path) -> ProjectModel {
        ProjectModel::missing(format!(
            "the {} adapter reads no project model",
            self.server_command()
        ))
    }

    /// Step two: the environment the server analyses against, from the first
    /// provider that has one. It reads the host and Kin's cache and never
    /// touches the network; what only a download can supply is left in
    /// [`Environment::pending`] for [`Self::provision`].
    fn environment(&self, _workspace_root: &Path, _model: &ProjectModel) -> Environment {
        Environment::from_provider(
            contract::Provider::Missing {
                reason: format!(
                    "the {} adapter resolves no environment",
                    self.server_command()
                ),
            },
            &[self.server_command(), "unresolved"],
        )
    }

    /// Step three: the server's configuration for this model and environment.
    fn configure(
        &self,
        workspace_root: &Path,
        _model: &ProjectModel,
        _environment: &Environment,
    ) -> ServerLaunch {
        ServerLaunch {
            initialization_options: self.initialization_options(workspace_root),
            settings: self.workspace_settings(workspace_root),
            env: self.server_env(workspace_root),
            label: self.server_command().to_string(),
            ..ServerLaunch::default()
        }
    }

    /// The whole configuration this server is started with for one workspace:
    /// the three steps in order, with the model and environment kept beside
    /// the configuration for reporting.
    fn launch(&self, workspace_root: &Path) -> ServerLaunch {
        let model = self.project_model(workspace_root);
        let environment = self.environment(workspace_root, &model);
        let mut launch = self.configure(workspace_root, &model, &environment);
        launch.resolution = Some(Resolution::new(&model, environment));
        launch
    }

    /// The environment's network step: fetch what [`Self::environment`] left
    /// pending, into Kin's shared cache, without running anything fetched.
    /// Blocking; call it off an async runtime. `None` when this adapter has
    /// nothing to provision.
    fn provision(&self, _workspace_root: &Path) -> Option<contract::ProvisionReport> {
        None
    }

    /// File extensions this adapter handles (e.g., ["rs"] for Rust).
    fn file_extensions(&self) -> &[&str];

    /// Whether this adapter needs the server to index the entire workspace
    /// before queries are meaningful (e.g., rust-analyzer needs cargo metadata).
    fn requires_workspace_indexing(&self) -> bool {
        true
    }

    /// Estimated time in seconds for the server to index a typical workspace.
    /// Used for progress reporting, not as a hard timeout.
    fn estimated_index_time_secs(&self) -> u32 {
        30
    }
}

pub mod clangd;
pub mod contract;
pub mod go;
pub mod java;
pub mod python;
pub(crate) mod repo_scan;
pub mod rust_analyzer;
pub mod typescript;
