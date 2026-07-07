// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! LSP server lifecycle management — start, initialize, shutdown.

use std::path::Path;
use std::process::Stdio;

use tokio::process::{Child, Command};
use tracing::{debug, info};

use crate::client::JsonRpcClient;
use crate::error::{LspError, Result};
use crate::protocol::{self, InitializeParams, InitializeResult};

/// A running LSP server with an initialized JSON-RPC client.
pub struct LspServer {
    pub client: JsonRpcClient,
    pub capabilities: protocol::ServerCapabilities,
    child: Child,
}

impl LspServer {
    /// Start an LSP server process and perform the initialize handshake.
    pub async fn start(
        command: &str,
        args: &[&str],
        workspace_root: &Path,
        initialization_options: Option<serde_json::Value>,
    ) -> Result<Self> {
        info!(command, ?args, "starting LSP server");

        let mut child = Command::new(command)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| LspError::ServerStartFailed(format!("{}: {}", command, e)))?;

        let stdin = child
            .stdin
            .take()
            .ok_or_else(|| LspError::ServerStartFailed("failed to capture stdin".to_string()))?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| LspError::ServerStartFailed("failed to capture stdout".to_string()))?;

        let client = JsonRpcClient::new(stdin, stdout);

        // Perform LSP initialize handshake.
        let init_params = InitializeParams {
            process_id: Some(std::process::id()),
            root_uri: Some(protocol::path_to_uri(workspace_root)),
            capabilities: protocol::kin_capabilities(),
            initialization_options,
        };

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(30),
            client.request("initialize", &init_params),
        )
        .await
        .map_err(|_| LspError::Timeout)?
        .map_err(|e| LspError::InitializeFailed(e.to_string()))?;

        let init_result: InitializeResult =
            serde_json::from_value(result).unwrap_or(InitializeResult {
                capabilities: protocol::ServerCapabilities::default(),
            });

        // Send `initialized` notification.
        client.notify("initialized", serde_json::json!({})).await?;

        debug!(
            call_hierarchy = init_result.capabilities.call_hierarchy_provider.is_some(),
            definition = init_result.capabilities.definition_provider.is_some(),
            references = init_result.capabilities.references_provider.is_some(),
            type_hierarchy = init_result.capabilities.type_hierarchy_provider.is_some(),
            type_definition = init_result.capabilities.type_definition_provider.is_some(),
            "server initialized"
        );

        Ok(Self {
            client,
            capabilities: init_result.capabilities,
            child,
        })
    }

    /// Send shutdown request and exit notification.
    pub async fn shutdown(self) -> Result<()> {
        let _ = self
            .client
            .request("shutdown", serde_json::json!(null))
            .await;
        let _ = self.client.notify("exit", serde_json::json!(null)).await;
        // Child is killed on drop via kill_on_drop(true).
        drop(self.child);
        Ok(())
    }

    /// Check if the server supports call hierarchy.
    pub fn has_call_hierarchy(&self) -> bool {
        self.capabilities.call_hierarchy_provider.is_some()
    }

    /// Check if the server supports go-to-definition.
    pub fn has_definition(&self) -> bool {
        self.capabilities.definition_provider.is_some()
    }

    /// Check if the server supports find references.
    pub fn has_references(&self) -> bool {
        self.capabilities.references_provider.is_some()
    }

    /// Check if the server supports type hierarchy.
    pub fn has_type_hierarchy(&self) -> bool {
        self.capabilities.type_hierarchy_provider.is_some()
    }

    /// Check if the server supports go-to-type-definition.
    pub fn has_type_definition(&self) -> bool {
        self.capabilities.type_definition_provider.is_some()
    }

    /// The capabilities this live server reported during the initialize
    /// handshake, expressed in the registry's capability vocabulary. This is the
    /// source of truth for what actually ran and feeds the enrichment proof.
    pub fn probed_capabilities(
        &self,
    ) -> std::collections::BTreeSet<crate::registry::LspCapability> {
        use crate::registry::LspCapability;
        let mut caps = std::collections::BTreeSet::new();
        if self.has_definition() {
            caps.insert(LspCapability::Definition);
        }
        if self.has_type_definition() {
            caps.insert(LspCapability::TypeDefinition);
        }
        if self.has_references() {
            caps.insert(LspCapability::References);
        }
        if self.has_call_hierarchy() {
            caps.insert(LspCapability::CallHierarchy);
        }
        if self.has_type_hierarchy() {
            caps.insert(LspCapability::TypeHierarchy);
        }
        caps
    }
}
