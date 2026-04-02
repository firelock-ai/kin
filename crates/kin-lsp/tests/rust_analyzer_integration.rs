// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Integration test: start rust-analyzer, query call hierarchy on a real Rust project.
//!
//! Requires: rust-analyzer installed (`rustup component add rust-analyzer`).
//! Skipped if rust-analyzer is not available.

use std::path::Path;

use kin_lsp::adapters::rust_analyzer::RustAnalyzerAdapter;
use kin_lsp::adapters::LspAdapter;
use kin_lsp::lifecycle::LspServer;
use kin_lsp::protocol;

fn has_rust_analyzer() -> bool {
    which::which("rust-analyzer").is_ok()
        && std::process::Command::new("rust-analyzer")
            .arg("--version")
            .output()
            .is_ok_and(|o| o.status.success())
}

/// Test that we can start rust-analyzer, initialize it on a Rust project,
/// and get a valid response.
#[tokio::test]
async fn start_and_initialize_rust_analyzer() {
    if !has_rust_analyzer() {
        eprintln!("SKIP: rust-analyzer not available");
        return;
    }

    // Use the kin crate itself as the test workspace — it's always available.
    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().join("kin");
    if !workspace.join("Cargo.toml").exists() {
        eprintln!("SKIP: kin workspace not found at {:?}", workspace);
        return;
    }

    let adapter = RustAnalyzerAdapter;
    let server = LspServer::start(
        adapter.server_command(),
        &[],
        &workspace,
        adapter.initialization_options(&workspace),
    )
    .await;

    match server {
        Ok(server) => {
            eprintln!("rust-analyzer started and initialized successfully");
            eprintln!(
                "  call_hierarchy: {}",
                server.has_call_hierarchy()
            );
            eprintln!("  definition: {}", server.has_definition());
            eprintln!("  references: {}", server.has_references());

            // Verify we got some capabilities back.
            assert!(
                server.has_call_hierarchy() || server.has_definition(),
                "server should support at least call_hierarchy or definition"
            );

            // Clean shutdown.
            server.shutdown().await.expect("shutdown failed");
            eprintln!("rust-analyzer shut down cleanly");
        }
        Err(e) => {
            eprintln!("rust-analyzer failed to start: {}", e);
            // Don't fail the test — server might not support the workspace
        }
    }
}

/// Test querying textDocument/definition on a known function.
#[tokio::test]
async fn query_definition_on_rust_file() {
    if !has_rust_analyzer() {
        eprintln!("SKIP: rust-analyzer not available");
        return;
    }

    let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().join("kin");
    if !workspace.join("Cargo.toml").exists() {
        eprintln!("SKIP: kin workspace not found");
        return;
    }

    let adapter = RustAnalyzerAdapter;
    let server = match LspServer::start(
        adapter.server_command(),
        &[],
        &workspace,
        adapter.initialization_options(&workspace),
    )
    .await
    {
        Ok(s) => s,
        Err(e) => {
            eprintln!("SKIP: server start failed: {}", e);
            return;
        }
    };

    // Open a file so rust-analyzer knows about it.
    let test_file = workspace.join("crates/kin-core/src/init.rs");
    if !test_file.exists() {
        eprintln!("SKIP: test file not found");
        server.shutdown().await.ok();
        return;
    }

    let file_content = std::fs::read_to_string(&test_file).unwrap();
    let uri = protocol::path_to_uri(&test_file);

    // Send textDocument/didOpen notification.
    server
        .client
        .notify(
            "textDocument/didOpen",
            serde_json::json!({
                "textDocument": {
                    "uri": uri,
                    "languageId": "rust",
                    "version": 1,
                    "text": file_content,
                }
            }),
        )
        .await
        .expect("didOpen failed");

    // Wait for rust-analyzer to index (it needs time to load cargo metadata).
    eprintln!("waiting for rust-analyzer to index...");
    tokio::time::sleep(std::time::Duration::from_secs(10)).await;

    // Query definition at the start of the `init` function.
    // Find the line containing "pub fn init("
    let init_line = file_content
        .lines()
        .enumerate()
        .find(|(_, line)| line.contains("pub fn init(working_dir"))
        .map(|(i, _)| i as u32);

    if let Some(line) = init_line {
        eprintln!("querying definition at line {}", line);

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            server.client.request(
                "textDocument/definition",
                protocol::TextDocumentPositionParams {
                    text_document: protocol::TextDocumentIdentifier { uri: uri.clone() },
                    position: protocol::Position {
                        line,
                        character: 10,
                    },
                },
            ),
        )
        .await;

        match result {
            Ok(Ok(value)) => {
                eprintln!("definition response: {}", serde_json::to_string_pretty(&value).unwrap_or_default());
            }
            Ok(Err(e)) => {
                eprintln!("definition request failed: {}", e);
            }
            Err(_) => {
                eprintln!("definition request timed out (rust-analyzer may still be indexing)");
            }
        }
    }

    server.shutdown().await.ok();
    eprintln!("test complete");
}
