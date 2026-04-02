// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Reproduces the daemon LSP worker flow: start RA, didOpen, prepareCallHierarchy.
//! This tests whether the background reader + oneshot + timeout work correctly
//! when called in the same sequence as the daemon worker.

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

/// Reproduces the EXACT daemon worker flow:
/// 1. Start RA (like daemon lazy server start)
/// 2. Wait 25s (like daemon indexing wait)
/// 3. didOpen a file (like daemon worker)
/// 4. Wait 10s (like daemon post-didOpen delay)
/// 5. prepareCallHierarchy with 5s timeout (like daemon enrichment)
#[tokio::test]
async fn daemon_flow_reproduction() {
    if !has_rust_analyzer() {
        eprintln!("SKIP: rust-analyzer not available");
        return;
    }

    // Use a tiny project — same as daemon test
    let workspace = std::env::temp_dir().join("lsp-repro-test");
    let _ = std::fs::remove_dir_all(&workspace);
    std::fs::create_dir_all(workspace.join("src")).unwrap();
    std::fs::write(
        workspace.join("Cargo.toml"),
        b"[package]\nname = \"repro\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
    ).unwrap();
    std::fs::write(
        workspace.join("src/main.rs"),
        b"fn helper() -> i32 { 42 }\nfn caller() -> i32 { helper() }\nfn main() { println!(\"{}\", caller()); }\n",
    ).unwrap();

    let adapter = RustAnalyzerAdapter;

    // Step 1: Start RA
    eprintln!("Step 1: Starting rust-analyzer...");
    let server = LspServer::start(
        adapter.server_command(),
        &[],
        &workspace,
        adapter.initialization_options(&workspace),
    )
    .await
    .expect("server start failed");
    eprintln!("  RA started. Capabilities: call_hierarchy={}", server.has_call_hierarchy());

    // Step 2: Wait for indexing (daemon waits 25s)
    eprintln!("Step 2: Waiting 25s for indexing...");
    tokio::time::sleep(std::time::Duration::from_secs(25)).await;
    eprintln!("  Indexing wait complete.");

    // Step 3: didOpen
    let file_path = workspace.join("src/main.rs");
    let file_content = std::fs::read_to_string(&file_path).unwrap();
    let uri = protocol::path_to_uri(&file_path);
    eprintln!("Step 3: Sending didOpen for {}", uri);
    server.client.notify(
        "textDocument/didOpen",
        serde_json::json!({
            "textDocument": {
                "uri": uri,
                "languageId": "rust",
                "version": 1,
                "text": file_content,
            }
        }),
    ).await.expect("didOpen failed");
    eprintln!("  didOpen sent.");

    // Step 4: Wait for RA to process (daemon waits 10s)
    eprintln!("Step 4: Waiting 10s post-didOpen...");
    tokio::time::sleep(std::time::Duration::from_secs(10)).await;
    eprintln!("  Post-didOpen wait complete.");

    // Step 5: prepareCallHierarchy with 5s timeout (daemon pattern)
    eprintln!("Step 5: prepareCallHierarchy with 5s timeout...");
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        server.client.request(
            "textDocument/prepareCallHierarchy",
            protocol::CallHierarchyPrepareParams {
                text_document: protocol::TextDocumentIdentifier { uri: uri.clone() },
                position: protocol::Position { line: 1, character: 4 }, // caller function
            },
        ),
    ).await;

    match result {
        Ok(Ok(ref value)) => {
            eprintln!("  SUCCESS: Got response: {}", serde_json::to_string_pretty(value).unwrap_or_default());
        }
        Ok(Err(ref e)) => {
            eprintln!("  LSP error: {}", e);
        }
        Err(_) => {
            eprintln!("  TIMEOUT: 5s timeout fired (this is the daemon bug!)");
        }
    }

    // Step 6: If prepareCallHierarchy worked, try outgoingCalls
    if let Ok(Ok(value)) = &result {
        let items: Vec<protocol::CallHierarchyItem> = serde_json::from_value(value.clone()).unwrap_or_default();
        if let Some(item) = items.first() {
            eprintln!("Step 6: querying outgoingCalls for '{}'...", item.name);
            let outgoing_result = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                server.client.request(
                    "callHierarchy/outgoingCalls",
                    protocol::CallHierarchyOutgoingCallsParams { item: item.clone() },
                ),
            ).await;

            match outgoing_result {
                Ok(Ok(calls)) => {
                    let parsed: Vec<protocol::CallHierarchyOutgoingCall> = serde_json::from_value(calls).unwrap_or_default();
                    eprintln!("  SUCCESS: {} outgoing calls", parsed.len());
                    for call in &parsed {
                        eprintln!("    -> {}", call.to.name);
                    }
                }
                Ok(Err(e)) => eprintln!("  outgoingCalls error: {}", e),
                Err(_) => eprintln!("  outgoingCalls TIMEOUT"),
            }
        }
    }

    server.shutdown().await.ok();
    let _ = std::fs::remove_dir_all(&workspace);
    eprintln!("Test complete.");
}
