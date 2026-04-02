// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! JSON-RPC 2.0 client over stdio with background reader.
//!
//! Architecture: a dedicated tokio task owns the BufReader<ChildStdout>
//! and reads all messages. Responses are dispatched by ID via oneshot
//! channels. Notifications are discarded. No mutex on the read path.
//!
//! The write path uses a Mutex<ChildStdin> since sends are infrequent
//! and non-blocking relative to reads.

use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;

use serde::Serialize;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::ChildStdin;
use tokio::sync::{oneshot, Mutex};
use tracing::debug;

use crate::error::{LspError, Result};

/// Pending response waiters, keyed by request ID.
/// The background reader removes entries and fires the oneshot.
type WaiterMap = Arc<Mutex<HashMap<i64, oneshot::Sender<Result<Value>>>>>;

/// A JSON-RPC 2.0 client with a background reader for async response dispatch.
pub struct JsonRpcClient {
    stdin: Mutex<ChildStdin>,
    waiters: WaiterMap,
    next_id: AtomicI64,
    /// Handle to the background reader task (kept alive with the client).
    _reader_handle: tokio::task::JoinHandle<()>,
}

impl JsonRpcClient {
    pub fn new(stdin: ChildStdin, stdout: tokio::process::ChildStdout) -> Self {
        let waiters: WaiterMap = Arc::new(Mutex::new(HashMap::new()));
        let reader_waiters = Arc::clone(&waiters);

        // Spawn background reader — owns stdout exclusively, no mutex on reads.
        let reader_handle = tokio::spawn(async move {
            let mut reader = BufReader::new(stdout);
            loop {
                match read_one_message(&mut reader).await {
                    Ok(msg) => {
                        // Response (has "id") → dispatch to waiter.
                        if let Some(id) = msg.get("id").and_then(|v| v.as_i64()) {
                            let mut map = reader_waiters.lock().await;
                            if let Some(tx) = map.remove(&id) {
                                let result = if let Some(error) = msg.get("error") {
                                    Err(LspError::JsonRpc(error.to_string()))
                                } else {
                                    Ok(msg.get("result").cloned().unwrap_or(Value::Null))
                                };
                                let _ = tx.send(result); // Receiver may have dropped (timeout)
                            }
                        }
                        // Notification (no "id") → drop silently.
                    }
                    Err(_) => {
                        // Server closed stdout or parse error — wake all waiters with error.
                        let mut map = reader_waiters.lock().await;
                        for (_, tx) in map.drain() {
                            let _ = tx.send(Err(LspError::ServerDied));
                        }
                        break;
                    }
                }
            }
        });

        Self {
            stdin: Mutex::new(stdin),
            waiters,
            next_id: AtomicI64::new(1),
            _reader_handle: reader_handle,
        }
    }

    /// Send a request and wait for the response (with 10s timeout).
    pub async fn request<P: Serialize>(&self, method: &str, params: P) -> Result<Value> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);

        // Register waiter BEFORE sending (no race with the reader).
        let (tx, rx) = oneshot::channel();
        self.waiters.lock().await.insert(id, tx);

        // Send the request.
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });
        if let Err(e) = self.send_message(&request).await {
            self.waiters.lock().await.remove(&id);
            return Err(e);
        }

        // Wait for the background reader to dispatch our response.
        match tokio::time::timeout(std::time::Duration::from_secs(10), rx).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => Err(LspError::ServerDied), // Sender dropped (reader died)
            Err(_) => {
                // Timeout — clean up the waiter.
                self.waiters.lock().await.remove(&id);
                Err(LspError::Timeout)
            }
        }
    }

    /// Send a notification (no response expected).
    pub async fn notify<P: Serialize>(&self, method: &str, params: P) -> Result<()> {
        let notification = serde_json::json!({
            "jsonrpc": "2.0",
            "method": method,
            "params": params,
        });
        self.send_message(&notification).await
    }

    /// Send a raw JSON-RPC message with Content-Length header.
    async fn send_message(&self, message: &Value) -> Result<()> {
        let body = serde_json::to_string(message)?;
        let header = format!("Content-Length: {}\r\n\r\n", body.len());

        let mut stdin = self.stdin.lock().await;
        stdin.write_all(header.as_bytes()).await?;
        stdin.write_all(body.as_bytes()).await?;
        stdin.flush().await?;

        debug!(
            method = message
                .get("method")
                .and_then(|m| m.as_str())
                .unwrap_or("response"),
            "sent message"
        );
        Ok(())
    }
}

/// Read one JSON-RPC message from a BufReader (Content-Length delimited).
/// This is a free function — no &self, no mutex. Called only by the reader task.
async fn read_one_message(
    reader: &mut BufReader<tokio::process::ChildStdout>,
) -> std::result::Result<Value, LspError> {
    // Read headers until blank line.
    let mut content_length: Option<usize> = None;
    let mut header_line = String::new();
    loop {
        header_line.clear();
        let bytes_read = reader.read_line(&mut header_line).await?;
        if bytes_read == 0 {
            return Err(LspError::ServerDied);
        }
        let trimmed = header_line.trim();
        if trimmed.is_empty() {
            break;
        }
        if let Some(len_str) = trimmed.strip_prefix("Content-Length: ") {
            content_length = len_str.parse().ok();
        }
    }

    let length = content_length
        .ok_or_else(|| LspError::Protocol("missing Content-Length header".to_string()))?;

    // Read exactly `length` bytes of body.
    let mut body = vec![0u8; length];
    tokio::io::AsyncReadExt::read_exact(reader, &mut body).await?;

    let value: Value = serde_json::from_slice(&body)?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_rpc_request_format() {
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {},
        });
        let body = serde_json::to_string(&request).unwrap();
        assert!(body.contains("\"jsonrpc\":\"2.0\""));
        assert!(body.contains("\"method\":\"initialize\""));
    }
}
