// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Firelock, LLC

//! Generic JSON-RPC 2.0 client over stdio transport.
//!
//! Communicates with LSP servers via stdin/stdout using the LSP base protocol:
//! `Content-Length: N\r\n\r\n{json body}`.

use std::sync::atomic::{AtomicI64, Ordering};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::ChildStdin;
use tokio::sync::Mutex;
use tracing::{debug, warn};

use crate::error::{LspError, Result};

/// A JSON-RPC 2.0 client that speaks LSP base protocol over stdio.
pub struct JsonRpcClient {
    stdin: Mutex<ChildStdin>,
    /// Buffered reader for stdout — reads Content-Length delimited messages.
    stdout: Mutex<BufReader<tokio::process::ChildStdout>>,
    next_id: AtomicI64,
}

impl JsonRpcClient {
    pub fn new(stdin: ChildStdin, stdout: tokio::process::ChildStdout) -> Self {
        Self {
            stdin: Mutex::new(stdin),
            stdout: Mutex::new(BufReader::new(stdout)),
            next_id: AtomicI64::new(1),
        }
    }

    /// Send a request and wait for the response.
    pub async fn request<P: Serialize>(
        &self,
        method: &str,
        params: P,
    ) -> Result<Value> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": method,
            "params": params,
        });

        self.send_message(&request).await?;

        // Read responses until we get one matching our ID.
        // (LSP servers may send notifications interleaved with responses.)
        loop {
            let msg = self.read_message().await?;
            if let Some(msg_id) = msg.get("id") {
                if msg_id.as_i64() == Some(id) {
                    if let Some(error) = msg.get("error") {
                        return Err(LspError::JsonRpc(error.to_string()));
                    }
                    return Ok(msg.get("result").cloned().unwrap_or(Value::Null));
                }
            }
            // Not our response — it's a notification or someone else's response.
            // Log and continue waiting.
            if let Some(method) = msg.get("method").and_then(|m| m.as_str()) {
                debug!(method, "received notification while waiting for response");
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

        debug!(method = message.get("method").and_then(|m| m.as_str()).unwrap_or("response"), "sent message");
        Ok(())
    }

    /// Read one JSON-RPC message from stdout (Content-Length delimited).
    async fn read_message(&self) -> Result<Value> {
        let mut stdout = self.stdout.lock().await;

        // Read headers until blank line.
        let mut content_length: Option<usize> = None;
        let mut header_line = String::new();
        loop {
            header_line.clear();
            let bytes_read = stdout.read_line(&mut header_line).await?;
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

        let length = content_length.ok_or_else(|| {
            LspError::Protocol("missing Content-Length header".to_string())
        })?;

        // Read exactly `length` bytes of body.
        let mut body = vec![0u8; length];
        tokio::io::AsyncReadExt::read_exact(&mut *stdout, &mut body).await?;

        let value: Value = serde_json::from_slice(&body)?;
        Ok(value)
    }
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
